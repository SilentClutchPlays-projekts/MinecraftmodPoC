# Minecraft Mod Security PoC

A Fabric client-side security lab for Minecraft 1.21.11. It looks for files named `flag.txt` and reports their path, size and SHA-256 to a Discord webhook.

## Search behavior

1. It recursively scans the active Minecraft game directory first, including hidden directories.
2. Only if no `flag.txt` is found there, it scans the operating-system user folder:
   - Linux: `/home` (or the current user's home directory if `/home` is unavailable).
   - Windows: `<SystemDrive>\\Users`.
3. Symbolic links are not followed. Directories the operating system denies access to are skipped; the scan does not bypass permissions.

## Source-code content toggle

Open `SecurityPocMod.java` and find:

```java
private static final boolean SEND_FILE_CONTENTS = false;
```

- `false`: sends only the matching file's full path, size and SHA-256.
- `true`: still sends metadata for all discovered files. It may attach contents **only** for the dedicated disposable fixture at `<game-directory>/security-poc/approved-test-files/flag.txt`, with a 7 MiB limit. Other discovered files (Desktop, Documents, hidden folders, etc.) are never uploaded.

This restriction is intentional: the mod can demonstrate that a hidden test file was found without turning the project into a tool that uploads arbitrary personal files. SHA-256 is calculated by streaming the file locally; file bytes are not sent for ordinary matches.

## Setup

1. Install the mod in your Fabric 1.21.11 client.
2. Start Minecraft once, then close it.
3. Edit `config/mcsecuritypoc.properties` and set `webhookUrl` to your Discord webhook.
4. Put a disposable test file named `flag.txt` somewhere under the active game directory. To test the permitted content-upload path, put it specifically at `security-poc/approved-test-files/flag.txt` under the game directory and change the Java constant to `true`.
5. Rebuild the mod and inspect the Discord report.

Do not put passwords, session tokens, or other secrets in the test fixture.

## Build

The GitHub Actions workflow is manual: **Actions → Build Fabric Mod → Run workflow**. It uploads the built JAR as an artifact. It is not triggered by pushes.

Local build: `gradle build` (JDK 21).

## Compatibility

Minecraft 1.21.11; Fabric Loader range declared as `>=0.18.4 <=0.20.1`.
