# Minecraft Mod Security PoC

A Fabric client-side security lab for Minecraft 1.21.11. It searches only a user-configured scan directory for files named `flag.txt` and reports metadata (path, size, SHA-256) to a Discord webhook.

## Safety behavior

- `sendContents=false`: sends metadata and SHA-256 only.
- `sendContents=true`: still reports metadata for discovered files, but attaches file contents **only** when the discovered file is exactly `<game-directory>/security-poc/approved-test-files/flag.txt`. This is an explicit test-fixture location, not a general file-exfiltration feature.
- Symlinks are not followed.
- The scan root must remain inside the Minecraft game directory.
- The mod never searches account/session files or other directories automatically.

## Setup

1. Install the mod in your Fabric 1.21.11 client.
2. Start Minecraft once, then close it.
3. Edit `config/mcsecuritypoc.properties`:
   - Set `webhookUrl` to your Discord webhook.
   - Keep `sendContents=false` for the first run.
   - Set `scanRoot=security-poc` or another directory under the Minecraft game directory.
4. Put your test file at `<game-directory>/security-poc/flag.txt`.
5. Start Minecraft and inspect the Discord report.
6. To test the content-upload path, copy a disposable test file to `<game-directory>/security-poc/approved-test-files/flag.txt`, then set `sendContents=true`.

Do not put passwords, session tokens, or other secrets in the test fixture.

## Build

The GitHub Actions workflow is manual: **Actions → Build Fabric Mod → Run workflow**. It uploads the built JAR as an artifact. It is not triggered by pushes.

Local build: `gradle build` (JDK 21).

## Compatibility

Minecraft 1.21.11; Fabric Loader range declared as `>=0.18.4 <=0.20.1`.
