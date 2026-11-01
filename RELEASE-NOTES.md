# Release notes — GeDefense TV 0.3.0-alpha1 (Titan Engine)

| Field | Value |
| --- | --- |
| Product | GeDefense TV (`de.visiongaia.gedefense.tv`) |
| Version | `0.3.0-alpha1` |
| VersionCode | `4` |
| Release date | 1 November 2026 |
| Status | **Public Alpha (Titan Engine)** — signed with VGT Alpha Certificate (`CN=VisionGaiaTechnology GeDefense TV Alpha`) |
| Platform | Android TV OS / Google TV, `minSdk 26` (Android 8.0), `targetSdk`/`compileSdk 36` |
| ABIs | `arm64-v8a`, `x86_64` |
| Verification | `:tvCoreCheck` PASS (554/0), `:tvV2Check` PASS (4398/0), `:tvKineticCheck` PASS (3025/0), `:tvTitanCheck` PASS (6624/0) — **14,601 JVM tests, 0 failures** |

> **Alpha Release.** GeDefense TV 0.3.0-alpha1 introduces the **Titan Engine (Endpoint Guardian)**.
> This build is designed for real-world alpha testing on physical Android TV / Google TV hardware and rooted TV boxes.
> Please read the [Alpha-Tester Guide](docs/ALPHA-TESTER-GUIDE.md) and report findings via GitHub Issues.

---

## Highlights

### 1. Titan Engine — Three-Tier Privilege Architecture
- **Level 1 · Standard (Non-Root, all Android TVs):**
  Pure observation and on-device loopback VPN filtering. Zero Snake Oil guarantee: If no root is present, Titan honestly reports `Level 1 Standard` with 7 capability shields marked as *Unavailable*. No intrusive prompts, no fake claims.
- **Level 2 · Supervised (Detection-Only):**
  Detection of Shizuku Binder bridges and active ADB debugging (`service.adb.tcp.port 5555`).
- **Level 3 · Sovereign Root (Privileged TV Endpoint Defense):**
  Activated **only** with explicit, 2-step user confirmation (default focus on *Cancel*). Requires verified `su -c id` yielding `uid=0(root)`.

### 2. Socket Provenance Radar
- Parses `/proc/net/tcp` and `/proc/net/tcp6` in real-time.
- Maps network sockets directly: `Inode → PID → UID → Package Name`.
- Flags high-risk patterns: exposed open ADB ports (Port 5555), unattributed sockets, and threat-feed matching C2 connections.
- Bounded safety: max 4,096 sockets, 512 observations, truncated flag on overload.

### 3. File Integrity Monitoring (FIM) & Anti-Planting
- Monitors critical system locations (`/system/bin`, `/system/xbin`, `/vendor/bin`, `/system/etc/init`, `/data/adb/modules`).
- Detects new, modified, or unreadable binaries against SHA-256 baseline deltas.
- Unreadable files remain honestly unreadable (never assumed "clean").

### 4. Reversible Active Response (Containment)
- Policy-first safety: strictly allowlisted commands (`FREEZE_APP`, `RESTORE_APP`, `ISOLATE_NETWORK_UID`, `KILL_PROCESS`, `CLOSE_ADB_PORT`).
- **Zero destructive commands:** absolutely no `rm -rf`, format, or partition wiping code.
- Protected system apps, UID ≥ 10,000, PID ≠ 1/self, max 16 active containments, rate-limited to 8 actions / 60 seconds.

### 5. Ed25519 / HMAC Witness Checkpoints
- Tamper-evident evidence ledger with signed cryptographic witness checkpoints.
- Constant-time verification of ledger continuity and integrity.

### 6. 100% 10-Foot Leanback UI with Glass 2100 Design
- Dedicated `Titan Live` navigation screen and Home Screen status strip.
- Glassmorphic panels, metallic gold accents (`#E6B95C`), electric blue highlights.
- Full D-Pad remote control support (UP, DOWN, LEFT, RIGHT, OK, BACK) with zero touch dependencies.
- Sir Quacksec mascot and 6 complete UI localizations (English, German, French, Russian, Simplified Chinese, Japanese).

---

## Artifacts & Checksums

The release APKs are signed with the VGT Alpha Certificate:

| Artifact | Size | SHA-256 Checksum |
| :--- | :--- | :--- |
| **`VGT_GeDefense_TV_0.3.0-alpha1_VC4_release-signed.apk`** | **6,522,110 Bytes** | `DA4110EB18ED9376B2C16AD70065C9F39A1F7592865B612A469E969B0F3F2934` |
| `VGT_GeDefense_TV_0.3.0-alpha1_VC4_debug.apk` | 8,811,121 Bytes | `2FB107BB473BFF4C6BCDBE8ED97605D057BD7E18B404BF80561331A25087B2D4` |

Authoritative hashes are documented in [SHA256SUMS.txt](SHA256SUMS.txt).

---

## Alpha Testing Instructions

Please consult the **[Alpha-Tester Guide](docs/ALPHA-TESTER-GUIDE.md)** for installation methods (ADB Wi-Fi, USB Flash Drive, Downloader App) and testing matrices.

### Known Alpha Boundaries (by design in v0.3.0):
1. **Shizuku Execution Bridge:** Passive detection only; execution bridge scheduled for v0.4.0.
2. **Mobile Witness Pairing:** Local HMAC checkpoints are fully functional; wireless sync to GeDefense Mobile is planned for future beta.
3. **Quarantine Vault UI:** Read-only inspection; manual restore button will be exposed in v0.4.0.

---

## Feedback & Issues

Open issues and feedback are welcome at:  
👉 **<https://github.com/visiongaiatechnology/gedefense_androidtv/issues>**
