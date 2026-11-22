# Release notes — GeDefense TV 0.3.1-alpha1 (Titan Level 2 & TV Hardening Guards)

| Field | Value |
| --- | --- |
| Product | GeDefense TV (`de.visiongaia.gedefense.tv`) |
| Version | `0.3.1-alpha1` |
| VersionCode | `5` |
| Release date | 22 November 2026 |
| Status | **Public Alpha (Titan Engine + Level-2 Shizuku Bridge)** — signed with VGT Alpha Certificate (`CN=VisionGaiaTechnology GeDefense TV Alpha`) |
| Platform | Android TV OS / Google TV, `minSdk 26` (Android 8.0), `targetSdk`/`compileSdk 36` |
| ABIs | `arm64-v8a`, `x86_64` |
| Verification | `:tvCoreCheck` PASS (591/0), `:tvV2Check` PASS (4,584/0), `:tvKineticCheck` PASS (3,259/0), `:tvTitanCheck` PASS (6,693/0) — **15,127 JVM assertions, 0 failures**; `:app:lintDebug` 0 Errors / 305 Warnings |

> **Alpha Release.** GeDefense TV **0.3.1-alpha1 (VC5)** adds an opt-in, zero-dependency **Level-2 Shizuku Bridge** alongside major **Non-Root TV Hardening**, **Sideload/Debuggable Detection**, and **BadBox / Residential-Proxy Relay** analytics.
> Please read the [Alpha-Tester Guide](docs/ALPHA-TESTER-GUIDE.md) and report findings via GitHub Issues.

---

## Highlights in 0.3.1-alpha1

### 1. Zero-Dependency Shizuku Level-2 Bridge (`TitanPrivilegeLevel.SHIZUKU`)
- **Pure Android AIDL / Binder IPC (`android.useAndroidX=false`):** Implements official Shizuku AIDL specs (`IShizukuService`, `IShizukuApplication`, `IShizukuServiceConnection`, `IRemoteProcess`) plus `ITitanShizukuBridge.aidl` with explicit transaction IDs (`= 1`, `= 2`, `= 16777114`), pure `moe.shizuku.api.BinderContainer`, and `TitanShizukuProvider` protected by `android.permission.INTERACT_ACROSS_USERS_FULL`.
- **Fail-Closed Isolation:** `TitanShizukuUserService` restricts execution strictly to `{pm, am, cmd, getprop, id, cat, ls}` with `SAFE_ARG_PATTERN` validation, caller-UID checks, hard wall-clock timeouts, and output caps. No generic `sh -c` is used.
- **Honest Capability Separation (`allowsShizuku`):** Level 2 enables user-consented `APP_FREEZE` (`pm`/`am`/`cmd`) and `SOCKET_PROVENANCE` (including `cmd package list packages -U` to resolve packages beyond `<queries>` limits). Root-only containment (`isolateUid`, `killProcess`, `closeAdbTcp`, Vault) remains locked unless Level 3 (`ROOT`) is confirmed. Cold start and Binder death immediately degrade back to Level 1 (`STANDARD`).

### 2. Non-Root TV Hardening, Sideload & Debuggable Guards
- **14 Local Hardening Checks:** Audits SELinux (`getenforce`), ADB-over-TCP (`service.adb.tcp.port` + loopback 5555 probe), Wireless ADB (`adb_wifi_enabled`), unauthenticated ADB (`ro.adb.secure == 0`), active HTTP proxies, missing Private DNS on non-VPN links, plus visible sideloaded and `FLAG_DEBUGGABLE` apps.
- **Inventory Accuracy:** Fixes `installerIsKnownStore` via `hasUnknownInstaller` so third-party apps with `installerPackage == null` are surfaced honestly as unknown/sideloaded sources in the TV UI.

### 3. BadBox Direct-IP & Residential-Proxy Relay Heuristics (`PolicyAction.OBSERVE`)
- **`DIRECT_IP_BYPASS` & `PROXY_RELAY_PATTERN`:** `OutboundAnomalyEngine` detects repeated raw public-IP outbound connections without DNS resolution (`>= 4 KiB`) and sustained multi-prefix bidirectional/raw-dominant relay traffic (`>= 16 KiB`).
- **XDR Correlation:** `TvXdrEngine` integrates direct-IP fanout, proxy-relay signals, and `+10` sideload risk weighting strictly under `PolicyAction.OBSERVE`.

---

## Artifacts & Checksums

The release APKs are signed with the VGT Alpha Certificate (`CN=VisionGaiaTechnology GeDefense TV Alpha`):

| Artifact | Size | SHA-256 Checksum |
| :--- | :--- | :--- |
| **`VGT_GeDefense_TV_0.3.1-alpha1_VC5_release-signed.apk`** | **6,577,286 Bytes** | `1A181288DCE177CAFBB545A4AC72F52BF077093A1A685489E3F60B7B8035FFA9` |
| `VGT_GeDefense_TV_0.3.1-alpha1_VC5_debug.apk` | 8,474,619 Bytes | `478B51DA852D8E59FD4823B6812C41A4425F67F52E6E45E734EB658B24477C03` |

Authoritative hashes are documented in [SHA256SUMS.txt](SHA256SUMS.txt).

---

## Known Alpha Boundaries (Honest Status)
1. **Hardware Runtime (`NOT_TESTED`):** Live Shizuku IPC (`UserService` / `newProcess`, Binder death) and on-device SELinux/ADB/Proxy/BadBox telemetry have been verified via static analysis, Android Lint, and JVM harnesses (`15,127` assertions), not yet on physical Android TV / Google TV hardware.
2. **Mobile Witness Pairing:** Local HMAC checkpoints are active; wireless pairing/push to GeDefense Mobile remains planned for a future release.
3. **Quarantine Vault:** Moves binaries with `chmod 000`; per-file vault encryption is not yet implemented.

---

## Feedback & Issues

Open issues and feedback are welcome at:  
👉 **<https://github.com/visiongaiatechnology/gedefense_androidtv/issues>**
