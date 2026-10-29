# Security

**Product:** GeDefense TV · **Version:** 0.2.0-alpha1 (VersionCode 2) · **Owner:** VisionGaiaTechnology (VGT)

> **Alpha status.** GeDefense TV 0.2.0-alpha1 is an early alpha. It has **not** been independently
> audited or penetration-tested, it has **not** been verified on real TV hardware, and the published
> APK is signed with a **test signing key**. This document describes the security design and the
> known limitations — it is not a certification.

## Reporting a vulnerability

Please do **not** publish exploit details, proof-of-concept code or sensitive personal data in
public issues. To report a security problem:

1. Contact VisionGaiaTechnology through the contact options on the
   [VisionGaiaTechnology GitHub organisation](https://github.com/visiongaiatechnology) and state that
   the report concerns GeDefense TV security.
2. Include the app version (`0.2.0-alpha1`), device/API level, affected component and reproduction
   steps. Do **not** include real credentials, personal data or third-party data.
3. Reports are handled on a best-effort basis. There is no bug-bounty programme and no guaranteed
   response time for the alpha.

Please do not test against devices or networks you do not own or have permission to test.

## Design principles

| Principle | Implementation |
| --- | --- |
| Local first | Filtering, traffic aggregation, evidence and reports stay on the device. No cloud backend, no external VPN server, no telemetry upload. |
| Least privilege | Only the permissions required for VPN filtering, foreground-service visibility and public feed retrieval are requested. No location, accessibility, overlay, camera, microphone or package-enumeration permission. |
| Honest visibility | Every collector carries a capability/visibility state. `NONE`/`PARTIAL`/`STALE` are never rendered as "clean" or "protected". |
| Observe before enforce | V1 surfaces are read-only recommendations. Enforcement exists only as the explicit, reversible Kinetic-Lite containment in the Strict profile. |
| Fail closed on evidence | If the evidence key cannot be recovered, the evidence store becomes unavailable instead of silently starting a new chain. |
| No MITM | No TLS interception, no installed CA, no payload inspection. Only DNS/connection metadata is evaluated. |
| Bounded input | Size, time, line, entry and redirect limits for every externally supplied data source. |
| No plaintext secrets | Keys live in the Android Keystore; no keys, tokens or credentials in code, logs or reports. |

## Permissions

| Permission | Why it is needed |
| --- | --- |
| `INTERNET` | Retrieving public threat-intelligence feeds and the public IP-to-country dataset; the local VPN data path's own egress. |
| `ACCESS_NETWORK_STATE` | Reading network state/connectivity for the connectivity collector. |
| `FOREGROUND_SERVICE` | The local loopback VPN runs as a foreground service. |
| `FOREGROUND_SERVICE_SPECIAL_USE` | Required by `targetSdk 36` for the VPN foreground-service type; the subtype is documented as local loopback filtering. |
| `POST_NOTIFICATIONS` | Making the foreground-service notification visible. Used only for service status. |
| Service permission `BIND_VPN_SERVICE` | Prevents other apps from binding to `TvVpnService`. |

**Not requested:** location, accessibility, overlay, camera, microphone, `QUERY_ALL_PACKAGES`,
contacts, SMS, storage permissions. Package visibility is restricted to targeted `<queries>` for
launcher apps and HTTPS links.

Android's VPN consent dialog is a system dialog (`VpnService.prepare`). Without consent, no tunnel is
created and the app does not claim protection.

## Local loopback VPN

- A TUN interface owned by `TvVpnService` (foreground service, `SUPPORTS_ALWAYS_ON` metadata).
- The data plane runs in a **vendored native helper** (`libgedefense_gaianet_v2.so`) started as a
  child process from the app's `nativeLibraryDir`. It runs **without root**, is not exported, and
  communicates over a private control socket with a random token handshake. File descriptors for the
  TUN device are passed via `SCM_RIGHTS`; packet payloads are not copied through the control channel.
- Telemetry frames are bounded (2–1024 bytes per frame) and validated by the app; unknown frames are
  discarded instead of guessed.
- **Fail-closed anchor:** if the helper fails, the TUN interface remains in place and the state
  becomes degraded/failed with a visible cause. A restart does not silently leave traffic unfiltered.
  This behaviour is implemented, but its recovery on real TV hardware is **not yet verified**.
- There is **no external VPN server** and no WireGuard egress: filtered traffic leaves the device
  directly for its destination. This also means the app cannot bypass geo-restrictions and does not
  hide the user's IP address from destinations.

## Data protection and key custody

- Evidence entries are stored in a local ledger with an **HMAC-verified hash chain** and
  **AES-256-GCM** payload encryption.
- The evidence root key is generated locally and wrapped by an Android Keystore key; domain-separated
  software subkeys are derived from it. If the Keystore key is lost, the app fails closed and
  archives the old ledger instead of silently deleting it.
- Traffic metadata is bounded (aggregated apps/countries/domains, no payloads, no per-packet logs,
  no screen/audio/video capture).
- Reports are exported only on user action. On TV images without a document picker, the app writes
  the report to `Downloads/GeDefenseTV` without storage permissions and tells the user where the
  files are; those files are outside the app's management and must be deleted by the user.

Details: [PRIVACY.md](PRIVACY.md) and [DATA-SAFETY.md](DATA-SAFETY.md).

## Native helper supply chain

| Property | Value |
| --- | --- |
| Source | `libgedefense_gaianet_v2.so`, byte-identical copy from GeDefense Mobile `0.28.0-beta1` |
| ABIs | `arm64-v8a`, `x86_64` |
| SHA-256 | `arm64-v8a` `d34fda6f06ed7809c386af243b55e55cadd20794f1413b94ada3a729b26fd15e` · `x86_64` `9f393ce49032a84f75717174b09748c08e86ff831886a38f68d0ac12975394f3` |
| Packaging | `jniLibs.useLegacyPackaging = true` (the helper must exist as an executable file in `nativeLibraryDir`) |
| Execution | Child process of the app, no root, no exported surface |

The vendored core (`core/`) is also byte-identical to the GeDefense Mobile core and is protected by
`SOURCE-MANIFEST.sha256` and `tools/verify-source-fidelity.ps1`. A runtime integrity self-check of the
native helper is **not implemented / not verified**.

## Network and data-plane hardening

- Threat-intelligence feeds and the geo dataset are fetched over **HTTPS only**
  (`usesCleartextTraffic="false"`, `network_security_config.xml` with system trust anchors only, no
  user CAs).
- Downloads are bounded (size, line count, time) and same-host redirects are enforced where applicable.
- Geo dataset downloads are validated against upstream SHA-256 checksums when provided.
- Feed content is parsed defensively and treated as untrusted data. Feed availability and content are
  not guaranteed; stale feeds are labelled as stale.

## Verification status (honest)

| Area | Status |
| --- | --- |
| Manifest/permission review (static) | Static review performed; only the permissions listed above are declared. |
| Domain logic (pure JVM harnesses) | `:tv-core:tvCoreCheck`, `:tvV2Check`, `:tvKineticCheck` cover scan/scoring/event/report, traffic/privacy/XDR and anomaly/containment logic. |
| Android emulator (Android 16 Google TV, API 36) | UI and core flows exercised; screenshots in `docs/screenshots/`. |
| Cleartext/TLS configuration | Static check: cleartext disabled, system trust anchors only. |
| Independent security review / pentest | **Not done.** |
| Real TV hardware, OEM behaviour, Always-On recovery | **Not tested.** |
| Production signing | **Not done** — the alpha APK is test-signed. |
| Runtime integrity self-check of the native helper | **Not implemented / not verified.** |

Full acceptance matrix: [TEST-PLAN.md](TEST-PLAN.md). Threat model: [THREAT-MODEL.md](THREAT-MODEL.md).
Architecture: [ARCHITECTURE.md](ARCHITECTURE.md) and [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md).

## Known security limitations

- The app is **not** a privileged EDR: no kernel access, no root, no system-wide process or flow
  visibility, no firmware integrity attestation.
- Apps using DNS-over-TLS/HTTPS hide their domain names from local observation.
- Country attribution is approximate; false positives are possible for CDNs, anycast and shared hosting.
- Kinetic-Lite containment is a temporary, reversible network measure; it is not malware removal and
  it does not provide complete protection.
- The threat-intelligence feeds are public and not cryptographically signed by this project; malicious
  or wrong feed data cannot be fully excluded.
- An alpha APK signed with a test key must not be treated as a trusted production build.

## Third-party components

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The app contains no analytics, advertising,
crash-reporting or third-party networking SDK and no AndroidX.
