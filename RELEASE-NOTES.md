# Release notes — GeDefense TV 0.2.0-alpha1

| Field | Value |
| --- | --- |
| Product | GeDefense TV (`de.visiongaia.gedefense.tv`) |
| Version | `0.2.0-alpha1` |
| VersionCode | `2` |
| Release date | 29 October 2026 |
| Status | **Early alpha** — test-signed build for evaluation and alpha feedback |
| Platform | Android TV OS / Google TV, `minSdk 26`, `targetSdk`/`compileSdk 36` |
| ABIs | `arm64-v8a`, `x86_64` |

> **Early alpha.** Every user is an alpha tester. This build is not a finished consumer product and
> the APK is signed with a test signing key, not a production release key. Expect rough edges,
> missing polish and behaviour changes between alpha builds.

## Highlights

- **On-device loopback VPN** (V2): local filtering of DNS and outbound connections through a TUN
  interface and the vendored GaiaNet data-plane helper. **No external VPN server**, no account, no
  cloud. Filter profiles: Off, Conservative, Balanced, Strict.
- **Traffic map with local geo attribution** (V2): per-app, per-country and per-domain view of
  observed traffic, bytes, active flows and blocked flows. Country attribution uses an offline
  IP-to-country dataset and the TV region; **no GPS and no location permission**.
- **XDR-Light** (V2): correlation of local check findings, traffic anomalies and threat-intelligence
  status into explainable incidents — not a privileged EDR.
- **Outbound Kinetic-Lite** (V2.1): local, explainable outbound-anomaly heuristics (DNS burst,
  destination fanout, beacon pattern, volume spike, repeated blocks, tracker categories, C2 match,
  high-risk corridors). **Observe-only by default.** Opt-in temporary containment is available only
  in the Strict profile, is limited to destination prefixes, requires multiple independent signals,
  expires automatically and can be undone from the TV popup.
- **First-run onboarding** (V2): step-by-step setup with Sir Quacksec, VPN consent, threat-intel
  sync, first check and activation summary.
- **Threat-intelligence sync overlay** (V2): D-pad-safe progress overlay while feeds are updated;
  stale feeds are labelled instead of hidden.
- **Six UI languages**: English (default), German, French, Russian, Simplified Chinese, Japanese —
  the app follows the system language.
- **Evidence and report export**: HMAC-chained, encrypted local evidence ledger plus local report
  export as text and JSON.
- **Honest status model**: no "protected" claim without an active tunnel; partial visibility and
  missing data are shown as such, never as "clean".

## Changes since 0.1.0-alpha1

- New V2/V2.1 product surface: Protection dashboard, Network (traffic map), XDR-Light, onboarding
  wizard, Sir Quacksec welcome, TI sync overlay, Kinetic-Lite anomaly feed and containment popup.
- New manifest components and permissions (all justified in [SECURITY.md](SECURITY.md)):
  `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`, service permission
  `BIND_VPN_SERVICE`, `SUPPORTS_ALWAYS_ON` metadata. No location, accessibility, overlay, camera,
  microphone or `QUERY_ALL_PACKAGES` permission.
- Localization: the UI is now multilingual (English default); the German UI remains available via
  German resources.
- Vendored native helper `libgedefense_gaianet_v2.so` for `arm64-v8a` and `x86_64`
  (byte-identical to GeDefense Mobile `0.28.0-beta1`; see `THIRD_PARTY_NOTICES.md`).
- Version bump to `0.2.0-alpha1` / VersionCode `2`.

## Verification status

This release is an **alpha** and the verification state is reported honestly:

| Check | Status |
| --- | --- |
| JVM domain harnesses `:tv-core:tvCoreCheck`, `:tv-core:tvV2Check`, `:tv-core:tvKineticCheck` | PASS for the checked-in source (dependency-free Kotlin harnesses; see `TEST-PLAN.md`) |
| App compile and debug/release APK build | The alpha APK and the UI screenshots were produced from this source tree; lint results are not published with the alpha. |
| UI on Android TV emulator (Android 16 Google TV, API 36, 1920×1080) | Screenshots in `docs/screenshots/` were captured from the running build |
| Real TV hardware (OEM devices) | **NOT TESTED** |
| Independent security review / penetration test | **NOT DONE** |
| APK signing | **Test signing key** — not a production key |
| Play Store / Google TV app-store review | **NOT DONE** |

Do not interpret this alpha as a guaranteed protection product. See the limitations in
[README.md](README.md#scope-and-limitations) and the test matrix in [TEST-PLAN.md](TEST-PLAN.md).

## Artifacts

The APK is published as a GitHub release asset. Expected file names:

- `VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-debugsigned.apk` (R8-minified, test-signed)
- `VGT_GeDefense_TV_0.2.0-alpha1_VC2_debug.apk` (debug build, for development only)

Checksums: see [SHA256SUMS.txt](SHA256SUMS.txt). Verify the downloaded APK against the checksums
attached to the exact release before installing it.

## Install / upgrade

1. Enable installation from unknown sources for your file manager / sideload tool on the TV.
2. Install `VGT_GeDefense_TV_0.2.0-alpha1_VC2_release-debugsigned.apk`
   (`adb install -r <file>` over ADB, or a sideload app on the TV).
3. Start GeDefense TV, follow the onboarding and grant the Android VPN consent dialog once.

Upgrading from 0.1.0-alpha1 keeps app data; if the evidence key cannot be recovered, the app fails
closed instead of pretending the evidence is intact. A fresh install is the safest alpha path.

## Known limitations (short list)

- Real TV hardware, OEM-specific behaviour and Always-On recovery are not verified.
- Filtering sees only what the local VPN data path observes; apps using DoT/DoH hide domains.
- Country attribution is an estimate; CDNs, anycast and shared hosting can be misattributed.
- Kinetic-Lite containment is a temporary, explicit, reversible measure — not malware removal and
  not a complete network block.
- The alpha APK is test-signed; do not distribute it as a production build.

## Feedback

Alpha feedback is welcome via GitHub issues in
<https://github.com/visiongaiatechnology/gedefense_androidtv>. For security-relevant reports, do not
post exploitable details publicly — see [SECURITY.md](SECURITY.md).
