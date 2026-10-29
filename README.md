<p align="center">
  <img src="docs/assets/sir_quacksec.png" alt="Sir Quacksec — GeDefense TV" width="200">
</p>

<h1 align="center">GeDefense TV</h1>

<p align="center"><b>On-device security console for Android TV OS and Google TV.</b><br>
Local loopback VPN filtering, traffic map with geo attribution, XDR-Light and an honest status model.<br>
No external VPN server. No cloud. No telemetry.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk"><img src="https://img.shields.io/badge/release-0.2.0--alpha1-E8C46A?style=flat-square" alt="Release 0.2.0-alpha2"></a>
  <img src="https://img.shields.io/badge/status-early%20alpha-E86A5A?style=flat-square" alt="Early alpha">
  <img src="https://img.shields.io/badge/platform-Android_TV%20%7C%20Google_TV-5FBFA8?style=flat-square" alt="Android TV / Google TV">
  <img src="https://img.shields.io/badge/Kotlin-1.9.24-7F52FF?style=flat-square&logo=kotlin&logoColor=white" alt="Kotlin 1.9.24">
  <img src="https://img.shields.io/badge/minSdk-26-3DDC84?style=flat-square&logo=android&logoColor=white" alt="minSdk 26">
  <img src="https://img.shields.io/badge/license-VGT%20proprietary-B08D57?style=flat-square" alt="VGT proprietary license">
</p>

**English** · [Deutsch](README.de.md) · [Русский](README.ru.md) · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

---

> ## ⚠️ EARLY ALPHA — every user is an alpha tester
>
> GeDefense TV **0.2.0-alpha2** is an early alpha build. It is not a finished consumer product, not
> an audited security product, and the published APK is signed with a **test signing key**.
> Behaviour, UI and the filtering policy will change between alpha builds. Before you rely on it:
> understand the [scope and limitations](#scope-and-limitations), read the [release notes](RELEASE-NOTES.md)
> and treat every result as a hint, never as a guarantee.

## Download

[![Download the latest alpha APK](https://img.shields.io/badge/Download-latest%20APK-E8C46A?style=for-the-badge&logo=android&logoColor=black)](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk)

Always use the [latest release page](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk):
the exact APK asset, its checksums and the build notes live there. The alpha APK is test-signed —
Android may warn when you sideload it. Verify the SHA-256 checksum against [SHA256SUMS.txt](SHA256SUMS.txt)
or the checksums attached to the release before installing.

## Screenshots

Real renders of the English UI, captured from a running Android TV emulator build (1920×1080,
Android 16 Google TV / API 36).

| Home — security posture | Protection — local loopback VPN |
| --- | --- |
| ![Home screen](docs/screenshots/home.png) | ![Protection dashboard](docs/screenshots/protection.png) |

| Network — traffic map and destinations | Reversible containment popup (Kinetic-Lite) |
| --- | --- |
| ![Network and traffic map](docs/screenshots/network.png) | ![Temporary containment popup](docs/screenshots/containment.png) |

| First-run onboarding with Sir Quacksec | XDR-Light — correlated incidents | Threat-intelligence sync overlay |
| --- | --- | --- |
| ![Onboarding step 1](docs/screenshots/onboarding.png) | ![XDR-Light incidents](docs/screenshots/xdr.png) | ![Threat-intelligence sync overlay](docs/screenshots/ti-sync.png) |

### Six UI languages

The UI follows the TV system language. English is the default; German, French, Russian, Simplified
Chinese and Japanese ship complete resource sets.

| English (default) | Deutsch | Français |
| --- | --- | --- |
| ![English home](docs/screenshots/home.png) | ![German home](docs/screenshots/languages/home-de.png) | ![French home](docs/screenshots/languages/home-fr.png) |

| Русский | 简体中文 | 日本語 |
| --- | --- | --- |
| ![Russian home](docs/screenshots/languages/home-ru.png) | ![Chinese home](docs/screenshots/languages/home-zh-CN.png) | ![Japanese home](docs/screenshots/languages/home-ja.png) |

## What is GeDefense TV?

GeDefense TV is a D-pad-first security app for Android TV OS and Google TV. It combines a local
filtering layer with a local observability console: it shows what the TV is doing on the network,
what it blocked, which apps talk to which countries, and which findings are actually verifiable on
the device.

The guiding rule is: **only report what is observable on this specific device.** Missing permissions,
unsupported APIs or partial visibility are shown as partial visibility — never as proof that the TV
is clean. A protection state is only claimed when a tunnel is actually active.

The app is a **standalone TV app**. It is not a router, firewall gateway or network sensor, and it
does not integrate with router firmware.

### Why a local-only loopback VPN?

GeDefense TV filters on the device itself. The app creates a local TUN interface, routes its own
traffic through it and lets a vendored, audited data-plane helper evaluate DNS and connection
metadata. The filtered traffic then leaves the device directly for its destination.

That design has deliberate consequences:

- **No external server, no account, no subscription.** Your traffic is not relayed through a VGT
  server or any third-party VPN endpoint, so there is nothing to trust in the middle.
- **No payload inspection.** Only DNS and connection metadata are evaluated. TLS/QUIC content stays
  encrypted and untouched — this is not a MITM proxy and cannot see inside HTTPS.
- **Local evidence.** Findings, counters and evidence stay on the TV. Nothing is uploaded.
- **Honest failure.** If consent is missing, the helper fails or the policy cannot be evaluated, the
  app reports a degraded/failed state instead of silently passing traffic through unfiltered.

## Features

### Local protection (loopback VPN)

- On-device TUN service (`VpnService`, foreground service, Always-On support) with a vendored native
  helper for `arm64-v8a` and `x86_64`.
- Start / stop with Android's one-time VPN consent; optional auto-start after app start.
- Filter profiles: **Off**, **Conservative**, **Balanced**, **Strict** — each profile changes how
  aggressively known telemetry, ACR, ads, tracker and C2 destinations are treated.
- Explicit state model: Off, Preparing, Active, Limited, Failed, Not supported. "Active" is only
  shown while the local tunnel really runs.
- Live counters: blocked flows, observed apps, active flows and transferred volume since start.

### Filtering: DNS, trackers, ACR, ads and C2

- Local evaluation of DNS queries and connection destinations against the vendored threat index,
  a curated tracker/telemetry catalog, and the selectable privacy profile.
- Actions are explainable: allow, annotate, correlate or block — with a reason from the local policy,
  never from a remote verdict.
- Bounded threat-intelligence cache fed from public IOC lists; stale feeds are labelled, not hidden.
- Honest limitation: if an app uses DNS-over-TLS/HTTPS, its domain names are not visible; the app
  says so instead of guessing.

### Traffic map with local geo attribution

- Per-app, per-country and per-domain aggregation of observed traffic: bytes, active flows, blocked
  flows, correlated flows.
- World map with country markers and an origin marker derived from the TV region/network — **no GPS,
  no location permission**.
- IP-to-country attribution uses an offline dataset downloaded once with SHA-256 checksums; country
  attribution is an estimate (CDNs, anycast and shared hosting can be misattributed).
- Bounded, privacy-friendly data: no payloads, no screen content, no audio/video, no per-packet logs.

### XDR-Light

Correlates what is locally observable into explainable incidents: repeated blocked flows per app,
blocked telemetry/ACR traffic, first-seen app traffic, C2 feed matches and high-risk country
corridors (informational only). Every incident carries its rule, confidence, visibility and a
recommendation. Deduplicated, bounded, and explicitly **not** a privileged EDR: no system-wide
flows, no process monitoring, no firmware integrity claims.

### V2.1 Outbound Kinetic-Lite

Deterministic, bounded sliding-window heuristics over observed outbound traffic: DNS bursts,
destination fan-out, beacon patterns, volume spikes, repeated blocks, tracker categories, C2 matches
and high-risk corridors. Every anomaly is a score with named signals — never a "malware" verdict.

**Observe-only by default.** Temporary containment is an explicit opt-in available only in the
Strict profile. When enabled, only destination prefixes are contained (never apps), with strict
guardrails: at least two independent signals, a minimum score, a known destination country, a short
TTL (1–30 minutes, default 10), a maximum of four active containments, and allowlists for platform,
Google and CDN ranges. Every containment is reversible: a TV popup appears, the user can press
**Undo**, and the block lifts automatically when the TTL expires.

### First-run onboarding with Sir Quacksec

A six-step, D-pad-only setup wizard: welcome, how local protection works, VPN consent, threat-intel
sync (skippable), first check, and a summary that activates full protection. Nothing is faked: if
consent is denied or a step fails, the wizard says so.

### Threat-intelligence sync overlay

A D-pad-safe overlay shows feed sync progress while public IOC feeds are updated. Stale or failed
synchronisation is reported honestly and can be retried later.

### Evidence, reports and export

- Local evidence ledger with an HMAC-verified hash chain and encrypted payloads; fail-closed if the
  evidence key is lost instead of silently starting a new chain.
- Local text and JSON security report.
- Export through the system file picker (SAF); on TV images without a document picker the app uses a
  permission-free `Downloads/GeDefenseTV` fallback and tells the user where the files went.

### Six languages, fully localised

English (default), German, French, Russian, Simplified Chinese and Japanese — complete resource sets
for every UI string, checked by the repository translation checker.

### Device audit and findings

Beyond filtering, GeDefense TV keeps the read-only audit surface that the product started with:

- **Device posture:** Android version/API level, build fingerprint, ABI and security-patch age
  classification — explicitly metadata, not a vulnerability guarantee.
- **Visible apps:** version, installer, signature digests and NEW/CHANGED state versus a baseline,
  with Android package-visibility limits shown instead of hidden.
- **Hardening checks:** ADB/debugging, developer options, test-keys/userdebug builds, device admins,
  accessibility services and non-store installers — tri-state, where unreadable values stay
  unreadable and are never treated as "secure".
- **Findings and threat intelligence:** explainable findings with severity, confidence and
  visibility, plus local feed freshness and indicator matches.

### Honest status model

The status model is the product: capability and visibility are first-class data. Instead of a green
"secure" badge, you get a posture score only when coverage is sufficient, explicit partial-visibility
labels, and a clear statement of what could not be observed.

## How it works

```text
Android TV / Google TV (not rooted)
┌──────────────────────────────────────────────────────────────────────────┐
│ :app  (normal app sandbox, no AndroidX, no third-party runtime libraries) │
│   UI (Views, D-pad)   Protection   Network   XDR   Onboarding   Settings │
│   contracts / services                                                     │
│        │                                                                   │
│   TvVpnService (foreground service, local TUN)                             │
│        │  bounded control + telemetry                                     │
│        ▼                                                                   │
│   GaiaNet helper (vendored native .so, child process, no root)             │
│        DNS / flow policy  →  direct egress to the destination              │
└──────────────────────────────────────────────────────────────────────────┘
     :tv-core — pure JVM domain: scan, scoring, traffic, XDR, anomalies,
                containment policy, geo helpers, reports, events
     :core    — vendored, byte-identical GeDefense Mobile core
```

## Scope and limitations

GeDefense TV is intentionally **not**:

- an external VPN or geo-unblocking service — there is no server and nothing is tunnelled off-device;
- an anti-virus or malware remover — it observes network behaviour and reports, it does not clean apps;
- a privileged EDR — no kernel access, no root, no system-wide process or flow monitoring;
- a router/gateway/firewall appliance replacement — it runs on the TV only;
- a full app inventory — Android package visibility limits what an app can see;
- a guarantee of protection — filtering only covers traffic that actually passes through the local
  data path, and only the policies it knows about.

Additional known limitations:

- **Alpha quality:** real TV hardware (OEM devices) is not yet verified; emulator behaviour is the
  current evidence base.
- **DNS visibility:** DoT/DoH traffic hides domains from local observation.
- **Geo attribution is approximate:** CDNs, anycast and shared hosting can be assigned to the wrong country.
- **Containment is temporary by design:** short TTL, max four active blocks, easy to undo — not a
  permanent firewall rule.
- **Test-signed alpha APK:** not a production-signed build; sideloading requires allowing unknown sources.

## Safety and privacy

- **No telemetry, no analytics, no ads, no crash SDKs.** The app contains no third-party runtime SDK.
- **No content capture:** no screen, audio, video or payload capture; no TLS interception.
- **Local processing by default:** traffic metadata, findings and evidence stay on the device.
- **Minimal permissions:** `INTERNET`, `ACCESS_NETWORK_STATE`, `FOREGROUND_SERVICE`,
  `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS` plus the `BIND_VPN_SERVICE` service
  permission. No location, accessibility, overlay, camera, microphone or `QUERY_ALL_PACKAGES`.
- **Only public data leaves the device:** threat-intel feeds and an IP-to-country dataset are fetched
  over HTTPS; no device data is uploaded.
- **Security reporting:** see [SECURITY.md](SECURITY.md). Please do not publish exploitable details
  in public issues.

Full data inventory: [PRIVACY.md](PRIVACY.md) · [DATA-SAFETY.md](DATA-SAFETY.md).
Security design and threat model: [SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md).

## Requirements

| Component | Requirement |
| --- | --- |
| Device | Android TV OS / Google TV, `minSdk 26` (Android 8.0) or newer, `arm64-v8a` or `x86_64` |
| TV UI | Leanback-compatible launcher, D-pad remote (no touch required) |
| Build | JDK 17, Android SDK platform 36, Build-Tools 36.0.0, Gradle 8.7 (wrapper included) |
| Runtime dependencies | none — no AndroidX, no third-party libraries |

## Install (sideload)

1. On the TV, allow installation from unknown sources for the app you use to install APKs
   (a sideload/file manager app, or ADB).
2. Install the APK from the [latest release](https://github.com/visiongaiatechnology/gedefense_androidtv/releases/download/v0.2.0-alpha2/VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-signed.apk).
3. Start **GeDefense TV**, follow the onboarding and accept Android's one-time VPN consent dialog.
4. Optional, over ADB:

```bash
adb connect <tv-ip>:5555
adb install -r VGT_GeDefense_TV_0.2.0-alpha2_VC3_release-debugsigned.apk
adb shell am start -n de.visiongaia.gedefense.tv/.TvMainActivity
```

The alpha APK is **test-signed**. A production signing key is not part of this alpha.

## Build from source

```bash
git clone https://github.com/visiongaiatechnology/gedefense_androidtv.git
cd gedefense_androidtv

export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk

./gradlew :app:assembleDebug           # debug APK
./gradlew :app:assembleRelease         # R8-minified release APK
```

Release signing reads `GEDEFENSE_RELEASE_STORE_FILE`, `GEDEFENSE_RELEASE_STORE_PASSWORD`,
`GEDEFENSE_RELEASE_KEY_ALIAS` and `GEDEFENSE_RELEASE_KEY_PASSWORD` from the environment. Without
them the build falls back to the debug signing config — fine for alpha testing, not for distribution.
More details: [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md).

## Tests

```bash
./gradlew :tv-core:tvCoreCheck     # core domain harness
./gradlew :tv-core:tvV2Check       # traffic / privacy / XDR domain harness
./gradlew :tv-core:tvKineticCheck  # V2.1 anomaly + containment harness
./gradlew :app:lintDebug           # Android lint
```

The vendored core harness (`:core:coreCheck`) needs a Linux/macOS JVM: its durable-file code uses
directory `fsync`, which is not supported on Windows. The Android TV emulator guide, including
commands to create an AVD and capture screenshots, is in [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md).
The acceptance matrix is [TEST-PLAN.md](TEST-PLAN.md).

## Project structure

```text
.
├── app/                    Android TV application module (Views, no AndroidX)
│   └── src/main/            java/ · res/ (6 locales) · assets/ · jniLibs/ · AndroidManifest.xml
├── core/                   vendored, byte-identical GeDefense Mobile core (pure JVM)
├── tv-core/                pure JVM domain: scan, scoring, traffic, XDR, anomalies, reports
├── docs/                   architecture, traffic map, onboarding, design DNA, emulator guide,
│                           screenshots/ and assets/
├── tools/                  build/test/emulator/remote/verification scripts
├── gradle/ + gradlew*      Gradle 8.7 wrapper (distribution SHA-256 pinned)
├── build.gradle.kts        AGP 8.5.2 · Kotlin 1.9.24 · Java 17
└── settings.gradle.kts     modules :core, :tv-core, :app
```

## Documentation

| Document | Content |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module graph, data flow, collectors, evidence, performance budgets |
| [docs/V2-ARCHITECTURE.md](docs/V2-ARCHITECTURE.md) | Loopback VPN, telemetry, traffic aggregation, native helper supply chain |
| [docs/TRAFFIC-MAP.md](docs/TRAFFIC-MAP.md) | Traffic map data sources, limits, colors and privacy |
| [docs/ONBOARDING.md](docs/ONBOARDING.md) | First-run wizard, consent and permission explanations |
| [docs/DESIGN-DNA.md](docs/DESIGN-DNA.md) | TV design system, focus/interaction rules, forbidden patterns |
| [SECURITY.md](SECURITY.md) | Security design, key custody, permissions, reporting policy |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Assets, trust boundaries, STRIDE analysis, TV-specific risks |
| [PRIVACY.md](PRIVACY.md) | Data inventory, retention, export, permissions rationale |
| [TEST-PLAN.md](TEST-PLAN.md) | Acceptance matrix and evidence requirements |
| [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md) | Build, signing, logs and troubleshooting |
| [docs/TV-EMULATOR-TESTING.md](docs/TV-EMULATOR-TESTING.md) | Step-by-step Android TV emulator guide |
| [docs/SOURCES.md](docs/SOURCES.md) | Sources and references |
| [RELEASE-NOTES.md](RELEASE-NOTES.md) | What changed in this alpha and its verification status |

## License and third-party notices

GeDefense TV is **proprietary software of VisionGaiaTechnology (VGT)**. This repository is published
for transparency, review and alpha testing. No license to redistribute or create derivative works is
granted by publishing it — see [LICENSE](LICENSE).

Third-party components, vendored binaries, assets and runtime data sources (public threat-intel
feeds, the public IP-to-country dataset, the Go standard library inside the native helper) are
documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Alpha feedback

Feedback is welcome via [GitHub issues](https://github.com/visiongaiatechnology/gedefense_androidtv/issues).
Please include your device model, Android TV OS version and the app version shown in Settings.
Do not post secrets, personal data or exploitable security details in public issues — see
[SECURITY.md](SECURITY.md).

---

<p align="center"><i>GeDefense TV is a project of VisionGaiaTechnology.<br>
“The humor is load-bearing. The code is not a joke.”</i></p>
