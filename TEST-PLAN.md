# Test plan — GeDefense TV 0.2.0-alpha1

This plan lists the checks used for the public alpha. Status values are evidence-based:
`PASS` (executed and passed), `FAIL` (executed and failed), `BLOCKED` (cannot execute here),
`NOT RUN` (not executed — never counted as passed), `N/A`.

## Environment

| Item | Value |
| --- | --- |
| Build | JDK 17, Android SDK platform 36, Build-Tools 36.0.0, Gradle 8.7 (wrapper, SHA-256 pinned), AGP 8.5.2, Kotlin 1.9.24 |
| App | `de.visiongaia.gedefense.tv`, `0.2.0-alpha1`, VersionCode 2, `minSdk 26`, `targetSdk`/`compileSdk 36` |
| Emulator | Android TV / Google TV emulator, Android 16 (API 36), 1920×1080, `x86_64`, canonical 960×540 dp |
| Real hardware | **Not available** — all OEM behaviour is `NOT RUN` |

## Automated checks

| ID | Command | What it covers |
| --- | --- | --- |
| A-01 | `./gradlew :tv-core:tvCoreCheck` | Scan engine, scoring/coverage, hardening rules, report renderer, event codec, text catalog |
| A-02 | `./gradlew :tv-core:tvV2Check` | Traffic policy, tracker/privacy categories, aggregation bounds, XDR-Lite correlation, geo helpers |
| A-03 | `./gradlew :tv-core:tvKineticCheck` | V2.1 anomaly rules, containment guardrails, TTL/expiry, allowlists, threat-index composition |
| A-04 | `./gradlew :core:coreCheck` | Vendored core harness — requires Linux/macOS JVM (directory `fsync` is unsupported on Windows) |
| A-05 | `./gradlew :app:lintDebug` | Android lint over the app module |
| A-06 | `python tools/check_translations.py` | Key parity, placeholder parity and XML validity across all six UI locales |
| A-07 | `python tools/verify_release_tree.py` | Release-tree hygiene: required files, no internal notes/build output/secrets/local paths, README links/badges/switcher/images |
| A-08 | `powershell tools/verify-source-fidelity.ps1` | `core/` is byte-identical to `SOURCE-MANIFEST.sha256` |

Status of A-01…A-08 for the published alpha: the repository contains all harnesses and tooling,
and the release tree itself was validated with `tools/verify_release_tree.py`. Individual JVM harness
logs are not attached to the alpha release (a known transparency gap for the alpha).

## Functional acceptance matrix

### Installation and first run

| ID | Check | Status |
| --- | --- | --- |
| I-01 | TV-only app installs on Android TV / Google TV API 26+ | PASS (emulator, API 36) |
| I-02 | Leanback/launcher entry present, D-pad only, no touch required | PASS (emulator) |
| I-03 | First-run wizard appears on a clean install and can be completed or skipped where allowed | PASS (emulator, screenshots in `docs/screenshots/`) |
| I-04 | VPN consent: cancelling leaves protection off and the app says so | NOT RUN (manual negative check) |
| I-05 | Upgrade from 0.1.0-alpha1 keeps data; unrecoverable evidence key fails closed | NOT RUN |

### Local loopback VPN

| ID | Check | Status |
| --- | --- | --- |
| V-01 | Start/stop protection, state only "Active" with a running tunnel | PASS (emulator UI) |
| V-02 | Filter profiles Off/Conservative/Balanced/Strict change policy | PASS (JVM policy harness) · UI NOT RUN in full |
| V-03 | Auto-start after app start when consent exists | NOT RUN |
| V-04 | Always-On support declared and survives reboot without unfiltered traffic | NOT RUN (needs real device) |
| V-05 | Helper failure → degraded/failed state, TUN anchor remains, recovery works | NOT RUN (fault injection) |
| V-06 | No external VPN endpoint; filtered traffic egresses directly | Static review PASS (design) |

### Filtering (DNS, trackers, ACR, ads, C2)

| ID | Check | Status |
| --- | --- | --- |
| F-01 | Known telemetry/tracker destination is blocked/annotated per profile | PASS (JVM policy harness) · emulator partially observed |
| F-02 | Non-blocked destination is allowed (no blanket blocking) | PASS (JVM harness) |
| F-03 | C2 feed match maps to the configured action | PASS (JVM harness) |
| F-04 | DNS-over-TLS/HTTPS traffic: domain not visible, UI states the limitation | Static review PASS (documented) |
| F-05 | Stale/empty threat feeds are labelled and do not fake protection | PASS (JVM harness + UI states) |

### Traffic map and geo attribution

| ID | Check | Status |
| --- | --- | --- |
| T-01 | Per-app/country/domain aggregation with bytes and blocked counters | PASS (JVM aggregator harness) |
| T-02 | Bounds (apps/countries/domains/flows) enforced, deterministic sorting | PASS (JVM harness) |
| T-03 | Country attribution from offline dataset; no GPS/location permission | Static review PASS · emulator render PASS |
| T-04 | Empty state without an active tunnel, no invented traffic | PASS (emulator) |
| T-05 | Geo dataset download integrity (SHA-256) | NOT RUN (network-dependent) |

### XDR-Light

| ID | Check | Status |
| --- | --- | --- |
| X-01 | Correlated incident from repeated blocked flows and first-seen app traffic | PASS (JVM harness) · emulator render PASS |
| X-02 | Deduplication and bounded incident count | PASS (JVM harness) |
| X-03 | Recommendation is a hint, never an automatic action | PASS (JVM harness) |
| X-04 | Empty state when no local observations exist | PASS (emulator) |

### V2.1 Outbound Kinetic-Lite and containment

| ID | Check | Status |
| --- | --- | --- |
| K-01 | Each anomaly rule fires only above its threshold (negative tests included) | PASS (JVM harness) |
| K-02 | Observe-only by default: no containment without opt-in | PASS (JVM harness) |
| K-03 | Containment only in Strict profile; destination prefixes only, never apps | PASS (JVM harness) |
| K-04 | Guardrails: ≥2 independent signals, min score, known country, max 4 active, protected packages and platform/CDN allowlists | PASS (JVM harness) |
| K-05 | TTL clamp (1–30 min), automatic expiry and manual release | PASS (JVM harness) |
| K-06 | Reversible TV popup with Undo; block lifts after undo | PASS (emulator screenshot evidence) |
| K-07 | Containment survives app restart? | NOT RUN |

### Threat-intelligence sync

| ID | Check | Status |
| --- | --- | --- |
| TI-01 | Sync overlay shows progress and is D-pad-safe | PASS (emulator screenshot evidence) |
| TI-02 | Failure/stale state is honest and retryable | NOT RUN (network failure injection) |
| TI-03 | Feeds are fetched over HTTPS only | Static review PASS |

### Evidence, report, export

| ID | Check | Status |
| --- | --- | --- |
| E-01 | Evidence ledger HMAC chain validates; tampering is detected | PASS (JVM harness) |
| E-02 | Export produces text + JSON on user action | PASS (emulator; V1 run) |
| E-03 | Fallback export path without storage permission | PASS (emulator, V1 run) |
| E-04 | Delete evidence requires confirmation | PASS (emulator, V1 run) |

### Privacy and platform

| ID | Check | Status |
| --- | --- | --- |
| P-01 | Manifest declares only the documented permissions | PASS (static) |
| P-02 | No analytics/ads/crash SDK, no upload of traffic/evidence | PASS (static + SBOM review) |
| P-03 | `allowBackup=false`, cleartext disabled, system trust anchors only | PASS (static) |
| P-04 | No location/GPS usage; origin from locale/network | PASS (static) |

### Localization

| ID | Check | Status |
| --- | --- | --- |
| L-01 | Six complete locale resource sets (default/English, de, fr, ru, zh-CN, ja) | PASS (`tools/check_translations.py`) |
| L-02 | UI follows system language; screenshots for each locale | PASS (emulator, `docs/screenshots/languages/`) |
| L-03 | Placeholders and XML escaping valid | PASS (checker) |

### Performance, hardware, release

| ID | Check | Status |
| --- | --- | --- |
| PF-01 | Cold start on emulator within the project budget | PASS (project evidence, V1/V2 emulator runs) |
| PF-02 | VPN throughput, battery and thermal behaviour | NOT RUN |
| HW-01 | ≥ 2 real TV OEM profiles (remote, launcher, Always-On) | NOT RUN |
| REL-01 | Release APK builds and installs (R8) | PASS (alpha build) |
| REL-02 | Production signing key and store review | NOT RUN — alpha is test-signed |
| REL-03 | Independent security review | NOT RUN |

## Exit criteria for the public alpha

The alpha may be published when: the release tree passes `tools/verify_release_tree.py`; the JVM
harnesses pass; the app builds and starts on the Android TV emulator; the README documents the
verification gaps and limitations honestly; and the APK is clearly marked as test-signed alpha.

For a production release, additionally required: real TV hardware verification, an independent
security review, production signing, and a completed functional matrix including the `NOT RUN` items
above.
