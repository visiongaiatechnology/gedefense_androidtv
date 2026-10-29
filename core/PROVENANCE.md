# Core module provenance

This directory is a byte-identical copy of the dependency-free GeDefense core module from:

- Source dossier: `GeDefense/Mobile/0.28.0-beta1/Source/core`
- Product version: `0.28.0-beta1`
- Version code: `59`
- Copy date: 2026-10-29 (Europe/Berlin)
- Copy policy: verbatim (files, tests, package names unchanged). No file in this directory was modified.

Rationale: GeDefense TV must reuse the audited evidence, threat-intelligence and crypto
building blocks of GeDefense Mobile instead of forking them. The TV app depends on this module
only through its public API.

Verification: `tools/verify-source-fidelity.ps1` re-computes the SHA-256 of every file in this
directory against `SOURCE-MANIFEST.sha256`. A mismatch means the shared core was modified, which
is a release blocker until the provenance record is updated deliberately.

Upstream maintenance rule: changes to the core must be made in the mobile source first, verified
there, and then re-imported as a whole directory together with a refreshed manifest. Never patch
the copy in place.
