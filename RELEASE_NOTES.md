# Notrus Release Notes

## v0.3.1-beta2 (current beta release)

Release date: 2026-04-22

This release ships refreshed native artifacts for both macOS and Android, clarifies attestation posture and setup, and fixes linked-device and layout issues reported during beta validation.

### Included artifacts

- macOS:
  - `dist/Notrus.app`
  - `dist/Notrus.zip`
  - `dist/Notrus-0.3.1-beta2.zip`
- Android:
  - `dist/android/Notrus-debug.apk`
  - `dist/android/Notrus-release.apk`
  - `dist/android/Notrus-0.3.1-beta2-debug.apk`
  - `dist/android/Notrus-0.3.1-beta2-release.apk`

### What changed

- macOS UI polish pass:
  - removed warm/brown cast from the current visual palette
  - fixed clipping/readability in account inventory rows (including long device identifiers)
  - rebalanced compose/new-thread and account-center sheet sizing to prevent left/right text cutoff
- Android linked-device fixes:
  - sanitized `"null"` / `"nil"` / `"undefined"` values in relay device payload rendering
  - improved fallback labels for missing device fields
  - explicit message when the current device is already marked revoked on relay state
- release/docs pass:
  - synchronized beta version labels (`0.3.1-beta2` / `0.3.1-beta.2`) across packaging and Android app metadata
  - added explicit attestation-state and enablement documentation for relay operators
  - updated usage and roadmap docs to include attestation deployment posture

### Attestation state in this release

- Default relay behavior is unchanged:
  - attestation verification is supported, but not enforced unless explicitly configured
  - without configuration, relay health reports `attestation.configured: false`
- Full setup and enforcement instructions are documented in:
  - [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md)

### Verification snapshot

Executed and passing for this release refresh:

- `npm run test:mac-app`
- `./gradlew :app:compileDebugKotlin` (Android)
- `npm run test:attestation-service`
- `npm run test:attestation-enforcement`
- `npm run package:android-app`
- `npm run package:mac-app`

### Boundary reminder

- This is a beta release, not a warranty-backed stable/GA release.
- Stable checklist section 12 remains maturity/operations evidence work, and section 13 remains external by definition.
- See:
  - [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
  - [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
  - [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
