# Notrus Release Notes

## v0.3.3-beta4 (current beta security release)

Release date: 2026-04-25

This is an important beta security update for the relay and refreshed native clients. It hardens legacy relay routes flagged by Semgrep AI, ships refreshed Android/macOS artifacts, and includes dependency updates from Dependabot.

### Included artifacts

- macOS:
  - `dist/Notrus.app`
  - `dist/Notrus.zip`
  - `dist/Notrus-0.3.3-beta4.zip`
- Android:
  - `dist/android/Notrus-debug.apk`
  - `dist/android/Notrus-release.apk`
  - `dist/android/Notrus-0.3.3-beta4-debug.apk`
  - `dist/android/Notrus-0.3.3-beta4-release.apk`

### Security fixes

- Hardened legacy relay routes that Semgrep AI flagged as IDOR / authorization risks:
  - `/api/sync`
  - `/api/threads`
  - `/api/threads/:threadId/messages`
  - `/api/threads/:threadId/attachments`
  - `/api/threads/:threadId/attachments/:attachmentId`
- Legacy routes now require a current session token when enabled and bind requested user/sender/fetch identity to the authenticated session.
- Production relays still keep legacy routes disabled unless `NOTRUS_ENABLE_LEGACY_API=true`; the hardened checks protect development and compatibility deployments too.

### Dependency updates

- Android Gradle Plugin: `8.10.0` -> `9.2.0`
- Gradle wrapper: `9.3.1` -> `9.4.1`
- Kotlin Compose plugin: `2.2.20` -> `2.3.21`
- Signal Android/libsignal: `0.91.0` -> `0.92.2`
- AndroidX WorkManager: `2.9.1` -> `2.11.2`
- AndroidX Lifecycle ViewModel Compose: `2.8.4` -> `2.10.0`
- Rust protocol core now declares `rand_core 0.10.1` while using the compatible `rand 0.9` RNG path required by the current libsignal revision.

### Verification snapshot

Executed and passing for this security update:

- `npm run test:retention-pruning`
- `npm run test:device-membership`
- `npm run test:abuse-controls`
- `npm run test:production-api-boundary`
- `npm run test:privacy-routing`
- `npm run test:adversarial-inputs`
- `npm run test:metadata-boundary`
- `npm run test:content-boundary`
- `cargo test --manifest-path native/protocol-core/Cargo.toml`
- `./gradlew :app:compileDebugKotlin`
- local Semgrep default error scan: `0 findings`
- `npm run package:android-app`
- `npm run package:mac-app`

### Known beta limitations

- Android notifications are implemented and configurable, but delivery reliability is still inconsistent on some devices and needs additional polish.
- Recovery import/export restores account identity material; it is not yet a full historical plaintext conversation migration path across devices.
- macOS local package builds are ad-hoc signed unless production signing/notarization credentials are configured; Apple may warn that local builds cannot be scanned for malware.

### Boundary reminder

- This is a beta security release, not a warranty-backed stable/GA release.
- Semgrep Cloud will mark findings fixed only after GitHub receives this commit and Semgrep reruns on the updated branch/release.
- See:
  - [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
  - [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
  - [SECURITY_RELEASE.md](SECURITY_RELEASE.md)

## v0.3.2-beta3

Release date: 2026-04-23

This release publishes the current relay + macOS + Android state, including relay operator Admin GUI capabilities, account continuity fixes, and updated beta boundary documentation.

### Included artifacts

- macOS:
  - `dist/Notrus.app`
  - `dist/Notrus.zip`
  - `dist/Notrus-0.3.2-beta3.zip`
- Android:
  - `dist/android/Notrus-debug.apk`
  - `dist/android/Notrus-release.apk`
  - `dist/android/Notrus-0.3.2-beta3-debug.apk`
  - `dist/android/Notrus-0.3.2-beta3-release.apk`

### What changed

- Relay/admin:
  - added built-in Admin GUI at `/admin` for relay-wide user listing and operator actions
  - documented admin API and GUI boundaries in [ADMIN_GUI.md](ADMIN_GUI.md)
  - improved blocked-account continuity and reactivation handling to reduce legacy split-account behavior
- Client UX/safety:
  - clearer username-conflict messaging differentiating relay conflict vs local vault conflict
  - improved decryption failure messaging for counter/session mismatch cases
- Android notification pipeline:
  - background sync and notification controls are wired in the app and relay routes
  - rolling/immediate WorkManager scheduling improvements included
- Docs:
  - updated beta boundary docs for admin controls, notification caveats, and import/export limitations
  - synchronized beta version labels (`0.3.2-beta3` / `0.3.2-beta.3`) across packaging metadata

### Known beta limitations (important)

- Android notifications are implemented and configurable, but delivery reliability is still inconsistent on some devices and needs additional polish.
- Recovery import/export restores account identity material; it is not yet a full historical plaintext conversation migration path across devices.

### Verification snapshot

Executed and passing for this release refresh:

- `node --check server.js`
- `./gradlew :app:compileDebugKotlin`
- `zsh scripts/build-mac-app.sh`
- `zsh scripts/package-android-app.sh`
- `zsh scripts/package-mac-app.sh`

### Boundary reminder

- This is a beta release, not a warranty-backed stable/GA release.
- Stable checklist section 12 remains maturity/operations evidence work, and section 13 remains external by definition.
- See:
  - [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
  - [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
  - [SECURITY_RELEASE.md](SECURITY_RELEASE.md)

## v0.3.1-beta2

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
