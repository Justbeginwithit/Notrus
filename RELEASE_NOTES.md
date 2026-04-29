# Notrus Release Notes

## Unreleased

- No changes yet.

## v0.3.4-beta5 (draft security and reliability beta)

Release date: 2026-04-30

This draft beta release focuses on Android notification reliability, durable
local message/session persistence, account recovery and chat-backup handling,
archived-chat behavior, and refreshed Android/macOS artifacts. It also prepares
F-Droid-compatible metadata without claiming that Notrus is audited, anonymous,
or proven secure.

### Included artifacts

- macOS:
  - `dist/Notrus.app`
  - `dist/Notrus.zip`
  - `dist/Notrus-0.3.4-beta5.zip`
- Android:
  - `dist/android/Notrus-debug.apk`
  - `dist/android/Notrus-release.apk`
  - `dist/android/Notrus-0.3.4-beta5-debug.apk`
  - `dist/android/Notrus-0.3.4-beta5-release.apk`

### Security and privacy fixes

- Made Android notification preview decrypt non-committing, so background
  notification rendering cannot silently advance local secure-message session
  state before the foreground chat has durably cached the plaintext.
- Persist Android relay message wire-envelope metadata into the encrypted vault
  before notification acknowledgement/bookkeeping, preserving durable local
  ciphertext for later foreground materialization.
- Hardened Android sync/materialization so cached local plaintext is preserved
  when sync ordering, relay retention, or app updates change message counters.
- Changed Android foreground sync ordering so notification baseline state is
  written only after thread/session materialization has been persisted.
- Switched encrypted Android vault writes used by the notification/session path
  to synchronous commits before dependent notification bookkeeping continues.
- Fixed safety-number verification recovery on Android and macOS so verifying
  a changed contact identity preserves readable local chat history and refreshes
  secure-session material instead of deleting direct-thread records.
- Fixed Android archive-state merge behavior so restoring a chat clears the old
  `hiddenAt` state across later manual syncs and newly reopened direct chats.
- Kept notification content hidden by default; sender/preview modes still render
  only after local sync and local decrypt.

### Android background notifications

- Added a foreground `dataSync` background delivery service for the Android client. When Reliable background delivery is enabled, Notrus keeps an authenticated relay event listener alive and Android shows a persistent low-priority service notification.
- Kept WorkManager as the fallback path with periodic, rolling, and expedited sync jobs.
- Added boot/package-replaced rescheduling so notification workers and the optional background listener are restored after reboot or app update.
- Added a Settings toggle for Reliable background delivery.
- Kept hidden notification content as the default. Sender and preview modes still render only after local sync/decrypt.
- Improved notification dedupe so messages are marked notified only after a notification is actually posted, reducing missed-notification cases after permission or channel failures.
- Fixed a background-preview state bug where Android notification preview decrypt could advance local secure-message state before the foreground chat had cached the plaintext. Background preview decrypt is now non-committing, so opening the chat can still decrypt/cache the message normally.
- Persist relay message wire-envelope metadata into the encrypted Android vault before posting or acknowledging notification delivery, so notification-received messages have durable local ciphertext state for later foreground materialization.
- Hardened Android chat materialization so cached local plaintext is preserved when sync order/count changes across app updates or relay retention changes.
- Changed Android foreground sync ordering so notification seen/baseline state is written only after thread/session materialization has been persisted.
- Switched encrypted Android vault saves to synchronous commits so state writes complete before dependent notification bookkeeping continues.
- Replaced user-facing “Signal message” wording with Notrus/secure-message wording in Android error notices.

### Android chat management and UX

- Added Android archived chats, restore, mute, local conversation deletion, and
  single-message local deletion flows.
- Added Android read receipts with a user setting to turn them off for others.
- Added Android version/build identifiers in the app so repeated rebuilds of the
  same version are easier to distinguish during testing.
- Added Android About/settings surfaces with project and version information.
- Fixed the Android archived-chat regression where restored chats went back into
  Archived after manual sync, and deleted/recreated direct chats inherited old
  archive state.

### macOS recovery/import

- Fixed macOS Account Center import handling by using one mode-aware file importer for account recovery and encrypted chat backup.
- Added security-scoped file access while importing macOS recovery archives and chat backups, improving Finder/file-picker compatibility.
- Fixed safety-number verification recovery so Android and macOS preserve readable local chat history instead of deleting direct-thread records when a contact identity changes after account import/reset.
- Fixed Android archive-state persistence so restored chats stay restored after manual sync, and newly reopened direct chats no longer fall back into Archived because of an old `hiddenAt` timestamp.
- Documented the supported recovery sequence: import account recovery first, restore encrypted chat backup second, sync both clients, verify any security-number change, then use Reset secure session only if sending still fails.

### F-Droid preparation

- Added draft F-Droid metadata for `com.notrus.android`.
- Added Fastlane-compatible Android listing metadata and changelogs.
- Documented F-Droid build verification, screenshot location, dependency audit
  scope, and conservative security wording.
- Kept the F-Droid metadata disabled until a matching public release tag exists
  and the fdroiddata signing/build recipe is finalized.

### Verification

- `cd native/android/NotrusAndroid && ./gradlew clean assembleRelease`
- `./gradlew testDebugUnitTest`
- `npm run test:mac-app`
- `npm run test:client-surfaces`
- `npm run package:android-app`
- `npm run package:mac-app`
- F-Droid YAML parse and required-field check

### Remaining validation boundary

- Emulator validation passed, but physical-device closed-app/OEM battery behavior still needs device testing before this should be called fully production-reliable.
- This release is still a beta, not a stable or externally audited release.

## v0.3.3-beta4 (previous beta security release)

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
