# Notrus Stable Release Checklist (13 Sections)

## Status legend

- `pass`: implemented, tested, used in current native clients, and documented
- `partial`: significant controls exist, but one or more stable-grade conditions are still open
- `external`: requires independent outside process, not repository-only work

## Summary

| # | Section | Status |
| --- | --- | --- |
| 1 | Core architecture is finished | `pass` |
| 2 | End-to-end encryption is complete on real clients | `pass` |
| 3 | Metadata reduction is finished enough for stable | `pass` |
| 4 | Authentication and authorization are consistent | `pass` |
| 5 | Device and recovery model is complete | `pass` |
| 6 | Local client security is complete | `pass` |
| 7 | Release and update trust is finished | `pass` |
| 8 | Security testing is strong enough for stable | `pass` |
| 9 | Operational safety is stable | `pass` |
| 10 | Documentation is honest and complete | `pass` |
| 11 | Client UX is stable enough for real users | `pass` |
| 12 | Real-world maturity threshold | `partial` |
| 13 | Optional confidence boosters | `external` |

## 1) Core architecture is finished

Status: `pass`

Evidence:
- Opaque routing path is active and used by both native clients: `/api/sync/state`, `/api/routing/threads`, mailbox capability routes in [server.js](server.js), [RelayClient.swift](native/macos/NotrusMac/Sources/RelayClient.swift), and [RelayClient.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/relay/RelayClient.kt).
- Legacy metadata-heavier `/api/sync` and `/api/threads` are now dev-only by default and disabled when `NODE_ENV=production`, with explicit enforcement in [server.js](server.js).
- Production enforcement is verified in [test-production-api-boundary.mjs](scripts/test-production-api-boundary.mjs).

Re-verify:
- `npm run test:production-api-boundary`
- `npm run test:privacy-routing`

## 2) End-to-end encryption is complete on real clients

Status: `pass`

Evidence:
- Direct Signal path and encrypted attachment routing work in both native clients and relay tests.
- Standards MLS group path remains validated in strict production policy mode via [test-standards-e2e.mjs](scripts/test-standards-e2e.mjs).
- Cross-client compatible group transport for standards threads is implemented in both native clients:
  - Android group fanout send/receive in [NotrusViewModel.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusViewModel.kt) and relay transport support in [RelayClient.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/relay/RelayClient.kt).
  - macOS compatibility send/receive and compose fallback in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift).
- Compatibility envelope round-trip is verified in [test-mls-fanout-compat.mjs](scripts/test-mls-fanout-compat.mjs), and Android relay transport instrumentation coverage is in [RelayClientInstrumentedTest.kt](native/android/NotrusAndroid/app/src/androidTest/java/com/notrus/android/relay/RelayClientInstrumentedTest.kt).

Re-verify:
- `npm run test:standards-e2e`
- `npm run test:mls-fanout-compat`
- `npm run test:mac-app`
- `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.relay.RelayClientInstrumentedTest` (from `native/android/NotrusAndroid`)

## 3) Metadata reduction is finished enough for stable

Status: `pass`

Evidence:
- Opaque contact handles, mailbox routing, tokenized routine requests, and minimized routine sync surface are implemented and tested in [server.js](server.js), [test-metadata-boundary.mjs](scripts/test-metadata-boundary.mjs), and [test-privacy-routing.mjs](scripts/test-privacy-routing.mjs).

Re-verify:
- `npm run test:metadata-boundary`
- `npm run test:privacy-routing`

## 4) Authentication and authorization are consistent

Status: `pass`

Evidence:
- Session capabilities and mailbox capabilities are enforced per request.
- Revoked devices invalidate session/mailbox access.
- Device revoke requires signed requests.
- Abuse-report submission now requires authenticated relay session ownership and blocks spoofed reporter IDs in [server.js](server.js).
- Coverage in [test-device-membership.mjs](scripts/test-device-membership.mjs) and relay authorization code in [server.js](server.js).

Re-verify:
- `npm run test:device-membership`
- `npm run test:abuse-controls`

## 5) Device and recovery model is complete

Status: `pass`

Evidence:
- Linked-device enroll/list/revoke/reset paths exist and are enforced.
- Recovery-authorized account reset, old-session invalidation, active-device rollover, and username rebinding after delete are verified in [test-recovery-lifecycle.mjs](scripts/test-recovery-lifecycle.mjs).
- macOS recovery archive/import/transfer and account portability tests exist in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift), including Android transfer archive import coverage.
- Android recovery archive round-trip, wrong-passphrase rejection, and recovery-authority rebuild checks run in [AndroidLocalSecurityInstrumentedTest.kt](native/android/NotrusAndroid/app/src/androidTest/java/com/notrus/android/security/AndroidLocalSecurityInstrumentedTest.kt).

Re-verify:
- `npm run test:recovery-lifecycle`
- `npm run test:mac-app`
- `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.security.AndroidLocalSecurityInstrumentedTest` (from `native/android/NotrusAndroid`)

## 6) Local client security is complete

Status: `pass`

Evidence:
- Platform-native secret handling, biometric gating, attachment encryption, backup restrictions, and boundary checks are implemented.
- Coverage in [test-client-surfaces.mjs](scripts/test-client-surfaces.mjs), [AndroidLocalSecurityInstrumentedTest.kt](native/android/NotrusAndroid/app/src/androidTest/java/com/notrus/android/security/AndroidLocalSecurityInstrumentedTest.kt), and macOS security tests.

## 7) Release and update trust is finished

Status: `pass`

Evidence:
- Production release governance gate with two-reviewer artifact check in [verify-release-governance.mjs](scripts/verify-release-governance.mjs).
- macOS production packaging blocks unsigned/unnotarized release mode in [package-mac-app.sh](scripts/package-mac-app.sh).
- Android production packaging blocks debug signing and missing external keystore credentials in [package-android-app.sh](scripts/package-android-app.sh) and [build.gradle.kts](native/android/NotrusAndroid/app/build.gradle.kts).

Re-verify:
- `npm run test:release-governance`
- `NOTRUS_RELEASE_MODE=production zsh scripts/package-mac-app.sh` (must fail without release approvals/signing inputs)
- `NOTRUS_RELEASE_MODE=production zsh scripts/package-android-app.sh` (must fail without release approvals/signing inputs)

## 8) Security testing is strong enough for stable

Status: `pass`

Evidence:
- Security suite now runs content boundary, metadata/privacy routing, production API boundary, standards E2E, MLS-compatible fanout interoperability, recovery lifecycle, retention, abuse controls, attestation enforcement, and device membership in [test-security-suite.mjs](scripts/test-security-suite.mjs).
- Standards direct and native MLS protocol flow remains verified in [test-standards-e2e.mjs](scripts/test-standards-e2e.mjs).
- Standards-thread compatible group fanout flow is verified in [test-mls-fanout-compat.mjs](scripts/test-mls-fanout-compat.mjs).
- macOS checkpoint coverage includes compose fallback behavior and local security/state controls in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).
- Android connected instrumentation covers relay routing and message transport contracts (including MLS bootstrap parsing and MLS message posting) in [RelayClientInstrumentedTest.kt](native/android/NotrusAndroid/app/src/androidTest/java/com/notrus/android/relay/RelayClientInstrumentedTest.kt).

Re-verify:
- `npm run test:security-suite`
- `npm run test:mac-app`
- `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.relay.RelayClientInstrumentedTest` (from `native/android/NotrusAndroid`)

## 9) Operational safety is stable

Status: `pass`

Evidence:
- TLS policy, localhost-only HTTP model, bounded logging intent, retention pruning, rate limiting, and PoW abuse controls are implemented.
- Verification scripts: [test-retention-pruning.mjs](scripts/test-retention-pruning.mjs), [test-abuse-controls.mjs](scripts/test-abuse-controls.mjs), plus relay health exposure in [server.js](server.js).

## 10) Documentation is honest and complete

Status: `pass`

Evidence:
- Threat model, crypto spec, metadata policy, integrity policy, release-security model, and external-audit process are documented in:
  - [THREAT_MODEL.md](THREAT_MODEL.md)
  - [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
  - [METADATA_POLICY.md](METADATA_POLICY.md)
  - [INTEGRITY_POLICY.md](INTEGRITY_POLICY.md)
  - [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
  - [EXTERNAL_AUDIT.md](EXTERNAL_AUDIT.md)

## 11) Client UX is stable enough for real users

Status: `pass`

Evidence:
- Core messaging/account/security workflows are present and usable across native clients, including direct messaging, standards-group compatibility flow, and local profile operations.
- Android conversation UX now reflects protocol-specific readiness (direct vs group), auto-dismisses transient status surfaces, and keeps security warnings persistent/actionable in [NotrusAndroidApp.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusAndroidApp.kt) and [NotrusViewModel.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusViewModel.kt).
- macOS compose UX no longer hard-blocks group creation when contacts lack native MLS key packages; it transparently uses compatible standards-group fanout mode, covered by [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).
- Local account/profile cleanup flows remain available on both clients (delete local profile/contact/thread behaviors in current client models and view models).

Re-verify:
- `npm run test:mac-app`
- `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.relay.RelayClientInstrumentedTest` (from `native/android/NotrusAndroid`)

## 12) Real-world maturity threshold

Status: `partial`

Evidence:
- Major trust-model controls are implemented and repeatedly tested in repo.

Open work:
- This section requires broader sustained real-world operation evidence and issue-closure history beyond local repository checks.

## 13) Optional confidence boosters

Status: `external`

Evidence:
- External audit/review, independent testing, and public disclosure process maturity remain outside code-only completion and are tracked in [EXTERNAL_AUDIT.md](EXTERNAL_AUDIT.md).

## Current gate

Notrus can be described as **stable in repository-controlled sections**, with remaining maturity work tracked explicitly.

To claim full stable under this 13-section bar, section `12` still needs sustained real-world operational history, and section `13` remains external by definition.
