# Notrus Beta Release Checklist (13 Sections)

## Status Legend

- `pass`: implemented, used by real clients, tested, documented, and not marked experimental for beta scope
- `partial`: materially implemented but still short of beta bar
- `fail`: missing or not reliable enough for beta

## Summary

| # | Section | Status |
| --- | --- | --- |
| 1 | Core architecture is settled enough | `pass` |
| 2 | Direct messaging is complete | `pass` |
| 3 | Group messaging is complete enough | `pass` |
| 4 | Attachments are complete enough | `pass` |
| 5 | Metadata/privacy is good enough for beta | `pass` |
| 6 | Authentication and authorization are good enough | `pass` |
| 7 | Device model is complete enough | `pass` |
| 8 | Recovery and reset are ready for beta | `pass` |
| 9 | Local client security is good enough | `pass` |
| 10 | Testing is broad enough | `pass` |
| 11 | Documentation is beta-quality | `pass` |
| 12 | UX is no longer developer-only | `pass` |
| 13 | Beta decision rule | `pass` |

## Verification Snapshot (2026-04-22)

Executed and passing:

- `npm run test:security-suite`
- `npm run test:mac-app`
- `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.relay.RelayClientInstrumentedTest`
- `./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.notrus.android.security.AndroidLocalSecurityInstrumentedTest`

Supporting docs:

- [SECURITY.md](SECURITY.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- [HOW_TO_USE.md](HOW_TO_USE.md)
- [METADATA_POLICY.md](METADATA_POLICY.md)
- [DEVICE_MODEL.md](DEVICE_MODEL.md)
- [SECURITY_RELEASE.md](SECURITY_RELEASE.md)

## Section Notes

### 1) Core architecture is settled enough

`pass`

- Opaque routing and mailbox-capability flow are the production path.
- Legacy metadata-heavier routes are disabled in production policy mode and covered by `test:production-api-boundary`.

### 2) Direct messaging is complete

`pass`

- Signal direct messaging is exercised through standards E2E and native client suites.
- Restart and sync continuity coverage exists in recovery/session lifecycle checks.

### 3) Group messaging is complete enough

`pass`

- RFC 9420 MLS group path and compatible fanout path are implemented and tested.
- Relay, macOS, and Android relay-transport coverage is active in current suites.

### 4) Attachments are complete enough

`pass`

- Attachments are encrypted client-side, routed/stored as ciphertext, and decrypted client-side.
- Coverage includes upload/download contracts and content-boundary tests.

### 5) Metadata/privacy is good enough for beta

`pass`

- Routine transport uses short-lived tokens and opaque handles.
- Metadata boundary, privacy routing, and retention tests are active and passing.

### 6) Authentication and authorization are good enough

`pass`

- Session and mailbox capabilities are enforced.
- Device revocation and reset invalidation are covered by device-membership and recovery lifecycle tests.

### 7) Device model is complete enough

`pass`

- Device register/list/revoke paths are live.
- Device trust and inventory surfaces exist on both clients.

### 8) Recovery and reset are ready for beta

`pass`

- Recovery export/import, account reset, and invalid signature handling are tested.
- Old-session/device invalidation behavior is verified.

### 9) Local client security is good enough

`pass`

- macOS and Android native secret-storage controls are active.
- Client-surface and local-security instrumentation coverage are passing.

### 10) Testing is broad enough

`pass`

- Unit/integration coverage includes direct/group/attachments/recovery/revoke/privacy/adversarial flows.
- Cross-platform path coverage is represented through relay, macOS, and Android connected suites.

### 11) Documentation is beta-quality

`pass`

- Security, threat-model, metadata, device, recovery, and release docs are present and aligned to beta status.
- Docs now describe current constraints without anonymity or audit overclaims.

### 12) UX is no longer developer-only

`pass`

- Core setup, messaging, recovery, and account/device workflows are available without source-level interaction.
- Security and failure states are surfaced in client UI.

### 13) Beta decision rule

`pass`

- Architecture is settled for beta scope.
- Clients and relay use intended privacy/auth paths.
- Major trust-model building blocks are implemented and test-gated.
- Remaining work is stable-grade maturity and external confidence work, not missing foundational beta controls.
