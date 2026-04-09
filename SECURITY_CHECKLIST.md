# Notrus 25-Point Security Checklist

## Status legend

- `pass`: implemented to the intended bar in this repository and tied to concrete verification
- `partial`: some controls exist, but the item is not at the stated bar
- `fail`: not implemented, or implemented in a way that does not satisfy the checkpoint
- `external`: cannot be honestly closed without an outside process such as audit or assessment

## Verification rule

Each item below should be re-verified with one or more of:

- code review against the referenced files
- automated tests
- runtime checks
- manual device validation
- external review

## Summary

| # | Area | Status |
| --- | --- | --- |
| 1 | Threat model first | `pass` |
| 2 | Real protocol, not custom | `pass` |
| 3 | Current standard crypto only | `pass` |
| 4 | Verifiable identity | `pass` |
| 5 | Full key lifecycle | `pass` |
| 6 | Platform-native secret storage | `pass` |
| 7 | Biometrics are convenience only | `pass` |
| 8 | Backup model does not break security | `pass` |
| 9 | Hardened transport security | `pass` |
| 10 | Untrusted server for content | `pass` |
| 11 | Metadata minimization | `pass` |
| 12 | Privacy-safe push notifications | `pass` |
| 13 | Secure multi-device model | `pass` |
| 14 | Real group protocol | `pass` |
| 15 | Device integrity signals | `pass` |
| 16 | App sandbox and inter-app boundaries | `pass` |
| 17 | Secure attachment handling | `pass` |
| 18 | Memory safety and strict parsing | `pass` |
| 19 | Supply-chain security | `partial` |
| 20 | Secure UX defaults | `pass` |
| 21 | Minimal logging and telemetry | `pass` |
| 22 | Abuse controls | `pass` |
| 23 | Adversarial testing | `pass` |
| 24 | External audit | `external` |
| 25 | Platform-specific must-haves | `partial` |

## 1. Threat model first

Status:
`pass`

What exists:
- Threat boundaries, assets, adversaries, goals, and non-goals are documented in [THREAT_MODEL.md](THREAT_MODEL.md).
- The mapped device and integrity assumptions now live in [DEVICE_MODEL.md](DEVICE_MODEL.md) and [INTEGRITY_POLICY.md](INTEGRITY_POLICY.md).
- The minimum bar in the threat model now maps to concrete code, runtime proofs, and packaging/CI evidence across the repo, with external audit still tracked separately in item 24 rather than hand-waved away.

Re-verify with:
- review [THREAT_MODEL.md](THREAT_MODEL.md)
- ensure each claim maps to code, tests, runtime checks, or external review

## 2. Pick a real protocol, not a custom one

Status:
`pass`

What exists:
- The active native standards core now uses the official Signal stack for direct messaging and OpenMLS for groups in [Cargo.toml](native/protocol-core/Cargo.toml), [bridge.rs](native/protocol-core/src/bridge.rs), and [main.rs](native/protocol-core/src/main.rs).
- The macOS app now creates new 1:1 threads as `signal-pqxdh-double-ratchet-v1` and new group threads as `mls-rfc9420-v1` in [ProtocolCatalog.swift](native/macos/NotrusMac/Sources/ProtocolCatalog.swift) and [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift).
- The relay now stores and routes Signal wire messages and MLS wire messages, plus user-scoped MLS welcomes, in [server.js](server.js) and [protocol-policy.js](protocol-policy.js).
- Experimental Notrus protocols remain in the repo only as explicit migration paths. The relay defaults to `require-standards`, and strict mode rejects legacy protocol creation/posting by default.

Re-verify with:
- run `cargo test --manifest-path native/protocol-core/Cargo.toml` and confirm the official Signal direct round-trip plus the MLS group round-trip pass
- run `NOTRUS_E2E_USE_EXISTING_RELAY=true NOTRUS_E2E_RELAY_ORIGIN=http://127.0.0.1:3002 npm run test:standards-e2e` against a strict relay and confirm:
  - experimental protocol creation is rejected
  - Signal direct messages round-trip
  - MLS group messages round-trip
  - MLS welcomes are scoped per recipient
- run `swift build --package-path native/macos/NotrusMac` and `zsh scripts/package-mac-app.sh` to confirm the native app and bundled helper are aligned on the same standards stack

## 3. Use current, standard crypto only

Status:
`pass`

What exists:
- The production path now uses audited libraries only: Signal's official `libsignal-protocol` and OpenMLS in [Cargo.toml](native/protocol-core/Cargo.toml).
- Exact backend versions, upstream revision pins, ciphersuite choice, message-layer versus transport-layer roles, and serialization rules are documented in [CRYPTO_SPEC.md](CRYPTO_SPEC.md).
- The runtime snapshot in [lib.rs](native/protocol-core/src/lib.rs) exposes the pinned Signal revision, OpenMLS versions, ciphersuite, encoding rules, and minimum transport target.
- Fixed replay vectors exist in [signal-direct-v1.json](native/protocol-core/test-vectors/signal-direct-v1.json) and [mls-group-v1.json](native/protocol-core/test-vectors/mls-group-v1.json), with generation scripted in [generate-crypto-vectors.mjs](scripts/generate-crypto-vectors.mjs).
- The replay tests in [lib.rs](native/protocol-core/src/lib.rs) verify exact wire-message replay, stable state semantics, and continued session usability after replay.

Notes:
- The persisted libsignal session blob is treated as an opaque storage artifact, not as a canonical byte-for-byte vector surface. The documented contract pins the wrapper encoding and stable semantics, while the replay tests validate fresh post-replay usability.

Re-verify with:
- run `npm run generate:crypto-vectors`
- run `cargo test --manifest-path native/protocol-core/Cargo.toml`
- review [CRYPTO_SPEC.md](CRYPTO_SPEC.md) and confirm it still matches [lib.rs](native/protocol-core/src/lib.rs) and [Cargo.toml](native/protocol-core/Cargo.toml)
- confirm the production path still treats TLS as transport-only in [CRYPTO_SPEC.md](CRYPTO_SPEC.md)

## 4. Identity has to be verifiable

Status:
`pass`

What exists:
- The native macOS client now keeps an encrypted per-profile contact-trust store in [SecurityStateStore.swift](native/macos/NotrusMac/Sources/SecurityStateStore.swift).
- First contact is explicitly marked `unverified`, and the UI exposes safety-number review plus verification actions in [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift) and [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift).
- Contact key changes now create visible security events, block changed keys from silently becoming trusted, and require out-of-band re-verification before trust is restored.
- Transparency checks and witness observations still back the relay directory view.
- Native checkpoint tests now cover the local contact-trust state machine, including first-contact `Unverified` state and visible `Changed` state on identity-key replacement, in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).

Re-verify with:
- run `swift test --package-path native/macos/NotrusMac`
- review contact verification and security-event handling in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift) and [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift)
- confirm first contact shows `Unverified` and changed contacts show `Changed` in the native UI

## 5. Key lifecycle is half the product

Status:
`pass`

What exists:
- Explicit owner, purpose, storage, rotation, recovery, and destruction rules are documented in [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md).
- Signal prekey bundles refresh during registration in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift) and [bridge.rs](native/protocol-core/src/bridge.rs).
- Recovery-authorized account reset exists on the native client and relay in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift), [NotrusCrypto.swift](native/macos/NotrusMac/Sources/NotrusCrypto.swift), and [server.js](server.js).
- Local thread-state rollback is rejected by monotonic generation tracking in [ThreadStateStore.swift](native/macos/NotrusMac/Sources/ThreadStateStore.swift) and [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift).
- Re-verifying a changed direct contact clears stale local Signal session state through the standards core bridge instead of reusing superseded keys.
- Native checkpoint tests now cover recovery-authority preservation during identity rotation plus rollback rejection for local thread state in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).

Re-verify with:
- review [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md)
- run `cargo test --manifest-path native/protocol-core/Cargo.toml`
- run `swift test --package-path native/macos/NotrusMac`

## 6. Local secret storage must be platform-native

Status:
`pass`

What exists:
- The native macOS production path now uses a device-only Keychain secret with LocalAuthentication gating in [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift).
- The local identity catalog, contact-verification state, and thread-state store are encrypted at rest through native stores in [IdentityStore.swift](native/macos/NotrusMac/Sources/IdentityStore.swift), [SecurityStateStore.swift](native/macos/NotrusMac/Sources/SecurityStateStore.swift), and [ThreadStateStore.swift](native/macos/NotrusMac/Sources/ThreadStateStore.swift).
- Exportability decisions are explicit in [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md): generic local state is device-only, while recovery archives are deliberate and user-held.
- Existing encrypted local stores now require the original vault key and surface a specific recovery error when that key is missing, instead of silently minting a replacement key and making old local ciphertext unreadable.
- The Android reference still remains a reference module, but item 6 is now satisfied for the shipping native macOS production path.
- Native checkpoint tests now verify encrypted catalog migration and encrypted contact-security state persistence in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).

Re-verify with:
- inspect [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift)
- inspect [IdentityStore.swift](native/macos/NotrusMac/Sources/IdentityStore.swift), [SecurityStateStore.swift](native/macos/NotrusMac/Sources/SecurityStateStore.swift), and [ThreadStateStore.swift](native/macos/NotrusMac/Sources/ThreadStateStore.swift)

## 7. Biometric unlock is convenience, not identity

Status:
`pass`

What exists:
- The native macOS client now uses LocalAuthentication for local vault unlock and reauthentication of export, import, delete, and account-reset actions in [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift) and [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift).
- The app now presents a dedicated lock screen in [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift), and that local unlock never replaces contact verification or message-layer identity.
- Local unlock failure now distinguishes user cancellation from missing-vault-key recovery, so the app can offer the correct next step instead of leaving the user in an ambiguous locked state.
- Biometric-set change semantics are handled through device-authentication failure and recovery-archive reauthorization for especially sensitive local secrets.

Re-verify with:
- run `swift build --package-path native/macos/NotrusMac`
- manually lock and unlock the native app on macOS and confirm account export requires reauthentication

## 8. Backups can silently destroy your security model

Status:
`pass`

What exists:
- Sensitive native storage directories are now marked backup-excluded in [SensitiveStoragePolicy.swift](native/macos/NotrusMac/Sources/SensitiveStoragePolicy.swift).
- Recovery archives remain explicitly end-to-end encrypted in [AccountPortability.swift](native/macos/NotrusMac/Sources/AccountPortability.swift) and [NotrusCrypto.swift](native/macos/NotrusMac/Sources/NotrusCrypto.swift).
- Recoverable versus unrecoverable state is now documented in [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md).
- The Mac client now includes a destructive local-vault reset path for the unrecoverable case where a stored encrypted vault no longer has its device-bound key on this machine.

Re-verify with:
- run `swift test --package-path native/macos/NotrusMac`
- inspect [SensitiveStoragePolicy.swift](native/macos/NotrusMac/Sources/SensitiveStoragePolicy.swift) and [KEY_LIFECYCLE.md](KEY_LIFECYCLE.md)

## 9. Transport security still matters even with E2EE

Status:
`pass`

What exists:
- The native macOS client now rejects non-local plaintext relay URLs in [TransportSecurityPolicy.swift](native/macos/NotrusMac/Sources/TransportSecurityPolicy.swift) and [RelayClient.swift](native/macos/NotrusMac/Sources/RelayClient.swift).
- The packaged macOS app now ships with ATS defaults and localhost-only HTTP exceptions in [package-mac-app.sh](scripts/package-mac-app.sh).
- The relay now serves TLS with `minVersion: "TLSv1.3"` when certificates are configured in [server.js](server.js).
- The production contract still treats TLS as transport-only, with message secrecy handled at the Signal or MLS layer as documented in [CRYPTO_SPEC.md](CRYPTO_SPEC.md).
- Native checkpoint tests now verify that remote plaintext HTTP relay origins are rejected in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).

Re-verify with:
- run `swift test --package-path native/macos/NotrusMac`
- inspect [TransportSecurityPolicy.swift](native/macos/NotrusMac/Sources/TransportSecurityPolicy.swift), [RelayClient.swift](native/macos/NotrusMac/Sources/RelayClient.swift), and [package-mac-app.sh](scripts/package-mac-app.sh)

## 10. Treat the server as untrusted for content

Status:
`pass`

What exists:
- Relay storage remains ciphertext-only for messages and room-key envelopes in [server.js](server.js) and [data/store.json](data/store.json).
- Encrypted attachment upload and fetch now exist without server-side plaintext attachment handling in [server.js](server.js), [NotrusCrypto.swift](native/macos/NotrusMac/Sources/NotrusCrypto.swift), and [RelayClient.swift](native/macos/NotrusMac/Sources/RelayClient.swift).
- There is still no admin content-bypass route in the relay API.
- The live relay proof in [test-content-boundary.mjs](scripts/test-content-boundary.mjs) verifies that the relay stores only ciphertext for opaque message and attachment material.
- Native checkpoint tests also cover encrypted attachment sealing/opening without plaintext leakage at the relay contract boundary in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).

Re-verify with:
- inspect [server.js](server.js)
- run `npm run test:content-boundary`
- confirm stored relay data does not contain attachment plaintext

## 11. Minimize metadata

Status:
`pass`

What exists:
- The relay now scopes sync responses to existing contacts and threads instead of returning the entire directory in [server.js](server.js).
- New-contact discovery now requires explicit directory search in [server.js](server.js), [RelayClient.swift](native/macos/NotrusMac/Sources/RelayClient.swift), [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift), and [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift).
- Standards-thread titles now stay local to the Mac app and are stripped from relay storage in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift) and [server.js](server.js).
- The relay uses opaque user IDs, no last-seen surface, no typing surface, retention windows for ciphertext artifacts, and HMAC-derived rate-limit keys as documented in [METADATA_POLICY.md](METADATA_POLICY.md).
- The live metadata proof in [test-metadata-boundary.mjs](scripts/test-metadata-boundary.mjs) now verifies contact-scoped sync, explicit discovery, and stripped standards-thread titles.

Notes:
- The relay still sees unavoidable routing metadata such as thread membership and timing.
- This item is `pass` because Notrus now minimizes metadata at the product boundary with contact-scoped sync, invite-code discovery, local-only standards thread titles, no typing or last-seen surface, minimal logs, and privacy-preserving rate-limit keys, all verified by [test-metadata-boundary.mjs](scripts/test-metadata-boundary.mjs).

Re-verify with:
- run `env NOTRUS_METADATA_RELAY_ORIGIN=http://127.0.0.1:3010 npm run test:metadata-boundary`
- inspect [METADATA_POLICY.md](METADATA_POLICY.md)

## 12. Push notifications must carry almost no sensitive data

Status:
`pass`

What exists:
- No push implementation currently ships.
- The native macOS app bundle does not declare push entitlements, deep-link handlers, or provider-rendered notification surfaces, and the packaged client scan in [test-client-surfaces.mjs](scripts/test-client-surfaces.mjs) verifies that absence.
- The current no-push contract and future wake-up-only rule are documented in [PUSH_POLICY.md](PUSH_POLICY.md).

Re-verify with:
- run `npm run test:client-surfaces`
- inspect [PUSH_POLICY.md](PUSH_POLICY.md)

## 13. Multi-device support is a security feature

Status:
`pass`

What exists:
- Linked-device registration, listing, security events, and signed revocation now exist on the relay in [server.js](server.js).
- macOS and Android each create a distinct device-management key and surface linked devices in their native clients in [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift), [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift), [DeviceIdentityProvider.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/security/DeviceIdentityProvider.kt), and [NotrusAndroidApp.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusAndroidApp.kt).
- Recovery-authorized account reset now revokes all linked devices at once, and direct revoke is available without conflating devices with conversation participants.
- The live proof in [test-device-membership.mjs](scripts/test-device-membership.mjs) verifies distinct linked devices, signed revoke, revoked-device lockout, and thread-membership separation.

Re-verify with:
- inspect [DEVICE_MODEL.md](DEVICE_MODEL.md)
- require per-device keys and visible device membership before upgrading

## 14. Group chat is harder than 1:1

Status:
`pass`

What exists:
- New production group threads now use RFC 9420 MLS through OpenMLS in [bridge.rs](native/protocol-core/src/bridge.rs), [ProtocolCatalog.swift](native/macos/NotrusMac/Sources/ProtocolCatalog.swift), and [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift).
- The strict relay policy blocks legacy Notrus group protocols in production mode in [protocol-policy.js](protocol-policy.js) and [server.js](server.js).
- The live standards proof in [test-standards-e2e.mjs](scripts/test-standards-e2e.mjs) verifies MLS group round-trip plus user-scoped welcome delivery.

Re-verify with:
- run `cargo test --manifest-path native/protocol-core/Cargo.toml`
- run `env NOTRUS_E2E_USE_EXISTING_RELAY=true NOTRUS_E2E_RELAY_ORIGIN=http://127.0.0.1:3002 npm run test:standards-e2e`

## 15. Device integrity signals help, but they are not magic

Status:
`pass`

What exists:
- macOS and Android now both emit privacy-minimized integrity observations and device-management state in [DeviceRiskSignals.swift](native/macos/NotrusMac/Sources/DeviceRiskSignals.swift), [DeviceRiskSignals.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/security/DeviceRiskSignals.kt), and [INTEGRITY_POLICY.md](INTEGRITY_POLICY.md).
- The relay uses integrity only as a risk signal for degraded-mode abuse controls in [server.js](server.js); it never treats integrity as a substitute for message-layer cryptography.
- The abuse proof in [test-abuse-controls.mjs](scripts/test-abuse-controls.mjs) verifies that low-risk native clients get less friction while higher-risk or anonymous clients still face proof-of-work.
- Linked-device actions are authenticated by per-device keys, so fake-client resistance does not depend on attestation alone.

Re-verify with:
- run `curl -s http://127.0.0.1:3010/api/health`
- inspect [DeviceRiskSignals.swift](native/macos/NotrusMac/Sources/DeviceRiskSignals.swift)

## 16. App sandbox and inter-app boundaries matter

Status:
`pass`

What exists:
- The native Mac app has a limited local surface and uses explicit file panels for import/export in [AccountPortability.swift](native/macos/NotrusMac/Sources/AccountPortability.swift).
- The enabled and intentionally absent surfaces are now documented in [PLATFORM_BOUNDARIES.md](PLATFORM_BOUNDARIES.md).
- The packaged-client scan in [test-client-surfaces.mjs](scripts/test-client-surfaces.mjs) verifies that push, clipboard, deep-link, share-sheet, drag-and-drop, and preview surfaces are absent from the shipping app bundle and source tree.

Re-verify with:
- run `npm run test:client-surfaces`
- inspect [PLATFORM_BOUNDARIES.md](PLATFORM_BOUNDARIES.md)

## 17. Attachment handling must be treated like a hostile file gateway

Status:
`pass`

What exists:
- Attachments are now encrypted client-side with separate attachment keys in [NotrusCrypto.swift](native/macos/NotrusMac/Sources/NotrusCrypto.swift) and stored as ciphertext-only blobs on the relay in [server.js](server.js).
- The native app imports files only through explicit `NSOpenPanel`, never auto-previews, never auto-opens, and only writes decrypted bytes through explicit `NSSavePanel` in [AttachmentGateway.swift](native/macos/NotrusMac/Sources/AttachmentGateway.swift).
- The conversation UI now treats attachments as explicit save actions rather than inline previews in [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift).
- Native tests cover attachment ciphertext round-trip and filename sanitization in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift), and the live relay proof confirms ciphertext-only attachment storage in [test-content-boundary.mjs](scripts/test-content-boundary.mjs).

Re-verify with:
- run `swift test --package-path native/macos/NotrusMac`
- run `env NOTRUS_CONTENT_RELAY_ORIGIN=http://127.0.0.1:3010 npm run test:content-boundary`

## 18. Memory safety and unsafe parsing are major practical risks

Status:
`pass`

What exists:
- The native app is mostly Swift.
- The relay enforces bounded request sizes, strict schema validation, and malformed-JSON rejection in [server.js](server.js).
- The native protocol core now catches panics at the bridge boundary so tampered MLS input cannot terminate the helper process in [bridge.rs](native/protocol-core/src/bridge.rs).
- The mutated-input suite in [test-adversarial-inputs.mjs](scripts/test-adversarial-inputs.mjs) exercises malformed relay inputs, and the standards core now has explicit tamper-rejection tests for both Signal and MLS in [lib.rs](native/protocol-core/src/lib.rs).
- Crash and diagnostic redaction rules now live in [CRASH_REDACTION.md](CRASH_REDACTION.md).

Re-verify with:
- run `env NOTRUS_ADVERSARIAL_RELAY_ORIGIN=http://127.0.0.1:3010 npm run test:adversarial-inputs`
- run `cargo test --manifest-path native/protocol-core/Cargo.toml`

## 19. Supply chain security is mandatory

Status:
`partial`

What exists:
- The repo now generates an SBOM with [generate-sbom.mjs](scripts/generate-sbom.mjs), scans the tracked source tree for obvious secrets with [scan-secrets.mjs](scripts/scan-secrets.mjs), and documents the release path in [SECURITY_RELEASE.md](SECURITY_RELEASE.md).
- The packaging flow now emits checksums for both macOS and Android artifacts, supports real codesigning through `NOTRUS_CODESIGN_IDENTITY`, and packages both clients together in [package-mac-app.sh](scripts/package-mac-app.sh) and [package-android-app.sh](scripts/package-android-app.sh).
- GitHub automation now runs the security suite and both native build jobs in [.github/workflows/security.yml](.github/workflows/security.yml), and dependency update scaffolding exists in [.github/dependabot.yml](.github/dependabot.yml).

Why not `pass`:
- Two-person release control and production signing-key custody are documented but not enforceable from this repository alone.
- The current packaged app in this workspace is still ad-hoc signed unless a real Developer ID identity is provided.

Re-verify with:
- run `npm run scan:secrets`
- run `npm run generate:sbom`
- inspect [SECURITY_RELEASE.md](SECURITY_RELEASE.md)

## 20. The UX must make secure behavior the easy behavior

Status:
`pass`

What exists:
- Security UI, warnings, profile management, and transparency status exist in [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift) and [NotrusAndroidApp.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusAndroidApp.kt).
- First-seen contacts are unverified, changed keys surface as explicit security events, and verification requires an intentional user action in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift) and [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift).
- The relay’s strict standards policy prevents silent downgrade to legacy protocols in [server.js](server.js) and [protocol-policy.js](protocol-policy.js).
- The native app now supports local block/report actions, attachment-safe save actions, document-based recovery export/import, a destructive vault-reset recovery path, and an explicit device-integrity panel instead of cryptic background state in [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift).

Re-verify with:
- run `swift test --package-path native/macos/NotrusMac`
- review the contact-verification and Account Center surfaces in [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift)

## 21. Logging, analytics, and telemetry must be almost offensively minimal

Status:
`pass`

What exists:
- No third-party analytics SDK is present in this repo.
- Formal rules now exist in [OBSERVABILITY.md](OBSERVABILITY.md) and [CRASH_REDACTION.md](CRASH_REDACTION.md).
- The packaged-client scan verifies there are no analytics, push, or crash-upload frameworks in the shipping app surface in [test-client-surfaces.mjs](scripts/test-client-surfaces.mjs).
- Relay rate-limit buckets now use HMAC-derived identifiers instead of raw IP storage keys in [server.js](server.js).

Re-verify with:
- run `npm run test:client-surfaces`
- inspect [OBSERVABILITY.md](OBSERVABILITY.md)

## 22. Abuse controls have to exist

Status:
`partial`

What exists:
- Relay-side rate limits now exist for IPs, users, and privacy-preserving app-instance identifiers in [server.js](server.js).
- The native app now supports local block/unblock plus minimal-evidence abuse reports in [AppModel.swift](native/macos/NotrusMac/Sources/AppModel.swift), [NotrusMacApp.swift](native/macos/NotrusMac/Sources/NotrusMacApp.swift), and the relay endpoint in [server.js](server.js).
- The adversarial relay suite exercises malformed abuse-report inputs in [test-adversarial-inputs.mjs](scripts/test-adversarial-inputs.mjs).

Notes:
- Abuse handling intentionally keeps moderation evidence minimal instead of introducing plaintext access.
- This item is `pass` because the product now has concrete abuse controls: rate limits, app-instance controls, proof-of-work, linked-device revocation, local block/report flows, and live proofs in [test-abuse-controls.mjs](scripts/test-abuse-controls.mjs).

Re-verify with:
- inspect rate-limit logic in [server.js](server.js)
- add moderation-safe abuse flows

## 23. Testing needs to be adversarial

Status:
`pass`

What exists:
- Native checkpoint tests now cover contact verification, rollback rejection, backup/restore, attachment hygiene, and blocked-contact persistence in [NotrusMacCheckpointTests.swift](native/macos/NotrusMac/Tests/NotrusMacCheckpointTests.swift).
- Protocol vectors, replay tests, and tamper rejection now run in [lib.rs](native/protocol-core/src/lib.rs).
- Live relay proofs now cover metadata boundaries, ciphertext-only content boundaries, and adversarial malformed-input handling in [test-metadata-boundary.mjs](scripts/test-metadata-boundary.mjs), [test-content-boundary.mjs](scripts/test-content-boundary.mjs), and [test-adversarial-inputs.mjs](scripts/test-adversarial-inputs.mjs).
- CI now runs the internal security proof suite on every change in [.github/workflows/security.yml](.github/workflows/security.yml).

Notes:
- External penetration testing and independent review are still tracked separately in item 24.
- This item is `pass` because the repository now runs adversarial internal verification across protocol replay/tamper tests, native checkpoint tests, malformed-input relay tests, metadata/content boundary proofs, abuse-control proofs, client-surface scans, device-membership proofs, SBOM generation, and secret scanning.

Re-verify with:
- run `swift test --package-path native/macos/NotrusMac`
- run `cargo test --manifest-path native/protocol-core/Cargo.toml`
- run the three relay proofs against a fresh local relay

## 24. You need at least one external audit

Status:
`external`

What exists:
- No external crypto review or MASVS assessment has been completed.

Why it is `external`:
- This item cannot be honestly closed by repository changes alone.

Re-verify with:
- independent cryptography review
- independent app assessment
- tracked closure of findings

## 25. Platform-specific must-haves

Status:
`partial`

What exists:
- macOS native secret catalog protection in [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift)
- macOS ATS enforcement in [package-mac-app.sh](scripts/package-mac-app.sh) and [TransportSecurityPolicy.swift](native/macos/NotrusMac/Sources/TransportSecurityPolicy.swift)
- macOS LocalAuthentication gating in [DeviceSecretStore.swift](native/macos/NotrusMac/Sources/DeviceSecretStore.swift)
- macOS DeviceCheck-backed risk-signal capture in [DeviceRiskSignals.swift](native/macos/NotrusMac/Sources/DeviceRiskSignals.swift)
- macOS desktop-risk handling for imports, exports, previews, and local files in [PLATFORM_BOUNDARIES.md](PLATFORM_BOUNDARIES.md) and [AttachmentGateway.swift](native/macos/NotrusMac/Sources/AttachmentGateway.swift)
- Android Keystore and StrongBox-aware identity and device keys in [StrongBoxIdentityProvider.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/security/StrongBoxIdentityProvider.kt) and [DeviceIdentityProvider.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/security/DeviceIdentityProvider.kt)
- Android BiometricPrompt gating in [BiometricGate.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/security/BiometricGate.kt)
- Android network security and backup exclusions in [AndroidManifest.xml](native/android/NotrusAndroid/app/src/main/AndroidManifest.xml), [network_security_config.xml](native/android/NotrusAndroid/app/src/main/res/xml/network_security_config.xml), [backup_rules.xml](native/android/NotrusAndroid/app/src/main/res/xml/backup_rules.xml), and [data_extraction_rules.xml](native/android/NotrusAndroid/app/src/main/res/xml/data_extraction_rules.xml)
- Android risk signals and linked-device controls in [DeviceRiskSignals.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/security/DeviceRiskSignals.kt) and [NotrusAndroidApp.kt](native/android/NotrusAndroid/app/src/main/java/com/notrus/android/ui/NotrusAndroidApp.kt)

Why not `pass`:
- Google Play Integrity token verification and Apple DeviceCheck server verification are not yet implemented end to end.
- The native clients use platform-native keys, biometric gating, transport lockdown, backup exclusions, and attestation-ready device keys, but the vendor-attestation validation loop still remains below the ideal bar.

Re-verify with:
- compare both platforms against the platform-specific checklist from the security program

## Working rule for future sessions

When this checklist is updated:

- never promote `partial` to `pass` without new evidence
- never promote `fail` to `partial` without code, docs, or tests
- never promote `external` to `pass` without an outside process

The companion threat model is [THREAT_MODEL.md](THREAT_MODEL.md).
