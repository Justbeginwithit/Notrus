# Notrus

Notrus is a self-hostable, native-first encrypted messenger project with:

- a relay that stores ciphertext, attachment blobs, transparency data, device records, and abuse-control state
- a native macOS client in [`native/macos/NotrusMac`](native/macos/NotrusMac)
- a native Android client in [`native/android/NotrusAndroid`](native/android/NotrusAndroid)
- a standards protocol core in [`native/protocol-core`](native/protocol-core)

Current production-target protocol choices:

- direct chats: `signal-pqxdh-double-ratchet-v1`
- groups: `mls-rfc9420-v1`

This repository is native-only. The earlier browser client is not part of the current product surface.

## Beta Status

Notrus is currently **beta software**.

That means:

- the core architecture and security paths are implemented and test-gated
- the real clients use the intended privacy/auth routing path
- major trust-model controls are in place
- remaining work is focused on stable-release maturity, operations, and external confidence signals

Do not treat this as a finished, externally audited, warranty-backed messenger.

Read before use:

- [HOW_TO_USE.md](HOW_TO_USE.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [LEGAL.md](LEGAL.md)
- [SECURITY.md](SECURITY.md)
- [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
- [RELEASE_NOTES.md](RELEASE_NOTES.md)
- [ROADMAP.md](ROADMAP.md)
- [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md)
- [ADMIN_GUI.md](ADMIN_GUI.md)
- [LICENSE](LICENSE)

## What Notrus Uses

- official Signal protocol components through `libsignal-protocol` for direct messaging
- OpenMLS for RFC 9420 MLS group messaging
- a standards-thread compatible group fanout transport (per-recipient Signal sealing inside `mls-rfc9420-v1` delivery) for client interoperability when native MLS state is unavailable
- TLS 1.3 for client-to-relay transport when HTTPS is configured
- Ed25519 transparency signing for relay key-directory events
- SwiftUI for the native macOS client
- Kotlin and Jetpack Compose for the native Android client
- Rust for the standards protocol helper/core

Notrus is not affiliated with or endorsed by any of those projects or vendors. See [LEGAL.md](LEGAL.md).

## Repository Layout

- Relay: [`server.js`](server.js)
- Witness: [`witness.js`](witness.js)
- macOS app: [`native/macos/NotrusMac/README.md`](native/macos/NotrusMac/README.md)
- Android app: [`native/android/NotrusAndroid/README.md`](native/android/NotrusAndroid/README.md)
- Standards core: [`native/protocol-core/README.md`](native/protocol-core/README.md)
- Security release notes: [`SECURITY_RELEASE.md`](SECURITY_RELEASE.md)
- Release notes: [`RELEASE_NOTES.md`](RELEASE_NOTES.md)
- Roadmap: [`ROADMAP.md`](ROADMAP.md)

## Quick Start

Start the relay:

```bash
node server.js
```

Optional relay-operator API (disabled by default):

```bash
NOTRUS_ENABLE_ADMIN_API=true \
NOTRUS_ADMIN_API_TOKEN="replace-with-long-random-token" \
node server.js
```

When enabled, the relay exposes token-protected operator routes:

- `GET /api/admin/users`
- `POST /api/admin/users/:userId/unblock`
- `POST /api/admin/users/:userId/block`
- `POST /api/admin/users/:userId/delete`

Relay also serves a built-in admin GUI at:

- `/admin`

Use header `X-Notrus-Admin-Token: <token>`.

Admin GUI capabilities and limits are documented in [ADMIN_GUI.md](ADMIN_GUI.md).

Local development relay origins:

- `http://127.0.0.1:3000`
- `http://localhost:3000`

Any non-local relay origin should use HTTPS.

Optional witness:

```bash
RELAY_ORIGIN=http://127.0.0.1:3000 npm run start:witness
```

Optional attestation service (recommended for production-like trust posture):

```bash
npm run start:attestation
```

Build/package both native clients:

```bash
npm run build:protocol-core
npm run package:android-app
npm run package:mac-app
```

Artifacts:

- `dist/Notrus.app`
- `dist/Notrus.zip`
- `dist/Notrus-0.3.2-beta3.zip`
- `dist/android/Notrus-debug.apk`
- `dist/android/Notrus-release.apk`
- `dist/android/Notrus-0.3.2-beta3-debug.apk`
- `dist/android/Notrus-0.3.2-beta3-release.apk`

## Current Product Boundary

The relay is not trusted with:

- message plaintext
- attachment plaintext
- private identity keys
- local ratchet state
- recovery secrets

The relay still sees:

- account identifiers and public keys
- linked-device metadata
- opaque mailbox handles, short-lived delivery capabilities, and ciphertext routing state
- thread membership
- timestamps and traffic patterns

Routine delivery traffic is intentionally narrower than the old model:

- bootstrap and registration carry richer device/integrity material
- routine sync, search, message, and attachment requests use short-lived session or delivery tokens
- routine message delivery uses an opaque mailbox handle plus encrypted payload, not stable sender and thread identifiers in the request body

Both native clients also expose an optional privacy mode that adds short random delays to routine network actions to weaken simple timing correlation.

Attestation posture:

- relay attestation verification support exists, but enforcement is operator-configured
- default startup does not enforce vendor attestation checks
- see [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md) for current state, env flags, and strict-mode setup

Current native-client boundary:

- direct chats work across macOS and Android
- encrypted mailbox attachments on the standards direct path work on both native clients
- standards-group messaging works across macOS and Android through native MLS or compatible fanout transport, depending on client state
- both clients can read and send compatible standards-group traffic on the current relay policy path

## Recovery And Device Movement

The supported account-move path is native recovery export/import.

1. Export a recovery archive from a trusted device.
2. Move it through a trusted channel.
3. Import it on the replacement device.
4. Revoke the old device or perform a recovery-authorized reset if needed.

Current beta limitation:

- recovery import/export restores account identity material, but does not yet provide full historical plaintext chat restoration across devices. Older chats may appear as unavailable/invalid local plaintext on the destination device.

## Known Beta Limitations

- Android notifications are implemented in code and UI but still require reliability polish on some devices/OS scheduling conditions.
- Recovery import/export is currently identity-first and not a full conversation-history migration path.

## Verification Commands

```bash
npm run test:beta-readiness
```

Extended command set:

```bash
npm run generate:crypto-vectors
npm run test:protocol-core
npm run test:client-surfaces
npm run test:metadata-boundary
npm run test:content-boundary
npm run test:adversarial-inputs
npm run test:abuse-controls
npm run test:device-membership
npm run test:attestation-service
npm run test:attestation-enforcement
npm run test:release-governance
npm run test:security-suite
```

Native checks:

```bash
swift test --package-path native/macos/NotrusMac
swift build --package-path native/macos/NotrusMac
cd native/android/NotrusAndroid && ./gradlew testDebugUnitTest connectedDebugAndroidTest
```

## Security And Release Docs

- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)
- Security model: [SECURITY.md](SECURITY.md)
- Security checklist: [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- Beta release checklist: [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
- Stable release checklist: [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
- Crypto contract: [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
- Protocol migration: [PROTOCOL_MIGRATION.md](PROTOCOL_MIGRATION.md)
- Metadata policy: [METADATA_POLICY.md](METADATA_POLICY.md)
- Device model: [DEVICE_MODEL.md](DEVICE_MODEL.md)
- Integrity policy: [INTEGRITY_POLICY.md](INTEGRITY_POLICY.md)
- Attestation setup: [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md)
- Release security: [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
- Release notes: [RELEASE_NOTES.md](RELEASE_NOTES.md)
- Product roadmap: [ROADMAP.md](ROADMAP.md)

## Non-Affiliation And Legal

Notrus is an independent software project. It is not affiliated with Signal, OpenAI, Apple, Google, Android, ngrok, or the editors and maintainers of MLS or libsignal.

Read:

- [LEGAL.md](LEGAL.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [LICENSE](LICENSE)
