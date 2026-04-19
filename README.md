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

## Alpha Status

Notrus is still alpha software.

That means:

- the codebase is functional, but still changing
- release hardening is incomplete
- external audit is not complete
- operators are responsible for their own relay and release hygiene

Do not treat the current build as a finished, audited, or emergency-grade secure messenger.

Read before use:

- [HOW_TO_USE.md](HOW_TO_USE.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [LEGAL.md](LEGAL.md)
- [SECURITY.md](SECURITY.md)
- [LICENSE](LICENSE)

## What Notrus Uses

- official Signal protocol components through `libsignal-protocol` for direct messaging
- OpenMLS for RFC 9420 MLS group messaging
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

## Quick Start

Start the relay:

```bash
node server.js
```

Local development relay origins:

- `http://127.0.0.1:3000`
- `http://localhost:3000`

Any non-local relay origin should use HTTPS.

Optional witness:

```bash
RELAY_ORIGIN=http://127.0.0.1:3000 npm run start:witness
```

Build/package both native clients:

```bash
npm run build:protocol-core
npm run package:clients
```

Artifacts:

- `dist/NotrusMac.app`
- `dist/NotrusMac.zip`
- `dist/NotrusMac-0.2.0-alpha2.zip`
- `dist/android/NotrusAndroid-debug.apk`
- `dist/android/NotrusAndroid-release.apk`
- `dist/android/NotrusAndroid-0.2.0-alpha2-debug.apk`
- `dist/android/NotrusAndroid-0.2.0-alpha2-release.apk`

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

Current native-client boundary:

- direct chats work across macOS and Android
- macOS has the strongest current product surface
- Android parity for advanced group behavior is still incomplete

## Recovery And Device Movement

The supported account-move path is native recovery export/import.

1. Export a recovery archive from a trusted device.
2. Move it through a trusted channel.
3. Import it on the replacement device.
4. Revoke the old device or perform a recovery-authorized reset if needed.

## Verification Commands

```bash
npm run generate:crypto-vectors
npm run test:protocol-core
npm run test:client-surfaces
npm run test:metadata-boundary
npm run test:content-boundary
npm run test:adversarial-inputs
npm run test:abuse-controls
npm run test:device-membership
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
- Crypto contract: [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
- Protocol migration: [PROTOCOL_MIGRATION.md](PROTOCOL_MIGRATION.md)
- Metadata policy: [METADATA_POLICY.md](METADATA_POLICY.md)
- Device model: [DEVICE_MODEL.md](DEVICE_MODEL.md)
- Integrity policy: [INTEGRITY_POLICY.md](INTEGRITY_POLICY.md)
- Release security: [SECURITY_RELEASE.md](SECURITY_RELEASE.md)

## Non-Affiliation And Legal

Notrus is an independent software project. It is not affiliated with Signal, OpenAI, Apple, Google, Android, ngrok, or the editors and maintainers of MLS or libsignal.

Read:

- [LEGAL.md](LEGAL.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [LICENSE](LICENSE)
