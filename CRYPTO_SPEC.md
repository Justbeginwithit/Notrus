# Notrus Crypto Specification

This file defines the production cryptographic contract for the standards-based Notrus path.

## Scope

Production scope in this repository means:

- native macOS client in [NotrusMac](native/macos/NotrusMac)
- native standards core in [native/protocol-core](native/protocol-core)
- relay running with `NOTRUS_PROTOCOL_POLICY=require-standards`

Legacy browser and Notrus-specific protocols remain in the repository only as experimental migration paths and are not part of this production crypto contract.

## Message-Layer Protocols

Direct chats:

- protocol id: `signal-pqxdh-double-ratchet-v1`
- backend: official Signal `libsignal-protocol`
- upstream pin: `8418be45dba3ebc17127b5c6b76ce02886350524`
- async setup model: Signal pre-key session setup with signed prekeys and Kyber prekeys
- ongoing session model: Double Ratchet through `signal-prekey` and `signal-whisper` messages

Group chats:

- protocol id: `mls-rfc9420-v1`
- backend: `openmls = 0.8.1`
- crypto provider: `openmls_rust_crypto = 0.5.1`
- credential package: `openmls_basic_credential = 0.5.0`
- standard: RFC 9420
- ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`

## Transport Layer

Transport security is separate from message security.

- production minimum transport target: TLS 1.3
- transport role: relay authentication, confidentiality in transit, and downgrade resistance
- message-layer role: end-to-end confidentiality, authenticity, forward secrecy, and post-compromise recovery

The relay must never be treated as trusted for message plaintext just because TLS is present. TLS protects the client-relay hop; Signal and MLS protect the message contents end to end.

## Serialization Rules

General:

- wrapper encoding: UTF-8 JSON
- binary encoding inside JSON: standard base64 with padding
- protocol ids are fixed string literals
- timestamps use ISO 8601 / RFC 3339 UTC strings

Signal direct messages:

- relay thread protocol: `signal-pqxdh-double-ratchet-v1`
- relay message fields:
  - `messageKind`: `signal-prekey` or `signal-whisper`
  - `wireMessage`: base64 of the serialized libsignal ciphertext message bytes
- relay registration field:
  - `signalBundle`: camelCase JSON object carrying the public pre-key bundle
- helper bridge field:
  - `signal_bundle`: underscored JSON equivalent of the same public pre-key bundle

MLS group threads:

- relay thread protocol: `mls-rfc9420-v1`
- relay thread bootstrap fields:
  - `mlsBootstrap.groupId`: base64 of the MLS group id bytes
  - `mlsBootstrap.welcomes[*].welcome`: base64 of the TLS-serialized MLS Welcome message
- relay message fields:
  - `messageKind`: `mls-application`
  - `wireMessage`: base64 of the TLS-serialized `MlsMessageOut`
- relay registration field:
  - `mlsKeyPackage.keyPackage`: base64 of the TLS-serialized MLS KeyPackage

Bridge contract:

- the Rust helper uses underscored JSON fields
- the relay and app models use camelCase JSON fields
- conversion happens explicitly in:
  - [StandardsCoreBridge.swift](native/macos/NotrusMac/Sources/StandardsCoreBridge.swift)
  - [server.js](server.js)
  - [generate-crypto-vectors.mjs](scripts/generate-crypto-vectors.mjs)
  - [test-standards-e2e.mjs](scripts/test-standards-e2e.mjs)

Opaque persisted state:

- `signal_state`, `mls_state`, and `thread_state` are persistence artifacts, not wire formats
- the wrapper field names and encodings are part of the contract
- the embedded libsignal session blob is not treated as a canonical byte-for-byte replay artifact
- fixed vectors therefore validate:
  - exact wire-message replay
  - exact protocol ids, backend pins, and transport split
  - stable state semantics needed to continue the session safely
  - fresh post-replay session usability

## Verification Artifacts

Pinned runtime snapshot:

- [lib.rs](native/protocol-core/src/lib.rs) exposes the exact backend pins and ciphersuite in `core_profile_snapshot()`

Fixed replay vectors:

- [signal-direct-v1.json](native/protocol-core/test-vectors/signal-direct-v1.json)
- [mls-group-v1.json](native/protocol-core/test-vectors/mls-group-v1.json)

Vector generation:

- `npm run generate:crypto-vectors`

Vector replay and crypto-core verification:

- `cargo test --manifest-path native/protocol-core/Cargo.toml`

End-to-end relay proof:

- start a strict relay
- run `NOTRUS_E2E_USE_EXISTING_RELAY=true NOTRUS_E2E_RELAY_ORIGIN=http://127.0.0.1:3002 npm run test:standards-e2e`

That proof must show:

- strict policy rejects experimental protocol creation
- Signal direct messages decrypt correctly end to end
- MLS group messages decrypt correctly end to end
- MLS welcomes are scoped per recipient
