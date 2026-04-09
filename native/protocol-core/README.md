# Notrus Protocol Core

This crate is the production crypto core for the standards-only Notrus path.

What it owns:

- direct-message protocol bindings through Signal's official `libsignal-protocol`
- group-message protocol bindings through OpenMLS for RFC 9420 MLS
- a narrow native bridge for the macOS client
- pinned runtime snapshots, serialization rules, and replay vectors for checklist item 3

Current state:

- direct chats: `signal-pqxdh-double-ratchet-v1`
- group chats: `mls-rfc9420-v1`
- C ABI surface: exported profile and readiness snapshot functions in [notrus_protocol_core.h](native/protocol-core/include/notrus_protocol_core.h)
- exact protocol pins and serialization rules: [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
- fixed replay vectors: [test-vectors](native/protocol-core/test-vectors)

Verification:

```bash
npm run build:protocol-core
npm run generate:crypto-vectors
npm run test:protocol-core
```

Those checks verify:

- backend readiness snapshots expose the pinned Signal and MLS versions
- Signal direct-message vectors replay and continue safely after replay
- MLS group vectors replay with the pinned ciphersuite
- the helper binary and library build locally for the macOS client
