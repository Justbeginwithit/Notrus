# Security Model

Notrus is a native-only system. The shipped product surface in this repository is:

- the relay in [`server.js`](server.js)
- the witness in [`witness.js`](witness.js)
- the macOS client in [`native/macos/NotrusMac`](native/macos/NotrusMac)
- the Android client in [`native/android/NotrusAndroid`](native/android/NotrusAndroid)
- the standards core in [`native/protocol-core`](native/protocol-core)

## Trust Boundary

The relay is trusted for:

- availability
- routing
- ciphertext queueing
- linked-device coordination
- rate limiting and abuse controls

The relay is not trusted for:

- message plaintext
- attachment plaintext
- private identity keys
- local ratchet/session state
- recovery secrets

## Message-Layer Security

Production-target protocol choices:

- direct chats: Signal PQXDH plus Double Ratchet
- groups: RFC 9420 MLS

Transport security remains separate from message security. TLS protects the client-to-relay hop. Message secrecy and authenticity come from the message layer.

## Native Local Security

macOS:

- device-local encrypted account catalog
- Keychain-backed wrapping keys
- LocalAuthentication for local unlock and sensitive account actions
- encrypted recovery archives

Android:

- Android Keystore or StrongBox-aware local key usage
- biometric/device-credential unlock for the local vault
- encrypted local vault storage
- per-device identity and linked-device controls

## Attestation Posture

- relay-side attestation verification support exists through the separate attestation service (`attestation.js`)
- default relay startup does not enforce attestation verification unless operator flags are set
- production-like deployments should explicitly configure `NOTRUS_ATTESTATION_ORIGIN` and the required enforcement flags per platform
- attestation outcomes are treated as trust/risk and abuse-control signals, not as a plaintext decryption authority
- setup and runtime verification are documented in [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md)

## Transparency And Verification

- the relay maintains an append-only transparency log for identity and key events
- the witness can independently observe relay heads
- clients pin transparency state locally and surface trust reset/recovery actions
- contact verification remains an explicit user action
- first contact is unverified by default

## Metadata Boundary

Notrus minimizes, but does not eliminate, metadata exposure.

Current relay routing shape is intentionally close to:

- authorization token
- opaque mailbox handle or discovery query
- encrypted blob

Routine message and attachment delivery do not require stable sender ID, thread ID, or device ID in the request body.

The relay still learns:

- who is in a thread
- when clients sync and post
- attachment sizes and ciphertext timing
- linked-device lifecycle events

Notrus avoids:

- plaintext message storage
- plaintext attachment storage
- typing indicators
- last-seen surfaces
- global plaintext contact-graph sync

The native macOS and Android clients also expose an optional privacy mode that adds short random delay before routine sync, search, thread-creation, and message-delivery operations. This is a timing-obfuscation tradeoff, not an anonymity guarantee.

## Recovery And Device Loss

- linked devices can be listed and revoked
- recovery-authorized account reset rotates account material after device compromise or loss
- recovery archives move state between trusted native devices

## Current Honest Boundary

Notrus is currently beta software.

The remaining high-value work before stable is:

- sustained real-world operational burn-in across varied environments
- stronger external confidence signals (independent review, reproducibility maturity)
- continued operator-side hardening for release and infrastructure management

Related docs:

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
- [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
- [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
- [PROTOCOL_MIGRATION.md](PROTOCOL_MIGRATION.md)
- [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
- [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [LEGAL.md](LEGAL.md)
