# Notrus Threat Model

## Scope

This threat model covers:

- the relay in [`server.js`](server.js)
- the witness in [`witness.js`](witness.js)
- the macOS client in [`native/macos/NotrusMac`](native/macos/NotrusMac)
- the Android client in [`native/android/NotrusAndroid`](native/android/NotrusAndroid)
- the standards protocol core in [`native/protocol-core`](native/protocol-core)

Only the native clients and native supporting services are part of the shipping surface.

## Assets

- message plaintext
- attachment plaintext and attachment keys
- long-term identity keys
- per-device keys
- Signal and MLS session state
- recovery archives and recovery-authority material
- contact-verification state
- transparency pins and witness observations
- device membership state
- release-signing and deployment secrets
- metadata about who talks to whom and when

## Adversaries

### Passive network observer

Goals:

- read message content
- read attachment content
- learn timing and communication patterns

Stance:

- message and attachment content should remain unreadable
- timing and traffic-pattern leakage is reduced, not eliminated

### Malicious or compromised relay

Goals:

- read content
- substitute keys
- split transparency views
- learn social graph and timing data
- degrade clients to weaker paths

Stance:

- relay should not see plaintext
- relay still sees unavoidable routing metadata
- key substitution must be detectable through transparency, verification, and local trust state

### Stolen device

Goals:

- extract local secrets
- keep receiving future traffic

Stance:

- native local state is encrypted at rest
- device loss is addressed through linked-device revocation and recovery-authorized account reset

### Rooted, jailbroken, or malware-compromised endpoint

Goals:

- steal plaintext at runtime
- steal or misuse local keys
- tamper with UI or app logic

Stance:

- endpoint compromise is not fully solvable by protocol design
- native storage, local auth, and attestation can raise the bar, not eliminate this class

### Account takeover

Goals:

- bind a malicious device
- replace account keys
- abuse recovery flows

Stance:

- account/device lifecycle must be explicit, visible, and revocable

### Malicious contact

Goals:

- flood, replay, harass, or trigger parser/state bugs
- exploit key changes or verification confusion

Stance:

- message authentication, strict parsing, trust-state changes, and abuse controls are required

### Spam and bot abuse

Goals:

- mass registrations
- scrape discovery surfaces
- overload delivery infrastructure

Stance:

- proof-of-work, rate limits, integrity signals, and minimal-evidence abuse flows are required

### Supply-chain attacker

Goals:

- compromise dependencies
- compromise CI or release signing
- deliver a malicious build

Stance:

- release hardening and signed release workflows are part of the threat model, not optional extras

### Future cryptanalytic risk

Goals:

- decrypt stored traffic later

Stance:

- the production path follows current standards libraries and version pins
- long-term resilience still depends on upstream cryptographic evolution and review

## Minimum Security Bar

Notrus should only claim trustworthiness when the system delivers:

- end-to-end encryption for messages and attachments
- forward secrecy
- post-compromise recovery
- secure asynchronous delivery
- device loss resistance
- metadata minimization
- compromise detection and recovery
- independent auditability

## Non-Goals

This repository does not claim:

- guaranteed confidentiality on a fully compromised endpoint
- full metadata privacy against the relay
- immunity from traffic analysis
- completed external review by default

## Trust Boundaries

### Native clients

Trusted for:

- local plaintext handling
- local key use
- local session state

Not trusted once the endpoint itself is compromised.

### Relay

Trusted for:

- ciphertext routing
- account and linked-device coordination
- abuse controls
- availability

Not trusted for:

- plaintext
- private keys
- decrypted attachments

### Witness

Trusted for:

- independently observing relay transparency state

Not trusted for:

- message content
- contact verification decisions

## Current Native-Only Boundary

The remaining high-risk areas in this repository are native platform hardening, attestation validation, release-chain hardening, stronger transparency guarantees, and deeper metadata protection.
