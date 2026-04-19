# Notrus Integrity Policy

## Purpose

Notrus treats client integrity as a coarse risk signal for abuse resistance and device management. It does not treat integrity as proof that a client is honest, uncompromised, or safe to trust with plaintext.

## Current signals

### macOS

- local code-signature validation
- DeviceCheck token availability
- Secure Enclave or Keychain-backed local device key presence

### Android

- app signature digest presence
- installer source
- debuggable build detection
- emulator heuristics
- Android Keystore or StrongBox-backed device key presence

## Relay behavior

- end-to-end cryptography remains mandatory regardless of integrity state
- low-risk native clients may bypass relay proof-of-work challenges for registration and abuse-controlled actions
- medium, high, or unknown risk clients are rate-limited and required to satisfy proof-of-work on sensitive anonymous paths
- the relay stores only coarse risk summaries and privacy-minimized integrity observations
- integrity failures are counted as risk signals, not as plaintext-access exceptions

## Degraded-mode rules

- no integrity signal can decrypt content, override contact verification, or bypass message-layer cryptography
- clients with weaker integrity simply face more friction
- revoked linked devices stay revoked even if they later present a low-risk integrity report

## Honest boundary

- Notrus does not currently perform full vendor-backed attestation verification for Apple or Google
- integrity is still useful for rate limiting, device listing, and visible security posture, but not as a root of trust
