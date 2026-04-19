# Notrus Crash and Diagnostic Redaction

## Current rules

- no third-party crash-reporting SDK is linked into the shipping macOS app
- message plaintext, attachment plaintext, contact verification records, and vault state must not be logged
- relay request handlers return bounded client errors for malformed input instead of dumping request bodies
- the native protocol helper now catches panics at the bridge boundary and converts them into ordinary errors for untrusted input

## Verification

- `npm run test:adversarial-inputs` proves malformed relay inputs stay bounded without crashing the relay
- `cargo test --manifest-path native/protocol-core/Cargo.toml` proves tampered Signal and MLS ciphertext are rejected without panicking across the bridge boundary
- `npm run scan:secrets` ensures no obvious secrets are committed into the tracked source tree
