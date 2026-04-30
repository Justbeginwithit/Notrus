# Notrus Roadmap

This roadmap tracks next work after the `v0.3.4-beta5` security/reliability beta release.

## Current state (Beta 4 security update)

- Native clients: macOS + Android
- Relay + witness + attestation service in one repository
- Standards protocol surface:
  - Direct: `signal-pqxdh-double-ratchet-v1`
  - Group: `mls-rfc9420-v1`
  - Compatibility path: standards-thread fanout transport when native MLS state is unavailable
- Opaque routine routing active: session token + mailbox handle + delivery capability
- Release labels aligned for current artifacts:
  - macOS: `Notrus-0.3.4-beta5.zip`
  - Android: `Notrus-0.3.4-beta5-release.apk`

## Near-term release-candidate track

- Attestation hardening:
  - make attestation deployment posture explicit in operator setup docs and release notes
  - keep enforcement tests green (`test:attestation-service`, `test:attestation-enforcement`)
  - add operator-facing guidance for partial enforcement profiles (Android-only, Apple-only)
- UX refinement:
  - macOS dark-mode contrast and visual parity pass
  - Android trust/device screen polish after beta-device feedback
- Reliability:
  - continue burn-in across profile import/export, linked-device, and relay session-expiry edges
  - burn in Android background notifications across OEM/device scheduling behavior now that channels, WorkManager fallback, boot/package rescheduling, dedupe, and optional reliable foreground delivery are implemented
  - continue burn-in for the separate encrypted chat-backup restore path across same-platform and mixed-platform moves

## Stable track

- Close stable checklist section 12 with sustained real-world operation evidence
- Complete external confidence items where possible:
  - independent testing and review
  - disclosure-process maturity
  - reproducible/verifiable build improvements

## Tracking docs

- [RELEASE_NOTES.md](RELEASE_NOTES.md)
- [ATTESTATION_SETUP.md](ATTESTATION_SETUP.md)
- [BETA_RELEASE_CHECKLIST.md](BETA_RELEASE_CHECKLIST.md)
- [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
