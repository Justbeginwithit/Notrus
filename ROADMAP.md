# Notrus Roadmap

This roadmap tracks product direction for the native clients, relay, and release process.

## Current State (Alpha 2 Refresh 2)

- Native clients: macOS + Android
- Relay + witness running in the same repository
- Standards protocol surface:
  - Direct: `signal-pqxdh-double-ratchet-v1`
  - Group: `mls-rfc9420-v1`
  - Compatibility path: standards-thread fanout transport when native MLS state is unavailable
- Branding standardized to `Notrus` across packaged app artifacts

## Next Milestone (Alpha 3)

- Finish remaining cross-platform recovery edge cases and migration diagnostics
- Harden linked-device lifecycle UX and revoke/reset clarity
- Expand Android/macOS parity coverage for group and attachment edge paths
- Improve release automation with stricter release metadata checks

## Stable Track

- Close stable checklist section 12 via sustained real-world operation evidence
- Complete optional confidence items where possible:
  - independent testing
  - public disclosure process maturity
  - reproducible/verifiable build improvements

See:

- [STABLE_RELEASE_CHECKLIST.md](STABLE_RELEASE_CHECKLIST.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)
- [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
