# Notrus Roadmap

This roadmap tracks next work after the `v0.3.4-beta5` security/reliability beta release.

## Current state (v0.3.4-beta5 beta)

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

## Immediate polish track

1. Notifications:
   - keep hidden content as the default
   - keep sender-only and full-preview as explicit settings
   - keep group previews separately controlled
   - keep muted chats quiet
   - define archived chats as notifying unless muted
   - keep notification taps opening the correct conversation
   - keep duplicate suppression by stable message/thread identity
2. Delivery/read receipts:
   - show sent, delivered, read, and failed/local-unreadable state
   - show exact sent/delivered/read timestamps in message info
   - keep read receipt sending optional
   - keep read receipt display optional
   - keep group receipt detail in message info instead of message bubbles
3. Local encrypted message search:
   - search local decrypted history only
   - never send plaintext search queries to the relay
   - respect deleted/hidden chats
   - include archived chats only through an explicit filter
4. Message delete/edit:
   - keep local delete-for-me separate from cross-device delete-for-everyone
   - require authenticated edit/delete protocol events before shipping cross-device mutation
   - show edited markers and deleted-message tombstones
   - do not silently rewrite history

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
