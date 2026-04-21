# Notrus 0.2.0 Alpha 2 Notes

The active pre-release tag for this line is:

- `v0.2.0-alpha2-refresh2`

This tag consolidates the Alpha 2 refresh cycle into one current release surface.

## Included

- native macOS client
- native Android client
- relay
- witness
- standards protocol core

## Refresh 2 Additions

- standalone packaged app naming normalized to `Notrus`
- Android adaptive icon foreground geometry re-centered for cleaner rendering across launcher masks
- macOS app icon orientation corrected
- macOS UI brand mark orientation corrected

## Visual Upgrade

- Android now uses a calmer Material 3 base with optional enhanced floating/glass polish.
- Android appearance settings include System, Light, and Dark theme modes.
- Android release assets include versioned debug and release APK filenames so Alpha 2 builds are easy to distinguish from Alpha 1.
- macOS and Android release artifacts are built together for this release line.

## Intended Use

- product evaluation
- local and private alpha testing
- relay/client integration testing
- recovery-flow and account-portability testing

## Current Boundary

- direct chats are the primary stable cross-platform path
- Android parity for advanced group behavior is still incomplete
- cross-platform recovery import has improved, but it remains an alpha account-move path and should be tested before relying on it
- release hardening is still in progress
- external audit is not complete

## Important Warnings

- this is alpha software
- no warranty is provided
- do not treat this as emergency-grade or audit-complete secure infrastructure
- operators remain responsible for relay security, release hygiene, and device hygiene

## Non-Affiliation

Notrus is an independent project and is not affiliated with or endorsed by Signal, OpenAI, Apple, Google, Android, ngrok, libsignal maintainers, or OpenMLS maintainers.

See:

- [README.md](README.md)
- [HOW_TO_USE.md](HOW_TO_USE.md)
- [DISCLAIMER.md](DISCLAIMER.md)
- [LEGAL.md](LEGAL.md)
- [SECURITY.md](SECURITY.md)
