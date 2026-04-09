# Notrus Release Security

## Current Release Contract

- macOS packaging is produced from `scripts/package-mac-app.sh`
- Android packaging is produced from `scripts/package-android-app.sh`
- `npm run package:clients` refreshes both native artifacts together
- the macOS packaged binary is code-signed with `NOTRUS_CODESIGN_IDENTITY` when provided, or ad-hoc signed for local verification builds
- packaged artifacts emit SHA-256 checksum sidecars in `dist/`
- the repository can generate an SBOM with `npm run generate:sbom`
- the repository can scan the tracked source tree for obvious committed secrets with `npm run scan:secrets`
- `.github/workflows/security.yml` runs protocol, relay, and native verification checks on push and pull request

## Clean Repository Release Model

The intended public-facing release model for Notrus is:

1. maintain source in a clean `Notrus` repository
2. publish release notes with explicit alpha warnings
3. attach packaged artifacts and checksums to GitHub releases
4. keep runtime state, local relay data, and secret material out of the repository

## Required Controls For A Production Release

- use a non-ad-hoc Developer ID signing identity through `NOTRUS_CODESIGN_IDENTITY`
- notarize macOS releases through `NOTRUS_NOTARY_PROFILE`
- protect Android production signing keys outside the repository
- review the generated SBOM and dependency diffs before release
- require a second reviewer for release-tag creation and production relay configuration changes
- retain release checksums and build logs long enough to investigate rollback or tampering events

## Release Notes Requirements

Every GitHub release should clearly state:

- that Notrus is alpha or otherwise state the current maturity level
- the supported clients and their current boundaries
- whether the release is a local verification build or a signed release candidate
- what changed
- known limitations
- non-affiliation and no-warranty disclaimers

## Current Honest Boundary

This repository contains the technical scaffolding for macOS and Android packaging, signed-build hooks, SBOM generation, secret scanning, and CI verification.

It does not, by itself, prove:

- two-person release control
- Android production signing-key custody
- Apple notarization on every published build
- external release governance
- external audit
