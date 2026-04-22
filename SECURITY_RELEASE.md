# Notrus Release Security

## Current Release Contract

- macOS packaging is produced from `scripts/package-mac-app.sh`
- Android packaging is produced from `scripts/package-android-app.sh`
- run `npm run package:android-app` and `npm run package:mac-app` to refresh both native artifacts
- production packaging enforces two-reviewer governance input through `scripts/verify-release-governance.mjs`
- the macOS packaged binary is code-signed with `NOTRUS_CODESIGN_IDENTITY` when provided, or ad-hoc signed for local verification builds
- macOS production packaging hard-fails without governance approval input, non-adhoc signing identity, and notarization profile
- Android production packaging hard-fails without governance approval input, external keystore credentials, and non-debug signer verification via `apksigner`
- release docs now require explicit attestation posture disclosure (configured/enforced/off) for each published release
- packaged artifacts emit SHA-256 checksum sidecars in `dist/`
- runtime privacy-routing and retention-pruning proofs exist in `scripts/test-privacy-routing.mjs` and `scripts/test-retention-pruning.mjs`
- the repository can generate an SBOM with `npm run generate:sbom`
- the repository can scan the tracked source tree for obvious committed secrets with `npm run scan:secrets`
- `.github/workflows/security.yml` runs protocol, relay, and native verification checks on push and pull request

## Clean Repository Release Model

The intended public-facing release model for Notrus is:

1. maintain source in a clean `Notrus` repository
2. publish release notes with explicit maturity and boundary warnings
3. attach packaged artifacts and checksums to GitHub releases
4. keep runtime state, local relay data, and secret material out of the repository

## Required Controls For A Production Release

- use a non-ad-hoc Developer ID signing identity through `NOTRUS_CODESIGN_IDENTITY`
- notarize macOS releases through `NOTRUS_NOTARY_PROFILE`
- keep Android production signing keys outside the repository and pass them only through release-time environment variables
- provide `NOTRUS_RELEASE_APPROVALS_PATH` with at least two unique reviewers for production packaging
- review the generated SBOM and dependency diffs before release
- retain release checksums and build logs long enough to investigate rollback or tampering events
- state relay attestation posture explicitly in release notes (`configured` and which `NOTRUS_REQUIRE_*` flags were enabled)

## Release Notes Requirements

Every GitHub release should clearly state:

- the current maturity level (beta, release candidate, stable, etc.)
- the supported clients and their current boundaries
- whether the release is a local verification build or a signed release candidate
- what changed
- known limitations
- non-affiliation and no-warranty disclaimers

## Current Honest Boundary

This repository contains technical enforcement for production packaging gates, signed-build hooks, SBOM generation, secret scanning, and CI verification.

It does not, by itself, prove:

- Android production signing-key custody
- Apple notarization on every published build
- external audit
