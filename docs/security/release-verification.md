# Release Verification

Users and reviewers should be able to connect a release artifact to source.

## Required release evidence

- Source tag.
- Android APK version name and version code.
- macOS version and build number.
- SHA-256 checksums for artifacts.
- Android signing certificate fingerprint for official APK releases.
- macOS signing and notarization status for production distribution.
- Security scanner status for the release candidate.
- Release notes that call out security fixes and limitations.

## Release gate

Before a beta or stable release, run:

```bash
npm run test:emergency-trust-gate
```

Production release packaging should also run release-governance checks and fail if signing or approval inputs are missing.

## Boundary

Local ad-hoc builds and CI test artifacts are not equivalent to a notarized macOS release or an officially signed Android release.
