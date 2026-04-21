# External Audit Plan

This repository includes code-level hardening and internal verification, but the independent external audit requirement is still separate and mandatory for a stable trust claim.

## Scope expected from an external review

- relay authorization and routing boundaries
- standards protocol bridge behavior (Signal + MLS)
- key lifecycle, recovery, and account reset guarantees
- metadata exposure boundaries at relay and client layers
- macOS and Android local secret handling and platform controls
- release and update-chain controls

## Inputs prepared by this repository

- threat model: [THREAT_MODEL.md](THREAT_MODEL.md)
- crypto spec: [CRYPTO_SPEC.md](CRYPTO_SPEC.md)
- device model: [DEVICE_MODEL.md](DEVICE_MODEL.md)
- metadata policy: [METADATA_POLICY.md](METADATA_POLICY.md)
- integrity policy: [INTEGRITY_POLICY.md](INTEGRITY_POLICY.md)
- release controls: [SECURITY_RELEASE.md](SECURITY_RELEASE.md)
- current security checkpoint evidence: [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)

## Auditor handoff package

Before audit kickoff:

1. freeze the release candidate commit hash
2. export the latest security-suite logs (`npm run test:security-suite`)
3. export package verification logs for macOS and Android
4. provide this repository and all security documents above

## Findings process

- all findings must be tracked as issues with severity, impact, and owner
- critical/high findings must be fixed and re-verified before stable release
- closure evidence must include code reference and a verification command

## Honest status

- No independent external audit report is bundled in this repository yet.
- Until an outside review is completed, checklist item 24 remains `external`.
