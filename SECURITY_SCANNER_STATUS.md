# Security Scanner Status

This file tracks release-candidate scanner closure. It is not a substitute for the external scanner dashboards.

## Current gate

Status: release-candidate scanner evidence required before any stable or emergency/high-risk wording.

Requirement: no unresolved high or critical findings may remain in Semgrep, SonarCloud, CodeQL, dependency scanning, or secret scanning before a beta/stable release is promoted.

## Semgrep

- Status: must be re-run for each release candidate.
- Required evidence: dashboard link or exported result.
- High/critical policy: block release unless fixed or justified as false positive.

## SonarCloud

- Status: must be re-run for each release candidate.
- Required evidence: project analysis link or exported result.
- High/critical policy: block release unless fixed or justified as false positive.

## CodeQL

- Status: enabled or required as a GitHub code-scanning gate.
- Required evidence: clean GitHub code-scanning result for the release commit.
- High/critical policy: block release unless fixed or justified as false positive.

## Dependency scanning

- Status: Dependabot is configured for npm, Gradle, GitHub Actions, and Cargo.
- Required evidence: no unresolved high/critical dependency advisory for the release commit.
- High/critical policy: block release unless upgraded, patched, removed, or justified with a documented non-reachability note.

## Secret scanning

- Status: local `npm run scan:secrets` is required and GitHub secret scanning should remain enabled.
- Required evidence: passing local scan plus clean GitHub secret-scanning result.
- High/critical policy: block release if any real secret is present.

## False positives

False positives must include:

- scanner name
- finding identifier
- affected file and line
- why the finding is safe
- why it cannot bypass auth, session, capability, admin-token, or cryptographic checks
- regression test or code comment when applicable

Local/private address checks such as `127.0.0.1` and `::ffff:127.0.0.1` may be justified only when they do not bypass admin authorization, session authorization, or capability authorization.
