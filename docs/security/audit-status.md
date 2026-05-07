# Audit Status

Notrus has not completed a full independent security audit.

## Current assurance sources

- Repository tests.
- Manual app testing.
- Static-analysis services such as Semgrep, SonarCloud, CodeQL, dependency scanning, and secret scanning when configured.
- User and developer issue reports.

## Required before stronger public trust claims

- Freeze a review candidate.
- Provide threat model, protocol docs, endpoint list, metadata exposure docs, platform-security docs, admin API docs, and recovery/backup docs.
- Fix known critical and high findings before review.
- Add regression tests for confirmed findings.
- Publish an audit summary only if reviewers permit it.

## Public wording

Until an independent review is complete, public materials must say Notrus is not independently audited.
