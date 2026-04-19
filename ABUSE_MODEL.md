# Notrus Abuse Model

## Goals

Notrus aims to slow spam, mass registration, scraping, and harassment without giving the relay plaintext message access.

## Current controls

- per-IP rate limits
- per-account rate limits
- privacy-preserving app-instance rate limits
- linked-device registration and revocation
- proof-of-work for remote or untrusted clients on sensitive anonymous paths
- local block and minimal-evidence report flows
- coarse integrity-risk signals used only to tune friction, never to replace end-to-end crypto

## Proof-of-work policy

Proof-of-work is required for:

- remote anonymous account registration
- remote directory search
- remote thread creation
- remote message posting
- remote attachment upload
- remote abuse reporting
- remote linked-device revocation

Low-risk local native clients can bypass proof-of-work, but they are still rate-limited.

## Evidence minimization

Abuse reports intentionally carry only:

- reporter
- target
- optional shared thread
- optional message identifiers
- reason
- timestamp

No server-side plaintext access is introduced for moderation.

## Honest boundary

- Notrus still lacks a mature human moderation workflow
- Notrus still lacks phone or email registration abuse controls because it does not use those identifiers
- proof-of-work slows abuse but does not eliminate determined attackers
