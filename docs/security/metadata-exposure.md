# Metadata Exposure

Notrus protects message and attachment content from the relay, but it does not eliminate metadata.

## Relay-visible metadata

- Registration: username, account identifier, public identity keys, device descriptors, integrity or attestation observations when configured, timestamps, and network-layer source metadata.
- Session bootstrap: account/session association, device association, token issuance time, and coarse risk state.
- Directory search: authenticated search timing and the matched public contact record for explicit username or invite-code lookup.
- Thread creation: participant membership and protocol type. Standards-thread titles are stripped from relay storage.
- Message delivery: opaque mailbox handle, delivery capability use, encrypted wire message, message kind, message size, and timing.
- Delivery/read receipts: recipient account id, thread id, last delivered/read message id, and timestamp needed for user-visible receipt state.
- Sync: scoped users and threads needed by the authenticated account.
- Attachments: encrypted attachment blob, size, ciphertext integrity data, upload/fetch timing, and access-control state.
- Event streaming: authenticated listener timing and generic sync-required events.
- Notification registration: hashed wake-up registration identifier, platform, registration mode, and device association.
- Account reset, device revoke, and admin actions: event timing and state changes needed for safety and abuse handling.

## Minimization rules

- Routine requests use session tokens, mailbox handles, and short-lived delivery capabilities.
- Routine requests do not need caller-supplied stable sender IDs or thread IDs.
- Integrity/attestation metadata belongs at registration or session bootstrap, not routine delivery.
- Production logs must not contain plaintext, raw session tokens, raw capability tokens, or raw request bodies.
- Rate-limit buckets should use blinded/HMAC-derived identifiers where possible.

## Boundary

Notrus is not an anonymity network. Timing, IP-layer data, membership, and traffic volume can still reveal patterns to a relay operator or network observer.
