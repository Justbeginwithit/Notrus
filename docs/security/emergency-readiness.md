# Emergency Readiness

Notrus is designed for private end-to-end encrypted messaging and includes modern cryptographic protections, including post-quantum hybrid direct-message session setup.

Current status: beta.

Notrus is not independently audited and is not recommended as the only emergency channel. Users in high-risk or time-critical situations should keep at least one separate backup communication method.

## Required user-visible reliability signals

- Relay connection state must be visible.
- Last successful sync time must be visible.
- Outgoing message state must distinguish queued, sent, synced, and failed states.
- Failed sends must remain visible and actionable.
- Relay downtime must be shown as a failure state, not hidden as normal sync delay.
- Notification and background-sync limitations must be documented.

## Emergency-use warnings

- Relay availability depends on the selected or self-hosted relay.
- A compromised device can expose plaintext while the app is in use.
- Notification previews can expose plaintext locally if enabled.
- The relay still sees some metadata.
- Account recovery and chat backup have different security properties.
- Backup communication is required for emergency use.

## Gate

Emergency/high-risk wording requires stable readiness, sustained real-world reliability evidence, independent security review, and updated documentation that matches the exact code shipped in the release.
