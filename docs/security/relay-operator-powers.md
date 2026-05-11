# Relay Operator Powers

The relay operator can provide availability, routing, retention, abuse controls, directory search, and optional admin operations. The relay operator cannot decrypt normal message bodies or attachment plaintext without compromising an endpoint or obtaining user backup material.

## Operator can see or influence

- Account and device records.
- Public identity material.
- Thread membership and delivery timing.
- Ciphertext queues and encrypted attachment manifests/chunks.
- Notification registration hashes.
- Rate-limit and abuse-control state.
- Admin block, unblock, and delete state if admin API is enabled.
- Relay configuration, logs, retention, and uptime.

## Operator cannot legitimately do

- Read message plaintext from relay storage.
- Read attachment plaintext from relay storage.
- Export user recovery archives.
- Issue user sessions through admin routes.
- Impersonate users through admin routes.
- Bypass user/device/session/capability authorization by using localhost or private IP status.

## Trust limits

A malicious relay can deny service, delay messages, collect timing metadata, and attempt key-directory attacks. Transparency verification and contact verification are intended to make silent key replacement detectable, not impossible.
