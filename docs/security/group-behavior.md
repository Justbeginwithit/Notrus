# Group Behavior, Limits, And Trust Changes

Current status: beta behavior. This document describes the current intended behavior and the remaining limits that must be considered before stable.

## Size Limits

Notrus groups currently support up to 32 members by default.

- Relay enforcement: `MAX_THREAD_PARTICIPANTS`, default `32`.
- macOS client limit: 32 members.
- Android can read and send compatible group fanout threads that already exist, but group creation is not presented as a separate Android group-composer flow in this build.
- Recommended practical group size for beta testing: 3 to 12 members.

Larger groups are not supported yet because MLS/fanout encryption, delivery state, read receipts, sync payloads, and local receipt UI all become heavier.

When the limit is reached, clients should show:

> Groups currently support up to 32 members. Larger groups are not supported yet.

## Protocol Paths

Groups use `mls-rfc9420-v1` at the relay protocol level.

Client behavior can differ depending on available local state:

- Native MLS state is used where the client has the required MLS material.
- Compatible group fanout uses per-recipient Signal-compatible envelopes inside the standards group transport when needed for cross-platform interoperability.
- Group security should not be described as stronger than direct-chat security unless a specific path has been tested.
- Groups are not currently documented as post-quantum hybrid in the same way as direct-message setup.

## Device And Security Number Changes

When a member changes device, restores from backup, imports account identity, resets account state, or changes identity/security number:

- The change must be visible as a security event when the client can detect it.
- Users should see plain-language warnings such as "Alice's security number changed" or "Alice needs to be re-verified."
- Clients should avoid silently dropping a member from group access.
- If automatic recovery is unsafe, the UI must tell users whether the changed member needs to reset secure state, publish fresh pre-keys, or be re-added.

Messages sent before a device or identity change may require old local group/session state to remain readable. Chat backup is the feature intended to preserve that local history state. Account recovery alone does not promise full group-history readability.

## Import, Export, And Restore

Account recovery and chat backup are separate:

- Account recovery restores identity/account continuity and future messaging ability.
- Chat backup restores readable local history, local message cache, and group/session state when included in the backup.
- Full device migration means identity plus chat backup plus group/session state.

Expected beta behavior:

- Account recovery does not promise old group messages will decrypt.
- Chat backup may restore group history if the backup contains the needed local group/session state.
- Restored devices may trigger security-number warnings for contacts.
- If old devices are revoked or account reset occurs, clients should show clear trust-change events instead of cryptic decrypt errors.

## Receipts And Message Info

Direct and group read receipts are privacy-sensitive and user-controlled.

- Read receipts can be disabled in privacy settings.
- Displaying read receipts from other users can also be disabled locally.
- Delivery receipts are recorded when a recipient device syncs the message ciphertext from the relay.
- Android and macOS show receipt summaries in the message bubble and provide a message info action for sent, delivered, read, and not-delivered member detail.
- Message info shows exact sent, delivered, and read timestamps where the client has them.
- Group receipt detail lives in message info instead of cluttering bubbles.

Delivery receipts are not the same as read receipts. The current beta distinguishes sent to relay, delivered to recipient device, read, and failed/unreadable local state. Full per-recipient failed-delivery diagnostics are still a stable-hardening item.

## Stable Blockers

Before stable, Notrus should have regression tests for:

- Archived group stays archived after sync.
- Unarchived group stays unarchived after sync.
- Locally deleted group does not reappear as archived after sync.
- Device/security-number changes create visible security events.
- Restored group history decrypts when chat backup includes the required state.
- Message info accurately groups read, delivered, not delivered, and failed members.
