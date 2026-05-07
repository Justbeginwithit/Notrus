# Message Edit And Delete

Current status: planned stable-track feature. Local single-message deletion exists as a local-only UI action, but authenticated cross-device edit/delete events are not yet a finished protocol feature.

## Required Product Semantics

- Delete for me removes local visibility on the current device only.
- Delete for everyone must leave a tombstone such as "message deleted."
- Edit must leave an "edited" marker.
- History must not be silently rewritten.
- Deleted messages must not reappear after sync.
- Edited messages must not duplicate after sync.
- Old clients must handle edit/delete events safely.
- Direct and group behavior must be explicitly defined before release.

## Security Requirements

- Only the original sender may edit their own message.
- Only the original sender may delete for everyone unless a documented group-admin rule allows otherwise.
- Receipt, edit, and delete events must be authenticated.
- A user must not be able to forge edits/deletes for another sender.
- The relay must not need message plaintext to process edit/delete events.
- Edit/delete events should reference message IDs or encrypted envelopes, not plaintext.

## Protocol Requirements Before Implementation

- Relay event type for edit.
- Relay event type for delete-for-everyone tombstone.
- Client-side local delete marker for delete-for-me.
- Idempotent merge logic for edit/delete events.
- Cross-platform rendering on Android and macOS.
- Regression tests for unauthorized edit/delete attempts.

## Acceptance Tests

- Edit own direct message.
- Cannot edit another user's message.
- Delete own message for me.
- Delete own message for everyone.
- Cannot delete another user's message for everyone unless a documented group-admin rule allows it.
- Edit/delete syncs to Android.
- Edit/delete syncs to macOS.
- Edit/delete survives app restart and relay restart.
- Edited marker appears.
- Deleted tombstone appears.
- Deleted message does not reappear after sync.
- Group edit/delete works or fails clearly.
