# Local Message Search

Current status: planned stable-track feature.

Search must stay local-only because Notrus message content is end-to-end encrypted.

## Required Behavior

- Search local decrypted message history only.
- Do not send message search queries to the relay.
- Do not add server-side plaintext search.
- Search by message text, contact, group name, and date where local history has that data.
- Group results by conversation.
- Opening a result should select the conversation and scroll the message into context.
- Respect locally deleted/hidden chats.
- Archived chats may appear only when the user includes archived conversations in the search filter.

## Storage Boundary

If Notrus later adds a local index, the index must be protected by the same encrypted local storage boundary as the message database.

- No plaintext search index may be uploaded to a relay.
- Search queries must not be written to relay logs.
- Search queries must not be written to crash logs.
- Clearing an account, chat history, or local vault must clear the matching local search data.

## Acceptance Tests

- Direct message search.
- Group message search.
- Archived chat search filter behavior.
- Deleted chat does not appear.
- Search after app restart.
- Search after import/restore.
- Search with no network connection.
- Search does not contact the relay.
