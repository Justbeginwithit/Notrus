# Protocol Migration Plan

This repository no longer treats any Notrus-specific experimental protocol as a shipping production path.

## Production Targets

- direct conversations: `signal-pqxdh-double-ratchet-v1`
- group conversations: `mls-rfc9420-v1`

## Experimental Paths

The following protocols remain in the repository only for explicit migration or regression work:

- `static-room-v1`
- `pairwise-v2`
- `group-epoch-v2`
- `group-tree-v3`

## Enforcement

Relay policy is controlled by `NOTRUS_PROTOCOL_POLICY`.

- `require-standards`: production default
- `allow-experimental`: migration-only override

The relay rejects experimental protocol creation and posting when strict mode is active.

## Native Production Path

- macOS creates new direct threads as `signal-pqxdh-double-ratchet-v1`
- macOS creates new group threads as `mls-rfc9420-v1`
- Android direct-chat support is being kept on the same standards track
- the standards bridge lives in [`native/protocol-core/src/bridge.rs`](native/protocol-core/src/bridge.rs)

## Verification

Re-verify by checking:

- `/api/health` reports `require-standards`
- strict mode rejects experimental thread creation with HTTP `412`
- `npm run test:standards-e2e` passes against a strict relay
- native clients continue labeling direct and group threads with the standards identifiers above
