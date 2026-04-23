# Notrus Admin GUI

This document describes the built-in relay operator GUI at `/admin`.

## Purpose

The Admin GUI is an optional operator surface for self-hosted relays to inspect and manage relay-side accounts.

It is disabled by default and only available when:

```bash
NOTRUS_ENABLE_ADMIN_API=true \
NOTRUS_ADMIN_API_TOKEN="replace-with-long-random-token" \
node server.js
```

## Authentication

- Every admin API request requires `X-Notrus-Admin-Token`.
- The GUI stores the token only in local browser storage on the operator machine.
- Do not expose the token publicly.

## Current actions

- List relay users (`GET /api/admin/users`)
- List full relay user inventory (`all=true`, includes deactivated users)
- Block a user (`POST /api/admin/users/:userId/block`)
- Unblock/reactivate a user (`POST /api/admin/users/:userId/unblock`)
- Delete a user (`POST /api/admin/users/:userId/delete`)

## Boundaries

The Admin GUI can:

- inspect relay account metadata
- deactivate and reactivate accounts
- remove relay accounts and associated relay-side thread/report records

The Admin GUI cannot:

- create users
- read message plaintext
- read attachment plaintext
- recover private keys from client hardware stores
- manage local client vault contents on end-user devices

## Identity and unblock behavior

- Block/unblock is designed to preserve account identity continuity by user ID.
- If a username is already used by a different relay account, unblock/register actions return conflict errors.
- Operator cleanup may still be required for legacy duplicates created before this behavior was enforced.

## Operational cautions

- `delete` is destructive and removes relay-side account/thread state.
- Prefer `block` for temporary suspension and `unblock` for reactivation.
- Local device profile lists shown in macOS/Android clients are not the same as relay-wide account inventory.
