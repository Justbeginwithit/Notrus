# Notrus Production API Boundary

This document defines the relay API shape that the native clients should use for production-target builds.

## Default Mode

By default, development compatibility routes are disabled.

Set `NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES=true` only for local migration tests that intentionally exercise older raw-identifier endpoints.

By default, the relay also refuses non-local HTTP binds. Use TLS with `HTTPS_KEY_FILE` and `HTTPS_CERT_FILE`, bind to `127.0.0.1` behind a trusted local tunnel, or set `NOTRUS_ALLOW_REMOTE_HTTP=true` only for isolated development.

Production-target clients should use:

- bootstrap sessions
- Bearer session tokens
- opaque contact handles
- mailbox handles
- short-lived mailbox delivery capabilities
- encrypted message and attachment bodies

Production-target clients should not use compatibility routes that send raw user, thread, or device identifiers as their main authorization model.

## Public Routes

These routes do not require a client session:

- `GET /api/health`: coarse relay status, policy summary, and public capability hints
- `GET /api/transparency`: public signed transparency state

## Bootstrap Routes

These routes intentionally carry richer account, public-key, device, and integrity material because they create or recover account state:

- `POST /api/bootstrap/register`
- `POST /api/bootstrap/account-reset`

Normal sync, search, message, and attachment delivery must not resend the full integrity/bootstrap payload.

## Session-Authenticated Routes

These routes require `Authorization: Bearer <session-token>`:

- `GET /api/sync/state`
- `GET /api/events`
- `GET /api/directory/search`
- `GET /api/security/devices`
- `GET /api/security/transparency`
- `GET /api/notifications/status`
- `POST /api/notifications/register`
- `POST /api/notifications/unregister`
- `POST /api/routing/threads`
- `POST /api/reports`
- `POST /api/devices/revoke`
- `POST /api/account/delete`

Session validation checks that:

- the token exists and has not expired
- the account still exists
- the linked device is still active when the session is device-bound
- revoked devices cannot continue using old session tokens

## Mailbox Capability Routes

These routes require a short-lived mailbox delivery capability, not a normal account session token:

- `POST /api/mailboxes/:mailboxHandle/messages`
- `POST /api/mailboxes/:mailboxHandle/attachments`
- `GET /api/mailboxes/:mailboxHandle/attachments/:attachmentId`

Mailbox validation checks that:

- the capability exists and has not expired
- the mailbox handle still resolves
- the capability is bound to the same thread as the mailbox handle
- the capability user is still a participant before posting or fetching thread material

Routine post responses remain minimal and only return acceptance identifiers such as `messageId` or `attachmentId`.

## Disabled Compatibility Routes

These routes return `410` unless `NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES=true` is set:

- `GET /events`
- `POST /api/register`
- `POST /api/account-reset`
- `GET /api/sync`
- `POST /api/threads`
- `POST /api/threads/:threadId/messages`
- `POST /api/threads/:threadId/attachments`
- `GET /api/threads/:threadId/attachments/:attachmentId`
- unauthenticated `GET /api/directory/search?userId=...`

Legacy `X-Notrus-Session` and `X-Notrus-Capability` headers are also disabled unless compatibility mode is enabled. Production-target requests use the standard `Authorization: Bearer ...` header.

## Error Logging

The relay does not log request bodies or raw headers.

Unhandled server errors log only the error class by default. Set `NOTRUS_VERBOSE_RELAY_ERRORS=true` for local development if full stack traces are needed.

Do not enable verbose relay errors in a production relay because stack traces can contain implementation details.

## Regression Test

Run:

```bash
npm run test:production-api-boundary
npm run test:standards-e2e
```

The test starts a relay with compatibility routes disabled and verifies that:

- non-local HTTP binding fails closed unless explicitly allowed
- bootstrap registration issues session tokens
- authenticated directory search returns opaque contact handles
- thread creation uses contact handles
- sync returns mailbox handles and delivery capabilities
- mailbox message and attachment delivery require mailbox capabilities
- normal session tokens cannot post to mailbox routes
- routine responses stay minimal
- forged report and device-revoke callers are rejected
- revoked device sessions lose access
- recovery-authorized account reset invalidates old sessions and issues a replacement session
- raw-identifier compatibility APIs return `410`
- legacy auth headers are rejected in default mode

`npm run test:standards-e2e` additionally exercises the same production bootstrap/session, opaque contact-handle, `/api/routing/threads`, and `/api/mailboxes/...` path with real protocol-core Signal direct and MLS group round-trips.
