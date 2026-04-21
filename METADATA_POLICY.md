# Notrus Metadata Policy

## Current minimization rules

- users are identified on the relay by opaque UUID-style identifiers rather than phone numbers
- sync only returns the local user plus users that already share a thread with that user
- discovering a new contact requires explicit directory search
- routine sync and directory requests use short-lived session tokens rather than repeating full device/integrity metadata on each request
- routine message and attachment delivery use opaque mailbox handles plus short-lived delivery capabilities
- raw-identifier compatibility routes are disabled by default and require `NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES=true` for development-only migration tests
- standards-based thread titles are stored locally on the Mac and stripped from the relay
- the relay does not publish plaintext last-seen, typing, or read-receipt surfaces
- rate-limit buckets are keyed by HMAC-derived blinded bucket values rather than retaining raw identifiers in bucket keys
- ciphertext messages and encrypted attachments age out under retention policy
- unhandled relay errors log only the error class by default; verbose stack traces require `NOTRUS_VERBOSE_RELAY_ERRORS=true` for local development
- both native clients expose an optional privacy mode that adds short random delays to routine network actions
- Android protects sensitive vault/profile screens from screenshots and app-switcher previews by default, independent of timing privacy mode

## Honest boundary

The relay still learns timing, IP-layer delivery metadata, and thread membership because it is the delivery service. Notrus currently minimizes routine metadata through the production API boundary documented in [PRODUCTION_API_BOUNDARY.md](PRODUCTION_API_BOUNDARY.md); it does not provide traffic-analysis resistance or an anonymity network.
