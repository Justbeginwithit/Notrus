# Notrus Observability Policy

## Current rule

- no third-party analytics SDKs
- no content-derived telemetry
- no plaintext message or attachment logging
- no raw-IP retention for rate-limit buckets
- no crash-report upload SDK in the shipping app

## Relay behavior

- relay rate limits are keyed by privacy-preserving HMACs rather than retaining raw IPs in bucket identifiers
- operational responses expose only coarse counters and limits through `/api/health`
- request bodies are not logged
- unhandled server errors log only the error class by default
- full stack traces require `NOTRUS_VERBOSE_RELAY_ERRORS=true` and are local-development only
- non-local HTTP relay binding is refused by default unless `NOTRUS_ALLOW_REMOTE_HTTP=true` is explicitly set for isolated development

## Native client behavior

- no analytics or remote diagnostics frameworks are linked
- contact verification, message plaintext, and local vault state remain on-device
- future diagnostics must be explicit, redact identifiers, and remain opt-in

## Retention rule

- relay-stored ciphertext messages and encrypted attachments age out under retention policy
- future diagnostics must declare retention windows before they can ship
