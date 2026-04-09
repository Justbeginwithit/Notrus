# Notrus Metadata Policy

## Current minimization rules

- users are identified on the relay by opaque UUID-style identifiers rather than phone numbers
- sync only returns the local user plus users that already share a thread with that user
- discovering a new contact requires explicit directory search
- standards-based thread titles are stored locally on the Mac and stripped from the relay
- the relay does not publish plaintext last-seen, typing, or read-receipt surfaces
- rate-limit buckets are keyed by HMACs of IP addresses rather than retaining raw IPs in bucket identifiers
- ciphertext messages and encrypted attachments age out under retention policy

## Honest boundary

The relay still learns timing, IP-layer delivery metadata, and thread membership because it is the delivery service. Notrus currently minimizes metadata for the shipping macOS path; it does not provide traffic-analysis resistance or an anonymity network.
