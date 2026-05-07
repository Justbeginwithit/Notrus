# Self-Hosting Security

Notrus is self-hostable, but relay security depends on deployment configuration.

Endpoint provider choices, limits, and recommended use cases are documented in [endpoint-provider-guide.md](endpoint-provider-guide.md).

## Transport

- Use HTTPS for remote relays.
- Use HTTP only for localhost or local development.
- Configure TLS termination carefully behind reverse proxies.
- Keep `TRUST_PROXY=false` unless the relay is behind a trusted proxy that controls forwarding headers.

## Secrets

- Keep admin tokens, transparency signing keys, TLS keys, and signing credentials outside the repository.
- Restrict filesystem permissions for data and secret directories.
- Rotate secrets after suspected exposure.

## Relay Operator API

The relay operator API is disabled by default. If enabled, it requires a long random token and restricted network exposure.

## Retention

Configure message, attachment, report, and device-event retention for the deployment. Shorter retention reduces post-compromise exposure but can affect usability.

## Boundary

Self-hosting reduces dependency on a third-party relay operator. It does not remove metadata visible to the relay.

## Witness Transparency

Run a witness when you want an independent observer for relay transparency heads. The current public Notrus deployment uses:

```text
Relay origin:   https://relay.notrus.cloud
Witness origin: https://witness.notrus.cloud
```

Witness behavior, check endpoints, healthy output, and warning signs are documented in [witness-transparency.md](witness-transparency.md).

If the witness is publicly exposed, set `WITNESS_ADMIN_TOKEN` so detailed history endpoints require `X-Notrus-Witness-Admin-Token`. Keep the public `/api/witness/head` endpoint available for clients unless you also add client-side witness-token support.

## DuckDNS + Caddy

The repository includes a free self-hosting template at `deploy/duckdns-caddy/`.

Use it when you want a normal HTTPS relay without ngrok:

- DuckDNS provides a free `*.duckdns.org` hostname.
- Caddy terminates HTTPS and reverse-proxies to the local relay.
- The relay binds to `127.0.0.1:3000`, so only Caddy is exposed publicly.
- Server-Sent Events work through normal Caddy reverse proxying, unlike Cloudflare Quick Tunnel.

Requirements:

- A Linux host reachable on public TCP ports `80` and `443`.
- A DuckDNS token and chosen subdomain.
- A working Node.js runtime for the relay.
- Caddy installed on the host.

Keep `TRUST_PROXY=true` only when the Node relay is bound to localhost and Caddy is the only public entrypoint.
