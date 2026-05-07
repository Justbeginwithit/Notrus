# Endpoint Provider Guide

This document explains the practical relay/witness hosting options for Notrus and the current recommended setup. Message contents remain end-to-end encrypted, but the endpoint provider can still observe transport metadata such as client IPs, hostnames, request timing, paths, traffic volume, and connection behavior.

## Current Notrus Deployment

Current public endpoints:

```text
Relay origin:   https://relay.notrus.cloud
Witness origin: https://witness.notrus.cloud
Relay console:  https://relay.notrus.cloud/admin
Witness console: https://witness.notrus.cloud/witness
```

Current routing:

```text
relay.notrus.cloud   -> Cloudflare Tunnel -> local relay on 127.0.0.1:3000
witness.notrus.cloud -> Cloudflare Tunnel -> local witness on 127.0.0.1:3400
```

This gives stable public URLs without opening inbound router ports, but the backend still depends on the Mac that runs `cloudflared`, the relay, the witness, and attestation services.

## Provider Options

| Option | Best Use | Ease | Reliability | Cost | Main Caveat |
| --- | --- | --- | --- | --- | --- |
| Cloudflare Named Tunnel with owned domain | Current best compromise for beta testing and small self-hosting | Medium | Good while the host is awake and `cloudflared` runs | Domain cost; Cloudflare Tunnel is available on Cloudflare plans | Cloudflare is in the transport path and the local host is still infrastructure |
| Cloudflare Quick Tunnel (`trycloudflare.com`) | Temporary testing only | Easy | Not suitable for production | Free | Random URL, no SLA/uptime guarantee, 200 in-flight request limit, no SSE support |
| ngrok free dev endpoint | Quick demos and temporary API testing | Easy | Limited by free-plan quotas | Free | Free plan has monthly request/data/connection limits and no custom domain |
| ngrok paid/custom domain | Simple managed tunnel with predictable endpoint | Easy | Better than free dev endpoints | Paid | Provider traffic metadata still visible; usage limits and costs depend on plan |
| DuckDNS + Caddy on home network | Free domain-like hostname with normal HTTPS and SSE | Medium to hard | Depends on ISP/router/home power | Free plus hardware/power | Requires public inbound ports `80`/`443` and exposes home IP/origin path |
| VPS or dedicated always-on host | Most production-like current Node.js deployment | Medium | Best normal option | Paid | Requires server hardening, backups, monitoring, and secret custody |

## Recommendation

For Notrus beta testing:

```text
Best current choice: Cloudflare Named Tunnel + owned domain
```

Reasons:

- stable public hostnames
- no router port forwarding
- no direct origin IP exposure
- supports the relay and witness as separate hostnames through one tunnel
- easier than maintaining a VPS while still being more stable than random temporary tunnel URLs

For production-like public availability:

```text
Best next step: move the relay/witness to an always-on VPS or dedicated mini-server, then keep Cloudflare Tunnel or put Caddy/reverse proxy in front.
```

The current Mac-backed setup is acceptable for beta testing, but it is not independent infrastructure. If the Mac sleeps, restarts, loses network, or the tunnel process dies, the public endpoints stop working.

## Cloudflare Named Tunnel

Cloudflare Tunnel connects the local origin to Cloudflare with outbound-only `cloudflared` connections. The origin does not need public inbound ports. Cloudflare documents Tunnel as available on all plans and describes named tunnels as the production path for public applications.

Current Notrus Cloudflare ingress shape:

```yaml
tunnel: <notrus-relay-tunnel-id>
credentials-file: /Users/tim/.cloudflared/<notrus-relay-tunnel-id>.json

ingress:
  - hostname: relay.notrus.cloud
    service: http://127.0.0.1:3000
  - hostname: witness.notrus.cloud
    service: http://127.0.0.1:3400
  - service: http_status:404
```

Security notes:

- Keep `/Users/tim/.cloudflared/` private.
- Do not commit tunnel credentials.
- Cloudflare can see transport metadata, not Notrus message plaintext.
- Use `launchd`, systemd, or another service manager so `cloudflared` restarts after reboot.
- If higher availability is needed, Cloudflare supports multiple replicas for a tunnel; each replica creates additional Cloudflare connections.

## Cloudflare Quick Tunnel

Cloudflare Quick Tunnel is useful for a temporary public URL while testing. It should not be used as the normal Notrus relay endpoint.

Known current limitations from Cloudflare documentation:

- intended for testing and development
- random `trycloudflare.com` subdomain
- no uptime/SLA guarantee
- currently limited to 200 in-flight proxied requests
- does not support Server-Sent Events

Because Notrus uses event/live-update paths and benefits from stable endpoints, Quick Tunnel is not a good beta relay default.

## ngrok

ngrok is useful for demos and quick remote testing. The free plan is not a good default for Notrus beta usage because it has quota and domain restrictions.

Current ngrok free-plan limits documented by ngrok include:

- up to 3 online endpoints
- 20,000 HTTP requests per month
- 1 GB/month data transfer out
- 5,000 TCP connections per month
- one automatically assigned development domain
- no custom domain on the free plan
- browser interstitial for HTML traffic unless bypassed by supported methods or upgraded

ngrok paid plans can be reasonable for users who prefer a managed tunnel and are willing to pay for custom domains and higher limits.

## DuckDNS + Caddy

DuckDNS + Caddy remains a valid free self-hosting route when the operator can expose a machine on public ports `80` and `443`.

Use this when:

- you have a public IPv4/IPv6 path or can port-forward from the router
- you want normal HTTPS termination through Caddy
- you want Server-Sent Events to work through a conventional reverse proxy
- you are comfortable exposing a home-hosted service path

Avoid this when:

- your ISP blocks inbound ports
- your router cannot port-forward
- you do not want your home IP/origin path exposed
- you cannot keep the host online

The repository template is under:

```text
deploy/duckdns-caddy/
```

Caddy provides automatic HTTPS and can reverse-proxy to the local relay. The relay should still bind to localhost when Caddy is the public entrypoint.

## VPS Or Dedicated Host

A VPS or dedicated mini-server is the cleanest production-like deployment for the current Node.js relay.

Use this when:

- multiple people depend on the relay
- you need uptime independent from a laptop
- you need predictable backups and monitoring
- you want service-manager restarts after reboot
- you can keep secrets and OS packages maintained

Recommended shape:

```text
Cloudflare DNS/Tunnel or Caddy/TLS
  -> Notrus relay service
  -> Notrus witness service
  -> Notrus attestation service
  -> encrypted/permission-restricted data and secret directories
```

## Operational Checklist

For the current Cloudflare setup:

- Keep `https://relay.notrus.cloud` as the client relay origin.
- Keep `https://witness.notrus.cloud` as the client witness origin.
- Keep `https://relay.notrus.cloud/admin` for the relay operator console.
- Keep `https://witness.notrus.cloud/witness` for the witness console.
- Protect relay operator actions with `X-Notrus-Admin-Token`.
- Protect detailed witness history with `X-Notrus-Witness-Admin-Token`.
- Rotate both tokens if pasted into chat, logs, screenshots, or issue trackers.
- Install relay, witness, attestation, and Cloudflare Tunnel as startup services before relying on the endpoints for long tests.

## Sources

- Cloudflare Tunnel: https://developers.cloudflare.com/tunnel/
- Cloudflare Tunnel configuration and replicas: https://developers.cloudflare.com/tunnel/configuration/
- Cloudflare Quick Tunnel limitations: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/
- ngrok free-plan limits: https://ngrok.com/docs/pricing-limits/free-plan-limits/
- Caddy automatic HTTPS: https://caddyserver.com/docs/automatic-https
- Caddy reverse proxy: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
