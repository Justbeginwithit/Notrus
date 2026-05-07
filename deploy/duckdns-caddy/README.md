# Notrus Relay With DuckDNS And Caddy

This deployment path is for a free or near-free self-hosted relay with:

- a Linux host that can receive public traffic on ports `80` and `443`
- DuckDNS for a free `*.duckdns.org` hostname
- Caddy for automatic HTTPS and reverse proxying to the local Notrus relay

This is more production-like than ngrok or Cloudflare Quick Tunnel because normal HTTPS and Server-Sent Events work through Caddy.

## Required Inputs

You need these before the setup can be completed:

- `DUCKDNS_DOMAIN`: the DuckDNS subdomain without `.duckdns.org`, for example `notrus-relay`
- `DUCKDNS_TOKEN`: the token shown in your DuckDNS account
- a reachable Linux host, for example an Oracle Cloud Always Free VM or a home server with ports `80` and `443` forwarded

The final relay URL will be:

```text
https://DUCKDNS_DOMAIN.duckdns.org
```

## Recommended Host

Use Ubuntu 24.04 or newer on an Oracle Cloud Always Free VM if you want a free 24/7 host. A local Mac or home machine can also work, but only if your router forwards ports `80` and `443` to it and your ISP does not block inbound traffic.

## Files

- `Caddyfile`: HTTPS reverse proxy to `127.0.0.1:3000`
- `notrus-relay.env.example`: relay environment template
- `notrus-relay.service`: systemd unit for the relay
- `duckdns-update.sh`: DuckDNS IP updater
- `notrus-duckdns.service`: one-shot systemd unit for DuckDNS updates
- `notrus-duckdns.timer`: runs the DuckDNS updater every 5 minutes
- `install-ubuntu.sh`: installs the templates on a Linux host

## Setup

Copy the Notrus repository to the server, then run:

```bash
cd /opt/notrus
sudo NOTRUS_PUBLIC_HOST=notrus-relay.duckdns.org \
  DUCKDNS_DOMAIN=notrus-relay \
  DUCKDNS_TOKEN=replace-with-duckdns-token \
  deploy/duckdns-caddy/install-ubuntu.sh
```

Then install dependencies and start:

```bash
npm install --omit=dev
sudo systemctl enable --now notrus-duckdns.timer
sudo systemctl enable --now notrus-relay.service
sudo systemctl reload caddy
```

Verify:

```bash
curl -s https://notrus-relay.duckdns.org/api/health
```

## Security Notes

- Keep `/etc/notrus/notrus-relay.env` readable only by root.
- Keep `NOTRUS_ENABLE_ADMIN_API=false` unless you need the admin UI.
- If admin API is enabled, set a long random `NOTRUS_ADMIN_API_TOKEN`.
- The relay binds to `127.0.0.1`, so only Caddy should be public.
- `TRUST_PROXY=true` is safe only when the relay is not directly reachable from the internet and Caddy is the trusted local proxy.
- DuckDNS gives DNS only. Caddy provides HTTPS certificates.

## Router / Firewall

For a home server:

- forward public TCP `80` to server TCP `80`
- forward public TCP `443` to server TCP `443`

For Oracle Cloud:

- allow ingress TCP `80`
- allow ingress TCP `443`
- do not expose relay port `3000`

## Limitations

DuckDNS is a free dynamic DNS service, not a paid SLA-backed DNS product. For serious production use, a paid domain with controlled DNS is more reliable. For early Notrus self-hosting, DuckDNS plus Caddy is a practical free compromise.
