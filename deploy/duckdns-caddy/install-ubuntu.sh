#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root, for example: sudo NOTRUS_PUBLIC_HOST=... DUCKDNS_DOMAIN=... DUCKDNS_TOKEN=... $0" >&2
  exit 1
fi

: "${NOTRUS_PUBLIC_HOST:?Set NOTRUS_PUBLIC_HOST, for example notrus-relay.duckdns.org}"
: "${DUCKDNS_DOMAIN:?Set DUCKDNS_DOMAIN without .duckdns.org}"
: "${DUCKDNS_TOKEN:?Set DUCKDNS_TOKEN from your DuckDNS account}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${REPO_DIR}" != "/opt/notrus" ]]; then
  echo "This installer expects the Notrus repo at /opt/notrus." >&2
  echo "Current repo path: ${REPO_DIR}" >&2
  echo "Move or clone the repo to /opt/notrus before running this installer." >&2
  exit 1
fi

install -d -m 0755 /etc/notrus
install -d -m 0750 -o root -g root /var/lib/notrus/data /var/lib/notrus/secrets

if ! id notrus >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/notrus --shell /usr/sbin/nologin notrus
fi

chown -R notrus:notrus /var/lib/notrus

if [[ ! -f /etc/notrus/notrus-relay.env ]]; then
  install -m 0600 "${SCRIPT_DIR}/notrus-relay.env.example" /etc/notrus/notrus-relay.env
fi

sed -i "s|^NOTRUS_PUBLIC_HOST=.*|NOTRUS_PUBLIC_HOST=${NOTRUS_PUBLIC_HOST}|" /etc/notrus/notrus-relay.env

if grep -q '^RATE_LIMIT_HMAC_KEY=$' /etc/notrus/notrus-relay.env; then
  sed -i "s|^RATE_LIMIT_HMAC_KEY=.*|RATE_LIMIT_HMAC_KEY=$(openssl rand -hex 32)|" /etc/notrus/notrus-relay.env
fi

if grep -q '^POW_HMAC_KEY=$' /etc/notrus/notrus-relay.env; then
  sed -i "s|^POW_HMAC_KEY=.*|POW_HMAC_KEY=$(openssl rand -hex 32)|" /etc/notrus/notrus-relay.env
fi

cat >/etc/notrus/duckdns.env <<EOF
DUCKDNS_DOMAIN=${DUCKDNS_DOMAIN}
DUCKDNS_TOKEN=${DUCKDNS_TOKEN}
EOF
chmod 0600 /etc/notrus/duckdns.env

install -m 0755 "${SCRIPT_DIR}/duckdns-update.sh" /usr/local/bin/notrus-duckdns-update
install -m 0644 "${SCRIPT_DIR}/notrus-relay.service" /etc/systemd/system/notrus-relay.service
install -m 0644 "${SCRIPT_DIR}/notrus-duckdns.service" /etc/systemd/system/notrus-duckdns.service
install -m 0644 "${SCRIPT_DIR}/notrus-duckdns.timer" /etc/systemd/system/notrus-duckdns.timer

install -d -m 0755 /etc/caddy
sed "s|{\$NOTRUS_PUBLIC_HOST}|${NOTRUS_PUBLIC_HOST}|g" "${SCRIPT_DIR}/Caddyfile" >/etc/caddy/Caddyfile

systemctl daemon-reload
systemctl enable notrus-duckdns.timer
systemctl enable notrus-relay.service

if ! command -v caddy >/dev/null 2>&1; then
  echo "Caddy is not installed. On Ubuntu, install it with: apt-get update && apt-get install -y caddy" >&2
fi

echo "Installed Notrus DuckDNS/Caddy deployment files."
echo "Next:"
echo "  npm install --omit=dev"
echo "  systemctl start notrus-duckdns.service"
echo "  systemctl start notrus-relay.service"
echo "  systemctl reload caddy"
echo "  curl -s https://${NOTRUS_PUBLIC_HOST}/api/health"
