#!/usr/bin/env bash
set -euo pipefail

: "${DUCKDNS_DOMAIN:?Set DUCKDNS_DOMAIN without .duckdns.org}"
: "${DUCKDNS_TOKEN:?Set DUCKDNS_TOKEN from your DuckDNS account}"

response="$(curl -fsS "https://www.duckdns.org/update?domains=${DUCKDNS_DOMAIN}&token=${DUCKDNS_TOKEN}&verbose=true")"

case "${response}" in
  *OK*)
    printf '%s\n' "${response}"
    ;;
  *)
    printf 'DuckDNS update failed: %s\n' "${response}" >&2
    exit 1
    ;;
esac
