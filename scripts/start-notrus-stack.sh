#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${NOTRUS_STACK_ENV_FILE:-$ROOT_DIR/.notrus-local.env}"
RUN_DIR="${NOTRUS_STACK_RUN_DIR:-$ROOT_DIR/.notrus-stack}"
LOG_DIR="$RUN_DIR/logs"
PID_DIR="$RUN_DIR/pids"

RELAY_PUBLIC_ORIGIN="${RELAY_PUBLIC_ORIGIN:-https://relay.notrus.cloud}"
WITNESS_PUBLIC_ORIGIN="${WITNESS_PUBLIC_ORIGIN:-https://witness.notrus.cloud}"
RELAY_HOST="${RELAY_HOST:-127.0.0.1}"
RELAY_PORT="${RELAY_PORT:-3000}"
WITNESS_HOST="${WITNESS_HOST:-127.0.0.1}"
WITNESS_PORT="${WITNESS_PORT:-3400}"
ATTESTATION_HOST="${ATTESTATION_HOST:-127.0.0.1}"
ATTESTATION_PORT="${ATTESTATION_PORT:-3500}"
CLOUDFLARED_CONFIG="${CLOUDFLARED_CONFIG:-$HOME/.cloudflared/config.yml}"

NOTRUS_DATA_DIR="${NOTRUS_DATA_DIR:-$ROOT_DIR/data}"
NOTRUS_SECRET_DIR="${NOTRUS_SECRET_DIR:-$ROOT_DIR/.secrets}"
WITNESS_DATA_DIR="${WITNESS_DATA_DIR:-$ROOT_DIR/data}"

COMMAND="${1:-start}"

mkdir -p "$LOG_DIR" "$PID_DIR" "$NOTRUS_DATA_DIR" "$NOTRUS_SECRET_DIR" "$WITNESS_DATA_DIR"

random_token() {
  node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url"))'
}

write_default_env() {
  if [[ -f "$ENV_FILE" ]]; then
    return
  fi

  umask 077
  cat >"$ENV_FILE" <<EOF
# Local Notrus stack secrets. Do not commit this file.
NOTRUS_ADMIN_API_TOKEN=$(random_token)
WITNESS_ADMIN_TOKEN=$(random_token)
RATE_LIMIT_HMAC_KEY=$(random_token)
POW_HMAC_KEY=$(random_token)
EOF
  chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE with local admin/witness tokens."
}

load_env() {
  write_default_env
  set -a
  source "$ENV_FILE"
  set +a
}

pid_alive() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

port_listener() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR == 2 {print $2}'
}

cloudflared_listener() {
  ps -axo pid=,command= | awk -v cfg="$CLOUDFLARED_CONFIG" '
    /cloudflared tunnel/ && index($0, cfg) > 0 {
      print $1
      exit
    }
  '
}

adopt_pid() {
  local name="$1"
  local pid="$2"
  local pid_file="$PID_DIR/$name.pid"
  if [[ -n "$pid" && ! -f "$pid_file" ]]; then
    echo "$pid" >"$pid_file"
    echo "Adopted existing $name process with PID $pid."
  fi
}

start_process() {
  local name="$1"
  local pid_file="$PID_DIR/$name.pid"
  shift

  if pid_alive "$pid_file"; then
    echo "$name already running with PID $(cat "$pid_file")."
    return
  fi

  nohup "$@" >"$LOG_DIR/$name.log" 2>&1 &
  echo $! >"$pid_file"
  echo "Started $name with PID $(cat "$pid_file"). Logs: $LOG_DIR/$name.log"
}

stop_process() {
  local name="$1"
  local pid_file="$PID_DIR/$name.pid"
  if ! pid_alive "$pid_file"; then
    rm -f "$pid_file"
    echo "$name is not managed/running."
    return
  fi

  local pid
  pid="$(cat "$pid_file")"
  kill "$pid"
  rm -f "$pid_file"
  echo "Stopped $name with PID $pid."
}

wait_for_url() {
  local label="$1"
  local url="$2"
  local max_attempts="${3:-30}"
  local attempt=1

  while (( attempt <= max_attempts )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "$label OK: $url"
      return
    fi
    sleep 1
    attempt=$((attempt + 1))
  done

  echo "$label not reachable after ${max_attempts}s: $url" >&2
  return 1
}

start_stack() {
  load_env

  if [[ ! -f "$CLOUDFLARED_CONFIG" ]]; then
    echo "Missing Cloudflare Tunnel config: $CLOUDFLARED_CONFIG" >&2
    exit 1
  fi

  if [[ -n "$(port_listener "$ATTESTATION_PORT")" && ! -f "$PID_DIR/attestation.pid" ]]; then
    adopt_pid attestation "$(port_listener "$ATTESTATION_PORT")"
  else
    start_process attestation \
      env ATTESTATION_HOST="$ATTESTATION_HOST" ATTESTATION_PORT="$ATTESTATION_PORT" \
      node "$ROOT_DIR/attestation.js"
  fi

  if [[ -n "$(port_listener "$RELAY_PORT")" && ! -f "$PID_DIR/relay.pid" ]]; then
    adopt_pid relay "$(port_listener "$RELAY_PORT")"
  else
    start_process relay \
      env HOST="$RELAY_HOST" PORT="$RELAY_PORT" CLIENT_ORIGIN="*" TRUST_PROXY=true \
      NOTRUS_DATA_DIR="$NOTRUS_DATA_DIR" \
      NOTRUS_SECRET_DIR="$NOTRUS_SECRET_DIR" \
      NOTRUS_ATTESTATION_ORIGIN="http://$ATTESTATION_HOST:$ATTESTATION_PORT" \
      NOTRUS_REQUIRE_ANDROID_ATTESTATION="${NOTRUS_REQUIRE_ANDROID_ATTESTATION:-false}" \
      NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY="${NOTRUS_REQUIRE_ANDROID_PLAY_INTEGRITY:-false}" \
      NOTRUS_REQUIRE_APPLE_DEVICECHECK="${NOTRUS_REQUIRE_APPLE_DEVICECHECK:-false}" \
      NOTRUS_PROTOCOL_POLICY=require-standards \
      NOTRUS_ENABLE_DEVELOPMENT_COMPAT_ROUTES=false \
      NOTRUS_ENABLE_LEGACY_API=false \
      NOTRUS_ENABLE_ADMIN_API=true \
      NOTRUS_ADMIN_API_TOKEN="$NOTRUS_ADMIN_API_TOKEN" \
      RATE_LIMIT_HMAC_KEY="$RATE_LIMIT_HMAC_KEY" \
      POW_HMAC_KEY="$POW_HMAC_KEY" \
      node "$ROOT_DIR/server.js"
  fi

  if [[ -n "$(port_listener "$WITNESS_PORT")" && ! -f "$PID_DIR/witness.pid" ]]; then
    adopt_pid witness "$(port_listener "$WITNESS_PORT")"
  else
    start_process witness \
      env WITNESS_HOST="$WITNESS_HOST" WITNESS_PORT="$WITNESS_PORT" \
      WITNESS_DATA_DIR="$WITNESS_DATA_DIR" \
      WITNESS_ADMIN_TOKEN="$WITNESS_ADMIN_TOKEN" \
      RELAY_ORIGINS="$RELAY_PUBLIC_ORIGIN" \
      node "$ROOT_DIR/witness.js"
  fi

  if [[ -n "$(cloudflared_listener)" && ! -f "$PID_DIR/cloudflared.pid" ]]; then
    adopt_pid cloudflared "$(cloudflared_listener)"
  else
    start_process cloudflared \
      cloudflared tunnel --config "$CLOUDFLARED_CONFIG" run
  fi

  health_stack
}

stop_stack() {
  stop_process cloudflared
  stop_process witness
  stop_process relay
  stop_process attestation
}

status_stack() {
  for name in attestation relay witness cloudflared; do
    local pid_file="$PID_DIR/$name.pid"
    if pid_alive "$pid_file"; then
      echo "$name: running PID $(cat "$pid_file")"
    else
      echo "$name: not managed/running"
    fi
  done

  echo "Relay origin:   $RELAY_PUBLIC_ORIGIN"
  echo "Witness origin: $WITNESS_PUBLIC_ORIGIN"
  echo "Relay admin:    $RELAY_PUBLIC_ORIGIN/admin"
  echo "Witness GUI:    $WITNESS_PUBLIC_ORIGIN/witness"
  echo "Tunnel config:  $CLOUDFLARED_CONFIG"
  echo "Local env file: $ENV_FILE"
}

health_stack() {
  wait_for_url "Local relay" "http://$RELAY_HOST:$RELAY_PORT/api/health" 20
  wait_for_url "Local attestation" "http://$ATTESTATION_HOST:$ATTESTATION_PORT/api/attestation/health" 20
  wait_for_url "Local witness" "http://$WITNESS_HOST:$WITNESS_PORT/api/witness/health" 20
  wait_for_url "Public relay" "$RELAY_PUBLIC_ORIGIN/api/health" 40
  wait_for_url "Public witness" "$WITNESS_PUBLIC_ORIGIN/api/witness/health" 40
  wait_for_url "Public witness head" "$WITNESS_PUBLIC_ORIGIN/api/witness/head?relayOrigin=$RELAY_PUBLIC_ORIGIN" 40
}

case "$COMMAND" in
  start)
    start_stack
    ;;
  stop)
    stop_stack
    ;;
  restart)
    stop_stack
    start_stack
    ;;
  status)
    status_stack
    ;;
  health)
    health_stack
    ;;
  *)
    echo "Usage: $0 [start|stop|restart|status|health]" >&2
    exit 2
    ;;
esac
