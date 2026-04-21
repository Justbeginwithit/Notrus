#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_PATH="${1:-$ROOT_DIR/dist/Notrus.app}"
ZIP_PATH="$ROOT_DIR/dist/Notrus.zip"
NOTARY_PROFILE="${NOTRUS_NOTARY_PROFILE:-}"

if [[ -z "$NOTARY_PROFILE" ]]; then
  echo "Set NOTRUS_NOTARY_PROFILE to a stored notarytool keychain profile." >&2
  exit 1
fi

if [[ ! -d "$APP_PATH" ]]; then
  echo "App bundle not found at $APP_PATH" >&2
  exit 1
fi

rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP_PATH"

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$ZIP_PATH" > "$ROOT_DIR/dist/Notrus.zip.sha256"
fi
