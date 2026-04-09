#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PACKAGE_PATH="$ROOT_DIR/native/macos/NotrusMac"

source "$ROOT_DIR/scripts/swift-env.sh"

swift test --disable-sandbox --package-path "$PACKAGE_PATH"
