#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PACKAGE_PATH="$ROOT_DIR/native/macos/NotrusMac"

zsh "$ROOT_DIR/scripts/build-protocol-core.sh"
source "$ROOT_DIR/scripts/swift-env.sh"

swift build --disable-sandbox --package-path "$PACKAGE_PATH"
