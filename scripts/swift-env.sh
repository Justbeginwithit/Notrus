#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi

export HOME="$ROOT_DIR/.build/swift-home"
export XDG_CACHE_HOME="$ROOT_DIR/.build/xdg-cache"
export TMPDIR="$ROOT_DIR/.build/tmp/"
export CLANG_MODULE_CACHE_PATH="$ROOT_DIR/.build/module-cache"
export SWIFT_MODULECACHE_PATH="$ROOT_DIR/.build/module-cache"

mkdir -p \
  "$HOME" \
  "$XDG_CACHE_HOME" \
  "$TMPDIR" \
  "$CLANG_MODULE_CACHE_PATH"
