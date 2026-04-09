#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

cargo build --release --manifest-path native/protocol-core/Cargo.toml

echo "Built protocol core:"
echo "  $ROOT_DIR/native/protocol-core/target/release/notrus-protocol-core"
echo "  $ROOT_DIR/native/protocol-core/target/release/libnotrus_protocol_core.a"
echo "  $ROOT_DIR/native/protocol-core/target/release/libnotrus_protocol_core.dylib"
