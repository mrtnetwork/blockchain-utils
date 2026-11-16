#!/usr/bin/env bash
# Run release timing smoke tests for scalar mul (dudect-style).
# Usage: ./scripts/timing_scalar_mul.sh [ed25519|secp256k1|all|...]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-all}"
export SAMPLES="${SAMPLES:-20000}"

echo "Building timing_harness (release) SAMPLES=$SAMPLES TARGET=$TARGET..."
cd "$ROOT/scripts/timing_harness"
cargo build --release
BIN=target/release/timing_harness
cp "$BIN" /tmp/timing_harness_bu 2>/dev/null || true
chmod +x /tmp/timing_harness_bu 2>/dev/null || true
if [[ -x /tmp/timing_harness_bu ]]; then
  /tmp/timing_harness_bu "$TARGET"
else
  "$BIN" "$TARGET"
fi
