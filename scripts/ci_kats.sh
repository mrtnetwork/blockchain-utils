#!/usr/bin/env bash
# P0 #5 / #2 CI gate: locked KATs + OpenSSL differential + self-consistency.
#
# Exit non-zero on any failure. Intended for local and CI use:
#   bash scripts/ci_kats.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

echo "=== [1/4] locked KATs (P0 #5) ==="
cargo test --test kats kat_locked -- --nocapture

echo "=== [2/4] algebraic self-diff (P0 #2 supplement) ==="
cargo test --test diff diff_self -- --nocapture

echo "=== [3/4] OpenSSL differential (P0 #2, skip if no openssl) ==="
# Single-threaded: avoids any residual tempfile races
cargo test --test diff diff_openssl -- --nocapture --test-threads=1

echo "=== [4/5] BIP-340 + RFC6979 official vectors (item 10) ==="
cargo test --test kats rfc6979_bip340_vectors -- --nocapture

echo "=== [5/5] in-tree curve_vectors + critical lib tests ==="
cargo test --test kats curve_vectors -- --nocapture
# Lib tests that hard-assert QUUX / Ristretto / pairing
# (cargo test takes a single TESTNAME filter: loop over them).
for t in hash_to_g1_quux_abc_px quux_abc_u0_u1 pairing_bilinearity rfc9496_basepoint_roundtrip; do
  cargo test --lib "$t" -- --nocapture
done

echo "=== timing smoke (optional) ==="
cargo test --test diff ct_timing_smoke -- --nocapture || true

echo "=== CI KAT gate: ALL GREEN ==="
