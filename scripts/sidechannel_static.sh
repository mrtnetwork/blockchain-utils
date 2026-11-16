#!/usr/bin/env bash
# Static side-channel pattern scan for blockchain-utils curve code.
# Usage: from repo root:  ./scripts/sidechannel_static.sh
# Exit 0 = no high-severity hits (warnings may still print).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RED=$'\033[31m'
YEL=$'\033[33m'
GRN=$'\033[32m'
RST=$'\033[0m'

echo "=== Side-channel static scan ==="
echo "Root: $ROOT"
echo

FAIL=0
WARN=0

# --- High: branching directly on scalar.bit without ct_select nearby (heuristic) ---
echo "[1] Secret-looking branches on .bit( / is_odd in curve (manual review)"
# Flag `if scalar.bit` or `if bit ==` style
if rg -n --type rust 'if\s+.*\.bit\s*\(|if\s+bit\s*==|if\s+bit\s*\!=' src/curve 2>/dev/null; then
  echo "${YEL}WARN${RST}: found if-on-bit patterns — confirm CT select is used"
  WARN=$((WARN+1))
else
  echo "${GRN}OK${RST}: no crude if-on-bit patterns"
fi
echo

# --- High: == on byte arrays that might be secrets (keys) ---
echo "[2] Non-CT equality on [u8; 32] / [u8; 64] in curve (prefer ct_eq)"
if rg -n --type rust 'assert_eq!\(\s*[a-z_]+,\s*[a-z_]+\)|\[[u8; 32]\].*==|secret.*=|private_key.*==' src/curve 2>/dev/null | head -20; then
  echo "${YEL}WARN${RST}: possible non-CT compares (tests often OK)"
  WARN=$((WARN+1))
else
  echo "${GRN}OK${RST}"
fi
echo

# --- Medium: vartime markers ---
echo "[3] Explicit vartime / variable-time APIs"
rg -n --type rust -i 'vartime|variable.?time|ge_fromfe|try.?and.?increment' src/curve || true
echo "(These must only process public inputs.)"
echo

# --- Medium: early return on is_zero / infinity in point add ---
echo "[4] Exceptional branches in point add (infinity / h==0)"
rg -n --type rust 'if .*\.is_infinity|if .*\.is_zero\(\)|if h\.is_zero|if r\.is_zero' src/curve || true
echo "${YEL}INFO${RST}: Jacobian exceptional cases — OK if only public points"
echo

# --- Good: CT primitives used ---
echo "[5] CT primitive usage counts"
echo -n "  ct_eq / ct_select calls: "
rg -c --type rust 'ct_eq|ct_select' src/curve 2>/dev/null | awk -F: '{s+=$2} END {print s+0}'
echo -n "  mul_ct definitions: "
rg -c --type rust 'fn mul_ct' src/curve 2>/dev/null | awk -F: '{s+=$2} END {print s+0}'
echo

# --- mul dispatches to mul_ct? ---
echo "[6] CurvePoint::mul should call mul_ct where available"
for f in src/curve/ed25519/point.rs src/curve/secp256k1/point.rs src/curve/secp256r1/point.rs; do
  if [[ -f "$f" ]]; then
    if rg -q 'fn mul\(' "$f" && rg -q 'mul_ct' "$f"; then
      echo "  ${GRN}OK${RST}: $f has mul + mul_ct"
    else
      echo "  ${RED}FAIL${RST}: $f missing mul_ct linkage"
      FAIL=$((FAIL+1))
    fi
  fi
done
echo

# --- Monero must not be used as secret map ---
echo "[7] Monero from_fe documentation"
if rg -q 'vartime|public|Elligator' src/curve/ed25519/monero.rs 2>/dev/null; then
  echo "  ${GRN}OK${RST}: monero module present (treat as VT)"
else
  echo "  ${YEL}WARN${RST}: check monero.rs docs"
  WARN=$((WARN+1))
fi
echo

# --- Summary ---
echo "=== Summary ==="
echo "FAIL=$FAIL  WARN=$WARN"
if [[ "$FAIL" -gt 0 ]]; then
  echo "${RED}High-severity issues found.${RST}"
  exit 1
fi
echo "${GRN}Static scan finished (review WARNs manually).${RST}"
exit 0
