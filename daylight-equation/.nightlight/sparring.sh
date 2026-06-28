#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: sparring.sh [--quick|--full] [--rounds N] [--no-clear]

Run a Daylight vs Nightlight sparring match. Daylight presents evidence;
Nightlight applies local falsification pressure; WUCI proof lanes defend the
release-evidence boundary.
USAGE
}

MODE=quick
ROUNDS=1
CLEAR=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --quick) MODE=quick ;;
    --full) MODE=full ;;
    --rounds)
      shift
      [ "$#" -gt 0 ] || { echo "sparring: --rounds needs a value" >&2; exit 2; }
      ROUNDS="$1"
      ;;
    --no-clear) CLEAR=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "sparring: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$ROUNDS" in
  ''|*[!0-9]*) echo "sparring: rounds must be a positive integer" >&2; exit 2 ;;
esac
[ "$ROUNDS" -gt 0 ] || { echo "sparring: rounds must be positive" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYLIGHT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DAYLIGHT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="build/nightlight"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/sparring-${MODE}.log"
SCORE="$OUT_DIR/sparring-latest.txt"
: > "$LOG"
: > "$SCORE"

if [ "$CLEAR" -eq 1 ]; then
  clear
fi

fail() {
  printf '\nSPARRING FAILURE: %s\n' "$1" >&2
  printf 'Log: %s\n' "$LOG" >&2
  exit 1
}

run() {
  local corner="$1"
  local label="$2"
  shift 2
  printf '  %-10s %-46s' "$corner" "$label"
  if "$@" >>"$LOG" 2>&1; then
    printf 'PASS\n'
    printf '%s | %s | PASS\n' "$corner" "$label" >>"$SCORE"
  else
    printf 'FAIL\n'
    printf '%s | %s | FAIL\n' "$corner" "$label" >>"$SCORE"
    fail "$corner $label"
  fi
}

printf 'DAYLIGHT / NIGHTLIGHT SPARRING\n'
printf '==============================\n'
printf 'Mode: %s  Rounds: %s\n' "$MODE" "$ROUNDS"
printf 'Rule: Daylight can improve only if Nightlight still fails to falsify it.\n\n'

round=1
while [ "$round" -le "$ROUNDS" ]; do
  printf '[Round %s] Constructive evidence vs falsification pressure\n' "$round"

  run DAYLIGHT 'protocol-state and WUCI bridge' make -s wuci-daylight-bridge-test
  run DAYLIGHT 'provider vector agreement' make -s daylight-v6-provider-vector-agreement-test
  run DAYLIGHT 'KAT reproduction bundle' make -s daylight-v6-kat-reproduction-bundle-test

  run NIGHTLIGHT 'negative corpus fail-closed' make -s daylight-v6-reference-negative-corpus-test
  run NIGHTLIGHT 'M4 symbolic model' make -s daylight-v06-m4-symbolic-model-test
  run NIGHTLIGHT 'Z3 negated obligations' make -s daylight-v06-m4-z3-proof-test
  run NIGHTLIGHT 'parser mutation replay' make -s parser-hardening-proof

  run WUCI 'Gate contract boundary' make -s gate-contract-asm
  run WUCI 'CAGE artifact airlock' make -s cage-proof
  run WUCI 'QCAGE claim discipline' make -s qcage-proof

  run CLAIMS '1000 preflight remains gated' make -s daylight-v06-1000-preflight-test
  run CLAIMS '1000 claim gate remains gated' make -s daylight-v06-1000-claim-gate-test
  run CLAIMS '1000 checkpoint remains gated' make -s daylight-v06-1000-checkpoint-test

  if [ "$MODE" = "full" ]; then
    run WUCI 'kernel sandbox proof lane' make -s kernel-sandbox-proof
    run WUCI 'FIPS 204 verifier proof lane' make -s pq-verifier-fips204-proof
    run WUCI 'high-attestation proof' make -s high-attestation-proof
  fi

  printf '\n'
  round=$((round + 1))
done

printf '[Verdict]\n'
printf '  Sparring complete: Daylight evidence survived Nightlight pressure.\n'
printf '  Scoreboard: %s\n' "$SCORE"
printf '  Log: %s\n' "$LOG"
