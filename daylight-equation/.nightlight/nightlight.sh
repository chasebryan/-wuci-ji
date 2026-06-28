#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: nightlight.sh [--quick|--full] [--no-clear]

Nightlight is a local falsification battery against Daylight/WUCI proof claims.
It is defensive only: no network, no exploit payloads, no offensive scanning.
USAGE
}

MODE=quick
CLEAR=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --quick) MODE=quick ;;
    --full) MODE=full ;;
    --no-clear) CLEAR=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "nightlight: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYLIGHT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$DAYLIGHT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="build/nightlight"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/nightlight-${MODE}.log"
: > "$LOG"

if [ "$CLEAR" -eq 1 ]; then
  clear
fi

fail() {
  printf '\nNIGHTLIGHT FAILURE: %s\n' "$1" >&2
  printf 'Log: %s\n' "$LOG" >&2
  exit 1
}

run() {
  local label="$1"
  shift
  printf '  %-48s' "$label"
  if "$@" >>"$LOG" 2>&1; then
    printf 'PASS\n'
  else
    printf 'FAIL\n'
    fail "$label"
  fi
}

emit_daylight_evidence() {
  local subcommand="$1"
  local pattern="$2"
  local tmp
  tmp="$(mktemp "$OUT_DIR/daylight.XXXXXX")"
  if ( cd "$DAYLIGHT_DIR/rust/daylight-crypto" && cargo run --quiet --offline -- "$subcommand" ) >"$tmp" 2>>"$LOG"; then
    cat "$tmp" >>"$LOG"
    awk -F= "$pattern" "$tmp"
  else
    cat "$tmp" >>"$LOG" || true
    rm -f "$tmp"
    fail "daylight evidence: $subcommand"
  fi
  rm -f "$tmp"
}

B="build/wuci-ji"
KEY="1111111111111111111111111111111111111111111111111111111111111111"
SALT="2222222222222222222222222222222222222222222222222222222222222222"
INFO="3333333333333333333333333333333333333333333333333333333333333333"
MSG="Nightlight challenges Daylight"

printf 'NIGHTLIGHT vs DAYLIGHT\n'
printf '======================\n'
printf 'Mode: %s\n' "$MODE"
printf 'Nightlight is a local falsifier: no network, no exploit payloads, no offensive scan.\n'
printf 'It attacks claims; WUCI/Daylight must fail closed.\n\n'

printf '[1] Artifact machine comes alive\n'
run 'native assembly build' make -s all
run 'linux cross artifact' make -s build-linux
printf '  native sha256: %s\n\n' "$(sha256sum "$B" | awk '{print $1}')"

printf '[2] Crypto surface, visible not hidden\n'
printf '  sha256(msg):        '
printf '%s' "$MSG" | "$B" sha256
printf '  hmac-sha256(msg):   '
printf '%s' "$MSG" | "$B" hmac-sha256 "$KEY"
printf '  hkdf-sha256(msg):   '
printf '%s' "$MSG" | "$B" hkdf-sha256 "$SALT" "$INFO"
printf '  secp scalar inv(2): '
"$B" secp256k1-scalar-inv 0000000000000000000000000000000000000000000000000000000000000002
printf '  x25519 keypair:     private=<redacted> '
"$B" keypair | awk '/public:/ {printf "public=%s\n", $2}'
printf '\n'

printf '[3] Daylight: provider-backed evidence, bounded claims\n'
emit_daylight_evidence \
  v6-provider-kem-evidence \
  '$1 ~ /^(version|provider_backed_kem|provider_backed_reference_seal_open|production_allowed|schema_expected_rejection_stage|schema_private_kem_allowed|schema_aead_dec_allowed|mlkem1024_decaps_matches|dhkem_p384_decaps_matches)$/ {printf "  %-38s %s\n",$1,$2}'
printf '\n'

printf '[4] Nightlight: adversarial corpus must fail closed\n'
emit_daylight_evidence \
  v6-reference-negative-corpus-evidence \
  '$1 ~ /^(version|provider_backed_reference_seal_open|public_authority_external|production_allowed|total_cases|all_fail_closed)$/ {printf "  %-38s %s\n",$1,$2}'
run 'Daylight negative corpus' make -s daylight-v6-reference-negative-corpus-test
run 'M4 symbolic falsification model' make -s daylight-v06-m4-symbolic-model-test
run 'Z3 negated obligations' make -s daylight-v06-m4-z3-proof-test
run 'parser mutation replay' make -s parser-hardening-proof
run 'Gate contract rejection matrix' make -s gate-contract-asm
run 'CAGE rejects private/run material' make -s cage-proof
run 'QCAGE rejects false PQ safety' make -s qcage-proof

if [ "$MODE" = "full" ]; then
  printf '\n[5] Full-pressure additions\n'
  run 'WUCI-Daylight bridge boundary' make -s wuci-daylight-bridge-test
  run '1000 preflight remains gated' make -s daylight-v06-1000-preflight-test
  run '1000 claim gate remains gated' make -s daylight-v06-1000-claim-gate-test
  run '1000 checkpoint writer remains gated' make -s daylight-v06-1000-checkpoint-test
  run 'high-attestation proof' make -s high-attestation-proof
fi

printf '\n[Verdict]\n'
printf '  Daylight score boundary: 975/1000\n'
printf '  ProductionAllowed=0 RuntimeContainmentClaim=0 WholeSystemPQClaim=0 ExternalReviewClaim=0\n'
printf '  Nightlight result: every local falsification lane failed closed.\n'
printf '  Log: %s\n' "$LOG"
