#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
README="$SCAFFOLD/README.md"
CONTRACT="$SCAFFOLD/profile-contract.md"
MANIFEST="$SCAFFOLD/contract-manifest.json"
PROBE3_VALIDATOR="$SCRIPT_DIR/validate-disposable-developer-profile.sh"
EVIDENCE_CONTRACT_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-dry-run-evidence-contract.sh"
failures=0

pass() {
	printf 'PASS: %s\n' "$1"
}

fail() {
	printf 'FAIL: %s\n' "$1"
	failures=$((failures + 1))
}

check_file() {
	file=$1
	label=$2
	if [ -f "$file" ]; then
		pass "$label exists"
	else
		fail "$label missing"
	fi
}

check_text() {
	file=$1
	label=$2
	text=$3
	if [ ! -f "$file" ]; then
		fail "$label missing because file is absent"
		return
	fi
	if grep -F -q "$text" "$file"; then
		pass "$label"
	else
		fail "$label missing"
	fi
}

check_forbidden_claims_absent() {
	if grep -RniE \
		"production ready|externally validated|runtime validated|ready for installation|secure by default|full isolation proven|developer profile implemented|operational readiness" \
		"$SCAFFOLD"; then
		fail "forbidden scaffold claim phrase present"
	else
		pass "forbidden scaffold claim phrases absent"
	fi
}

printf '%s\n' 'Disposable developer profile scaffold validator'
printf 'Scaffold: %s\n' "$SCAFFOLD"

check_file "$SCAFFOLD/.gitkeep" ".gitkeep"
check_file "$README" "README.md"
check_file "$CONTRACT" "profile-contract.md"
check_file "$MANIFEST" "contract-manifest.json"
check_file "$PROBE3_VALIDATOR" "Probe 3 validator"
check_file "$EVIDENCE_CONTRACT_VALIDATOR" "dry-run evidence contract validator"

check_text "$README" "README identifies Probe 4 scaffold-only scope" "Probe 4 is scaffold-only."
check_text "$README" "README reserves later structure" "reserves structure for a later"
check_text "$README" "README states no runtime behavior" "No runtime behavior is implemented."
check_text "$README" "README states no profile creation" "No profile creation is implemented."
check_text "$README" "README states no install command" "No install command is implemented."
check_text "$README" "README states no isolation enforcement" "No isolation enforcement is implemented."
check_text "$README" "README points to Probe 3 validator" "Probe 3 remains the current claim-boundary validator."

check_text "$CONTRACT" "contract purpose section present" "## Purpose"
check_text "$CONTRACT" "contract non-claims section present" "## Non-Claims"
check_text "$CONTRACT" "contract future inputs section present" "## Future Inputs"
check_text "$CONTRACT" "contract future outputs section present" "## Future Outputs"
check_text "$CONTRACT" "contract future validation section present" "## Future Validation Requirements"
check_text "$CONTRACT" "contract forbidden claims section present" "## Forbidden Claims"
check_text "$CONTRACT" "contract current status section present" "## Current Status"
check_text "$CONTRACT" "contract avoids profile creation claim" "This scaffold does not create a profile."
check_text "$CONTRACT" "contract avoids runtime profile claim" "This scaffold does not run a profile."
check_text "$CONTRACT" "contract avoids install action claim" "This scaffold does not install packages."
check_text "$CONTRACT" "contract avoids package-manager action claim" "This scaffold does not execute a package manager."
check_text "$CONTRACT" "contract avoids network action claim" "This scaffold does not enable network access."
check_text "$CONTRACT" "contract avoids isolation action claim" "This scaffold does not enforce isolation."

check_text "$MANIFEST" "manifest schema present" '"schema": "wucios-dev-lane-disposable-profile-contract-v1"'
check_text "$MANIFEST" "manifest scaffold-only status present" '"status": "scaffold_only"'
check_text "$MANIFEST" "manifest profile behavior boundary present" '"profile_behavior": "not_implemented"'
check_text "$MANIFEST" "manifest required files include README" '"README.md"'
check_text "$MANIFEST" "manifest required files include contract" '"profile-contract.md"'
check_text "$MANIFEST" "manifest validation requires Probe 3" '"probe_3_validator_passes"'
check_text "$MANIFEST" "manifest validation requires forbidden phrase absence" '"forbidden_claim_phrases_absent"'

check_forbidden_claims_absent

if [ -f "$PROBE3_VALIDATOR" ]; then
	if sh "$PROBE3_VALIDATOR"; then
		pass "Probe 3 validator passes"
	else
		fail "Probe 3 validator failed"
	fi
fi

if [ -f "$EVIDENCE_CONTRACT_VALIDATOR" ]; then
	if [ "${WUCIOS_SKIP_EVIDENCE_CONTRACT:-0}" = "1" ]; then
		pass "dry-run evidence contract validator skipped for nested planner validation"
	elif WUCIOS_SKIP_EVIDENCE_CONTRACT=1 sh "$EVIDENCE_CONTRACT_VALIDATOR"; then
		pass "dry-run evidence contract validator passes"
	else
		fail "dry-run evidence contract validator failed"
	fi
fi

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile scaffold contract satisfied'
	exit 0
fi

printf 'FAIL: disposable developer profile scaffold contract failed with %d failure(s)\n' "$failures"
exit 1
