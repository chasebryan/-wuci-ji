#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-plan-input.sh"
PLANNER="$SCRIPT_DIR/plan-disposable-profile-dry-run.sh"
TESTDATA="$LANE_DIR/scaffolds/disposable-developer-profile/testdata"
VALID="$TESTDATA/valid-minimal-plan-input.json"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-3/negative-input-harness"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"
RUN1_REL="$BATCH_REL/valid-run-1"
RUN2_REL="$BATCH_REL/valid-run-2"
RUN1_DIR="$REPO_ROOT/$RUN1_REL"
RUN2_DIR="$REPO_ROOT/$RUN2_REL"
failures=0

pass() {
	printf 'PASS: %s\n' "$1"
}

fail() {
	printf 'FAIL: %s\n' "$1"
	failures=$((failures + 1))
}

require_file() {
	file=$1
	label=$2
	if [ -f "$file" ]; then
		pass "$label exists"
	else
		fail "$label missing"
	fi
}

reset_harness_dir() {
	case "$BATCH_DIR" in
		"$REPO_ROOT"/build/wucios/devlanes/disposable-profile-foundation-batch-3/negative-input-harness)
			rm -rf "$BATCH_DIR" || {
				fail "could not remove harness evidence directory"
				return
			}
			mkdir -p "$BATCH_DIR" || fail "could not create harness evidence directory"
			;;
		*)
			fail "refusing to reset unexpected directory: $BATCH_DIR"
			;;
	esac
}

compare_file() {
	rel=$1
	left="$RUN1_DIR/$rel"
	right="$RUN2_DIR/$rel"
	require_file "$left" "valid-run-1 $rel"
	require_file "$right" "valid-run-2 $rel"
	if [ -f "$left" ] && [ -f "$right" ]; then
		if cmp -s "$left" "$right"; then
			pass "$rel stable across valid-input dry runs"
		else
			fail "$rel differs across valid-input dry runs"
		fi
	fi
}

check_forbidden_claims_absent() {
	for phrase in \
		"production"" ready" \
		"externally"" validated" \
		"runtime"" validated" \
		"ready for"" installation" \
		"secure by"" default" \
		"full isolation"" proven" \
		"developer profile"" implemented" \
		"operational"" readiness"
	do
		if grep -RniF "$phrase" "$BATCH_DIR"; then
			fail "forbidden claim phrase present in harness evidence: $phrase"
		fi
	done
}

printf '%s\n' 'Disposable developer profile negative input harness'
printf 'Harness evidence directory: %s\n' "$BATCH_REL"

require_file "$VALIDATOR" "input validator"
require_file "$PLANNER" "dry-run planner"
require_file "$VALID" "valid input fixture"

if [ "$failures" -eq 0 ]; then
	reset_harness_dir
fi

if [ "$failures" -eq 0 ]; then
	if sh "$VALIDATOR" "$VALID" >/dev/null; then
		pass "valid input fixture accepted by input validator"
	else
		fail "valid input fixture rejected by input validator"
	fi

	for invalid in "$TESTDATA"/invalid-*.json; do
		require_file "$invalid" "invalid input fixture"
		if sh "$VALIDATOR" "$invalid" >/dev/null 2>&1; then
			fail "invalid input fixture unexpectedly accepted: $invalid"
		else
			pass "invalid input fixture rejected: $invalid"
		fi
	done

	if sh "$PLANNER" --input "${VALID#$REPO_ROOT/}" >/dev/null; then
		pass "planner accepts valid input fixture"
	else
		fail "planner rejected valid input fixture"
	fi

	for invalid in "$TESTDATA"/invalid-*.json; do
		name=$(basename "$invalid" .json)
		invalid_rel=${invalid#$REPO_ROOT/}
		invalid_evidence_rel="$BATCH_REL/invalid/$name"
		invalid_evidence_dir="$REPO_ROOT/$invalid_evidence_rel"
		rm -rf "$invalid_evidence_dir" || {
			fail "could not reset invalid evidence probe directory: $invalid_evidence_rel"
			continue
		}
		if sh "$PLANNER" --input "$invalid_rel" --evidence-dir "$invalid_evidence_rel" >/dev/null 2>&1; then
			fail "planner unexpectedly accepted invalid input fixture: $invalid"
		else
			pass "planner rejected invalid input fixture: $invalid"
		fi
		if [ -e "$invalid_evidence_dir" ] && find "$invalid_evidence_dir" -type f | grep -q .; then
			fail "invalid planner run wrote evidence files: $invalid_evidence_rel"
		else
			pass "invalid planner run wrote no evidence files: $invalid_evidence_rel"
		fi
	done

	if sh "$PLANNER" --input "${VALID#$REPO_ROOT/}" --evidence-dir "$RUN1_REL" >/dev/null; then
		pass "valid-input evidence run 1 generated"
	else
		fail "valid-input evidence run 1 failed"
	fi
	if sh "$PLANNER" --input "${VALID#$REPO_ROOT/}" --evidence-dir "$RUN2_REL" >/dev/null; then
		pass "valid-input evidence run 2 generated"
	else
		fail "valid-input evidence run 2 failed"
	fi

	compare_file "dry-run-plan.txt"
	compare_file "dry-run-summary.json"
	compare_file "evidence-index.json"
	check_forbidden_claims_absent
fi

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile negative input harness passed'
	exit 0
fi

printf 'FAIL: disposable developer profile negative input harness failed with %d failure(s)\n' "$failures"
exit 1
