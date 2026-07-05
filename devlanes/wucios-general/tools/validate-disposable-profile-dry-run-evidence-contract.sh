#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
PLANNER="$SCRIPT_DIR/plan-disposable-profile-dry-run.sh"
TESTDATA="$LANE_DIR/scaffolds/disposable-developer-profile/testdata"
VALID_INPUT="$TESTDATA/valid-minimal-plan-input.json"
ALLOWLIST="$TESTDATA/expected-dry-run-evidence-files.txt"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-4/evidence-contract"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"
NO_INPUT_REL="$BATCH_REL/no-input"
VALID1_REL="$BATCH_REL/valid-input-run-1"
VALID2_REL="$BATCH_REL/valid-input-run-2"
INVALID_REL="$BATCH_REL/invalid-input"
NO_INPUT_DIR="$REPO_ROOT/$NO_INPUT_REL"
VALID1_DIR="$REPO_ROOT/$VALID1_REL"
VALID2_DIR="$REPO_ROOT/$VALID2_REL"
INVALID_DIR="$REPO_ROOT/$INVALID_REL"
failures=0

pass() {
	printf 'PASS: %s\n' "$1"
}

fail() {
	printf 'FAIL: %s\n' "$1"
	failures=$((failures + 1))
}

require_file() {
	required_file_path=$1
	required_file_label=$2
	if [ -f "$required_file_path" ]; then
		pass "$required_file_label exists"
	else
		fail "$required_file_label missing"
	fi
}

require_dir() {
	required_dir_path=$1
	required_dir_label=$2
	if [ -d "$required_dir_path" ]; then
		pass "$required_dir_label directory exists"
	else
		fail "$required_dir_label directory missing"
	fi
}

reset_batch_dir() {
	case "$BATCH_DIR" in
		"$REPO_ROOT"/build/wucios/devlanes/disposable-profile-foundation-batch-4/evidence-contract)
			rm -rf "$BATCH_DIR" || {
				fail "could not remove Batch 4 evidence contract directory"
				return
			}
			mkdir -p "$BATCH_DIR" || fail "could not create Batch 4 evidence contract directory"
			;;
		*)
			fail "refusing to reset unexpected directory: $BATCH_DIR"
			;;
	esac
}

reset_invalid_dir() {
	dir=$1
	case "$dir" in
		"$INVALID_DIR"/*)
			rm -rf "$dir" || fail "could not remove invalid evidence directory: $dir"
			;;
		*)
			fail "refusing to reset unexpected invalid evidence directory: $dir"
			;;
	esac
}

expected_count() {
	count=0
	while IFS= read -r rel || [ -n "$rel" ]; do
		case "$rel" in
			'' | \#*)
				continue
				;;
		esac
		count=$((count + 1))
	done < "$ALLOWLIST"
	printf '%s\n' "$count"
}

check_allowed_evidence_files() {
	evidence_dir=$1
	evidence_label=$2
	require_dir "$evidence_dir" "$evidence_label"
	if [ ! -d "$evidence_dir" ]; then
		return
	fi

	while IFS= read -r expected_rel || [ -n "$expected_rel" ]; do
		case "$expected_rel" in
			'' | \#*)
				continue
				;;
		esac
		evidence_file="$evidence_dir/$expected_rel"
		require_file "$evidence_file" "$evidence_label $expected_rel"
		if [ -f "$evidence_file" ]; then
			if [ -s "$evidence_file" ]; then
				pass "$evidence_label $expected_rel is non-empty"
			else
				fail "$evidence_label $expected_rel is empty"
			fi
			case "$expected_rel" in
				*.json)
					if python3 -m json.tool "$evidence_file" >/dev/null; then
						pass "$evidence_label $expected_rel parses as JSON"
					else
						fail "$evidence_label $expected_rel does not parse as JSON"
					fi
					;;
			esac
		fi
	done < "$ALLOWLIST"

	actual_count=$(find "$evidence_dir" -type f | wc -l | tr -d ' ')
	expected_total=$(expected_count)
	if [ "$actual_count" = "$expected_total" ]; then
		pass "$evidence_label has only expected evidence file count"
	else
		fail "$evidence_label evidence file count $actual_count did not match allowlist count $expected_total"
	fi

	if find "$evidence_dir" -type f | while IFS= read -r found_file; do
		found_rel=${found_file#"$evidence_dir"/}
		if ! grep -F -x -q "$found_rel" "$ALLOWLIST"; then
			printf 'unexpected evidence file: %s\n' "$found_rel" >&2
			exit 1
		fi
	done; then
		pass "$evidence_label evidence files match allowlist"
	else
		fail "$evidence_label has evidence files outside allowlist"
	fi
}

check_forbidden_claims_absent() {
	forbidden_dir=$1
	forbidden_label=$2
	for phrase in \
		"runtime"" provisioning" \
		"actual"" installation" \
		"host mutation"" completed" \
		"host mutation"" proven" \
		"credential"" setup" \
		"production"" ready" \
		"production"" readiness"" claimed" \
		"real disposable developer profile"" creation" \
		"working disposable developer profile" \
		"externally"" validated" \
		"runtime"" validated" \
		"ready for"" installation" \
		"secure by"" default" \
		"full isolation"" proven" \
		"developer profile"" implemented" \
		"operational"" readiness"
	do
		if grep -RniF "$phrase" "$forbidden_dir"; then
			fail "$forbidden_label contains forbidden claim phrase: $phrase"
		fi
	done
}

compare_allowed_files() {
	compare_left_dir=$1
	compare_right_dir=$2
	compare_label=$3
	while IFS= read -r compare_rel || [ -n "$compare_rel" ]; do
		case "$compare_rel" in
			'' | \#*)
				continue
				;;
		esac
		compare_left_file="$compare_left_dir/$compare_rel"
		compare_right_file="$compare_right_dir/$compare_rel"
		require_file "$compare_left_file" "$compare_label left $compare_rel"
		require_file "$compare_right_file" "$compare_label right $compare_rel"
		if [ -f "$compare_left_file" ] && [ -f "$compare_right_file" ]; then
			if cmp -s "$compare_left_file" "$compare_right_file"; then
				pass "$compare_label $compare_rel is stable"
			else
				fail "$compare_label $compare_rel differs"
			fi
		fi
	done < "$ALLOWLIST"
}

check_invalid_left_no_evidence() {
	invalid_check_dir=$1
	invalid_check_label=$2
	if [ -e "$invalid_check_dir" ] && find "$invalid_check_dir" -type f | grep -q .; then
		fail "$invalid_check_label wrote evidence files"
	else
		pass "$invalid_check_label wrote no evidence files"
	fi
	for invalid_evidence_rel in dry-run-plan.txt dry-run-summary.json evidence-index.json; do
		if [ -e "$invalid_check_dir/$invalid_evidence_rel" ]; then
			fail "$invalid_check_label wrote successful evidence artifact: $invalid_evidence_rel"
		fi
	done
}

check_no_staged_or_tracked_evidence() {
	if git -C "$REPO_ROOT" diff --cached --name-only -- "$BATCH_REL" | grep -q .; then
		fail "Batch 4 evidence is staged"
	else
		pass "Batch 4 evidence is not staged"
	fi
	if git -C "$REPO_ROOT" ls-files -- "$BATCH_REL" | grep -q .; then
		fail "Batch 4 evidence is tracked"
	else
		pass "Batch 4 evidence is not tracked"
	fi
}

printf '%s\n' 'Disposable developer profile dry-run evidence contract validator'
printf 'Batch evidence directory: %s\n' "$BATCH_REL"

require_file "$PLANNER" "dry-run planner"
require_file "$VALID_INPUT" "valid input fixture"
require_file "$ALLOWLIST" "expected evidence allowlist"

if [ "$failures" -eq 0 ]; then
	reset_batch_dir
fi

if [ "$failures" -eq 0 ]; then
	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 sh "$PLANNER" --evidence-dir "$NO_INPUT_REL" >/dev/null; then
		pass "no-input dry-run evidence generated"
	else
		fail "no-input dry-run evidence generation failed"
	fi

	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 sh "$PLANNER" \
		--input "${VALID_INPUT#"$REPO_ROOT"/}" \
		--evidence-dir "$VALID1_REL" >/dev/null; then
		pass "valid-input dry-run evidence run 1 generated"
	else
		fail "valid-input dry-run evidence run 1 failed"
	fi

	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 sh "$PLANNER" \
		--input "${VALID_INPUT#"$REPO_ROOT"/}" \
		--evidence-dir "$VALID2_REL" >/dev/null; then
		pass "valid-input dry-run evidence run 2 generated"
	else
		fail "valid-input dry-run evidence run 2 failed"
	fi

	check_allowed_evidence_files "$NO_INPUT_DIR" "no-input evidence"
	check_allowed_evidence_files "$VALID1_DIR" "valid-input evidence run 1"
	check_allowed_evidence_files "$VALID2_DIR" "valid-input evidence run 2"
	check_forbidden_claims_absent "$NO_INPUT_DIR" "no-input evidence"
	check_forbidden_claims_absent "$VALID1_DIR" "valid-input evidence run 1"
	check_forbidden_claims_absent "$VALID2_DIR" "valid-input evidence run 2"
	compare_allowed_files "$VALID1_DIR" "$VALID2_DIR" "valid-input repeated dry-run evidence"

	for invalid in "$TESTDATA"/invalid-*.json; do
		name=$(basename "$invalid" .json)
		invalid_rel=${invalid#"$REPO_ROOT"/}
		invalid_evidence_rel="$INVALID_REL/$name"
		invalid_evidence_dir="$REPO_ROOT/$invalid_evidence_rel"
		reset_invalid_dir "$invalid_evidence_dir"
		if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 sh "$PLANNER" \
			--input "$invalid_rel" \
			--evidence-dir "$invalid_evidence_rel" >/dev/null 2>&1; then
			fail "invalid input dry run unexpectedly succeeded: $invalid_rel"
		else
			pass "invalid input dry run rejected: $invalid_rel"
		fi
		check_invalid_left_no_evidence "$invalid_evidence_dir" "invalid input dry run $name"
	done

	check_no_staged_or_tracked_evidence
fi

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile dry-run evidence contract satisfied'
	exit 0
fi

printf 'FAIL: disposable developer profile dry-run evidence contract failed with %d failure(s)\n' "$failures"
exit 1
