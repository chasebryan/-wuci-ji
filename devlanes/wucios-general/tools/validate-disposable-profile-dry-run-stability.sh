#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
PLANNER="$SCRIPT_DIR/plan-disposable-profile-dry-run.sh"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-2"
RUN1_REL="$BATCH_REL/run-1"
RUN2_REL="$BATCH_REL/run-2"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"
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

reset_run_dir() {
	dir=$1
	case "$dir" in
		"$REPO_ROOT"/build/wucios/devlanes/disposable-profile-foundation-batch-2/run-*)
			rm -rf "$dir" || {
				fail "could not remove run directory: $dir"
				return
			}
			mkdir -p "$dir" || fail "could not create run directory: $dir"
			;;
		*)
			fail "refusing to reset unexpected directory: $dir"
			;;
	esac
}

outside_snapshot() {
	if [ ! -d "$BATCH_DIR" ]; then
		printf '\n'
		return
	fi
	find "$BATCH_DIR" -type f \
		! -path "$RUN1_DIR/*" \
		! -path "$RUN2_DIR/*" \
		-exec cksum {} \; 2>/dev/null | LC_ALL=C sort
}

compare_file() {
	rel=$1
	left="$RUN1_DIR/$rel"
	right="$RUN2_DIR/$rel"
	require_file "$left" "run-1 $rel"
	require_file "$right" "run-2 $rel"
	if [ -f "$left" ] && [ -f "$right" ]; then
		if cmp -s "$left" "$right"; then
			pass "$rel stable across dry-run evidence runs"
		else
			fail "$rel differs across dry-run evidence runs"
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
		if grep -RniF "$phrase" "$RUN1_DIR" "$RUN2_DIR"; then
			fail "forbidden claim phrase present in generated dry-run evidence: $phrase"
		fi
	done
	if [ "$failures" -eq 0 ]; then
		pass "forbidden claim phrases absent from generated dry-run evidence"
	fi
}

printf '%s\n' 'Disposable developer profile dry-run stability validator'
printf 'Batch evidence directory: %s\n' "$BATCH_REL"

require_file "$PLANNER" "dry-run planner"

mkdir -p "$BATCH_DIR" || fail "could not create batch evidence directory"
before=$(outside_snapshot)

reset_run_dir "$RUN1_DIR"
reset_run_dir "$RUN2_DIR"

if [ "$failures" -eq 0 ]; then
	if sh "$PLANNER" --evidence-dir "$RUN1_REL" >/dev/null; then
		pass "run-1 dry-run evidence generated"
	else
		fail "run-1 dry-run evidence generation failed"
	fi

	if sh "$PLANNER" --evidence-dir "$RUN2_REL" >/dev/null; then
		pass "run-2 dry-run evidence generated"
	else
		fail "run-2 dry-run evidence generation failed"
	fi
fi

compare_file "dry-run-plan.txt"
compare_file "dry-run-summary.json"
compare_file "evidence-index.json"

check_forbidden_claims_absent

after=$(outside_snapshot)
if [ "$before" = "$after" ]; then
	pass "planner wrote no files outside selected evidence run directories"
else
	fail "files outside selected evidence run directories changed"
fi

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile dry-run evidence is stable'
	exit 0
fi

printf 'FAIL: disposable developer profile dry-run stability failed with %d failure(s)\n' "$failures"
exit 1
