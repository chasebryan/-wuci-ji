#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
MANIFEST="$LANE_DIR/scaffolds/disposable-developer-profile/contract-manifest.json"
MANIFEST_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-contract-manifest.sh"
PLANNER="$SCRIPT_DIR/plan-disposable-profile-dry-run.sh"
TESTDATA="$LANE_DIR/scaffolds/disposable-developer-profile/testdata"
VALID_INPUT="$TESTDATA/valid-minimal-plan-input.json"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-5/manifest-binding"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"
NO_INPUT_REL="$BATCH_REL/no-input-evidence"
VALID_INPUT_REL="$BATCH_REL/valid-input-evidence"
INVALID_REL="$BATCH_REL/invalid-input"
NO_INPUT_DIR="$REPO_ROOT/$NO_INPUT_REL"
VALID_INPUT_DIR="$REPO_ROOT/$VALID_INPUT_REL"
INVALID_DIR="$REPO_ROOT/$INVALID_REL"
NO_INPUT_STDOUT="$BATCH_DIR/no-input.stdout"
VALID_INPUT_STDOUT="$BATCH_DIR/valid-input.stdout"
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

reset_batch_dir() {
	case "$BATCH_DIR" in
		"$REPO_ROOT"/build/wucios/devlanes/disposable-profile-foundation-batch-5/manifest-binding)
			rm -rf "$BATCH_DIR" || {
				fail "could not remove Batch 5 manifest binding directory"
				return
			}
			mkdir -p "$BATCH_DIR" || fail "could not create Batch 5 manifest binding directory"
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
			rm -rf "$dir" || fail "could not remove invalid binding evidence directory: $dir"
			;;
		*)
			fail "refusing to reset unexpected invalid binding evidence directory: $dir"
			;;
	esac
}

check_no_successful_invalid_evidence() {
	dir=$1
	label=$2
	if [ -e "$dir" ] && find "$dir" -type f | grep -q .; then
		fail "$label wrote evidence files"
	else
		pass "$label wrote no evidence files"
	fi
	for rel in dry-run-plan.txt dry-run-summary.json evidence-index.json; do
		if [ -e "$dir/$rel" ]; then
			fail "$label wrote successful evidence artifact: $rel"
		fi
	done
}

check_no_staged_or_tracked_evidence() {
	if git -C "$REPO_ROOT" diff --cached --name-only -- "$BATCH_REL" | grep -q .; then
		fail "Batch 5 manifest binding evidence is staged"
	else
		pass "Batch 5 manifest binding evidence is not staged"
	fi
	if git -C "$REPO_ROOT" ls-files -- "$BATCH_REL" | grep -q .; then
		fail "Batch 5 manifest binding evidence is tracked"
	else
		pass "Batch 5 manifest binding evidence is not tracked"
	fi
}

check_binding_outputs() {
	python3 - "$MANIFEST" "$NO_INPUT_DIR" "$VALID_INPUT_DIR" "$NO_INPUT_STDOUT" "$VALID_INPUT_STDOUT" <<'PY'
import json
import sys
from pathlib import Path

manifest_path, no_input_dir, valid_dir, no_stdout, valid_stdout = map(Path, sys.argv[1:])
failures = []

def fail(message):
    failures.append(message)

def require(condition, message):
    if not condition:
        fail(message)

with manifest_path.open("r", encoding="utf-8") as handle:
    manifest = json.load(handle)

expected = {
    "contract_manifest_schema": manifest["schema"],
    "contract_manifest_schema_version": manifest["schema_version"],
    "profile_contract_id": manifest["profile_contract_id"],
    "planner_mode": manifest["planner_contract"]["planner_mode"],
    "input_schema_id": manifest["input_contract"]["schema"],
    "evidence_contract_id": manifest["evidence_contract"]["id"],
}

def load_json(run_dir, name):
    path = run_dir / name
    require(path.is_file(), f"{path} exists")
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)

def check_evidence(run_dir, label, expected_input):
    summary = load_json(run_dir, "dry-run-summary.json")
    index = load_json(run_dir, "evidence-index.json")
    for doc_name, doc in (("summary", summary), ("index", index)):
        if not doc:
            continue
        schema_key = "summary_schema" if doc_name == "summary" else "index_schema"
        require(
            doc.get("schema") == manifest["evidence_contract"][schema_key],
            f"{label} {doc_name} schema matches manifest",
        )
        for key, value in expected.items():
            require(
                doc.get(key) == value,
                f"{label} {doc_name} {key} matches manifest",
            )
        require(doc.get("foundation_only") is True, f"{label} {doc_name} foundation_only is true")
        require(doc.get("dry_run_only") is True, f"{label} {doc_name} dry_run_only is true")
        require(
            doc.get("plan_input_path") == expected_input,
            f"{label} {doc_name} plan input path matches expected value",
        )

check_evidence(no_input_dir, "no-input", "none")
check_evidence(
    valid_dir,
    "valid-input",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/testdata/valid-minimal-plan-input.json",
)

stdout_expectations = [
    f"contract manifest schema: {manifest['schema']}",
    f"contract manifest schema version: {manifest['schema_version']}",
    f"profile contract id: {manifest['profile_contract_id']}",
    f"planner mode: {manifest['planner_contract']['planner_mode']}",
    "foundation only: true",
    "dry-run only: true",
    f"input schema id: {manifest['input_contract']['schema']}",
    f"evidence contract id: {manifest['evidence_contract']['id']}",
]

for stdout_path in (no_stdout, valid_stdout):
    require(stdout_path.is_file(), f"{stdout_path} exists")
    if not stdout_path.is_file():
        continue
    text = stdout_path.read_text(encoding="utf-8")
    for expected_line in stdout_expectations:
        require(expected_line in text, f"{stdout_path.name} contains {expected_line}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: planner stdout contains manifest binding identifiers")
print("PASS: generated evidence metadata matches manifest binding identifiers")
print("PASS: generated evidence keeps dry_run_only and foundation_only true")
PY
}

printf '%s\n' 'Disposable developer profile planner-manifest binding validator'
printf 'Batch evidence directory: %s\n' "$BATCH_REL"

require_file "$MANIFEST" "contract manifest"
require_file "$MANIFEST_VALIDATOR" "contract manifest validator"
require_file "$PLANNER" "dry-run planner"
require_file "$VALID_INPUT" "valid input fixture"

if [ "$failures" -eq 0 ]; then
	if sh "$MANIFEST_VALIDATOR" >/dev/null; then
		pass "contract manifest validator passes"
	else
		fail "contract manifest validator failed"
	fi
fi

if [ "$failures" -eq 0 ]; then
	reset_batch_dir
fi

if [ "$failures" -eq 0 ]; then
	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 \
		sh "$PLANNER" --evidence-dir "$NO_INPUT_REL" > "$NO_INPUT_STDOUT"; then
		pass "no-input manifest-bound planner evidence generated"
	else
		fail "no-input manifest-bound planner evidence generation failed"
	fi

	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 \
		sh "$PLANNER" \
		--input "${VALID_INPUT#"$REPO_ROOT"/}" \
		--evidence-dir "$VALID_INPUT_REL" > "$VALID_INPUT_STDOUT"; then
		pass "valid-input manifest-bound planner evidence generated"
	else
		fail "valid-input manifest-bound planner evidence generation failed"
	fi

	if [ "$failures" -eq 0 ]; then
		check_binding_outputs
	fi

	for invalid in "$TESTDATA"/invalid-*.json; do
		name=$(basename "$invalid" .json)
		invalid_rel=${invalid#"$REPO_ROOT"/}
		invalid_evidence_rel="$INVALID_REL/$name"
		invalid_evidence_dir="$REPO_ROOT/$invalid_evidence_rel"
		reset_invalid_dir "$invalid_evidence_dir"
		if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 \
			sh "$PLANNER" \
			--input "$invalid_rel" \
			--evidence-dir "$invalid_evidence_rel" >/dev/null 2>&1; then
			fail "invalid input emitted manifest-bound evidence: $invalid_rel"
		else
			pass "invalid input rejected before manifest-bound evidence: $invalid_rel"
		fi
		check_no_successful_invalid_evidence "$invalid_evidence_dir" "invalid input $name"
	done

	check_no_staged_or_tracked_evidence
fi

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile planner-manifest binding satisfied'
	exit 0
fi

printf 'FAIL: disposable developer profile planner-manifest binding failed with %d failure(s)\n' "$failures"
exit 1
