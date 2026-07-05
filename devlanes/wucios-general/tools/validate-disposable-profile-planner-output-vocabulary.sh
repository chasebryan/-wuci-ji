#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
PLANNER="$SCRIPT_DIR/plan-disposable-profile-dry-run.sh"
VOCABULARY_CONTRACT="$LANE_DIR/scaffolds/disposable-developer-profile/plan-vocabulary-contract.json"
VOCABULARY_VALIDATOR="$SCRIPT_DIR/validate-disposable-profile-plan-vocabulary.sh"
TESTDATA="$LANE_DIR/scaffolds/disposable-developer-profile/testdata"
VALID_INPUT="$TESTDATA/valid-minimal-plan-input.json"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-6/plan-vocabulary"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"
NO_INPUT_REL="$BATCH_REL/no-input"
VALID_INPUT_REL="$BATCH_REL/valid-input"
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
		"$REPO_ROOT"/build/wucios/devlanes/disposable-profile-foundation-batch-6/plan-vocabulary)
			rm -rf "$BATCH_DIR" || {
				fail "could not remove Batch 6 plan vocabulary directory"
				return
			}
			mkdir -p "$BATCH_DIR" || fail "could not create Batch 6 plan vocabulary directory"
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
			rm -rf "$dir" || fail "could not remove invalid plan vocabulary directory: $dir"
			;;
		*)
			fail "refusing to reset unexpected invalid plan vocabulary directory: $dir"
			;;
	esac
}

check_invalid_left_no_plan() {
	dir=$1
	label=$2
	if [ -e "$dir" ] && find "$dir" -type f | grep -q .; then
		fail "$label wrote evidence files"
	else
		pass "$label wrote no evidence files"
	fi
	for rel in dry-run-plan.txt dry-run-summary.json evidence-index.json plan-summary.json; do
		if [ -e "$dir/$rel" ]; then
			fail "$label wrote successful plan artifact: $rel"
		fi
	done
}

check_no_staged_or_tracked_evidence() {
	if git -C "$REPO_ROOT" diff --cached --name-only -- "$BATCH_REL" | grep -q .; then
		fail "Batch 6 plan vocabulary evidence is staged"
	else
		pass "Batch 6 plan vocabulary evidence is not staged"
	fi
	if git -C "$REPO_ROOT" ls-files -- "$BATCH_REL" | grep -q .; then
		fail "Batch 6 plan vocabulary evidence is tracked"
	else
		pass "Batch 6 plan vocabulary evidence is not tracked"
	fi
}

check_plan_outputs() {
	python3 - "$VOCABULARY_CONTRACT" "$NO_INPUT_DIR" "$VALID_INPUT_DIR" "$NO_INPUT_STDOUT" "$VALID_INPUT_STDOUT" <<'PY'
import json
import sys
from pathlib import Path

contract_path, no_input_dir, valid_input_dir, no_stdout, valid_stdout = map(Path, sys.argv[1:])
failures = []

def fail(message):
    failures.append(message)

def require(condition, message):
    if not condition:
        fail(message)

with contract_path.open("r", encoding="utf-8") as handle:
    contract = json.load(handle)

allowed_phases = set(contract["allowed_plan_phases"])
allowed_actions = set(contract["allowed_action_kinds"])
forbidden_fields = set(contract["forbidden_field_names"])

def walk_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_keys(nested)

def load_plan_summary(run_dir, label, expected_input):
    path = run_dir / "plan-summary.json"
    require(path.is_file(), f"{label} plan-summary.json exists")
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        summary = json.load(handle)
    require(summary.get("schema") == contract["plan_summary_schema"], f"{label} schema matches vocabulary contract")
    require(summary.get("profile_contract_id") == contract["profile_contract_id"], f"{label} profile contract id matches vocabulary contract")
    require(summary.get("planner_mode") == contract["planner_mode"], f"{label} planner mode matches vocabulary contract")
    require(summary.get("plan_vocabulary_contract_id") == contract["plan_vocabulary_contract_id"], f"{label} vocabulary contract id matches")
    require(summary.get("dry_run_only") is True, f"{label} dry_run_only is true")
    require(summary.get("foundation_only") is True, f"{label} foundation_only is true")
    require(summary.get("execution_status") == contract["execution_status"], f"{label} execution status matches vocabulary contract")
    actions = summary.get("planned_actions")
    require(isinstance(actions, list) and bool(actions), f"{label} planned actions are present")
    if isinstance(actions, list):
        for index, action in enumerate(actions):
            require(isinstance(action, dict), f"{label} planned action {index} is an object")
            if isinstance(action, dict):
                require(action.get("phase") in allowed_phases, f"{label} planned action {index} phase is allowlisted")
                require(action.get("action_kind") in allowed_actions, f"{label} planned action {index} kind is allowlisted")
    for key in walk_keys(summary):
        require(key not in forbidden_fields, f"{label} uses forbidden field name: {key}")
    if expected_input is not None:
        evidence_summary = run_dir / "dry-run-summary.json"
        require(evidence_summary.is_file(), f"{label} dry-run-summary.json exists")
        if evidence_summary.is_file():
            with evidence_summary.open("r", encoding="utf-8") as handle:
                evidence = json.load(handle)
            require(evidence.get("plan_input_path") == expected_input, f"{label} input path is stable")
    return summary

load_plan_summary(no_input_dir, "no-input", "none")
load_plan_summary(
    valid_input_dir,
    "valid-input",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/testdata/valid-minimal-plan-input.json",
)

for stdout_path in (no_stdout, valid_stdout):
    require(stdout_path.is_file(), f"{stdout_path.name} exists")
    if stdout_path.is_file():
        text = stdout_path.read_text(encoding="utf-8")
        require(
            f"plan vocabulary contract id: {contract['plan_vocabulary_contract_id']}" in text,
            f"{stdout_path.name} includes plan vocabulary contract id",
        )
        require("dry-run only: true" in text, f"{stdout_path.name} keeps dry-run flag visible")
        require("foundation only: true" in text, f"{stdout_path.name} keeps foundation flag visible")

scan_paths = [
    no_input_dir / "dry-run-plan.txt",
    no_input_dir / "dry-run-summary.json",
    no_input_dir / "evidence-index.json",
    no_input_dir / "plan-summary.json",
    valid_input_dir / "dry-run-plan.txt",
    valid_input_dir / "dry-run-summary.json",
    valid_input_dir / "evidence-index.json",
    valid_input_dir / "plan-summary.json",
]

forbidden_phrases = [
    "runtime" + " provisioning",
    "actual" + " installation",
    "host" + " mutation",
    "credential" + " setup",
    "package" + " installation",
    "service" + " setup",
    "production" + " readiness",
    "real disposable developer profile" + " creation",
    "external" + " validation",
    "high-assurance" + " certification",
]

for path in scan_paths:
    require(path.is_file(), f"{path} exists for vocabulary claim scan")
    if not path.is_file():
        continue
    text = path.read_text(encoding="utf-8").lower()
    for phrase in forbidden_phrases:
        require(phrase not in text, f"{path} contains forbidden operational phrase: {phrase}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: planner plan-summary action kinds are allowlisted")
print("PASS: planner plan-summary keeps dry_run_only and foundation_only true")
print("PASS: planner output vocabulary contains no forbidden field names")
print("PASS: planner output vocabulary contains no forbidden operational phrases")
PY
}

printf '%s\n' 'Disposable developer profile planner output vocabulary validator'
printf 'Batch evidence directory: %s\n' "$BATCH_REL"

require_file "$PLANNER" "dry-run planner"
require_file "$VOCABULARY_CONTRACT" "plan vocabulary contract"
require_file "$VOCABULARY_VALIDATOR" "plan vocabulary validator"
require_file "$VALID_INPUT" "valid input fixture"

if [ "$failures" -eq 0 ]; then
	if sh "$VOCABULARY_VALIDATOR" >/dev/null; then
		pass "plan vocabulary validator passes"
	else
		fail "plan vocabulary validator failed"
	fi
fi

if [ "$failures" -eq 0 ]; then
	reset_batch_dir
fi

if [ "$failures" -eq 0 ]; then
	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 WUCIOS_SKIP_PLANNER_OUTPUT_VOCABULARY=1 \
		sh "$PLANNER" --evidence-dir "$NO_INPUT_REL" > "$NO_INPUT_STDOUT"; then
		pass "no-input planner vocabulary evidence generated"
	else
		fail "no-input planner vocabulary evidence generation failed"
	fi

	if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 WUCIOS_SKIP_PLANNER_OUTPUT_VOCABULARY=1 \
		sh "$PLANNER" \
		--input "${VALID_INPUT#"$REPO_ROOT"/}" \
		--evidence-dir "$VALID_INPUT_REL" > "$VALID_INPUT_STDOUT"; then
		pass "valid-input planner vocabulary evidence generated"
	else
		fail "valid-input planner vocabulary evidence generation failed"
	fi

	if [ "$failures" -eq 0 ]; then
		if check_plan_outputs; then
			pass "planner output vocabulary evidence passes structural checks"
		else
			fail "planner output vocabulary evidence failed structural checks"
		fi
	fi

	for invalid in "$TESTDATA"/invalid-*.json; do
		name=$(basename "$invalid" .json)
		invalid_rel=${invalid#"$REPO_ROOT"/}
		invalid_evidence_rel="$INVALID_REL/$name"
		invalid_evidence_dir="$REPO_ROOT/$invalid_evidence_rel"
		reset_invalid_dir "$invalid_evidence_dir"
		if WUCIOS_SKIP_EVIDENCE_CONTRACT=1 WUCIOS_SKIP_PLANNER_MANIFEST_BINDING=1 WUCIOS_SKIP_PLANNER_OUTPUT_VOCABULARY=1 \
			sh "$PLANNER" \
			--input "$invalid_rel" \
			--evidence-dir "$invalid_evidence_rel" >/dev/null 2>&1; then
			fail "invalid input emitted plan vocabulary evidence: $invalid_rel"
		else
			pass "invalid input rejected before plan vocabulary evidence: $invalid_rel"
		fi
		check_invalid_left_no_plan "$invalid_evidence_dir" "invalid input $name"
	done

	check_no_staged_or_tracked_evidence
fi

if [ "$failures" -eq 0 ]; then
	printf '%s\n' 'PASS: disposable developer profile planner output vocabulary satisfied'
	exit 0
fi

printf 'FAIL: disposable developer profile planner output vocabulary failed with %d failure(s)\n' "$failures"
exit 1
