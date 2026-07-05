#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
CONTRACT="$LANE_DIR/scaffolds/disposable-developer-profile/plan-vocabulary-contract.json"

if [ "$#" -gt 1 ]; then
	printf '%s\n' 'usage: sh devlanes/wucios-general/tools/validate-disposable-profile-plan-vocabulary.sh [plan-vocabulary-contract.json]' >&2
	exit 2
fi

if [ "$#" -eq 1 ]; then
	CONTRACT=$1
fi

printf '%s\n' 'Disposable developer profile plan vocabulary validator'
printf 'Plan vocabulary contract: %s\n' "$CONTRACT"

if [ ! -f "$CONTRACT" ]; then
	printf 'FAIL: plan vocabulary contract missing: %s\n' "$CONTRACT"
	exit 1
fi

python3 - "$CONTRACT" <<'PY'
import json
import sys

path = sys.argv[1]
failures = []

def fail(message):
    failures.append(message)

def require(condition, message):
    if not condition:
        fail(message)

try:
    with open(path, "r", encoding="utf-8") as handle:
        contract = json.load(handle)
except Exception as exc:
    print(f"FAIL: plan vocabulary contract is not valid JSON: {exc}")
    sys.exit(1)

require(isinstance(contract, dict), "contract root must be an object")

expected = {
    "schema": "wucios.disposable_profile.plan_vocabulary_contract.v1",
    "schema_version": "1",
    "profile_contract_id": "wucios.disposable_developer_profile.scaffold_contract.v1",
    "plan_vocabulary_contract_id": "wucios.disposable_profile.no_execution_plan_vocabulary.v1",
    "planner_mode": "local_dry_run_evidence_only",
    "plan_summary_schema": "wucios.disposable_profile.no_execution_plan_summary.v1",
    "execution_status": "not_executed",
}

for key, value in expected.items():
    require(contract.get(key) == value, f"{key} must be {value}")

require(contract.get("dry_run_only") is True, "dry_run_only must be true")
require(contract.get("foundation_only") is True, "foundation_only must be true")

allowed_phases = contract.get("allowed_plan_phases")
allowed_actions = contract.get("allowed_action_kinds")
forbidden_fields = contract.get("forbidden_field_names")
forbidden_claims = contract.get("forbidden_claim_ids")

require(isinstance(allowed_phases, list) and bool(allowed_phases), "allowed_plan_phases must be a non-empty list")
require(isinstance(allowed_actions, list) and bool(allowed_actions), "allowed_action_kinds must be a non-empty list")
require(isinstance(forbidden_fields, list) and bool(forbidden_fields), "forbidden_field_names must be a non-empty list")
require(isinstance(forbidden_claims, list) and bool(forbidden_claims), "forbidden_claim_ids must be a non-empty list")

if isinstance(allowed_actions, list):
    required_actions = {
        "document_boundary",
        "validate_input",
        "summarize_requested_profile",
        "emit_dry_run_evidence",
        "record_manifest_binding",
        "report_no_execution",
    }
    missing = sorted(required_actions.difference(allowed_actions))
    require(not missing, "allowed_action_kinds missing: " + ", ".join(missing))

def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from walk_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_strings(nested)

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

for text in walk_strings(contract):
    lowered = text.lower()
    for phrase in forbidden_phrases:
        if phrase in lowered:
            fail(f"forbidden claim phrase present in plan vocabulary contract: {phrase}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: plan vocabulary contract JSON structure is valid")
print("PASS: plan vocabulary contract dry-run foundation flags are present")
print("PASS: plan vocabulary allowed action set is present")
print("PASS: plan vocabulary forbidden boundary lists are present")
PY
