#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
MANIFEST="$LANE_DIR/scaffolds/disposable-developer-profile/contract-manifest.json"

if [ "$#" -gt 1 ]; then
	printf '%s\n' 'usage: sh devlanes/wucios-general/tools/validate-disposable-profile-contract-manifest.sh [manifest.json]' >&2
	exit 2
fi

if [ "$#" -eq 1 ]; then
	MANIFEST=$1
fi

printf '%s\n' 'Disposable developer profile contract manifest validator'
printf 'Manifest: %s\n' "$MANIFEST"

if [ ! -f "$MANIFEST" ]; then
	printf 'FAIL: manifest missing: %s\n' "$MANIFEST"
	exit 1
fi

python3 - "$MANIFEST" <<'PY'
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
        manifest = json.load(handle)
except Exception as exc:
    print(f"FAIL: manifest is not valid JSON: {exc}")
    sys.exit(1)

require(isinstance(manifest, dict), "manifest root must be an object")

expected = {
    "schema": "wucios-dev-lane-disposable-profile-contract-v1",
    "schema_version": "1",
    "profile_contract_id": "wucios.disposable_developer_profile.scaffold_contract.v1",
    "status": "scaffold_only",
    "profile_behavior": "not_implemented",
}

for key, value in expected.items():
    require(manifest.get(key) == value, f"{key} must be {value}")

require(manifest.get("foundation_only") is True, "foundation_only must be true")
require(manifest.get("dry_run_only") is True, "dry_run_only must be true")

scope = manifest.get("scope")
require(isinstance(scope, dict), "scope must be an object")
if isinstance(scope, dict):
    require(
        scope.get("scaffold")
        == "devlanes/wucios-general/scaffolds/disposable-developer-profile",
        "scope.scaffold must identify the disposable developer profile scaffold",
    )
    require(
        scope.get("lane") == "devlanes/wucios-general",
        "scope.lane must identify the WuciOS general dev lane",
    )

planner = manifest.get("planner_contract")
require(isinstance(planner, dict), "planner_contract must be an object")
if isinstance(planner, dict):
    require(
        planner.get("planner_mode") == "local_dry_run_evidence_only",
        "planner_contract.planner_mode must be local_dry_run_evidence_only",
    )
    require(
        planner.get("planner")
        == "devlanes/wucios-general/tools/plan-disposable-profile-dry-run.sh",
        "planner_contract.planner must point to the dry-run planner",
    )

input_contract = manifest.get("input_contract")
require(isinstance(input_contract, dict), "input_contract must be an object")
if isinstance(input_contract, dict):
    require(
        input_contract.get("schema") == "wucios.disposable_profile.plan_input.v1",
        "input_contract.schema must identify the plan input schema",
    )
    require(
        input_contract.get("validator")
        == "devlanes/wucios-general/tools/validate-disposable-profile-plan-input.sh",
        "input_contract.validator must point to the plan input validator",
    )

evidence = manifest.get("evidence_contract")
require(isinstance(evidence, dict), "evidence_contract must be an object")
if isinstance(evidence, dict):
    require(
        evidence.get("id") == "wucios.disposable_profile.dry_run_evidence.v1",
        "evidence_contract.id must identify the dry-run evidence contract",
    )
    require(
        evidence.get("summary_schema")
        == "wucios-dev-lane-disposable-profile-dry-run-summary-v1",
        "evidence_contract.summary_schema must match planner summary evidence",
    )
    require(
        evidence.get("index_schema")
        == "wucios-dev-lane-disposable-profile-evidence-index-v1",
        "evidence_contract.index_schema must match planner index evidence",
    )

plan_vocabulary = manifest.get("plan_vocabulary_contract")
require(isinstance(plan_vocabulary, dict), "plan_vocabulary_contract must be an object")
if isinstance(plan_vocabulary, dict):
    require(
        plan_vocabulary.get("id")
        == "wucios.disposable_profile.no_execution_plan_vocabulary.v1",
        "plan_vocabulary_contract.id must identify the no-execution plan vocabulary",
    )
    require(
        plan_vocabulary.get("schema")
        == "wucios.disposable_profile.plan_vocabulary_contract.v1",
        "plan_vocabulary_contract.schema must identify the plan vocabulary contract",
    )
    require(
        plan_vocabulary.get("schema_version") == "1",
        "plan_vocabulary_contract.schema_version must be 1",
    )
    require(
        plan_vocabulary.get("plan_summary_schema")
        == "wucios.disposable_profile.no_execution_plan_summary.v1",
        "plan_vocabulary_contract.plan_summary_schema must match planner plan summary",
    )

required_non_claims = {
    "no_runtime_behavior",
    "no_profile_creation",
    "no_package_install",
    "no_package_manager_execution",
    "no_network_enablement",
    "no_isolation_enforcement",
    "no_external_review_result",
    "no_host_mutation_guarantee",
    "no_developer_use_approval",
    "no_operational_approval",
}
non_claims = manifest.get("non_claims")
require(isinstance(non_claims, list), "non_claims must be a list")
if isinstance(non_claims, list):
    missing = sorted(required_non_claims.difference(non_claims))
    require(not missing, "non_claims missing: " + ", ".join(missing))

required_forbidden_operations = {
    "runtime_behavior",
    "profile_creation",
    "package_install",
    "package_manager_execution",
    "network_enablement",
    "host_configuration_change",
    "isolation_enforcement",
    "credential_handling",
    "external_review_claim",
    "production_status_claim",
}
forbidden_operations = manifest.get("forbidden_operations")
require(
    isinstance(forbidden_operations, list),
    "forbidden_operations must be a list",
)
if isinstance(forbidden_operations, list):
    missing = sorted(required_forbidden_operations.difference(forbidden_operations))
    require(not missing, "forbidden_operations missing: " + ", ".join(missing))

for key in (
    "contract_manifest_validator_passes",
    "planner_manifest_binding_validator_passes",
    "plan_vocabulary_validator_passes",
    "planner_output_vocabulary_validator_passes",
):
    requirements = manifest.get("validation_requirements")
    require(isinstance(requirements, list), "validation_requirements must be a list")
    if isinstance(requirements, list):
        require(key in requirements, f"validation_requirements missing {key}")

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
    "host" + " mutation" + " completed",
    "host" + " mutation" + " proven",
    "credential" + " setup",
    "production" + " ready",
    "production" + " readiness" + " claimed",
    "real disposable developer profile" + " creation",
    "external" + " validation",
    "high-assurance" + " certification",
]

for text in walk_strings(manifest):
    lowered = text.lower()
    for phrase in forbidden_phrases:
        if phrase in lowered:
            fail(f"forbidden claim phrase present in manifest: {phrase}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: contract manifest JSON structure is valid")
print("PASS: contract manifest binding identifiers are present")
print("PASS: contract manifest dry-run foundation boundaries are present")
PY
