#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
FREEZE_CONTRACT="$SCAFFOLD/foundation-freeze-decision-contract.json"
FREEZE_DECISION="$SCAFFOLD/foundation-freeze-decision.json"
FREEZE_SUMMARY="$SCAFFOLD/foundation-freeze-summary.md"

printf '%s\n' 'Disposable developer profile foundation freeze decision validator'
printf 'Freeze decision contract: %s\n' "$FREEZE_CONTRACT"

python3 - "$REPO_ROOT" "$FREEZE_CONTRACT" "$FREEZE_DECISION" "$FREEZE_SUMMARY" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
decision_path = Path(sys.argv[3])
summary_path = Path(sys.argv[4])
failures = []

def fail(message):
    failures.append(message)

def require(condition, message):
    if not condition:
        fail(message)

def load_json(path, label):
    if not path.is_file():
        fail(f"{label} missing: {path}")
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        fail(f"{label} is not valid JSON: {exc}")
        return {}

contract = load_json(contract_path, "foundation freeze decision contract")
decision = load_json(decision_path, "foundation freeze decision")
summary_text = ""
if summary_path.is_file():
    summary_text = summary_path.read_text(encoding="utf-8")
else:
    fail(f"foundation freeze summary missing: {summary_path}")

expected_profile_id = "wucios.disposable_developer_profile.scaffold_contract.v1"
expected_contract_schema = "wucios.disposable_profile.foundation_freeze_decision_contract.v1"
expected_decision_schema = "wucios.disposable_profile.foundation_freeze_decision.v1"

require(contract.get("schema") == expected_contract_schema, "freeze contract schema must match")
require(contract.get("schema_version") == "1", "freeze contract schema_version must be 1")
require(contract.get("profile_contract_id") == expected_profile_id, "freeze contract profile id must match")
require(contract.get("foundation_freeze_decision_kind") == "foundation_review_freeze_decision", "freeze contract kind must match")
require(contract.get("dry_run_only") is True, "freeze contract dry_run_only must be true")
require(contract.get("foundation_only") is True, "freeze contract foundation_only must be true")

require(decision.get("schema") == expected_decision_schema, "freeze decision schema must match")
require(decision.get("schema_version") == "1", "freeze decision schema_version must be 1")
require(decision.get("profile_contract_id") == expected_profile_id, "freeze decision profile id must match")
require(decision.get("foundation_freeze_decision_kind") == "foundation_review_freeze_decision", "freeze decision kind must match")
require(decision.get("dry_run_only") is True, "freeze decision dry_run_only must be true")
require(decision.get("foundation_only") is True, "freeze decision foundation_only must be true")

allowed_decisions = contract.get("allowed_decision_values", [])
require(isinstance(allowed_decisions, list) and allowed_decisions, "allowed decisions must be listed")
for value in ("FOUNDATION_FROZEN_FOR_REVIEW", "FOUNDATION_NOT_FROZEN", "FOUNDATION_FREEZE_BLOCKED"):
    require(value in allowed_decisions, f"allowed decisions must include {value}")

selected_decision = decision.get("decision")
require(selected_decision in allowed_decisions, "selected decision must be allowlisted")
require(selected_decision == "FOUNDATION_FROZEN_FOR_REVIEW", "selected decision must freeze the foundation for review")

required_false_flags = [
    "runtime_ready",
    "production_ready",
    "external_validation",
    "host_mutation",
    "actual_installation",
    "credential_setup",
]
require(decision.get("foundation_review_ready") is True, "foundation_review_ready must be true")
for key in required_false_flags:
    require(decision.get(key) is False, f"{key} must be false")

def is_relative_repo_path(value):
    return isinstance(value, str) and value and not value.startswith("/") and "://" not in value

def validate_repo_path(value, label, must_exist=True):
    require(is_relative_repo_path(value), f"{label} must be a relative repo path: {value}")
    if not is_relative_repo_path(value):
        return
    require(".." not in Path(value).parts, f"{label} must not contain parent traversal: {value}")
    require("mnt-samsung-t7/" not in value, f"{label} must not reference personal SSD path: {value}")
    if must_exist:
        require((repo_root / value).exists(), f"{label} does not exist: {value}")

for key in ("required_decision_files", "required_referenced_closeout_files"):
    values = contract.get(key)
    require(isinstance(values, list) and values, f"contract {key} must be a non-empty list")
    if isinstance(values, list):
        for value in values:
            validate_repo_path(value, f"contract {key} entry")

for key in ("referenced_closeout_files", "referenced_contract_files"):
    values = decision.get(key)
    require(isinstance(values, list) and values, f"decision {key} must be a non-empty list")
    if isinstance(values, list):
        for value in values:
            validate_repo_path(value, f"decision {key} entry")

contract_closeout_files = set(contract.get("required_referenced_closeout_files", [])) if isinstance(contract.get("required_referenced_closeout_files"), list) else set()
decision_closeout_files = set(decision.get("referenced_closeout_files", [])) if isinstance(decision.get("referenced_closeout_files"), list) else set()
require(contract_closeout_files == decision_closeout_files, "contract and decision closeout references must match")

expected_referenced_contracts = {
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-review-packet-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-validation-report-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-validation-registry.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/contract-traceability-matrix.json",
}
decision_contracts = set(decision.get("referenced_contract_files", [])) if isinstance(decision.get("referenced_contract_files"), list) else set()
require(expected_referenced_contracts.issubset(decision_contracts), "decision must reference required Batch 7-9 contracts")

policy = decision.get("generated_evidence_policy")
require(isinstance(policy, dict), "generated evidence policy must be an object")
if isinstance(policy, dict):
    for key in ("validation_report_root", "review_packet_root"):
        value = policy.get(key)
        require(is_relative_repo_path(value), f"generated evidence {key} must be relative")
        if is_relative_repo_path(value):
            require(value.startswith("build/wucios/devlanes/"), f"generated evidence {key} must stay under build/wucios/devlanes/: {value}")
            require("mnt-samsung-t7/" not in value, f"generated evidence {key} must not reference personal SSD path")
    require(policy.get("tracked") is False, "generated evidence tracked flag must be false")
    require(policy.get("local_only") is True, "generated evidence local_only flag must be true")

required_summary_lines = [
    "Foundation frozen for review: yes",
    "Foundation review-ready: yes",
    "Runtime validation: no",
    "Production readiness: no",
    "External validation: no",
    "Host mutation: no",
    "Actual installation: no",
    "Credential setup: no",
]
for line in required_summary_lines:
    require(line in summary_text.splitlines(), f"summary must contain exact status line: {line}")

require("FOUNDATION_FROZEN_FOR_REVIEW" not in summary_text, "summary should describe the decision without duplicating machine status")
require("build/wucios/devlanes/disposable-profile-foundation-batch-9/foundation-review-packet/" in summary_text, "summary must identify ignored review packet path")
require("no further" in summary_text.lower(), "summary must state no further foundation expansion before adoption decision")

def walk_items(value, path="$"):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield ("key", key, path)
            yield from walk_items(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index_value, nested in enumerate(value):
            yield from walk_items(nested, f"{path}[{index_value}]")
    elif isinstance(value, str):
        yield ("value", value, path)

forbidden_fields = set(contract.get("forbidden_freeze_fields", [])) if isinstance(contract.get("forbidden_freeze_fields"), list) else set()
allowed_forbidden_field_values = forbidden_fields
for label, value in (("freeze contract", contract), ("freeze decision", decision)):
    for kind, text, path in walk_items(value):
        if kind == "key":
            require(text not in forbidden_fields, f"{label} contains forbidden field key: {text}")
        else:
            if text in allowed_forbidden_field_values:
                continue
            require("mnt-samsung-t7/" not in text, f"{label} contains personal SSD path at {path}")
            require(not text.startswith("/"), f"{label} contains absolute host path at {path}: {text}")

summary_allowed_lines = set(required_summary_lines)
summary_forbidden_phrases = [
    "runtime" + " validation",
    "actual" + " installation",
    "host" + " mutation",
    "credential" + " setup",
    "package" + " installation",
    "service" + " setup",
    "production" + " readiness",
    "external" + " validation",
    "runtime" + " provisioning",
    "real disposable developer profile" + " creation",
    "high-assurance" + " certification",
]

for line in summary_text.splitlines():
    require("mnt-samsung-t7/" not in line, "summary must not reference personal SSD path")
    require(not line.startswith("/"), f"summary must not contain absolute host path line: {line}")
    lowered = line.lower()
    for phrase in summary_forbidden_phrases:
        if phrase in lowered and line not in summary_allowed_lines:
            fail(f"summary contains forbidden affirmative phrase outside allowed negative status line: {phrase}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: foundation freeze decision contract is valid")
print("PASS: foundation freeze decision record is valid")
print("PASS: foundation freeze summary contains required boundary lines")
print("PASS: foundation freeze references are relative and present")
print("PASS: foundation is frozen for review only")
PY
