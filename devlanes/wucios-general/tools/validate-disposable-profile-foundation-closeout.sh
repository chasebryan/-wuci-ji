#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
CLOSEOUT_CONTRACT="$SCAFFOLD/foundation-closeout-contract.json"
CLOSEOUT_INDEX="$SCAFFOLD/foundation-closeout-index.json"
CLOSEOUT_SUMMARY="$SCAFFOLD/foundation-closeout-summary.md"

printf '%s\n' 'Disposable developer profile foundation closeout validator'
printf 'Closeout contract: %s\n' "$CLOSEOUT_CONTRACT"

python3 - "$REPO_ROOT" "$CLOSEOUT_CONTRACT" "$CLOSEOUT_INDEX" "$CLOSEOUT_SUMMARY" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
index_path = Path(sys.argv[3])
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

contract = load_json(contract_path, "foundation closeout contract")
index = load_json(index_path, "foundation closeout index")
summary_text = ""
if summary_path.is_file():
    summary_text = summary_path.read_text(encoding="utf-8")
else:
    fail(f"foundation closeout summary missing: {summary_path}")

expected_profile_id = "wucios.disposable_developer_profile.scaffold_contract.v1"
expected_contract_schema = "wucios.disposable_profile.foundation_closeout_contract.v1"
expected_index_schema = "wucios.disposable_profile.foundation_closeout_index.v1"

require(contract.get("schema") == expected_contract_schema, "closeout contract schema must match")
require(contract.get("schema_version") == "1", "closeout contract schema_version must be 1")
require(contract.get("profile_contract_id") == expected_profile_id, "closeout contract profile id must match")
require(contract.get("foundation_closeout_kind") == "foundation_review_closeout", "closeout contract kind must match")
require(contract.get("dry_run_only") is True, "closeout contract dry_run_only must be true")
require(contract.get("foundation_only") is True, "closeout contract foundation_only must be true")

require(index.get("schema") == expected_index_schema, "closeout index schema must match")
require(index.get("schema_version") == "1", "closeout index schema_version must be 1")
require(index.get("profile_contract_id") == expected_profile_id, "closeout index profile id must match")
require(index.get("foundation_closeout_kind") == "foundation_review_closeout", "closeout index kind must match")
require(index.get("foundation_review_ready") is True, "closeout index foundation_review_ready must be true")
require(index.get("runtime_ready") is False, "closeout index runtime_ready must be false")
require(index.get("production_ready") is False, "closeout index production_ready must be false")
require(index.get("external_validation") is False, "closeout index external_validation must be false")
require(index.get("closeout_status") == "FOUNDATION_REVIEW_READY", "closeout status must be FOUNDATION_REVIEW_READY")

allowed_status_values = contract.get("allowed_closeout_status_values", [])
require(isinstance(allowed_status_values, list), "allowed closeout status values must be a list")
for status in ("FOUNDATION_REVIEW_READY", "FOUNDATION_BLOCKED", "FOUNDATION_INCOMPLETE"):
    require(status in allowed_status_values, f"allowed closeout statuses must include {status}")

def is_relative_repo_path(value):
    return isinstance(value, str) and value and not value.startswith("/") and "://" not in value

def validate_repo_path(value, label, must_exist=True):
    require(is_relative_repo_path(value), f"{label} must be a relative repo path: {value}")
    if not is_relative_repo_path(value):
        return
    require("mnt-samsung-t7/" not in value, f"{label} must not reference personal SSD path: {value}")
    require(".." not in Path(value).parts, f"{label} must not contain parent traversal: {value}")
    if must_exist:
        require((repo_root / value).exists(), f"{label} does not exist: {value}")

def validate_generated_policy(policy, label):
    require(isinstance(policy, dict), f"{label} must be an object")
    if not isinstance(policy, dict):
        return
    for key in ("validation_report_root", "review_packet_root"):
        value = policy.get(key)
        require(is_relative_repo_path(value), f"{label}.{key} must be a relative path")
        if is_relative_repo_path(value):
            require(value.startswith("build/wucios/devlanes/"), f"{label}.{key} must stay under build/wucios/devlanes/: {value}")
            require("mnt-samsung-t7/" not in value, f"{label}.{key} must not reference personal SSD path")
    require(policy.get("tracked") is False, f"{label}.tracked must be false")
    require(policy.get("local_only") is True, f"{label}.local_only must be true")

for key in ("required_closeout_files", "required_contract_files", "required_validator_scripts", "required_validation_records"):
    values = contract.get(key)
    require(isinstance(values, list) and values, f"contract {key} must be a non-empty list")
    if isinstance(values, list):
        for value in values:
            validate_repo_path(value, f"contract {key} entry")

for key in ("canonical_contract_files", "canonical_generator_scripts", "canonical_validator_scripts", "validation_records"):
    values = index.get(key)
    require(isinstance(values, list) and values, f"index {key} must be a non-empty list")
    if isinstance(values, list):
        for value in values:
            validate_repo_path(value, f"index {key} entry")

validate_generated_policy(contract.get("required_generated_packet_policy"), "required_generated_packet_policy")
validate_generated_policy(index.get("generated_evidence_policy"), "generated_evidence_policy")

for key in ("canonical_generator_scripts", "canonical_validator_scripts"):
    for value in index.get(key, []) if isinstance(index.get(key), list) else []:
        if is_relative_repo_path(value) and (repo_root / value).is_file():
            result = subprocess.run(
                ["sh", "-n", str(repo_root / value)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            require(result.returncode == 0, f"{key} script must pass sh -n: {value}")

contract_records = set(contract.get("required_validation_records", [])) if isinstance(contract.get("required_validation_records"), list) else set()
index_records = set(index.get("validation_records", [])) if isinstance(index.get("validation_records"), list) else set()
require(contract_records == index_records, "contract and index validation record lists must match")

contract_files = set(contract.get("required_contract_files", [])) if isinstance(contract.get("required_contract_files"), list) else set()
index_contract_files = set(index.get("canonical_contract_files", [])) if isinstance(index.get("canonical_contract_files"), list) else set()
require(contract_files.issubset(index_contract_files), "index must include every required contract file")

required_summary_lines = [
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

require("build/wucios/devlanes/" in summary_text, "summary must explain generated evidence path policy")
require("run-disposable-profile-foundation-validation.sh" in summary_text, "summary must include canonical foundation validation command")
require("run-disposable-profile-foundation-review-packet.sh" in summary_text, "summary must include review packet generator command")

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

forbidden_fields = set(contract.get("forbidden_closeout_fields", [])) if isinstance(contract.get("forbidden_closeout_fields"), list) else set()
allowed_forbidden_field_values = forbidden_fields

for label, value in (("closeout contract", contract), ("closeout index", index)):
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

print("PASS: foundation closeout contract is valid")
print("PASS: foundation closeout index is valid")
print("PASS: foundation closeout summary contains required boundary lines")
print("PASS: foundation closeout indexed paths are relative and present")
print("PASS: foundation closeout status is review-ready only")
PY
