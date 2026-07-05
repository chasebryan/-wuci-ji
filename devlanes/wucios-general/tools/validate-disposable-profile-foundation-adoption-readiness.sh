#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
READINESS_CONTRACT="$SCAFFOLD/foundation-adoption-readiness-contract.json"
READINESS_RECORD="$SCAFFOLD/foundation-adoption-readiness.json"
ASSET_LEDGER="$SCAFFOLD/foundation-frozen-asset-ledger.json"

printf '%s\n' 'Disposable developer profile foundation adoption readiness validator'
printf 'Adoption readiness contract: %s\n' "$READINESS_CONTRACT"

python3 - "$REPO_ROOT" "$READINESS_CONTRACT" "$READINESS_RECORD" "$ASSET_LEDGER" <<'PY'
import json
import shlex
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
record_path = Path(sys.argv[3])
ledger_path = Path(sys.argv[4])
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

contract = load_json(contract_path, "foundation adoption readiness contract")
record = load_json(record_path, "foundation adoption readiness record")
ledger = load_json(ledger_path, "foundation frozen asset ledger")

expected_profile_id = "wucios.disposable_developer_profile.scaffold_contract.v1"
require(contract.get("schema") == "wucios.disposable_profile.foundation_adoption_readiness_contract.v1", "adoption readiness contract schema must match")
require(contract.get("schema_version") == "1", "adoption readiness contract schema_version must be 1")
require(contract.get("profile_contract_id") == expected_profile_id, "adoption readiness contract profile id must match")
require(contract.get("foundation_adoption_readiness_kind") == "frozen_foundation_adoption_review_readiness", "adoption readiness contract kind must match")
require(contract.get("dry_run_only") is True, "adoption readiness contract dry_run_only must be true")
require(contract.get("foundation_only") is True, "adoption readiness contract foundation_only must be true")

require(record.get("schema") == "wucios.disposable_profile.foundation_adoption_readiness.v1", "adoption readiness record schema must match")
require(record.get("schema_version") == "1", "adoption readiness record schema_version must be 1")
require(record.get("profile_contract_id") == expected_profile_id, "adoption readiness record profile id must match")
require(record.get("foundation_adoption_readiness_kind") == "frozen_foundation_adoption_review_readiness", "adoption readiness record kind must match")
require(record.get("dry_run_only") is True, "adoption readiness record dry_run_only must be true")
require(record.get("foundation_only") is True, "adoption readiness record foundation_only must be true")

require(ledger.get("schema") == "wucios.disposable_profile.foundation_frozen_asset_ledger.v1", "frozen asset ledger schema must match")
require(ledger.get("schema_version") == "1", "frozen asset ledger schema_version must be 1")
require(ledger.get("profile_contract_id") == expected_profile_id, "frozen asset ledger profile id must match")
require(ledger.get("foundation_frozen_for_review") is True, "frozen asset ledger foundation_frozen_for_review must be true")
require(ledger.get("dry_run_only") is True, "frozen asset ledger dry_run_only must be true")
require(ledger.get("foundation_only") is True, "frozen asset ledger foundation_only must be true")

allowed_readiness = contract.get("allowed_readiness_values", [])
require(isinstance(allowed_readiness, list) and allowed_readiness, "allowed readiness values must be listed")
for value in (
    "FOUNDATION_ADOPTION_REVIEW_READY",
    "FOUNDATION_ADOPTION_REVIEW_BLOCKED",
    "FOUNDATION_ADOPTION_REVIEW_INCOMPLETE",
):
    require(value in allowed_readiness, f"allowed readiness values must include {value}")

selected_readiness = record.get("readiness")
require(selected_readiness in allowed_readiness, "selected readiness must be allowlisted")
require(selected_readiness == "FOUNDATION_ADOPTION_REVIEW_READY", "selected readiness must be adoption-review ready")

required_true_flags = [
    "foundation_frozen_for_review",
    "adoption_review_ready",
]
required_false_flags = [
    "mainline_adopted",
    "runtime_ready",
    "production_ready",
    "external_validation",
    "host_mutation",
    "actual_installation",
    "credential_setup",
]
for key in required_true_flags:
    require(record.get(key) is True, f"{key} must be true")
for key in required_false_flags:
    require(record.get(key) is False, f"{key} must be false")

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

for key in ("required_referenced_freeze_files", "required_referenced_closeout_files"):
    values = contract.get(key)
    require(isinstance(values, list) and values, f"contract {key} must be a non-empty list")
    if isinstance(values, list):
        for value in values:
            validate_repo_path(value, f"contract {key} entry")

for key in ("referenced_freeze_files", "referenced_closeout_files"):
    values = record.get(key)
    require(isinstance(values, list) and values, f"record {key} must be a non-empty list")
    if isinstance(values, list):
        for value in values:
            validate_repo_path(value, f"record {key} entry")

contract_freeze_files = set(contract.get("required_referenced_freeze_files", [])) if isinstance(contract.get("required_referenced_freeze_files"), list) else set()
record_freeze_files = set(record.get("referenced_freeze_files", [])) if isinstance(record.get("referenced_freeze_files"), list) else set()
require(contract_freeze_files == record_freeze_files, "contract and record freeze file references must match")

contract_closeout_files = set(contract.get("required_referenced_closeout_files", [])) if isinstance(contract.get("required_referenced_closeout_files"), list) else set()
record_closeout_files = set(record.get("referenced_closeout_files", [])) if isinstance(record.get("referenced_closeout_files"), list) else set()
require(contract_closeout_files == record_closeout_files, "contract and record closeout file references must match")

ledger_path_value = record.get("frozen_asset_ledger")
validate_repo_path(ledger_path_value, "record frozen_asset_ledger")
if is_relative_repo_path(ledger_path_value):
    require((repo_root / ledger_path_value).resolve() == ledger_path.resolve(), "record frozen_asset_ledger must point at the validated ledger")

policy = record.get("generated_evidence_policy")
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

required_commands = contract.get("required_validation_commands", [])
require(isinstance(required_commands, list) and required_commands, "required validation commands must be listed")
if isinstance(required_commands, list):
    for command in required_commands:
        require(isinstance(command, str) and command, f"validation command must be a non-empty string: {command}")
        if not isinstance(command, str):
            continue
        require("mnt-samsung-t7/" not in command, "validation command must not reference personal SSD path")
        parts = shlex.split(command)
        require(len(parts) >= 2 and parts[0] == "sh", f"validation command must be runnable with sh: {command}")
        if len(parts) >= 2:
            validate_repo_path(parts[1], "validation command script")
            script_path = repo_root / parts[1]
            if script_path.is_file():
                result = subprocess.run(["sh", "-n", str(script_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                require(result.returncode == 0, f"validation command script must pass sh -n: {parts[1]}")
        for argument in parts[2:]:
            require(not argument.startswith("/"), f"validation command argument must not be absolute: {argument}")
            require("mnt-samsung-t7/" not in argument, f"validation command argument must not reference personal SSD path: {argument}")

assets = ledger.get("assets")
require(isinstance(assets, list) and assets, "frozen asset ledger assets must be a non-empty list")
required_asset_paths = {
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/contract-manifest.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/plan-vocabulary-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/contract-traceability-matrix.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-validation-registry.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-validation-report-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-review-packet-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-closeout-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-closeout-index.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-closeout-summary.md",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-freeze-decision-contract.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-freeze-decision.json",
    "devlanes/wucios-general/scaffolds/disposable-developer-profile/foundation-freeze-summary.md",
    "devlanes/wucios-general/tools/plan-disposable-profile-dry-run.sh",
    "devlanes/wucios-general/tools/run-disposable-profile-foundation-validation.sh",
    "devlanes/wucios-general/tools/run-disposable-profile-foundation-review-packet.sh",
}
seen_paths = set()
if isinstance(assets, list):
    for index, entry in enumerate(assets):
        require(isinstance(entry, dict), f"ledger asset {index} must be an object")
        if not isinstance(entry, dict):
            continue
        asset_path = entry.get("asset_path")
        validate_repo_path(asset_path, f"ledger asset {index} path")
        if is_relative_repo_path(asset_path):
            require(asset_path not in seen_paths, f"ledger asset path must be unique: {asset_path}")
            seen_paths.add(asset_path)
        require(entry.get("asset_kind") in {"contract", "traceability", "registry", "index", "summary", "decision", "validation_record", "generator_script", "validator_script"}, f"ledger asset {index} kind must be allowlisted")
        require(isinstance(entry.get("foundation_role"), str) and entry.get("foundation_role"), f"ledger asset {index} foundation_role must be present")
        if entry.get("asset_kind") in {"generator_script", "validator_script"} and is_relative_repo_path(asset_path) and (repo_root / asset_path).is_file():
            result = subprocess.run(["sh", "-n", str(repo_root / asset_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            require(result.returncode == 0, f"ledger script asset must pass sh -n: {asset_path}")

missing_assets = sorted(required_asset_paths.difference(seen_paths))
require(not missing_assets, "frozen asset ledger missing required assets: " + ", ".join(missing_assets))

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

forbidden_fields = set(contract.get("forbidden_adoption_fields", [])) if isinstance(contract.get("forbidden_adoption_fields"), list) else set()
allowed_forbidden_field_values = forbidden_fields
for label, value in (("adoption contract", contract), ("adoption record", record), ("frozen asset ledger", ledger)):
    for kind, text, path in walk_items(value):
        if kind == "key":
            require(text not in forbidden_fields, f"{label} contains forbidden field key: {text}")
        else:
            if text in allowed_forbidden_field_values:
                continue
            require("mnt-samsung-t7/" not in text, f"{label} contains personal SSD path at {path}")
            require(not text.startswith("/"), f"{label} contains absolute host path at {path}: {text}")

scan_text = "\n".join(json.dumps(value, sort_keys=True) for value in (contract, record, ledger)).lower()
forbidden_phrases = [
    "runtime" + " provisioning",
    "actual" + " installation" + " true",
    "host" + " mutation" + " true",
    "credential" + " setup" + " true",
    "package" + " installation",
    "service" + " setup",
    "production" + " readiness",
    "real disposable developer profile" + " creation",
    "external" + " validation" + " true",
    "high-assurance" + " certification",
    "mainline adoption already" + " completed",
    "release" + " readiness",
]
for phrase in forbidden_phrases:
    require(phrase not in scan_text, f"adoption readiness contains forbidden affirmative phrase: {phrase}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: foundation adoption readiness contract is valid")
print("PASS: foundation adoption readiness record is valid")
print("PASS: foundation frozen asset ledger is valid")
print("PASS: adoption readiness references are relative and present")
print("PASS: adoption readiness is review-ready only")
PY
