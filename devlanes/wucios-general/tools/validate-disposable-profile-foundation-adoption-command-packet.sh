#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
COMMAND_CONTRACT="$SCAFFOLD/foundation-adoption-command-contract.json"
COMMAND_PACKET="$SCAFFOLD/foundation-adoption-command-packet.json"
COMMAND_SUMMARY="$SCAFFOLD/foundation-adoption-command-summary.md"
COMMAND_NOTES="$SCAFFOLD/foundation-adoption-command-notes.md"

printf '%s\n' 'Disposable developer profile foundation adoption command packet validator'
printf 'Adoption command contract: %s\n' "$COMMAND_CONTRACT"

python3 - "$REPO_ROOT" "$COMMAND_CONTRACT" "$COMMAND_PACKET" "$COMMAND_SUMMARY" "$COMMAND_NOTES" <<'PY'
import json
import shlex
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
packet_path = Path(sys.argv[3])
summary_path = Path(sys.argv[4])
notes_path = Path(sys.argv[5])
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

contract = load_json(contract_path, "foundation adoption command contract")
packet = load_json(packet_path, "foundation adoption command packet")
summary_text = summary_path.read_text(encoding="utf-8") if summary_path.is_file() else ""
notes_text = notes_path.read_text(encoding="utf-8") if notes_path.is_file() else ""
require(summary_path.is_file(), f"foundation adoption command summary missing: {summary_path}")
require(notes_path.is_file(), f"foundation adoption command notes missing: {notes_path}")

expected_profile_id = "wucios.disposable_developer_profile.scaffold_contract.v1"
expected_kind = "frozen_foundation_future_adoption_command_packet"

require(contract.get("schema") == "wucios.disposable_profile.foundation_adoption_command_contract.v1", "adoption command contract schema must match")
require(contract.get("schema_version") == "1", "adoption command contract schema_version must be 1")
require(contract.get("profile_contract_id") == expected_profile_id, "adoption command contract profile id must match")
require(contract.get("foundation_adoption_command_kind") == expected_kind, "adoption command contract kind must match")
require(contract.get("dry_run_only") is True, "adoption command contract dry_run_only must be true")
require(contract.get("foundation_only") is True, "adoption command contract foundation_only must be true")
require(contract.get("mainline_adopted") is False, "adoption command contract mainline_adopted must be false")

require(packet.get("schema") == "wucios.disposable_profile.foundation_adoption_command_packet.v1", "adoption command packet schema must match")
require(packet.get("schema_version") == "1", "adoption command packet schema_version must be 1")
require(packet.get("profile_contract_id") == expected_profile_id, "adoption command packet profile id must match")
require(packet.get("foundation_adoption_command_kind") == expected_kind, "adoption command packet kind must match")
require(packet.get("dry_run_only") is True, "adoption command packet dry_run_only must be true")
require(packet.get("foundation_only") is True, "adoption command packet foundation_only must be true")

allowed_statuses = contract.get("allowed_command_packet_status_values", [])
require(isinstance(allowed_statuses, list) and allowed_statuses, "allowed command packet status values must be listed")
for value in (
    "FOUNDATION_ADOPTION_COMMAND_PACKET_READY",
    "FOUNDATION_ADOPTION_COMMAND_PACKET_BLOCKED",
    "FOUNDATION_ADOPTION_COMMAND_PACKET_INCOMPLETE",
):
    require(value in allowed_statuses, f"allowed command packet statuses must include {value}")

status = packet.get("status")
require(status in allowed_statuses, "selected command packet status must be allowlisted")
require(status == "FOUNDATION_ADOPTION_COMMAND_PACKET_READY", "selected command packet status must be ready")

required_true_flags = [
    "foundation_frozen_for_review",
    "adoption_review_ready",
    "adoption_command_packet_ready",
]
required_false_flags = [
    "mainline_adopted",
    "mainline_modified",
    "release_created",
    "runtime_ready",
    "production_ready",
    "external_validation",
    "host_mutation",
    "actual_installation",
    "credential_setup",
]
for key in required_true_flags:
    require(packet.get(key) is True, f"{key} must be true")
for key in required_false_flags:
    require(packet.get(key) is False, f"{key} must be false")

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

reference_pairs = [
    ("required_referenced_adoption_readiness_files", "referenced_adoption_readiness_files"),
    ("required_referenced_freeze_files", "referenced_freeze_files"),
    ("required_referenced_closeout_files", "referenced_closeout_files"),
]
for contract_key, packet_key in reference_pairs:
    contract_values = contract.get(contract_key)
    packet_values = packet.get(packet_key)
    require(isinstance(contract_values, list) and contract_values, f"contract {contract_key} must be a non-empty list")
    require(isinstance(packet_values, list) and packet_values, f"packet {packet_key} must be a non-empty list")
    if isinstance(contract_values, list):
        for value in contract_values:
            validate_repo_path(value, f"contract {contract_key} entry")
    if isinstance(packet_values, list):
        for value in packet_values:
            validate_repo_path(value, f"packet {packet_key} entry")
    require(
        set(contract_values or []) == set(packet_values or []),
        f"contract {contract_key} must match packet {packet_key}",
    )

preflight_checks = contract.get("required_preflight_checks")
stop_conditions = contract.get("required_stop_conditions")
require(isinstance(preflight_checks, list) and preflight_checks, "required preflight checks must be listed")
require(isinstance(stop_conditions, list) and stop_conditions, "required stop conditions must be listed")
if isinstance(preflight_checks, list):
    for item in (
        "clean_worktree",
        "origin_dev_lane_matches_frozen_adoption_ready_head",
        "all_required_validators_pass",
        "generated_evidence_untracked",
        "adoption_wording_preserves_claim_boundaries",
    ):
        require(item in preflight_checks, f"required preflight check missing: {item}")
if isinstance(stop_conditions, list):
    for item in (
        "worktree_not_clean",
        "origin_dev_lane_mismatch",
        "target_branch_unexpected_change",
        "required_validator_failure",
        "generated_evidence_would_be_committed",
        "claim_boundary_expansion_detected",
    ):
        require(item in stop_conditions, f"required stop condition missing: {item}")

policy = packet.get("generated_evidence_policy")
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

forbidden_fields = set(contract.get("forbidden_adoption_command_fields", [])) if isinstance(contract.get("forbidden_adoption_command_fields"), list) else set()
allowed_forbidden_field_values = forbidden_fields
for label, value in (("adoption command contract", contract), ("adoption command packet", packet)):
    for kind, text, path in walk_items(value):
        if kind == "key":
            require(text not in forbidden_fields, f"{label} contains forbidden field key: {text}")
        else:
            if text in allowed_forbidden_field_values:
                continue
            require("mnt-samsung-t7/" not in text, f"{label} contains personal SSD path at {path}")
            require(not text.startswith("/"), f"{label} contains absolute host path at {path}: {text}")

required_summary_lines = [
    "Adoption command packet ready: yes",
    "Mainline adopted: no",
    "Mainline modified: no",
    "Release created: no",
    "Runtime validation: no",
    "Production readiness: no",
    "External validation: no",
    "Host mutation: no",
    "Actual installation: no",
    "Credential setup: no",
]
for line in required_summary_lines:
    require(line in summary_text.splitlines(), f"summary must contain exact status line: {line}")

for phrase in (
    "fast-forward-only",
    "explicitly reviewed merge",
    "Stop if the worktree is not clean.",
    "Stop if any required validator fails.",
    "Stop if generated evidence would be committed.",
):
    require(phrase in summary_text or phrase in notes_text, f"summary or notes missing required future boundary phrase: {phrase}")

required_note_phrases = [
    "future-use outline only",
    "No adoption command is executed in",
    "git status --short",
    "git rev-parse origin/wucios-dev-general-lane",
    "validate-disposable-profile-foundation-adoption-command-packet.sh",
]
for phrase in required_note_phrases:
    require(phrase in notes_text, f"notes missing required phrase: {phrase}")

allowed_negative_lines = set(required_summary_lines)
for label, text in (("summary", summary_text), ("notes", notes_text)):
    require("mnt-samsung-t7/" not in text, f"{label} must not reference personal SSD path")
    for line in text.splitlines():
        require(not line.startswith("/"), f"{label} must not contain absolute path line: {line}")
    lowered = text.lower()
    forbidden_phrases = [
        "runtime" + " provisioning",
        "actual" + " installation" + " true",
        "host" + " mutation" + " true",
        "credential" + " setup" + " true",
        "package" + " installation",
        "service" + " setup",
        "production" + " readiness" + " true",
        "real disposable developer profile" + " creation",
        "external" + " validation" + " true",
        "high-assurance" + " certification",
        "mainline adoption already" + " completed",
        "release" + " readiness",
        "release" + " created" + " true",
    ]
    for phrase in forbidden_phrases:
        require(phrase not in lowered, f"{label} contains forbidden affirmative phrase: {phrase}")
    for line in text.splitlines():
        line_lowered = line.lower()
        for phrase in (
            "runtime" + " validation",
            "production" + " readiness",
            "external" + " validation",
            "host" + " mutation",
            "actual" + " installation",
            "credential" + " setup",
            "release" + " created",
        ):
            if phrase in line_lowered and line not in allowed_negative_lines:
                fail(f"{label} contains boundary phrase outside allowed negative status line: {phrase}")

scan_text = "\n".join(json.dumps(value, sort_keys=True) for value in (contract, packet)).lower()
for phrase in (
    "mainline adoption already" + " completed",
    "release" + " readiness",
    "release" + " created" + " true",
):
    require(phrase not in scan_text, f"packet JSON contains forbidden affirmative phrase: {phrase}")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: foundation adoption command contract is valid")
print("PASS: foundation adoption command packet is valid")
print("PASS: foundation adoption command summary and notes are valid")
print("PASS: adoption command references are relative and present")
print("PASS: adoption command packet is ready without adoption")
PY
