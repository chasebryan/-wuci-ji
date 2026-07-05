#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
MATRIX="$SCAFFOLD/contract-traceability-matrix.json"
MANIFEST="$SCAFFOLD/contract-manifest.json"
VOCABULARY="$SCAFFOLD/plan-vocabulary-contract.json"

printf '%s\n' 'Disposable developer profile traceability matrix validator'
printf 'Matrix: %s\n' "$MATRIX"

if [ ! -f "$MATRIX" ]; then
	printf 'FAIL: traceability matrix missing: %s\n' "$MATRIX"
	exit 1
fi

python3 - "$REPO_ROOT" "$MATRIX" "$MANIFEST" "$VOCABULARY" <<'PY'
import json
import shlex
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
matrix_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])
vocabulary_path = Path(sys.argv[4])
failures = []

def fail(message):
    failures.append(message)

def require(condition, message):
    if not condition:
        fail(message)

def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        fail(f"{label} is not valid JSON: {exc}")
        return {}

matrix = load_json(matrix_path, "traceability matrix")
manifest = load_json(manifest_path, "contract manifest")
vocabulary = load_json(vocabulary_path, "plan vocabulary contract")

require(isinstance(matrix, dict), "traceability matrix root must be an object")

if isinstance(matrix, dict):
    require(
        matrix.get("schema") == "wucios.disposable_profile.contract_traceability_matrix.v1",
        "matrix schema must identify the traceability matrix contract",
    )
    require(matrix.get("schema_version") == "1", "matrix schema_version must be 1")
    require(
        matrix.get("contract_traceability_matrix_id")
        == "wucios.disposable_profile.contract_traceability_matrix.batch7.v1",
        "matrix contract_traceability_matrix_id must identify the Batch 7 matrix",
    )
    require(
        matrix.get("profile_contract_id") == manifest.get("profile_contract_id"),
        "matrix profile contract identity must match contract manifest",
    )
    require(
        matrix.get("plan_vocabulary_contract_id") == vocabulary.get("plan_vocabulary_contract_id"),
        "matrix plan vocabulary identity must match vocabulary contract",
    )
    require(matrix.get("dry_run_only") is True, "matrix dry_run_only must be true")
    require(matrix.get("foundation_only") is True, "matrix foundation_only must be true")

required_claim_ids = {
    "disposable_profile_scaffold_identity",
    "dry_run_only_behavior",
    "foundation_only_behavior",
    "valid_input_acceptance",
    "invalid_input_rejection",
    "evidence_contract_stability",
    "manifest_binding",
    "no_execution_plan_vocabulary",
    "forbidden_host_configuration_change_boundary",
    "forbidden_install_and_profile_creation_boundary",
    "forbidden_production_status_boundary",
}

entries = matrix.get("entries")
require(isinstance(entries, list), "matrix entries must be a list")
if not isinstance(entries, list):
    entries = []

seen_claim_ids = set()

def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from walk_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_strings(nested)

def is_relative_repo_path(value):
    return isinstance(value, str) and value and not value.startswith("/") and "://" not in value

def validate_repo_path(value, label, must_exist=True):
    require(is_relative_repo_path(value), f"{label} must be a relative repo path: {value}")
    if is_relative_repo_path(value) and must_exist:
        require((repo_root / value).exists(), f"{label} does not exist: {value}")

def validate_evidence_path(value, label):
    require(is_relative_repo_path(value), f"{label} must be relative: {value}")
    if is_relative_repo_path(value):
        require(
            value.startswith("build/wucios/devlanes/"),
            f"{label} must stay under build/wucios/devlanes/: {value}",
        )

def validate_validator_command(command, label):
    require(isinstance(command, str) and command, f"{label} must be a non-empty string")
    if not isinstance(command, str) or not command:
        return
    require("mnt-samsung-t7" not in command, f"{label} must not reference personal SSD path")
    parts = shlex.split(command)
    require(len(parts) >= 2, f"{label} must include a shell and validator path")
    if len(parts) < 2:
        return
    require(parts[0] == "sh", f"{label} must be runnable with sh")
    script = parts[1]
    validate_repo_path(script, f"{label} validator script")
    if is_relative_repo_path(script) and (repo_root / script).exists():
        result = subprocess.run(
            ["sh", "-n", str(repo_root / script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        require(result.returncode == 0, f"{label} validator script must pass sh -n: {script}")
    for argument in parts[2:]:
        require(not argument.startswith("/"), f"{label} argument must not be an absolute path: {argument}")
        require("mnt-samsung-t7" not in argument, f"{label} argument must not reference personal SSD path")

for text in walk_strings(matrix):
    require("mnt-samsung-t7" not in text, "matrix must not reference personal SSD path")
    require(not text.startswith("/"), f"matrix string must not be an absolute host path: {text}")

for entry in entries:
    require(isinstance(entry, dict), "each matrix entry must be an object")
    if not isinstance(entry, dict):
        continue
    claim_id = entry.get("claim_id")
    require(isinstance(claim_id, str) and claim_id, "matrix entry claim_id must be present")
    if isinstance(claim_id, str):
        seen_claim_ids.add(claim_id)
    require(isinstance(entry.get("claim_summary"), str) and entry.get("claim_summary"), f"{claim_id} claim_summary must be present")
    require(entry.get("status") == "foundation_checkable", f"{claim_id} status must be foundation_checkable")

    for key in ("contract_sources", "positive_coverage", "negative_coverage", "validator_commands", "evidence_outputs"):
        require(isinstance(entry.get(key), list), f"{claim_id} {key} must be a list")

    for source in entry.get("contract_sources", []):
        validate_repo_path(source, f"{claim_id} contract source")

    for key in ("positive_coverage", "negative_coverage"):
        for item in entry.get(key, []):
            require(isinstance(item, dict), f"{claim_id} {key} item must be an object")
            if not isinstance(item, dict):
                continue
            kind = item.get("kind")
            path = item.get("path")
            require(kind in {"validator", "fixture"}, f"{claim_id} {key} kind must be validator or fixture")
            validate_repo_path(path, f"{claim_id} {key} {kind}")
            if kind == "validator" and is_relative_repo_path(path) and (repo_root / path).exists():
                result = subprocess.run(
                    ["sh", "-n", str(repo_root / path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                require(result.returncode == 0, f"{claim_id} validator must pass sh -n: {path}")

    for command in entry.get("validator_commands", []):
        validate_validator_command(command, f"{claim_id} validator command")

    for evidence in entry.get("evidence_outputs", []):
        validate_evidence_path(evidence, f"{claim_id} evidence output")

missing = sorted(required_claim_ids.difference(seen_claim_ids))
require(not missing, "matrix missing required claim IDs: " + ", ".join(missing))

forbidden_affirmative_phrases = [
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

for entry in entries:
    if not isinstance(entry, dict):
        continue
    claim_summary = str(entry.get("claim_summary", "")).lower()
    for phrase in forbidden_affirmative_phrases:
        require(
            phrase not in claim_summary,
            f"{entry.get('claim_id')} claim_summary contains forbidden affirmative phrase: {phrase}",
        )

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: traceability matrix JSON structure is valid")
print("PASS: traceability matrix identities match manifest and vocabulary")
print("PASS: traceability matrix required claims are present")
print("PASS: traceability matrix references are relative and scoped")
print("PASS: traceability matrix validator commands are runnable with sh")
PY
