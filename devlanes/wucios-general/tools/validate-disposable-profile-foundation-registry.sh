#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
REGISTRY="$SCAFFOLD/foundation-validation-registry.json"
MATRIX="$SCAFFOLD/contract-traceability-matrix.json"

printf '%s\n' 'Disposable developer profile foundation validation registry validator'
printf 'Registry: %s\n' "$REGISTRY"

if [ ! -f "$REGISTRY" ]; then
	printf 'FAIL: foundation validation registry missing: %s\n' "$REGISTRY"
	exit 1
fi

python3 - "$REPO_ROOT" "$REGISTRY" "$MATRIX" <<'PY'
import json
import shlex
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
registry_path = Path(sys.argv[2])
matrix_path = Path(sys.argv[3])
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

registry = load_json(registry_path, "foundation validation registry")
matrix = load_json(matrix_path, "traceability matrix")

require(isinstance(registry, dict), "registry root must be an object")
if isinstance(registry, dict):
    require(
        registry.get("schema") == "wucios.disposable_profile.foundation_validation_registry.v1",
        "registry schema must identify the foundation validation registry",
    )
    require(registry.get("schema_version") == "1", "registry schema_version must be 1")
    require(
        registry.get("profile_contract_id") == "wucios.disposable_developer_profile.scaffold_contract.v1",
        "registry profile contract identity must match the disposable scaffold",
    )
    require(
        registry.get("plan_vocabulary_contract_id") == "wucios.disposable_profile.no_execution_plan_vocabulary.v1",
        "registry plan vocabulary identity must match Batch 6 contract",
    )
    require(registry.get("dry_run_only") is True, "registry dry_run_only must be true")
    require(registry.get("foundation_only") is True, "registry foundation_only must be true")

validators = registry.get("validators")
require(isinstance(validators, list), "registry validators must be a list")
if not isinstance(validators, list):
    validators = []

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

def parse_command(command, label):
    require(isinstance(command, str) and command, f"{label} command must be a non-empty string")
    if not isinstance(command, str) or not command:
        return None
    require("mnt-samsung-t7" not in command, f"{label} command must not reference personal SSD path")
    parts = shlex.split(command)
    require(len(parts) >= 2, f"{label} command must include sh and a script path")
    if len(parts) < 2:
        return None
    require(parts[0] == "sh", f"{label} command must be runnable with sh")
    script = parts[1]
    require(is_relative_repo_path(script), f"{label} script must be a relative repo path: {script}")
    if is_relative_repo_path(script):
        script_path = repo_root / script
        require(script_path.is_file(), f"{label} script missing: {script}")
        if script_path.is_file():
            result = subprocess.run(
                ["sh", "-n", str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            require(result.returncode == 0, f"{label} script must pass sh -n: {script}")
    for argument in parts[2:]:
        require(not argument.startswith("/"), f"{label} argument must not be absolute: {argument}")
        require("mnt-samsung-t7" not in argument, f"{label} argument must not reference personal SSD path")
    return script

registry_scripts = []
seen_validator_ids = set()
for index, entry in enumerate(validators):
    label = f"registry validator entry {index}"
    require(isinstance(entry, dict), f"{label} must be an object")
    if not isinstance(entry, dict):
        continue
    validator_id = entry.get("validator_id")
    require(isinstance(validator_id, str) and validator_id, f"{label} validator_id must be present")
    if isinstance(validator_id, str):
        require(validator_id not in seen_validator_ids, f"validator_id must be unique: {validator_id}")
        seen_validator_ids.add(validator_id)
    for key in ("command", "purpose", "expected_scope", "generated_evidence_policy", "claim_boundary"):
        require(isinstance(entry.get(key), str) and entry.get(key), f"{label} {key} must be present")
    script = parse_command(entry.get("command"), label)
    if script:
        registry_scripts.append(script)

for text in walk_strings(registry):
    require("mnt-samsung-t7" not in text, "registry must not reference personal SSD path")
    require(not text.startswith("/"), f"registry string must not be an absolute host path: {text}")

forbidden_affirmative_phrases = [
    "production" + " readiness",
    "real runtime" + " validation",
    "external" + " validation",
    "high-assurance" + " certification",
    "runtime" + " provisioning",
    "actual" + " installation",
    "host" + " mutation",
    "credential" + " setup",
    "package" + " installation",
    "service" + " setup",
]

for entry in validators:
    if not isinstance(entry, dict):
        continue
    joined = " ".join(
        str(entry.get(key, ""))
        for key in ("purpose", "expected_scope", "generated_evidence_policy", "claim_boundary")
    ).lower()
    for phrase in forbidden_affirmative_phrases:
        require(
            phrase not in joined,
            f"{entry.get('validator_id')} contains forbidden affirmative phrase: {phrase}",
        )

required_order = [
    "devlanes/wucios-general/tools/validate-disposable-profile-plan-input.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-negative-inputs.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-dry-run-stability.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-dry-run-evidence-contract.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-contract-manifest.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-planner-manifest-binding.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-plan-vocabulary.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-planner-output-vocabulary.sh",
    "devlanes/wucios-general/tools/validate-disposable-profile-traceability-matrix.sh",
]

registry_set = set(registry_scripts)
for script in required_order:
    require(script in registry_set, f"registry missing required validator: {script}")

last_index = -1
for script in required_order:
    if script not in registry_scripts:
        continue
    index = registry_scripts.index(script)
    require(index > last_index, f"registry validator order is wrong at: {script}")
    last_index = index

matrix_scripts = set()
entries = matrix.get("entries") if isinstance(matrix, dict) else []
if isinstance(entries, list):
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for command in entry.get("validator_commands", []):
            parts = shlex.split(command)
            if len(parts) >= 2 and parts[0] == "sh":
                matrix_scripts.add(parts[1])
else:
    fail("traceability matrix entries must be a list")

missing_from_registry = sorted(matrix_scripts.difference(registry_set))
require(
    not missing_from_registry,
    "registry missing validator commands used by traceability matrix: " + ", ".join(missing_from_registry),
)

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: foundation validation registry JSON structure is valid")
print("PASS: foundation validation registry commands are relative and runnable with sh")
print("PASS: foundation validation registry contains required validator order")
print("PASS: foundation validation registry agrees with traceability matrix commands")
PY
