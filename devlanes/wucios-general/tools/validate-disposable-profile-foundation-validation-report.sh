#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd) || exit 2
LANE_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd) || exit 2
REPO_ROOT=$(git -C "$LANE_DIR" rev-parse --show-toplevel 2>/dev/null) || exit 2
SCAFFOLD="$LANE_DIR/scaffolds/disposable-developer-profile"
MANIFEST="$SCAFFOLD/contract-manifest.json"
REGISTRY="$SCAFFOLD/foundation-validation-registry.json"
MATRIX="$SCAFFOLD/contract-traceability-matrix.json"
REPORT_CONTRACT="$SCAFFOLD/foundation-validation-report-contract.json"
RUNNER="$SCRIPT_DIR/run-disposable-profile-foundation-validation.sh"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run"
REPORT_JSON="$REPO_ROOT/$BATCH_REL/foundation-validation-report.json"
REPORT_MD="$REPO_ROOT/$BATCH_REL/foundation-validation-report.md"

printf '%s\n' 'Disposable developer profile foundation validation report validator'
printf 'Report contract: %s\n' "$REPORT_CONTRACT"

if [ ! -f "$REPORT_CONTRACT" ]; then
	printf 'FAIL: foundation validation report contract missing: %s\n' "$REPORT_CONTRACT"
	exit 1
fi

if [ ! -f "$RUNNER" ]; then
	printf 'FAIL: foundation validation runner missing: %s\n' "$RUNNER"
	exit 1
fi

if sh "$RUNNER" >/dev/null; then
	RUNNER_STATUS=0
else
	RUNNER_STATUS=$?
fi

python3 - "$REPO_ROOT" "$MANIFEST" "$REGISTRY" "$MATRIX" "$REPORT_CONTRACT" "$REPORT_JSON" "$REPORT_MD" "$BATCH_REL" "$RUNNER_STATUS" <<'PY'
import json
import shlex
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
registry_path = Path(sys.argv[3])
matrix_path = Path(sys.argv[4])
contract_path = Path(sys.argv[5])
report_json_path = Path(sys.argv[6])
report_md_path = Path(sys.argv[7])
batch_rel = sys.argv[8]
runner_status = int(sys.argv[9])
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

manifest = load_json(manifest_path, "contract manifest")
registry = load_json(registry_path, "foundation validation registry")
matrix = load_json(matrix_path, "traceability matrix")
contract = load_json(contract_path, "foundation validation report contract")
report = load_json(report_json_path, "foundation validation report")

require(report_md_path.is_file(), "foundation validation markdown report exists")
markdown = report_md_path.read_text(encoding="utf-8") if report_md_path.is_file() else ""

require(runner_status == 0, "foundation validation runner must exit with status 0")

require(isinstance(contract, dict), "report contract root must be an object")
if isinstance(contract, dict):
    require(
        contract.get("schema") == "wucios.disposable_profile.foundation_validation_report_contract.v1",
        "report contract schema must identify the report contract",
    )
    require(contract.get("schema_version") == "1", "report contract schema_version must be 1")
    require(
        contract.get("foundation_validation_report_contract_id")
        == "wucios.disposable_profile.foundation_validation_report.batch8.v1",
        "report contract id must identify Batch 8 report contract",
    )
    require(contract.get("dry_run_only") is True, "report contract dry_run_only must be true")
    require(contract.get("foundation_only") is True, "report contract foundation_only must be true")
    require(contract.get("report_kind") == "foundation_validation_run_report", "report contract kind must match runner report")

allowed_results = set(contract.get("allowed_result_values", []))
require({"PASS", "FAIL", "SKIP", "NOT_RUN"}.issubset(allowed_results), "report contract result values must be complete")
required_sections = set(contract.get("required_report_sections", []))
require(
    {"identifiers", "boundaries", "summary", "validator_results", "generated_evidence"}.issubset(required_sections),
    "report contract required sections must be complete",
)
forbidden_fields = set(contract.get("forbidden_report_fields", []))
require(forbidden_fields, "report contract forbidden_report_fields must be non-empty")

require(isinstance(report, dict), "report root must be an object")
if isinstance(report, dict):
    require(report.get("schema") == "wucios.disposable_profile.foundation_validation_report.v1", "report schema must identify foundation validation report")
    require(report.get("schema_version") == contract.get("schema_version"), "report schema_version must match report contract")
    require(report.get("report_kind") == contract.get("report_kind"), "report kind must match report contract")

identifiers = report.get("identifiers")
require(isinstance(identifiers, dict), "report identifiers section must be an object")
if isinstance(identifiers, dict):
    require(
        identifiers.get("profile_contract_id") == manifest.get("profile_contract_id") == contract.get("profile_contract_id"),
        "report profile contract id must match manifest and report contract",
    )
    require(
        identifiers.get("foundation_validation_registry_id") == registry.get("registry_id") == contract.get("foundation_validation_registry_id"),
        "report registry id must match registry and report contract",
    )
    require(
        identifiers.get("contract_traceability_matrix_id")
        == matrix.get("contract_traceability_matrix_id")
        == contract.get("contract_traceability_matrix_id"),
        "report traceability matrix id must match matrix and report contract",
    )
    require(
        identifiers.get("foundation_validation_report_contract_id")
        == contract.get("foundation_validation_report_contract_id"),
        "report contract id must match report contract",
    )

boundaries = report.get("boundaries")
require(isinstance(boundaries, dict), "report boundaries section must be an object")
if isinstance(boundaries, dict):
    require(boundaries.get("dry_run_only") is True, "report dry_run_only must be true")
    require(boundaries.get("foundation_only") is True, "report foundation_only must be true")
    require(boundaries.get("execution_scope") == "scaffold_validation_only", "report execution_scope must be scaffold_validation_only")
    for key in ("runtime_validation", "production_readiness", "external_validation", "host_mutation"):
        require(boundaries.get(key) is False, f"report boundary {key} must be false")

summary = report.get("summary")
require(isinstance(summary, dict), "report summary section must be an object")
if isinstance(summary, dict):
    require(summary.get("overall_result") == "PASS", "report overall_result must be PASS")

registry_validators = registry.get("validators", [])
if not isinstance(registry_validators, list):
    registry_validators = []
expected_ids = [entry.get("validator_id") for entry in registry_validators if isinstance(entry, dict)]
expected_commands = [entry.get("command") for entry in registry_validators if isinstance(entry, dict)]

validator_results = report.get("validator_results")
require(isinstance(validator_results, list), "report validator_results section must be a list")
if not isinstance(validator_results, list):
    validator_results = []

actual_ids = [entry.get("validator_id") for entry in validator_results if isinstance(entry, dict)]
actual_commands = [entry.get("command") for entry in validator_results if isinstance(entry, dict)]
require(actual_ids == expected_ids, "report validator IDs must match registry order")
require(actual_commands == expected_commands, "report validator commands must match registry order")

for entry in validator_results:
    require(isinstance(entry, dict), "each validator result must be an object")
    if not isinstance(entry, dict):
        continue
    result = entry.get("result")
    require(result in allowed_results, f"validator result must be allowlisted: {result}")
    command = entry.get("command")
    require(isinstance(command, str) and command, "validator command must be present")
    if isinstance(command, str):
        parts = shlex.split(command)
        require(len(parts) >= 2 and parts[0] == "sh", f"validator command must use sh: {command}")
        if len(parts) >= 2:
            require(not parts[1].startswith("/"), f"validator command must use relative script path: {command}")
            require((repo_root / parts[1]).is_file(), f"validator command script must exist: {parts[1]}")

generated = report.get("generated_evidence")
require(isinstance(generated, dict), "report generated_evidence section must be an object")
if isinstance(generated, dict):
    for key in ("report_directory", "report_json", "report_markdown"):
        value = generated.get(key)
        require(isinstance(value, str) and value, f"generated evidence {key} must be present")
        if isinstance(value, str):
            require(not value.startswith("/"), f"generated evidence {key} must be relative")
            require(value.startswith("build/wucios/devlanes/"), f"generated evidence {key} must stay under build/wucios/devlanes/")

def walk_items(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield ("key", key)
            yield from walk_items(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_items(nested)
    elif isinstance(value, str):
        yield ("value", value)

for kind, text in walk_items(report):
    require("mnt-samsung-t7" not in text, "report must not reference personal SSD path")
    if kind == "key":
        require(text not in forbidden_fields, f"report contains forbidden field: {text}")
    if kind == "value":
        require(not text.startswith("/"), f"report string value must not be an absolute host path: {text}")

for text in (markdown,):
    require("mnt-samsung-t7" not in text, "markdown report must not reference personal SSD path")
    for line in text.splitlines():
        require(not line.startswith("/"), f"markdown report line must not start with an absolute path: {line}")

forbidden_phrases = [
    "runtime" + " provisioning",
    "actual" + " installation",
    "host" + " mutation" + " occurred",
    "host" + " mutation" + " proven",
    "credential" + " setup",
    "package" + " installation",
    "service" + " setup",
    "production" + " readiness",
    "real disposable developer profile" + " creation",
    "external" + " validation",
    "high-assurance" + " certification",
]

scan_text = json.dumps(report, sort_keys=True) + "\n" + markdown
lowered = scan_text.lower()
for phrase in forbidden_phrases:
    require(phrase not in lowered, f"report contains forbidden affirmative phrase: {phrase}")

tracked = subprocess.run(
    ["git", "-C", str(repo_root), "ls-files", "--", batch_rel],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
require(tracked.returncode == 0, "git ls-files check must succeed")
require(not tracked.stdout.strip(), "Batch 8 generated evidence must not be tracked")

staged = subprocess.run(
    ["git", "-C", str(repo_root), "diff", "--cached", "--name-only", "--", batch_rel],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
require(staged.returncode == 0, "git staged evidence check must succeed")
require(not staged.stdout.strip(), "Batch 8 generated evidence must not be staged")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: foundation validation report contract is valid")
print("PASS: foundation validation runner produced a valid report")
print("PASS: foundation validation report identifiers match manifest, registry, matrix, and report contract")
print("PASS: foundation validation report covers every registered validator")
print("PASS: foundation validation report paths are relative and scoped")
print("PASS: foundation validation report generated evidence is ignored")
PY
