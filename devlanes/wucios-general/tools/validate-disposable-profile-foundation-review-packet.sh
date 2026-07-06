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
REVIEW_CONTRACT="$SCAFFOLD/foundation-review-packet-contract.json"
GENERATOR="$SCRIPT_DIR/run-disposable-profile-foundation-review-packet.sh"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-9/foundation-review-packet"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"

printf '%s\n' 'Disposable developer profile foundation review packet validator'
printf 'Review packet contract: %s\n' "$REVIEW_CONTRACT"

if [ ! -f "$REVIEW_CONTRACT" ]; then
	printf 'FAIL: foundation review packet contract missing: %s\n' "$REVIEW_CONTRACT"
	exit 1
fi

if [ ! -f "$GENERATOR" ]; then
	printf 'FAIL: foundation review packet generator missing: %s\n' "$GENERATOR"
	exit 1
fi

if sh "$GENERATOR" >/dev/null; then
	GENERATOR_STATUS=0
else
	GENERATOR_STATUS=$?
fi

python3 - "$REPO_ROOT" "$MANIFEST" "$REGISTRY" "$MATRIX" "$REPORT_CONTRACT" "$REVIEW_CONTRACT" "$BATCH_REL" "$GENERATOR_STATUS" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
registry_path = Path(sys.argv[3])
matrix_path = Path(sys.argv[4])
report_contract_path = Path(sys.argv[5])
review_contract_path = Path(sys.argv[6])
batch_rel = sys.argv[7]
generator_status = int(sys.argv[8])
batch_dir = repo_root / batch_rel
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
report_contract = load_json(report_contract_path, "foundation validation report contract")
review_contract = load_json(review_contract_path, "foundation review packet contract")

require(generator_status == 0, "foundation review packet generator must exit with status 0")
require(batch_rel == "build/wucios/devlanes/disposable-profile-foundation-batch-9/foundation-review-packet", "Batch 9 packet path must be canonical")
require(batch_dir.is_dir(), "foundation review packet directory must exist")

require(
    review_contract.get("schema") == "wucios.disposable_profile.foundation_review_packet_contract.v1",
    "review packet contract schema must match",
)
require(review_contract.get("schema_version") == "1", "review packet contract schema_version must be 1")
require(
    review_contract.get("foundation_review_packet_contract_id")
    == "wucios.disposable_profile.foundation_review_packet.batch9.v1",
    "review packet contract id must identify Batch 9",
)
require(review_contract.get("dry_run_only") is True, "review packet contract dry_run_only must be true")
require(review_contract.get("foundation_only") is True, "review packet contract foundation_only must be true")

expected_ids = {
    "profile_contract_id": manifest.get("profile_contract_id"),
    "foundation_validation_report_contract_id": report_contract.get("foundation_validation_report_contract_id"),
    "foundation_validation_registry_id": registry.get("registry_id"),
    "contract_traceability_matrix_id": matrix.get("contract_traceability_matrix_id"),
    "foundation_review_packet_contract_id": review_contract.get("foundation_review_packet_contract_id"),
}

required_files = review_contract.get("required_packet_files", [])
require(isinstance(required_files, list) and required_files, "required packet files must be listed")
for name in required_files if isinstance(required_files, list) else []:
    require((batch_dir / name).is_file(), f"required packet file exists: {name}")

json_files = {
    "validation-summary.json": batch_dir / "validation-summary.json",
    "traceability-summary.json": batch_dir / "traceability-summary.json",
    "evidence-index.json": batch_dir / "evidence-index.json",
}
packet_json = {name: load_json(path, name) for name, path in json_files.items()}

def require_ids(value, label):
    identifiers = value.get("identifiers") if isinstance(value, dict) else None
    require(isinstance(identifiers, dict), f"{label} identifiers must be an object")
    if isinstance(identifiers, dict):
        for key, expected in expected_ids.items():
            require(identifiers.get(key) == expected, f"{label} {key} must match source contract")

for name, value in packet_json.items():
    require(isinstance(value, dict), f"{name} root must be an object")
    require_ids(value, name)

validation_summary = packet_json.get("validation-summary.json", {})
traceability_summary = packet_json.get("traceability-summary.json", {})
evidence_index = packet_json.get("evidence-index.json", {})

boundaries = validation_summary.get("boundaries") if isinstance(validation_summary, dict) else None
require(isinstance(boundaries, dict), "validation summary boundaries must be an object")
if isinstance(boundaries, dict):
    require(boundaries.get("dry_run_only") is True, "validation summary dry_run_only must be true")
    require(boundaries.get("foundation_only") is True, "validation summary foundation_only must be true")
    for key in (
        "runtime_validation",
        "production_readiness",
        "external_validation",
        "host_mutation",
        "actual_installation",
        "credential_setup",
    ):
        require(boundaries.get(key) is False, f"validation summary boundary {key} must be false")

registry_validators = registry.get("validators", [])
if not isinstance(registry_validators, list):
    registry_validators = []
expected_validator_ids = [entry.get("validator_id") for entry in registry_validators if isinstance(entry, dict)]
summary_validators = validation_summary.get("validators") if isinstance(validation_summary, dict) else []
require(isinstance(summary_validators, list), "validation summary validators must be a list")
if isinstance(summary_validators, list):
    actual_validator_ids = [entry.get("validator_id") for entry in summary_validators if isinstance(entry, dict)]
    require(actual_validator_ids == expected_validator_ids, "validation summary validators must match registry order")
    for entry in summary_validators:
        if isinstance(entry, dict):
            require(entry.get("result") in {"PASS", "FAIL", "SKIP", "NOT_RUN"}, "validator result must be allowlisted")

matrix_entries = matrix.get("entries", [])
if not isinstance(matrix_entries, list):
    matrix_entries = []
claims = traceability_summary.get("claims") if isinstance(traceability_summary, dict) else []
require(isinstance(claims, list), "traceability summary claims must be a list")
if isinstance(claims, list):
    require(len(claims) == len(matrix_entries), "traceability summary claim count must match matrix")
    require(
        [claim.get("claim_id") for claim in claims if isinstance(claim, dict)]
        == [entry.get("claim_id") for entry in matrix_entries if isinstance(entry, dict)],
        "traceability summary claim IDs must match matrix order",
    )

generated_files = evidence_index.get("generated_files") if isinstance(evidence_index, dict) else []
require(isinstance(generated_files, list), "evidence index generated_files must be a list")
if isinstance(generated_files, list):
    for rel in generated_files:
        require(isinstance(rel, str) and rel.startswith("build/wucios/devlanes/"), f"generated file must stay under build/wucios/devlanes/: {rel}")
        require(not rel.startswith("/"), f"generated file path must be relative: {rel}")
        require((repo_root / rel).is_file(), f"generated file must exist: {rel}")

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

forbidden_fields = set(review_contract.get("forbidden_packet_fields", []))
for name, value in packet_json.items():
    for kind, text in walk_items(value):
        require("mnt-samsung-t7" not in text, f"{name} must not reference personal SSD path")
        if kind == "key":
            require(text not in forbidden_fields, f"{name} contains forbidden field: {text}")
        if kind == "value":
            require(not text.startswith("/"), f"{name} contains absolute host path: {text}")

markdown_files = [
    batch_dir / "README.md",
    batch_dir / "claim-boundary.md",
    batch_dir / "validation-summary.md",
    batch_dir / "reviewer-commands.md",
]
for path in markdown_files:
    require(path.is_file(), f"markdown packet file exists: {path.name}")
    if not path.is_file():
        continue
    text = path.read_text(encoding="utf-8")
    require("mnt-samsung-t7" not in text, f"{path.name} must not reference personal SSD path")
    for line in text.splitlines():
        require(not line.startswith("/"), f"{path.name} must not contain absolute path line: {line}")

forbidden_phrases = [
    "runtime" + " provisioning",
    "actual" + " installation" + " true",
    "host" + " mutation" + " occurred",
    "host" + " mutation" + " proven",
    "credential" + " setup" + " true",
    "package" + " installation",
    "service" + " setup",
    "production" + " readiness",
    "real disposable developer profile" + " creation",
    "external" + " validation",
    "high-assurance" + " certification",
]

scan_text = "\n".join(
    json.dumps(value, sort_keys=True)
    for value in packet_json.values()
) + "\n" + "\n".join(
    path.read_text(encoding="utf-8")
    for path in markdown_files
    if path.is_file()
)
lowered = scan_text.lower()
for phrase in forbidden_phrases:
    require(phrase not in lowered, f"review packet contains forbidden affirmative phrase: {phrase}")

tracked = subprocess.run(
    ["git", "-C", str(repo_root), "ls-files", "--", batch_rel],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
require(tracked.returncode == 0, "git ls-files check must succeed")
require(not tracked.stdout.strip(), "Batch 9 review packet evidence must not be tracked")

staged = subprocess.run(
    ["git", "-C", str(repo_root), "diff", "--cached", "--name-only", "--", batch_rel],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
require(staged.returncode == 0, "git staged packet check must succeed")
require(not staged.stdout.strip(), "Batch 9 review packet evidence must not be staged")

if failures:
    for message in failures:
        print(f"FAIL: {message}")
    sys.exit(1)

print("PASS: foundation review packet contract is valid")
print("PASS: foundation review packet generator produced required files")
print("PASS: foundation review packet identifiers match source contracts")
print("PASS: foundation review packet validators match registry order")
print("PASS: foundation review packet traceability summary matches matrix")
print("PASS: foundation review packet paths are relative and scoped")
print("PASS: foundation review packet generated evidence is ignored")
PY
