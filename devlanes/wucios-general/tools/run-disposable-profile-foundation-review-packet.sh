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
FOUNDATION_RUNNER="$SCRIPT_DIR/run-disposable-profile-foundation-validation.sh"
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-9/foundation-review-packet"
BATCH_DIR="$REPO_ROOT/$BATCH_REL"
VALIDATION_REPORT_REL="build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run/foundation-validation-report.json"
VALIDATION_REPORT="$REPO_ROOT/$VALIDATION_REPORT_REL"

if [ "$#" -ne 0 ]; then
	printf '%s\n' 'usage: sh devlanes/wucios-general/tools/run-disposable-profile-foundation-review-packet.sh' >&2
	exit 2
fi

printf '%s\n' 'Disposable developer profile foundation review packet generator'
printf 'Packet directory: %s\n' "$BATCH_REL"

if [ ! -f "$FOUNDATION_RUNNER" ]; then
	printf 'FAIL: foundation validation runner missing: %s\n' "$FOUNDATION_RUNNER"
	exit 1
fi

if ! sh "$FOUNDATION_RUNNER" >/dev/null; then
	printf '%s\n' 'FAIL: foundation validation runner failed; review packet not generated'
	exit 1
fi

python3 - "$REPO_ROOT" "$MANIFEST" "$REGISTRY" "$MATRIX" "$REPORT_CONTRACT" "$REVIEW_CONTRACT" "$VALIDATION_REPORT" "$BATCH_REL" <<'PY'
import json
import shutil
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
registry_path = Path(sys.argv[3])
matrix_path = Path(sys.argv[4])
report_contract_path = Path(sys.argv[5])
review_contract_path = Path(sys.argv[6])
validation_report_path = Path(sys.argv[7])
batch_rel = sys.argv[8]
batch_dir = repo_root / batch_rel

expected_batch_dir = repo_root / "build/wucios/devlanes/disposable-profile-foundation-batch-9/foundation-review-packet"
if batch_dir != expected_batch_dir:
    print(f"FAIL: refusing unexpected review packet directory: {batch_rel}")
    sys.exit(1)

def load_json(path, label):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        print(f"FAIL: could not read {label}: {exc}")
        sys.exit(1)

manifest = load_json(manifest_path, "contract manifest")
registry = load_json(registry_path, "foundation validation registry")
matrix = load_json(matrix_path, "traceability matrix")
report_contract = load_json(report_contract_path, "foundation validation report contract")
review_contract = load_json(review_contract_path, "foundation review packet contract")
validation_report = load_json(validation_report_path, "foundation validation report")

required_files = review_contract.get("required_packet_files", [])
if not isinstance(required_files, list):
    print("FAIL: review packet contract required files must be a list")
    sys.exit(1)

shutil.rmtree(batch_dir, ignore_errors=True)
batch_dir.mkdir(parents=True, exist_ok=True)

validator_results = validation_report.get("validator_results", [])
if not isinstance(validator_results, list):
    print("FAIL: validation report validator_results must be a list")
    sys.exit(1)

entries = matrix.get("entries", [])
if not isinstance(entries, list):
    print("FAIL: traceability matrix entries must be a list")
    sys.exit(1)

boundaries = {
    "dry_run_only": True,
    "foundation_only": True,
    "runtime_validation": False,
    "production_readiness": False,
    "external_validation": False,
    "host_mutation": False,
    "actual_installation": False,
    "credential_setup": False,
}

identifiers = {
    "profile_contract_id": manifest["profile_contract_id"],
    "foundation_validation_report_contract_id": report_contract["foundation_validation_report_contract_id"],
    "foundation_validation_registry_id": registry["registry_id"],
    "contract_traceability_matrix_id": matrix["contract_traceability_matrix_id"],
    "foundation_review_packet_contract_id": review_contract["foundation_review_packet_contract_id"],
}

validation_summary = {
    "schema": "wucios.disposable_profile.foundation_review_packet.validation_summary.v1",
    "schema_version": review_contract["schema_version"],
    "review_packet_kind": review_contract["review_packet_kind"],
    "identifiers": identifiers,
    "boundaries": boundaries,
    "validation_report": "build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run/foundation-validation-report.json",
    "summary": validation_report["summary"],
    "validators": [
        {
            "sequence": item["sequence"],
            "validator_id": item["validator_id"],
            "command": item["command"],
            "result": item["result"],
        }
        for item in validator_results
    ],
}

traceability_summary = {
    "schema": "wucios.disposable_profile.foundation_review_packet.traceability_summary.v1",
    "schema_version": review_contract["schema_version"],
    "identifiers": identifiers,
    "boundaries": {
        "dry_run_only": True,
        "foundation_only": True,
    },
    "claim_count": len(entries),
    "claims": [
        {
            "claim_id": entry["claim_id"],
            "status": entry["status"],
            "contract_sources": entry["contract_sources"],
            "validator_commands": entry["validator_commands"],
            "evidence_outputs": entry["evidence_outputs"],
        }
        for entry in entries
    ],
}

packet_files = [
    "README.md",
    "claim-boundary.md",
    "validation-summary.json",
    "validation-summary.md",
    "traceability-summary.json",
    "evidence-index.json",
    "reviewer-commands.md",
]

evidence_index = {
    "schema": "wucios.disposable_profile.foundation_review_packet.evidence_index.v1",
    "schema_version": review_contract["schema_version"],
    "identifiers": identifiers,
    "packet_directory": batch_rel,
    "generated_files": [f"{batch_rel}/{name}" for name in packet_files],
    "source_validation_report": "build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run/foundation-validation-report.json",
    "local_only": True,
    "tracked": False,
}

def write_json(name, value):
    with (batch_dir / name).open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")

write_json("validation-summary.json", validation_summary)
write_json("traceability-summary.json", traceability_summary)
write_json("evidence-index.json", evidence_index)

with (batch_dir / "README.md").open("w", encoding="utf-8") as handle:
    handle.write("# WuciOS Disposable Profile Foundation Review Packet\n\n")
    handle.write("This packet summarizes the local scaffold foundation validation chain for reviewer use.\n\n")
    handle.write("- review_packet_kind: foundation_review_packet\n")
    handle.write("- dry_run_only: true\n")
    handle.write("- foundation_only: true\n")
    handle.write("- validation_report: build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run/foundation-validation-report.json\n")
    handle.write("- packet_directory: build/wucios/devlanes/disposable-profile-foundation-batch-9/foundation-review-packet\n\n")
    handle.write("The packet is generated evidence under the ignored build path and is not intended to be committed.\n")

with (batch_dir / "claim-boundary.md").open("w", encoding="utf-8") as handle:
    handle.write("# Claim Boundary\n\n")
    for key, value in boundaries.items():
        handle.write(f"- {key}: {str(value).lower()}\n")
    handle.write("\nNo profile behavior is implemented by this packet.\n")

with (batch_dir / "validation-summary.md").open("w", encoding="utf-8") as handle:
    handle.write("# Validation Summary\n\n")
    summary = validation_report["summary"]
    for key in ("overall_result", "total", "pass", "fail", "skip", "not_run"):
        handle.write(f"- {key}: {summary[key]}\n")
    handle.write("\n## Validators\n\n")
    handle.write("| sequence | validator_id | result |\n")
    handle.write("| --- | --- | --- |\n")
    for item in validator_results:
        handle.write(f"| {item['sequence']} | {item['validator_id']} | {item['result']} |\n")

with (batch_dir / "reviewer-commands.md").open("w", encoding="utf-8") as handle:
    handle.write("# Reviewer Commands\n\n")
    handle.write("```sh\n")
    handle.write("sh devlanes/wucios-general/tools/run-disposable-profile-foundation-validation.sh\n")
    handle.write("sh devlanes/wucios-general/tools/validate-disposable-profile-foundation-validation-report.sh\n")
    handle.write("sh devlanes/wucios-general/tools/run-disposable-profile-foundation-review-packet.sh\n")
    handle.write("sh devlanes/wucios-general/tools/validate-disposable-profile-foundation-review-packet.sh\n")
    handle.write("```\n")

missing = sorted(set(required_files).difference(packet_files))
if missing:
    print("FAIL: generator did not define required packet files: " + ", ".join(missing))
    sys.exit(1)

print(f"PASS: review packet written: {batch_rel}")
for name in packet_files:
    print(f"PASS: packet file: {batch_rel}/{name}")
PY
