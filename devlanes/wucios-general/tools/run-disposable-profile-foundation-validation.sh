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
BATCH_REL="build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run"

if [ "$#" -ne 0 ]; then
	printf '%s\n' 'usage: sh devlanes/wucios-general/tools/run-disposable-profile-foundation-validation.sh' >&2
	exit 2
fi

printf '%s\n' 'Disposable developer profile foundation validation runner'
printf 'Report directory: %s\n' "$BATCH_REL"

python3 - "$REPO_ROOT" "$MANIFEST" "$REGISTRY" "$MATRIX" "$REPORT_CONTRACT" "$BATCH_REL" <<'PY'
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
registry_path = Path(sys.argv[3])
matrix_path = Path(sys.argv[4])
contract_path = Path(sys.argv[5])
batch_rel = sys.argv[6]
batch_dir = repo_root / batch_rel

expected_batch_dir = repo_root / "build/wucios/devlanes/disposable-profile-foundation-batch-8/foundation-validation-run"
if batch_dir != expected_batch_dir:
    print(f"FAIL: refusing unexpected report directory: {batch_rel}")
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
report_contract = load_json(contract_path, "foundation validation report contract")

shutil.rmtree(batch_dir, ignore_errors=True)
batch_dir.mkdir(parents=True, exist_ok=True)

validators = registry.get("validators", [])
if not isinstance(validators, list):
    print("FAIL: registry validators must be a list")
    sys.exit(1)

allowed_results = set(report_contract.get("allowed_result_values", []))
if not {"PASS", "FAIL", "SKIP", "NOT_RUN"}.issubset(allowed_results):
    print("FAIL: report contract allowed result values are incomplete")
    sys.exit(1)

results = []
stop_after_failure = False

for index, entry in enumerate(validators, start=1):
    validator_id = entry.get("validator_id", f"validator_{index}")
    command = entry.get("command", "")
    result = "NOT_RUN"
    exit_code = None

    if not stop_after_failure:
        parts = shlex.split(command)
        if len(parts) < 2 or parts[0] != "sh":
            result = "FAIL"
            exit_code = 2
            stop_after_failure = True
        else:
            env = os.environ.copy()
            env["WUCIOS_SKIP_FOUNDATION_VALIDATION_REPORT"] = "1"
            env["WUCIOS_SKIP_FOUNDATION_REVIEW_PACKET"] = "1"
            completed = subprocess.run(
                parts,
                cwd=repo_root,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            exit_code = completed.returncode
            result = "PASS" if completed.returncode == 0 else "FAIL"
            if completed.returncode != 0:
                stop_after_failure = True

    results.append(
        {
            "sequence": index,
            "validator_id": validator_id,
            "command": command,
            "result": result,
            "exit_code": exit_code,
            "expected_scope": entry.get("expected_scope", ""),
            "generated_evidence_policy": entry.get("generated_evidence_policy", ""),
            "claim_boundary": entry.get("claim_boundary", ""),
        }
    )

summary = {
    "total": len(results),
    "pass": sum(1 for item in results if item["result"] == "PASS"),
    "fail": sum(1 for item in results if item["result"] == "FAIL"),
    "skip": sum(1 for item in results if item["result"] == "SKIP"),
    "not_run": sum(1 for item in results if item["result"] == "NOT_RUN"),
}
summary["overall_result"] = "PASS" if summary["fail"] == 0 and summary["not_run"] == 0 else "FAIL"

report_json_rel = f"{batch_rel}/foundation-validation-report.json"
report_md_rel = f"{batch_rel}/foundation-validation-report.md"

report = {
    "schema": "wucios.disposable_profile.foundation_validation_report.v1",
    "schema_version": report_contract["schema_version"],
    "report_kind": report_contract["report_kind"],
    "identifiers": {
        "profile_contract_id": manifest["profile_contract_id"],
        "foundation_validation_registry_id": registry["registry_id"],
        "contract_traceability_matrix_id": matrix["contract_traceability_matrix_id"],
        "foundation_validation_report_contract_id": report_contract["foundation_validation_report_contract_id"],
    },
    "boundaries": {
        "dry_run_only": True,
        "foundation_only": True,
        "execution_scope": "scaffold_validation_only",
        "runtime_validation": False,
        "production_readiness": False,
        "external_validation": False,
        "host_mutation": False,
    },
    "summary": summary,
    "validator_results": results,
    "generated_evidence": {
        "policy": "local_ignored_build_wucios_devlanes_only",
        "report_directory": batch_rel,
        "report_json": report_json_rel,
        "report_markdown": report_md_rel,
    },
}

json_path = repo_root / report_json_rel
md_path = repo_root / report_md_rel
with json_path.open("w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2)
    handle.write("\n")

with md_path.open("w", encoding="utf-8") as handle:
    handle.write("# WuciOS Disposable Profile Foundation Validation Run\n\n")
    handle.write(f"- report_kind: {report['report_kind']}\n")
    handle.write("- dry_run_only: true\n")
    handle.write("- foundation_only: true\n")
    handle.write("- execution_scope: scaffold_validation_only\n")
    handle.write("- runtime_validation: false\n")
    handle.write("- production_readiness: false\n")
    handle.write("- external_validation: false\n")
    handle.write("- host_mutation: false\n\n")
    handle.write("## Summary\n\n")
    for key in ("overall_result", "total", "pass", "fail", "skip", "not_run"):
        handle.write(f"- {key}: {summary[key]}\n")
    handle.write("\n## Validator Results\n\n")
    handle.write("| sequence | validator_id | result | command |\n")
    handle.write("| --- | --- | --- | --- |\n")
    for item in results:
        handle.write(
            f"| {item['sequence']} | {item['validator_id']} | {item['result']} | `{item['command']}` |\n"
        )

print(f"PASS: report JSON written: {report_json_rel}")
print(f"PASS: report markdown written: {report_md_rel}")
print(f"PASS: overall result: {summary['overall_result']}")
sys.exit(0 if summary["overall_result"] == "PASS" else 1)
PY
