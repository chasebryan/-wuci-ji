#!/usr/bin/env python3
"""Generate WuciOS v2.4 Euclid Trial Phase 1 evidence scaffolding."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trial_collectors.common import (
    CANDIDATE_BUILD_STATUS_VALUES,
    FIRST_COHORT,
    MEASUREMENT_FILES,
    NOETHER_REQUIREMENTS,
    REQUIRED_TRIAL_FILES,
    TRIAL_STATUS_VALUES,
    measured_line_count,
    measurement_status,
    sha256_file,
    text_is_missing,
)


ROOT = Path(__file__).resolve().parents[2]
TRIAL_ROOT = ROOT / "wucios/trials"
REVIEW_DIR = ROOT / "build/wucios/review"

OUTPUT_JSON = REVIEW_DIR / "euclid-trial-phase-1.json"
OUTPUT_MD = REVIEW_DIR / "euclid-trial-phase-1.md"

PLACEHOLDER_REASONS = {
    "package-manifest.txt": "No candidate artifact has been built or scanned.",
    "package-count.txt": "No package manifest has been measured.",
    "image-size.txt": "No candidate image artifact exists.",
    "enabled-services.txt": "No candidate image has been booted or inventoried.",
    "listening-ports.txt": "No candidate image has been booted or inventoried.",
    "suid-sgid.txt": "No candidate filesystem has been scanned.",
    "kernel-modules.txt": "No candidate kernel module inventory exists.",
    "dependency-tree.txt": "No candidate package closure has been generated.",
    "build-manifest.sha256": "No build manifest exists because no build was attempted.",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_text_if_missing(path: Path, text: str) -> None:
    if not path.exists():
        path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def placeholder_text(filename: str) -> str:
    return f"NOT_MEASURED\nreason: {PLACEHOLDER_REASONS[filename]}\n"


def candidate_dir(candidate_id: str) -> Path:
    return TRIAL_ROOT / candidate_id


def default_trial_plan(candidate_id: str) -> dict[str, Any]:
    meta = FIRST_COHORT[candidate_id]
    return {
        "schema": "wucios.euclid_candidate_trial.v1",
        "id": f"euclid-phase-1-{candidate_id}",
        "candidate": candidate_id,
        "display_name": meta["display_name"],
        "substrate_class": meta["substrate_class"],
        "phase": "WuciOS v2.4 Euclid Trial Phase 1",
        "selection_status": "NO_SUBSTRATE_SELECTED",
        "trial_status": "BUILD_NOT_ATTEMPTED",
        "allowed_candidate_status_values": CANDIDATE_BUILD_STATUS_VALUES,
        "required_outputs": REQUIRED_TRIAL_FILES,
        "noether_core_requirements": NOETHER_REQUIREMENTS,
        "non_claims": [
            "This candidate is not selected.",
            "No ranking is assigned by Phase 1.",
            "Missing measurements remain NOT_MEASURED.",
        ],
    }


def default_artifact_manifest(candidate_id: str) -> dict[str, Any]:
    return {
        "schema": "wucios.euclid_artifact_manifest.v1",
        "candidate": candidate_id,
        "build_status": "BUILD_NOT_ATTEMPTED",
        "artifact": {
            "path": "NOT_MEASURED",
            "sha256": "NOT_MEASURED",
            "size_bytes": "NOT_MEASURED",
        },
        "build": {
            "command": "NOT_MEASURED",
            "started_utc": "NOT_MEASURED",
            "completed_utc": "NOT_MEASURED",
            "tooling_status": "MISSING_TOOLING",
            "tooling_notes": [
                "No candidate-specific build recipe is implemented in this pass."
            ],
        },
        "non_claims": [
            "No artifact exists for this candidate until a build creates one.",
            "No artifact hash exists for this candidate until a build creates one.",
        ],
    }


def ensure_candidate_files(candidate_id: str) -> None:
    directory = candidate_dir(candidate_id)
    directory.mkdir(parents=True, exist_ok=True)

    plan_path = directory / "trial-plan.json"
    if not plan_path.exists():
        write_json(plan_path, default_trial_plan(candidate_id))
    else:
        plan = load_json(plan_path) or default_trial_plan(candidate_id)
        plan["allowed_candidate_status_values"] = CANDIDATE_BUILD_STATUS_VALUES
        plan["required_outputs"] = REQUIRED_TRIAL_FILES
        plan["noether_core_requirements"] = NOETHER_REQUIREMENTS
        plan.setdefault("selection_status", "NO_SUBSTRATE_SELECTED")
        write_json(plan_path, plan)

    manifest_path = directory / "artifact-manifest.json"
    if not manifest_path.exists():
        write_json(manifest_path, default_artifact_manifest(candidate_id))

    write_text_if_missing(
        directory / "build-notes.md",
        "\n".join(
            [
                f"# {FIRST_COHORT[candidate_id]['display_name']} Trial Build Notes",
                "",
                "Status: `BUILD_NOT_ATTEMPTED`",
                "",
                "No build was attempted in Euclid Trial Phase 1. This pass",
                "standardizes the evidence protocol before substrate builds.",
                "",
            ]
        ),
    )
    write_text_if_missing(
        directory / "failure-report.md",
        "\n".join(
            [
                f"# {FIRST_COHORT[candidate_id]['display_name']} Failure Report",
                "",
                "Status: `BUILD_NOT_ATTEMPTED`",
                "",
                "Failure is not inferred. No candidate build has been attempted.",
                "Missing measurements are recorded as `NOT_MEASURED`.",
                "",
            ]
        ),
    )

    for filename in MEASUREMENT_FILES:
        write_text_if_missing(directory / filename, placeholder_text(filename))


def update_artifact_hash(candidate_id: str) -> dict[str, Any]:
    path = candidate_dir(candidate_id) / "artifact-manifest.json"
    manifest = load_json(path) or default_artifact_manifest(candidate_id)
    artifact = manifest.setdefault("artifact", {})
    artifact_path = artifact.get("path", "NOT_MEASURED")
    if isinstance(artifact_path, str) and artifact_path not in {"", "NOT_MEASURED"}:
        resolved = (ROOT / artifact_path).resolve() if not Path(artifact_path).is_absolute() else Path(artifact_path)
        if resolved.is_file():
            artifact["sha256"] = sha256_file(resolved)
            artifact["size_bytes"] = resolved.stat().st_size
            if manifest.get("build_status") == "BUILD_NOT_ATTEMPTED":
                manifest["build_status"] = "NOT_MEASURED"
            write_json(path, manifest)
    return manifest


def read_first_line(path: Path) -> str:
    if not path.is_file():
        return "NOT_MEASURED"
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return "NOT_MEASURED"
    if text_is_missing(text):
        return "NOT_MEASURED"
    return text.splitlines()[0].strip()


def noether_violations(directory: Path) -> list[str]:
    measured_any = any(measurement_status(directory / name) == "PRESENT" for name in MEASUREMENT_FILES)
    if not measured_any:
        return ["NOT_MEASURED"]

    violations: list[str] = []
    package_manifest = (directory / "package-manifest.txt").read_text(encoding="utf-8", errors="replace").lower()
    for denied in ["xfce", "firefox", "chromium", "browser", "libreoffice", "vlc", "xorg", "wayland"]:
        if denied in package_manifest:
            violations.append(f"denied package or class present: {denied}")

    services = (directory / "enabled-services.txt").read_text(encoding="utf-8", errors="replace").lower()
    for denied_service in ["sshd", "ssh", "httpd", "nginx", "apache", "avahi", "cups"]:
        if denied_service in services:
            violations.append(f"denied default service present: {denied_service}")

    ports = (directory / "listening-ports.txt").read_text(encoding="utf-8", errors="replace").lower()
    if "listen" in ports or "listening" in ports:
        violations.append("listening ports present")

    return violations or ["NONE_DETECTED"]


def summarize_candidate(candidate_id: str) -> dict[str, Any]:
    directory = candidate_dir(candidate_id)
    artifact_manifest = update_artifact_hash(candidate_id)
    artifact = artifact_manifest.get("artifact", {})
    missing = [
        name
        for name in MEASUREMENT_FILES
        if measurement_status(directory / name) != "PRESENT"
    ]
    if artifact.get("sha256", "NOT_MEASURED") == "NOT_MEASURED":
        missing.append("artifact.sha256")

    package_count = read_first_line(directory / "package-count.txt")
    if package_count == "NOT_MEASURED":
        package_count = measured_line_count(directory / "package-manifest.txt")

    summary = {
        "candidate": candidate_id,
        "display_name": FIRST_COHORT[candidate_id]["display_name"],
        "trial_status": artifact_manifest.get("build_status", "BUILD_NOT_ATTEMPTED"),
        "artifact_path": artifact.get("path", "NOT_MEASURED"),
        "artifact_hash": artifact.get("sha256", "NOT_MEASURED"),
        "image_size": read_first_line(directory / "image-size.txt"),
        "package_count": package_count,
        "default_services": measurement_status(directory / "enabled-services.txt"),
        "listening_ports": measurement_status(directory / "listening-ports.txt"),
        "suid_sgid_count": measured_line_count(directory / "suid-sgid.txt"),
        "kernel_module_count": measured_line_count(directory / "kernel-modules.txt"),
        "dependency_tree_status": measurement_status(directory / "dependency-tree.txt"),
        "noether_core_violations": noether_violations(directory),
        "missing_measurements": sorted(set(missing)),
    }
    write_candidate_report(candidate_id, summary)
    return summary


def write_candidate_report(candidate_id: str, summary: dict[str, Any]) -> None:
    directory = candidate_dir(candidate_id)
    payload = {
        "schema": "wucios.euclid_substrate_report.v1",
        "generated_utc": utc_now(),
        "selection_status": "NO_SUBSTRATE_SELECTED",
        **summary,
        "non_claims": [
            "This report does not rank or select a substrate.",
            "NOT_MEASURED values are missing measurements, not estimates.",
        ],
    }
    write_json(directory / "substrate-report.json", payload)

    lines = [
        f"# {summary['display_name']} Euclid Phase 1 Report",
        "",
        f"Trial status: `{summary['trial_status']}`",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Artifact path | `{summary['artifact_path']}` |",
        f"| Artifact hash | `{summary['artifact_hash']}` |",
        f"| Image size | `{summary['image_size']}` |",
        f"| Package count | `{summary['package_count']}` |",
        f"| Default services | `{summary['default_services']}` |",
        f"| Listening ports | `{summary['listening_ports']}` |",
        f"| SUID/SGID count | `{summary['suid_sgid_count']}` |",
        f"| Kernel module count | `{summary['kernel_module_count']}` |",
        f"| Dependency tree status | `{summary['dependency_tree_status']}` |",
        "",
        "## Noether Core Violations",
        "",
    ]
    lines.extend(f"- `{item}`" for item in summary["noether_core_violations"])
    lines.extend(["", "## Missing Measurements", ""])
    lines.extend(f"- `{item}`" for item in summary["missing_measurements"])
    lines.append("")
    (directory / "substrate-report.md").write_text("\n".join(lines), encoding="utf-8")


def combined_status(candidates: list[dict[str, Any]]) -> str:
    if not candidates:
        return "TRIAL_BLOCKED"
    comparable = all(
        not candidate["missing_measurements"]
        and candidate["artifact_hash"] != "NOT_MEASURED"
        for candidate in candidates
    )
    return "TRIAL_DATA_COMPARABLE" if comparable else "TRIAL_DATA_PARTIAL"


def write_combined_report(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    status = combined_status(candidates)
    payload = {
        "schema": "wucios.euclid_trial_phase_1.v1",
        "generated_utc": utc_now(),
        "phase": "WuciOS v2.4 Euclid Trial Phase 1 - First Artifact Cohort",
        "selection_status": "NO_SUBSTRATE_SELECTED",
        "trial_status": status,
        "valid_trial_outcomes": TRIAL_STATUS_VALUES,
        "first_trial_cohort": list(FIRST_COHORT),
        "candidates": candidates,
        "non_claims": [
            "No substrate is selected by Phase 1.",
            "No candidate is ranked without comparable generated evidence.",
            "No numeric WuciOS score is generated by this trial.",
        ],
    }
    write_json(OUTPUT_JSON, payload)

    lines = [
        "# WuciOS v2.4 Euclid Trial Phase 1",
        "",
        f"Selection status: `{payload['selection_status']}`",
        f"Trial status: `{payload['trial_status']}`",
        "",
        "No substrate is ranked or selected by this report.",
        "",
        "| Candidate | Trial Status | Artifact Path | Artifact Hash | Image Size | Package Count | Default Services | Listening Ports | SUID/SGID Count | Kernel Module Count | Dependency Tree | Noether Core Violations | Missing Measurements |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in candidates:
        lines.append(
            "| {candidate} | {trial_status} | {artifact_path} | {artifact_hash} | {image_size} | {package_count} | {default_services} | {listening_ports} | {suid_sgid_count} | {kernel_module_count} | {dependency_tree_status} | {violations} | {missing} |".format(
                violations="<br>".join(candidate["noether_core_violations"]),
                missing="<br>".join(candidate["missing_measurements"]) or "NONE",
                **candidate,
            )
        )
    lines.extend(["", "## Non-Claims", ""])
    lines.extend(f"- {item}" for item in payload["non_claims"])
    lines.append("")
    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")
    return payload


def selected_candidates(candidate_args: list[str]) -> list[str]:
    if not candidate_args or "all" in candidate_args:
        return list(FIRST_COHORT)
    unknown = sorted(set(candidate_args) - set(FIRST_COHORT))
    if unknown:
        raise SystemExit(f"unknown Phase 1 candidate(s): {', '.join(unknown)}")
    return candidate_args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate",
        action="append",
        choices=[*FIRST_COHORT.keys(), "all"],
        help="candidate to prepare; defaults to all Phase 1 candidates",
    )
    args = parser.parse_args()

    candidate_ids = selected_candidates(args.candidate or ["all"])
    for candidate_id in candidate_ids:
        ensure_candidate_files(candidate_id)
    summaries = [summarize_candidate(candidate_id) for candidate_id in list(FIRST_COHORT)]
    payload = write_combined_report(summaries)

    print(f"Euclid Trial Phase 1: {payload['trial_status']}")
    print(f"- selection: {payload['selection_status']}")
    print(f"- report: {OUTPUT_MD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
