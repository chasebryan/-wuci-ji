#!/usr/bin/env python3
"""Run WuciOS v2.4 Euclid Trial Phase 2 build feasibility probes."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PHASE_ID = "euclid-trial-phase-2"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 2 — Build Feasibility Probes"
COHORT = {
    "buildroot": "Buildroot",
    "alpine": "Alpine Linux",
    "debian-minimal": "Debian Minimal",
}
REQUIRED_CANDIDATE_FILES = [
    "build-probe.sh",
    "phase-2-plan.json",
    "README.md",
]
REQUIRED_EVIDENCE_FILES = [
    "status.json",
    "status.txt",
    "tool-detection.json",
    "build-log.txt",
    "build-notes.md",
    "artifact-manifest.json",
    "package-manifest.txt",
    "image-size.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "dependency-tree.txt",
    "build-manifest.sha256",
    "substrate-report.json",
    "substrate-report.md",
    "failure-report.md",
    "noether-static-check.json",
    "noether-static-check.md",
    "missing-measurements.txt",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_tracked_files(trials_dir: Path, candidates: list[str]) -> None:
    phase_plan = trials_dir / "euclid-substrate-trial-phase-2.json"
    schema = ROOT / "wucios/schemas/euclid-trial-phase-2.schema.json"
    if not phase_plan.is_file():
        raise FileNotFoundError(phase_plan.relative_to(ROOT))
    if not schema.is_file():
        raise FileNotFoundError(schema.relative_to(ROOT))
    for candidate in candidates:
        directory = trials_dir / candidate
        for filename in REQUIRED_CANDIDATE_FILES:
            path = directory / filename
            if not path.is_file():
                raise FileNotFoundError(path.relative_to(ROOT))


def selected_candidates(candidate_args: list[str] | None) -> list[str]:
    if not candidate_args:
        return list(COHORT)
    unknown = sorted(set(candidate_args) - set(COHORT))
    if unknown:
        raise SystemExit(f"unknown Phase 2 candidate(s): {', '.join(unknown)}")
    return candidate_args


def normalize_missing_candidate(candidate: str, output_dir: Path, reason: str) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "present": False,
        "path": "NOT_MEASURED",
        "sha256": "NOT_MEASURED",
        "size_bytes": "NOT_MEASURED",
    }
    measurements = {
        "package_manifest": "NOT_MEASURED_NO_ARTIFACT",
        "image_size": "NOT_MEASURED_NO_ARTIFACT",
        "enabled_services": "NOT_MEASURED_NO_ARTIFACT",
        "listening_ports": "NOT_MEASURED_RUNTIME_REQUIRED",
        "suid_sgid": "NOT_MEASURED_NO_ARTIFACT",
        "kernel_modules": "NOT_MEASURED_RUNTIME_REQUIRED",
        "dependency_tree": "NOT_MEASURED_NO_ARTIFACT",
    }
    missing = sorted([*measurements, "artifact.sha256"])
    payload = {
        "schema": "wucios.euclid.phase2.candidate.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "id": candidate,
        "display_name": COHORT[candidate],
        "phase_status": "TRIAL_BLOCKED",
        "build_attempted": False,
        "execution_mode": "SAFE_DETECT_ONLY",
        "network_allowed": False,
        "sudo_used": False,
        "artifact": artifact,
        "tooling": [],
        "blockers": ["TRIAL_BLOCKED"],
        "measurements": measurements,
        "noether_core_static_check": {
            "status": "NOETHER_STATIC_CHECK_INCOMPLETE",
            "violations": [],
            "notes": [reason],
        },
        "missing_measurements": missing,
        "report_paths": {
            "candidate_report_md": str(output_dir / "substrate-report.md"),
            "candidate_report_json": str(output_dir / "substrate-report.json"),
        },
    }
    write_json(output_dir / "status.json", payload)
    write_json(output_dir / "substrate-report.json", payload)
    write_text(output_dir / "status.txt", "TRIAL_BLOCKED\n")
    write_text(output_dir / "build-log.txt", f"TRIAL_BLOCKED: {reason}\n")
    write_text(output_dir / "missing-measurements.txt", "\n".join(missing) + "\n")
    write_text(output_dir / "substrate-report.md", f"# {COHORT[candidate]} Phase 2 Report\n\nTRIAL_BLOCKED: {reason}\n")
    write_text(output_dir / "failure-report.md", f"# {COHORT[candidate]} Failure Report\n\nTRIAL_BLOCKED: {reason}\n")
    for filename in REQUIRED_EVIDENCE_FILES:
        path = output_dir / filename
        if not path.exists():
            write_text(path, f"NOT_MEASURED: {reason}\n")
    return payload


def run_candidate(
    candidate: str,
    trials_dir: Path,
    build_dir: Path,
    attempt_builds: bool,
    allow_network: bool,
) -> dict[str, Any]:
    script = trials_dir / candidate / "build-probe.sh"
    candidate_dir = build_dir / candidate / "phase-2"
    work_dir = candidate_dir / "work"
    command = [
        "bash",
        str(script),
        "--output-dir",
        str(candidate_dir),
        "--work-dir",
        str(work_dir),
    ]
    if attempt_builds:
        command.append("--attempt")
    else:
        command.append("--detect-only")
    if allow_network:
        command.append("--allow-network")
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    status_path = candidate_dir / "status.json"
    if result.stdout:
        candidate_dir.mkdir(parents=True, exist_ok=True)
        with (candidate_dir / "build-log.txt").open("a", encoding="utf-8") as log:
            log.write("\n# Runner output\n")
            log.write(result.stdout)
    if not status_path.is_file():
        if result.returncode != 0:
            return normalize_missing_candidate(candidate, candidate_dir, f"candidate probe exited {result.returncode} before status.json was written")
        return normalize_missing_candidate(candidate, candidate_dir, "candidate probe did not write status.json")
    data = load_json(status_path)
    if result.returncode != 0:
        data.setdefault("blockers", []).append("TRIAL_BLOCKED")
        data["phase_status"] = "TRIAL_BLOCKED"
        write_json(status_path, data)
    return data


def score_status(review_dir: Path) -> str:
    score_path = review_dir / "daylight-wucios-score.json"
    if not score_path.is_file():
        return "NO_ARTIFACT_SCORE"
    try:
        data = load_json(score_path)
    except Exception:  # noqa: BLE001 - report must degrade explicitly.
        return "NO_ARTIFACT_SCORE"
    if data.get("score_valid") is True and data.get("artifact", {}).get("sha256") not in {None, "NOT_MEASURED"}:
        return str(data.get("score_status", "ARTIFACT_BOUND_SCORE"))
    return "NO_ARTIFACT_SCORE"


def global_status(candidates: list[dict[str, Any]]) -> str:
    if not candidates:
        return "TRIAL_BLOCKED"
    comparable = all(
        candidate.get("artifact", {}).get("present") is True
        and not candidate.get("missing_measurements")
        for candidate in candidates
    )
    return "TRIAL_DATA_COMPARABLE" if comparable else "TRIAL_DATA_PARTIAL"


def combined_missing(candidates: list[dict[str, Any]]) -> list[str]:
    missing: list[str] = []
    for candidate in candidates:
        candidate_id = str(candidate.get("id", candidate.get("candidate", "unknown")))
        for item in candidate.get("missing_measurements", []):
            missing.append(f"{candidate_id}:{item}")
    return sorted(set(missing))


def write_combined_reports(
    review_dir: Path,
    candidates: list[dict[str, Any]],
    execution_mode: str,
    network_allowed: bool,
) -> dict[str, Any]:
    review_dir.mkdir(parents=True, exist_ok=True)
    status = global_status(candidates)
    score = score_status(review_dir)
    payload = {
        "schema": "wucios.euclid.phase2.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": status,
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "numeric_wucios_score_generated": score != "NO_ARTIFACT_SCORE",
        "score_status": score,
        "execution_mode": execution_mode,
        "network_allowed": network_allowed,
        "root_required_by_runner": False,
        "sudo_used": False,
        "candidates": candidates,
        "missing_measurements": combined_missing(candidates),
        "notes": [
            "Phase 2 probes build feasibility only.",
            "No substrate is selected.",
            "No candidate is ranked.",
        ],
    }
    write_json(review_dir / "euclid-trial-phase-2.json", payload)
    write_text(review_dir / "euclid-trial-phase-2.md", markdown_report(payload))
    return payload


def markdown_report(payload: dict[str, Any]) -> str:
    lines = [
        "# WuciOS v2.4 Euclid Trial Phase 2 — Build Feasibility Probes",
        "",
        f"Global Status: {payload['global_status']}",
        f"Substrate Selection: {payload['substrate_selection']}",
        f"WuciOS Score: {payload['score_status']}",
        f"Execution Mode: {payload['execution_mode']}",
        "",
        "## Purpose",
        "",
        "Phase 2 probes build feasibility only. It does not select, rank, or score substrates.",
        "",
        "## Candidate Summary",
        "",
        "| Candidate | Build Status | Build Attempted | Artifact | Artifact SHA-256 | Image Size | Primary Blockers | Missing Measurements |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in payload["candidates"]:
        artifact = candidate["artifact"]
        measurements = candidate["measurements"]
        lines.append(
            "| {name} | {status} | {attempted} | {artifact_present} | {sha256} | {image_size} | {blockers} | {missing} |".format(
                name=candidate["display_name"],
                status=candidate["phase_status"],
                attempted=str(candidate["build_attempted"]).lower(),
                artifact_present=str(artifact["present"]).lower(),
                sha256=artifact["sha256"],
                image_size=measurements.get("image_size", "NOT_MEASURED"),
                blockers="<br>".join(candidate.get("blockers", [])) or "NONE_DETECTED",
                missing="<br>".join(candidate.get("missing_measurements", [])) or "NONE",
            )
        )
    by_id = {candidate["id"]: candidate for candidate in payload["candidates"]}
    for candidate_id, heading in [("buildroot", "Buildroot"), ("alpine", "Alpine"), ("debian-minimal", "Debian Minimal")]:
        lines.extend(["", f"## {heading}", ""])
        candidate = by_id.get(candidate_id)
        if candidate:
            lines.append(f"Candidate report: `{candidate['report_paths']['candidate_report_md']}`")
            lines.append(f"Status: `{candidate['phase_status']}`")
        else:
            lines.append("Candidate was not run in this invocation.")
    lines.extend(
        [
            "",
            "## Noether Core Static Check",
            "",
            "Static checks are incomplete without artifacts and do not replace runtime validation.",
            "",
            "## Non-Selection Statement",
            "",
            "No substrate is selected in Phase 2. Buildroot, Alpine, and Debian minimal remain candidates until comparable measured evidence exists.",
            "",
            "## Score Statement",
            "",
            "No numeric WuciOS score is generated in Phase 2 unless a current artifact and all required score evidence exist.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", action="append", choices=sorted(COHORT))
    parser.add_argument("--attempt-builds", action="store_true")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--output-dir", default="build/wucios/review")
    parser.add_argument("--build-dir", default="build/wucios/trials")
    parser.add_argument("--trials-dir", default="wucios/trials")
    parser.add_argument("--json", action="store_true", help="print combined report JSON after writing files")
    args = parser.parse_args()

    candidates = selected_candidates(args.candidate)
    trials_dir = (ROOT / args.trials_dir).resolve() if not Path(args.trials_dir).is_absolute() else Path(args.trials_dir)
    build_dir = (ROOT / args.build_dir).resolve() if not Path(args.build_dir).is_absolute() else Path(args.build_dir)
    review_dir = (ROOT / args.output_dir).resolve() if not Path(args.output_dir).is_absolute() else Path(args.output_dir)

    try:
        validate_tracked_files(trials_dir, candidates)
        execution_mode = "EXPLICIT_BUILD_ATTEMPT" if args.attempt_builds else "SAFE_DETECT_ONLY"
        results = [
            run_candidate(candidate, trials_dir, build_dir, args.attempt_builds, args.allow_network)
            for candidate in candidates
        ]
        payload = write_combined_reports(review_dir, results, execution_mode, bool(args.allow_network))
    except Exception as exc:  # noqa: BLE001 - runner should fail clearly on structural errors.
        print(f"Euclid Trial Phase 2: TRIAL_BLOCKED: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Euclid Trial Phase 2: {payload['global_status']}")
        print(f"- selection: {payload['substrate_selection']}")
        print(f"- execution: {payload['execution_mode']}")
        print(f"- report: {(review_dir / 'euclid-trial-phase-2.md').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
