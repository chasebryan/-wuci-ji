#!/usr/bin/env python3
"""Run WuciOS Euclid Phase 3A build-room readiness detection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from buildroom_common import (
    READINESS_VALUES,
    ROOT,
    candidate_report_writing,
    combined_report_writing,
    detect_backends,
    host_summary,
    local_input_detection,
    normalize_status,
    write_json,
)


PHASE_ID = "euclid-trial-phase-3a"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 3A — Controlled Build Room Definitions"
COHORT = [
    "buildroot",
    "alpine",
    "debian-minimal",
    "void",
    "nixos",
    "guix",
    "yocto",
    "openbsd-reference",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", action="append", choices=COHORT)
    parser.add_argument("--json", action="store_true", help="Print combined JSON after writing reports")
    parser.add_argument("--output-dir", default="build/wucios/review")
    parser.add_argument("--buildroom-output-dir", default="build/wucios/buildrooms")
    parser.add_argument("--buildrooms-dir", default="wucios/buildrooms")
    return parser.parse_args()


def selected_candidates(candidate_args: list[str] | None) -> list[str]:
    if not candidate_args:
        return COHORT
    unknown = sorted(set(candidate_args) - set(COHORT))
    if unknown:
        raise SystemExit(f"unknown Phase 3A candidate(s): {', '.join(unknown)}")
    return candidate_args


def backend_summary(backends: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "docker": backends["docker"]["status"],
        "podman": backends["podman"]["status"],
        "buildah": backends["buildah"]["status"],
        "nix": backends["nix"]["status"],
        "guix": backends["guix"]["status"],
        "qemu_system_x86_64": backends["qemu-system-x86_64"]["status"],
        "qemu_img": backends["qemu-img"]["status"],
        "kvm": "KVM_DEVICE_PRESENT" if backends["kvm"]["present"] else "KVM_DEVICE_ABSENT",
    }


def backend_findings(allowed_backends: list[str], backends: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    names: list[str] = []
    for backend in allowed_backends:
        if backend == "qemu":
            names.extend(["qemu-system-x86_64", "qemu-img", "kvm"])
        else:
            names.append(backend)
    findings: list[dict[str, Any]] = []
    for name in names:
        detection = backends.get(name)
        if not detection:
            findings.append({"backend": name, "status": "BUILDROOM_BACKEND_ABSENT", "path": "NOT_FOUND", "details": "backend not in detector"})
            continue
        probe = detection.get("probe", {})
        findings.append(
            {
                "backend": name,
                "status": detection.get("status", "BUILDROOM_BACKEND_USABILITY_UNKNOWN"),
                "path": detection.get("path", "NOT_FOUND"),
                "details": str(probe.get("output", ""))[:400] or str(probe.get("returncode", "")),
            }
        )
    return findings


def attempt_readiness(missing_inputs: list[str], findings: list[dict[str, Any]]) -> str:
    if missing_inputs:
        return "BUILDROOM_INPUTS_MISSING"
    statuses = {str(finding.get("status")) for finding in findings}
    if not statuses or statuses == {"BUILDROOM_BACKEND_ABSENT"}:
        return "BUILDROOM_BACKEND_ABSENT"
    if "BUILDROOM_BACKEND_PERMISSION_BLOCKED" in statuses:
        return "BUILDROOM_BACKEND_PERMISSION_BLOCKED"
    if "BUILDROOM_BACKEND_CONFIG_BLOCKED" in statuses:
        return "BUILDROOM_BACKEND_CONFIG_BLOCKED"
    if "BUILDROOM_BACKEND_PRESENT" in statuses:
        return "BUILDROOM_ATTEMPT_NOT_AUTHORIZED"
    return "BUILDROOM_BACKEND_USABILITY_UNKNOWN"


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("phase_id") != PHASE_ID:
        raise SystemExit("Phase 3A plan has wrong phase_id")
    if plan.get("cohort") != COHORT:
        raise SystemExit("Phase 3A plan cohort mismatch")
    if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
        raise SystemExit("Phase 3A plan must not select a substrate")
    for key in [
        "ranking_allowed",
        "emotional_testing_allowed",
        "build_attempts_allowed_by_default",
        "container_builds_allowed_by_default",
        "container_runs_allowed_by_default",
        "container_pulls_allowed_by_default",
        "vm_runs_allowed_by_default",
        "sudo_allowed",
        "host_package_install_allowed",
        "host_mutation_allowed",
    ]:
        if plan.get(key) is not False:
            raise SystemExit(f"Phase 3A plan must set {key} false")


def markdown_report(payload: dict[str, Any]) -> str:
    backend = payload["backend_summary"]
    lines = [
        f"# {PHASE_NAME}",
        "",
        f"Global Status: {payload['global_status']}",
        f"Execution Mode: {payload['execution_mode']}",
        f"Substrate Selection: {payload['substrate_selection']}",
        f"WuciOS Score: {payload['score_status']}",
        "Build Attempts: none",
        "Container Runs: none",
        "VM Runs: none",
        "",
        "## Purpose",
        "",
        "Phase 3A defines controlled build rooms and detects backend readiness. It does not execute builds.",
        "",
        "## Build Room Rule",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        "## Execution Classes",
        "",
        "- Direct rootfs/image build rooms: Buildroot, Alpine, Debian minimal, Void",
        "- Store-aware build rooms: NixOS, Guix",
        "- Heavy source/build-system room: Yocto",
        "- Reference runtime room: OpenBSD reference",
        "",
        "## Backend Detection",
        "",
        f"- Docker: `{backend['docker']}`",
        f"- Podman: `{backend['podman']}`",
        f"- Buildah: `{backend['buildah']}`",
        f"- Nix: `{backend['nix']}`",
        f"- Guix: `{backend['guix']}`",
        f"- QEMU system: `{backend['qemu_system_x86_64']}`",
        f"- QEMU image: `{backend['qemu_img']}`",
        f"- KVM: `{backend['kvm']}`",
        "",
        "## Candidate Summary",
        "",
        "| Candidate | Execution Class | Definition Status | Attempt Readiness | Backends | Missing Inputs | Blocked Until |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in payload["candidates"]:
        backends = ", ".join(candidate["allowed_backends"])
        missing = "<br>".join(candidate["missing_inputs"]) if candidate["missing_inputs"] else "none detected"
        blocked = "<br>".join(candidate["blocked_until"])
        lines.append(
            f"| {candidate['display_name']} | `{candidate['execution_class']}` | `{candidate['definition_status']}` | "
            f"`{candidate['attempt_readiness']}` | {backends} | {missing} | {blocked} |"
        )
    lines.extend(
        [
            "",
            "## Non-Selection Statement",
            "",
            "No substrate is selected in Phase 3A. Build-room readiness is not substrate ranking.",
            "",
            "## Score Statement",
            "",
            "No numeric WuciOS score is generated in Phase 3A because no current WuciOS artifact and complete artifact-bound evidence exist.",
            "",
            "## Boundary Statement",
            "",
            "No build attempt was made. No container was pulled, built, or run. No VM was launched. No sudo was used. No package installation was attempted.",
        ]
    )
    return "\n".join(lines)


def build_candidate_status(
    candidate_id: str,
    buildroom: dict[str, Any],
    backends: dict[str, dict[str, Any]],
    output_root: Path,
) -> dict[str, Any]:
    findings = backend_findings(list(buildroom.get("allowed_backends", [])), backends)
    inputs = local_input_detection(candidate_id)
    readiness = normalize_status(attempt_readiness(inputs["missing_inputs"], findings), READINESS_VALUES, "BUILDROOM_BACKEND_USABILITY_UNKNOWN")
    candidate_dir = output_root / candidate_id / "phase-3a"
    report_paths = {
        "status_json": str(candidate_dir / "status.json"),
        "status_md": str(candidate_dir / "status.md"),
        "readiness_md": str(candidate_dir / "readiness.md"),
        "backend_detection_json": str(candidate_dir / "backend-detection.json"),
        "input_detection_json": str(candidate_dir / "input-detection.json"),
    }
    status = {
        "schema": "wucios.euclid.phase3a.candidate.v1",
        "id": candidate_id,
        "display_name": str(buildroom.get("display_name", candidate_id)),
        "execution_class": str(buildroom.get("execution_class", "UNKNOWN")),
        "definition_status": str(buildroom.get("definition_status", "BUILDROOM_DEFINITION_PRESENT")),
        "attempt_readiness": readiness,
        "allowed_backends": list(buildroom.get("allowed_backends", [])),
        "backend_findings": findings,
        "missing_inputs": inputs["missing_inputs"],
        "blocked_until": list(buildroom.get("blocked_until", [])),
        "artifact_candidates": list(buildroom.get("artifact_candidates", [])),
        "report_paths": report_paths,
    }
    candidate_report_writing(candidate_dir, status, {"candidate": candidate_id, "backend_findings": findings}, inputs)
    return status


def main() -> int:
    args = parse_args()
    review_dir = ROOT / args.output_dir
    buildroom_output_dir = ROOT / args.buildroom_output_dir
    buildrooms_dir = ROOT / args.buildrooms_dir
    plan = load_json(buildrooms_dir / "euclid-buildrooms-phase-3a.json")
    validate_plan(plan)
    candidates = selected_candidates(args.candidate)
    backends = detect_backends()

    candidate_statuses: list[dict[str, Any]] = []
    for candidate_id in candidates:
        buildroom = load_json(buildrooms_dir / candidate_id / "buildroom.json")
        if buildroom.get("candidate") != candidate_id:
            raise SystemExit(f"{candidate_id} buildroom candidate mismatch")
        candidate_statuses.append(build_candidate_status(candidate_id, buildroom, backends, buildroom_output_dir))

    global_status = "PHASE_3A_DEFINITIONS_COMPLETE" if set(candidates) == set(COHORT) and len(candidate_statuses) == len(COHORT) else "PHASE_3A_DEFINITIONS_PARTIAL"
    payload = {
        "schema": "wucios.euclid.phase3a.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": global_status,
        "execution_mode": "SAFE_DETECT_ONLY",
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "ranking_allowed": False,
        "numeric_wucios_score_generated": False,
        "score_status": "NO_ARTIFACT_SCORE",
        "build_attempt_made": False,
        "container_build_attempted": False,
        "container_run_attempted": False,
        "container_pull_attempted": False,
        "vm_run_attempted": False,
        "sudo_used": False,
        "package_installation_attempted": False,
        "candidate_count": len(candidate_statuses),
        "backend_summary": backend_summary(backends),
        "backend_detection": backends,
        "host": host_summary(),
        "candidates": candidate_statuses,
        "notes": [
            "Phase 3A defines build rooms and detects readiness only.",
            "Phase 3A does not execute build rooms.",
            "No substrate is selected.",
            "No candidate is ranked.",
            "No numeric WuciOS score is generated.",
        ],
    }
    combined_report_writing(
        review_dir / "euclid-trial-phase-3a.json",
        review_dir / "euclid-trial-phase-3a.md",
        payload,
        markdown_report(payload),
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"Euclid Trial Phase 3A: {global_status}")
    print("- execution: SAFE_DETECT_ONLY")
    print("- selection: NO_SUBSTRATE_SELECTED")
    print(f"- report: {(review_dir / 'euclid-trial-phase-3a.md').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
