#!/usr/bin/env python3
"""Run WuciOS Euclid Phase 3B readiness diagnostics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from backend_readiness_common import (
    READINESS_VALUES,
    ROOT,
    candidate_input_detection,
    generated_timestamp,
    host_summary,
    load_json,
    normalize_blockers,
    normalize_path,
    report_paths,
    run_allowed_detections,
    test_levels_by_id,
    write_candidate_outputs,
    write_json,
    write_markdown,
)


PHASE_ID = "euclid-trial-phase-3b-readiness"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 3B Readiness — Backend Remediation and Test Authorization Matrix"
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

CONTAINER_BACKENDS = ["docker", "podman", "buildah"]

PHASE_3C_PRECONDITIONS = [
    "clean worktree",
    "explicit future authorization",
    "backend usable",
    "no sudo-by-default policy preserved",
    "output paths under build/wucios",
    "source/image acquisition policy if needed",
    "no substrate selection",
    "no candidate ranking",
    "artifact evidence integrated into Tarski Review Appliance",
]


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
        raise SystemExit(f"unknown Phase 3B candidate(s): {', '.join(unknown)}")
    return candidate_args


def require_false(plan: dict[str, Any], keys: list[str], label: str) -> None:
    for key in keys:
        if plan.get(key) is not False:
            raise SystemExit(f"{label} must set {key} false")


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("phase_id") != PHASE_ID:
        raise SystemExit("Phase 3B readiness plan has wrong phase_id")
    if plan.get("phase_name") != PHASE_NAME:
        raise SystemExit("Phase 3B readiness plan has wrong phase_name")
    if plan.get("cohort") != COHORT:
        raise SystemExit("Phase 3B readiness plan cohort mismatch")
    if plan.get("default_execution_mode") != "SAFE_READINESS_ONLY":
        raise SystemExit("Phase 3B readiness plan must default to SAFE_READINESS_ONLY")
    if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
        raise SystemExit("Phase 3B readiness plan must preserve NO_SUBSTRATE_SELECTED")
    require_false(
        plan,
        [
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
        ],
        "Phase 3B readiness plan",
    )


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("phase_id") != PHASE_ID:
        raise SystemExit("backend remediation policy has wrong phase_id")
    if policy.get("safe_readiness_only") is not True:
        raise SystemExit("backend remediation policy must be safe_readiness_only")
    forbidden = "\n".join(str(item) for item in policy.get("forbidden_actions", []))
    for phrase in [
        "sudo",
        "package installation",
        "source tree cloning",
        "artifact download",
        "docker pull",
        "docker build",
        "docker run",
        "podman pull",
        "podman build",
        "podman run",
        "VM launch",
    ]:
        if phrase not in forbidden:
            raise SystemExit(f"backend remediation policy must forbid {phrase}")


def validate_authorization_matrix(matrix: dict[str, Any]) -> None:
    if matrix.get("phase_id") != PHASE_ID:
        raise SystemExit("test authorization matrix has wrong phase_id")
    if matrix.get("default_authorization") != "NO_EXECUTION_AUTHORIZED":
        raise SystemExit("test authorization matrix must default to NO_EXECUTION_AUTHORIZED")
    levels = test_levels_by_id(matrix)
    if set(levels) != {"L0", "L1", "L2", "L3", "L4"}:
        raise SystemExit("test authorization matrix must define L0 through L4")
    if levels["L0"].get("authorized_by_default") is not True:
        raise SystemExit("test authorization matrix must authorize L0 by default")
    for level_id in ["L1", "L2", "L3", "L4"]:
        if levels[level_id].get("authorized_by_default") is not False:
            raise SystemExit(f"test authorization matrix must not authorize {level_id} by default")
        if levels[level_id].get("requires_future_explicit_authorization") is not True:
            raise SystemExit(f"test authorization matrix must require future explicit authorization for {level_id}")


def backend_summary(backends: dict[str, dict[str, Any]]) -> dict[str, Any]:
    qemu_system = str(backends.get("qemu-system-x86_64", {}).get("status", "BACKEND_ABSENT"))
    qemu_img = str(backends.get("qemu-img", {}).get("status", "BACKEND_ABSENT"))
    qemu = "BACKEND_PRESENT" if qemu_system == "BACKEND_PRESENT" and qemu_img == "BACKEND_PRESENT" else "BACKEND_BLOCKED"
    return {
        "docker": backends.get("docker", {}).get("status", "BACKEND_ABSENT"),
        "podman": backends.get("podman", {}).get("status", "BACKEND_ABSENT"),
        "buildah": backends.get("buildah", {}).get("status", "BACKEND_ABSENT"),
        "qemu": qemu,
        "qemu-system-x86_64": qemu_system,
        "qemu-img": qemu_img,
        "kvm": backends.get("kvm", {}).get("status", "KVM_ABSENT"),
        "nix": backends.get("nix", {}).get("status", "BACKEND_ABSENT"),
        "guix": backends.get("guix", {}).get("status", "BACKEND_ABSENT"),
        "xbps-install": backends.get("xbps-install", {}).get("status", "BACKEND_ABSENT"),
        "xbps-query": backends.get("xbps-query", {}).get("status", "BACKEND_ABSENT"),
        "apk": backends.get("apk", {}).get("status", "BACKEND_ABSENT"),
        "debootstrap": backends.get("debootstrap", {}).get("status", "BACKEND_ABSENT"),
        "fakechroot": backends.get("fakechroot", {}).get("status", "BACKEND_ABSENT"),
        "fakeroot": backends.get("fakeroot", {}).get("status", "BACKEND_ABSENT"),
        "bitbake": backends.get("bitbake", {}).get("status", "BACKEND_ABSENT"),
    }


def authorization_summary(matrix: dict[str, Any]) -> dict[str, Any]:
    levels = test_levels_by_id(matrix)
    return {
        "default_authorization": matrix.get("default_authorization", "NO_EXECUTION_AUTHORIZED"),
        "authorized_by_default": [
            level_id for level_id, level in sorted(levels.items()) if level.get("authorized_by_default") is True
        ],
        "requires_future_explicit_authorization": [
            level_id
            for level_id, level in sorted(levels.items())
            if level.get("requires_future_explicit_authorization") is True
        ],
    }


def expand_allowed_backend(name: str) -> list[str]:
    if name == "qemu":
        return ["qemu-system-x86_64", "qemu-img", "kvm"]
    return [name]


def backend_findings(allowed_backends: list[str], backends: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    names: list[str] = []
    for backend in allowed_backends:
        names.extend(expand_allowed_backend(backend))
    findings: list[dict[str, Any]] = []
    for name in names:
        detection = backends.get(name)
        if not detection:
            findings.append(
                {
                    "backend": name,
                    "status": "BACKEND_ABSENT",
                    "path": "NOT_FOUND",
                    "details": "backend not detected",
                }
            )
            continue
        probe = detection.get("probe", {})
        findings.append(
            {
                "backend": name,
                "status": detection.get("status", "BACKEND_USABILITY_UNKNOWN"),
                "path": detection.get("path", "NOT_FOUND"),
                "details": str(probe.get("output", ""))[:600] or str(probe.get("returncode", "")),
            }
        )
    return findings


def usable_backend_present(names: list[str], backends: dict[str, dict[str, Any]]) -> bool:
    for name in names:
        if name == "qemu":
            if (
                backends.get("qemu-system-x86_64", {}).get("status") == "BACKEND_PRESENT"
                and backends.get("qemu-img", {}).get("status") == "BACKEND_PRESENT"
            ):
                return True
            continue
        if backends.get(name, {}).get("status") == "BACKEND_PRESENT":
            return True
    return False


def split_input_policy_blockers(input_blockers: list[str]) -> tuple[list[str], list[str], list[str]]:
    backend: list[str] = []
    inputs: list[str] = []
    policy: list[str] = []
    for blocker in input_blockers:
        if blocker.startswith("BACKEND_BLOCKED:"):
            backend.append(blocker)
        elif blocker.startswith("POLICY_BLOCKED:"):
            policy.append(blocker)
        else:
            inputs.append(blocker)
    return backend, inputs, policy


def candidate_future_level(candidate: str) -> str:
    return {
        "buildroot": "L2 before buildroom image preparation; L3 before artifact attempt",
        "alpine": "L2 or L3 depending on controlled rootfs strategy",
        "debian-minimal": "L2 or L3 depending on controlled rootfs strategy",
        "void": "L3 before any XBPS rootfs attempt",
        "nixos": "L2/L3 after store policy or isolated buildroom policy",
        "guix": "L2/L3 after store policy or isolated buildroom policy",
        "yocto": "L2 before image preparation; L3 before artifact attempt",
        "openbsd-reference": "L4 before runtime inspection",
    }[candidate]


def candidate_authorization_level_id(candidate: str) -> str:
    return {
        "buildroot": "L2",
        "alpine": "L2",
        "debian-minimal": "L2",
        "void": "L3",
        "nixos": "L2",
        "guix": "L2",
        "yocto": "L2",
        "openbsd-reference": "L4",
    }[candidate]


def recommended_next_action(candidate: str, backend_blockers: list[str], input_blockers: list[str], policy_blockers: list[str]) -> str:
    if candidate == "nixos":
        return "Wait for explicit store policy before NixOS attempt."
    if candidate == "guix":
        return "Wait for explicit store policy before Guix attempt."
    if candidate == "openbsd-reference":
        return "Wait for explicit runtime inspection plan before OpenBSD reference attempt."
    if candidate == "yocto":
        return "Provide local Yocto/Poky source tree and resource review before artifact attempts."
    if candidate == "buildroot" and input_blockers:
        return "Provide local Buildroot source tree or approved source acquisition policy."
    if candidate in {"alpine", "debian-minimal"} and input_blockers:
        return "Define controlled rootfs strategy before artifact attempts."
    if candidate == "void":
        return "Define explicit L3 authorization and output-path policy before any XBPS rootfs attempt."
    if backend_blockers:
        return "Resolve controlled backend access before artifact attempts."
    if policy_blockers:
        return "No execution authorized by this report."
    return "No execution authorized by this report."


def readiness_from_blockers(
    candidate: str,
    backend_blockers: list[str],
    input_blockers: list[str],
    policy_blockers: list[str],
    resource_blockers: list[str],
) -> str:
    if candidate == "openbsd-reference":
        return "REFERENCE_RUNTIME_BLOCKED"
    if backend_blockers:
        return "BACKEND_BLOCKED"
    if input_blockers:
        return "INPUTS_BLOCKED"
    if policy_blockers:
        return "POLICY_BLOCKED"
    if resource_blockers:
        return "RESOURCE_BLOCKED"
    return "READY_FOR_FUTURE_CONTROLLED_ATTEMPT"


def candidate_policy_and_resource_blockers(candidate: str, backends: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
    policy = ["POLICY_BLOCKED: Phase 3B authorizes L0 readiness only; future execution authorization is required"]
    resource: list[str] = []
    if candidate == "void":
        policy.append("POLICY_BLOCKED: direct host XBPS rootfs attempts require explicit L3 authorization and output-path policy")
    elif candidate == "nixos":
        policy.append("POLICY_BLOCKED: host-store writes require explicit host-store or isolated-store policy")
    elif candidate == "guix":
        policy.append("POLICY_BLOCKED: Guix daemon/store use requires explicit host-store or isolated-store policy")
    elif candidate == "yocto":
        resource.append("RESOURCE_REVIEW_REQUIRED: Yocto heavy source/build-system requirements need future resource review")
        policy.append("POLICY_BLOCKED: no Yocto source acquisition or heavy build output policy is authorized")
    elif candidate == "openbsd-reference":
        policy.append("POLICY_BLOCKED: non-Linux reference path requires a future runtime/VM inspection plan")
        if backends.get("kvm", {}).get("status") != "KVM_PRESENT":
            resource.append("RUNTIME_ACCELERATION_ABSENT: /dev/kvm is not available")
    return normalize_blockers(policy), normalize_blockers(resource)


def build_candidate_status(
    candidate: str,
    buildroom: dict[str, Any],
    backends: dict[str, dict[str, Any]],
    buildroom_output_dir: Path,
    matrix: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    allowed_backends = list(buildroom.get("allowed_backends", []))
    findings = backend_findings(allowed_backends, backends)
    backend_blockers: list[str] = []
    if allowed_backends and not usable_backend_present(allowed_backends, backends):
        backend_blockers.append("BACKEND_BLOCKED: no allowed controlled backend is currently usable")
    for finding in findings:
        status = str(finding.get("status", "BACKEND_USABILITY_UNKNOWN"))
        if status in {"BACKEND_PERMISSION_BLOCKED", "BACKEND_CONFIG_BLOCKED"}:
            backend_blockers.append(f"{status}: {finding.get('backend')} {finding.get('details', '')}".strip())

    input_findings = candidate_input_detection(candidate, backends)
    input_backend_blockers, input_blockers, input_policy_blockers = split_input_policy_blockers(
        list(input_findings.get("input_blockers", []))
    )
    backend_blockers.extend(input_backend_blockers)
    policy_blockers, resource_blockers = candidate_policy_and_resource_blockers(candidate, backends)
    policy_blockers.extend(input_policy_blockers)

    if candidate in {"nixos", "guix"}:
        # Missing store-aware tooling and missing store policy both block future attempts.
        backend_blockers = normalize_blockers(backend_blockers)
    elif candidate == "yocto" and input_blockers:
        resource_blockers = normalize_blockers(resource_blockers)

    readiness = readiness_from_blockers(candidate, backend_blockers, input_blockers, policy_blockers, resource_blockers)
    if readiness not in READINESS_VALUES:
        readiness = "POLICY_BLOCKED"

    paths = report_paths(candidate, buildroom_output_dir)
    status = {
        "schema": "wucios.euclid.phase3b_readiness.candidate.v1",
        "id": candidate,
        "display_name": str(buildroom.get("display_name", candidate)),
        "execution_class": str(buildroom.get("execution_class", "UNKNOWN")),
        "readiness": readiness,
        "backend_blockers": normalize_blockers(backend_blockers),
        "input_blockers": normalize_blockers(input_blockers),
        "policy_blockers": normalize_blockers(policy_blockers),
        "resource_blockers": normalize_blockers(resource_blockers),
        "future_authorization_level_required": candidate_future_level(candidate),
        "recommended_next_action": recommended_next_action(candidate, backend_blockers, input_blockers, policy_blockers),
        "report_paths": paths,
    }
    level_id = candidate_authorization_level_id(candidate)
    level = test_levels_by_id(matrix).get(level_id, {})
    return status, findings, input_findings, level


def format_bytes(value: Any) -> str:
    if not isinstance(value, int):
        return str(value)
    gib = value / (1024**3)
    return f"{gib:.1f} GiB"


def markdown_report(payload: dict[str, Any], matrix: dict[str, Any]) -> str:
    host = payload["host_summary"]
    backend = payload["backend_summary"]
    lines = [
        f"# {PHASE_NAME}",
        "",
        f"Global Status: {payload['global_status']}",
        f"Execution Mode: {payload['execution_mode']}",
        f"Substrate Selection: {payload['substrate_selection']}",
        f"WuciOS Score: {payload['score_status']}",
        "Build Attempts: none",
        "Container Pulls: none",
        "Container Builds: none",
        "Container Runs: none",
        "VM Runs: none",
        "Host Mutation: none",
        "",
        "## Purpose",
        "",
        "Phase 3B readiness inspects backend, input, policy, and resource blockers before controlled build-room attempts.",
        "",
        "## Boundary",
        "",
        "This phase does not execute build rooms.",
        "",
        "## Build Room Rule",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        "## X200 Machine Context",
        "",
        f"- Architecture: `{host.get('architecture')}`",
        f"- Kernel: `{host.get('system')} {host.get('release')}`",
        f"- CPU: `{host.get('logical_cpu_count')}` logical CPUs",
        f"- RAM: `{format_bytes(host.get('memory_total_bytes'))}` total, `{format_bytes(host.get('memory_available_bytes'))}` available",
        f"- Disk: `{format_bytes(host.get('disk_available_bytes'))}` available under repository filesystem",
        f"- Backend availability: Docker `{backend['docker']}`, Podman `{backend['podman']}`, Buildah `{backend['buildah']}`, QEMU `{backend['qemu']}`",
        f"- KVM state: `{backend['kvm']}`",
        "",
        "Heavier future tests may be deferred to a stronger controlled machine if resource or backend blockers remain.",
        "",
        "## Backend Findings",
        "",
        f"- Docker: `{backend['docker']}`",
        f"- Podman: `{backend['podman']}`",
        f"- Buildah: `{backend['buildah']}`",
        f"- QEMU: `{backend['qemu']}`",
        f"- KVM: `{backend['kvm']}`",
        f"- Nix: `{backend['nix']}`",
        f"- Guix: `{backend['guix']}`",
        "",
        "## Candidate Readiness Summary",
        "",
        "| Candidate | Execution Class | Readiness | Backend Blockers | Input Blockers | Policy Blockers | Resource Blockers | Future Authorization Level |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in payload["candidates"]:
        lines.append(
            "| {display} | `{execution}` | `{readiness}` | {backend_blockers} | {input_blockers} | {policy_blockers} | {resource_blockers} | {future_level} |".format(
                display=candidate["display_name"],
                execution=candidate["execution_class"],
                readiness=candidate["readiness"],
                backend_blockers="<br>".join(candidate["backend_blockers"]) if candidate["backend_blockers"] else "none detected",
                input_blockers="<br>".join(candidate["input_blockers"]) if candidate["input_blockers"] else "none detected",
                policy_blockers="<br>".join(candidate["policy_blockers"]) if candidate["policy_blockers"] else "none detected",
                resource_blockers="<br>".join(candidate["resource_blockers"]) if candidate["resource_blockers"] else "none detected",
                future_level=candidate["future_authorization_level_required"],
            )
        )
    lines.extend(
        [
            "",
            "## Test Authorization Matrix",
            "",
        ]
    )
    for level in matrix.get("test_levels", []):
        lines.append(
            f"- `{level.get('id')}`: {level.get('name')} (authorized by default: `{str(level.get('authorized_by_default')).lower()}`)"
        )
    lines.extend(
        [
            "",
            "## Phase 3C Preconditions",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in PHASE_3C_PRECONDITIONS)
    lines.extend(
        [
            "",
            "## Non-Selection Statement",
            "",
            "No substrate is selected in Phase 3B readiness. Backend readiness is not substrate ranking.",
            "",
            "## Score Statement",
            "",
            "No numeric WuciOS score is generated in Phase 3B readiness because no current WuciOS artifact and complete artifact-bound evidence exist.",
            "",
            "## Boundary Statement",
            "",
            "No build attempt was made. No container was pulled, built, or run. No VM was launched. No sudo was used. No package installation was attempted. No source tree was cloned. No image was downloaded.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    buildrooms_dir = ROOT / args.buildrooms_dir
    review_dir = ROOT / args.output_dir
    buildroom_output_dir = ROOT / args.buildroom_output_dir

    phase_3a_plan = load_json(buildrooms_dir / "euclid-buildrooms-phase-3a.json")
    if phase_3a_plan.get("phase_id") != "euclid-trial-phase-3a":
        raise SystemExit("Phase 3A buildroom definitions are not present")

    plan = load_json(buildrooms_dir / "euclid-buildrooms-phase-3b-readiness.json")
    policy = load_json(buildrooms_dir / "backend-remediation-policy.json")
    matrix = load_json(buildrooms_dir / "test-authorization-matrix.json")
    validate_plan(plan)
    validate_policy(policy)
    validate_authorization_matrix(matrix)

    candidates = selected_candidates(args.candidate)
    detection = run_allowed_detections(policy)
    backends = detection["backends"]

    candidate_statuses: list[dict[str, Any]] = []
    for candidate in candidates:
        buildroom = load_json(buildrooms_dir / candidate / "buildroom.json")
        if buildroom.get("candidate") != candidate:
            raise SystemExit(f"{candidate} buildroom candidate mismatch")
        status, findings, input_findings, authorization_level = build_candidate_status(
            candidate,
            buildroom,
            backends,
            buildroom_output_dir,
            matrix,
        )
        candidate_dir = buildroom_output_dir / candidate / "phase-3b-readiness"
        write_candidate_outputs(candidate_dir, status, findings, input_findings, authorization_level)
        candidate_statuses.append(status)

    global_status = (
        "PHASE_3B_READINESS_COMPLETE"
        if set(candidates) == set(COHORT) and len(candidate_statuses) == len(COHORT)
        else "PHASE_3B_READINESS_PARTIAL"
    )
    payload = {
        "schema": "wucios.euclid.phase3b_readiness.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": global_status,
        "execution_mode": "SAFE_READINESS_ONLY",
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "ranking_allowed": False,
        "numeric_wucios_score_generated": False,
        "score_status": "NO_ARTIFACT_SCORE",
        "build_attempt_made": False,
        "container_pull_attempted": False,
        "container_build_attempted": False,
        "container_run_attempted": False,
        "vm_run_attempted": False,
        "sudo_used": False,
        "package_installation_attempted": False,
        "source_clone_attempted": False,
        "image_download_attempted": False,
        "artifact_generated": False,
        "artifact_hash_measured": False,
        "candidate_count": len(candidate_statuses),
        "generated_utc": generated_timestamp(),
        "host_summary": host_summary(),
        "backend_summary": backend_summary(backends),
        "backend_detection": detection,
        "authorization_summary": authorization_summary(matrix),
        "candidates": candidate_statuses,
        "phase_3c_preconditions": PHASE_3C_PRECONDITIONS,
        "notes": [
            "Phase 3B readiness inspects blockers only.",
            "No build room execution is authorized by this report.",
            "No substrate is selected.",
            "No candidate is ranked.",
            "No numeric WuciOS score is generated.",
        ],
    }
    write_json(review_dir / "euclid-trial-phase-3b-readiness.json", payload)
    write_markdown(review_dir / "euclid-trial-phase-3b-readiness.md", markdown_report(payload, matrix))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"Euclid Trial Phase 3B Readiness: {global_status}")
    print("- execution: SAFE_READINESS_ONLY")
    print("- selection: NO_SUBSTRATE_SELECTED")
    print(f"- report: {normalize_path(review_dir / 'euclid-trial-phase-3b-readiness.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
