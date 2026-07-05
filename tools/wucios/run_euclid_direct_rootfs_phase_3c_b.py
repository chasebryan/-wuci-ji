#!/usr/bin/env python3
"""Run WuciOS Euclid Phase 3C-B direct-rootfs preparation policy checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from direct_rootfs_prep_common import (
    CANDIDATES,
    DISPLAY_NAMES,
    ROOT,
    detect_candidate_inputs,
    detect_candidate_tools,
    ensure_directory,
    generate_scaffold,
    generated_timestamp,
    load_json,
    normalize_candidate_status,
    normalize_path,
    safe_backend_info_capture,
    validate_command_shapes,
    write_json,
    write_markdown,
)


PHASE_ID = "euclid-trial-phase-3c-b"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 3C-B — Direct Rootfs Buildroom Preparation"
AUTH_ENV = "WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print combined JSON after writing reports")
    parser.add_argument("--l2-scaffold", action="store_true", help="Request authorized L2 non-artifact scaffolding")
    parser.add_argument("--candidate", action="append", choices=CANDIDATES)
    parser.add_argument("--output-dir", default="build/wucios/review")
    parser.add_argument("--buildroom-output-dir", default="build/wucios/buildrooms/direct-rootfs/phase-3c-b")
    parser.add_argument("--buildrooms-dir", default="wucios/buildrooms/direct-rootfs")
    parser.add_argument("--guardrails", action="store_true", help="Run Phase 3C-B negative guardrail checks")
    return parser.parse_args()


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("phase_id") != PHASE_ID:
        raise SystemExit("Phase 3C-B plan has wrong phase_id")
    if plan.get("phase_name") != PHASE_NAME:
        raise SystemExit("Phase 3C-B plan has wrong phase_name")
    if plan.get("default_execution_mode") != "L1_POLICY_AND_PREPARATION_RULES":
        raise SystemExit("Phase 3C-B plan must default to L1 policy and preparation rules")
    if plan.get("l2_scaffold_authorized_by_default") is not False:
        raise SystemExit("Phase 3C-B plan must disable L2 scaffold by default")
    if plan.get("l3_substrate_artifact_attempts_allowed") is not False:
        raise SystemExit("Phase 3C-B plan must forbid L3 artifact attempts")
    if plan.get("runtime_inspection_allowed") is not False:
        raise SystemExit("Phase 3C-B plan must forbid runtime inspection")
    if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
        raise SystemExit("Phase 3C-B plan must preserve NO_SUBSTRATE_SELECTED")
    for key in [
        "ranking_allowed",
        "emotional_testing_allowed",
        "numeric_score_allowed",
        "image_pulls_allowed",
        "container_runs_allowed",
        "vm_runs_allowed",
        "sudo_allowed",
        "host_package_install_allowed",
        "source_clone_allowed",
        "os_image_download_allowed",
    ]:
        if plan.get(key) is not False:
            raise SystemExit(f"Phase 3C-B plan must set {key} false")
    if list(plan.get("in_scope_candidates", [])) != CANDIDATES:
        raise SystemExit("Phase 3C-B plan has wrong in-scope candidate set")


def validate_policies(buildrooms_dir: Path) -> dict[str, Any]:
    plan = load_json(buildrooms_dir / "euclid-direct-rootfs-phase-3c-b.json")
    validate_plan(plan)
    direct_policy = load_json(buildrooms_dir / "direct-rootfs-policy.json")
    command_shapes = load_json(buildrooms_dir / "command-shapes.json")
    pull_policy = load_json(buildrooms_dir / "pull-pinning-cache-output-policy.json")
    evidence = load_json(buildrooms_dir / "evidence-requirements.json")
    guardrail_policy = load_json(buildrooms_dir / "guardrail-policy.json")
    command_shape_failures = validate_command_shapes(command_shapes)
    if command_shape_failures:
        raise SystemExit("; ".join(command_shape_failures))

    candidate_policies: dict[str, dict[str, Any]] = {}
    for candidate in CANDIDATES:
        policy = load_json(buildrooms_dir / candidate / "preparation-policy.json")
        if policy.get("phase_id") != PHASE_ID:
            raise SystemExit(f"{candidate} preparation policy has wrong phase_id")
        if policy.get("candidate") != candidate:
            raise SystemExit(f"{candidate} preparation policy has wrong candidate")
        if policy.get("l3_artifact_attempt_allowed") is not False:
            raise SystemExit(f"{candidate} preparation policy must forbid L3 artifact attempts")
        if policy.get("rootfs_generation_allowed") is not False:
            raise SystemExit(f"{candidate} preparation policy must forbid rootfs generation")
        candidate_policies[candidate] = policy

    return {
        "plan": plan,
        "direct_policy": direct_policy,
        "command_shapes": command_shapes,
        "pull_policy": pull_policy,
        "evidence": evidence,
        "guardrail_policy": guardrail_policy,
        "candidate_policies": candidate_policies,
    }


def candidate_report(candidate: str, policy: dict[str, Any], scaffold_paths: list[str]) -> dict[str, Any]:
    tool_detection = detect_candidate_tools(candidate)
    input_detection = detect_candidate_inputs(candidate, policy)
    status = normalize_candidate_status(tool_detection["missing"], input_detection["missing_inputs"], bool(scaffold_paths))
    return {
        "id": candidate,
        "display_name": str(policy.get("display_name", DISPLAY_NAMES[candidate])),
        "preparation_status": status,
        "required_future_inputs": list(policy.get("required_future_inputs", [])),
        "required_future_tools": list(policy.get("required_future_tools", [])),
        "detected_tools": tool_detection["present"],
        "missing_tools": tool_detection["missing"],
        "missing_inputs": input_detection["missing_inputs"],
        "future_artifact_candidates": list(policy.get("future_artifact_candidates", [])),
        "phase_3c_b_outputs": list(policy.get("phase_3c_b_allowed_outputs", [])),
        "blocked_until": list(policy.get("blocked_until", [])),
        "scaffold_paths": scaffold_paths,
        "notes": [
            "Phase 3C-B report only; no rootfs generated.",
            "No substrate selection or candidate ranking is implied.",
        ],
    }


def backend_summary(detection: dict[str, Any]) -> dict[str, str]:
    backends = detection.get("backends", {})
    return {
        "podman": str(backends.get("podman", {}).get("status", "BACKEND_ABSENT")),
        "buildah": str(backends.get("buildah", {}).get("status", "BACKEND_ABSENT")),
        "docker": str(backends.get("docker", {}).get("status", "BACKEND_ABSENT")),
        "qemu-system-x86_64": str(backends.get("qemu-system-x86_64", {}).get("status", "BACKEND_ABSENT")),
        "qemu-img": str(backends.get("qemu-img", {}).get("status", "BACKEND_ABSENT")),
    }


def scan_default_paths_for_forbidden_patterns() -> dict[str, Any]:
    makefile = ROOT / "Makefile"
    text = makefile.read_text(encoding="utf-8")
    default_targets = [
        "wucios-euclid-direct-rootfs-phase-3c-b",
        "wucios-euclid-direct-rootfs-phase-3c-b-json",
        "wucios-direct-rootfs-prep-buildroot",
        "wucios-direct-rootfs-prep-alpine",
        "wucios-direct-rootfs-prep-debian-minimal",
        "wucios-direct-rootfs-prep-void",
        "wucios-idempotence-check",
    ]
    forbidden = [
        "apk add",
        "apk --root",
        "debootstrap",
        "xbps-install -r",
        "make O=",
        "podman build",
        "buildah bud",
        "podman run",
        "buildah run",
        "docker build",
        "docker run",
        "qemu-system",
        "sudo",
        "git clone",
        "curl download",
        "wget download",
        "WUCIOS_EUCLID_ALLOW_ATTEMPT=1",
        "WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1",
        "WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1",
    ]
    violations: list[dict[str, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line or line.startswith("#") or not line.startswith("\t"):
            continue
        target = "UNKNOWN"
        for previous in range(index - 1, -1, -1):
            candidate = lines[previous]
            if candidate and not candidate.startswith("\t") and ":" in candidate:
                target = candidate.split(":", 1)[0].strip()
                break
        if target not in default_targets:
            continue
        for pattern in forbidden:
            if pattern in line:
                violations.append({"target": target, "pattern": pattern, "line": line.strip()})
    return {
        "status": "PASS" if not violations else "FAIL",
        "checked_targets": default_targets,
        "violations": violations,
    }


def run_guardrails(output_root: Path) -> dict[str, Any]:
    guardrail_dir = output_root / "guardrail-tests/phase-3c-b"
    ensure_directory(guardrail_dir)
    env = os.environ.copy()
    env.pop(AUTH_ENV, None)
    env.pop("WUCIOS_EUCLID_ALLOW_ATTEMPT", None)
    env.pop("WUCIOS_PHASE3CA_ALLOW_L2_SMOKE", None)

    checks: list[dict[str, Any]] = []
    commands = [
        ("l2-scaffold-without-authorization", ["make", "wucios-euclid-direct-rootfs-phase-3c-b-scaffold"]),
        ("phase-2-attempt-without-authorization", ["make", "wucios-euclid-trial-phase-2-attempt"]),
        ("phase-3c-a-smoke-without-authorization", ["make", "wucios-euclid-buildrooms-phase-3c-a-smoke"]),
    ]
    for name, command in commands:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        (guardrail_dir / f"{name}.log").write_text(result.stdout or "", encoding="utf-8")
        (guardrail_dir / f"{name}.exitcode").write_text(f"{result.returncode}\n", encoding="utf-8")
        checks.append({
            "name": name,
            "expected": "nonzero refusal",
            "returncode": result.returncode,
            "status": "PASS" if result.returncode != 0 else "FAIL",
        })

    scan = scan_default_paths_for_forbidden_patterns()
    write_json(guardrail_dir / "default-path-forbidden-pattern-scan.json", scan)
    checks.append({
        "name": "default-path-forbidden-pattern-scan",
        "expected": "no forbidden execution patterns in default Phase 3C-B paths",
        "status": scan["status"],
        "violations": scan["violations"],
    })

    report = {
        "schema": "wucios.euclid.phase3c_b.guardrails.v1",
        "phase_id": PHASE_ID,
        "generated_utc": generated_timestamp(),
        "status": "PASS" if all(check.get("status") == "PASS" for check in checks) else "FAIL",
        "checks": checks,
        "outputs": [normalize_path(path) for path in sorted(guardrail_dir.iterdir()) if path.is_file()],
    }
    write_json(guardrail_dir / "guardrail-report.json", report)
    return report


def load_existing_guardrails(output_root: Path) -> list[dict[str, Any]]:
    path = output_root / "guardrail-tests/phase-3c-b/guardrail-report.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return []
    return [check for check in checks if isinstance(check, dict)]


def build_report(args: argparse.Namespace, policies: dict[str, Any]) -> tuple[dict[str, Any], str]:
    output_dir = ROOT / args.output_dir
    buildroom_output_dir = ROOT / args.buildroom_output_dir
    ensure_directory(output_dir)
    ensure_directory(buildroom_output_dir)

    requested_candidates = args.candidate or CANDIDATES
    env_authorized = os.environ.get(AUTH_ENV) == "1"
    notes: list[str] = []
    blocked = False
    scaffold_attempted = False
    scaffold_authorized = False

    if env_authorized and not args.l2_scaffold:
        notes.append("L2_SCAFFOLD_ENV_PRESENT_BUT_FLAG_ABSENT")
    if args.l2_scaffold and not env_authorized:
        notes.append("L2_SCAFFOLD_NOT_AUTHORIZED")
        blocked = True
    if args.l2_scaffold and env_authorized:
        scaffold_attempted = True
        scaffold_authorized = True

    backend_detection = safe_backend_info_capture()
    scaffold_by_candidate: dict[str, list[str]] = {candidate: [] for candidate in requested_candidates}
    if scaffold_authorized:
        for candidate in requested_candidates:
            scaffold_by_candidate[candidate] = generate_scaffold(
                candidate,
                policies["candidate_policies"][candidate],
                policies["command_shapes"],
                policies["evidence"],
                ROOT / "build/wucios/buildrooms/direct-rootfs",
            )

    candidates = [
        candidate_report(candidate, policies["candidate_policies"][candidate], scaffold_by_candidate[candidate])
        for candidate in requested_candidates
    ]

    guardrails = []
    if args.guardrails:
        guardrail_report = run_guardrails(output_dir)
        guardrails = guardrail_report.get("checks", [])
        if guardrail_report.get("status") != "PASS":
            blocked = True
    else:
        guardrails = load_existing_guardrails(output_dir)

    if blocked:
        status = "PHASE_3C_B_BLOCKED"
        execution_mode = "L2_SCAFFOLD_NOT_AUTHORIZED" if args.l2_scaffold and not env_authorized else "PHASE_3C_B_GUARDRAIL_BLOCKED"
    elif scaffold_authorized:
        status = "PHASE_3C_B_SCAFFOLD_COMPLETE"
        execution_mode = "L2_NON_ARTIFACT_SCAFFOLD_AUTHORIZED"
    else:
        status = "PHASE_3C_B_RULES_COMPLETE"
        execution_mode = "L1_POLICY_AND_PREPARATION_RULES"

    scaffold_outputs = []
    for candidate in candidates:
        scaffold_outputs.extend(candidate.get("scaffold_paths", []))

    report = {
        "schema": "wucios.euclid.phase3c_b.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": status,
        "execution_mode": execution_mode,
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "ranking_allowed": False,
        "numeric_wucios_score_generated": False,
        "score_status": "NO_ARTIFACT_SCORE",
        "wucios_artifact_generated": False,
        "substrate_artifact_attempt_made": False,
        "runtime_inspection_attempted": False,
        "rootfs_generation_attempted": False,
        "container_build_attempted": False,
        "container_run_attempted": False,
        "image_pull_attempted": False,
        "network_used": False,
        "vm_run_attempted": False,
        "sudo_used": False,
        "package_installation_attempted": False,
        "source_clone_attempted": False,
        "image_download_attempted": False,
        "candidate_count": len(CANDIDATES),
        "in_scope_candidates": CANDIDATES,
        "out_of_scope_preserved": policies["plan"].get("out_of_scope_preserved", {}),
        "backend_detection": {
            "summary": backend_summary(backend_detection),
            "details": backend_detection,
        },
        "l2_scaffold": {
            "authorized": scaffold_authorized,
            "attempted": scaffold_attempted,
            "outputs": scaffold_outputs,
        },
        "candidates": candidates,
        "guardrails": guardrails,
        "notes": notes,
    }
    markdown = render_markdown(report)
    write_json(output_dir / "euclid-trial-phase-3c-b.json", report)
    write_markdown(output_dir / "euclid-trial-phase-3c-b.md", markdown)
    return report, markdown


def render_candidate_table(candidates: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Candidate | Preparation Status | Detected Tools | Missing Tools | Missing Inputs | Future Artifact Candidates | Blocked Until |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in candidates:
        lines.append(
            "| {name} | `{status}` | {detected} | {missing_tools} | {missing_inputs} | {artifacts} | {blocked} |".format(
                name=candidate["display_name"],
                status=candidate["preparation_status"],
                detected=", ".join(candidate["detected_tools"]) or "none",
                missing_tools=", ".join(candidate["missing_tools"]) or "none",
                missing_inputs=", ".join(candidate["missing_inputs"]) or "none",
                artifacts=", ".join(candidate["future_artifact_candidates"]) or "none",
                blocked=", ".join(candidate["blocked_until"]) or "none",
            )
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    backend = report["backend_detection"]["summary"]
    lines = [
        f"# {PHASE_NAME}",
        "",
        f"Global Status: {report['global_status']}",
        f"Execution Mode: {report['execution_mode']}",
        "Substrate Selection: NO_SUBSTRATE_SELECTED",
        "WuciOS Score: NO_ARTIFACT_SCORE",
        "In-Scope Candidates: Buildroot, Alpine, Debian minimal, Void",
        "Out-of-Scope Preserved: NixOS/Guix -> Phase 3C-C; Yocto -> Phase 3C-D; OpenBSD reference -> Phase 3C-E",
        "Substrate Artifact Attempt: false",
        "Rootfs Generation: false",
        "Runtime Inspection: false",
        "Container Builds: none",
        "Container Runs: none",
        "Image Pulls: none",
        "Network: disabled",
        "",
        "## Purpose",
        "",
        "Phase 3C-B defines direct-rootfs buildroom preparation rules for Buildroot, Alpine, Debian minimal, and Void.",
        "",
        "## Build Room Rule",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        "## Scope Boundary",
        "",
        "NixOS/Guix, Yocto, and OpenBSD reference are preserved for later dedicated phases and are not executed or downgraded by this phase.",
        "",
        "## Authorized Scope",
        "",
        "L1 policy validation and backend information checks are authorized by default. L2 non-artifact scaffolding is authorized only with `WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1` and an explicit scaffold target or runner flag.",
        "",
        "## Not Authorized",
        "",
        "L3 substrate artifact attempts and L4 runtime inspection are not authorized.",
        "",
        "## Candidate Summary",
        "",
        *render_candidate_table(report["candidates"]),
        "",
        "## Pull / Pinning / Cache / Output Policy",
        "",
        "Phase 3C-B permits no image pulls, network use, substrate source downloads, or OS image downloads. Future L3 work must pin images by digest if images are used, record source identity or repository configuration, keep cache/output paths under `build/wucios/`, and produce an artifact manifest and hash before any score is considered.",
        "",
        "## Future Evidence Requirements",
        "",
        "Future L3 direct-rootfs attempts require artifact manifests, artifact hash, build logs, build command and environment records, source policy, package manifests, size records, static Noether checks, Godel boundary notes, substrate reports, failure reports, and missing-measurement records. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.",
        "",
        "## Backend Findings",
        "",
        f"Podman: `{backend.get('podman', 'NOT_MEASURED')}`; Buildah: `{backend.get('buildah', 'NOT_MEASURED')}`; Docker: `{backend.get('docker', 'NOT_MEASURED')}`; QEMU system: `{backend.get('qemu-system-x86_64', 'NOT_MEASURED')}`; QEMU image tooling: `{backend.get('qemu-img', 'NOT_MEASURED')}`.",
        "",
        "## Guardrail Results",
        "",
    ]
    if report.get("guardrails"):
        lines.extend(f"- {item.get('name', 'guardrail')}: `{item.get('status', 'UNKNOWN')}`" for item in report["guardrails"])
    else:
        lines.append("- Guardrail target not requested in this report.")
    lines.extend([
        "",
        "## Non-Selection Statement",
        "",
        "No substrate is selected in Phase 3C-B. Direct-rootfs preparation readiness is not substrate ranking.",
        "",
        "## Score Statement",
        "",
        "No numeric WuciOS score is generated in Phase 3C-B because no current WuciOS artifact and complete artifact-bound evidence exist.",
        "",
        "## Boundary Statement",
        "",
        "No substrate artifact attempt was made. No rootfs was generated. No runtime inspection was attempted. No container was built or run. No image was pulled. No networked build was performed. No source tree was cloned. No OS image was downloaded. No sudo was used. No package installation was attempted.",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    policies = validate_policies(ROOT / args.buildrooms_dir)
    report, _markdown = build_report(args, policies)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if args.l2_scaffold and os.environ.get(AUTH_ENV) != "1":
        print("L2_SCAFFOLD_NOT_AUTHORIZED", file=sys.stderr)
        return 1
    if report.get("global_status") == "PHASE_3C_B_BLOCKED":
        return 1
    print(f"Phase 3C-B: {report['global_status']}")
    print(f"- output: {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
