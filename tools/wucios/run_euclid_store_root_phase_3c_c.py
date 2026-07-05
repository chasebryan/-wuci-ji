#!/usr/bin/env python3
"""Run WuciOS Euclid Phase 3C-C store-root preparation policy checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from store_root_prep_common import (
    CANDIDATES,
    DISPLAY_NAMES,
    ROOT,
    detect_declarative_inputs,
    ensure_directory,
    generate_scaffold,
    generated_timestamp,
    load_json,
    normalize_candidate_status,
    normalize_path,
    safe_static_tool_detection,
    validate_declarative_input_policy,
    write_json,
    write_markdown,
)


PHASE_ID = "euclid-trial-phase-3c-c"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 3C-C — NixOS/Guix Store-Root Preparation"
AUTH_ENV = "WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print combined JSON after writing reports")
    parser.add_argument("--l2-scaffold", action="store_true", help="Request authorized L2 non-artifact scaffolding")
    parser.add_argument("--candidate", action="append", choices=CANDIDATES)
    parser.add_argument("--output-dir", default="build/wucios/review")
    parser.add_argument("--buildroom-output-dir", default="build/wucios/buildrooms/store-root/phase-3c-c")
    parser.add_argument("--buildrooms-dir", default="wucios/buildrooms/store-root")
    parser.add_argument("--guardrails", action="store_true", help="Run Phase 3C-C negative guardrail checks")
    return parser.parse_args()


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("phase_id") != PHASE_ID:
        raise SystemExit("Phase 3C-C plan has wrong phase_id")
    if plan.get("phase_name") != PHASE_NAME:
        raise SystemExit("Phase 3C-C plan has wrong phase_name")
    if plan.get("default_execution_mode") != "L1_STORE_ROOT_POLICY_AND_DECLARATIVE_INPUTS":
        raise SystemExit("Phase 3C-C plan must default to L1 store-root policy checks")
    if plan.get("l2_scaffold_authorized_by_default") is not False:
        raise SystemExit("Phase 3C-C plan must disable L2 scaffold by default")
    if plan.get("l3_substrate_artifact_attempts_allowed") is not False:
        raise SystemExit("Phase 3C-C plan must forbid L3 artifact attempts")
    if plan.get("runtime_inspection_allowed") is not False:
        raise SystemExit("Phase 3C-C plan must forbid runtime inspection")
    if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
        raise SystemExit("Phase 3C-C plan must preserve NO_SUBSTRATE_SELECTED")
    for key in [
        "ranking_allowed",
        "emotional_testing_allowed",
        "numeric_score_allowed",
        "image_pulls_allowed",
        "container_builds_allowed",
        "container_runs_allowed",
        "vm_runs_allowed",
        "sudo_allowed",
        "host_package_install_allowed",
        "source_clone_allowed",
        "os_image_download_allowed",
        "store_realization_allowed",
        "derivation_build_allowed",
        "package_build_allowed",
        "system_activation_allowed",
        "rootfs_generation_allowed",
    ]:
        if plan.get(key) is not False:
            raise SystemExit(f"Phase 3C-C plan must set {key} false")
    if list(plan.get("in_scope_candidates", [])) != CANDIDATES:
        raise SystemExit("Phase 3C-C plan has wrong in-scope candidate set")


def validate_policies(buildrooms_dir: Path) -> dict[str, Any]:
    plan = load_json(buildrooms_dir / "euclid-store-root-phase-3c-c.json")
    validate_plan(plan)
    store_policy = load_json(buildrooms_dir / "store-root-policy.json")
    declarative_policy = load_json(buildrooms_dir / "declarative-input-policy.json")
    evidence = load_json(buildrooms_dir / "evidence-requirements.json")
    guardrail_policy = load_json(buildrooms_dir / "guardrail-policy.json")
    policy_failures = validate_declarative_input_policy(declarative_policy)
    if policy_failures:
        raise SystemExit("; ".join(policy_failures))

    candidate_policies: dict[str, dict[str, Any]] = {}
    for candidate in CANDIDATES:
        policy = load_json(buildrooms_dir / candidate / "preparation-policy.json")
        if policy.get("phase_id") != PHASE_ID:
            raise SystemExit(f"{candidate} preparation policy has wrong phase_id")
        if policy.get("candidate_id") != candidate:
            raise SystemExit(f"{candidate} preparation policy has wrong candidate_id")
        if policy.get("l3_artifact_attempt_allowed") is not False:
            raise SystemExit(f"{candidate} preparation policy must forbid L3 artifact attempts")
        if policy.get("rootfs_generation_allowed") is not False:
            raise SystemExit(f"{candidate} preparation policy must forbid rootfs generation")
        if policy.get("store_realization_allowed") is not False:
            raise SystemExit(f"{candidate} preparation policy must forbid store realization")
        candidate_policies[candidate] = policy

    return {
        "plan": plan,
        "store_policy": store_policy,
        "declarative_policy": declarative_policy,
        "evidence": evidence,
        "guardrail_policy": guardrail_policy,
        "candidate_policies": candidate_policies,
    }


def candidate_report(candidate: str, policy: dict[str, Any], scaffold_paths: list[str]) -> dict[str, Any]:
    input_detection = detect_declarative_inputs(candidate, policy)
    status = normalize_candidate_status(input_detection["missing_inputs"], bool(scaffold_paths))
    return {
        "id": candidate,
        "display_name": str(policy.get("candidate_name", DISPLAY_NAMES[candidate])),
        "candidate_family": str(policy.get("candidate_family", "NOT_MEASURED")),
        "preparation_status": status,
        "declarative_input_type": str(policy.get("declarative_input_type", "NOT_MEASURED")),
        "required_inputs": list(policy.get("required_inputs", [])),
        "optional_inputs": list(policy.get("optional_inputs", [])),
        "detected_inputs": input_detection["detected_inputs"],
        "missing_inputs": input_detection["missing_inputs"],
        "artifact_status": str(policy.get("artifact_status", "NO_WUCIOS_ARTIFACT")),
        "score_status": str(policy.get("score_status", "NO_ARTIFACT_SCORE")),
        "authorization_status": str(policy.get("authorization_status", "L3_AND_L4_UNAUTHORIZED")),
        "future_artifact_candidates": list(policy.get("future_artifact_candidates", [])),
        "phase_3c_c_outputs": list(policy.get("phase_3c_c_allowed_outputs", [])),
        "blocked_until": list(policy.get("blocked_until", [])),
        "scaffold_paths": scaffold_paths,
        "notes": [
            "Phase 3C-C report only; no store realization or rootfs generation occurred.",
            "No substrate selection or candidate ranking is implied.",
        ],
    }


def scan_default_paths_for_forbidden_patterns() -> dict[str, Any]:
    makefile = ROOT / "Makefile"
    text = makefile.read_text(encoding="utf-8")
    default_targets = [
        "wucios-euclid-store-root-phase-3c-c",
        "wucios-euclid-store-root-phase-3c-c-json",
        "wucios-store-root-prep-nixos",
        "wucios-store-root-prep-guix",
        "wucios-idempotence-check",
    ]
    forbidden = [
        "nix-build",
        "nixos-rebuild",
        "nix develop",
        "nix shell",
        "nix flake check",
        "guix build",
        "guix system",
        "guix shell",
        "guix environment",
        "guix pull",
        "docker",
        "podman build",
        "podman run",
        "buildah",
        "qemu",
        "virt-install",
        "sudo",
        "apt",
        "apk",
        "xbps-install",
        "pacman",
        "curl download",
        "wget download",
        "git clone",
        "WUCIOS_EUCLID_ALLOW_ATTEMPT=1",
        "WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1",
        "WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1",
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
    guardrail_dir = output_root / "guardrail-tests/phase-3c-c"
    ensure_directory(guardrail_dir)
    env = os.environ.copy()
    env.pop(AUTH_ENV, None)
    env.pop("WUCIOS_EUCLID_ALLOW_ATTEMPT", None)
    env.pop("WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD", None)

    checks: list[dict[str, Any]] = []
    commands = [
        ("l2-declarative-scaffold-without-authorization", ["make", "wucios-euclid-store-root-phase-3c-c-scaffold"]),
        ("phase-2-attempt-without-authorization", ["make", "wucios-euclid-trial-phase-2-attempt"]),
        ("phase-3c-b-scaffold-without-authorization", ["make", "wucios-euclid-direct-rootfs-phase-3c-b-scaffold"]),
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
        "expected": "no forbidden execution patterns in default Phase 3C-C paths",
        "status": scan["status"],
        "violations": scan["violations"],
    })

    report = {
        "schema": "wucios.euclid.phase3c_c.guardrails.v1",
        "phase_id": PHASE_ID,
        "generated_utc": generated_timestamp(),
        "status": "PASS" if all(check.get("status") == "PASS" for check in checks) else "FAIL",
        "checks": checks,
        "outputs": [normalize_path(path) for path in sorted(guardrail_dir.iterdir()) if path.is_file()],
    }
    write_json(guardrail_dir / "guardrail-report.json", report)
    return report


def load_existing_guardrails(output_root: Path) -> list[dict[str, Any]]:
    path = output_root / "guardrail-tests/phase-3c-c/guardrail-report.json"
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
        notes.append("L2_DECLARATIVE_SCAFFOLD_ENV_PRESENT_BUT_FLAG_ABSENT")
    if args.l2_scaffold and not env_authorized:
        notes.append("L2_DECLARATIVE_SCAFFOLD_NOT_AUTHORIZED")
        blocked = True
    if args.l2_scaffold and env_authorized:
        scaffold_attempted = True
        scaffold_authorized = True

    static_detection = safe_static_tool_detection()
    scaffold_by_candidate: dict[str, list[str]] = {candidate: [] for candidate in requested_candidates}
    if scaffold_authorized:
        for candidate in requested_candidates:
            scaffold_by_candidate[candidate] = generate_scaffold(
                candidate,
                policies["candidate_policies"][candidate],
                policies["declarative_policy"],
                policies["evidence"],
                ROOT / "build/wucios/buildrooms/store-root",
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
        status = "PHASE_3C_C_BLOCKED"
        execution_mode = "L2_DECLARATIVE_SCAFFOLD_NOT_AUTHORIZED" if args.l2_scaffold and not env_authorized else "PHASE_3C_C_GUARDRAIL_BLOCKED"
    elif scaffold_authorized:
        status = "PHASE_3C_C_SCAFFOLD_COMPLETE"
        execution_mode = "L2_DECLARATIVE_NON_ARTIFACT_SCAFFOLD_AUTHORIZED"
    else:
        status = "PHASE_3C_C_RULES_COMPLETE"
        execution_mode = "L1_STORE_ROOT_POLICY_AND_DECLARATIVE_INPUTS"

    scaffold_outputs = []
    for candidate in candidates:
        scaffold_outputs.extend(candidate.get("scaffold_paths", []))

    report = {
        "schema": "wucios.euclid.phase3c_c.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": status,
        "execution_mode": execution_mode,
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "ranking_allowed": False,
        "numeric_wucios_score_generated": False,
        "score_status": "NO_ARTIFACT_SCORE",
        "wucios_artifact_generated": False,
        "artifact_hash_generated": False,
        "substrate_artifact_attempt_made": False,
        "runtime_inspection_attempted": False,
        "rootfs_generation_attempted": False,
        "store_realization_attempted": False,
        "derivation_build_attempted": False,
        "package_build_attempted": False,
        "system_activation_attempted": False,
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
        "static_tool_detection": static_detection,
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
    write_json(output_dir / "euclid-trial-phase-3c-c.json", report)
    write_markdown(output_dir / "euclid-trial-phase-3c-c.md", markdown)
    return report, markdown


def render_candidate_table(candidates: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Candidate | Family | Preparation Status | Missing Inputs | Artifact Status | Score Status | Blocked Until |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in candidates:
        lines.append(
            "| {name} | `{family}` | `{status}` | {missing_inputs} | `{artifact}` | `{score}` | {blocked} |".format(
                name=candidate["display_name"],
                family=candidate["candidate_family"],
                status=candidate["preparation_status"],
                missing_inputs=", ".join(candidate["missing_inputs"]) or "none",
                artifact=candidate["artifact_status"],
                score=candidate["score_status"],
                blocked=", ".join(candidate["blocked_until"]) or "none",
            )
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    detection_summary = report["static_tool_detection"]["summary"]
    lines = [
        f"# {PHASE_NAME}",
        "",
        f"Global Status: {report['global_status']}",
        f"Execution Mode: {report['execution_mode']}",
        "Substrate Selection: NO_SUBSTRATE_SELECTED",
        "WuciOS Score: NO_ARTIFACT_SCORE",
        "In-Scope Candidates: NixOS, Guix",
        "Out-of-Scope Preserved: Buildroot/Alpine/Debian minimal/Void -> Phase 3C-B; Yocto -> Phase 3C-D; OpenBSD reference -> Phase 3C-E",
        "Substrate Artifact Attempt: false",
        "Rootfs Generation: false",
        "Store Realization: false",
        "Runtime Inspection: false",
        "Container Builds: none",
        "Container Runs: none",
        "Image Pulls: none",
        "Network: disabled",
        "",
        "## Purpose",
        "",
        "Phase 3C-C defines NixOS and Guix store-root preparation rules without building, realizing, downloading, executing, or scoring anything.",
        "",
        "## Build Room Rule",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        "## Scope Boundary",
        "",
        "Buildroot, Alpine, Debian minimal, and Void remain Phase 3C-B direct-rootfs candidates. Yocto and OpenBSD reference remain deferred to Phase 3C-D and Phase 3C-E. None are executed or downgraded by this phase.",
        "",
        "## Authorized Scope",
        "",
        "L1 policy validation and declarative-input missing-status reporting are authorized by default. L2 non-artifact scaffolding is authorized only with `WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1` and an explicit scaffold target or runner flag.",
        "",
        "## Not Authorized",
        "",
        "L3 substrate artifact attempts and L4 runtime inspection are not authorized. NixOS and Guix build, shell, pull, system, store realization, derivation build, package build, and activation commands remain forbidden.",
        "",
        "## Candidate Summary",
        "",
        *render_candidate_table(report["candidates"]),
        "",
        "## Store-Root Policy",
        "",
        "Phase 3C-C records declarative input, store policy, source or channel identity, cache, output, and evidence requirements. Direct-rootfs assumptions from Phase 3C-B are not reused as execution policy for NixOS or Guix.",
        "",
        "## Future Evidence Requirements",
        "",
        "Future L3 store-root attempts require declarative input manifests, store policy records, source or channel identity, build command and environment records, store realization logs, artifact manifests, artifact hashes, closure or package manifests, static Noether checks, Godel boundary notes, substrate reports, failure reports, and missing-measurement records. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.",
        "",
        "## Static Tool Findings",
        "",
        f"Nix: `{detection_summary.get('nix', 'NOT_MEASURED')}`; Guix: `{detection_summary.get('guix', 'NOT_MEASURED')}`; Docker: `{detection_summary.get('docker', 'NOT_MEASURED')}`; Podman: `{detection_summary.get('podman', 'NOT_MEASURED')}`; Buildah: `{detection_summary.get('buildah', 'NOT_MEASURED')}`; QEMU system: `{detection_summary.get('qemu-system-x86_64', 'NOT_MEASURED')}`.",
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
        "No substrate is selected in Phase 3C-C. Store-root preparation readiness is not substrate ranking.",
        "",
        "## Score Statement",
        "",
        "No numeric WuciOS score is generated in Phase 3C-C because no current WuciOS artifact and complete artifact-bound evidence exist.",
        "",
        "## Boundary Statement",
        "",
        "No substrate artifact attempt was made. No rootfs was generated. No store path was realized. No derivation or package was built. No system activation was attempted. No runtime inspection was attempted. No container was built or run. No image was pulled. No networked build was performed. No source tree was cloned. No OS image was downloaded. No sudo was used. No package installation was attempted.",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    policies = validate_policies(ROOT / args.buildrooms_dir)
    report, _markdown = build_report(args, policies)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if args.l2_scaffold and os.environ.get(AUTH_ENV) != "1":
        print("L2_DECLARATIVE_SCAFFOLD_NOT_AUTHORIZED", file=sys.stderr)
        return 1
    if report.get("global_status") == "PHASE_3C_C_BLOCKED":
        return 1
    print(f"Phase 3C-C: {report['global_status']}")
    print(f"- output: {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
