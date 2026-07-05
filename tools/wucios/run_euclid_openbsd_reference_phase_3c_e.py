#!/usr/bin/env python3
"""Run WuciOS Euclid Phase 3C-E OpenBSD reference preparation policy checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from openbsd_reference_prep_common import (
    DISPLAY_NAMES,
    REFERENCES,
    ROOT,
    detect_openbsd_reference_inputs,
    ensure_directory,
    generate_scaffold,
    generated_timestamp,
    load_json,
    normalize_path,
    normalize_reference_status,
    safe_static_context,
    validate_openbsd_reference_input_policy,
    write_json,
    write_markdown,
)


PHASE_ID = "euclid-trial-phase-3c-e"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 3C-E — OpenBSD Reference Preparation"
AUTH_ENV = "WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print combined JSON after writing reports")
    parser.add_argument("--l2-scaffold", action="store_true", help="Request authorized L2 non-artifact scaffolding")
    parser.add_argument("--reference", action="append", choices=REFERENCES)
    parser.add_argument("--output-dir", default="build/wucios/review")
    parser.add_argument("--buildroom-output-dir", default="build/wucios/buildrooms/openbsd-reference/phase-3c-e")
    parser.add_argument("--buildrooms-dir", default="wucios/buildrooms/openbsd-reference")
    parser.add_argument("--guardrails", action="store_true", help="Run Phase 3C-E negative guardrail checks")
    return parser.parse_args()


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("phase_id") != PHASE_ID:
        raise SystemExit("Phase 3C-E plan has wrong phase_id")
    if plan.get("phase_name") != PHASE_NAME:
        raise SystemExit("Phase 3C-E plan has wrong phase_name")
    if plan.get("default_execution_mode") != "L1_OPENBSD_REFERENCE_POLICY_AND_INPUTS":
        raise SystemExit("Phase 3C-E plan must default to L1 OpenBSD reference policy checks")
    if plan.get("l2_scaffold_authorized_by_default") is not False:
        raise SystemExit("Phase 3C-E plan must disable L2 scaffold by default")
    if plan.get("l3_substrate_artifact_attempts_allowed") is not False:
        raise SystemExit("Phase 3C-E plan must forbid L3 artifact attempts")
    if plan.get("runtime_inspection_allowed") is not False:
        raise SystemExit("Phase 3C-E plan must forbid runtime inspection")
    if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
        raise SystemExit("Phase 3C-E plan must preserve NO_SUBSTRATE_SELECTED")
    for key in [
        "openbsd_boot_allowed",
        "openbsd_install_allowed",
        "openbsd_package_admin_allowed",
        "source_clone_allowed",
        "ports_tree_download_allowed",
        "install_media_download_allowed",
        "snapshot_download_allowed",
        "signature_download_allowed",
        "rootfs_generation_allowed",
        "image_generation_allowed",
        "vm_launch_allowed",
        "hypervisor_tooling_allowed",
        "selection_allowed",
        "ranking_allowed",
        "emotional_testing_allowed",
        "numeric_score_allowed",
        "image_pulls_allowed",
        "container_builds_allowed",
        "container_runs_allowed",
        "vm_runs_allowed",
        "sudo_allowed",
        "host_package_install_allowed",
        "os_image_download_allowed",
    ]:
        if plan.get(key) is not False:
            raise SystemExit(f"Phase 3C-E plan must set {key} false")
    if list(plan.get("in_scope_references", [])) != REFERENCES:
        raise SystemExit("Phase 3C-E plan has wrong in-scope reference set")


def validate_policies(buildrooms_dir: Path) -> dict[str, Any]:
    plan = load_json(buildrooms_dir / "euclid-openbsd-reference-phase-3c-e.json")
    validate_plan(plan)
    reference_policy = load_json(buildrooms_dir / "openbsd-reference-policy.json")
    input_policy = load_json(buildrooms_dir / "openbsd-reference-input-policy.json")
    evidence = load_json(buildrooms_dir / "evidence-requirements.json")
    guardrail_policy = load_json(buildrooms_dir / "guardrail-policy.json")
    policy_failures = validate_openbsd_reference_input_policy(input_policy)
    if policy_failures:
        raise SystemExit("; ".join(policy_failures))

    reference_policies: dict[str, dict[str, Any]] = {}
    for reference in REFERENCES:
        policy = load_json(buildrooms_dir / reference / "preparation-policy.json")
        if policy.get("phase_id") != PHASE_ID:
            raise SystemExit(f"{reference} preparation policy has wrong phase_id")
        if policy.get("reference_id") != reference:
            raise SystemExit(f"{reference} preparation policy has wrong reference_id")
        for key in [
            "l3_artifact_attempt_allowed",
            "runtime_inspection_allowed",
            "openbsd_boot_allowed",
            "openbsd_install_allowed",
            "openbsd_package_admin_allowed",
            "source_clone_allowed",
            "ports_tree_download_allowed",
            "install_media_download_allowed",
            "vm_launch_allowed",
            "rootfs_generation_allowed",
            "image_generation_allowed",
        ]:
            if policy.get(key) is not False:
                raise SystemExit(f"{reference} preparation policy must set {key} false")
        reference_policies[reference] = policy

    return {
        "plan": plan,
        "reference_policy": reference_policy,
        "input_policy": input_policy,
        "evidence": evidence,
        "guardrail_policy": guardrail_policy,
        "reference_policies": reference_policies,
    }


def reference_report(reference: str, policy: dict[str, Any], scaffold_paths: list[str]) -> dict[str, Any]:
    input_detection = detect_openbsd_reference_inputs(reference, policy)
    status = normalize_reference_status(input_detection["missing_inputs"], bool(scaffold_paths))
    return {
        "id": reference,
        "display_name": str(policy.get("reference_name", DISPLAY_NAMES[reference])),
        "reference_family": str(policy.get("reference_family", "NOT_MEASURED")),
        "preparation_status": status,
        "openbsd_reference_input_type": str(policy.get("openbsd_reference_input_type", "NOT_MEASURED")),
        "required_inputs": list(policy.get("required_inputs", [])),
        "optional_inputs": list(policy.get("optional_inputs", [])),
        "detected_inputs": input_detection["detected_inputs"],
        "missing_inputs": input_detection["missing_inputs"],
        "artifact_status": str(policy.get("artifact_status", "NO_WUCIOS_ARTIFACT")),
        "score_status": str(policy.get("score_status", "NO_ARTIFACT_SCORE")),
        "authorization_status": str(policy.get("authorization_status", "L3_AND_L4_UNAUTHORIZED")),
        "selection_status": str(policy.get("selection_status", "NO_SUBSTRATE_SELECTED")),
        "ranking_status": str(policy.get("ranking_status", "NO_CANDIDATE_RANKED")),
        "future_artifact_candidates": list(policy.get("future_artifact_candidates", [])),
        "phase_3c_e_outputs": list(policy.get("phase_3c_e_allowed_outputs", [])),
        "blocked_until": list(policy.get("blocked_until", [])),
        "scaffold_paths": scaffold_paths,
        "notes": [
            "Phase 3C-E report only; no OpenBSD install, boot, runtime inspection, package operation, source clone, media download, VM launch, rootfs generation, or image generation occurred.",
            "OpenBSD reference preparation is not substrate selection or candidate ranking.",
        ],
    }


def scan_default_paths_for_forbidden_patterns() -> dict[str, Any]:
    makefile = ROOT / "Makefile"
    text = makefile.read_text(encoding="utf-8")
    default_targets = [
        "wucios-euclid-openbsd-reference-phase-3c-e",
        "wucios-euclid-openbsd-reference-phase-3c-e-json",
        "wucios-openbsd-reference-prep",
        "wucios-idempotence-check",
    ]
    forbidden = [
        "pkg_add",
        "pkg_info",
        "syspatch",
        "sysupgrade",
        "fw_update",
        "rcctl",
        "doas",
        "mount",
        "disklabel",
        "installboot",
        "sysctl",
        "OpenBSD install",
        "OpenBSD boot",
        "OpenBSD runtime inspection",
        "git clone",
        "curl download",
        "wget download",
        "qemu",
        "vmd",
        "virt-install",
        "hypervisor launch",
        "docker",
        "podman build",
        "podman run",
        "buildah",
        "sudo",
        "apt",
        "apk",
        "xbps-install",
        "pacman",
        "dnf",
        "WUCIOS_EUCLID_ALLOW_ATTEMPT=1",
        "WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1",
        "WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1",
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
    guardrail_dir = output_root / "guardrail-tests/phase-3c-e"
    ensure_directory(guardrail_dir)
    env = os.environ.copy()
    env.pop(AUTH_ENV, None)
    env.pop("WUCIOS_EUCLID_ALLOW_ATTEMPT", None)
    env.pop("WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD", None)

    checks: list[dict[str, Any]] = []
    commands = [
        ("l2-openbsd-reference-scaffold-without-authorization", ["make", "wucios-euclid-openbsd-reference-phase-3c-e-scaffold"]),
        ("phase-2-attempt-without-authorization", ["make", "wucios-euclid-trial-phase-2-attempt"]),
        ("phase-3c-d-scaffold-without-authorization", ["make", "wucios-euclid-yocto-phase-3c-d-scaffold"]),
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
        "expected": "no forbidden execution patterns in default Phase 3C-E paths",
        "status": scan["status"],
        "violations": scan["violations"],
    })

    report = {
        "schema": "wucios.euclid.phase3c_e.guardrails.v1",
        "phase_id": PHASE_ID,
        "generated_utc": generated_timestamp(),
        "status": "PASS" if all(check.get("status") == "PASS" for check in checks) else "FAIL",
        "checks": checks,
        "outputs": [normalize_path(path) for path in sorted(guardrail_dir.iterdir()) if path.is_file()],
    }
    write_json(guardrail_dir / "guardrail-report.json", report)
    return report


def load_existing_guardrails(output_root: Path) -> list[dict[str, Any]]:
    path = output_root / "guardrail-tests/phase-3c-e/guardrail-report.json"
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

    requested_references = args.reference or REFERENCES
    env_authorized = os.environ.get(AUTH_ENV) == "1"
    notes: list[str] = []
    blocked = False
    scaffold_attempted = False
    scaffold_authorized = False

    if env_authorized and not args.l2_scaffold:
        notes.append("L2_OPENBSD_REFERENCE_SCAFFOLD_ENV_PRESENT_BUT_FLAG_ABSENT")
    if args.l2_scaffold and not env_authorized:
        notes.append("L2_OPENBSD_REFERENCE_SCAFFOLD_NOT_AUTHORIZED")
        blocked = True
    if args.l2_scaffold and env_authorized:
        scaffold_attempted = True
        scaffold_authorized = True

    static_context = safe_static_context()
    scaffold_by_reference: dict[str, list[str]] = {reference: [] for reference in requested_references}
    if scaffold_authorized:
        for reference in requested_references:
            scaffold_by_reference[reference] = generate_scaffold(
                reference,
                policies["reference_policies"][reference],
                policies["input_policy"],
                policies["evidence"],
                ROOT / "build/wucios/buildrooms/openbsd-reference",
            )

    references = [
        reference_report(reference, policies["reference_policies"][reference], scaffold_by_reference[reference])
        for reference in requested_references
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
        status = "PHASE_3C_E_BLOCKED"
        execution_mode = "L2_OPENBSD_REFERENCE_SCAFFOLD_NOT_AUTHORIZED" if args.l2_scaffold and not env_authorized else "PHASE_3C_E_GUARDRAIL_BLOCKED"
    elif scaffold_authorized:
        status = "PHASE_3C_E_SCAFFOLD_COMPLETE"
        execution_mode = "L2_OPENBSD_REFERENCE_NON_ARTIFACT_SCAFFOLD_AUTHORIZED"
    else:
        status = "PHASE_3C_E_RULES_COMPLETE"
        execution_mode = "L1_OPENBSD_REFERENCE_POLICY_AND_INPUTS"

    scaffold_outputs = []
    for reference in references:
        scaffold_outputs.extend(reference.get("scaffold_paths", []))

    report = {
        "schema": "wucios.euclid.phase3c_e.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": status,
        "execution_mode": execution_mode,
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "selection_allowed": False,
        "ranking_allowed": False,
        "numeric_wucios_score_generated": False,
        "score_status": "NO_ARTIFACT_SCORE",
        "wucios_artifact_generated": False,
        "artifact_hash_generated": False,
        "substrate_artifact_attempt_made": False,
        "runtime_inspection_attempted": False,
        "openbsd_boot_attempted": False,
        "openbsd_install_attempted": False,
        "openbsd_package_admin_attempted": False,
        "rootfs_generation_attempted": False,
        "image_generation_attempted": False,
        "vm_launch_attempted": False,
        "hypervisor_tooling_attempted": False,
        "container_build_attempted": False,
        "container_run_attempted": False,
        "image_pull_attempted": False,
        "network_used": False,
        "sudo_used": False,
        "package_installation_attempted": False,
        "source_clone_attempted": False,
        "ports_tree_download_attempted": False,
        "install_media_download_attempted": False,
        "os_image_download_attempted": False,
        "reference_count": len(REFERENCES),
        "in_scope_references": REFERENCES,
        "out_of_scope_preserved": policies["plan"].get("out_of_scope_preserved", {}),
        "static_context": static_context,
        "l2_scaffold": {
            "authorized": scaffold_authorized,
            "attempted": scaffold_attempted,
            "outputs": scaffold_outputs,
        },
        "references": references,
        "guardrails": guardrails,
        "notes": notes,
    }
    markdown = render_markdown(report)
    write_json(output_dir / "euclid-trial-phase-3c-e.json", report)
    write_markdown(output_dir / "euclid-trial-phase-3c-e.md", markdown)
    return report, markdown


def render_reference_table(references: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Reference | Family | Preparation Status | Missing Inputs | Selection Status | Artifact Status | Score Status | Blocked Until |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for reference in references:
        lines.append(
            "| {name} | `{family}` | `{status}` | {missing_inputs} | `{selection}` | `{artifact}` | `{score}` | {blocked} |".format(
                name=reference["display_name"],
                family=reference["reference_family"],
                status=reference["preparation_status"],
                missing_inputs=", ".join(reference["missing_inputs"]) or "none",
                selection=reference["selection_status"],
                artifact=reference["artifact_status"],
                score=reference["score_status"],
                blocked=", ".join(reference["blocked_until"]) or "none",
            )
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    host = report["static_context"]["host"]
    lines = [
        f"# {PHASE_NAME}",
        "",
        f"Global Status: {report['global_status']}",
        f"Execution Mode: {report['execution_mode']}",
        "Substrate Selection: NO_SUBSTRATE_SELECTED",
        "WuciOS Score: NO_ARTIFACT_SCORE",
        "In-Scope Reference: OpenBSD reference",
        "Out-of-Scope Preserved: Buildroot/Alpine/Debian minimal/Void -> Phase 3C-B; NixOS/Guix -> Phase 3C-C; Yocto -> Phase 3C-D",
        "Substrate Artifact Attempt: false",
        "OpenBSD Install: false",
        "OpenBSD Boot: false",
        "Runtime Inspection: false",
        "Package/Admin Commands: false",
        "Rootfs Generation: false",
        "Image Generation: false",
        "VM Launch: false",
        "Container Builds: none",
        "Container Runs: none",
        "Image Pulls: none",
        "Network: disabled",
        "",
        "## Purpose",
        "",
        "Phase 3C-E defines OpenBSD reference preparation rules without booting, installing, downloading, cloning, executing, imaging, selecting, ranking, or scoring anything.",
        "",
        "## Build Room Rule",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        "## Scope Boundary",
        "",
        "OpenBSD is modeled as a reference operating-system baseline only. Buildroot, Alpine, Debian minimal, and Void remain Phase 3C-B direct-rootfs candidates. NixOS and Guix remain Phase 3C-C store-root candidates. Yocto remains the Phase 3C-D layer/recipe preparation candidate. None are executed or reworked by this phase.",
        "",
        "## Authorized Scope",
        "",
        "L1 policy validation and OpenBSD reference missing-input reporting are authorized by default. L2 non-artifact reference scaffolding is authorized only with `WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1` and an explicit scaffold target or runner flag.",
        "",
        "## Not Authorized",
        "",
        "L3 substrate artifact attempts and L4 runtime inspection are not authorized. OpenBSD install, boot, runtime inspection, package/admin commands, source clones, ports tree downloads, install media downloads, VM launch, rootfs generation, image generation, container actions, package installation, and scoring remain forbidden.",
        "",
        "## Reference Summary",
        "",
        *render_reference_table(report["references"]),
        "",
        "## OpenBSD Reference Input Policy",
        "",
        "Phase 3C-E records required reference target identity, media acquisition, sets/signature, source, ports, package/admin, runtime authorization, VM/hardware, output path, and evidence hook policies. Direct-rootfs, store-root, and Yocto assumptions are not reused as OpenBSD reference execution policy.",
        "",
        "## Future Evidence Requirements",
        "",
        "Future OpenBSD reference movement requires reference input manifests, media identity records, sets and signature policy, source and ports acquisition policy, runtime authorization policy, VM or hardware policy, package/admin command policy, logs, evidence manifests, substrate reports, failure reports, and missing-measurement records. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.",
        "",
        "## Static Context",
        "",
        f"Host system: `{host.get('system', 'NOT_MEASURED')}`; release: `{host.get('release', 'NOT_MEASURED')}`; machine: `{host.get('machine', 'NOT_MEASURED')}`; Python: `{host.get('python', 'NOT_MEASURED')}`. No OpenBSD, VM, package, container, or network tool was executed for this context.",
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
        "No substrate is selected in Phase 3C-E. OpenBSD reference preparation is not substrate ranking.",
        "",
        "## Score Statement",
        "",
        "No numeric WuciOS score is generated in Phase 3C-E because no current WuciOS artifact and complete artifact-bound evidence exist.",
        "",
        "## Boundary Statement",
        "",
        "No substrate artifact attempt was made. No OpenBSD install was attempted. No OpenBSD boot was attempted. No OpenBSD runtime inspection was attempted. No OpenBSD package or admin command was run. No rootfs was generated. No image was generated. No VM was launched. No container was built or run. No image was pulled. No networked build was performed. No source tree was cloned. No ports tree was downloaded. No install media was downloaded. No OS image was downloaded. No sudo was used. No package installation was attempted.",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    policies = validate_policies(ROOT / args.buildrooms_dir)
    report, _markdown = build_report(args, policies)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if args.l2_scaffold and os.environ.get(AUTH_ENV) != "1":
        print("L2_OPENBSD_REFERENCE_SCAFFOLD_NOT_AUTHORIZED", file=sys.stderr)
        return 1
    if report.get("global_status") == "PHASE_3C_E_BLOCKED":
        return 1
    print(f"Phase 3C-E: {report['global_status']}")
    print(f"- output: {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
