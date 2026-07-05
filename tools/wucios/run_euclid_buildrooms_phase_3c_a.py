#!/usr/bin/env python3
"""Run WuciOS Euclid Phase 3C-A backend smoke guardrails."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from synthetic_smoke_common import (
    ROOT,
    backend_info_capture,
    cleanup_image,
    create_synthetic_context,
    ensure_directory,
    generated_timestamp,
    load_json,
    normalize_path,
    read_iidfile,
    safe_command_execution,
    sha256_file,
    validate_build_command,
    validate_containerfile,
    write_json,
    write_markdown,
)


PHASE_ID = "euclid-trial-phase-3c-a"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 3C-A — Rootless Backend Smoke and Buildroom Preparation Guardrails"
AUTH_ENV = "WUCIOS_PHASE3CA_ALLOW_L2_SMOKE"
ALLOWED_BACKENDS = ["podman", "buildah"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print combined JSON after writing reports")
    parser.add_argument("--l2-smoke", action="store_true", help="Request authorized L2 synthetic smoke")
    parser.add_argument("--backend", action="append", choices=ALLOWED_BACKENDS)
    parser.add_argument("--output-dir", default="build/wucios/review")
    parser.add_argument("--buildroom-output-dir", default="build/wucios/buildrooms/synthetic-smoke/phase-3c-a")
    parser.add_argument("--buildrooms-dir", default="wucios/buildrooms")
    parser.add_argument("--guardrails", action="store_true", help="Run Phase 3C-A negative guardrail tests")
    return parser.parse_args()


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("phase_id") != PHASE_ID:
        raise SystemExit("Phase 3C-A plan has wrong phase_id")
    if plan.get("phase_name") != PHASE_NAME:
        raise SystemExit("Phase 3C-A plan has wrong phase_name")
    if plan.get("default_execution_mode") != "L1_SAFE_BACKEND_DETECTION":
        raise SystemExit("Phase 3C-A plan must default to L1 safe backend detection")
    if plan.get("l2_synthetic_smoke_authorized_by_default") is not False:
        raise SystemExit("Phase 3C-A plan must disable L2 smoke by default")
    if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
        raise SystemExit("Phase 3C-A plan must preserve NO_SUBSTRATE_SELECTED")
    for key in [
        "ranking_allowed",
        "emotional_testing_allowed",
        "image_pulls_allowed",
        "substrate_artifact_attempts_allowed",
        "runtime_inspection_allowed",
        "container_runs_allowed",
        "vm_runs_allowed",
        "sudo_allowed",
        "host_package_install_allowed",
    ]:
        if plan.get(key) is not False:
            raise SystemExit(f"Phase 3C-A plan must set {key} false")


def validate_buildroom(buildroom: dict[str, Any]) -> None:
    if buildroom.get("phase_id") != PHASE_ID:
        raise SystemExit("synthetic smoke buildroom has wrong phase_id")
    if buildroom.get("id") != "synthetic-smoke":
        raise SystemExit("synthetic smoke buildroom has wrong id")
    for key in ["is_substrate", "is_wucios_artifact", "score_eligible", "base_image_pull_required", "network_required", "substrate_inputs_required", "container_run_required", "vm_required"]:
        if buildroom.get(key) is not False:
            raise SystemExit(f"synthetic smoke buildroom must set {key} false")
    if buildroom.get("base_image") != "scratch":
        raise SystemExit("synthetic smoke buildroom must use scratch")
    if "docker" not in buildroom.get("forbidden_backends", []):
        raise SystemExit("synthetic smoke buildroom must forbid Docker")


def backend_summary(detection: dict[str, Any]) -> dict[str, str]:
    backends = detection.get("backends", {})
    qemu_system = str(backends.get("qemu-system-x86_64", {}).get("status", "BACKEND_ABSENT"))
    qemu_img = str(backends.get("qemu-img", {}).get("status", "BACKEND_ABSENT"))
    qemu = "BACKEND_PRESENT" if qemu_system == "BACKEND_PRESENT" and qemu_img == "BACKEND_PRESENT" else "BACKEND_BLOCKED"
    return {
        "podman": str(backends.get("podman", {}).get("status", "BACKEND_ABSENT")),
        "buildah": str(backends.get("buildah", {}).get("status", "BACKEND_ABSENT")),
        "docker": str(backends.get("docker", {}).get("status", "BACKEND_ABSENT")),
        "qemu": qemu,
        "qemu-system-x86_64": qemu_system,
        "qemu-img": qemu_img,
        "kvm": str(backends.get("kvm", {}).get("status", "KVM_ABSENT")),
    }


def smoke_command(backend: str, tag: str, iidfile: Path, containerfile: Path, context_dir: Path) -> list[str]:
    if backend == "podman":
        return [
            "podman",
            "build",
            "--pull=never",
            "--network=none",
            "--format",
            "oci",
            "--iidfile",
            str(iidfile),
            "-t",
            tag,
            "-f",
            str(containerfile),
            str(context_dir),
        ]
    return [
        "buildah",
        "bud",
        "--pull-never",
        "--network=none",
        "--format",
        "oci",
        "--iidfile",
        str(iidfile),
        "-t",
        tag,
        "-f",
        str(containerfile),
        str(context_dir),
    ]


def inspect_command(backend: str, tag: str) -> list[str]:
    if backend == "podman":
        return ["podman", "image", "inspect", tag]
    return ["buildah", "inspect", "--type", "image", tag]


def archive_command(backend: str, tag: str, archive: Path) -> list[str]:
    if backend == "podman":
        return ["podman", "save", "--format", "oci-archive", "-o", str(archive), tag]
    return ["buildah", "push", "--format", "oci", tag, f"oci-archive:{archive}:{tag}"]


def run_smoke_backend(backend: str, detection: dict[str, Any], context_dir: Path, backend_dir: Path) -> dict[str, Any]:
    backends = detection.get("backends", {})
    backend_detection = backends.get(backend, {})
    ensure_directory(backend_dir)
    tag = f"localhost/wucios-phase3ca-synthetic-smoke:{backend}"
    iidfile = backend_dir / "synthetic-image-iid.txt"
    containerfile = context_dir / "Containerfile"
    archive = backend_dir / "synthetic-image.oci-archive"
    build_log = backend_dir / "build-log.txt"
    cleanup_log = backend_dir / "cleanup-log.txt"

    result: dict[str, Any] = {
        "backend": backend,
        "attempted": False,
        "succeeded": False,
        "status": "BACKEND_NOT_ATTEMPTED",
        "tag": tag,
        "image_id": "NOT_MEASURED",
        "synthetic_smoke_archive_sha256": "NOT_EXPORTED",
        "outputs": [],
        "is_wucios_artifact": False,
        "is_substrate_artifact": False,
        "score_eligible": False,
    }

    if backend_detection.get("status") != "BACKEND_PRESENT":
        result["status"] = str(backend_detection.get("status", "BACKEND_ABSENT"))
        return result

    command = smoke_command(backend, tag, iidfile, containerfile, context_dir)
    command_failures = validate_build_command(backend, command)
    if command_failures:
        result["status"] = "BACKEND_L2_SMOKE_UNSUPPORTED_SAFE_FLAGS"
        result["guardrail_failures"] = command_failures
        return result

    result["attempted"] = True
    build = safe_command_execution(command, timeout_seconds=120)
    write_json(build_log, build)
    result["build"] = build
    result["outputs"].append(normalize_path(build_log))
    if build.get("returncode") != 0:
        result["status"] = "L2_SMOKE_BUILD_FAILED"
        return result

    image_id = read_iidfile(iidfile)
    result["image_id"] = image_id
    if iidfile.is_file():
        result["outputs"].append(normalize_path(iidfile))

    inspect = safe_command_execution(inspect_command(backend, tag), timeout_seconds=60)
    inspect_path = backend_dir / "synthetic-image-inspect.json"
    write_json(inspect_path, inspect)
    result["inspect"] = inspect
    result["outputs"].append(normalize_path(inspect_path))

    archive_result = safe_command_execution(archive_command(backend, tag, archive), timeout_seconds=120)
    archive_log = backend_dir / "archive-log.txt"
    write_json(archive_log, archive_result)
    result["archive"] = archive_result
    result["outputs"].append(normalize_path(archive_log))
    if archive_result.get("returncode") == 0 and archive.is_file():
        result["synthetic_smoke_archive_sha256"] = sha256_file(archive)
        archive_hash_path = backend_dir / "synthetic-image-archive.sha256"
        archive_hash_path.write_text(f"{result['synthetic_smoke_archive_sha256']}  {archive.name}\n", encoding="utf-8")
        result["outputs"].extend([normalize_path(archive), normalize_path(archive_hash_path)])

    cleanup = cleanup_image(backend, tag, cleanup_log)
    result["cleanup"] = cleanup
    result["outputs"].append(normalize_path(cleanup_log))
    if cleanup.get("returncode") != 0:
        result["status"] = "SYNTHETIC_IMAGE_CLEANUP_FAILED"
        return result

    result["succeeded"] = True
    result["status"] = "L2_SMOKE_SUCCEEDED"
    return result


def run_guardrails(output_root: Path) -> dict[str, Any]:
    guardrail_dir = output_root / "guardrail-tests/phase-3c-a"
    ensure_directory(guardrail_dir)
    env = os.environ.copy()
    env.pop(AUTH_ENV, None)
    env.pop("WUCIOS_EUCLID_ALLOW_ATTEMPT", None)

    l2 = subprocess.run(
        ["make", "wucios-euclid-buildrooms-phase-3c-a-smoke"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (guardrail_dir / "l2-smoke-without-authorization.log").write_text(l2.stdout or "", encoding="utf-8")
    (guardrail_dir / "l2-smoke-without-authorization.exitcode").write_text(f"{l2.returncode}\n", encoding="utf-8")

    phase2 = subprocess.run(
        ["make", "wucios-euclid-trial-phase-2-attempt"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (guardrail_dir / "phase-2-attempt-without-authorization.log").write_text(phase2.stdout or "", encoding="utf-8")
    (guardrail_dir / "phase-2-attempt-without-authorization.exitcode").write_text(f"{phase2.returncode}\n", encoding="utf-8")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    safe_targets = [
        "wucios-euclid-buildrooms-phase-3c-a",
        "wucios-euclid-buildrooms-phase-3c-a-json",
        "wucios-euclid-buildrooms-phase-3c-a-guardrails",
        "wucios-idempotence-check",
        "wucios-review",
    ]
    forbidden = [
        "podman run",
        "buildah run",
        "docker run",
        "docker build",
        "qemu-system-x86_64 ",
        "WUCIOS_EUCLID_ALLOW_ATTEMPT=1",
        "WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1",
    ]
    recipe_hits: list[str] = []
    lines = makefile.splitlines()
    for index, line in enumerate(lines):
        if not any(line.startswith(f"{target}:") for target in safe_targets):
            continue
        target = line.split(":", 1)[0]
        cursor = index + 1
        while cursor < len(lines) and (lines[cursor].startswith("\t") or not lines[cursor].strip()):
            recipe_line = lines[cursor]
            if recipe_line.startswith("\t"):
                for token in forbidden:
                    if token in recipe_line:
                        recipe_hits.append(f"{target}:{cursor + 1}: {token.strip()}")
            cursor += 1
    (guardrail_dir / "default-safe-target-scan.txt").write_text("\n".join(recipe_hits) + ("\n" if recipe_hits else ""), encoding="utf-8")

    checks = {
        "l2_smoke_without_authorization_blocked": l2.returncode != 0,
        "phase_2_attempt_without_authorization_blocked": phase2.returncode != 0,
        "default_safe_targets_forbidden_execution_absent": not recipe_hits,
    }
    status = "GUARDRAILS_PASS" if all(checks.values()) else "GUARDRAILS_FAIL"
    payload = {
        "schema": "wucios.euclid.phase3c_a.guardrails.v1",
        "phase_id": PHASE_ID,
        "status": status,
        "checks": checks,
        "l2_smoke_without_authorization_exitcode": l2.returncode,
        "phase_2_attempt_without_authorization_exitcode": phase2.returncode,
        "default_safe_target_hits": recipe_hits,
        "generated_utc": generated_timestamp(),
    }
    write_json(guardrail_dir / "guardrails.json", payload)
    write_markdown(
        guardrail_dir / "guardrails.md",
        "\n".join([
            "# Phase 3C-A Guardrail Tests",
            "",
            f"Status: {status}",
            f"L2 smoke without authorization blocked: `{str(checks['l2_smoke_without_authorization_blocked']).lower()}`",
            f"Phase 2 attempt without authorization blocked: `{str(checks['phase_2_attempt_without_authorization_blocked']).lower()}`",
            f"Default safe targets free of forbidden execution: `{str(checks['default_safe_targets_forbidden_execution_absent']).lower()}`",
        ]),
    )
    return payload


def markdown_report(payload: dict[str, Any]) -> str:
    backend = payload.get("l1_backend_detection", {}).get("summary", {})
    smoke = payload.get("l2_synthetic_smoke", {})
    podman = smoke.get("podman", {})
    buildah = smoke.get("buildah", {})
    lines = [
        f"# {PHASE_NAME}",
        "",
        f"Global Status: {payload['global_status']}",
        f"Execution Mode: {payload['execution_mode']}",
        "Substrate Selection: NO_SUBSTRATE_SELECTED",
        "WuciOS Score: NO_ARTIFACT_SCORE",
        "WuciOS Artifact Generated: false",
        "Substrate Artifact Attempt: false",
        "Runtime Inspection: false",
        "Image Pulls: none",
        "Container Runs: none",
        "VM Runs: none",
        "Network: disabled",
        "",
        "## Purpose",
        "",
        "Phase 3C-A verifies rootless backend mechanics and buildroom preparation guardrails using a synthetic non-substrate smoke image.",
        "",
        "## Build Room Rule",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        "## Authorization Boundary",
        "",
        "L1 backend detection is authorized by default. L2 synthetic smoke is authorized only when the smoke target or runner flag is used with `WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1`. L3 substrate artifact attempts and L4 runtime inspection are not authorized.",
        "",
        "## Synthetic Smoke Boundary",
        "",
        "The synthetic smoke image is not a WuciOS artifact, not a substrate artifact, and not score eligible.",
        "",
        "## Backend Findings",
        "",
        f"- Podman: `{backend.get('podman', 'NOT_MEASURED')}`",
        f"- Buildah: `{backend.get('buildah', 'NOT_MEASURED')}`",
        f"- Docker: `{backend.get('docker', 'NOT_MEASURED')}` detection only",
        f"- QEMU: `{backend.get('qemu', 'NOT_MEASURED')}` version context only",
        f"- KVM: `{backend.get('kvm', 'NOT_MEASURED')}` context only",
        "",
        "## L2 Synthetic Smoke Results",
        "",
        f"- Authorized: `{str(smoke.get('authorized', False)).lower()}`",
        f"- Attempted: `{str(smoke.get('attempted', False)).lower()}`",
        f"- Podman: `{podman.get('status', 'NOT_ATTEMPTED')}`",
        f"- Buildah: `{buildah.get('status', 'NOT_ATTEMPTED')}`",
        "",
        "## Guardrail Results",
        "",
    ]
    for guardrail in payload.get("guardrails", []):
        lines.append(f"- `{guardrail.get('status', 'UNKNOWN')}`: {guardrail.get('name', guardrail.get('message', ''))}")
    if not payload.get("guardrails"):
        lines.append("- No guardrail failure detected by this run.")
    lines.extend(
        [
            "",
            "## Non-Selection Statement",
            "",
            "No substrate is selected in Phase 3C-A. Backend smoke success is not substrate ranking.",
            "",
            "## Score Statement",
            "",
            "No numeric WuciOS score is generated in Phase 3C-A because no current WuciOS artifact and complete artifact-bound evidence exist.",
            "",
            "## Boundary Statement",
            "",
            "No substrate artifact attempt was made. No runtime inspection was attempted. No container was run. No VM was launched. No image was pulled. No source tree was cloned. No OS image was downloaded. No sudo was used. No package installation was attempted.",
            "",
        ]
    )
    return "\n".join(lines)


def build_payload(
    args: argparse.Namespace,
    detection: dict[str, Any],
    context_manifest: dict[str, Any],
    l2: dict[str, Any],
    guardrails: list[dict[str, Any]],
    notes: list[str],
) -> dict[str, Any]:
    authorized = os.environ.get(AUTH_ENV) == "1"
    if args.l2_smoke and not authorized:
        global_status = "PHASE_3C_A_BLOCKED"
        execution_mode = "L2_SMOKE_NOT_AUTHORIZED"
    elif args.l2_smoke:
        succeeded = any(l2.get(name, {}).get("succeeded") is True for name in ALLOWED_BACKENDS)
        global_status = "PHASE_3C_A_L2_SMOKE_COMPLETE" if succeeded else "PHASE_3C_A_PARTIAL"
        execution_mode = "L2_SYNTHETIC_SMOKE_AUTHORIZED"
    else:
        global_status = "PHASE_3C_A_L1_COMPLETE"
        execution_mode = "L1_SAFE_BACKEND_DETECTION"

    return {
        "schema": "wucios.euclid.phase3c_a.v1",
        "phase_id": PHASE_ID,
        "phase_name": PHASE_NAME,
        "global_status": global_status,
        "execution_mode": execution_mode,
        "substrate_selection": "NO_SUBSTRATE_SELECTED",
        "ranking_allowed": False,
        "numeric_wucios_score_generated": False,
        "score_status": "NO_ARTIFACT_SCORE",
        "wucios_artifact_generated": False,
        "substrate_artifact_attempt_made": False,
        "runtime_inspection_attempted": False,
        "container_pull_attempted": False,
        "container_run_attempted": False,
        "vm_run_attempted": False,
        "sudo_used": False,
        "package_installation_attempted": False,
        "source_clone_attempted": False,
        "image_download_attempted": False,
        "network_used": False,
        "generated_utc": generated_timestamp(),
        "l1_backend_detection": {
            "summary": backend_summary(detection),
            "details": detection,
        },
        "l2_synthetic_smoke": {
            "authorized": authorized and args.l2_smoke,
            "attempted": bool(args.l2_smoke and authorized),
            "podman": l2.get("podman", {}),
            "buildah": l2.get("buildah", {}),
        },
        "synthetic_outputs": [context_manifest],
        "guardrails": guardrails,
        "notes": notes,
    }


def main() -> int:
    args = parse_args()
    output_dir = ROOT / args.output_dir
    buildroom_output_dir = ROOT / args.buildroom_output_dir
    buildrooms_dir = ROOT / args.buildrooms_dir
    ensure_directory(output_dir)
    ensure_directory(buildroom_output_dir)

    if args.guardrails:
        payload = run_guardrails(output_dir)
        print(f"Phase 3C-A guardrails: {payload['status']}")
        return 0 if payload["status"] == "GUARDRAILS_PASS" else 1

    plan = load_json(buildrooms_dir / "euclid-buildrooms-phase-3c-a.json")
    buildroom = load_json(buildrooms_dir / "synthetic-smoke/synthetic-smoke-buildroom.json")
    validate_plan(plan)
    validate_buildroom(buildroom)

    context_dir = buildroom_output_dir / "context"
    context_manifest = create_synthetic_context(context_dir, buildrooms_dir / "synthetic-smoke/Containerfile.template")
    containerfile_failures = validate_containerfile(context_dir / "Containerfile")
    guardrails: list[dict[str, Any]] = []
    notes: list[str] = [
        "Synthetic smoke image is not a WuciOS artifact.",
        "Synthetic smoke image is not a substrate artifact.",
        "Synthetic smoke image is not score eligible.",
    ]
    if containerfile_failures:
        guardrails.extend({"status": "GUARDRAIL_FAILURE", "name": "containerfile_validation", "message": item} for item in containerfile_failures)

    detection = backend_info_capture()
    l2: dict[str, Any] = {"podman": {}, "buildah": {}}

    authorized = os.environ.get(AUTH_ENV) == "1"
    exit_code = 0
    if authorized and not args.l2_smoke:
        notes.append("L2_SMOKE_ENV_PRESENT_BUT_FLAG_ABSENT")
    if args.l2_smoke and not authorized:
        notes.append("L2_SMOKE_NOT_AUTHORIZED")
        exit_code = 2
    elif args.l2_smoke and authorized and not guardrails:
        selected = args.backend or ALLOWED_BACKENDS
        for backend in selected:
            l2[backend] = run_smoke_backend(backend, detection, context_dir, buildroom_output_dir / backend)
    elif args.l2_smoke and guardrails:
        exit_code = 3

    payload = build_payload(args, detection, context_manifest, l2, guardrails, notes)
    write_json(output_dir / "euclid-trial-phase-3c-a.json", payload)
    write_markdown(output_dir / "euclid-trial-phase-3c-a.md", markdown_report(payload))
    write_json(buildroom_output_dir / "backend-smoke.json", payload["l2_synthetic_smoke"])
    write_json(buildroom_output_dir / "status.json", payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Euclid Trial Phase 3C-A: {payload['global_status']}")
        print(f"- execution: {payload['execution_mode']}")
        print("- selection: NO_SUBSTRATE_SELECTED")
        print("- score: NO_ARTIFACT_SCORE")
        print(f"- report: {normalize_path(output_dir / 'euclid-trial-phase-3c-a.md')}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
