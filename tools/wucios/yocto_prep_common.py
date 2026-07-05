#!/usr/bin/env python3
"""Shared helpers for WuciOS Phase 3C-D Yocto preparation policy."""

from __future__ import annotations

import json
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PHASE_ID = "euclid-trial-phase-3c-d"
CANDIDATES = ["yocto_layer_recipe"]
DISPLAY_NAMES = {
    "yocto_layer_recipe": "Yocto Layer/Recipe",
}
YOCTO_INPUT_MANIFESTS = {
    "yocto_layer_recipe": [
        "wucios/buildrooms/yocto-layer/yocto_layer_recipe/yocto-metadata-input-manifest.json",
        "wucios/buildrooms/yocto-layer/yocto_layer_recipe/layer-identity-manifest.json",
        "wucios/buildrooms/yocto-layer/yocto_layer_recipe/recipe-identity-manifest.json",
    ],
}


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: Any) -> None:
    ensure_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, text: str) -> None:
    ensure_directory(path.parent)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def generated_timestamp() -> str:
    """Return a timestamp for ignored generated outputs only."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def command_detection(command: str) -> dict[str, Any]:
    path = shutil.which(command)
    return {
        "name": command,
        "present": path is not None,
        "path": path or "NOT_FOUND",
        "status": "TOOL_PRESENT" if path else "TOOL_ABSENT",
    }


def safe_static_tool_detection() -> dict[str, Any]:
    """Detect relevant commands with PATH lookup only; do not execute them."""
    commands = [
        "bitbake",
        "devtool",
        "kas",
        "repo",
        "git",
        "curl",
        "wget",
        "docker",
        "podman",
        "buildah",
        "qemu-system-x86_64",
        "qemu-img",
    ]
    detections = {name: command_detection(name) for name in commands}
    summary = {name: info["status"] for name, info in detections.items()}
    return {
        "schema": "wucios.euclid.phase3c_d.static_tool_detection.v1",
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "summary": summary,
        "details": detections,
        "commands_executed": False,
    }


def detect_yocto_inputs(candidate: str, policy: dict[str, Any]) -> dict[str, Any]:
    detected = []
    for relative in YOCTO_INPUT_MANIFESTS[candidate]:
        path = ROOT / relative
        if path.is_file():
            detected.append(normalize_path(path))
    missing = list(policy.get("required_inputs", []))
    if detected:
        missing = [item for item in missing if "manifest" not in item.lower()]
    return {
        "detected_inputs": detected,
        "missing_inputs": missing,
    }


def normalize_candidate_status(missing_inputs: list[str], scaffold_generated: bool) -> str:
    if scaffold_generated:
        return "PREP_YOCTO_SCAFFOLD_GENERATED"
    if missing_inputs:
        return "PREP_YOCTO_INPUTS_MISSING"
    return "PREP_RULES_DEFINED"


def validate_yocto_metadata_policy(policy: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if policy.get("status") != "POLICY_ONLY_NOT_EXECUTABLE":
        failures.append("yocto-metadata-input-policy.json must be policy-only")
    if policy.get("metadata_evaluated_in_phase_3c_d") is not False:
        failures.append("Yocto metadata must not be evaluated in Phase 3C-D")
    if policy.get("build_environment_initialized_in_phase_3c_d") is not False:
        failures.append("Yocto build environment must not be initialized in Phase 3C-D")
    if policy.get("bitbake_invoked_in_phase_3c_d") is not False:
        failures.append("BitBake must not be invoked in Phase 3C-D")
    if policy.get("network_allowed_in_phase_3c_d") is not False:
        failures.append("Phase 3C-D Yocto metadata policy must disable network")
    candidates = policy.get("candidates", {})
    for candidate in CANDIDATES:
        item = candidates.get(candidate)
        if not isinstance(item, dict):
            failures.append(f"yocto-metadata-input-policy.json missing {candidate}")
            continue
        if item.get("future_level_required") != "L3":
            failures.append(f"{candidate} Yocto metadata policy must require future L3")
        forbidden = "\n".join(str(entry) for entry in item.get("forbidden_in_phase_3c_d", []))
        for phrase in [
            "execute bitbake",
            "initialize build environment",
            "clone Yocto source or layers",
            "download Yocto source, layer, SDK, toolchain, mirror, or image",
            "generate rootfs",
            "generate image",
            "generate artifact",
            "select substrate",
            "rank candidate",
            "generate numeric score",
        ]:
            if phrase not in forbidden:
                failures.append(f"{candidate} Yocto metadata policy must forbid {phrase}")
    return failures


def generate_scaffold(candidate: str, policy: dict[str, Any], metadata_policy: dict[str, Any], evidence: dict[str, Any], root: Path) -> list[str]:
    scaffold_dir = root / candidate / "phase-3c-d/scaffold"
    ensure_directory(scaffold_dir)
    labels = [
        "NOT_EXECUTABLE",
        "NOT_ARTIFACT",
        "NOT_SCORE_ELIGIBLE",
        "YOCTO_BUILD_FORBIDDEN",
        "BITBAKE_FORBIDDEN",
        "L3_AUTHORIZATION_REQUIRED",
    ]
    readme = "\n".join([
        f"# {DISPLAY_NAMES[candidate]} Phase 3C-D Scaffold",
        "",
        *labels,
        "",
        "This scaffold is a non-artifact preparation record for future policy review.",
        "It must not be executed, initialized, cloned, downloaded, built, imaged, or scored.",
    ])
    write_markdown(scaffold_dir / "README.md", readme)
    future_command_manifest = {
        "schema": "wucios.euclid.yocto.future_command_manifest.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "POLICY_ONLY_NOT_EXECUTABLE",
        "future_level_required": "L3",
        "commands_execute_in_phase_3c_d": False,
        "forbidden_commands": policy.get("forbidden_commands", []),
        "yocto_input_type": policy.get("yocto_input_type", "NOT_MEASURED"),
    }
    write_json(scaffold_dir / "future-command-manifest.json", future_command_manifest)
    metadata_placeholder = {
        "schema": "wucios.euclid.yocto.metadata_input_placeholder.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_EVALUATED",
        "yocto_input_type": policy.get("yocto_input_type", "NOT_MEASURED"),
        "required_manifest_concepts": metadata_policy.get("candidates", {}).get(candidate, {}).get("required_manifest_concepts", []),
        "metadata_evaluated_in_phase_3c_d": False,
        "build_environment_initialized_in_phase_3c_d": False,
        "bitbake_invoked_in_phase_3c_d": False,
    }
    write_json(scaffold_dir / "yocto-metadata-input-placeholder.json", metadata_placeholder)
    evidence_manifest = {
        "schema": "wucios.euclid.yocto.evidence_placeholder_manifest.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_SUBSTRATE_EVIDENCE",
        "future_required_outputs": evidence.get("future_l3_required_outputs", []),
        "not_generated_in_phase_3c_d": True,
    }
    write_json(scaffold_dir / "evidence-placeholder-manifest.json", evidence_manifest)
    output_policy = {
        "schema": "wucios.euclid.yocto.output_policy_placeholder.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_YOCTO_BUILD_FORBIDDEN",
        "bitbake_execution_allowed": False,
        "build_environment_initialization_allowed": False,
        "yocto_build_allowed": False,
        "rootfs_generation_allowed": False,
        "image_generation_allowed": False,
    }
    write_json(scaffold_dir / "yocto-output-policy-placeholder.json", output_policy)
    return [
        normalize_path(scaffold_dir / "README.md"),
        normalize_path(scaffold_dir / "future-command-manifest.json"),
        normalize_path(scaffold_dir / "yocto-metadata-input-placeholder.json"),
        normalize_path(scaffold_dir / "evidence-placeholder-manifest.json"),
        normalize_path(scaffold_dir / "yocto-output-policy-placeholder.json"),
    ]
