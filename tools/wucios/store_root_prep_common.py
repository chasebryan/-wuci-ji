#!/usr/bin/env python3
"""Shared helpers for WuciOS Phase 3C-C store-root preparation policy."""

from __future__ import annotations

import json
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PHASE_ID = "euclid-trial-phase-3c-c"
CANDIDATES = ["nixos_store_root", "guix_store_root"]
DISPLAY_NAMES = {
    "nixos_store_root": "NixOS Store Root",
    "guix_store_root": "Guix Store Root",
}
DECLARATIVE_INPUT_MANIFESTS = {
    "nixos_store_root": [
        "wucios/buildrooms/store-root/nixos_store_root/declarative-input-manifest.json",
        "wucios/buildrooms/store-root/nixos_store_root/nixos-input-policy.json",
    ],
    "guix_store_root": [
        "wucios/buildrooms/store-root/guix_store_root/declarative-input-manifest.json",
        "wucios/buildrooms/store-root/guix_store_root/guix-input-policy.json",
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
    """Detect tools with PATH lookup only; do not execute Nix, Guix, or runtime tools."""
    commands = ["nix", "guix", "docker", "podman", "buildah", "qemu-system-x86_64", "qemu-img"]
    detections = {name: command_detection(name) for name in commands}
    summary = {name: info["status"] for name, info in detections.items()}
    return {
        "schema": "wucios.euclid.phase3c_c.static_tool_detection.v1",
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


def detect_declarative_inputs(candidate: str, policy: dict[str, Any]) -> dict[str, Any]:
    detected = []
    for relative in DECLARATIVE_INPUT_MANIFESTS[candidate]:
        path = ROOT / relative
        if path.is_file():
            detected.append(normalize_path(path))
    missing = list(policy.get("required_inputs", []))
    if detected:
        missing = [item for item in missing if "policy" not in item.lower()]
    return {
        "detected_inputs": detected,
        "missing_inputs": missing,
    }


def normalize_candidate_status(missing_inputs: list[str], scaffold_generated: bool) -> str:
    if scaffold_generated:
        return "PREP_DECLARATIVE_SCAFFOLD_GENERATED"
    if missing_inputs:
        return "PREP_DECLARATIVE_INPUTS_MISSING"
    return "PREP_RULES_DEFINED"


def validate_declarative_input_policy(policy: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if policy.get("status") != "POLICY_ONLY_NOT_EXECUTABLE":
        failures.append("declarative-input-policy.json must be policy-only")
    if policy.get("inputs_evaluated_in_phase_3c_c") is not False:
        failures.append("declarative inputs must not be evaluated in Phase 3C-C")
    if policy.get("inputs_realized_in_phase_3c_c") is not False:
        failures.append("declarative inputs must not be realized in Phase 3C-C")
    if policy.get("network_allowed_in_phase_3c_c") is not False:
        failures.append("Phase 3C-C declarative input policy must disable network")
    candidates = policy.get("candidates", {})
    for candidate in CANDIDATES:
        item = candidates.get(candidate)
        if not isinstance(item, dict):
            failures.append(f"declarative-input-policy.json missing {candidate}")
            continue
        if item.get("future_level_required") != "L3":
            failures.append(f"{candidate} declarative input policy must require future L3")
        forbidden = "\n".join(str(entry) for entry in item.get("forbidden_in_phase_3c_c", []))
        for phrase in [
            "evaluate declarative input",
            "realize store path",
            "use network",
            "generate rootfs",
            "select substrate",
            "rank candidate",
            "generate numeric score",
        ]:
            if phrase not in forbidden:
                failures.append(f"{candidate} declarative input policy must forbid {phrase}")
    return failures


def generate_scaffold(candidate: str, policy: dict[str, Any], declarative_policy: dict[str, Any], evidence: dict[str, Any], root: Path) -> list[str]:
    scaffold_dir = root / candidate / "phase-3c-c/scaffold"
    ensure_directory(scaffold_dir)
    labels = [
        "NOT_EXECUTABLE",
        "NOT_ARTIFACT",
        "NOT_SCORE_ELIGIBLE",
        "STORE_REALIZATION_FORBIDDEN",
        "L3_AUTHORIZATION_REQUIRED",
    ]
    readme = "\n".join([
        f"# {DISPLAY_NAMES[candidate]} Phase 3C-C Scaffold",
        "",
        *labels,
        "",
        "This scaffold is a non-artifact preparation record for future policy review.",
        "It must not be executed, evaluated, built, realized, activated, or scored.",
    ])
    write_markdown(scaffold_dir / "README.md", readme)
    future_command_manifest = {
        "schema": "wucios.euclid.store_root.future_command_manifest.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "POLICY_ONLY_NOT_EXECUTABLE",
        "future_level_required": "L3",
        "commands_execute_in_phase_3c_c": False,
        "forbidden_commands": policy.get("forbidden_commands", []),
        "declarative_input_type": policy.get("declarative_input_type", "NOT_MEASURED"),
    }
    write_json(scaffold_dir / "future-command-manifest.json", future_command_manifest)
    declarative_placeholder = {
        "schema": "wucios.euclid.store_root.declarative_input_placeholder.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_EVALUATED",
        "declarative_input_type": policy.get("declarative_input_type", "NOT_MEASURED"),
        "required_manifest_concepts": declarative_policy.get("candidates", {}).get(candidate, {}).get("required_manifest_concepts", []),
        "inputs_evaluated_in_phase_3c_c": False,
        "inputs_realized_in_phase_3c_c": False,
    }
    write_json(scaffold_dir / "declarative-input-placeholder.json", declarative_placeholder)
    evidence_manifest = {
        "schema": "wucios.euclid.store_root.evidence_placeholder_manifest.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_SUBSTRATE_EVIDENCE",
        "future_required_outputs": evidence.get("future_l3_required_outputs", []),
        "not_generated_in_phase_3c_c": True,
    }
    write_json(scaffold_dir / "evidence-placeholder-manifest.json", evidence_manifest)
    store_policy = {
        "schema": "wucios.euclid.store_root.store_policy_placeholder.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_STORE_REALIZATION_FORBIDDEN",
        "store_realization_allowed": False,
        "derivation_build_allowed": False,
        "package_build_allowed": False,
        "system_activation_allowed": False,
    }
    write_json(scaffold_dir / "store-policy-placeholder.json", store_policy)
    return [
        normalize_path(scaffold_dir / "README.md"),
        normalize_path(scaffold_dir / "future-command-manifest.json"),
        normalize_path(scaffold_dir / "declarative-input-placeholder.json"),
        normalize_path(scaffold_dir / "evidence-placeholder-manifest.json"),
        normalize_path(scaffold_dir / "store-policy-placeholder.json"),
    ]
