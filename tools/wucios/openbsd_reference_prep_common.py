#!/usr/bin/env python3
"""Shared helpers for WuciOS Phase 3C-E OpenBSD reference preparation."""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PHASE_ID = "euclid-trial-phase-3c-e"
REFERENCES = ["openbsd_reference"]
DISPLAY_NAMES = {
    "openbsd_reference": "OpenBSD Reference",
}
OPENBSD_REFERENCE_INPUT_MANIFESTS = {
    "openbsd_reference": [
        "wucios/buildrooms/openbsd-reference/openbsd_reference/openbsd-reference-input-manifest.json",
        "wucios/buildrooms/openbsd-reference/openbsd_reference/openbsd-media-identity-manifest.json",
        "wucios/buildrooms/openbsd-reference/openbsd_reference/openbsd-runtime-policy-manifest.json",
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


def safe_static_context() -> dict[str, Any]:
    """Capture host context without executing OpenBSD, VM, package, or network tools."""
    return {
        "schema": "wucios.euclid.phase3c_e.static_context.v1",
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "tool_execution_performed": False,
        "openbsd_runtime_inspection_performed": False,
    }


def detect_openbsd_reference_inputs(reference: str, policy: dict[str, Any]) -> dict[str, Any]:
    detected = []
    for relative in OPENBSD_REFERENCE_INPUT_MANIFESTS[reference]:
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


def normalize_reference_status(missing_inputs: list[str], scaffold_generated: bool) -> str:
    if scaffold_generated:
        return "PREP_OPENBSD_REFERENCE_SCAFFOLD_GENERATED"
    if missing_inputs:
        return "PREP_OPENBSD_REFERENCE_INPUTS_MISSING"
    return "PREP_RULES_DEFINED"


def validate_openbsd_reference_input_policy(policy: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if policy.get("status") != "POLICY_ONLY_NOT_EXECUTABLE":
        failures.append("openbsd-reference-input-policy.json must be policy-only")
    for key in [
        "reference_inputs_evaluated_in_phase_3c_e",
        "openbsd_runtime_inspected_in_phase_3c_e",
        "openbsd_install_boot_or_package_command_invoked_in_phase_3c_e",
        "network_allowed_in_phase_3c_e",
    ]:
        if policy.get(key) is not False:
            failures.append(f"OpenBSD reference input policy must set {key} false")
    references = policy.get("references", {})
    for reference in REFERENCES:
        item = references.get(reference)
        if not isinstance(item, dict):
            failures.append(f"openbsd-reference-input-policy.json missing {reference}")
            continue
        if item.get("future_level_required") != "L3_OR_L4":
            failures.append(f"{reference} OpenBSD reference input policy must require future L3 or L4")
        forbidden = "\n".join(str(entry) for entry in item.get("forbidden_in_phase_3c_e", []))
        for phrase in [
            "install OpenBSD",
            "boot OpenBSD",
            "inspect OpenBSD runtime behavior",
            "execute package or admin command",
            "clone OpenBSD source or mirror",
            "download OpenBSD media, sets, packages, ports, snapshots, signatures, source archives, or mirrors",
            "launch VM",
            "use qemu or hypervisor tooling",
            "generate rootfs",
            "generate image",
            "generate artifact",
            "select substrate",
            "rank candidate",
            "generate numeric score",
        ]:
            if phrase not in forbidden:
                failures.append(f"{reference} OpenBSD reference input policy must forbid {phrase}")
    return failures


def generate_scaffold(reference: str, policy: dict[str, Any], input_policy: dict[str, Any], evidence: dict[str, Any], root: Path) -> list[str]:
    scaffold_dir = root / reference / "phase-3c-e/scaffold"
    ensure_directory(scaffold_dir)
    labels = [
        "NOT_EXECUTABLE",
        "NOT_ARTIFACT",
        "NOT_SCORE_ELIGIBLE",
        "OPENBSD_RUNTIME_FORBIDDEN",
        "OPENBSD_INSTALL_FORBIDDEN",
        "OPENBSD_DOWNLOAD_FORBIDDEN",
        "SUBSTRATE_SELECTION_FORBIDDEN",
        "L3_AUTHORIZATION_REQUIRED",
    ]
    readme = "\n".join([
        f"# {DISPLAY_NAMES[reference]} Phase 3C-E Scaffold",
        "",
        *labels,
        "",
        "This scaffold is a non-artifact reference preparation record for future policy review.",
        "It must not be executed, booted, installed, downloaded, cloned, packaged, virtualized, imaged, inspected, selected, ranked, or scored.",
    ])
    write_markdown(scaffold_dir / "README.md", readme)
    future_command_manifest = {
        "schema": "wucios.euclid.openbsd_reference.future_command_manifest.v1",
        "phase_id": PHASE_ID,
        "reference": reference,
        "labels": labels,
        "status": "POLICY_ONLY_NOT_EXECUTABLE",
        "future_level_required": "L3_OR_L4",
        "commands_execute_in_phase_3c_e": False,
        "forbidden_commands": policy.get("forbidden_commands", []),
        "openbsd_reference_input_type": policy.get("openbsd_reference_input_type", "NOT_MEASURED"),
    }
    write_json(scaffold_dir / "future-command-manifest.json", future_command_manifest)
    reference_placeholder = {
        "schema": "wucios.euclid.openbsd_reference.input_placeholder.v1",
        "phase_id": PHASE_ID,
        "reference": reference,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_EVALUATED",
        "openbsd_reference_input_type": policy.get("openbsd_reference_input_type", "NOT_MEASURED"),
        "required_manifest_concepts": input_policy.get("references", {}).get(reference, {}).get("required_manifest_concepts", []),
        "reference_inputs_evaluated_in_phase_3c_e": False,
        "openbsd_runtime_inspected_in_phase_3c_e": False,
        "openbsd_install_boot_or_package_command_invoked_in_phase_3c_e": False,
    }
    write_json(scaffold_dir / "openbsd-reference-input-placeholder.json", reference_placeholder)
    evidence_manifest = {
        "schema": "wucios.euclid.openbsd_reference.evidence_placeholder_manifest.v1",
        "phase_id": PHASE_ID,
        "reference": reference,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_SUBSTRATE_EVIDENCE",
        "future_required_outputs": evidence.get("future_l3_or_l4_required_outputs", []),
        "not_generated_in_phase_3c_e": True,
    }
    write_json(scaffold_dir / "evidence-placeholder-manifest.json", evidence_manifest)
    output_policy = {
        "schema": "wucios.euclid.openbsd_reference.output_policy_placeholder.v1",
        "phase_id": PHASE_ID,
        "reference": reference,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_OPENBSD_RUNTIME_FORBIDDEN",
        "openbsd_boot_allowed": False,
        "openbsd_install_allowed": False,
        "openbsd_package_admin_allowed": False,
        "source_clone_allowed": False,
        "install_media_download_allowed": False,
        "vm_launch_allowed": False,
        "rootfs_generation_allowed": False,
        "image_generation_allowed": False,
        "substrate_selection_allowed": False,
    }
    write_json(scaffold_dir / "openbsd-output-policy-placeholder.json", output_policy)
    return [
        normalize_path(scaffold_dir / "README.md"),
        normalize_path(scaffold_dir / "future-command-manifest.json"),
        normalize_path(scaffold_dir / "openbsd-reference-input-placeholder.json"),
        normalize_path(scaffold_dir / "evidence-placeholder-manifest.json"),
        normalize_path(scaffold_dir / "openbsd-output-policy-placeholder.json"),
    ]
