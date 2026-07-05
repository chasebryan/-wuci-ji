#!/usr/bin/env python3
"""Shared helpers for WuciOS Phase 3C-B direct-rootfs preparation policy."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CANDIDATES = ["buildroot", "alpine", "debian-minimal", "void"]
DISPLAY_NAMES = {
    "buildroot": "Buildroot",
    "alpine": "Alpine",
    "debian-minimal": "Debian minimal",
    "void": "Void",
}
PHASE_ID = "euclid-trial-phase-3c-b"


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


def safe_command_execution(command: list[str], timeout_seconds: int = 30, cwd: Path | None = None) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd or ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "command": command,
            "returncode": result.returncode,
            "output": (result.stdout or "").strip()[:12000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {
            "command": command,
            "returncode": "TIMEOUT",
            "output": output.strip()[:12000],
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": "OS_ERROR",
            "output": str(exc),
            "timed_out": False,
        }


def backend_status_from_capture(present: bool, capture: dict[str, Any] | None = None) -> str:
    if not present:
        return "BACKEND_ABSENT"
    if capture is None:
        return "BACKEND_PRESENT"
    if capture.get("returncode") == 0:
        return "BACKEND_PRESENT"
    text = str(capture.get("output", "")).lower()
    if "permission denied" in text or "operation not permitted" in text or "access denied" in text:
        return "BACKEND_PERMISSION_BLOCKED"
    if "read-only" in text or "read only" in text or "configuration" in text or "config" in text or "mkdir" in text:
        return "BACKEND_CONFIG_BLOCKED"
    return "BACKEND_USABILITY_UNKNOWN"


def safe_backend_info_capture() -> dict[str, Any]:
    commands = {
        "podman": ["podman", "info"],
        "buildah": ["buildah", "info"],
        "docker": ["docker", "info"],
        "qemu-system-x86_64": ["qemu-system-x86_64", "--version"],
        "qemu-img": ["qemu-img", "--version"],
    }
    backends: dict[str, dict[str, Any]] = {}
    for name, command in commands.items():
        detection = command_detection(name)
        capture = safe_command_execution(command, timeout_seconds=20) if detection["present"] else {
            "command": command,
            "returncode": "NOT_RUN",
            "output": "BINARY_NOT_FOUND",
            "timed_out": False,
        }
        backends[name] = {
            **detection,
            "status": backend_status_from_capture(bool(detection["present"]), capture),
            "probe": capture,
        }
    return {
        "schema": "wucios.euclid.phase3c_b.backend_detection.v1",
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "backends": backends,
    }


def candidate_tool_names(candidate: str) -> list[str]:
    tools = {
        "buildroot": ["make", "git", "tar", "sha256sum", "shasum"],
        "alpine": ["apk", "tar", "sha256sum", "shasum"],
        "debian-minimal": ["debootstrap", "fakeroot", "fakechroot", "tar", "sha256sum", "shasum"],
        "void": ["xbps-install", "xbps-query", "tar", "sha256sum", "shasum"],
    }
    return tools[candidate]


def detect_candidate_tools(candidate: str) -> dict[str, Any]:
    detections = {name: command_detection(name) for name in candidate_tool_names(candidate)}
    present = [name for name, info in detections.items() if info["present"]]
    missing = [name for name, info in detections.items() if not info["present"]]

    if "sha256sum" in detections or "shasum" in detections:
        if detections.get("sha256sum", {}).get("present") or detections.get("shasum", {}).get("present"):
            missing = [name for name in missing if name not in {"sha256sum", "shasum"}]
        else:
            missing = [name for name in missing if name not in {"sha256sum", "shasum"}]
            missing.append("sha256sum-or-shasum")

    if candidate == "debian-minimal":
        if detections.get("fakeroot", {}).get("present") or detections.get("fakechroot", {}).get("present"):
            missing = [name for name in missing if name not in {"fakeroot", "fakechroot"}]
        else:
            missing = [name for name in missing if name not in {"fakeroot", "fakechroot"}]
            missing.append("fakeroot-or-fakechroot")

    return {
        "detections": detections,
        "present": sorted(set(present)),
        "missing": sorted(set(missing)),
    }


def detect_candidate_inputs(candidate: str, policy: dict[str, Any]) -> dict[str, Any]:
    missing = list(policy.get("required_future_inputs", []))
    detected: list[str] = []
    if candidate == "buildroot":
        candidates = [
            os.environ.get("BUILDROOT_DIR", ""),
            "wucios/trials/buildroot/buildroot-src",
            "third_party/buildroot",
            "vendor/buildroot",
        ]
        for item in candidates:
            if item and (ROOT / item).is_dir():
                detected.append(normalize_path(ROOT / item))
        if detected:
            missing = [item for item in missing if "Buildroot source" not in item]
    return {
        "detected_inputs": detected,
        "missing_inputs": missing,
    }


def validate_command_shapes(command_shapes: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if command_shapes.get("status") != "POLICY_ONLY_NOT_EXECUTABLE":
        failures.append("command-shapes.json must be policy-only")
    if command_shapes.get("commands_execute_in_phase_3c_b") is not False:
        failures.append("command-shapes.json must not execute in Phase 3C-B")
    candidates = command_shapes.get("candidates", {})
    for candidate in CANDIDATES:
        item = candidates.get(candidate)
        if not isinstance(item, dict):
            failures.append(f"command-shapes.json missing candidate {candidate}")
            continue
        if item.get("future_level_required") != "L3":
            failures.append(f"{candidate} command shape must require future L3")
        if not isinstance(item.get("command_shapes"), list) or not item.get("command_shapes"):
            failures.append(f"{candidate} command shapes must be descriptive list")
        forbidden = "\n".join(str(entry) for entry in item.get("forbidden_in_phase_3c_b", []))
        for phrase in ["execute command shape", "generate substrate artifact", "generate rootfs", "run container", "use network", "select substrate", "rank candidate", "generate numeric score"]:
            if phrase not in forbidden:
                failures.append(f"{candidate} command shape must forbid {phrase}")
    return failures


def normalize_candidate_status(missing_tools: list[str], missing_inputs: list[str], scaffold_generated: bool) -> str:
    if scaffold_generated:
        return "PREP_SCAFFOLD_GENERATED"
    if missing_inputs:
        return "PREP_INPUTS_MISSING"
    if missing_tools:
        return "PREP_BACKEND_BLOCKED"
    return "PREP_RULES_DEFINED"


def generate_scaffold(candidate: str, policy: dict[str, Any], command_shapes: dict[str, Any], evidence: dict[str, Any], root: Path) -> list[str]:
    scaffold_dir = root / candidate / "phase-3c-b/scaffold"
    ensure_directory(scaffold_dir)
    labels = ["NOT_EXECUTABLE", "NOT_ARTIFACT", "NOT_SCORE_ELIGIBLE", "L3_AUTHORIZATION_REQUIRED"]
    readme = "\n".join([
        f"# {DISPLAY_NAMES[candidate]} Phase 3C-B Scaffold",
        "",
        "NOT_EXECUTABLE",
        "NOT_ARTIFACT",
        "NOT_SCORE_ELIGIBLE",
        "L3_AUTHORIZATION_REQUIRED",
        "",
        "This scaffold is a non-artifact preparation record for future policy review. It is not a rootfs and must not be executed.",
    ])
    write_markdown(scaffold_dir / "README.md", readme)
    command_manifest = {
        "schema": "wucios.euclid.direct_rootfs.future_command_manifest.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "POLICY_ONLY_NOT_EXECUTABLE",
        "future_level_required": "L3",
        "command_shapes": command_shapes.get("candidates", {}).get(candidate, {}).get("command_shapes", []),
        "commands_execute_in_phase_3c_b": False,
    }
    write_json(scaffold_dir / "future-command-manifest.json", command_manifest)
    evidence_manifest = {
        "schema": "wucios.euclid.direct_rootfs.evidence_placeholder_manifest.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "status": "PLACEHOLDER_ONLY_NOT_SUBSTRATE_EVIDENCE",
        "future_required_outputs": evidence.get("future_l3_required_outputs", []),
        "not_generated_in_phase_3c_b": True,
    }
    write_json(scaffold_dir / "evidence-placeholder-manifest.json", evidence_manifest)
    output_paths = {
        "schema": "wucios.euclid.direct_rootfs.output_paths.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "labels": labels,
        "output_root": f"build/wucios/buildrooms/direct-rootfs/{candidate}/phase-3c-b/",
        "future_artifact_candidates": policy.get("future_artifact_candidates", []),
        "phase_3c_b_outputs_are_artifacts": False,
    }
    write_json(scaffold_dir / "output-paths.json", output_paths)
    return [
        normalize_path(scaffold_dir / "README.md"),
        normalize_path(scaffold_dir / "future-command-manifest.json"),
        normalize_path(scaffold_dir / "evidence-placeholder-manifest.json"),
        normalize_path(scaffold_dir / "output-paths.json"),
    ]
