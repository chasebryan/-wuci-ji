#!/usr/bin/env python3
"""Shared helpers for WuciOS Phase 3C-A synthetic backend smoke."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


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
        "status": "BACKEND_PRESENT" if path else "BACKEND_ABSENT",
    }


def safe_command_execution(command: list[str], timeout_seconds: int = 60, cwd: Path | None = None) -> dict[str, Any]:
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


def backend_info_capture() -> dict[str, Any]:
    commands = {
        "podman": ["podman", "info"],
        "buildah": ["buildah", "info"],
        "docker": ["docker", "info"],
        "qemu-system-x86_64": ["qemu-system-x86_64", "--version"],
        "qemu-img": ["qemu-img", "--version"],
    }
    backends: dict[str, dict[str, Any]] = {}
    commands_out: dict[str, dict[str, Any]] = {}
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
        commands_out[" ".join(command)] = capture

    for name in ["apk", "debootstrap", "fakeroot", "fakechroot", "xbps-install", "xbps-query", "bitbake", "nix", "guix"]:
        detection = command_detection(name)
        backends[name] = {
            **detection,
            "probe": {
                "command": ["command", "-v", name],
                "returncode": 0 if detection["present"] else 1,
                "output": detection["path"] if detection["present"] else "BINARY_NOT_FOUND",
                "timed_out": False,
            },
        }

    kvm_present = Path("/dev/kvm").exists()
    backends["kvm"] = {
        "name": "kvm",
        "present": kvm_present,
        "path": "/dev/kvm" if kvm_present else "NOT_FOUND",
        "status": "KVM_PRESENT" if kvm_present else "KVM_ABSENT",
        "probe": {
            "command": ["test", "-e", "/dev/kvm"],
            "returncode": 0 if kvm_present else 1,
            "output": "KVM_PRESENT" if kvm_present else "KVM_ABSENT",
            "timed_out": False,
        },
    }

    return {
        "schema": "wucios.euclid.phase3c_a.backend_detection.v1",
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "backends": backends,
        "commands": commands_out,
    }


def create_synthetic_context(context_dir: Path, template_path: Path) -> dict[str, Any]:
    ensure_directory(context_dir)
    containerfile = context_dir / "Containerfile"
    smoke_txt = context_dir / "wucios-smoke.txt"
    evidence_json = context_dir / "synthetic-evidence.json"

    containerfile.write_text(template_path.read_text(encoding="utf-8"), encoding="utf-8")
    smoke_txt.write_text(
        "WuciOS Phase 3C-A synthetic smoke file.\n"
        "Not a WuciOS artifact.\n"
        "Not a substrate artifact.\n"
        "Not score eligible.\n",
        encoding="utf-8",
    )
    evidence = {
        "schema": "wucios.euclid.phase3c_a.synthetic_context.v1",
        "phase_id": "euclid-trial-phase-3c-a",
        "generated_utc": generated_timestamp(),
        "is_wucios_artifact": False,
        "is_substrate_artifact": False,
        "score_eligible": False,
        "network_required": False,
        "image_pull_required": False,
    }
    write_json(evidence_json, evidence)

    files = []
    for path in sorted(context_dir.iterdir()):
        if path.is_file():
            files.append({
                "path": normalize_path(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            })
    manifest = {
        "schema": "wucios.euclid.phase3c_a.synthetic_context_manifest.v1",
        "phase_id": "euclid-trial-phase-3c-a",
        "context_dir": normalize_path(context_dir),
        "generated_utc": generated_timestamp(),
        "files": files,
        "is_wucios_artifact": False,
        "is_substrate_artifact": False,
        "score_eligible": False,
    }
    write_json(context_dir.parent / "synthetic-context-manifest.json", manifest)
    return manifest


def validate_containerfile(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    failures: list[str] = []
    instruction_lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    from_lines = [line for line in instruction_lines if line.upper().startswith("FROM ")]
    if from_lines != ["FROM scratch"]:
        failures.append("Containerfile must contain exactly FROM scratch")
    for line in instruction_lines:
        upper = line.upper()
        if upper.startswith("RUN "):
            failures.append("Containerfile must not contain RUN")
        if upper.startswith("ADD "):
            failures.append("Containerfile must not contain ADD")
    lowered = text.lower()
    if "http://" in lowered or "https://" in lowered:
        failures.append("Containerfile must not contain remote URLs")
    if "--privileged" in lowered:
        failures.append("Containerfile must not contain privileged flags")
    if "CMD " in text.upper() or "ENTRYPOINT " in text.upper():
        failures.append("Containerfile must not contain runtime commands")
    return failures


def validate_build_command(backend: str, command: list[str]) -> list[str]:
    failures: list[str] = []
    joined = " ".join(command)
    if backend == "podman":
        if command[:2] != ["podman", "build"]:
            failures.append("podman smoke must use podman build")
        if "--pull=never" not in command:
            failures.append("podman smoke must use --pull=never")
    elif backend == "buildah":
        if command[:2] != ["buildah", "bud"]:
            failures.append("buildah smoke must use buildah bud")
        if "--pull-never" not in command:
            failures.append("buildah smoke must use --pull-never")
    else:
        failures.append("only podman and buildah are allowed for L2 smoke")
    if "--network=none" not in command:
        failures.append("smoke build must use --network=none")
    if "--privileged" in command or "--privileged" in joined:
        failures.append("smoke build must not use privileged flags")
    for forbidden in [" run ", " pull ", "docker", "qemu-system"]:
        if forbidden in f" {joined} ":
            failures.append(f"smoke build command contains forbidden token: {forbidden.strip()}")
    return failures


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_iidfile(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return "NOT_MEASURED"


def cleanup_image(backend: str, tag: str, cleanup_log: Path) -> dict[str, Any]:
    ensure_directory(cleanup_log.parent)
    command = [backend, "rmi", "-f", tag] if backend == "podman" else [backend, "rmi", tag]
    result = safe_command_execution(command, timeout_seconds=60)
    cleanup_log.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def guardrail_failure(message: str) -> dict[str, Any]:
    return {
        "status": "GUARDRAIL_FAILURE",
        "message": message,
    }
