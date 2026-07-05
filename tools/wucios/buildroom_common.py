#!/usr/bin/env python3
"""Shared helpers for WuciOS Euclid build-room readiness reports."""

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

READINESS_VALUES = {
    "BUILDROOM_ATTEMPT_NOT_AUTHORIZED",
    "BUILDROOM_BACKEND_ABSENT",
    "BUILDROOM_BACKEND_PRESENT",
    "BUILDROOM_BACKEND_PERMISSION_BLOCKED",
    "BUILDROOM_BACKEND_CONFIG_BLOCKED",
    "BUILDROOM_BACKEND_USABILITY_UNKNOWN",
    "BUILDROOM_INPUTS_MISSING",
    "BUILDROOM_READY_FOR_FUTURE_ATTEMPT",
}

FORBIDDEN_DEFAULT_ACTIONS = [
    "docker pull",
    "docker build",
    "docker run",
    "podman pull",
    "podman build",
    "podman run",
    "buildah bud",
    "buildah from",
    "buildah run",
    "nix build",
    "guix system",
    "qemu-system execution",
    "VM launch",
    "sudo",
    "package installation",
    "source tree cloning",
    "artifact download",
]


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, text: str) -> None:
    ensure_directory(path.parent)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def generated_timestamp() -> str:
    """Return a timestamp for ignored generated outputs only."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def normalize_status(value: str, allowed: set[str], fallback: str) -> str:
    return value if value in allowed else fallback


def command_detection(command: str) -> dict[str, Any]:
    path = shutil.which(command)
    return {
        "name": command,
        "present": path is not None,
        "path": path or "NOT_FOUND",
    }


def safe_command_version_capture(command: list[str], timeout_seconds: int = 8) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        output = (result.stdout or "").strip()
        return {
            "command": command,
            "returncode": result.returncode,
            "output": output[:2000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "")
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {
            "command": command,
            "returncode": "TIMEOUT",
            "output": output[:2000],
            "timed_out": True,
        }
    except OSError as exc:
        return {
            "command": command,
            "returncode": "OS_ERROR",
            "output": str(exc),
            "timed_out": False,
        }


def classify_backend_result(present: bool, capture: dict[str, Any] | None = None) -> str:
    if not present:
        return "BUILDROOM_BACKEND_ABSENT"
    if capture is None:
        return "BUILDROOM_BACKEND_PRESENT"
    if capture.get("returncode") == 0:
        return "BUILDROOM_BACKEND_PRESENT"
    text = str(capture.get("output", "")).lower()
    if "permission denied" in text or "access denied" in text or "operation not permitted" in text:
        return "BUILDROOM_BACKEND_PERMISSION_BLOCKED"
    if "read-only" in text or "configuration" in text or "config" in text or "mkdir" in text:
        return "BUILDROOM_BACKEND_CONFIG_BLOCKED"
    if capture.get("timed_out"):
        return "BUILDROOM_BACKEND_USABILITY_UNKNOWN"
    return "BUILDROOM_BACKEND_USABILITY_UNKNOWN"


def detect_backends() -> dict[str, dict[str, Any]]:
    detections: dict[str, dict[str, Any]] = {}
    commands = {
        "docker": ["docker", "info"],
        "podman": ["podman", "info"],
        "buildah": ["buildah", "info"],
        "qemu-system-x86_64": ["qemu-system-x86_64", "--version"],
        "qemu-img": ["qemu-img", "--version"],
    }
    for name, probe in commands.items():
        detected = command_detection(name)
        capture = safe_command_version_capture(probe) if detected["present"] else None
        detected["status"] = classify_backend_result(bool(detected["present"]), capture)
        detected["probe"] = capture or {"command": probe, "returncode": "NOT_RUN", "output": "BINARY_NOT_FOUND"}
        detections[name] = detected

    for name in ["nerdctl", "nix", "guix"]:
        detected = command_detection(name)
        detected["status"] = classify_backend_result(bool(detected["present"]))
        detected["probe"] = {"command": ["command", "-v", name], "returncode": 0 if detected["present"] else 1, "output": detected["path"]}
        detections[name] = detected

    kvm_path = Path("/dev/kvm")
    detections["kvm"] = {
        "name": "kvm",
        "present": kvm_path.exists(),
        "path": str(kvm_path) if kvm_path.exists() else "NOT_FOUND",
        "status": "BUILDROOM_BACKEND_PRESENT" if kvm_path.exists() else "BUILDROOM_BACKEND_ABSENT",
        "probe": {"command": ["test", "-e", "/dev/kvm"], "returncode": 0 if kvm_path.exists() else 1, "output": "KVM_DEVICE_PRESENT" if kvm_path.exists() else "KVM_DEVICE_ABSENT"},
    }
    return detections


def host_summary() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def _existing_paths(paths: list[Path]) -> list[str]:
    existing: list[str] = []
    for path in paths:
        try:
            if path.exists():
                existing.append(normalize_path(path))
        except OSError:
            continue
    return existing


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    return Path(value).expanduser()


def local_input_detection(candidate: str) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    missing: list[str] = []

    def record_path_group(name: str, paths: list[Path], missing_label: str) -> None:
        present = _existing_paths(paths)
        if present:
            found.append({"name": name, "paths": present})
        else:
            missing.append(missing_label)

    if candidate == "buildroot":
        paths = [
            *([_env_path("BUILDROOT_DIR")] if _env_path("BUILDROOT_DIR") else []),
            ROOT / "wucios/trials/buildroot/buildroot-src",
            ROOT / "third_party/buildroot",
            ROOT / "vendor/buildroot",
        ]
        record_path_group("buildroot_source", paths, "local Buildroot source tree or approved source acquisition policy")
    elif candidate == "alpine":
        missing.append("controlled apk/rootfs strategy")
    elif candidate == "debian-minimal":
        missing.append("controlled debootstrap or rootfs strategy")
    elif candidate == "void":
        missing.append("controlled XBPS rootfs strategy")
    elif candidate == "nixos":
        missing.append("explicit host-store policy or isolated Nix store policy")
    elif candidate == "guix":
        missing.append("explicit Guix daemon/store policy")
    elif candidate == "yocto":
        paths = [
            *([_env_path("YOCTO_DIR")] if _env_path("YOCTO_DIR") else []),
            *([_env_path("POKY_DIR")] if _env_path("POKY_DIR") else []),
            ROOT / "wucios/trials/yocto/poky-src",
            ROOT / "third_party/poky",
            ROOT / "vendor/poky",
        ]
        record_path_group("yocto_poky_source", paths, "local Yocto/Poky source tree or approved source acquisition policy")
        missing.append("controlled output path policy")
    elif candidate == "openbsd-reference":
        paths = [
            *([_env_path("OPENBSD_IMAGE")] if _env_path("OPENBSD_IMAGE") else []),
            ROOT / "wucios/trials/openbsd-reference/openbsd.img",
            ROOT / "wucios/trials/openbsd-reference/install.iso",
            ROOT / "third_party/openbsd/openbsd.img",
            ROOT / "vendor/openbsd/openbsd.img",
        ]
        record_path_group("openbsd_image", paths, "local OpenBSD image or approved image acquisition policy")
        missing.append("future explicit runtime attempt authorization")
    else:
        missing.append("unknown candidate input policy")

    return {
        "candidate": candidate,
        "found_inputs": found,
        "missing_inputs": missing,
    }


def candidate_report_writing(
    output_dir: Path,
    candidate_status: dict[str, Any],
    backend_detection: dict[str, Any],
    input_detection: dict[str, Any],
) -> None:
    ensure_directory(output_dir)
    write_json(output_dir / "status.json", candidate_status)
    write_json(output_dir / "backend-detection.json", backend_detection)
    write_json(output_dir / "input-detection.json", input_detection)

    missing_inputs = candidate_status.get("missing_inputs", [])
    blocked_actions = "\n".join(FORBIDDEN_DEFAULT_ACTIONS) + "\n"
    (output_dir / "missing-inputs.txt").write_text(("\n".join(missing_inputs) + "\n") if missing_inputs else "NONE_DETECTED\n", encoding="utf-8")
    (output_dir / "blocked-actions.txt").write_text(blocked_actions, encoding="utf-8")

    display = candidate_status.get("display_name", candidate_status.get("id", "unknown"))
    status_md = [
        f"# {display} Phase 3A Status",
        "",
        f"Definition Status: `{candidate_status.get('definition_status')}`",
        f"Attempt Readiness: `{candidate_status.get('attempt_readiness')}`",
        f"Execution Class: `{candidate_status.get('execution_class')}`",
        "",
        "No build attempt was made. No container was pulled, built, or run. No VM was launched.",
    ]
    write_markdown(output_dir / "status.md", "\n".join(status_md))

    readiness_md = [
        f"# {display} Build-Room Readiness",
        "",
        "The build room is not the substrate; the build room is the measuring chamber.",
        "",
        f"- Attempt readiness: `{candidate_status.get('attempt_readiness')}`",
        f"- Missing inputs: {', '.join(missing_inputs) if missing_inputs else 'none detected'}",
        f"- Blocked until: {', '.join(candidate_status.get('blocked_until', []))}",
    ]
    write_markdown(output_dir / "readiness.md", "\n".join(readiness_md))


def combined_report_writing(json_path: Path, markdown_path: Path, payload: dict[str, Any], markdown: str) -> None:
    write_json(json_path, payload)
    write_markdown(markdown_path, markdown)
