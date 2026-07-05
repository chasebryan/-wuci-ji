#!/usr/bin/env python3
"""Shared helpers for WuciOS Euclid Phase 3B readiness diagnostics."""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

READINESS_VALUES = {
    "BACKEND_BLOCKED",
    "INPUTS_BLOCKED",
    "POLICY_BLOCKED",
    "RESOURCE_BLOCKED",
    "READY_FOR_FUTURE_CONTROLLED_ATTEMPT",
    "REFERENCE_RUNTIME_BLOCKED",
}

BACKEND_STATUS_VALUES = {
    "BACKEND_PRESENT",
    "BACKEND_ABSENT",
    "BACKEND_PERMISSION_BLOCKED",
    "BACKEND_CONFIG_BLOCKED",
    "BACKEND_USABILITY_UNKNOWN",
    "KVM_PRESENT",
    "KVM_ABSENT",
}

COMMAND_BACKEND_NAMES = {
    "docker info": "docker",
    "podman info": "podman",
    "buildah info": "buildah",
    "qemu-system-x86_64 --version": "qemu-system-x86_64",
    "qemu-img --version": "qemu-img",
}

COMMAND_V_BACKEND_NAMES = {
    "docker": "docker",
    "podman": "podman",
    "buildah": "buildah",
    "qemu-system-x86_64": "qemu-system-x86_64",
    "qemu-img": "qemu-img",
    "nix": "nix",
    "guix": "guix",
    "xbps-install": "xbps-install",
    "xbps-query": "xbps-query",
    "apk": "apk",
    "debootstrap": "debootstrap",
    "fakechroot": "fakechroot",
    "fakeroot": "fakeroot",
    "bitbake": "bitbake",
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


def normalize_blockers(blockers: list[str]) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for blocker in blockers:
        item = " ".join(str(blocker).replace("|", "/").split())
        if item and item not in seen:
            normalized.append(item)
            seen.add(item)
    return normalized


def command_detection(command: str) -> dict[str, Any]:
    path = shutil.which(command)
    return {
        "name": command,
        "present": path is not None,
        "path": path or "NOT_FOUND",
        "status": "BACKEND_PRESENT" if path else "BACKEND_ABSENT",
        "probe": {
            "command": ["command", "-v", command],
            "returncode": 0 if path else 1,
            "output": path or "BINARY_NOT_FOUND",
            "timed_out": False,
        },
    }


def safe_command_execution(command: list[str], timeout_seconds: int = 8) -> dict[str, Any]:
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
        return {
            "command": command,
            "returncode": result.returncode,
            "output": (result.stdout or "").strip()[:4000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {
            "command": command,
            "returncode": "TIMEOUT",
            "output": output.strip()[:4000],
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
    if "permission denied" in text or "access denied" in text or "operation not permitted" in text:
        return "BACKEND_PERMISSION_BLOCKED"
    if "read-only" in text or "read only" in text or "configuration" in text or "config" in text or "mkdir" in text:
        return "BACKEND_CONFIG_BLOCKED"
    if capture.get("timed_out"):
        return "BACKEND_USABILITY_UNKNOWN"
    return "BACKEND_USABILITY_UNKNOWN"


def readonly_file_probe(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    result: dict[str, Any] = {
        "path": path_text,
        "exists": False,
        "readable": False,
        "is_symlink": False,
        "is_socket": False,
        "is_char_device": False,
        "mode_octal": "NOT_MEASURED",
        "size_bytes": "NOT_MEASURED",
    }
    try:
        stat_result = path.lstat()
    except OSError as exc:
        result["error"] = str(exc)
        return result

    result["exists"] = True
    result["is_symlink"] = path.is_symlink()
    result["mode_octal"] = oct(stat_result.st_mode & 0o7777)
    result["size_bytes"] = stat_result.st_size
    try:
        result["is_socket"] = path.is_socket()
        result["is_char_device"] = path.is_char_device()
        result["readable"] = os.access(path, os.R_OK)
    except OSError as exc:
        result["error"] = str(exc)
    if path_text == "/proc/sys/kernel/unprivileged_userns_clone":
        try:
            result["value"] = path.read_text(encoding="utf-8", errors="replace").strip()[:40]
        except OSError as exc:
            result["value_error"] = str(exc)
    return result


def run_allowed_detections(policy: dict[str, Any]) -> dict[str, Any]:
    allowed_commands = [str(item) for item in policy.get("allowed_detection_commands", [])]
    command_results: dict[str, dict[str, Any]] = {}
    backends: dict[str, dict[str, Any]] = {}

    for command_text in allowed_commands:
        if command_text.startswith("command -v "):
            name = command_text.removeprefix("command -v ").strip()
            detection = command_detection(name)
            command_results[command_text] = detection["probe"]
            backends[COMMAND_V_BACKEND_NAMES.get(name, name)] = detection
            continue
        if command_text == "test -e /dev/kvm":
            present = Path("/dev/kvm").exists()
            detection = {
                "name": "kvm",
                "present": present,
                "path": "/dev/kvm" if present else "NOT_FOUND",
                "status": "KVM_PRESENT" if present else "KVM_ABSENT",
                "probe": {
                    "command": ["test", "-e", "/dev/kvm"],
                    "returncode": 0 if present else 1,
                    "output": "KVM_PRESENT" if present else "KVM_ABSENT",
                    "timed_out": False,
                },
            }
            command_results[command_text] = detection["probe"]
            backends["kvm"] = detection
            continue

        argv = shlex.split(command_text)
        if not argv:
            continue
        detected = command_detection(argv[0])
        if not detected["present"]:
            capture = {
                "command": argv,
                "returncode": "NOT_RUN",
                "output": "BINARY_NOT_FOUND",
                "timed_out": False,
            }
        else:
            capture = safe_command_execution(argv)
        command_results[command_text] = capture
        name = COMMAND_BACKEND_NAMES.get(command_text, argv[0])
        backends[name] = {
            "name": name,
            "present": bool(detected["present"]),
            "path": detected["path"],
            "status": backend_status_from_capture(bool(detected["present"]), capture),
            "probe": capture,
        }

    file_checks = [str(item) for item in policy.get("allowed_readonly_file_checks", [])]
    readonly_files = {path: readonly_file_probe(path) for path in file_checks}
    return {
        "commands": command_results,
        "backends": backends,
        "readonly_files": readonly_files,
    }


def _read_proc_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" not in line:
                continue
            key, raw_value = line.split(":", 1)
            parts = raw_value.strip().split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) * 1024
    except OSError:
        pass
    return values


def _cpuinfo_summary() -> dict[str, Any]:
    count = 0
    model = "NOT_MEASURED"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("processor"):
                count += 1
            elif line.startswith("model name") and model == "NOT_MEASURED":
                model = line.split(":", 1)[1].strip()
    except OSError:
        count = os.cpu_count() or 0
    return {
        "logical_cpu_count": count or os.cpu_count() or "NOT_MEASURED",
        "cpu_model": model,
    }


def host_summary() -> dict[str, Any]:
    meminfo = _read_proc_meminfo()
    disk = shutil.disk_usage(ROOT)
    cpu = _cpuinfo_summary()
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "logical_cpu_count": cpu["logical_cpu_count"],
        "cpu_model": cpu["cpu_model"],
        "memory_total_bytes": meminfo.get("MemTotal", "NOT_MEASURED"),
        "memory_available_bytes": meminfo.get("MemAvailable", "NOT_MEASURED"),
        "disk_total_bytes": disk.total,
        "disk_available_bytes": disk.free,
    }


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    if not value:
        return None
    return Path(value).expanduser()


def _existing_paths(paths: list[Path]) -> list[str]:
    found: list[str] = []
    for path in paths:
        try:
            if path.exists():
                found.append(normalize_path(path))
        except OSError:
            continue
    return found


def candidate_input_detection(candidate: str, backends: dict[str, dict[str, Any]]) -> dict[str, Any]:
    found_inputs: list[dict[str, Any]] = []
    input_blockers: list[str] = []

    def record_paths(name: str, paths: list[Path], blocker: str) -> None:
        existing = _existing_paths(paths)
        if existing:
            found_inputs.append({"name": name, "paths": existing})
        else:
            input_blockers.append(blocker)

    def require_command(name: str, blocker: str) -> None:
        detection = backends.get(name, {})
        if detection.get("present"):
            found_inputs.append({"name": name, "paths": [str(detection.get("path", "NOT_FOUND"))]})
        else:
            input_blockers.append(blocker)

    if candidate == "buildroot":
        paths = [
            *([_env_path("BUILDROOT_DIR")] if _env_path("BUILDROOT_DIR") else []),
            ROOT / "wucios/trials/buildroot/buildroot-src",
            ROOT / "third_party/buildroot",
            ROOT / "vendor/buildroot",
        ]
        record_paths(
            "buildroot_source",
            paths,
            "INPUTS_BLOCKED: local Buildroot source tree or approved source acquisition policy missing",
        )
    elif candidate == "alpine":
        require_command("apk", "INPUTS_BLOCKED: apk tooling not found")
        input_blockers.append("POLICY_BLOCKED: controlled apk/rootfs strategy is not defined")
    elif candidate == "debian-minimal":
        require_command("debootstrap", "INPUTS_BLOCKED: debootstrap tooling not found")
        require_command("fakechroot", "INPUTS_BLOCKED: fakechroot tooling not found")
        require_command("fakeroot", "INPUTS_BLOCKED: fakeroot tooling not found")
        input_blockers.append("POLICY_BLOCKED: controlled debootstrap/fakechroot strategy is not defined")
    elif candidate == "void":
        require_command("xbps-install", "INPUTS_BLOCKED: xbps-install tooling not found")
        require_command("xbps-query", "INPUTS_BLOCKED: xbps-query tooling not found")
    elif candidate == "nixos":
        require_command("nix", "BACKEND_BLOCKED: nix tooling not found")
    elif candidate == "guix":
        require_command("guix", "BACKEND_BLOCKED: guix tooling not found")
    elif candidate == "yocto":
        require_command("bitbake", "INPUTS_BLOCKED: bitbake tooling not found")
        paths = [
            *([_env_path("YOCTO_DIR")] if _env_path("YOCTO_DIR") else []),
            *([_env_path("POKY_DIR")] if _env_path("POKY_DIR") else []),
            ROOT / "wucios/trials/yocto/poky-src",
            ROOT / "third_party/poky",
            ROOT / "vendor/poky",
        ]
        record_paths(
            "yocto_poky_source",
            paths,
            "INPUTS_BLOCKED: local Yocto/Poky source tree or approved source acquisition policy missing",
        )
    elif candidate == "openbsd-reference":
        paths = [
            *([_env_path("OPENBSD_IMAGE")] if _env_path("OPENBSD_IMAGE") else []),
            ROOT / "wucios/trials/openbsd-reference/openbsd.img",
            ROOT / "wucios/trials/openbsd-reference/install.iso",
            ROOT / "third_party/openbsd/openbsd.img",
            ROOT / "vendor/openbsd/openbsd.img",
        ]
        record_paths(
            "openbsd_image",
            paths,
            "INPUTS_BLOCKED: local OpenBSD image or approved image acquisition policy missing",
        )
    else:
        input_blockers.append("INPUTS_BLOCKED: unknown candidate input policy")

    return {
        "candidate": candidate,
        "found_inputs": found_inputs,
        "input_blockers": normalize_blockers(input_blockers),
    }


def test_levels_by_id(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    levels: dict[str, dict[str, Any]] = {}
    for level in matrix.get("test_levels", []):
        if isinstance(level, dict) and level.get("id"):
            levels[str(level["id"])] = level
    return levels


def report_paths(candidate: str, output_root: Path) -> dict[str, str]:
    base = output_root / candidate / "phase-3b-readiness"
    return {
        "status_json": normalize_path(base / "status.json"),
        "status_md": normalize_path(base / "status.md"),
        "backend_findings_json": normalize_path(base / "backend-findings.json"),
        "input_findings_json": normalize_path(base / "input-findings.json"),
        "remediation_notes_md": normalize_path(base / "remediation-notes.md"),
        "future_test_authorization_md": normalize_path(base / "future-test-authorization.md"),
    }


def write_candidate_outputs(
    output_dir: Path,
    candidate_status: dict[str, Any],
    backend_findings: list[dict[str, Any]],
    input_findings: dict[str, Any],
    authorization_level: dict[str, Any],
) -> None:
    display = str(candidate_status.get("display_name", candidate_status.get("id", "unknown")))
    write_json(output_dir / "status.json", candidate_status)
    write_json(output_dir / "backend-findings.json", {"candidate": candidate_status["id"], "backend_findings": backend_findings})
    write_json(output_dir / "input-findings.json", input_findings)

    blocker_lines = []
    for key in ["backend_blockers", "input_blockers", "policy_blockers", "resource_blockers"]:
        values = candidate_status.get(key, [])
        blocker_lines.append(f"- {key}: {', '.join(values) if values else 'none detected'}")
    status_md = [
        f"# {display} Phase 3B Readiness Status",
        "",
        f"Readiness: `{candidate_status.get('readiness')}`",
        f"Execution Class: `{candidate_status.get('execution_class')}`",
        f"Future Authorization Level: `{candidate_status.get('future_authorization_level_required')}`",
        f"Recommended Next Action: {candidate_status.get('recommended_next_action')}",
        "",
        "No build attempt was made. No container was pulled, built, or run. No VM was launched.",
        "",
        "## Blockers",
        "",
        *blocker_lines,
    ]
    write_markdown(output_dir / "status.md", "\n".join(status_md))

    remediation_md = [
        f"# {display} Backend Remediation Notes",
        "",
        "Phase 3B readiness detects blockers only. It does not remediate host configuration.",
        "",
        "Human authorization is required before host configuration changes, package installation, source acquisition, image acquisition, or runtime execution.",
        "",
        "## Findings",
        "",
        *blocker_lines,
    ]
    write_markdown(output_dir / "remediation-notes.md", "\n".join(remediation_md))

    auth_md = [
        f"# {display} Future Test Authorization",
        "",
        "No execution is authorized by this report.",
        "",
        f"Required level before next controlled attempt: `{candidate_status.get('future_authorization_level_required')}`",
        "",
        f"Level name: {authorization_level.get('name', 'NOT_DEFINED')}",
        "",
        "The test authorization matrix authorizes L0 readiness by default only. L1-L4 require future explicit authorization.",
    ]
    write_markdown(output_dir / "future-test-authorization.md", "\n".join(auth_md))
