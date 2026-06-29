#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA = "wuci-kaiju-catalog-v1"
DEFAULT_MANIFEST = Path("docs/noxframe/wuci_kaiju_manifest.json")
DEFAULT_ISO_ROOT = Path("build/noxframe/kaiju/iso")
DEFAULT_DISK_ROOT = Path("build/noxframe/kaiju/disk")
ISO_MANIFEST_NAME = "manifest.json"
DISK_MANIFEST_NAME = "disk.json"
ISO_SCHEMA = "wuci-kaiju-iso-install-v1"
DISK_SCHEMA = "wuci-kaiju-disk-v1"
BOOT_SCHEMA = "wuci-kaiju-boot-plan-v1"
DEFAULT_QEMU_BIN = "qemu-system-x86_64"
DEFAULT_QEMU_CANDIDATES = (
    "qemu-system-x86_64",
    "qemu-kvm",
    "/usr/libexec/qemu-kvm",
)
QEMU_INSTALL_HINT = (
    "install qemu-kvm-core on RHEL, or pass --kaiju-qemu-bin /path/to/qemu"
)
DEFAULT_MEMORY_MIB = 2048
DEFAULT_CPUS = 2
REQUIRED_PURPOSES = (
    "top10-anchor",
    "information-gathering",
    "vulnerability-analysis",
    "web-applications",
    "database-assessment",
    "password-audit",
    "wireless-analysis",
    "reverse-engineering",
    "exploitation-frameworks",
    "social-engineering-awareness",
    "sniffing-spoofing",
    "post-exploitation-review",
    "forensics",
    "reporting",
    "802-11",
    "bluetooth",
    "rfid",
    "sdr",
    "voip",
    "windows-resources",
    "gpu",
    "crypto-stego",
    "fuzzing",
    "hardware",
    "labs",
)
REQUIRED_TOOL_KEYS = {
    "name",
    "package",
    "kali_url",
    "role",
    "disposition",
    "host_execution",
    "notes",
}
ALLOWED_DISPOSITIONS = {
    "catalog-only",
    "offline-evidence-catalog",
    "blocked-catalog",
}
FORBIDDEN_KEYS = {
    "argv",
    "command",
    "commands",
    "pipeline",
    "shell_pipeline",
    "target_args",
    "scan_args",
    "exploit_args",
    "module_path",
    "operator_steps",
}
ISO_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\.iso")


class KaijuError(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_manifest_path(root: Path | None = None) -> Path:
    base = repo_root() if root is None else root
    return base / DEFAULT_MANIFEST


def default_iso_root(root: Path | None = None) -> Path:
    base = repo_root() if root is None else root
    return base / DEFAULT_ISO_ROOT


def default_disk_root(root: Path | None = None) -> Path:
    base = repo_root() if root is None else root
    return base / DEFAULT_DISK_ROOT


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _nofollow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _cloexec() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def read_public_json(path: Path, label: str = "WUCI-KAIJU manifest") -> dict[str, Any]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise KaijuError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise KaijuError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise KaijuError(f"{label} must not be hardlinked: {path}")

    flags = os.O_RDONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise KaijuError(f"could not open {label}: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise KaijuError(f"{label} changed type while opening: {path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise KaijuError(f"{label} changed while opening: {path}")
        if opened.st_nlink != 1:
            raise KaijuError(f"{label} must not be hardlinked: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)

    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KaijuError(f"{label} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise KaijuError(f"{label} must be a JSON object: {path}")
    return value


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_unsafe_existing_path(path, f"{path.name} JSON")
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def require_regular_local_file(path: Path, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise KaijuError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise KaijuError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise KaijuError(f"{label} must not be hardlinked: {path}")
    return info


def reject_unsafe_existing_path(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KaijuError(f"could not stat {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"{label} must not be a symlink: {path}")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise KaijuError(f"{label} must not be hardlinked: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise KaijuError(f"{label} must be a regular file: {path}")


def prepare_output_path(path: Path, label: str, *, force: bool) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    reject_unsafe_existing_path(path, label)
    if not force:
        raise KaijuError(f"refusing to overwrite {label}: {path}")


def safe_iso_name(name: str) -> str:
    candidate = Path(name).name
    if candidate != name or not ISO_NAME_RE.fullmatch(candidate):
        raise KaijuError("ISO name must be a plain .iso filename")
    return candidate


def iso_manifest_path(iso_root: Path) -> Path:
    return iso_root / ISO_MANIFEST_NAME


def disk_manifest_path(disk_root: Path) -> Path:
    return disk_root / DISK_MANIFEST_NAME


def read_iso_manifest(iso_root: Path) -> dict[str, Any]:
    return read_public_json(iso_manifest_path(iso_root), "WUCI-KAIJU ISO manifest")


def read_disk_manifest(disk_root: Path) -> dict[str, Any]:
    return read_public_json(disk_manifest_path(disk_root), "WUCI-KAIJU disk manifest")


def file_digest_vector(path: Path, label: str) -> tuple[dict[str, str], int]:
    require_regular_local_file(path, label)
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise KaijuError(f"could not open {label}: {path}") from exc
    total = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise KaijuError(f"{label} changed type while opening: {path}")
        if opened.st_nlink != 1:
            raise KaijuError(f"{label} must not be hardlinked: {path}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    finally:
        os.close(fd)
    return {name: digest.hexdigest() for name, digest in digests.items()}, total


def install_iso(
    source: Path,
    *,
    iso_root: Path | None = None,
    name: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    source = source if source.is_absolute() else Path.cwd() / source
    source_info = require_regular_local_file(source, "Kali ISO source")
    iso_name = safe_iso_name(name or source.name)
    root = default_iso_root() if iso_root is None else iso_root
    root.mkdir(parents=True, exist_ok=True)
    dest = root / iso_name
    try:
        if source.resolve(strict=True) == dest.resolve(strict=False):
            raise KaijuError("Kali ISO source and destination must differ")
    except OSError:
        pass
    prepare_output_path(dest, "installed Kali ISO", force=force)

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{iso_name}.", dir=str(root))
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    total = 0
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        os.close(tmp_fd)
        os.unlink(tmp_name)
        raise KaijuError(f"could not open Kali ISO source: {source}") from exc
    try:
        opened = os.fstat(source_fd)
        if opened.st_ino != source_info.st_ino or opened.st_dev != source_info.st_dev:
            raise KaijuError(f"Kali ISO source changed while opening: {source}")
        with os.fdopen(tmp_fd, "wb") as out_handle:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                for digest in digests.values():
                    digest.update(chunk)
                out_handle.write(chunk)
            out_handle.flush()
            os.fsync(out_handle.fileno())
        if total == 0:
            raise KaijuError("Kali ISO source is empty")
        prepare_output_path(dest, "installed Kali ISO", force=force)
        os.replace(tmp_name, dest)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    finally:
        os.close(source_fd)

    manifest: dict[str, Any] = {
        "schema": ISO_SCHEMA,
        "name": "WUCI-KAIJU Kali ISO",
        "installed_utc": utc_now(),
        "source_path": str(source),
        "source_basename": source.name,
        "image_path": str(dest),
        "image_bytes": total,
        "digest_vector": {name: digest.hexdigest() for name, digest in digests.items()},
        "boot_profile": {
            "graphics": "none",
            "serial": "stdio",
            "default_network": "none",
            "launcher": DEFAULT_QEMU_BIN,
        },
        "guards": {
            "source_symlink": "rejected",
            "source_hardlink": "rejected",
            "installed_symlink": "rejected",
            "installed_hardlink": "rejected",
            "shell": "disabled",
            "network": "disabled by default",
        },
        "non_claims": [
            "not a host shell",
            "not NOXFRAME runtime containment",
            "not a Kali tool execution grant",
            "not a network authorization",
        ],
    }
    write_json_atomic(iso_manifest_path(root), manifest)
    return manifest


def verify_iso_install(iso_root: Path | None = None) -> dict[str, Any]:
    root = default_iso_root() if iso_root is None else iso_root
    problems: list[str] = []
    try:
        manifest = read_iso_manifest(root)
    except KaijuError as exc:
        return {
            "schema": "wuci-kaiju-iso-verification-v1",
            "status": "fail",
            "iso_root": str(root),
            "problems": [str(exc)],
        }
    if manifest.get("schema") != ISO_SCHEMA:
        problems.append("ISO manifest schema mismatch")
    image_path_value = manifest.get("image_path")
    if not isinstance(image_path_value, str):
        problems.append("ISO manifest image_path missing")
        image_path = root / "missing.iso"
    else:
        image_path = Path(image_path_value)
    try:
        digest_vector, size = file_digest_vector(image_path, "installed Kali ISO")
    except KaijuError as exc:
        problems.append(str(exc))
        digest_vector = {}
        size = -1
    if digest_vector and manifest.get("digest_vector") != digest_vector:
        problems.append("installed ISO digest mismatch")
    if size >= 0 and manifest.get("image_bytes") != size:
        problems.append("installed ISO size mismatch")
    return {
        "schema": "wuci-kaiju-iso-verification-v1",
        "status": "pass" if not problems else "fail",
        "iso_root": str(root),
        "image_path": str(image_path),
        "image_bytes": size,
        "problems": problems,
    }


def iso_status_text(iso_root: Path | None = None) -> str:
    result = verify_iso_install(iso_root)
    rows = [
        "schema: wuci-kaiju-iso-status-v1",
        f"status: {result['status']}",
        f"iso_root: {result['iso_root']}",
    ]
    if result["status"] == "pass":
        rows.extend(
            [
                f"image: {result['image_path']}",
                f"bytes: {result['image_bytes']}",
                "boot: non-graphical QEMU plan available",
            ]
        )
    else:
        rows.append("boot: unavailable until a local ISO is installed")
        rows.extend(f"problem: {problem}" for problem in result.get("problems", []))
    rows.append("")
    return "\n".join(rows)


def create_disk(
    *,
    disk_root: Path | None = None,
    size_mib: int,
    force: bool = False,
    name: str = "kali.raw",
) -> dict[str, Any]:
    if size_mib < 1 or size_mib > 262144:
        raise KaijuError("disk size must be between 1 and 262144 MiB")
    if "/" in name or name in {"", ".", ".."}:
        raise KaijuError("disk name must be a plain filename")
    root = default_disk_root() if disk_root is None else disk_root
    root.mkdir(parents=True, exist_ok=True)
    disk_path = root / name
    prepare_output_path(disk_path, "disk image", force=force)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{name}.", dir=str(root))
    try:
        os.ftruncate(tmp_fd, size_mib * 1024 * 1024)
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = -1
        os.replace(tmp_name, disk_path)
    except Exception:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    manifest: dict[str, Any] = {
        "schema": DISK_SCHEMA,
        "created_utc": utc_now(),
        "disk_path": str(disk_path),
        "format": "raw",
        "size_mib": size_mib,
        "mutable": True,
        "guards": {
            "shell": "disabled",
            "network": "not applicable",
            "symlink": "rejected",
            "hardlink": "rejected",
        },
        "non_claims": [
            "not public evidence",
            "not runtime containment",
            "not encrypted storage",
        ],
    }
    write_json_atomic(disk_manifest_path(root), manifest)
    return manifest


def verify_disk(disk_root: Path | None = None) -> dict[str, Any]:
    root = default_disk_root() if disk_root is None else disk_root
    problems: list[str] = []
    try:
        manifest = read_disk_manifest(root)
    except KaijuError as exc:
        return {
            "schema": "wuci-kaiju-disk-verification-v1",
            "status": "fail",
            "disk_root": str(root),
            "problems": [str(exc)],
        }
    if manifest.get("schema") != DISK_SCHEMA:
        problems.append("disk manifest schema mismatch")
    disk_path_value = manifest.get("disk_path")
    if not isinstance(disk_path_value, str):
        problems.append("disk manifest disk_path missing")
        disk_path = root / "missing.raw"
    else:
        disk_path = Path(disk_path_value)
    try:
        info = require_regular_local_file(disk_path, "Kali disk image")
    except KaijuError as exc:
        problems.append(str(exc))
        size = -1
    else:
        size = info.st_size
        if manifest.get("size_mib") != size // (1024 * 1024):
            problems.append("disk size mismatch")
    return {
        "schema": "wuci-kaiju-disk-verification-v1",
        "status": "pass" if not problems else "fail",
        "disk_root": str(root),
        "disk_path": str(disk_path),
        "disk_bytes": size,
        "problems": problems,
    }


def disk_status_text(disk_root: Path | None = None) -> str:
    result = verify_disk(disk_root)
    rows = [
        "schema: wuci-kaiju-disk-status-v1",
        f"status: {result['status']}",
        f"disk_root: {result['disk_root']}",
    ]
    if result["status"] == "pass":
        rows.extend([f"disk: {result['disk_path']}", f"bytes: {result['disk_bytes']}"])
    else:
        rows.append("disk: absent")
        rows.extend(f"problem: {problem}" for problem in result.get("problems", []))
    rows.append("")
    return "\n".join(rows)


def discover_qemu(qemu_bin: str = DEFAULT_QEMU_BIN) -> str | None:
    candidates = [qemu_bin]
    if qemu_bin == DEFAULT_QEMU_BIN:
        candidates.extend(candidate for candidate in DEFAULT_QEMU_CANDIDATES if candidate not in candidates)
    for candidate in candidates:
        if os.sep in candidate:
            path = Path(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            continue
        found = shutil.which(candidate)
        if found:
            return found
    return None


def boot_plan(
    *,
    iso_root: Path | None = None,
    disk_root: Path | None = None,
    qemu_bin: str = DEFAULT_QEMU_BIN,
    memory_mib: int = DEFAULT_MEMORY_MIB,
    cpus: int = DEFAULT_CPUS,
    network: bool = False,
) -> dict[str, Any]:
    if memory_mib < 512 or memory_mib > 262144:
        raise KaijuError("memory must be between 512 and 262144 MiB")
    if cpus < 1 or cpus > 256:
        raise KaijuError("cpus must be between 1 and 256")
    iso_result = verify_iso_install(iso_root)
    if iso_result["status"] != "pass":
        raise KaijuError("Kali ISO is not installed: " + "; ".join(iso_result["problems"]))
    disk_result = verify_disk(disk_root)
    disk_path = disk_result.get("disk_path") if disk_result["status"] == "pass" else None
    qemu_path = discover_qemu(qemu_bin)
    argv = [
        qemu_path or qemu_bin,
        "-m",
        str(memory_mib),
        "-smp",
        str(cpus),
        "-cdrom",
        str(iso_result["image_path"]),
        "-boot",
        "d",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-no-reboot",
    ]
    if disk_path:
        argv.extend(["-drive", f"file={disk_path},format=raw,if=virtio"])
    if network:
        argv.extend(["-nic", "user,model=virtio-net-pci"])
    else:
        argv.extend(["-net", "none"])
    return {
        "schema": BOOT_SCHEMA,
        "status": "ready",
        "argv": argv,
        "qemu_bin": qemu_bin,
        "qemu_discovered": qemu_path or "not found on PATH",
        "qemu_candidates": list(DEFAULT_QEMU_CANDIDATES) if qemu_bin == DEFAULT_QEMU_BIN else [qemu_bin],
        "graphics": "none",
        "console": "serial mon:stdio",
        "network": "user" if network else "none",
        "iso": iso_result,
        "disk": disk_result,
        "exit_hint": "inside QEMU monitor use Ctrl-a x to quit when -nographic owns stdio",
        "non_claims": [
            "NOXFRAME is launching a local VM process, not enforcing a kernel sandbox",
            "Kali tools are not exposed as NOXFRAME commands",
            "network is disabled unless explicitly requested",
        ],
    }


def iter_dicts(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        for child in value.values():
            found.extend(iter_dicts(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(iter_dicts(child))
    return found


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if manifest.get("schema") != SCHEMA:
        problems.append("schema mismatch")
    if manifest.get("name") != "WUCI-KAIJU":
        problems.append("name mismatch")

    boundary = manifest.get("boundary")
    if not isinstance(boundary, dict):
        problems.append("boundary must be an object")
    else:
        for key in ("host_execution", "network_access", "shell"):
            if boundary.get(key) != "unavailable":
                problems.append(f"boundary {key} must be unavailable")
        if boundary.get("runtime_sandbox_claim") != "none":
            problems.append("boundary runtime_sandbox_claim must be none")

    boot_bridge = manifest.get("boot_bridge")
    if boot_bridge is not None:
        if not isinstance(boot_bridge, dict):
            problems.append("boot_bridge must be an object")
        else:
            if boot_bridge.get("graphics") != "none":
                problems.append("boot_bridge graphics must be none")
            if boot_bridge.get("default_network") != "none":
                problems.append("boot_bridge default_network must be none")
            if boot_bridge.get("host_execution") != "explicit --allow-kaiju-boot only":
                problems.append("boot_bridge host_execution must require --allow-kaiju-boot")

    for item in iter_dicts(manifest):
        for key in item:
            if key in FORBIDDEN_KEYS:
                problems.append(f"forbidden key present: {key}")

    purposes = manifest.get("purposes")
    if not isinstance(purposes, list):
        problems.append("purposes must be a list")
        return problems

    seen: set[str] = set()
    for index, purpose in enumerate(purposes):
        if not isinstance(purpose, dict):
            problems.append(f"purpose {index} must be an object")
            continue
        purpose_id = purpose.get("id")
        if not isinstance(purpose_id, str) or not purpose_id:
            problems.append(f"purpose {index} has invalid id")
            continue
        if purpose_id in seen:
            problems.append(f"duplicate purpose id: {purpose_id}")
        seen.add(purpose_id)
        if purpose.get("risk_gate") not in {"metadata-only", "blocked-by-noxframe"}:
            problems.append(f"{purpose_id}: invalid risk_gate")
        tools = purpose.get("selected_tools")
        if not isinstance(tools, list) or not tools:
            problems.append(f"{purpose_id}: selected_tools must be non-empty")
            continue
        for tool_index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                problems.append(f"{purpose_id}: tool {tool_index} must be an object")
                continue
            missing = sorted(REQUIRED_TOOL_KEYS - set(tool))
            if missing:
                problems.append(f"{purpose_id}: tool {tool_index} missing {','.join(missing)}")
            if tool.get("host_execution") != "unavailable":
                problems.append(f"{purpose_id}: {tool.get('name', tool_index)} host_execution must be unavailable")
            if tool.get("disposition") not in ALLOWED_DISPOSITIONS:
                problems.append(f"{purpose_id}: {tool.get('name', tool_index)} invalid disposition")
            url = tool.get("kali_url")
            if not isinstance(url, str) or not url.startswith("https://www.kali.org/tools/"):
                problems.append(f"{purpose_id}: {tool.get('name', tool_index)} must use Kali tool URL")

    missing_purposes = sorted(set(REQUIRED_PURPOSES) - seen)
    extra_purposes = sorted(seen - set(REQUIRED_PURPOSES))
    if missing_purposes:
        problems.append("missing required purpose(s): " + ",".join(missing_purposes))
    if extra_purposes:
        problems.append("unexpected purpose(s): " + ",".join(extra_purposes))

    denials = manifest.get("global_denials")
    if not isinstance(denials, list) or "no offensive scanning" not in denials:
        problems.append("global_denials must include no offensive scanning")
    return problems


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = default_manifest_path() if path is None else path
    return read_public_json(manifest_path)


def verify_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = default_manifest_path() if path is None else path
    manifest = load_manifest(manifest_path)
    problems = validate_manifest(manifest)
    purposes = manifest.get("purposes", [])
    tool_count = 0
    if isinstance(purposes, list):
        for purpose in purposes:
            if isinstance(purpose, dict) and isinstance(purpose.get("selected_tools"), list):
                tool_count += len(purpose["selected_tools"])
    return {
        "schema": "wuci-kaiju-verification-v1",
        "status": "pass" if not problems else "fail",
        "manifest": str(manifest_path),
        "purpose_count": len(purposes) if isinstance(purposes, list) else 0,
        "selected_tool_count": tool_count,
        "problems": problems,
    }


def manifest_status_text(manifest: dict[str, Any]) -> str:
    purposes = manifest.get("purposes", [])
    tool_count = 0
    blocked = 0
    if isinstance(purposes, list):
        for purpose in purposes:
            if not isinstance(purpose, dict):
                continue
            if purpose.get("risk_gate") == "blocked-by-noxframe":
                blocked += 1
            tools = purpose.get("selected_tools")
            if isinstance(tools, list):
                tool_count += len(tools)
    return "\n".join(
        [
            "schema: wuci-kaiju-status-v1",
            f"name: {manifest.get('name', 'WUCI-KAIJU')}",
            f"catalog_schema: {manifest.get('schema')}",
            f"purposes: {len(purposes) if isinstance(purposes, list) else 0}",
            f"selected_tools: {tool_count}",
            f"blocked_purposes: {blocked}",
            "kali_tool_execution: unavailable",
            "iso_boot_bridge: non-graphical QEMU, explicit opt-in",
            "default_vm_network: none",
            "shell: unavailable",
            "non_claim: not runtime containment",
            "",
        ]
    )


def manifest_policy_text(manifest: dict[str, Any]) -> str:
    boundary = manifest.get("boundary", {})
    denials = manifest.get("global_denials", [])
    rows = [
        "schema: wuci-kaiju-policy-v1",
        f"mode: {boundary.get('mode', 'metadata-only') if isinstance(boundary, dict) else 'metadata-only'}",
        "kali_tool_execution: unavailable",
        "iso_boot_bridge: explicit local QEMU bridge only",
        "default_vm_network: none",
        "shell: unavailable",
        "substrate_use: catalog read/verify/list plus operator-supplied ISO boot",
        "",
        "denials:",
    ]
    if isinstance(denials, list):
        rows.extend(f"- {item}" for item in denials)
    rows.append("")
    return "\n".join(rows)


def purpose_rows(manifest: dict[str, Any], purpose_id: str | None = None) -> list[str]:
    rows: list[str] = []
    purposes = manifest.get("purposes", [])
    if not isinstance(purposes, list):
        return ["kaiju: invalid manifest purposes"]
    for purpose in purposes:
        if not isinstance(purpose, dict):
            continue
        current_id = purpose.get("id")
        if purpose_id is not None and current_id != purpose_id:
            continue
        rows.append(
            f"{current_id}: {purpose.get('summary', '')} gate={purpose.get('risk_gate', 'unknown')}"
        )
        tools = purpose.get("selected_tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                rows.append(
                    "  - "
                    f"{tool.get('package')}: {tool.get('role')} "
                    f"disposition={tool.get('disposition')} host_execution={tool.get('host_execution')}"
                )
    if purpose_id is not None and not rows:
        rows.append(f"kaiju: no purpose named {purpose_id}")
    return rows


def manifest_list_text(manifest: dict[str, Any], purpose_id: str | None = None) -> str:
    return "\n".join(["schema: wuci-kaiju-purpose-list-v1", *purpose_rows(manifest, purpose_id), ""])


def resolve_manifest_arg(value: str | None) -> Path:
    if value is None:
        return default_manifest_path()
    path = Path(value)
    return path if path.is_absolute() else Path.cwd() / path


def resolve_root_arg(value: str | None, default: Path) -> Path:
    if value is None:
        return default
    path = Path(value)
    return path if path.is_absolute() else Path.cwd() / path


def command_status(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(manifest_status_text(manifest), end="")
    return 0


def command_policy(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(manifest_policy_text(manifest), end="")
    return 0


def command_list(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(manifest_list_text(manifest, args.purpose), end="")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    result = verify_manifest(resolve_manifest_arg(args.manifest))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["status"] == "pass":
        print(
            "wuci-kaiju: PASS "
            f"purposes={result['purpose_count']} selected_tools={result['selected_tool_count']}"
        )
    else:
        print("wuci-kaiju: FAIL")
        for problem in result["problems"]:
            print(f"- {problem}")
    return 0 if result["status"] == "pass" else 1


def command_manifest(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def command_iso(args: argparse.Namespace) -> int:
    iso_root = resolve_root_arg(args.iso_root, default_iso_root())
    subcommand = args.iso_command or "status"
    if subcommand == "status":
        print(iso_status_text(iso_root), end="")
        return 0
    if subcommand == "install":
        manifest = install_iso(
            Path(args.source),
            iso_root=iso_root,
            name=args.name,
            force=args.force,
        )
        if args.json:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju iso: installed {manifest['image_path']}")
            print(f"bytes: {manifest['image_bytes']}")
            print(f"sha256: {manifest['digest_vector']['sha256']}")
        return 0
    if subcommand == "verify":
        result = verify_iso_install(iso_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju iso verify: {result['status']}")
            for problem in result.get("problems", []):
                print(f"problem: {problem}")
        return 0 if result["status"] == "pass" else 1
    raise KaijuError(f"unsupported iso command: {subcommand}")


def command_disk(args: argparse.Namespace) -> int:
    disk_root = resolve_root_arg(args.disk_root, default_disk_root())
    subcommand = args.disk_command or "status"
    if subcommand == "status":
        print(disk_status_text(disk_root), end="")
        return 0
    if subcommand == "create":
        manifest = create_disk(
            disk_root=disk_root,
            size_mib=args.size_mib,
            force=args.force,
            name=args.name,
        )
        if args.json:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju disk: created {manifest['disk_path']}")
            print(f"size-mib: {manifest['size_mib']}")
        return 0
    if subcommand == "verify":
        result = verify_disk(disk_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju disk verify: {result['status']}")
            for problem in result.get("problems", []):
                print(f"problem: {problem}")
        return 0 if result["status"] == "pass" else 1
    raise KaijuError(f"unsupported disk command: {subcommand}")


def command_boot(args: argparse.Namespace) -> int:
    plan = boot_plan(
        iso_root=resolve_root_arg(args.iso_root, default_iso_root()),
        disk_root=resolve_root_arg(args.disk_root, default_disk_root()),
        qemu_bin=args.qemu_bin,
        memory_mib=args.memory_mib,
        cpus=args.cpus,
        network=args.allow_network,
    )
    if args.json or not args.run:
        print(json.dumps(plan, indent=2, sort_keys=True))
    if not args.run:
        return 0
    if plan["qemu_discovered"] == "not found on PATH":
        raise KaijuError(f"QEMU executable not found: {args.qemu_bin}; {QEMU_INSTALL_HINT}")
    print("wuci-kaiju boot: launching non-graphical QEMU")
    print("argv: " + " ".join(plan["argv"]))
    result = subprocess.run(plan["argv"], check=False, shell=False)
    return result.returncode


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify and inspect the WUCI-KAIJU catalog.")
    parser.add_argument(
        "--manifest",
        help="WUCI-KAIJU manifest path; defaults to docs/noxframe/wuci_kaiju_manifest.json",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="show catalog status")
    subparsers.add_parser("policy", help="show catalog boundary policy")
    list_parser = subparsers.add_parser("list", help="list selected tools by purpose")
    list_parser.add_argument("--purpose", help="filter to one purpose id")
    verify_parser = subparsers.add_parser("verify", help="verify catalog structure and guards")
    verify_parser.add_argument("--json", action="store_true", help="emit JSON verification result")
    subparsers.add_parser("manifest", help="print canonical manifest JSON")

    iso_parser = subparsers.add_parser("iso", help="install and verify a local Kali ISO")
    iso_parser.add_argument("--iso-root", help="NOXFRAME Kaiju ISO workspace")
    iso_subparsers = iso_parser.add_subparsers(dest="iso_command")
    iso_subparsers.add_parser("status", help="show installed ISO status")
    iso_install = iso_subparsers.add_parser("install", help="copy a local operator-supplied ISO")
    iso_install.add_argument("source", help="local Kali ISO path")
    iso_install.add_argument("--name", help="installed ISO filename; defaults to source basename")
    iso_install.add_argument("--force", action="store_true", help="replace an existing installed ISO")
    iso_install.add_argument("--json", action="store_true", help="emit JSON install manifest")
    iso_verify = iso_subparsers.add_parser("verify", help="verify installed ISO digest evidence")
    iso_verify.add_argument("--json", action="store_true", help="emit JSON verification result")

    disk_parser = subparsers.add_parser("disk", help="create and verify a raw Kali VM disk")
    disk_parser.add_argument("--disk-root", help="NOXFRAME Kaiju disk workspace")
    disk_subparsers = disk_parser.add_subparsers(dest="disk_command")
    disk_subparsers.add_parser("status", help="show disk status")
    disk_create = disk_subparsers.add_parser("create", help="create a sparse raw disk image")
    disk_create.add_argument("--size-mib", type=int, required=True, help="disk size in MiB")
    disk_create.add_argument("--name", default="kali.raw", help="disk filename")
    disk_create.add_argument("--force", action="store_true", help="replace an existing disk image")
    disk_create.add_argument("--json", action="store_true", help="emit JSON disk manifest")
    disk_verify = disk_subparsers.add_parser("verify", help="verify disk image metadata")
    disk_verify.add_argument("--json", action="store_true", help="emit JSON verification result")

    boot_parser = subparsers.add_parser("boot", help="build or run a non-graphical QEMU Kali boot")
    boot_parser.add_argument("--iso-root", help="NOXFRAME Kaiju ISO workspace")
    boot_parser.add_argument("--disk-root", help="NOXFRAME Kaiju disk workspace")
    boot_parser.add_argument("--qemu-bin", default=DEFAULT_QEMU_BIN, help="QEMU executable")
    boot_parser.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB, help="VM memory in MiB")
    boot_parser.add_argument("--cpus", type=int, default=DEFAULT_CPUS, help="VM CPU count")
    boot_parser.add_argument("--allow-network", action="store_true", help="enable QEMU user networking")
    boot_parser.add_argument("--run", action="store_true", help="launch QEMU instead of printing the plan")
    boot_parser.add_argument("--json", action="store_true", help="emit JSON boot plan")

    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "status"
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "status":
            return command_status(args)
        if args.command == "policy":
            return command_policy(args)
        if args.command == "list":
            return command_list(args)
        if args.command == "verify":
            return command_verify(args)
        if args.command == "manifest":
            return command_manifest(args)
        if args.command == "iso":
            return command_iso(args)
        if args.command == "disk":
            return command_disk(args)
        if args.command == "boot":
            return command_boot(args)
    except KaijuError as exc:
        print(f"wuci-kaiju: {exc}", file=sys.stderr)
        return 1
    raise KaijuError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
