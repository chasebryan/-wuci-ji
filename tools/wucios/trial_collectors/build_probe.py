#!/usr/bin/env python3
"""Shared build feasibility probe helpers for WuciOS Euclid trials."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
PHASE_ID = "euclid-trial-phase-2"
PHASE_NAME = "WuciOS v2.4 Euclid Trial Phase 2 - Build Feasibility Probes"

CANDIDATES = {
    "buildroot": {
        "display_name": "Buildroot",
        "tools": ["make", "git", "tar"],
        "tool_blockers": {"make": "MISSING_MAKE", "git": "MISSING_GIT", "tar": "MISSING_TAR"},
        "artifact_candidates": ["rootfs.tar", "rootfs.cpio", "sdcard.img", "bzImage"],
    },
    "alpine": {
        "display_name": "Alpine Linux",
        "tools": ["apk", "tar", "fakeroot"],
        "tool_blockers": {"apk": "MISSING_APK", "tar": "MISSING_TAR"},
        "artifact_candidates": ["rootfs.tar.gz"],
    },
    "debian-minimal": {
        "display_name": "Debian Minimal",
        "tools": ["debootstrap", "tar", "fakeroot", "fakechroot"],
        "tool_blockers": {"debootstrap": "MISSING_DEBOOTSTRAP", "tar": "MISSING_TAR"},
        "artifact_candidates": ["rootfs.tar.gz"],
    },
}

ALLOWED_CANDIDATE_STATUSES = {
    "BUILD_NOT_ATTEMPTED",
    "BUILD_ATTEMPTED_FAILED",
    "BUILD_SUCCEEDED_PARTIAL",
    "ARTIFACT_GENERATED",
    "TRIAL_BLOCKED",
}

RUNTIME_REQUIRED_TEXT = {
    "listening-ports.txt": "NOT_MEASURED_RUNTIME_REQUIRED: Phase 2 does not boot the artifact. Runtime network exposure requires a later boot smoke test.",
    "kernel-modules.txt": "NOT_MEASURED_RUNTIME_REQUIRED: Phase 2 does not boot the artifact. Loaded kernel modules require runtime inspection.",
}

MEASUREMENT_FILES = [
    "package-manifest.txt",
    "image-size.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "dependency-tree.txt",
    "build-manifest.sha256",
]

REQUIRED_EVIDENCE_FILES = [
    "status.json",
    "status.txt",
    "tool-detection.json",
    "build-log.txt",
    "build-notes.md",
    "artifact-manifest.json",
    *MEASUREMENT_FILES,
    "substrate-report.json",
    "substrate-report.md",
    "failure-report.md",
    "noether-static-check.json",
    "noether-static-check.md",
    "missing-measurements.txt",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_size(path: Path) -> int:
    return path.stat().st_size


def detect_command(name: str) -> dict[str, Any]:
    found = shutil.which(name)
    return {
        "name": name,
        "present": found is not None,
        "path": found if found else "NOT_MEASURED_MISSING_TOOL",
    }


def detect_hash_tool() -> dict[str, Any]:
    for name in ["sha256sum", "shasum"]:
        found = shutil.which(name)
        if found:
            return {"name": name, "present": True, "path": found}
    return {"name": "sha256sum_or_shasum", "present": False, "path": "NOT_MEASURED_MISSING_TOOL"}


def detect_os() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def normalize_blockers(blockers: list[str]) -> list[str]:
    allowed = {
        "MISSING_TOOL",
        "MISSING_BUILDROOT_SOURCE",
        "MISSING_APK",
        "MISSING_DEBOOTSTRAP",
        "MISSING_TAR",
        "MISSING_MAKE",
        "MISSING_GIT",
        "MISSING_QEMU_IMG",
        "MISSING_ROOT_PRIVILEGE",
        "MISSING_FAKECHROOT_OR_ROOT",
        "NETWORK_DISABLED",
        "UNSUPPORTED_HOST",
        "ARTIFACT_NOT_FOUND",
        "BUILD_COMMAND_FAILED",
        "RUNTIME_SCAN_REQUIRED",
        "NOETHER_STATIC_CHECK_INCOMPLETE",
        "TRIAL_BLOCKED",
    }
    normalized = [item if item in allowed else "MISSING_TOOL" for item in blockers]
    return sorted(dict.fromkeys(normalized))


def validate_status(status: str) -> str:
    if status not in ALLOWED_CANDIDATE_STATUSES:
        raise ValueError(f"invalid candidate status: {status}")
    return status


def buildroot_source_candidates() -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get("BUILDROOT_DIR")
    if env_path:
        paths.append(Path(env_path))
    paths.extend(
        [
            ROOT / "wucios/trials/buildroot/buildroot-src",
            ROOT / "third_party/buildroot",
            ROOT / "vendor/buildroot",
        ]
    )
    return paths


def detect_buildroot_source() -> dict[str, Any]:
    for path in buildroot_source_candidates():
        if path.is_dir() and (path / "Makefile").is_file():
            return {"present": True, "path": str(path)}
    return {"present": False, "path": "NOT_MEASURED_MISSING_TOOL"}


def detect_tooling(candidate: str) -> list[dict[str, Any]]:
    tooling = [detect_command(name) for name in CANDIDATES[candidate]["tools"]]
    tooling.append(detect_hash_tool())
    if candidate == "buildroot":
        source = detect_buildroot_source()
        tooling.append({"name": "buildroot_source", "present": source["present"], "path": source["path"]})
    tooling.append({"name": "host_os", "present": True, "path": json.dumps(detect_os(), sort_keys=True)})
    return tooling


def tool_present(tooling: list[dict[str, Any]], name: str) -> bool:
    return any(item["name"] == name and item["present"] for item in tooling)


def buildroot_source_path(tooling: list[dict[str, Any]]) -> Path | None:
    for item in tooling:
        if item["name"] == "buildroot_source" and item["present"]:
            return Path(str(item["path"]))
    return None


def detect_artifact_candidates(candidate: str, output_dir: Path, work_dir: Path) -> Path | None:
    names = CANDIDATES[candidate]["artifact_candidates"]
    search_dirs = [
        output_dir,
        work_dir,
        work_dir / "output/images",
        work_dir / "buildroot-output/images",
    ]
    for directory in search_dirs:
        for name in names:
            path = directory / name
            if path.is_file():
                return path
    return None


def not_measured_file(path: Path, marker: str, reason: str) -> None:
    write_text(path, f"{marker}: {reason}\n")


def measurement_has_data(path: Path) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return False
    return not text.startswith("NOT_MEASURED")


def extract_alpine_package_manifest(rootfs: Path, destination: Path) -> bool:
    installed = rootfs / "lib/apk/db/installed"
    if not installed.is_file():
        return False
    packages: list[str] = []
    for line in installed.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("P:"):
            packages.append(line[2:].strip())
    if not packages:
        return False
    write_text(destination, "\n".join(sorted(packages)) + "\n")
    return True


def extract_debian_package_manifest(rootfs: Path, destination: Path) -> bool:
    status = rootfs / "var/lib/dpkg/status"
    if not status.is_file():
        return False
    packages: list[str] = []
    for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Package:"):
            packages.append(line.split(":", 1)[1].strip())
    if not packages:
        return False
    write_text(destination, "\n".join(sorted(packages)) + "\n")
    return True


def extract_buildroot_package_manifest(work_dir: Path, destination: Path) -> bool:
    candidates = [
        work_dir / "buildroot-output/legal-info/manifest.csv",
        work_dir / "buildroot-output/build/packages-file-list.txt",
        work_dir / "output/legal-info/manifest.csv",
        work_dir / "output/build/packages-file-list.txt",
    ]
    for path in candidates:
        if path.is_file():
            write_text(destination, path.read_text(encoding="utf-8", errors="replace"))
            return True
    return False


def static_service_manifest(rootfs: Path, destination: Path) -> bool:
    service_dirs = [
        rootfs / "etc/init.d",
        rootfs / "etc/systemd/system",
        rootfs / "etc/runlevels/default",
        rootfs / "etc/rc.d",
    ]
    services: list[str] = []
    for directory in service_dirs:
        if directory.is_dir():
            for path in sorted(directory.iterdir()):
                if path.name.startswith("."):
                    continue
                services.append(path.name)
    if not services:
        return False
    write_text(destination, "\n".join(sorted(set(services))) + "\n")
    return True


def static_suid_sgid_manifest(rootfs: Path, destination: Path) -> bool:
    if not rootfs.is_dir():
        return False
    entries: list[str] = []
    for path in rootfs.rglob("*"):
        try:
            mode = path.stat().st_mode
        except OSError:
            continue
        if mode & 0o6000:
            entries.append(str(path.relative_to(rootfs)))
    if not entries:
        write_text(destination, "PARTIAL: static rootfs scan found no SUID/SGID entries\n")
    else:
        write_text(destination, "\n".join(sorted(entries)) + "\n")
    return True


def tar_rootfs(rootfs: Path, artifact: Path) -> None:
    ensure_dir(artifact.parent)
    with tarfile.open(artifact, "w:gz") as archive:
        archive.add(rootfs, arcname=".")


def run_command(command: list[str], log_path: Path, cwd: Path | None = None) -> int:
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n$ {' '.join(command)}\n")
        log.flush()
        result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        log.write(f"\nexit_code={result.returncode}\n")
        return result.returncode


def read_denied_set(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def noether_static_check(output_dir: Path) -> dict[str, Any]:
    package_path = output_dir / "package-manifest.txt"
    service_path = output_dir / "enabled-services.txt"
    denied_packages = read_denied_set(ROOT / "wucios/sets/cantor-denied-noether-packages.txt")
    denied_services = read_denied_set(ROOT / "wucios/sets/cantor-denied-default-services.txt")
    violations: list[str] = []
    notes: list[str] = []
    checked_any = False

    if measurement_has_data(package_path):
        checked_any = True
        packages = [line.strip().lower() for line in package_path.read_text(encoding="utf-8", errors="replace").splitlines()]
        for denied in denied_packages:
            if denied in packages:
                violations.append(f"denied package present: {denied}")
    else:
        notes.append("package manifest unavailable")

    if measurement_has_data(service_path):
        checked_any = True
        services = [line.strip().lower() for line in service_path.read_text(encoding="utf-8", errors="replace").splitlines()]
        for denied in denied_services:
            if denied in services:
                violations.append(f"denied default service present: {denied}")
    else:
        notes.append("static service manifest unavailable")

    if not checked_any:
        status = "NOETHER_STATIC_CHECK_INCOMPLETE"
    elif violations:
        status = "NOETHER_STATIC_CHECK_FAILED"
    elif "static service manifest unavailable" in notes:
        status = "NOETHER_STATIC_CHECK_PARTIAL"
    else:
        status = "NOETHER_STATIC_CHECK_PASSED_STATIC_ONLY"

    if status == "NOETHER_STATIC_CHECK_INCOMPLETE":
        notes.append("static checks require an artifact or manifest")
    return {"status": status, "violations": violations, "notes": notes}


def write_noether_static_check(output_dir: Path, check: dict[str, Any]) -> None:
    write_json(output_dir / "noether-static-check.json", check)
    lines = [
        "# Noether Core Static Check",
        "",
        f"Status: `{check['status']}`",
        "",
        "Static checks do not replace runtime validation.",
        "",
        "## Violations",
        "",
    ]
    lines.extend(f"- `{item}`" for item in check["violations"] or ["NONE_DETECTED"])
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {item}" for item in check["notes"] or ["No notes."])
    lines.append("")
    write_text(output_dir / "noether-static-check.md", "\n".join(lines))


def initial_measurements(artifact_present: bool) -> dict[str, str]:
    no_artifact = "NOT_MEASURED_NO_ARTIFACT"
    return {
        "package_manifest": no_artifact,
        "image_size": no_artifact,
        "enabled_services": no_artifact,
        "listening_ports": "NOT_MEASURED_RUNTIME_REQUIRED",
        "suid_sgid": no_artifact,
        "kernel_modules": "NOT_MEASURED_RUNTIME_REQUIRED",
        "dependency_tree": no_artifact,
    }


def missing_measurements(measurements: dict[str, str], artifact: dict[str, Any]) -> list[str]:
    missing = [
        name
        for name, value in measurements.items()
        if str(value).startswith("NOT_MEASURED")
    ]
    if not artifact["present"]:
        missing.append("artifact.sha256")
    return sorted(set(missing))


def write_measurement_files(output_dir: Path, measurements: dict[str, str], artifact: dict[str, Any]) -> None:
    for filename in MEASUREMENT_FILES:
        path = output_dir / filename
        if path.exists() and measurement_has_data(path):
            continue
        if filename in RUNTIME_REQUIRED_TEXT:
            write_text(path, RUNTIME_REQUIRED_TEXT[filename] + "\n")
        elif filename == "image-size.txt" and artifact["present"]:
            write_text(path, f"{artifact['size_bytes']}\n")
        elif filename == "build-manifest.sha256" and artifact["present"]:
            write_text(path, f"{artifact['sha256']}  {artifact['path']}\n")
        else:
            not_measured_file(path, "NOT_MEASURED_NO_ARTIFACT", "No artifact was generated.")


def attempt_buildroot(output_dir: Path, work_dir: Path, tooling: list[dict[str, Any]], log_path: Path) -> tuple[str, list[str]]:
    blockers: list[str] = []
    source = buildroot_source_path(tooling)
    if source is None:
        return "TRIAL_BLOCKED", ["MISSING_BUILDROOT_SOURCE"]
    if not tool_present(tooling, "make"):
        blockers.append("MISSING_MAKE")
    if not tool_present(tooling, "tar"):
        blockers.append("MISSING_TAR")
    if blockers:
        return "TRIAL_BLOCKED", blockers
    out_dir = work_dir / "buildroot-output"
    ensure_dir(out_dir)
    defconfig = "qemu_x86_64_defconfig"
    config_exit = run_command(["make", "-C", str(source), f"O={out_dir}", defconfig], log_path)
    if config_exit != 0:
        return "BUILD_ATTEMPTED_FAILED", ["BUILD_COMMAND_FAILED"]
    build_exit = run_command(["make", "-C", str(source), f"O={out_dir}"], log_path)
    if build_exit != 0:
        return "BUILD_ATTEMPTED_FAILED", ["BUILD_COMMAND_FAILED"]
    return "BUILD_SUCCEEDED_PARTIAL", []


def attempt_alpine(output_dir: Path, work_dir: Path, tooling: list[dict[str, Any]], log_path: Path) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if not tool_present(tooling, "apk"):
        blockers.append("MISSING_APK")
    if not tool_present(tooling, "tar"):
        blockers.append("MISSING_TAR")
    if blockers:
        return "TRIAL_BLOCKED", blockers
    rootfs = work_dir / "rootfs"
    ensure_dir(rootfs)
    command = ["apk", "--root", str(rootfs), "--initdb", "--update-cache", "add", "alpine-base"]
    exit_code = run_command(command, log_path)
    if exit_code != 0:
        blockers = ["BUILD_COMMAND_FAILED"]
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            blockers.append("MISSING_ROOT_PRIVILEGE")
        return "BUILD_ATTEMPTED_FAILED", blockers
    tar_rootfs(rootfs, output_dir / "rootfs.tar.gz")
    return "BUILD_SUCCEEDED_PARTIAL", []


def attempt_debian(output_dir: Path, work_dir: Path, tooling: list[dict[str, Any]], log_path: Path) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if not tool_present(tooling, "debootstrap"):
        blockers.append("MISSING_DEBOOTSTRAP")
    if not tool_present(tooling, "tar"):
        blockers.append("MISSING_TAR")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    fake_available = tool_present(tooling, "fakeroot") and tool_present(tooling, "fakechroot")
    if not is_root and not fake_available:
        blockers.append("MISSING_FAKECHROOT_OR_ROOT")
    if blockers:
        return "TRIAL_BLOCKED", blockers
    rootfs = work_dir / "rootfs"
    ensure_dir(rootfs)
    base_command = ["debootstrap", "--variant=minbase", "stable", str(rootfs), "http://deb.debian.org/debian"]
    command = base_command if is_root else ["fakeroot", "fakechroot", *base_command]
    exit_code = run_command(command, log_path)
    if exit_code != 0:
        return "BUILD_ATTEMPTED_FAILED", ["BUILD_COMMAND_FAILED"]
    tar_rootfs(rootfs, output_dir / "rootfs.tar.gz")
    return "BUILD_SUCCEEDED_PARTIAL", []


def update_static_artifact_evidence(candidate: str, output_dir: Path, work_dir: Path, artifact: dict[str, Any], measurements: dict[str, str]) -> None:
    rootfs = work_dir / "rootfs"
    if candidate == "alpine" and extract_alpine_package_manifest(rootfs, output_dir / "package-manifest.txt"):
        measurements["package_manifest"] = "STATIC_ARTIFACT_SCAN"
    elif candidate == "debian-minimal" and extract_debian_package_manifest(rootfs, output_dir / "package-manifest.txt"):
        measurements["package_manifest"] = "STATIC_ARTIFACT_SCAN"
    elif candidate == "buildroot" and extract_buildroot_package_manifest(work_dir, output_dir / "package-manifest.txt"):
        measurements["package_manifest"] = "STATIC_ARTIFACT_SCAN"

    if static_service_manifest(rootfs, output_dir / "enabled-services.txt"):
        measurements["enabled_services"] = "STATIC_ARTIFACT_SCAN"
    if static_suid_sgid_manifest(rootfs, output_dir / "suid-sgid.txt"):
        measurements["suid_sgid"] = "STATIC_ARTIFACT_SCAN"
    if artifact["present"]:
        measurements["image_size"] = "STATIC_ARTIFACT_SCAN"
        measurements["dependency_tree"] = measurements["dependency_tree"] if measurements["dependency_tree"] != "NOT_MEASURED_NO_ARTIFACT" else "NOT_MEASURED"


def candidate_blockers(candidate: str, tooling: list[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for tool, blocker in CANDIDATES[candidate]["tool_blockers"].items():
        if not tool_present(tooling, tool):
            blockers.append(blocker)
    if candidate == "buildroot" and buildroot_source_path(tooling) is None:
        blockers.append("MISSING_BUILDROOT_SOURCE")
    if candidate == "debian-minimal":
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        fake_available = tool_present(tooling, "fakeroot") and tool_present(tooling, "fakechroot")
        if not is_root and not fake_available:
            blockers.append("MISSING_FAKECHROOT_OR_ROOT")
    return normalize_blockers(blockers)


def run_probe(candidate: str, output_dir: Path, work_dir: Path, attempt: bool, allow_network: bool) -> dict[str, Any]:
    if candidate not in CANDIDATES:
        raise ValueError(f"unknown candidate: {candidate}")
    ensure_dir(output_dir)
    ensure_dir(work_dir)
    log_path = output_dir / "build-log.txt"
    mode = "EXPLICIT_BUILD_ATTEMPT" if attempt else "SAFE_DETECT_ONLY"
    write_text(
        log_path,
        "\n".join(
            [
                f"phase_id={PHASE_ID}",
                f"candidate={candidate}",
                f"execution_mode={mode}",
                f"network_allowed={str(allow_network).lower()}",
                "sudo_used=false",
                "",
            ]
        ),
    )

    tooling = detect_tooling(candidate)
    blockers = candidate_blockers(candidate, tooling)
    phase_status = "BUILD_NOT_ATTEMPTED"
    build_attempted = False

    if attempt and os.environ.get("WUCIOS_EUCLID_ALLOW_ATTEMPT") != "1":
        phase_status = "TRIAL_BLOCKED"
        blockers = normalize_blockers([*blockers, "TRIAL_BLOCKED"])
        with log_path.open("a", encoding="utf-8") as log:
            log.write("TRIAL_BLOCKED: Explicit build attempt requested, but WUCIOS_EUCLID_ALLOW_ATTEMPT=1 was not set.\n")
    elif attempt and not allow_network:
        phase_status = "TRIAL_BLOCKED"
        blockers = normalize_blockers([*blockers, "NETWORK_DISABLED"])
        with log_path.open("a", encoding="utf-8") as log:
            log.write("TRIAL_BLOCKED: NETWORK_DISABLED\n")
    elif attempt:
        build_attempted = True
        with log_path.open("a", encoding="utf-8") as log:
            log.write("Explicit build attempt enabled by WUCIOS_EUCLID_ALLOW_ATTEMPT=1.\n")
        if candidate == "buildroot":
            phase_status, attempt_blockers = attempt_buildroot(output_dir, work_dir, tooling, log_path)
        elif candidate == "alpine":
            phase_status, attempt_blockers = attempt_alpine(output_dir, work_dir, tooling, log_path)
        else:
            phase_status, attempt_blockers = attempt_debian(output_dir, work_dir, tooling, log_path)
        blockers = normalize_blockers([*blockers, *attempt_blockers])

    artifact_path = detect_artifact_candidates(candidate, output_dir, work_dir)
    artifact = {
        "present": artifact_path is not None,
        "path": str(artifact_path) if artifact_path else "NOT_MEASURED",
        "sha256": sha256_file(artifact_path) if artifact_path else "NOT_MEASURED",
        "size_bytes": file_size(artifact_path) if artifact_path else "NOT_MEASURED",
    }
    if attempt and artifact["present"]:
        phase_status = "ARTIFACT_GENERATED"
        blockers = [blocker for blocker in blockers if blocker != "ARTIFACT_NOT_FOUND"]
    elif attempt and not artifact["present"] and phase_status == "BUILD_SUCCEEDED_PARTIAL":
        blockers = normalize_blockers([*blockers, "ARTIFACT_NOT_FOUND"])

    measurements = initial_measurements(artifact["present"])
    update_static_artifact_evidence(candidate, output_dir, work_dir, artifact, measurements)
    write_measurement_files(output_dir, measurements, artifact)
    noether_check = noether_static_check(output_dir)
    if noether_check["status"] == "NOETHER_STATIC_CHECK_INCOMPLETE":
        blockers = normalize_blockers([*blockers, "NOETHER_STATIC_CHECK_INCOMPLETE"])
    write_noether_static_check(output_dir, noether_check)

    if not artifact["present"] and not attempt:
        measurements = initial_measurements(False)

    missing = missing_measurements(measurements, artifact)
    artifact_manifest = {
        "schema": "wucios.euclid.phase2.artifact_manifest.v1",
        "artifact_present": artifact["present"],
        "artifact_path": artifact["path"],
        "sha256": artifact["sha256"],
        "size_bytes": artifact["size_bytes"],
        "measurement_scope": "STATIC_ARTIFACT_SCAN" if artifact["present"] else "NOT_MEASURED_NO_ARTIFACT",
    }
    write_json(output_dir / "artifact-manifest.json", artifact_manifest)
    write_json(output_dir / "tool-detection.json", {"schema": "wucios.euclid.phase2.tool_detection.v1", "candidate": candidate, "tooling": tooling})
    write_text(output_dir / "missing-measurements.txt", "\n".join(missing) + "\n")

    report_paths = {
        "candidate_report_md": str(output_dir / "substrate-report.md"),
        "candidate_report_json": str(output_dir / "substrate-report.json"),
    }
    status_payload = {
        "schema": "wucios.euclid.phase2.candidate.v1",
        "phase_id": PHASE_ID,
        "candidate": candidate,
        "id": candidate,
        "display_name": CANDIDATES[candidate]["display_name"],
        "phase_status": validate_status(phase_status),
        "build_attempted": build_attempted,
        "execution_mode": mode,
        "network_allowed": allow_network,
        "sudo_used": False,
        "artifact": artifact,
        "tooling": tooling,
        "blockers": blockers,
        "measurements": measurements,
        "noether_core_static_check": noether_check,
        "missing_measurements": missing,
        "report_paths": report_paths,
    }
    write_json(output_dir / "status.json", status_payload)
    write_text(output_dir / "status.txt", f"{phase_status}\n")
    write_candidate_markdown(candidate, output_dir, status_payload)
    write_json(output_dir / "substrate-report.json", status_payload)
    write_failure_report(candidate, output_dir, status_payload)

    for filename in REQUIRED_EVIDENCE_FILES:
        path = output_dir / filename
        if not path.exists():
            not_measured_file(path, "NOT_MEASURED", "Required evidence file was not produced by the probe.")

    return status_payload


def write_candidate_markdown(candidate: str, output_dir: Path, status: dict[str, Any]) -> None:
    artifact = status["artifact"]
    lines = [
        f"# {status['display_name']} Phase 2 Build Feasibility Probe",
        "",
        f"Build Status: `{status['phase_status']}`",
        f"Build Attempted: `{str(status['build_attempted']).lower()}`",
        f"Artifact: `{str(artifact['present']).lower()}`",
        f"Artifact SHA-256: `{artifact['sha256']}`",
        "",
        "This candidate report does not rank substrates.",
        "",
        "## Blockers",
        "",
    ]
    lines.extend(f"- `{item}`" for item in status["blockers"] or ["NONE_DETECTED"])
    lines.extend(["", "## Measurements", "", "| Measurement | Status |", "| --- | --- |"])
    for name, value in status["measurements"].items():
        lines.append(f"| `{name}` | `{value}` |")
    lines.extend(["", "## Missing Measurements", ""])
    lines.extend(f"- `{item}`" for item in status["missing_measurements"] or ["NONE"])
    lines.extend(["", "## Noether Core Static Check", "", f"`{status['noether_core_static_check']['status']}`", ""])
    write_text(output_dir / "substrate-report.md", "\n".join(lines))
    write_text(
        output_dir / "build-notes.md",
        "\n".join(
            [
                f"# {status['display_name']} Build Notes",
                "",
                f"Execution mode: `{status['execution_mode']}`",
                f"Build attempted: `{str(status['build_attempted']).lower()}`",
                "Default validation uses safe detect-only mode.",
                "",
            ]
        ),
    )


def write_failure_report(candidate: str, output_dir: Path, status: dict[str, Any]) -> None:
    lines = [
        f"# {status['display_name']} Failure Report",
        "",
        f"Status: `{status['phase_status']}`",
        "",
    ]
    if status["blockers"]:
        lines.extend(["## Blockers", ""])
        lines.extend(f"- `{item}`" for item in status["blockers"])
    else:
        lines.append("No blocker was detected by this probe.")
    lines.extend(["", "Missing measurements remain explicit and are not estimates.", ""])
    write_text(output_dir / "failure-report.md", "\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, choices=sorted(CANDIDATES))
    parser.add_argument("--detect-only", action="store_true")
    parser.add_argument("--attempt", action="store_true")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    if args.detect_only and args.attempt:
        parser.error("--detect-only and --attempt are mutually exclusive")
    try:
        payload = run_probe(
            args.candidate,
            Path(args.output_dir).resolve(),
            Path(args.work_dir).resolve(),
            attempt=args.attempt,
            allow_network=args.allow_network,
        )
    except Exception as exc:  # noqa: BLE001 - CLI must fail clearly on script errors.
        print(f"build probe error: {exc}", file=sys.stderr)
        return 1
    print(f"{args.candidate}: {payload['phase_status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
