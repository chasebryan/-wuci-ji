"""Strict public artifact firewall for Aperture Bastion.

Recursively scans a public output directory before any upload or release.
Rejects private filenames, private directories, private content markers,
symlinks, hardlinks, hidden components, oversized files, key-shaped content,
unexpected files, missing manifest files, and SHA256SUMS drift. Writes a
firewall report only after the scan passes, and only outside the scanned
root.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path
from typing import Any

from . import profile
from .canonical_json import json_bytes, load_json_no_floats
from .capsule import CAPSULE_FILENAME, SUMS_FILENAME, verify_capsule
from .pathsafe import PathSafetyError, atomic_write_bytes, read_public_bytes, sha256_file

REPORT_SCHEMA = "daylight-v19-aperture-firewall-report"
SUMS_LINE_RE = re.compile(r"^([0-9a-f]{64})  (.+)$")


class FirewallScanError(ValueError):
    pass


def default_report_path(root: Path | str) -> Path:
    root = Path(root)
    return root.parent / (root.name + ".firewall-report.v19.json")


def _parse_sha256sums(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = SUMS_LINE_RE.fullmatch(line)
        if match is None:
            raise FirewallScanError(f"invalid SHA256SUMS line: {line!r}")
        digest, name = match.group(1), match.group(2)
        if name in entries:
            raise FirewallScanError(f"duplicate SHA256SUMS entry: {name}")
        entries[name] = digest
    return entries


def scan_public_root(
    root: Path | str,
    *,
    max_file_bytes: int = profile.DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    root_path = Path(root)
    violations: list[dict[str, str]] = []

    def add(path: str, reason: str) -> None:
        violations.append({"path": path, "reason": reason})

    if root_path.is_symlink():
        raise FirewallScanError(f"public root is a symlink: {root_path}")
    if not root_path.exists():
        raise FirewallScanError(f"public root does not exist: {root_path}")
    if not root_path.is_dir():
        raise FirewallScanError(f"public root is not a directory: {root_path}")

    files: list[str] = []
    for path in sorted(root_path.rglob("*")):
        relative = path.relative_to(root_path).as_posix()
        try:
            st = path.lstat()
        except OSError as exc:
            add(relative, f"unreadable_path:{exc}")
            continue
        if stat.S_ISLNK(st.st_mode):
            add(relative, "symlink_in_public_artifact")
            continue
        if stat.S_ISDIR(st.st_mode):
            for reason in profile.check_path_name(relative):
                add(relative, reason)
            continue
        if not stat.S_ISREG(st.st_mode):
            add(relative, "non_regular_public_artifact_member")
            continue
        files.append(relative)
        if st.st_nlink > 1:
            add(relative, "hardlink_in_public_artifact")
            continue
        for reason in profile.check_path_name(relative):
            add(relative, reason)
        if st.st_size > max_file_bytes:
            add(relative, "file_exceeds_public_artifact_size_limit")
            continue
        try:
            data = read_public_bytes(path, relative, max_bytes=max_file_bytes)
        except PathSafetyError as exc:
            add(relative, f"path_safety_error:{exc}")
            continue
        for reason in profile.check_content(data, rel_path=relative):
            add(relative, reason)

    capsule_digest_value: str | None = None
    if CAPSULE_FILENAME not in files:
        add(CAPSULE_FILENAME, "capsule_missing_from_public_root")
    else:
        try:
            capsule = load_json_no_floats(root_path / CAPSULE_FILENAME)
            result = verify_capsule(
                capsule,
                base_dir=root_path,
                check_subject_files=False,
                check_public_files=True,
            )
            capsule_digest_value = result["capsule_digest"]
            for blocker in result["blockers"]:
                add(CAPSULE_FILENAME, f"capsule_verify:{blocker}")
            if result["verified"]:
                manifest_paths = {entry["path"] for entry in capsule["public_manifest"]}
                expected = manifest_paths | set(capsule["allowed_extra_files"])
                expected |= {CAPSULE_FILENAME, SUMS_FILENAME}
                for extra in sorted(set(files) - expected):
                    add(extra, "unexpected_public_file")
                for missing in sorted(manifest_paths - set(files)):
                    add(missing, "manifest_listed_file_missing")
                if SUMS_FILENAME not in files:
                    add(SUMS_FILENAME, "sha256sums_missing")
                else:
                    try:
                        sums_text = read_public_bytes(
                            root_path / SUMS_FILENAME,
                            SUMS_FILENAME,
                            max_bytes=max_file_bytes,
                        ).decode("utf-8")
                        sums = _parse_sha256sums(sums_text)
                        hashable = set(files) - {SUMS_FILENAME}
                        if set(sums) != hashable:
                            add(SUMS_FILENAME, "sha256sums_file_set_mismatch")
                        for name in sorted(set(sums) & hashable):
                            if sha256_file(root_path / name) != sums[name]:
                                add(name, "sha256sum_mismatch")
                        for entry in capsule["public_manifest"]:
                            if sums.get(entry["path"]) != entry["sha256"]:
                                add(entry["path"], "sha256sums_manifest_mismatch")
                    except (FirewallScanError, OSError) as exc:
                        add(SUMS_FILENAME, f"sha256sums_invalid:{exc}")
        except (ValueError, OSError) as exc:
            add(CAPSULE_FILENAME, f"capsule_invalid:{exc}")

    return {
        "schema": REPORT_SCHEMA,
        "ok": not violations,
        "profile_id": profile.PROFILE_ID,
        "profile_digest": profile.PROFILE_DIGEST,
        "scanned_root": Path(root).as_posix(),
        "file_count": len(files),
        "capsule_digest": capsule_digest_value,
        "violations": violations,
    }


def run_firewall(
    root: Path | str,
    *,
    report_path: Path | str | None = None,
    max_file_bytes: int = profile.DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    root_path = Path(root)
    report = scan_public_root(root_path, max_file_bytes=max_file_bytes)
    target = Path(report_path) if report_path is not None else default_report_path(root_path)
    resolved_root = root_path.resolve()
    resolved_target = target.parent.resolve() / target.name
    if resolved_target == resolved_root or resolved_root in resolved_target.parents:
        raise FirewallScanError("firewall report must be written outside the public root")
    if target.exists() or target.is_symlink():
        recognized = False
        if target.is_file() and not target.is_symlink():
            try:
                old = load_json_no_floats(target)
                recognized = isinstance(old, dict) and old.get("schema") == REPORT_SCHEMA
            except (ValueError, OSError):
                recognized = False
        if not recognized:
            raise FirewallScanError(f"refusing to replace unrecognized report path: {target}")
        target.unlink()
    if report["ok"]:
        atomic_write_bytes(target, json_bytes(report))
        report["report_path"] = target.as_posix()
    return report
