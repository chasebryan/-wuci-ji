#!/usr/bin/env python3
"""Reject tracked binary artifacts from the Noether Forge source-review lane.

The fixed review range is checked repository-wide so renamed binary payloads do
not escape by moving outside a path containing ``noether``.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
REVIEW_BASE = "d9e1f5466a29cd4e0e0870b37398130b116c79e8"
RELEASE_PREFIX = "wucios/releases/noether-forge-v2.4.0/"
BUILD_PREFIX = "build/wucios/noether-forge-v2.4.0/"
PROHIBITED_SUFFIXES = (
    ".7z",
    ".a",
    ".apk",
    ".bin",
    ".bz2",
    ".c32",
    ".class",
    ".cpio",
    ".deb",
    ".dmg",
    ".dtb",
    ".dll",
    ".efi",
    ".elf",
    ".exe",
    ".fw",
    ".gif",
    ".gz",
    ".img",
    ".iso",
    ".jar",
    ".jpeg",
    ".jpg",
    ".ko",
    ".lz4",
    ".lzma",
    ".msi",
    ".mov",
    ".mp4",
    ".o",
    ".otf",
    ".pdf",
    ".pem",
    ".png",
    ".qcow2",
    ".rar",
    ".raw",
    ".rpm",
    ".so",
    ".squashfs",
    ".tar",
    ".tar.gz",
    ".ttf",
    ".ucode",
    ".vdi",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".war",
    ".wasm",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".xz",
    ".zip",
    ".zst",
)
ARTIFACT_UPLOAD_MARKERS = (
    b"actions/upload-artifact",
    b"actions/upload-pages-artifact",
    b"actions/upload-release-asset",
    b"gh release create",
    b"gh release upload",
    b"ncipollo/release-action",
    b"softprops/action-gh-release",
    b"svenstaro/upload-release-action",
)
GIT_LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"
BINARY_PREFIXES = (
    b"\x7fELF",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
    b"BZh",
    b"Rar!\x1a\x07",
    b"\xed\xab\xee\xdb",
    b"hsqs",
    b"sqsh",
)
WORKFLOW_PREFIX = ".github/workflows/"
ACTION_PREFIX = ".github/actions/"
LOCAL_USES = re.compile(
    rb"(?im)^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*['\"]?(\./\.github/(?:workflows|actions)/[^'\"#\s]+)"
)
REMOTE_WORKFLOW_USES = re.compile(
    rb"(?im)^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*['\"]?"
    rb"([^/'\"#\s]+/[^/'\"#\s]+/\.github/workflows/[^@'\"#\s]+@[^'\"#\s]+)"
)
ALL_USES = re.compile(
    rb"(?im)^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*['\"]?([^'\"#\s]+)"
)
ALLOWED_REMOTE_ACTIONS = {
    "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/setup-python": "39cd14951b08e74b54015e9e001cdefcf80e669f",
}


class SourceGuardError(RuntimeError):
    pass


def normalized_path(path: str) -> str:
    return path.replace(os.sep, "/").lower()


def is_noether_scoped(path: str) -> bool:
    normalized = normalized_path(path)
    return "noether" in normalized or normalized.startswith(RELEASE_PREFIX)


def is_noether_workflow(path: str, data: bytes) -> bool:
    normalized = normalized_path(path)
    return normalized.startswith(WORKFLOW_PREFIX) and (
        "noether" in normalized or b"noether" in data.lower()
    )


def is_binary_payload(data: bytes) -> bool:
    if not data:
        return False
    if any(data.startswith(prefix) for prefix in BINARY_PREFIXES):
        return True
    if data.startswith(b"MZ") and len(data) >= 0x40:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            return True
    if len(data) >= 0x8006 and data[0x8001:0x8006] == b"CD001":
        return True
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def contains_publication_primitive(data: bytes) -> bool:
    lower = data.lower().replace(b"\\\r\n", b" ").replace(b"\\\n", b" ")
    collapsed = b" ".join(lower.split())
    return any(marker in lower or marker in collapsed for marker in ARTIFACT_UPLOAD_MARKERS)


def local_uses(data: bytes) -> tuple[str, ...]:
    return tuple(os.fsdecode(match).replace("\\", "/") for match in LOCAL_USES.findall(data))


def remote_workflow_uses(data: bytes) -> tuple[str, ...]:
    return tuple(os.fsdecode(match) for match in REMOTE_WORKFLOW_USES.findall(data))


def unapproved_remote_actions(data: bytes) -> tuple[str, ...]:
    failures: list[str] = []
    for raw_reference in ALL_USES.findall(data):
        reference = os.fsdecode(raw_reference)
        lower = reference.lower()
        if lower.startswith("./") or "/.github/workflows/" in lower:
            continue
        action, separator, revision = lower.partition("@")
        if (
            separator
            and action in ALLOWED_REMOTE_ACTIONS
            and revision == ALLOWED_REMOTE_ACTIONS[action]
        ):
            continue
        failures.append(reference)
    return tuple(failures)


def resolve_local_use(reference: str, files: dict[str, bytes]) -> tuple[str, ...]:
    candidate = reference.removeprefix("./").lower()
    if candidate in files:
        return (candidate,)
    return tuple(
        path
        for path in (f"{candidate.rstrip('/')}/action.yml", f"{candidate.rstrip('/')}/action.yaml")
        if path in files
    )


def violations_for_file(path: str, data: bytes, mode: str = "100644") -> list[str]:
    normalized = normalized_path(path)
    noether_scoped = is_noether_scoped(path)
    violations: list[str] = []
    if normalized.startswith(BUILD_PREFIX):
        violations.append("tracked Noether build output")
    if noether_scoped and normalized.endswith(PROHIBITED_SUFFIXES):
        violations.append("prohibited Noether binary or archive extension")
    if noether_scoped and data.startswith(b"\x7fELF"):
        violations.append("tracked Noether ELF payload")
    elif noether_scoped and is_binary_payload(data):
        violations.append("tracked Noether non-source binary payload")
    if noether_scoped and data.startswith(GIT_LFS_POINTER_PREFIX):
        violations.append("tracked Noether Git LFS indirection")
    if noether_scoped and mode == "120000":
        violations.append("tracked Noether symlink")
    if noether_scoped and mode == "160000":
        violations.append("tracked Noether gitlink indirection")
    if is_noether_workflow(path, data):
        publication_primitive = contains_publication_primitive(data)
        if publication_primitive:
            violations.append("workflow can publish a Noether binary artifact")
        for reference in remote_workflow_uses(data):
            violations.append(f"workflow remote dependency cannot be inspected: {reference}")
        if not publication_primitive:
            for reference in unapproved_remote_actions(data):
                violations.append(f"workflow uses unapproved remote action: {reference}")
    return violations


def violations_for_repository(
    entries: Iterable[tuple[str, str, bytes]],
    review_paths: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    records = list(entries)
    changed = {
        normalized_path(path)
        for path in (
            review_paths if review_paths is not None else (record[0] for record in records)
        )
    }
    failures = [
        (path, reason)
        for path, mode, data in records
        for reason in violations_for_file(path, data, mode)
    ]
    for path, mode, data in records:
        normalized = normalized_path(path)
        if normalized not in changed:
            continue
        if mode == "120000":
            failures.append((path, "review-range symlink indirection"))
        if mode == "160000":
            failures.append((path, "review-range gitlink indirection"))
        if data.startswith(GIT_LFS_POINTER_PREFIX):
            failures.append((path, "review-range Git LFS indirection"))
        if normalized.endswith(PROHIBITED_SUFFIXES):
            failures.append((path, "review-range binary or archive extension"))
        if mode.startswith("100") and is_binary_payload(data):
            failures.append((path, "review-range non-source binary payload"))
    workflow_files = {
        normalized_path(path): data
        for path, _mode, data in records
        if normalized_path(path).startswith((WORKFLOW_PREFIX, ACTION_PREFIX))
    }
    roots = sorted(
        normalized_path(path)
        for path, _mode, data in records
        if is_noether_workflow(path, data)
    )
    for root in roots:
        pending = list(local_uses(workflow_files.get(root, b"")))
        visited = {root}
        while pending:
            reference = pending.pop()
            targets = resolve_local_use(reference, workflow_files)
            if not targets:
                failures.append((root, f"workflow local dependency cannot be inspected: {reference}"))
                continue
            for target in targets:
                if target in visited:
                    continue
                visited.add(target)
                data = workflow_files[target]
                if contains_publication_primitive(data):
                    failures.append(
                        (
                            root,
                            f"workflow can publish a Noether binary artifact through local dependency {target}",
                        )
                    )
                for remote in remote_workflow_uses(data):
                    failures.append(
                        (
                            root,
                            f"workflow remote dependency cannot be inspected through {target}: {remote}",
                        )
                    )
                if not contains_publication_primitive(data):
                    for remote in unapproved_remote_actions(data):
                        failures.append(
                            (
                                root,
                                f"workflow uses unapproved remote action through {target}: {remote}",
                            )
                        )
                pending.extend(local_uses(data))
    return list(dict.fromkeys(failures))


def review_changed_files(root: Path = ROOT, base: str = REVIEW_BASE) -> tuple[str, ...]:
    available = subprocess.run(
        ["git", "cat-file", "-e", f"{base}^{{commit}}"],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if available.returncode != 0:
        raise SourceGuardError(f"configured review base is unavailable: {base}")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, "HEAD"],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if ancestor.returncode != 0:
        raise SourceGuardError(f"configured review base is not an ancestor of HEAD: {base}")
    changed = subprocess.run(
        [
            "git",
            "diff",
            "--cached",
            "--no-renames",
            "--diff-filter=ACMT",
            "--name-only",
            "-z",
            base,
            "--",
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return tuple(os.fsdecode(path) for path in changed.stdout.split(b"\0") if path)


def tracked_files(
    root: Path = ROOT,
    review_paths: Iterable[str] = (),
) -> Iterable[tuple[str, str, bytes]]:
    review_set = {normalized_path(path) for path in review_paths}
    result = subprocess.run(
        ["git", "ls-files", "-s", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        header, raw_path = record.split(b"\t", 1)
        mode, object_id, _stage = header.decode("ascii").split(" ")
        path = os.fsdecode(raw_path)
        normalized = normalized_path(path)
        if mode == "160000" or not (
            normalized in review_set
            or is_noether_scoped(path)
            or normalized.startswith(WORKFLOW_PREFIX)
            or normalized.startswith(ACTION_PREFIX)
        ):
            data = b""
        else:
            blob = subprocess.run(
                ["git", "cat-file", "blob", object_id],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            data = blob.stdout
        yield path, mode, data


def main() -> int:
    try:
        review_paths = review_changed_files()
        entries = list(tracked_files(review_paths=review_paths))
    except (SourceGuardError, subprocess.CalledProcessError) as exc:
        print("Noether Forge source-only guard: FAIL", file=sys.stderr)
        print(f"- {exc}", file=sys.stderr)
        return 1
    failures = [
        f"{path}: {reason}"
        for path, reason in violations_for_repository(entries, review_paths)
    ]
    if failures:
        print("Noether Forge source-only guard: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(
        "Noether Forge source-only guard: PASS "
        f"({len(entries)} tracked files checked; "
        f"{len(review_paths)} review-range paths from {REVIEW_BASE})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
