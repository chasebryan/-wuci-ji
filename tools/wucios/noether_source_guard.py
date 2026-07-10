#!/usr/bin/env python3
"""Reject tracked binary artifacts from the Noether Forge source-review lane."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
RELEASE_PREFIX = "wucios/releases/noether-forge-v2.4.0/"
BUILD_PREFIX = "build/wucios/noether-forge-v2.4.0/"
PROHIBITED_SUFFIXES = (
    ".apk",
    ".bin",
    ".c32",
    ".deb",
    ".dtb",
    ".efi",
    ".fw",
    ".gz",
    ".img",
    ".iso",
    ".ko",
    ".mov",
    ".mp4",
    ".pem",
    ".rpm",
    ".squashfs",
    ".tar",
    ".tar.gz",
    ".ucode",
    ".webm",
    ".xz",
    ".zip",
    ".zst",
)
ARTIFACT_UPLOAD_MARKERS = (
    b"actions/upload-artifact",
    b"gh release create",
    b"gh release upload",
    b"softprops/action-gh-release",
)


def violations_for_file(path: str, data: bytes, mode: str = "100644") -> list[str]:
    normalized = path.replace(os.sep, "/").lower()
    noether_scoped = "noether" in normalized or normalized.startswith(RELEASE_PREFIX)
    violations: list[str] = []
    if normalized.startswith(BUILD_PREFIX):
        violations.append("tracked Noether build output")
    if noether_scoped and normalized.endswith(PROHIBITED_SUFFIXES):
        violations.append("prohibited Noether binary or archive extension")
    if noether_scoped and data.startswith(b"\x7fELF"):
        violations.append("tracked Noether ELF payload")
    if noether_scoped and mode == "120000":
        violations.append("tracked Noether symlink")
    if normalized.startswith(".github/workflows/") and b"noether" in data.lower():
        if any(marker in data.lower() for marker in ARTIFACT_UPLOAD_MARKERS):
            violations.append("workflow can publish a Noether binary artifact")
    return violations


def tracked_files(root: Path = ROOT) -> Iterable[tuple[str, str, bytes]]:
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
        normalized = path.replace(os.sep, "/").lower()
        if mode == "160000" or not (
            "noether" in normalized or normalized.startswith(".github/workflows/")
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
    failures: list[str] = []
    checked = 0
    for path, mode, data in tracked_files():
        checked += 1
        failures.extend(f"{path}: {reason}" for reason in violations_for_file(path, data, mode))
    if failures:
        print("Noether Forge source-only guard: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Noether Forge source-only guard: PASS ({checked} tracked files checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
