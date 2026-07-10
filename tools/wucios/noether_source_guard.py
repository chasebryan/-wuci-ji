#!/usr/bin/env python3
"""Reject tracked binary artifacts from the Noether Forge source-review lane.

The fixed review range is checked repository-wide so renamed binary payloads do
not escape by moving outside a path containing ``noether``.
"""

from __future__ import annotations

import base64
import binascii
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
ALLOWED_WORKFLOW_ACTIONS = frozenset({
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "actions/setup-python@39cd14951b08e74b54015e9e001cdefcf80e669f",
})
ALLOWED_WORKFLOW_RUN_COMMANDS = frozenset({
    "make wucios-noether-forge-source-guard",
    "make wucios-noether-forge-test",
    "make wucios-validate",
})
WORKFLOW_EXECUTION_KEY = re.compile(
    rb"(?i)^(?P<indent>[ \t]*)(?:-[ \t]*)?"
    rb"(?P<quote>['\"]?)(?P<key>uses|run)(?P=quote)[ \t]*:[ \t]*(?P<value>.*)$"
)
FLOW_EXECUTION_KEY = re.compile(
    rb"(?i)(?:^|[,{])[ \t]*['\"]?(?:uses|run)['\"]?[ \t]*:"
)
BASE64_TOKEN = re.compile(
    rb"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])"
)
HEX_TOKEN = re.compile(rb"(?i)(?<![0-9a-f])([0-9a-f]{64,})(?![0-9a-f])")
BASE64_LINE_BLOCK = re.compile(
    rb"(?m)(?:^[ \t]*[A-Za-z0-9+/]{16,}={0,2}[ \t]*(?:\r?\n|$)){2,}"
)
HEX_LINE_BLOCK = re.compile(
    rb"(?im)(?:^[ \t]*[0-9a-f]{32,}[ \t]*(?:\r?\n|$)){2,}"
)
ENCODED_SIGNATURE_SAMPLE_BYTES = 0x8006


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


def has_binary_signature(data: bytes) -> bool:
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
    return False


def is_binary_payload(data: bytes) -> bool:
    if not data:
        return False
    if has_binary_signature(data):
        return True
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _base64_decodes_to_binary_signature(candidate: bytes) -> bool:
    compact = b"".join(candidate.split())
    if len(compact) < 32 or len(compact) % 4 == 1:
        return False
    sample_chars = ((ENCODED_SIGNATURE_SAMPLE_BYTES + 2) // 3) * 4
    sample = compact[:sample_chars]
    sample += b"=" * (-len(sample) % 4)
    try:
        decoded = base64.b64decode(sample, validate=True)
    except (binascii.Error, ValueError):
        return False
    return has_binary_signature(decoded)


def _hex_decodes_to_binary_signature(candidate: bytes) -> bool:
    compact = b"".join(candidate.split())
    if len(compact) < 64 or len(compact) % 2:
        return False
    sample = compact[: ENCODED_SIGNATURE_SAMPLE_BYTES * 2]
    try:
        decoded = bytes.fromhex(sample.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return False
    return has_binary_signature(decoded)


def contains_encoded_binary_payload(data: bytes) -> bool:
    """Recognize common textual encodings only when decoded magic is binary."""

    base64_candidates = [match.group(1) for match in BASE64_TOKEN.finditer(data)]
    base64_candidates.extend(BASE64_LINE_BLOCK.findall(data))
    if any(_base64_decodes_to_binary_signature(candidate) for candidate in base64_candidates):
        return True
    hex_candidates = [match.group(1) for match in HEX_TOKEN.finditer(data)]
    hex_candidates.extend(HEX_LINE_BLOCK.findall(data))
    return any(_hex_decodes_to_binary_signature(candidate) for candidate in hex_candidates)


def contains_publication_primitive(data: bytes) -> bool:
    lower = data.lower().replace(b"\\\r\n", b" ").replace(b"\\\n", b" ")
    collapsed = b" ".join(lower.split())
    return any(marker in lower or marker in collapsed for marker in ARTIFACT_UPLOAD_MARKERS)


def _workflow_scalar(raw_value: bytes, *, allow_comment: bool) -> str | None:
    value = raw_value.strip()
    if allow_comment:
        value = re.split(rb"[ \t]+#", value, maxsplit=1)[0].rstrip()
    if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in (b"'", b'"'):
        value = value[1:-1]
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return None


def workflow_execution_violations(data: bytes) -> tuple[str, ...]:
    """Allow only the exact reviewed action pins and Make targets."""

    failures: list[str] = []
    lines = data.splitlines()
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(b"#"):
            continue
        match = WORKFLOW_EXECUTION_KEY.match(line)
        if match is None:
            if FLOW_EXECUTION_KEY.search(line):
                failures.append("workflow uses unsupported execution-key syntax")
            continue
        key = match.group("key").lower()
        value = _workflow_scalar(match.group("value"), allow_comment=key == b"uses")
        if key == b"uses":
            if value not in ALLOWED_WORKFLOW_ACTIONS:
                failures.append(f"workflow action is not allowlisted: {value or '<invalid>'}")
            continue
        if value not in ALLOWED_WORKFLOW_RUN_COMMANDS:
            failures.append(f"workflow run command is not allowlisted: {value or '<invalid>'}")
            continue
        indentation = len(match.group("indent").expandtabs(8))
        for continuation in lines[index + 1:]:
            if not continuation.strip() or continuation.lstrip().startswith(b"#"):
                continue
            continuation_indent = len(continuation) - len(continuation.lstrip(b" \t"))
            if continuation_indent > indentation:
                failures.append("workflow run command uses unsupported multiline syntax")
            break
    return tuple(dict.fromkeys(failures))


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
    elif noether_scoped and contains_encoded_binary_payload(data):
        violations.append("tracked Noether encoded binary payload")
    if noether_scoped and data.startswith(GIT_LFS_POINTER_PREFIX):
        violations.append("tracked Noether Git LFS indirection")
    if noether_scoped and mode == "120000":
        violations.append("tracked Noether symlink")
    if noether_scoped and mode == "160000":
        violations.append("tracked Noether gitlink indirection")
    if is_noether_workflow(path, data):
        if contains_publication_primitive(data):
            violations.append("workflow can publish a Noether binary artifact")
        violations.extend(workflow_execution_violations(data))
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
        if mode.startswith("100") and contains_encoded_binary_payload(data):
            failures.append((path, "review-range encoded binary payload"))
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
