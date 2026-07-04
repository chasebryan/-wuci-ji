#!/usr/bin/env python3
"""Audit candidate public release artifacts for private local material.

This is a release-surface audit, not a whole-host forensic scan. It scans only
operator-selected files/directories and reports redacted findings so secrets are
not copied into evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "wuci-release-privacy-audit-v1"
DEFAULT_OUT = Path("build/wuci-os/privacy-audit.json")
DEFAULT_PATHS = (
    Path("build/daylight"),
    Path("build/wuci-os/overlay"),
    Path("build/wuci-os/final/Wuci-OS-x86_64-musl.iso"),
    Path("build/wuci-os/final/Wuci-OS-x86_64-musl.iso.sha256"),
    Path("build/wuci-os/final/manifest.json"),
    Path("build/wuci-os/final/daylight-manifest.json"),
    Path("build/wuci-os/final/rootfs-manifest.json"),
    Path("build/wuci-os/final/wuci-os-boot-splash.png"),
    Path("build/wuci-os/final/wuci-os-overlay.tar"),
    Path("build/wuci-os/final/wuci-os-source-kit.tar"),
    Path("build/wuci-os/release-evidence"),
    Path("site"),
)
READ_CHUNK = 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024

NON_CLAIM = (
    "This audit scans selected candidate public artifact paths for high "
    "confidence private-material indicators. It does not prove host cleanliness, "
    "runtime containment, independent review, or absence of secrets outside the "
    "selected paths."
)

PRIVATE_KEY_BEGIN_RE = rb"-----BEGIN [A-Z0-9 ]*" + rb"PRIVATE KEY-----"
PRIVATE_KEY_END_RE = rb"-----END [A-Z0-9 ]*" + rb"PRIVATE KEY-----"
OPENSSH_PRIVATE_KEY_BEGIN = rb"-----BEGIN OPENSSH " + rb"PRIVATE KEY-----"
OPENSSH_PRIVATE_KEY_END = rb"-----END OPENSSH " + rb"PRIVATE KEY-----"

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes], str], ...] = (
    (
        "private_key_block",
        re.compile(
            PRIVATE_KEY_BEGIN_RE
            + rb"[\s\S]{16,200000}"
            + PRIVATE_KEY_END_RE
            + rb"|"
            + OPENSSH_PRIVATE_KEY_BEGIN
            + rb"[\s\S]{16,200000}"
            + OPENSSH_PRIVATE_KEY_END
        ),
        "private key block",
    ),
    (
        "openai_api_key",
        re.compile(rb"\b(?:sk-proj|sk)-[A-Za-z0-9_-]{20,}\b"),
        "OpenAI-style API key",
    ),
    (
        "github_token",
        re.compile(rb"\b(?:gh[opsru]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        "GitHub-style token",
    ),
    (
        "slack_token",
        re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "Slack-style token",
    ),
    (
        "aws_access_key",
        re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
        "AWS access key id",
    ),
    (
        "email_address",
        re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "email address",
    ),
)

SENSITIVE_PATH_PARTS = {
    ".aws": "AWS config/cache path",
    ".azure": "Azure config/cache path",
    ".config/gh": "GitHub CLI auth path",
    ".docker": "Docker auth path",
    ".gnupg": "GnuPG private config path",
    ".kube": "Kubernetes config path",
    ".netrc": "netrc credential path",
    ".npmrc": "npm credential path",
    ".pypirc": "Python package credential path",
    ".ssh": "SSH private config path",
    "id_dsa": "SSH private key filename",
    "id_ecdsa": "SSH private key filename",
    "id_ed25519": "SSH private key filename",
    "id_rsa": "SSH private key filename",
    "known_hosts": "SSH known-hosts fingerprint path",
}


class PrivacyAuditError(RuntimeError):
    pass


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redaction_digest(match: bytes) -> str:
    return sha256_bytes(match)[:16]


def _looks_textual(data: bytes) -> bool:
    if not data or b"\x00" in data:
        return False
    printable = sum(1 for byte in data if byte in b"\t\r\n" or 32 <= byte <= 126)
    return printable / len(data) >= 0.85


def _safe_display(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _validate_archive_name(name: str) -> bool:
    pure = PurePosixPath(name)
    return bool(name) and not pure.is_absolute() and all(part not in {"", ".", ".."} for part in pure.parts)


def _path_indicators(display_path: str) -> list[dict[str, str]]:
    normalized = display_path.replace("\\", "/")
    parts = set(PurePosixPath(normalized).parts)
    findings: list[dict[str, str]] = []
    for marker, message in sorted(SENSITIVE_PATH_PARTS.items()):
        if "/" in marker:
            if marker in normalized:
                findings.append({"kind": "sensitive_path", "indicator": marker, "message": message})
            continue
        if marker in parts:
            findings.append({"kind": "sensitive_path", "indicator": marker, "message": message})
    return findings


def _scan_bytes(data: bytes, display_path: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for kind, pattern, message in SECRET_PATTERNS:
        for match in pattern.finditer(data):
            if kind == "email_address":
                if match.group(0).lower().endswith(b"@openssh.com"):
                    continue
                start = max(0, match.start() - 64)
                end = min(len(data), match.end() + 64)
                if not _looks_textual(data[start:end]):
                    continue
            findings.append(
                {
                    "kind": kind,
                    "path": display_path,
                    "message": message,
                    "match_sha256_16": _redaction_digest(match.group(0)),
                }
            )
            break
    return findings


def _scan_regular_file(path: Path, display_path: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return (
            [{"kind": "unsafe_file", "path": display_path, "message": "release artifact must not be a symlink"}],
            {"path": display_path, "type": "symlink", "bytes": 0},
        )
    if not stat.S_ISREG(info.st_mode):
        return ([], {"path": display_path, "type": "non-regular", "bytes": 0})
    if info.st_nlink != 1:
        return (
            [{"kind": "unsafe_file", "path": display_path, "message": "release artifact must not be hardlinked"}],
            {"path": display_path, "type": "hardlinked", "bytes": info.st_size},
        )

    findings = [{"path": display_path, **item} for item in _path_indicators(display_path)]
    if path.suffix.lower() in {".iso", ".ova"}:
        digest = sha256_file(path)
        return (
            _dedupe_findings(findings),
            {
                "path": display_path,
                "type": path.suffix.lower().lstrip(".") + "-container",
                "bytes": info.st_size,
                "sha256": digest,
                "content_scan": f"skipped-raw-{path.suffix.lower().lstrip('.')}-container",
            },
        )
    digest = hashlib.sha256()
    overlap = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            window = overlap + chunk
            findings.extend(_scan_bytes(window, display_path))
            overlap = window[-256:]
    return (
        _dedupe_findings(findings),
        {"path": display_path, "type": "file", "bytes": info.st_size, "sha256": digest.hexdigest()},
    )


def _scan_tar(path: Path, display_path: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                member_path = f"{display_path}!/{member.name}"
                if not _validate_archive_name(member.name):
                    findings.append({"kind": "unsafe_archive_member", "path": member_path, "message": "unsafe archive member path"})
                    continue
                findings.extend({"path": member_path, **item} for item in _path_indicators(member_path))
                if member.issym() or member.islnk():
                    findings.append({"kind": "unsafe_archive_member", "path": member_path, "message": "archive member must not be a link"})
                    continue
                if not member.isfile():
                    continue
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                findings.extend(_scan_bytes(data, member_path))
    except (tarfile.TarError, OSError):
        return []
    return findings


def _scan_zip(path: Path, display_path: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(path, "r") as archive:
            for member in archive.infolist():
                member_path = f"{display_path}!/{member.filename}"
                if not _validate_archive_name(member.filename):
                    findings.append({"kind": "unsafe_archive_member", "path": member_path, "message": "unsafe archive member path"})
                    continue
                findings.extend({"path": member_path, **item} for item in _path_indicators(member_path))
                mode_type = (member.external_attr >> 16) & 0o170000
                if mode_type and mode_type != stat.S_IFREG:
                    findings.append({"kind": "unsafe_archive_member", "path": member_path, "message": "archive member must be a regular file"})
                    continue
                if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    continue
                data = archive.read(member, pwd=None)
                findings.extend(_scan_bytes(data, member_path))
    except (zipfile.BadZipFile, OSError):
        return []
    return findings


def _dedupe_findings(findings: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[tuple[str, str], ...]] = set()
    result: list[dict[str, str]] = []
    for item in findings:
        key = tuple(sorted(item.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(item))
    return result


def iter_paths(paths: Iterable[Path]) -> Iterable[tuple[Path, Path]]:
    for root in paths:
        if not root.exists():
            continue
        info = root.lstat()
        if stat.S_ISLNK(info.st_mode):
            yield root, root
            continue
        if stat.S_ISDIR(info.st_mode):
            for current, dirnames, filenames in os.walk(root):
                current_path = Path(current)
                kept_dirs: list[str] = []
                for dirname in sorted(dirnames):
                    child = current_path / dirname
                    try:
                        child_info = child.lstat()
                    except OSError:
                        continue
                    if stat.S_ISLNK(child_info.st_mode):
                        yield root, child
                    elif stat.S_ISDIR(child_info.st_mode):
                        kept_dirs.append(dirname)
                dirnames[:] = kept_dirs
                for filename in sorted(filenames):
                    yield root, current_path / filename
        else:
            yield root, root


def audit_paths(paths: Iterable[Path]) -> dict[str, Any]:
    roots = [Path(path) for path in paths]
    findings: list[dict[str, str]] = []
    scanned_files: list[dict[str, Any]] = []
    existing_roots: list[str] = []
    missing_roots: list[str] = []

    for root in roots:
        if root.exists():
            existing_roots.append(str(root))
        else:
            missing_roots.append(str(root))

    for root, path in iter_paths(roots):
        display_path = _safe_display(path, Path.cwd())
        file_findings, record = _scan_regular_file(path, display_path)
        findings.extend(file_findings)
        scanned_files.append(record)
        suffix = path.suffix.lower()
        if suffix in {".tar", ".ova"} or "".join(path.suffixes[-2:]).lower() in {".tar.gz", ".tgz"}:
            findings.extend(_scan_tar(path, display_path))
        elif suffix in {".zip", ".jar", ".whl"}:
            findings.extend(_scan_zip(path, display_path))

    findings = _dedupe_findings(findings)
    status = "pass" if not findings else "fail"
    return {
        "schema": SCHEMA,
        "status": status,
        "roots": {"existing": existing_roots, "missing": missing_roots},
        "summary": {
            "files_scanned": len(scanned_files),
            "bytes_scanned": sum(int(item.get("bytes", 0)) for item in scanned_files),
            "findings": len(findings),
        },
        "findings": findings,
        "scanned_files": scanned_files,
        "non_claim_boundary": NON_CLAIM,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(stable_json(report), encoding="utf-8")
    os.replace(tmp, path)


def run_audit(args: argparse.Namespace) -> int:
    paths = [Path(value) for value in args.paths] if args.paths else list(DEFAULT_PATHS)
    report = audit_paths(paths)
    write_report(Path(args.out), report)
    print(f"wuci-release-privacy-audit: {report['status']}")
    print(f"files: {report['summary']['files_scanned']}")
    print(f"findings: {report['summary']['findings']}")
    print(f"report: {args.out}")
    if args.json:
        print(stable_json(report), end="")
    return 0 if report["status"] == "pass" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit public release artifacts for private material.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit", help="scan selected release artifact paths")
    audit.add_argument("paths", nargs="*", help="files or directories to scan")
    audit.add_argument("--out", default=str(DEFAULT_OUT), help="privacy audit report path")
    audit.add_argument("--json", action="store_true", help="also print the full redacted JSON report")
    audit.set_defaults(func=run_audit)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
