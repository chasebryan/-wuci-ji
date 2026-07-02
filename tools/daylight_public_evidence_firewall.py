#!/usr/bin/env python3
"""Daylight Public Evidence Firewall.

PrivateMaterial(x) and PublicArtifact(x) is a hard failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


SCHEMA = "daylight-public-evidence-firewall-v1"
DAYLIGHT_V15_PUBLIC_FILES = {
    "SHA256SUMS",
    "artifact-manifest.json",
    "frontier-report.v15-meridian.json",
    "frontier-report.v15-meridian.md",
    "ledger.with-scorecard.jsonl",
    "reproducibility-receipt.v15-meridian.json",
    "scorecard.v15-meridian.json",
}
PUBLIC_DOC_SUFFIXES = {".css", ".html", ".js", ".json", ".md", ".png", ".svg", ".txt", ".webp", ".yml"}
FORBIDDEN_SUFFIXES = {
    ".key",
    ".pem",
    ".priv",
    ".secret",
    ".mae",
    ".dhv",
    ".dhr",
}
FORBIDDEN_PATH_PARTS = {
    ".meridian-vault",
    "private",
    "private-transcripts",
    "smoke-vault",
    "store",
    "vault",
    "vault-work",
}
FORBIDDEN_NAME_RE = re.compile(
    r"(^|[._-])(secret|plaintext|plain|opened|open-output|keyfile|vault-key|passphrase|luks|private)([._-]|$)",
    re.IGNORECASE,
)
HEX_KEY_RE = re.compile(rb"^[0-9a-fA-F]{64}\s*$")
SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"PRIVATE KEY",
    b"API_KEY=",
    b"hunter2",
    b"DAYLIGHT_BASTION_PASSPHRASE",
    b"daylight-v18-fixture-passphrase",
    b"meridian vault demo: sealed by evidence, opened by proof",
)
BROAD_UPLOAD_ROOTS = {
    "build/",
    "build/daylight/",
    "build/daylight/v15-meridian/",
    "build/daylight/v15-meridian-private/",
}
PRIVATE_UPLOAD_PARTS = {"private", "vault", "vault-work", "smoke-vault", ".meridian-vault"}


class FirewallError(RuntimeError):
    pass


def violation(path: str, reason: str, severity: str = "critical") -> dict[str, str]:
    return {"path": path, "reason": reason, "severity": severity}


def rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return str(path)


def base_report(scanned_root: str, command: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": True,
        "command": command,
        "scanned_root": scanned_root,
        "violations": [],
    }


def add(report: dict[str, Any], path: str, reason: str, severity: str = "critical") -> None:
    report["ok"] = False
    report["violations"].append(violation(path, reason, severity))


def iter_paths(root: Path) -> list[Path]:
    if not root.exists():
        raise FirewallError(f"scan root does not exist: {root}")
    if not root.is_dir():
        raise FirewallError(f"scan root is not a directory: {root}")
    return sorted(root.rglob("*"))


def check_profile(root: Path, files: list[Path], profile: str | None, report: dict[str, Any]) -> None:
    if profile is None:
        return
    if profile == "daylight-v15-meridian-public":
        actual = {rel(path, root) for path in files}
        for name in sorted(actual - DAYLIGHT_V15_PUBLIC_FILES):
            add(report, name, "unexpected_public_artifact_file")
        for name in sorted(DAYLIGHT_V15_PUBLIC_FILES - actual):
            add(report, name, "missing_public_artifact_file")
        return
    if profile == "public-docs":
        for path in files:
            if path.suffix.lower() not in PUBLIC_DOC_SUFFIXES:
                add(report, rel(path, root), "unexpected_public_doc_suffix")
        return
    raise FirewallError(f"unknown profile: {profile}")


def check_json_oracle(path: Path, root: Path, data: bytes, report: dict[str, Any]) -> None:
    if path.suffix.lower() not in {".json", ".jsonl"}:
        return
    text = data.decode("utf-8", "ignore")
    if '"plaintext_bytes"' in text and re.search(r'"sha256"\s*:', text) and '"envelope_sha256"' not in text:
        add(report, rel(path, root), "plaintext_sha256_oracle")
    if path.name == "index.json" and '"plaintext_bytes"' in text:
        add(report, rel(path, root), "public_vault_index")


def scan_root(root: Path, *, profile: str | None, max_file_bytes: int) -> dict[str, Any]:
    report = base_report(str(root), "scan")
    files: list[Path] = []
    for path in iter_paths(root):
        relative = rel(path, root)
        try:
            st = path.lstat()
        except OSError as exc:
            add(report, relative, f"unreadable_path:{exc}")
            continue
        if stat.S_ISLNK(st.st_mode):
            add(report, relative, "symlink_inside_public_artifact")
            continue
        if stat.S_ISDIR(st.st_mode):
            if set(path.relative_to(root).parts) & FORBIDDEN_PATH_PARTS:
                add(report, relative, "public_artifact_contains_private_directory")
            continue
        if not stat.S_ISREG(st.st_mode):
            add(report, relative, "non_regular_public_artifact_member")
            continue
        files.append(path)
        if st.st_nlink > 1:
            add(report, relative, "hardlink_anomaly")
        if (st.st_mode & 0o777) == 0o600:
            add(report, relative, "private_mode_file_in_public_artifact")
        if st.st_size > max_file_bytes:
            add(report, relative, "file_exceeds_public_artifact_size_limit")
        parts = set(path.relative_to(root).parts[:-1])
        if parts & FORBIDDEN_PATH_PARTS:
            add(report, relative, "public_artifact_contains_private_directory")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            add(report, relative, "forbidden_private_material_suffix")
        if FORBIDDEN_NAME_RE.search(path.name):
            add(report, relative, "forbidden_secret_path")
        data = path.read_bytes()
        if HEX_KEY_RE.match(data):
            add(report, relative, "raw_key_shaped_material")
        for marker in SECRET_MARKERS:
            if marker in data:
                add(report, relative, "known_secret_marker")
                break
        check_json_oracle(path, root, data, report)
    check_profile(root, files, profile, report)
    report["file_count"] = len(files)
    return report


def parse_sha256sums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        if sep != "  " or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise FirewallError(f"invalid SHA256SUMS line: {line}")
        entries[name] = digest
    return entries


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest(manifest_path: Path, root: Path | None) -> dict[str, Any]:
    root = root or manifest_path.parent
    report = base_report(str(root), "verify-manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    outputs = set(manifest.get("outputs", {}))
    expected = set(outputs) | {"artifact-manifest.json", "SHA256SUMS"}
    actual = {rel(path, root) for path in root.rglob("*") if path.is_file() and not path.is_symlink()}
    for name in sorted(actual - expected):
        add(report, name, "unlisted_file_in_public_artifact")
    for name in sorted(expected - actual):
        add(report, name, "manifest_listed_file_missing")
    sha_path = root / "SHA256SUMS"
    if sha_path.is_file():
        try:
            sums = parse_sha256sums(sha_path)
            if set(sums) != expected - {"SHA256SUMS"}:
                add(report, "SHA256SUMS", "sha256sums_public_file_set_mismatch")
            for name, digest in sorted(sums.items()):
                file_path = root / name
                if file_path.is_file() and sha256_file(file_path) != digest:
                    add(report, name, "sha256sum_mismatch")
        except (OSError, FirewallError) as exc:
            add(report, "SHA256SUMS", f"sha256sums_invalid:{exc}")
    else:
        add(report, "SHA256SUMS", "sha256sums_missing")
    scan = scan_root(root, profile="daylight-v15-meridian-public", max_file_bytes=5_000_000)
    for item in scan["violations"]:
        report["ok"] = False
        report["violations"].append(item)
    return report


def normalized_upload_path(line: str) -> str:
    value = line.split(":", 1)[1].strip().strip("'\"")
    return value.rstrip("/") + "/"


def extract_upload_blocks(lines: list[str]) -> list[tuple[int, list[str]]]:
    blocks: list[tuple[int, list[str]]] = []
    for index, line in enumerate(lines):
        if "actions/upload-artifact@" not in line:
            continue
        start = index
        while start > 0 and not lines[start].lstrip().startswith("- name:"):
            start -= 1
        end = index + 1
        while end < len(lines) and not lines[end].lstrip().startswith("- name:"):
            end += 1
        blocks.append((index + 1, lines[start:end]))
    return blocks


def check_workflow(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    report = base_report(str(path), "check-workflow")
    upload_blocks = extract_upload_blocks(lines)
    if upload_blocks and not re.search(r"(?m)^permissions:\n(?:  .+\n)*  contents: read$", text):
        add(report, str(path), "workflow_permissions_missing_contents_read")
    for line_number, block in upload_blocks:
        joined = "\n".join(block)
        if "if-no-files-found: warn" in joined:
            add(report, f"{path}:{line_number}", "artifact_upload_warns_on_missing_files")
        if re.search(r"(?m)^\s*if:\s*always\(\)\s*$", joined):
            add(report, f"{path}:{line_number}", "artifact_upload_uses_always")
        paths = [normalized_upload_path(line) for line in block if re.match(r"\s*path:\s*", line)]
        if not paths:
            add(report, f"{path}:{line_number}", "artifact_upload_missing_path")
        for upload_path in paths:
            if upload_path in BROAD_UPLOAD_ROOTS:
                add(report, upload_path, "broad_upload_root")
            if set(Path(upload_path).parts) & PRIVATE_UPLOAD_PARTS:
                add(report, upload_path, "secret_path_in_upload_path")
        prefix = "\n".join(lines[max(0, line_number - 25): line_number])
        if "daylight-public-artifact-firewall" not in prefix and "Public evidence firewall" not in prefix:
            add(report, f"{path}:{line_number}", "workflow_upload_without_firewall")
    return report


def emit(report: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    print(f"ok: {report['ok']}")
    print(f"schema: {report['schema']}")
    print(f"command: {report['command']}")
    print(f"scanned_root: {report['scanned_root']}")
    if report["violations"]:
        print("violations:")
        for item in report["violations"]:
            print(f"  - {item['path']}: {item['reason']} ({item['severity']})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("path")
    scan.add_argument("--profile", choices=("daylight-v15-meridian-public", "public-docs"))
    scan.add_argument("--max-file-bytes", type=int, default=5_000_000)
    scan.add_argument("--json", action="store_true")
    manifest = sub.add_parser("verify-manifest")
    manifest.add_argument("manifest")
    manifest.add_argument("--root")
    manifest.add_argument("--json", action="store_true")
    workflow = sub.add_parser("check-workflow")
    workflow.add_argument("workflow")
    workflow.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "scan":
        report = scan_root(Path(args.path), profile=args.profile, max_file_bytes=args.max_file_bytes)
        emit(report, as_json=args.json)
        return 0 if report["ok"] else 1
    if args.command == "verify-manifest":
        report = verify_manifest(Path(args.manifest), Path(args.root) if args.root else None)
        emit(report, as_json=args.json)
        return 0 if report["ok"] else 1
    if args.command == "check-workflow":
        report = check_workflow(Path(args.workflow))
        emit(report, as_json=args.json)
        return 0 if report["ok"] else 1
    raise AssertionError(args.command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FirewallError as exc:
        print(f"daylight-public-evidence-firewall: {exc}", file=sys.stderr)
        raise SystemExit(1)
