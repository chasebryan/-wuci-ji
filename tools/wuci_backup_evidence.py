"""Emit deterministic local backup and restore evidence for Wuci-Ji.

The backup artifact is local evidence only. It does not certify disaster
recovery, offsite retention, production readiness, or host cleanliness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "wuci.backup_evidence.v1"
DEFAULT_OUT = Path("build/wuci-backup/backup-evidence.json")
DEFAULT_ARCHIVE = Path("build/wuci-backup/wuci-ji-tracked-source.zip")
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
NON_CLAIM = (
    "This local backup evidence proves only that tracked files were archived "
    "and restored in a temporary directory during this run. It does not prove "
    "offsite retention, production disaster recovery, host cleanliness, or "
    "runtime containment."
)


class BackupEvidenceError(Exception):
    """Expected backup evidence generation error."""


def dumps_stable(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_relative(rel: str) -> None:
    pure = PurePosixPath(rel)
    if pure.is_absolute() or not rel or any(part in {"", ".."} for part in pure.parts):
        raise BackupEvidenceError(f"unsafe relative path: {rel!r}")


def _repo_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise BackupEvidenceError(f"path is outside repository root: {path}") from exc


def git_tracked_files(root: Path) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
            text=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BackupEvidenceError("could not enumerate git-tracked files") from exc
    files = [name.decode("utf-8") for name in proc.stdout.split(b"\0") if name]
    return sorted(files)


def _tracked_manifest(root: Path, tracked_files: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for rel in sorted(tracked_files):
        _validate_relative(rel)
        path = root / rel
        try:
            info = path.lstat()
        except OSError as exc:
            raise BackupEvidenceError(f"tracked path unavailable: {rel}") from exc
        if not stat.S_ISREG(info.st_mode):
            raise BackupEvidenceError(f"tracked backup input must be a regular file: {rel}")
        if info.st_nlink != 1:
            raise BackupEvidenceError(f"tracked backup input must not be hardlinked: {rel}")
        entries.append(
            {
                "path": rel,
                "sha256": _sha256_file(path),
                "size": info.st_size,
            }
        )
    if not entries:
        raise BackupEvidenceError("no tracked files available for backup evidence")
    return entries


def _write_archive(root: Path, archive: Path, manifest: list[dict[str, Any]]) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    tmp = archive.with_name(archive.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for entry in manifest:
                rel = entry["path"]
                info = zipfile.ZipInfo(rel, FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                with (root / rel).open("rb") as source, zf.open(info, "w") as dest:
                    for chunk in iter(lambda: source.read(65536), b""):
                        dest.write(chunk)
        tmp.replace(archive)
    finally:
        if tmp.exists():
            tmp.unlink()


def _extract_and_verify(archive: Path, manifest: list[dict[str, Any]]) -> dict[str, Any]:
    expected = {entry["path"]: entry for entry in manifest}
    with tempfile.TemporaryDirectory(prefix="wuci-backup-restore-") as tmp_name:
        restore_root = Path(tmp_name)
        with zipfile.ZipFile(archive, "r") as zf:
            names = sorted(zf.namelist())
            if names != sorted(expected):
                raise BackupEvidenceError("archive member list does not match manifest")
            for member in zf.infolist():
                _validate_relative(member.filename)
                mode_type = (member.external_attr >> 16) & 0o170000
                if mode_type and mode_type != stat.S_IFREG:
                    raise BackupEvidenceError(f"archive member must be a regular file: {member.filename}")
                target = restore_root / member.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as source, target.open("wb") as dest:
                    for chunk in iter(lambda: source.read(65536), b""):
                        dest.write(chunk)
            for rel, entry in expected.items():
                restored = restore_root / rel
                if _sha256_file(restored) != entry["sha256"]:
                    raise BackupEvidenceError(f"restored file digest mismatch: {rel}")
    return {"checked": True, "files_verified": len(manifest), "failures": 0}


def emit_backup_evidence(
    repo_root: Path,
    out_path: Path = DEFAULT_OUT,
    archive_path: Path = DEFAULT_ARCHIVE,
    tracked_files: list[str] | None = None,
) -> dict[str, Any]:
    root = repo_root.resolve()
    files = tracked_files if tracked_files is not None else git_tracked_files(root)
    manifest = _tracked_manifest(root, files)
    _write_archive(root, archive_path, manifest)
    restore = _extract_and_verify(archive_path, manifest)

    archive_rel = _repo_relative(root, archive_path)
    archive_info = archive_path.stat()
    manifest_digest = hashlib.sha256(dumps_stable(manifest).encode("utf-8")).hexdigest()
    report = {
        "schema": SCHEMA,
        "result": "pass",
        "files_total": len(manifest),
        "bytes_total": sum(entry["size"] for entry in manifest),
        "manifest_sha256": manifest_digest,
        "archive": {
            "path": archive_rel,
            "sha256": _sha256_file(archive_path),
            "bytes": archive_info.st_size,
        },
        "restore": restore,
        "non_claim_boundary": NON_CLAIM,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text(dumps_stable(report), encoding="utf-8")
    os.replace(tmp, out_path)
    return report


def run_emit(args: argparse.Namespace) -> int:
    try:
        report = emit_backup_evidence(Path(args.repo_root), Path(args.out), Path(args.archive))
    except BackupEvidenceError as exc:
        print(f"wuci-backup-evidence: {exc}")
        return 2
    print(f"wuci-backup-evidence: {report['result']}")
    print(f"files: {report['files_total']}")
    print(f"archive: {report['archive']['path']}")
    print(f"report: {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit local Wuci-Ji backup evidence.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    emit = subparsers.add_parser("emit", help="create and verify a local tracked-source backup")
    emit.add_argument("--repo-root", default=".", help="repository root")
    emit.add_argument("--out", default=str(DEFAULT_OUT), help="backup evidence JSON path")
    emit.add_argument("--archive", default=str(DEFAULT_ARCHIVE), help="tracked-source backup archive path")
    emit.set_defaults(func=run_emit)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
