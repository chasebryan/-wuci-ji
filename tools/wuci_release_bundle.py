#!/usr/bin/env python3
"""Build a public Wuci-OS release-candidate bundle from allowlisted artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import wuci_release_privacy_audit


SCHEMA = "wuci-os-public-release-bundle-v1"
DEFAULT_OUT = Path("build/wuci-os/release-candidate/Wuci-Ji-v2.2-Aperture-Bastion")
DEFAULT_FINAL_DIR = Path("build/wuci-os/final")
DEFAULT_EVIDENCE_DIR = Path("build/wuci-os/release-evidence")
DEFAULT_PRIVACY_AUDIT = Path("build/wuci-os/privacy-audit.json")
DEFAULT_ROOTFS_PRIVACY_AUDIT = Path("build/wuci-os/privacy-audit-final-rootfs.json")
DEFAULT_DAYLIGHT_SSV = Path("build/daylight/ssv-v1/daylight-ssv.report.json")

ISO_NAME = "Wuci-OS-x86_64-musl.iso"
NON_CLAIMS = (
    "This bundle is an allowlisted public release-candidate directory, not a whole-workstation copy.",
    "This bundle is ISO-only by default; VirtualBox/OVA artifacts are intentionally not included.",
    "If release_gate.release_allowed is false, this bundle is not final publish authorization.",
    "Privacy audit evidence covers selected candidate artifacts, not the entire operator host.",
)


class ReleaseBundleError(RuntimeError):
    pass


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def sha256_file(path: Path) -> tuple[str, int]:
    info = require_regular(path, "digest input")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), info.st_size


def require_regular(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ReleaseBundleError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ReleaseBundleError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ReleaseBundleError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise ReleaseBundleError(f"{label} must not be hardlinked: {path}")
    return info


def read_json(path: Path, label: str) -> dict[str, Any]:
    require_regular(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseBundleError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseBundleError(f"{label} must be a JSON object: {path}")
    return value


def write_text_atomic(path: Path, text: str, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
        fsync_parent(path.parent)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    write_text_atomic(path, stable_json(value))


def fsync_parent(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def reset_output_dir(path: Path, *, force: bool) -> None:
    if path.exists() or path.is_symlink():
        if not force:
            raise ReleaseBundleError(f"output already exists; pass --force to replace: {path}")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseBundleError(f"output directory must not be a symlink: {path}")
        if not stat.S_ISDIR(info.st_mode):
            raise ReleaseBundleError(f"output path must be a directory: {path}")
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            root_path = Path(root)
            for name in files:
                item = root_path / name
                item.unlink()
            for name in dirs:
                item = root_path / name
                if item.is_symlink():
                    item.unlink()
                else:
                    item.rmdir()
    path.mkdir(parents=True, exist_ok=True)
    fsync_parent(path.parent)


def safe_relpath(value: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ReleaseBundleError(f"unsafe bundle relative path: {value}")
    return pure


def copy_regular(src: Path, dst_root: Path, rel: str) -> dict[str, Any]:
    safe = safe_relpath(rel)
    dst = dst_root.joinpath(*safe.parts)
    info = require_regular(src, f"release artifact {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.", suffix=".tmp", dir=str(dst.parent))
    tmp = Path(tmp_name)
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out, src.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dst)
        os.chmod(dst, 0o644)
        fsync_parent(dst.parent)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    return {
        "source": str(src),
        "path": safe.as_posix(),
        "bytes": info.st_size,
        "sha256": digest.hexdigest(),
    }


def input_artifacts(
    *,
    final_dir: Path,
    evidence_dir: Path,
    privacy_audit: Path,
    rootfs_privacy_audit: Path,
    daylight_ssv: Path,
) -> list[tuple[str, Path, str, bool]]:
    return [
        ("final_iso", final_dir / ISO_NAME, f"iso/{ISO_NAME}", True),
        ("final_iso_sha256", final_dir / f"{ISO_NAME}.sha256", f"iso/{ISO_NAME}.sha256", True),
        ("final_manifest", final_dir / "manifest.json", "evidence/final-manifest.json", True),
        ("rootfs_manifest", final_dir / "rootfs-manifest.json", "evidence/rootfs-manifest.json", True),
        ("daylight_manifest", final_dir / "daylight-manifest.json", "evidence/daylight-manifest.json", True),
        ("release_gate", evidence_dir / "release-gate.json", "evidence/release-gate.json", True),
        ("qemu_boot_trace", evidence_dir / "qemu-boot-trace.json", "evidence/qemu-boot-trace.json", True),
        ("privacy_audit", privacy_audit, "evidence/privacy-audit.json", True),
        ("rootfs_privacy_audit", rootfs_privacy_audit, "evidence/privacy-audit-final-rootfs.json", False),
        ("daylight_ssv", daylight_ssv, "evidence/daylight-ssv.report.json", False),
    ]


def require_privacy_pass(path: Path) -> dict[str, Any]:
    report = read_json(path, "Wuci-OS privacy audit")
    if report.get("status") != "pass":
        raise ReleaseBundleError(f"privacy audit is not pass: {path}")
    summary = report.get("summary")
    if isinstance(summary, dict) and summary.get("findings") not in (0, None):
        raise ReleaseBundleError(f"privacy audit has findings: {path}")
    findings = report.get("findings")
    if isinstance(findings, list) and findings:
        raise ReleaseBundleError(f"privacy audit has findings: {path}")
    return report


def checksum_lines(root: Path, records: Iterable[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for record in sorted(records, key=lambda item: str(item["path"])):
        rel = str(record["path"])
        path = root.joinpath(*PurePosixPath(rel).parts)
        digest, _size = sha256_file(path)
        lines.append(f"{digest}  {rel}")
    return lines


def release_notes(release_allowed: bool, blockers: list[str]) -> str:
    status = "release gate pass" if release_allowed else "release gate blocked"
    blocker_text = "\n".join(f"- {item}" for item in blockers) if blockers else "- none"
    return f"""Wuci-Ji v2.2 - Aperture Bastion

Status: {status}

This directory is the curated public release-candidate bundle for the Wuci-OS
ISO. It intentionally excludes VirtualBox/OVA artifacts, local home directories,
developer credentials, shell histories, private keys, package caches, and
workspace build intermediates outside the allowlist.

Release gate blockers:
{blocker_text}

Use CHECKSUMS.sha256 to verify copied artifacts. If release gate blockers are
listed, do not treat this bundle as final publish authorization.
"""


def build_bundle(
    *,
    out: Path,
    final_dir: Path,
    evidence_dir: Path,
    privacy_audit: Path,
    rootfs_privacy_audit: Path,
    daylight_ssv: Path,
    force: bool,
) -> dict[str, Any]:
    privacy_report = require_privacy_pass(privacy_audit)
    release_gate_path = evidence_dir / "release-gate.json"
    release_gate = read_json(release_gate_path, "Wuci-OS release gate")
    release_allowed = bool(release_gate.get("release_allowed") is True)
    blockers = release_gate.get("blockers")
    if not isinstance(blockers, list):
        blockers = []

    reset_output_dir(out, force=force)
    copied: list[dict[str, Any]] = []
    missing_optional: list[str] = []
    for label, src, rel, required in input_artifacts(
        final_dir=final_dir,
        evidence_dir=evidence_dir,
        privacy_audit=privacy_audit,
        rootfs_privacy_audit=rootfs_privacy_audit,
        daylight_ssv=daylight_ssv,
    ):
        if not src.exists():
            if required:
                raise ReleaseBundleError(f"required public artifact is missing: {label}: {src}")
            missing_optional.append(label)
            continue
        record = copy_regular(src, out, rel)
        record["label"] = label
        copied.append(record)

    notes_path = out / "RELEASE-NOTES.txt"
    write_text_atomic(notes_path, release_notes(release_allowed, [str(item) for item in blockers]))
    notes_digest, notes_size = sha256_file(notes_path)
    copied.append({"label": "release_notes", "source": "generated", "path": "RELEASE-NOTES.txt", "bytes": notes_size, "sha256": notes_digest})

    manifest = {
        "schema": SCHEMA,
        "status": "pass" if release_allowed else "candidate-blocked",
        "release": "Wuci-Ji v2.2 - Aperture Bastion",
        "release_allowed": release_allowed,
        "release_gate_blockers": blockers,
        "privacy_audit": {
            "path": str(privacy_audit),
            "status": privacy_report.get("status"),
            "findings": privacy_report.get("summary", {}).get("findings") if isinstance(privacy_report.get("summary"), dict) else None,
        },
        "copied_artifacts": copied,
        "missing_optional_artifacts": missing_optional,
        "non_claims": list(NON_CLAIMS),
    }
    write_json_atomic(out / "public-release-bundle-manifest.json", manifest)
    manifest_digest, manifest_size = sha256_file(out / "public-release-bundle-manifest.json")
    copied.append(
        {
            "label": "public_release_bundle_manifest",
            "source": "generated",
            "path": "public-release-bundle-manifest.json",
            "bytes": manifest_size,
            "sha256": manifest_digest,
        }
    )

    checksums = checksum_lines(out, copied)
    write_text_atomic(out / "CHECKSUMS.sha256", "\n".join(checksums) + "\n")

    bundle_audit = wuci_release_privacy_audit.audit_paths([out])
    if bundle_audit.get("status") != "pass":
        raise ReleaseBundleError("public bundle privacy audit failed: " + stable_json(bundle_audit))

    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    build = subparsers.add_parser("build", help="build the public release-candidate bundle")
    build.add_argument("--out", type=Path, default=DEFAULT_OUT)
    build.add_argument("--final-dir", type=Path, default=DEFAULT_FINAL_DIR)
    build.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    build.add_argument("--privacy-audit", type=Path, default=DEFAULT_PRIVACY_AUDIT)
    build.add_argument("--rootfs-privacy-audit", type=Path, default=DEFAULT_ROOTFS_PRIVACY_AUDIT)
    build.add_argument("--daylight-ssv", type=Path, default=DEFAULT_DAYLIGHT_SSV)
    build.add_argument("--force", action="store_true")
    build.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "build":
        parser.print_help()
        return 2
    try:
        result = build_bundle(
            out=args.out,
            final_dir=args.final_dir,
            evidence_dir=args.evidence_dir,
            privacy_audit=args.privacy_audit,
            rootfs_privacy_audit=args.rootfs_privacy_audit,
            daylight_ssv=args.daylight_ssv,
            force=args.force,
        )
    except ReleaseBundleError as exc:
        print(f"wuci-release-bundle: {exc}", file=os.sys.stderr)
        return 1
    if args.json:
        print(stable_json(result), end="")
    else:
        print(f"wuci-release-bundle: {result['status']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
