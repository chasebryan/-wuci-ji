#!/usr/bin/env python3
"""Bind Wuci-OS release evidence to the final ISO manifest.

This tool does not manufacture release authority. It verifies local evidence
artifacts and keeps release blockers active when evidence is absent, stale, or
not bound to the exact final manifest/ISO digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import wuci_safeio


SCHEMA_PREFIX = "wuci-os-release"
DEFAULT_FINAL_MANIFEST = Path("build/wuci-os/final/manifest.json")
DEFAULT_FINAL_ISO = Path("build/wuci-os/final/Wuci-OS-x86_64-musl.iso")
DEFAULT_EVIDENCE_ROOT = Path("build/wuci-os/release-evidence")
DEFAULT_RELEASE_GATE = DEFAULT_EVIDENCE_ROOT / "release-gate.json"

QEMU_TRACE_NAME = "qemu-boot-trace.json"
HARDWARE_TRACE_NAME = "hardware-boot-trace.json"
SIGNATURE_NAME = "manifest-signature.json"
WITNESS_NAME = "witness-ledger-entry.json"

PROMPT_MARKER = "WJ>_"
QEMU_REQUIRED_MARKERS = (
    PROMPT_MARKER,
    "Wuci-OS live profile",
    "Loading sysctl",
)
HARDWARE_REQUIRED_MARKERS = (
    PROMPT_MARKER,
    "Wuci-OS live profile",
    "wuci-network",
    "INSTALL",
)
FAILURE_MARKERS = (
    "access denied",
    "dracut: FATAL",
    "Kernel panic",
    "not syncing",
    "emergency mode",
    "Unable to mount root",
)


class ReleaseGateError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_regular(path: Path, label: str) -> os.stat_result:
    try:
        return wuci_safeio.require_regular_file(path, label, reject_hardlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise ReleaseGateError(str(exc)) from exc


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(path, label, reject_hardlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise ReleaseGateError(str(exc)) from exc


def read_text(path: Path, label: str) -> str:
    return read_bytes(path, label).decode("utf-8", errors="replace")


def read_json(path: Path, label: str) -> dict[str, Any]:
    data = read_bytes(path, label)
    try:
        value = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseGateError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseGateError(f"{label} must be a JSON object: {path}")
    return value


def file_digest(path: Path, label: str) -> tuple[str, int]:
    info = require_regular(path, label)
    digest = hashlib.sha256()
    try:
        for chunk in wuci_safeio.iter_regular_chunks(path, label, reject_hardlink=True):
            digest.update(chunk)
    except wuci_safeio.SafeIOError as exc:
        raise ReleaseGateError(str(exc)) from exc
    return digest.hexdigest(), info.st_size


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    try:
        wuci_safeio.ensure_parent_directory(path, f"{path} parent")
    except wuci_safeio.SafeIOError as exc:
        raise ReleaseGateError(str(exc)) from exc
    if path.exists() or path.is_symlink():
        try:
            info = path.lstat()
        except OSError as exc:
            raise ReleaseGateError(f"could not inspect release gate output {path}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseGateError(f"release gate output must not be a symlink: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseGateError(f"release gate output must be a regular file: {path}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(stable_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o644)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def manifest_context(manifest_path: Path, iso_path: Path | None = None) -> dict[str, Any]:
    manifest = read_json(manifest_path, "Wuci-OS final manifest")
    manifest_sha256, manifest_bytes = file_digest(manifest_path, "Wuci-OS final manifest")
    manifest_iso = manifest.get("iso")
    if not isinstance(manifest_iso, dict):
        raise ReleaseGateError("Wuci-OS final manifest is missing iso evidence")
    digest_vector = manifest_iso.get("digest_vector")
    if not isinstance(digest_vector, dict) or not isinstance(digest_vector.get("sha256"), str):
        raise ReleaseGateError("Wuci-OS final manifest is missing iso.digest_vector.sha256")
    resolved_iso = iso_path or Path(str(manifest_iso.get("path") or DEFAULT_FINAL_ISO))
    iso_sha256, iso_bytes = file_digest(resolved_iso, "Wuci-OS final ISO")
    if iso_sha256 != digest_vector["sha256"]:
        raise ReleaseGateError(
            "Wuci-OS final ISO digest does not match manifest: "
            f"actual={iso_sha256}, manifest={digest_vector['sha256']}"
        )
    return {
        "manifest": manifest,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "manifest_bytes": manifest_bytes,
        "iso_path": str(resolved_iso),
        "iso_sha256": iso_sha256,
        "iso_bytes": iso_bytes,
    }


def marker_report(log_text: str, required_markers: Iterable[str]) -> dict[str, Any]:
    found = [marker for marker in required_markers if marker in log_text]
    missing = [marker for marker in required_markers if marker not in log_text]
    failures = [marker for marker in FAILURE_MARKERS if marker.lower() in log_text.lower()]
    return {
        "required": list(required_markers),
        "found": found,
        "missing": missing,
        "failure_markers": failures,
    }


def bind_boot_trace(
    *,
    manifest_path: Path,
    iso_path: Path | None,
    boot_log: Path,
    out: Path,
    kind: str,
    required_markers: Iterable[str],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = manifest_context(manifest_path, iso_path)
    log_data = read_bytes(boot_log, f"Wuci-OS {kind} boot log")
    log_text = log_data.decode("utf-8", errors="replace")
    markers = marker_report(log_text, required_markers)
    status = "pass" if not markers["missing"] and not markers["failure_markers"] else "blocked"
    evidence = {
        "schema": f"{SCHEMA_PREFIX}-{kind}-boot-trace-v1",
        "status": status,
        "created_utc": utc_now(),
        "final_manifest": {
            "path": context["manifest_path"],
            "sha256": context["manifest_sha256"],
            "bytes": context["manifest_bytes"],
        },
        "final_iso": {
            "path": context["iso_path"],
            "sha256": context["iso_sha256"],
            "bytes": context["iso_bytes"],
        },
        "boot_log": {
            "path": str(boot_log),
            "sha256": sha256_bytes(log_data),
            "bytes": len(log_data),
        },
        "markers": markers,
        "non_claims": [
            "boot trace evidence is artifact binding, not a whole-host security proof",
            "QEMU evidence does not replace hardware boot evidence",
        ],
    }
    if metadata:
        evidence["metadata"] = metadata
    write_json_atomic(out, evidence)
    return evidence


def minisign_public_key_from_file(path: Path) -> str:
    text = read_text(path, "minisign public key")
    key_lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("untrusted comment:")]
    if not key_lines:
        raise ReleaseGateError(f"minisign public key file does not contain a key line: {path}")
    return key_lines[-1]


def verify_minisign_signature(
    *,
    manifest_path: Path,
    iso_path: Path | None,
    signature_path: Path,
    public_key: str,
    out: Path,
) -> dict[str, Any]:
    minisign = shutil.which("minisign")
    if not minisign:
        raise ReleaseGateError("minisign is required to verify the release manifest signature")
    context = manifest_context(manifest_path, iso_path)
    signature_sha256, signature_bytes = file_digest(signature_path, "Wuci-OS manifest signature")
    command = [minisign, "-Vm", str(manifest_path), "-P", public_key, "-x", str(signature_path)]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False, check=False)
    status = "pass" if completed.returncode == 0 else "blocked"
    evidence = {
        "schema": f"{SCHEMA_PREFIX}-manifest-signature-v1",
        "status": status,
        "created_utc": utc_now(),
        "tool": "minisign",
        "final_manifest": {
            "path": context["manifest_path"],
            "sha256": context["manifest_sha256"],
            "bytes": context["manifest_bytes"],
        },
        "final_iso": {
            "path": context["iso_path"],
            "sha256": context["iso_sha256"],
            "bytes": context["iso_bytes"],
        },
        "signature": {
            "path": str(signature_path),
            "sha256": signature_sha256,
            "bytes": signature_bytes,
        },
        "public_key": {
            "sha256": sha256_bytes(public_key.encode("utf-8")),
            "value": public_key,
        },
        "verification": {
            "returncode": completed.returncode,
            "stdout_sha256": sha256_bytes(completed.stdout.encode("utf-8")),
            "stderr_sha256": sha256_bytes(completed.stderr.encode("utf-8")),
        },
        "non_claims": [
            "signature verification only proves possession of the matching release key",
            "fixture keys must not be used as production release authority",
        ],
    }
    write_json_atomic(out, evidence)
    if status != "pass":
        raise ReleaseGateError("minisign verification failed for final manifest signature")
    return evidence


def bind_witness_entry(
    *,
    manifest_path: Path,
    iso_path: Path | None,
    signature_evidence: Path,
    ledger_entry: Path,
    ledger_head: Path,
    inclusion_proof: Path,
    out: Path,
    operated_ledger_id: str,
    operator: str,
    ledger_url: str | None,
) -> dict[str, Any]:
    context = manifest_context(manifest_path, iso_path)
    signature = read_json(signature_evidence, "Wuci-OS manifest signature evidence")
    signature_record = signature.get("signature")
    if not isinstance(signature_record, dict) or not isinstance(signature_record.get("sha256"), str):
        raise ReleaseGateError("signature evidence is missing signature.sha256")
    entry_text = read_text(ledger_entry, "Wuci-OS witness ledger entry")
    head_text = read_text(ledger_head, "Wuci-OS witness ledger head")
    proof_text = read_text(inclusion_proof, "Wuci-OS witness ledger inclusion proof")
    manifest_bound = context["manifest_sha256"] in entry_text or context["manifest_sha256"] in proof_text
    signature_bound = signature_record["sha256"] in entry_text or signature_record["sha256"] in proof_text
    head_present = bool(head_text.strip())
    proof_present = bool(proof_text.strip())
    entry_sha256, entry_bytes = file_digest(ledger_entry, "Wuci-OS witness ledger entry")
    head_sha256, head_bytes = file_digest(ledger_head, "Wuci-OS witness ledger head")
    proof_sha256, proof_bytes = file_digest(inclusion_proof, "Wuci-OS witness ledger inclusion proof")
    operated_metadata_present = bool(operated_ledger_id.strip()) and bool(operator.strip()) and bool((ledger_url or "").strip())
    status = "pass" if manifest_bound and signature_bound and head_present and proof_present and operated_metadata_present else "blocked"
    evidence = {
        "schema": f"{SCHEMA_PREFIX}-witness-ledger-entry-v1",
        "status": status,
        "created_utc": utc_now(),
        "operated_ledger_id": operated_ledger_id,
        "operator": operator,
        "ledger_url": ledger_url or "",
        "final_manifest": {
            "path": context["manifest_path"],
            "sha256": context["manifest_sha256"],
            "bytes": context["manifest_bytes"],
        },
        "final_iso": {
            "path": context["iso_path"],
            "sha256": context["iso_sha256"],
            "bytes": context["iso_bytes"],
        },
        "signature_sha256": signature_record["sha256"],
        "ledger_entry": {"path": str(ledger_entry), "sha256": entry_sha256, "bytes": entry_bytes},
        "ledger_head": {"path": str(ledger_head), "sha256": head_sha256, "bytes": head_bytes},
        "inclusion_proof": {"path": str(inclusion_proof), "sha256": proof_sha256, "bytes": proof_bytes},
        "checks": {
            "manifest_digest_bound": manifest_bound,
            "signature_digest_bound": signature_bound,
            "ledger_head_present": head_present,
            "inclusion_proof_present": proof_present,
            "operated_ledger_metadata_present": operated_metadata_present,
        },
        "non_claims": [
            "witness evidence records inclusion artifacts; external ledger operation must be independently reviewable",
            "local fixture/demo ledgers are not production release authority",
        ],
    }
    write_json_atomic(out, evidence)
    if status != "pass":
        raise ReleaseGateError("witness ledger evidence is not bound to manifest and signature digests")
    return evidence


def package_closure_status(manifest: dict[str, Any]) -> dict[str, Any]:
    rootfs_remaster = manifest.get("rootfs_remaster")
    if isinstance(rootfs_remaster, dict):
        suite = rootfs_remaster.get("suite_package_install")
        if isinstance(suite, dict) and suite.get("status") == "pass":
            return {
                "schema": f"{SCHEMA_PREFIX}-package-closure-status-v1",
                "status": "pass",
                "source": "rootfs_remaster.suite_package_install",
                "package_count": suite.get("package_count"),
            }
        secure_default = rootfs_remaster.get("secure_default_package_closure")
        if (
            isinstance(secure_default, dict)
            and secure_default.get("status") == "pass"
            and secure_default.get("policy") == "secure-default-firstboot-v1"
        ):
            return {
                "schema": f"{SCHEMA_PREFIX}-package-closure-status-v1",
                "status": "pass",
                "source": "rootfs_remaster.secure_default_package_closure",
                "policy": secure_default.get("policy"),
                "required_command_count": secure_default.get("required_command_count"),
                "required_firstboot_executable_count": secure_default.get("required_firstboot_executable_count"),
                "required_firstboot_file_count": secure_default.get("required_firstboot_file_count"),
                "optional_suite_status": secure_default.get("optional_suite_status"),
                "optional_suite_failed_count": secure_default.get("optional_suite_failed_count"),
                "non_claims": secure_default.get("non_claims", []),
            }
    return {
        "schema": f"{SCHEMA_PREFIX}-package-closure-status-v1",
        "status": "blocked",
        "reason": "neither full suite package install nor secure-default first-boot package closure evidence is pass",
    }


def verify_evidence_file(
    path: Path,
    *,
    schema: str,
    manifest_sha256: str,
    iso_sha256: str,
) -> dict[str, Any]:
    evidence = read_json(path, path.name)
    manifest = evidence.get("final_manifest")
    iso = evidence.get("final_iso")
    status = evidence.get("status") == "pass"
    schema_ok = evidence.get("schema") == schema
    manifest_ok = isinstance(manifest, dict) and manifest.get("sha256") == manifest_sha256
    iso_ok = isinstance(iso, dict) and iso.get("sha256") == iso_sha256
    return {
        "path": str(path),
        "status": "pass" if status and schema_ok and manifest_ok and iso_ok else "blocked",
        "checks": {
            "status_pass": status,
            "schema": schema_ok,
            "manifest_sha256": manifest_ok,
            "iso_sha256": iso_ok,
        },
    }


def release_status(
    *,
    manifest_path: Path,
    iso_path: Path | None,
    evidence_root: Path,
    out: Path | None = None,
) -> dict[str, Any]:
    context = manifest_context(manifest_path, iso_path)
    manifest = context["manifest"]
    blockers: list[str] = []
    retired: dict[str, Any] = {}
    evidence: dict[str, Any] = {}

    validation = manifest.get("validation")
    if not (isinstance(validation, dict) and validation.get("rootfs_remastered") is True):
        blockers.append("deterministic-rootfs-not-remastered")
    else:
        retired["deterministic-rootfs-not-remastered"] = {"status": "pass", "source": "final manifest validation"}

    package_status = package_closure_status(manifest)
    evidence["package_closure"] = package_status
    if package_status["status"] != "pass":
        blockers.append("package-closure-fixed-point-missing")
    else:
        retired["package-closure-fixed-point-missing"] = package_status

    checks = {
        "qemu-boot-trace-not-bound-to-final-manifest": (
            evidence_root / QEMU_TRACE_NAME,
            f"{SCHEMA_PREFIX}-qemu-boot-trace-v1",
        ),
        "hardware-boot-trace-missing": (
            evidence_root / HARDWARE_TRACE_NAME,
            f"{SCHEMA_PREFIX}-hardware-boot-trace-v1",
        ),
        "final-iso-manifest-signature-missing": (
            evidence_root / SIGNATURE_NAME,
            f"{SCHEMA_PREFIX}-manifest-signature-v1",
        ),
        "witness-ledger-entry-missing": (
            evidence_root / WITNESS_NAME,
            f"{SCHEMA_PREFIX}-witness-ledger-entry-v1",
        ),
    }
    for blocker, (path, schema) in checks.items():
        if not path.exists():
            blockers.append(blocker)
            evidence[blocker] = {"status": "missing", "path": str(path)}
            continue
        check = verify_evidence_file(
            path,
            schema=schema,
            manifest_sha256=context["manifest_sha256"],
            iso_sha256=context["iso_sha256"],
        )
        evidence[blocker] = check
        if check["status"] == "pass":
            retired[blocker] = check
        else:
            blockers.append(blocker)

    blocker_requirements = {
        "deterministic-rootfs-not-remastered": "Rebuild with --remaster-rootfs.",
        "package-closure-fixed-point-missing": "Bake and verify the full release package closure, or formally change the release policy to a smaller secure-default package graph.",
        "qemu-boot-trace-not-bound-to-final-manifest": "Run qemu-trace against this final manifest and ISO.",
        "hardware-boot-trace-missing": "Run hardware-trace from a reference hardware boot log.",
        "final-iso-manifest-signature-missing": "Verify a detached minisign signature for the final manifest with the production release public key.",
        "witness-ledger-entry-missing": "Bind the signed final manifest digest into the operated witness ledger and record inclusion evidence.",
    }
    gate = {
        "schema": f"{SCHEMA_PREFIX}-gate-v1",
        "status": "pass" if not blockers else "blocked",
        "release_allowed": not blockers,
        "created_utc": utc_now(),
        "final_manifest": {
            "path": context["manifest_path"],
            "sha256": context["manifest_sha256"],
            "bytes": context["manifest_bytes"],
        },
        "final_iso": {
            "path": context["iso_path"],
            "sha256": context["iso_sha256"],
            "bytes": context["iso_bytes"],
        },
        "evidence_root": str(evidence_root),
        "blockers": blockers,
        "blocker_requirements": {blocker: blocker_requirements[blocker] for blocker in blockers},
        "retired_blockers": retired,
        "evidence": evidence,
        "non_claims": [
            "release_allowed=false means evidence candidate, not public final release",
            "this gate does not replace independent review, government validation, or whole-host forensics",
        ],
    }
    if out is not None:
        write_json_atomic(out, gate)
    return gate


def command_qemu_trace(args: argparse.Namespace) -> int:
    out = Path(args.out or DEFAULT_EVIDENCE_ROOT / QEMU_TRACE_NAME)
    evidence = bind_boot_trace(
        manifest_path=Path(args.manifest),
        iso_path=Path(args.iso) if args.iso else None,
        boot_log=Path(args.boot_log),
        out=out,
        kind="qemu",
        required_markers=QEMU_REQUIRED_MARKERS,
        metadata={"command": args.command or ""},
    )
    print(f"wuci-release qemu-trace: {evidence['status']}")
    print(f"evidence: {out}")
    return 0 if evidence["status"] == "pass" else 1


def command_hardware_trace(args: argparse.Namespace) -> int:
    out = Path(args.out or DEFAULT_EVIDENCE_ROOT / HARDWARE_TRACE_NAME)
    markers = tuple(args.require_marker or HARDWARE_REQUIRED_MARKERS)
    evidence = bind_boot_trace(
        manifest_path=Path(args.manifest),
        iso_path=Path(args.iso) if args.iso else None,
        boot_log=Path(args.boot_log),
        out=out,
        kind="hardware",
        required_markers=markers,
        metadata={
            "hardware_id": args.hardware_id,
            "operator": args.operator,
            "observed_at_utc": args.observed_at_utc,
        },
    )
    print(f"wuci-release hardware-trace: {evidence['status']}")
    print(f"evidence: {out}")
    return 0 if evidence["status"] == "pass" else 1


def command_verify_signature(args: argparse.Namespace) -> int:
    out = Path(args.out or DEFAULT_EVIDENCE_ROOT / SIGNATURE_NAME)
    public_key = args.public_key or minisign_public_key_from_file(Path(args.public_key_file))
    evidence = verify_minisign_signature(
        manifest_path=Path(args.manifest),
        iso_path=Path(args.iso) if args.iso else None,
        signature_path=Path(args.signature),
        public_key=public_key,
        out=out,
    )
    print(f"wuci-release manifest-signature: {evidence['status']}")
    print(f"evidence: {out}")
    return 0


def command_witness(args: argparse.Namespace) -> int:
    out = Path(args.out or DEFAULT_EVIDENCE_ROOT / WITNESS_NAME)
    evidence = bind_witness_entry(
        manifest_path=Path(args.manifest),
        iso_path=Path(args.iso) if args.iso else None,
        signature_evidence=Path(args.signature_evidence),
        ledger_entry=Path(args.ledger_entry),
        ledger_head=Path(args.ledger_head),
        inclusion_proof=Path(args.inclusion_proof),
        out=out,
        operated_ledger_id=args.operated_ledger_id,
        operator=args.operator,
        ledger_url=args.ledger_url,
    )
    print(f"wuci-release witness-ledger: {evidence['status']}")
    print(f"evidence: {out}")
    return 0


def command_status(args: argparse.Namespace) -> int:
    out = Path(args.out or DEFAULT_RELEASE_GATE)
    gate = release_status(
        manifest_path=Path(args.manifest),
        iso_path=Path(args.iso) if args.iso else None,
        evidence_root=Path(args.evidence_root),
        out=out,
    )
    print(f"wuci-release gate: {gate['status']}")
    print(f"release_allowed: {str(gate['release_allowed']).lower()}")
    if gate["blockers"]:
        print("blockers:")
        for blocker in gate["blockers"]:
            print(f"  - {blocker}")
    print(f"report: {out}")
    return 0 if gate["release_allowed"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.set_defaults(func=None)
    subparsers = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--manifest", default=str(DEFAULT_FINAL_MANIFEST), help="final ISO manifest path")
        p.add_argument("--iso", default=str(DEFAULT_FINAL_ISO), help="final ISO path")

    qemu = subparsers.add_parser("qemu-trace", help="bind a QEMU boot log to the final manifest and ISO")
    add_common(qemu)
    qemu.add_argument("--boot-log", required=True, help="serial boot log that reaches WJ>_")
    qemu.add_argument("--command", help="QEMU command used to produce the log")
    qemu.add_argument("--out", help="output qemu trace evidence path")
    qemu.set_defaults(func=command_qemu_trace)

    hardware = subparsers.add_parser("hardware-trace", help="bind a reference hardware boot log")
    add_common(hardware)
    hardware.add_argument("--boot-log", required=True, help="reference hardware boot log/transcript")
    hardware.add_argument("--hardware-id", required=True, help="reference hardware identifier")
    hardware.add_argument("--operator", required=True, help="operator who captured the evidence")
    hardware.add_argument("--observed-at-utc", required=True, help="observation timestamp in UTC")
    hardware.add_argument("--require-marker", action="append", help="required marker; may be repeated")
    hardware.add_argument("--out", help="output hardware trace evidence path")
    hardware.set_defaults(func=command_hardware_trace)

    signature = subparsers.add_parser("verify-signature", help="verify detached minisign signature over final manifest")
    add_common(signature)
    signature.add_argument("--signature", required=True, help="detached minisign signature path")
    key_group = signature.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--public-key", help="minisign public key string")
    key_group.add_argument("--public-key-file", help="minisign public key file")
    signature.add_argument("--out", help="output signature evidence path")
    signature.set_defaults(func=command_verify_signature)

    witness = subparsers.add_parser("witness", help="bind signed manifest evidence into witness ledger evidence")
    add_common(witness)
    witness.add_argument("--signature-evidence", default=str(DEFAULT_EVIDENCE_ROOT / SIGNATURE_NAME))
    witness.add_argument("--ledger-entry", required=True)
    witness.add_argument("--ledger-head", required=True)
    witness.add_argument("--inclusion-proof", required=True)
    witness.add_argument("--operated-ledger-id", required=True)
    witness.add_argument("--operator", required=True)
    witness.add_argument("--ledger-url")
    witness.add_argument("--out", help="output witness evidence path")
    witness.set_defaults(func=command_witness)

    status = subparsers.add_parser("status", help="verify release evidence and write release-gate status")
    add_common(status)
    status.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT))
    status.add_argument("--out", help="output release gate report path")
    status.set_defaults(func=command_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.func is None:
        parser.print_help()
        return 2
    try:
        return int(args.func(args))
    except ReleaseGateError as exc:
        print(f"wuci-release: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
