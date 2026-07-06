#!/usr/bin/env python3
"""Build a public Wuci-OS release-candidate bundle from allowlisted artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
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

VERIFY_SCHEMA = "wuci-release-bundle-verification-v1"
VERIFY_NON_CLAIMS = (
    "release bundle verification is evidence-candidate verification, not production readiness",
    "fixture authority does not provide production trust",
    "classical cryptographic evidence does not provide post-quantum system security",
    "CARROT and Rust wrapper evidence do not prove complete runtime containment",
    "crypto self-audit evidence is not external validation",
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


def digest_file(path: Path, algorithm: str, label: str) -> tuple[str, int]:
    info = require_regular(path, label)
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), info.st_size


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


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


def run_command(argv: list[str], *, cwd: Path, label: str, fatal: bool = True) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ReleaseBundleError(f"{label} failed to execute: {argv[0]}") from exc
    record = {
        "label": label,
        "command": argv,
        "returncode": proc.returncode,
        "passed": proc.returncode == 0,
        "stdout_sha256": sha256_text(proc.stdout),
        "stderr_sha256": sha256_text(proc.stderr),
        "stdout_tail": proc.stdout[-2048:],
        "stderr_tail": proc.stderr[-2048:],
    }
    if fatal and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise ReleaseBundleError(f"{label} failed: {detail}")
    return record


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


def require_schema(path: Path, label: str, schema: str) -> dict[str, Any]:
    value = read_json(path, label)
    if value.get("schema") != schema:
        raise ReleaseBundleError(f"{label} has unsupported schema: {path}")
    return value


def verify_carrot_attestation(path: Path, repo: Path) -> dict[str, Any]:
    value = require_schema(path, "CARROT attestation", "wuci-carrot-runtime-attestation-v1")
    if value.get("allow_network") is not False:
        raise ReleaseBundleError("CARROT attestation must set allow_network false")
    if value.get("policy_status") != "kernel-enforced-no-network-baseline-v1":
        raise ReleaseBundleError("CARROT attestation has unexpected policy status")
    expected_policy_sha256, _size = sha256_file(repo / "docs/wuci_carrot_runtime_policy.json")
    if value.get("policy_sha256") != expected_policy_sha256:
        raise ReleaseBundleError("CARROT policy digest mismatch")
    probe = value.get("kernel_probe")
    if not isinstance(probe, dict) or probe.get("socket_probe_denied") is not True:
        raise ReleaseBundleError("CARROT kernel probe does not show socket denial")
    return {
        "schema": value["schema"],
        "policy_sha256": value["policy_sha256"],
        "socket_probe_denied": True,
    }


def verify_parser_replay(path: Path) -> dict[str, Any]:
    value = read_json(path, "parser corpus replay evidence")
    if value.get("fail_closed") is not True:
        raise ReleaseBundleError("parser replay evidence must be fail_closed")
    if value.get("network_required") is not False:
        raise ReleaseBundleError("parser replay evidence must not require network")
    if value.get("offensive_fuzzing") is not False:
        raise ReleaseBundleError("parser replay evidence must not be offensive fuzzing")
    results = value.get("results")
    if not isinstance(results, list) or not results:
        raise ReleaseBundleError("parser replay evidence must contain results")
    if any(item.get("timeout") is True for item in results if isinstance(item, dict)):
        raise ReleaseBundleError("parser replay evidence contains timeout result")
    if any(item.get("signal") is not None for item in results if isinstance(item, dict)):
        raise ReleaseBundleError("parser replay evidence contains signal result")
    return {
        "cases": value.get("cases"),
        "accepted_cases": value.get("accepted_cases"),
        "rejected_cases": value.get("rejected_cases"),
        "surfaces": value.get("required_surfaces"),
    }


def verify_optional_group(
    *,
    paths: list[Path | None],
    names: list[str],
    blocker: str,
) -> tuple[bool, list[str]]:
    present = [path is not None for path in paths]
    if any(present) and not all(present):
        missing = [name for name, is_present in zip(names, present, strict=True) if not is_present]
        raise ReleaseBundleError(f"partial optional evidence supplied; missing: {', '.join(missing)}")
    if all(present):
        return True, []
    return False, [blocker]


def verify_release_bundle(
    *,
    repo: Path,
    bin_path: Path,
    sbom: Path,
    provenance: Path,
    carrot: Path,
    pq: Path,
    real_pq_evidence: Path | None,
    pq_pins: Path,
    crypto_audit: Path,
    parser_replay: Path,
    production_authority_policy: Path,
    production_authority: Path | None,
    production_authority_ceremony: Path | None,
    production_authority_ceremony_root_key: Path | None,
    production_authority_ceremony_signature: Path | None,
    external_audit_evidence: Path | None,
    external_audit_report: Path | None,
    external_audit_root_key: Path | None,
    external_audit_signature: Path | None,
    witness_bundle: Path,
    ledger: Path,
    install_manifest: Path,
    install_signature: Path,
    install_root_key: Path,
    rust_sandbox: Path,
    zig_witness: Path,
    zig_ledger: Path,
) -> dict[str, Any]:
    repo = repo.resolve()
    bin_path = bin_path if bin_path.is_absolute() else repo / bin_path
    sbom = sbom if sbom.is_absolute() else repo / sbom
    provenance = provenance if provenance.is_absolute() else repo / provenance
    carrot = carrot if carrot.is_absolute() else repo / carrot
    pq = pq if pq.is_absolute() else repo / pq
    real_pq_evidence = (
        real_pq_evidence
        if real_pq_evidence is None or real_pq_evidence.is_absolute()
        else repo / real_pq_evidence
    )
    pq_pins = pq_pins if pq_pins.is_absolute() else repo / pq_pins
    crypto_audit = crypto_audit if crypto_audit.is_absolute() else repo / crypto_audit
    parser_replay = parser_replay if parser_replay.is_absolute() else repo / parser_replay
    production_authority_policy = (
        production_authority_policy
        if production_authority_policy.is_absolute()
        else repo / production_authority_policy
    )
    production_authority = (
        production_authority
        if production_authority is None or production_authority.is_absolute()
        else repo / production_authority
    )
    production_authority_ceremony = (
        production_authority_ceremony
        if production_authority_ceremony is None or production_authority_ceremony.is_absolute()
        else repo / production_authority_ceremony
    )
    production_authority_ceremony_root_key = (
        production_authority_ceremony_root_key
        if production_authority_ceremony_root_key is None
        or production_authority_ceremony_root_key.is_absolute()
        else repo / production_authority_ceremony_root_key
    )
    production_authority_ceremony_signature = (
        production_authority_ceremony_signature
        if production_authority_ceremony_signature is None
        or production_authority_ceremony_signature.is_absolute()
        else repo / production_authority_ceremony_signature
    )
    external_audit_evidence = (
        external_audit_evidence
        if external_audit_evidence is None or external_audit_evidence.is_absolute()
        else repo / external_audit_evidence
    )
    external_audit_report = (
        external_audit_report
        if external_audit_report is None or external_audit_report.is_absolute()
        else repo / external_audit_report
    )
    external_audit_root_key = (
        external_audit_root_key
        if external_audit_root_key is None or external_audit_root_key.is_absolute()
        else repo / external_audit_root_key
    )
    external_audit_signature = (
        external_audit_signature
        if external_audit_signature is None or external_audit_signature.is_absolute()
        else repo / external_audit_signature
    )
    witness_bundle = witness_bundle if witness_bundle.is_absolute() else repo / witness_bundle
    ledger = ledger if ledger.is_absolute() else repo / ledger
    install_manifest = install_manifest if install_manifest.is_absolute() else repo / install_manifest
    install_signature = install_signature if install_signature.is_absolute() else repo / install_signature
    install_root_key = install_root_key if install_root_key.is_absolute() else repo / install_root_key
    rust_sandbox = rust_sandbox if rust_sandbox.is_absolute() else repo / rust_sandbox
    zig_witness = zig_witness if zig_witness.is_absolute() else repo / zig_witness
    zig_ledger = zig_ledger if zig_ledger.is_absolute() else repo / zig_ledger
    commands: list[dict[str, Any]] = []
    blockers: list[str] = []

    commit = run_command(["git", "rev-parse", "HEAD"], cwd=repo, label="git HEAD")
    status = run_command(["git", "status", "--short"], cwd=repo, label="git status")
    dirty = bool(status["stdout_tail"].strip())

    bin_sha256, bin_size = digest_file(bin_path, "sha256", "release binary")
    bin_sha384, _ = digest_file(bin_path, "sha384", "release binary")
    bin_sha512, _ = digest_file(bin_path, "sha512", "release binary")
    require_regular(pq_pins, "PQ verifier pins")
    require_regular(production_authority_policy, "production authority policy")

    commands.append(
        run_command(
            [sys.executable, "tools/wuci_provenance.py", "verify", "--repo", str(repo), "--sbom", str(sbom), "--provenance", str(provenance), "--quiet"],
            cwd=repo,
            label="SBOM/provenance verification",
        )
    )
    carrot_record = verify_carrot_attestation(carrot, repo)
    commands.append(
        run_command(
            [sys.executable, "tools/wuci_pq_verifier.py", "verify", "--evidence", str(pq), "--quiet"],
            cwd=repo,
            label="PQ detector verification",
        )
    )
    pq_detection = require_schema(pq, "PQ detector evidence", "wuci-pq-verifier-detection-v1")
    if pq_detection.get("quantum_safe_claim_allowed") is not False:
        raise ReleaseBundleError("PQ detector must not allow a quantum-safe claim")

    if real_pq_evidence is not None:
        commands.append(
            run_command(
                [
                    sys.executable,
                    "tools/wuci_pq_verifier.py",
                    "verify-real",
                    "--evidence",
                    str(real_pq_evidence),
                    "--pins",
                    str(pq_pins),
                    "--rerun",
                    "--quiet",
                ],
                cwd=repo,
                label="real PQ verifier evidence verification",
            )
        )
    else:
        blockers.append("real-pq-verifier-evidence-missing")

    commands.append(
        run_command(
            [sys.executable, "tools/wuci_crypto_audit.py", "verify", "--repo", str(repo), "--audit", str(crypto_audit), "--quiet"],
            cwd=repo,
            label="crypto self-audit verification",
        )
    )
    crypto = require_schema(crypto_audit, "crypto self-audit", "wuci-crypto-self-audit-v1")
    if crypto.get("external_audit") is not False or crypto.get("production_sufficient") is not False:
        raise ReleaseBundleError("crypto self-audit must not claim external audit or production sufficiency")

    parser_record = verify_parser_replay(parser_replay)

    prod_supplied, prod_blockers = verify_optional_group(
        paths=[
            production_authority,
            production_authority_ceremony,
            production_authority_ceremony_root_key,
            production_authority_ceremony_signature,
        ],
        names=[
            "production authority root",
            "production authority ceremony",
            "production authority ceremony root key",
            "production authority ceremony signature",
        ],
        blocker="signed-production-authority-evidence-missing",
    )
    blockers.extend(prod_blockers)
    if prod_supplied:
        commands.append(
            run_command(
                [
                    sys.executable,
                    "tools/wuci_production_authority.py",
                    "verify",
                    "--authority",
                    str(production_authority),
                    "--ceremony",
                    str(production_authority_ceremony),
                    "--ceremony-root-key",
                    str(production_authority_ceremony_root_key),
                    "--ceremony-signature",
                    str(production_authority_ceremony_signature),
                    "--policy",
                    str(production_authority_policy),
                    "--quiet",
                ],
                cwd=repo,
                label="signed production authority verification",
            )
        )

    audit_supplied, audit_blockers = verify_optional_group(
        paths=[external_audit_evidence, external_audit_report, external_audit_root_key, external_audit_signature],
        names=["external audit evidence", "external audit report", "external audit root key", "external audit signature"],
        blocker="signed-external-audit-evidence-missing",
    )
    blockers.extend(audit_blockers)
    if audit_supplied:
        commands.append(
            run_command(
                [
                    sys.executable,
                    "tools/wuci_external_audit.py",
                    "verify",
                    "--evidence",
                    str(external_audit_evidence),
                    "--report",
                    str(external_audit_report),
                    "--audit-root-key",
                    str(external_audit_root_key),
                    "--audit-signature",
                    str(external_audit_signature),
                    "--repo",
                    str(repo),
                    "--quiet",
                ],
                cwd=repo,
                label="signed external audit verification",
            )
        )

    commands.append(
        run_command(
            [str(zig_witness), "verify", str(witness_bundle), "--bin", str(bin_path)],
            cwd=repo,
            label="witness bundle verification",
        )
    )
    commands.append(
        run_command(
            [str(zig_ledger), "verify-history", "--bin", str(bin_path), "--ledger", str(ledger)],
            cwd=repo,
            label="ledger history verification",
        )
    )
    install_check = run_command(
        [
            sys.executable,
            "tools/wuci_install.py",
            "verify-manifest",
            "--install-root-key",
            str(install_root_key),
            "--bin",
            str(bin_path),
            "--manifest",
            str(install_manifest),
            "--signature",
            str(install_signature),
        ],
        cwd=repo,
        label="install manifest signature and digest verification",
        fatal=False,
    )
    commands.append(install_check)
    if not install_check["passed"]:
        blockers.append("current-build-install-manifest-signature-or-digest-not-verified")

    commands.append(run_command([str(rust_sandbox), "--selftest"], cwd=repo, label="Rust sandbox selftest"))
    commands.append(
        run_command(
            [str(rust_sandbox), "--no-network", "--", str(bin_path), "selftest"],
            cwd=repo,
            label="Rust sandbox no-network binary selftest",
        )
    )

    unique_blockers = sorted(set(blockers))
    result = {
        "schema": VERIFY_SCHEMA,
        "status": "verified" if not unique_blockers else "verified-with-blockers",
        "release_evidence_verified": True,
        "production_ready_claimed": False,
        "post_quantum_security_claimed": False,
        "runtime_containment_complete_claimed": False,
        "external_validation_claimed": False,
        "signed_external_audit_verified": audit_supplied,
        "git": {
            "head": commit["stdout_tail"].strip(),
            "dirty": dirty,
            "status_sha256": status["stdout_sha256"],
        },
        "binary": {
            "path": str(bin_path),
            "bytes": bin_size,
            "sha256": bin_sha256,
            "sha384": bin_sha384,
            "sha512": bin_sha512,
        },
        "checks": {
            "commands": commands,
            "carrot": carrot_record,
            "pq_detection": {
                "path": str(pq),
                "real_pq_signature_verifier_available": pq_detection.get("real_pq_signature_verifier_available"),
                "quantum_safe_claim_allowed": pq_detection.get("quantum_safe_claim_allowed"),
            },
            "parser_replay": parser_record,
        },
        "blockers": unique_blockers,
        "non_claims": list(VERIFY_NON_CLAIMS),
    }
    return result


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

    verify = subparsers.add_parser("verify", help="verify release-bundle evidence and write blocker-aware JSON")
    verify.add_argument("--repo", type=Path, default=Path("."))
    verify.add_argument("--bin", dest="bin_path", type=Path, required=True)
    verify.add_argument("--sbom", type=Path, required=True)
    verify.add_argument("--provenance", type=Path, required=True)
    verify.add_argument("--carrot", type=Path, required=True)
    verify.add_argument("--pq", type=Path, required=True)
    verify.add_argument("--real-pq-evidence", type=Path)
    verify.add_argument("--pq-pins", type=Path, required=True)
    verify.add_argument("--crypto-audit", type=Path, required=True)
    verify.add_argument("--parser-replay", type=Path, required=True)
    verify.add_argument("--production-authority-policy", type=Path, required=True)
    verify.add_argument("--production-authority", type=Path)
    verify.add_argument("--production-authority-ceremony", type=Path)
    verify.add_argument("--production-authority-ceremony-root-key", type=Path)
    verify.add_argument("--production-authority-ceremony-signature", type=Path)
    verify.add_argument("--external-audit-evidence", type=Path)
    verify.add_argument("--external-audit-report", type=Path)
    verify.add_argument("--external-audit-root-key", type=Path)
    verify.add_argument("--external-audit-signature", type=Path)
    verify.add_argument("--witness-bundle", type=Path, required=True)
    verify.add_argument("--ledger", type=Path, required=True)
    verify.add_argument("--install-manifest", type=Path, required=True)
    verify.add_argument("--install-signature", type=Path, required=True)
    verify.add_argument("--install-root-key", type=Path, required=True)
    verify.add_argument("--rust-sandbox", type=Path, required=True)
    verify.add_argument("--zig-witness", type=Path, required=True)
    verify.add_argument("--zig-ledger", type=Path, required=True)
    verify.add_argument("--out", type=Path, required=True)
    verify.add_argument("--quiet", action="store_true")
    verify.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command not in {"build", "verify"}:
        parser.print_help()
        return 2
    try:
        if args.command == "build":
            result = build_bundle(
                out=args.out,
                final_dir=args.final_dir,
                evidence_dir=args.evidence_dir,
                privacy_audit=args.privacy_audit,
                rootfs_privacy_audit=args.rootfs_privacy_audit,
                daylight_ssv=args.daylight_ssv,
                force=args.force,
            )
        else:
            result = verify_release_bundle(
                repo=args.repo,
                bin_path=args.bin_path,
                sbom=args.sbom,
                provenance=args.provenance,
                carrot=args.carrot,
                pq=args.pq,
                real_pq_evidence=args.real_pq_evidence,
                pq_pins=args.pq_pins,
                crypto_audit=args.crypto_audit,
                parser_replay=args.parser_replay,
                production_authority_policy=args.production_authority_policy,
                production_authority=args.production_authority,
                production_authority_ceremony=args.production_authority_ceremony,
                production_authority_ceremony_root_key=args.production_authority_ceremony_root_key,
                production_authority_ceremony_signature=args.production_authority_ceremony_signature,
                external_audit_evidence=args.external_audit_evidence,
                external_audit_report=args.external_audit_report,
                external_audit_root_key=args.external_audit_root_key,
                external_audit_signature=args.external_audit_signature,
                witness_bundle=args.witness_bundle,
                ledger=args.ledger,
                install_manifest=args.install_manifest,
                install_signature=args.install_signature,
                install_root_key=args.install_root_key,
                rust_sandbox=args.rust_sandbox,
                zig_witness=args.zig_witness,
                zig_ledger=args.zig_ledger,
            )
            write_json_atomic(args.out, result)
    except ReleaseBundleError as exc:
        print(f"wuci-release-bundle: {exc}", file=os.sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(stable_json(result), end="")
    elif args.command == "build":
        print(f"wuci-release-bundle: {result['status']} -> {args.out}")
    elif not args.quiet:
        print(f"wuci-release-bundle-verification: {result['status']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
