"""Deterministic public-review artifact emission for v20."""

from __future__ import annotations

import gzip
import hashlib
import re
import shutil
import stat
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Any

from . import boundary_debt
from . import evidence_audit
from .canonical import json_bytes, load_json_no_floats
from .pathsafe import atomic_write_bytes, hash_file_dual
from .singularity_gate import (
    PACKAGE_ROOT,
    DEFAULT_BOUNDARY_DEBT,
    DEFAULT_EXTERNAL_ATTESTATION,
    DEFAULT_FALSIFICATION,
    DEFAULT_FIREWALL_PROFILE_EXPANSION,
    DEFAULT_REPRODUCIBLE_BUILDS,
    DEFAULT_VERIFIER_BUNDLE,
    declaration_report,
    load_capsule,
)

CAPSULE_FILENAME = "aperture-singularity-capsule.v20.json"
SCHEMA_FILENAME = "aperture-singularity-capsule.schema.json"
VERIFIER_BUNDLE_FILENAME = "verifier-agreement.bundle.json"
EXTERNAL_ATTESTATION_FILENAME = "external-attestation.bundle.json"
REPRODUCIBLE_BUILD_FILENAME = "reproducible-build.bundle.json"
FALSIFICATION_FILENAME = "falsification-survival.bundle.json"
BOUNDARY_DEBT_FILENAME = "boundary-debt.report.json"
FIREWALL_PROFILE_FILENAME = "firewall-profile-expansion.bundle.json"
OMEGA_SCORECARD_FILENAME = "omega-field-scorecard.json"
BLOCKER_VECTOR_FILENAME = "singularity-blocker-vector.json"
DECLARATION_GATE_FILENAME = "singularity-declaration-gate.report.json"
EVIDENCE_AUDIT_FILENAME = "evidence-audit.report.json"
REVIEWER_GUIDE_FILENAME = "REVIEWER_GUIDE.md"
NON_CLAIMS_FILENAME = "NON_CLAIMS.md"
SHA256SUMS_FILENAME = "SHA256SUMS"
SHA3_512SUMS_FILENAME = "SHA3-512SUMS"
FIREWALL_REPORT_SCHEMA = "daylight-v20-aperture-singularity-firewall-report"

EXPECTED_FILES = [
    CAPSULE_FILENAME,
    SCHEMA_FILENAME,
    VERIFIER_BUNDLE_FILENAME,
    EXTERNAL_ATTESTATION_FILENAME,
    REPRODUCIBLE_BUILD_FILENAME,
    FALSIFICATION_FILENAME,
    BOUNDARY_DEBT_FILENAME,
    FIREWALL_PROFILE_FILENAME,
    OMEGA_SCORECARD_FILENAME,
    BLOCKER_VECTOR_FILENAME,
    DECLARATION_GATE_FILENAME,
    EVIDENCE_AUDIT_FILENAME,
    REVIEWER_GUIDE_FILENAME,
    NON_CLAIMS_FILENAME,
    SHA256SUMS_FILENAME,
    SHA3_512SUMS_FILENAME,
]

SUMS_LINE_RE = re.compile(r"^([0-9a-f]+)  (.+)$")
FORBIDDEN_SUFFIXES = {".key", ".pem", ".priv", ".secret", ".mae", ".dhv", ".dhr"}
FORBIDDEN_PATH_PARTS = {"private", "vault", "vault-work", "store", "smoke-vault", ".meridian-vault"}
FORBIDDEN_NAME_RE = re.compile(
    r"(^|[._-])(secret|plaintext|plain|opened|open-output|keyfile|vault-key|passphrase|luks|private)([._-]|$)",
    re.IGNORECASE,
)
SECRET_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"PRIVATE KEY",
    b"API_KEY=",
    b"DAYLIGHT_BASTION_PASSPHRASE",
    b"daylight-v18-fixture-passphrase",
)


class PublicArtifactError(ValueError):
    pass


def _guard_removable(out: Path, base: Path) -> None:
    resolved = out.resolve()
    if resolved == base or resolved in base.parents:
        raise PublicArtifactError("refusing to clear the repository root or one of its parents")
    if (resolved / ".git").exists():
        raise PublicArtifactError("refusing to clear a directory containing .git")


def _copy_json(src: Path, dst: Path) -> None:
    payload = load_json_no_floats(src)
    atomic_write_bytes(dst, json_bytes(payload))


def _reviewer_guide(capsule: dict[str, Any]) -> str:
    blockers = "\n".join(f"- {item}" for item in capsule["blockers"])
    return (
        "# Daylight v20 Reviewer Guide\n\n"
        "This public-review artifact is a deterministic evidence intake bundle. "
        "It is not a Singularity declaration and does not claim external closure.\n\n"
        "## Review order\n\n"
        "1. Verify `SHA256SUMS` and `SHA3-512SUMS` against every file in this directory.\n"
        "2. Verify `aperture-singularity-capsule.v20.json` with `src.cli verify-capsule`.\n"
        "3. Read `singularity-blocker-vector.json` before considering any declaration language.\n"
        "4. Treat every blocker as release-stopping until machine-verified evidence closes it.\n\n"
        "## Current blockers\n\n"
        f"{blockers}\n"
    )


def _non_claims_text(non_claims: list[str]) -> str:
    body = "\n".join(f"- {item}" for item in non_claims)
    return "# Daylight v20 Non-Claims\n\n" + body + "\n"


def _omega_scorecard(capsule: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_id": "daylight-v20-omega-field-scorecard",
        "capsule_digest": capsule["capsule_digest"],
        "omega_sum": capsule["omega_sum"],
        "omega_weak": capsule["omega_weak"],
        "omega_eff": capsule["omega_eff"],
        "score_AM_plus": capsule["score_AM_plus"],
        "field_thresholds_passed": capsule["field_thresholds_passed"],
        "proof_fields": capsule["proof_fields"],
        "non_claim": "score is regenerated from evidence atoms and does not modify conservative Daylight M",
    }


def _blocker_vector(capsule: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_id": "daylight-v20-singularity-blocker-vector",
        "capsule_digest": capsule["capsule_digest"],
        "declaration_allowed": capsule["declaration_allowed"],
        "blockers": capsule["blockers"],
        "fixture": capsule["fixture"],
        "claim_usable": capsule["claim_usable"],
        "verifier_quorum": capsule["verifier_quorum"],
        "external_attestation_verified": capsule["external_attestation_verified"],
    }


def _write_sums(root: Path) -> tuple[str, str]:
    sha256_lines: list[str] = []
    sha3_lines: list[str] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name in {SHA256SUMS_FILENAME, SHA3_512SUMS_FILENAME}:
            continue
        sha256, sha3_512, _size = hash_file_dual(path)
        sha256_lines.append(f"{sha256}  {path.name}\n")
        sha3_lines.append(f"{sha3_512}  {path.name}\n")
    sha256_text = "".join(sha256_lines).encode("utf-8")
    sha3_text = "".join(sha3_lines).encode("utf-8")
    atomic_write_bytes(root / SHA256SUMS_FILENAME, sha256_text, force=True)
    atomic_write_bytes(root / SHA3_512SUMS_FILENAME, sha3_text, force=True)
    return hashlib.sha256(sha256_text).hexdigest(), hashlib.sha256(sha3_text).hexdigest()


def _parse_sums(path: Path, digest_len: int) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = SUMS_LINE_RE.fullmatch(line)
        if match is None:
            raise PublicArtifactError(f"invalid sums line: {line!r}")
        digest, name = match.group(1), match.group(2)
        if len(digest) != digest_len:
            raise PublicArtifactError(f"invalid digest length in sums line: {line!r}")
        if name in entries:
            raise PublicArtifactError(f"duplicate sums entry: {name}")
        entries[name] = digest
    return entries


def _deterministic_tar_gz(root: Path, tar_path: Path) -> str:
    if tar_path.exists() or tar_path.is_symlink():
        tar_path.unlink()
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in sorted(root.iterdir(), key=lambda item: item.name):
            if not path.is_file():
                continue
            data = path.read_bytes()
            info = tarfile.TarInfo(name=path.name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, BytesIO(data))
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as handle:
            handle.write(buffer.getvalue())
    return hashlib.sha256(tar_path.read_bytes()).hexdigest()


def build_public_artifact(
    capsule_path: Path | str,
    out_dir: Path | str,
    *,
    verifier_bundle_path: Path | str | None = None,
    external_attestation_path: Path | str | None = None,
    reproducible_build_path: Path | str | None = None,
    falsification_path: Path | str | None = None,
    boundary_debt_path: Path | str | None = None,
    firewall_profile_path: Path | str | None = None,
    force: bool = False,
    tar_path: Path | str | None = None,
    firewall_report_path: Path | str | None = None,
) -> dict[str, Any]:
    base = PACKAGE_ROOT.parents[1]
    capsule = load_capsule(capsule_path)
    out = Path(out_dir)
    if out.is_symlink():
        raise PublicArtifactError(f"refusing to publish through a symlink: {out}")
    if out.exists():
        if not out.is_dir():
            raise PublicArtifactError(f"public artifact output is not a directory: {out}")
        if any(out.iterdir()):
            if not force:
                raise PublicArtifactError(f"refusing to overwrite non-empty output without --force: {out}")
            _guard_removable(out, base)
            shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        atomic_write_bytes(out / CAPSULE_FILENAME, json_bytes(capsule))
        _copy_json(PACKAGE_ROOT / "schema" / SCHEMA_FILENAME, out / SCHEMA_FILENAME)
        _copy_json(Path(verifier_bundle_path) if verifier_bundle_path is not None else DEFAULT_VERIFIER_BUNDLE, out / VERIFIER_BUNDLE_FILENAME)
        _copy_json(Path(external_attestation_path) if external_attestation_path is not None else DEFAULT_EXTERNAL_ATTESTATION, out / EXTERNAL_ATTESTATION_FILENAME)
        _copy_json(Path(reproducible_build_path) if reproducible_build_path is not None else DEFAULT_REPRODUCIBLE_BUILDS, out / REPRODUCIBLE_BUILD_FILENAME)
        _copy_json(Path(falsification_path) if falsification_path is not None else DEFAULT_FALSIFICATION, out / FALSIFICATION_FILENAME)
        _copy_json(Path(boundary_debt_path) if boundary_debt_path is not None else DEFAULT_BOUNDARY_DEBT, out / BOUNDARY_DEBT_FILENAME)
        _copy_json(Path(firewall_profile_path) if firewall_profile_path is not None else DEFAULT_FIREWALL_PROFILE_EXPANSION, out / FIREWALL_PROFILE_FILENAME)
        atomic_write_bytes(out / OMEGA_SCORECARD_FILENAME, json_bytes(_omega_scorecard(capsule)))
        atomic_write_bytes(out / BLOCKER_VECTOR_FILENAME, json_bytes(_blocker_vector(capsule)))
        atomic_write_bytes(out / DECLARATION_GATE_FILENAME, json_bytes(declaration_report(capsule)))
        atomic_write_bytes(out / EVIDENCE_AUDIT_FILENAME, json_bytes(evidence_audit.audit_capsule(capsule)))
        atomic_write_bytes(out / REVIEWER_GUIDE_FILENAME, _reviewer_guide(capsule).encode("utf-8"))
        atomic_write_bytes(out / NON_CLAIMS_FILENAME, _non_claims_text(boundary_debt.NON_CLAIMS).encode("utf-8"))
        sha256sums_sha256, sha3sums_sha256 = _write_sums(out)
        firewall = run_firewall(out, report_path=firewall_report_path)
        tar_target = Path(tar_path) if tar_path is not None else out.with_suffix(".tar.gz")
        tar_sha256 = _deterministic_tar_gz(out, tar_target)
    except (OSError, ValueError, PublicArtifactError):
        shutil.rmtree(out, ignore_errors=True)
        raise

    return {
        "out_dir": out.as_posix(),
        "tar_path": tar_target.as_posix(),
        "tar_sha256": tar_sha256,
        "file_count": len([item for item in out.iterdir() if item.is_file()]),
        "capsule_digest": capsule["capsule_digest"],
        "sha256sums_sha256": sha256sums_sha256,
        "sha3_512sums_sha256": sha3sums_sha256,
        "firewall_ok": firewall["ok"],
        "firewall_report_path": firewall["report_path"],
    }


def scan_public_root(root: Path | str, *, max_file_bytes: int = 5_000_000) -> dict[str, Any]:
    root_path = Path(root)
    violations: list[dict[str, str]] = []

    def add(path: str, reason: str) -> None:
        violations.append({"path": path, "reason": reason})

    if root_path.is_symlink():
        raise PublicArtifactError(f"public root is a symlink: {root_path}")
    if not root_path.exists():
        raise PublicArtifactError(f"public root does not exist: {root_path}")
    if not root_path.is_dir():
        raise PublicArtifactError(f"public root is not a directory: {root_path}")

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
            for part in path.relative_to(root_path).parts:
                if part.startswith("."):
                    add(relative, "hidden_component_in_public_artifact")
            if set(path.relative_to(root_path).parts) & FORBIDDEN_PATH_PARTS:
                add(relative, "public_artifact_contains_private_directory")
            continue
        if not stat.S_ISREG(st.st_mode):
            add(relative, "non_regular_public_artifact_member")
            continue
        files.append(relative)
        if "/" in relative:
            add(relative, "nested_public_artifact_path_unexpected")
        if path.name.startswith("."):
            add(relative, "hidden_component_in_public_artifact")
        if st.st_nlink > 1:
            add(relative, "hardlink_in_public_artifact")
        if st.st_size > max_file_bytes:
            add(relative, "file_exceeds_public_artifact_size_limit")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            add(relative, "forbidden_private_material_suffix")
        if FORBIDDEN_NAME_RE.search(path.name):
            add(relative, "forbidden_secret_path")
        data = path.read_bytes()
        for marker in SECRET_MARKERS:
            if marker in data:
                add(relative, "known_secret_marker")
                break

    expected = set(EXPECTED_FILES)
    actual = set(files)
    for extra in sorted(actual - expected):
        add(extra, "unexpected_public_artifact_file")
    for missing in sorted(expected - actual):
        add(missing, "missing_public_artifact_file")
    if SHA256SUMS_FILENAME in actual:
        try:
            sums = _parse_sums(root_path / SHA256SUMS_FILENAME, 64)
            expected_hashable = actual - {SHA256SUMS_FILENAME, SHA3_512SUMS_FILENAME}
            if set(sums) != expected_hashable:
                add(SHA256SUMS_FILENAME, "sha256sums_file_set_mismatch")
            for name in sorted(set(sums) & expected_hashable):
                if hash_file_dual(root_path / name)[0] != sums[name]:
                    add(name, "sha256sum_mismatch")
        except (OSError, ValueError) as exc:
            add(SHA256SUMS_FILENAME, f"sha256sums_invalid:{exc}")
    if SHA3_512SUMS_FILENAME in actual:
        try:
            sums = _parse_sums(root_path / SHA3_512SUMS_FILENAME, 128)
            expected_hashable = actual - {SHA256SUMS_FILENAME, SHA3_512SUMS_FILENAME}
            if set(sums) != expected_hashable:
                add(SHA3_512SUMS_FILENAME, "sha3_512sums_file_set_mismatch")
            for name in sorted(set(sums) & expected_hashable):
                if hash_file_dual(root_path / name)[1] != sums[name]:
                    add(name, "sha3_512sum_mismatch")
        except (OSError, ValueError) as exc:
            add(SHA3_512SUMS_FILENAME, f"sha3_512sums_invalid:{exc}")

    capsule_digest: str | None = None
    if CAPSULE_FILENAME in actual:
        try:
            capsule = load_capsule(root_path / CAPSULE_FILENAME)
            capsule_digest = capsule["capsule_digest"]
            if capsule["declaration_allowed"]:
                add(CAPSULE_FILENAME, "fixture public artifact unexpectedly declares Singularity")
        except (OSError, ValueError) as exc:
            add(CAPSULE_FILENAME, f"capsule_invalid:{exc}")

    return {
        "schema": FIREWALL_REPORT_SCHEMA,
        "ok": not violations,
        "scanned_root": root_path.as_posix(),
        "file_count": len(files),
        "capsule_digest": capsule_digest,
        "violations": violations,
    }


def default_report_path(root: Path | str) -> Path:
    root_path = Path(root)
    return root_path.parent / (root_path.name + ".firewall-report.v20.json")


def run_firewall(root: Path | str, *, report_path: Path | str | None = None) -> dict[str, Any]:
    root_path = Path(root)
    report = scan_public_root(root_path)
    target = Path(report_path) if report_path is not None else default_report_path(root_path)
    resolved_root = root_path.resolve()
    resolved_target = target.parent.resolve() / target.name
    if resolved_target == resolved_root or resolved_root in resolved_target.parents:
        raise PublicArtifactError("firewall report must be written outside the public root")
    if target.exists() or target.is_symlink():
        recognized = False
        if target.is_file() and not target.is_symlink():
            try:
                old = load_json_no_floats(target)
                recognized = isinstance(old, dict) and old.get("schema") == FIREWALL_REPORT_SCHEMA
            except (ValueError, OSError):
                recognized = False
        if not recognized:
            raise PublicArtifactError(f"refusing to replace unrecognized report path: {target}")
        target.unlink()
    if report["ok"]:
        atomic_write_bytes(target, json_bytes(report))
        report["report_path"] = target.as_posix()
    return report
