"""Deterministic public-review artifact emission for v20."""

from __future__ import annotations

import gzip
import hashlib
import re
import shutil
import stat
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Any

from . import boundary_debt
from . import evidence_audit
from . import firewall_profile
from .canonical import canonical_sha256, json_bytes, load_json_no_floats
from .pathsafe import atomic_write_bytes, hash_file_dual
from .singularity_gate import (
    D_BOUNDARY_DEBT,
    D_EXTERNAL_ATTESTATION,
    D_FALSIFICATION,
    D_REPRODUCIBLE_BUILD,
    D_VERIFIER_AGREEMENT,
    PACKAGE_ROOT,
    REPO_ROOT,
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
VERIFIER_SCHEMA_FILENAME = "verifier-agreement.bundle.schema.json"
EXTERNAL_ATTESTATION_SCHEMA_FILENAME = "external-attestation.bundle.schema.json"
REPRODUCIBLE_BUILD_SCHEMA_FILENAME = "reproducible-build.bundle.schema.json"
FALSIFICATION_SCHEMA_FILENAME = "falsification-survival.bundle.schema.json"
BOUNDARY_DEBT_SCHEMA_FILENAME = "boundary-debt.report.schema.json"
FIREWALL_PROFILE_SCHEMA_FILENAME = "firewall-profile-expansion.bundle.schema.json"
VERIFIER_BUNDLE_FILENAME = "verifier-agreement.bundle.json"
EXTERNAL_ATTESTATION_FILENAME = "external-attestation.bundle.json"
REPRODUCIBLE_BUILD_FILENAME = "reproducible-build.bundle.json"
FALSIFICATION_FILENAME = "falsification-survival.bundle.json"
BOUNDARY_DEBT_FILENAME = "boundary-debt.report.json"
FIREWALL_PROFILE_FILENAME = "firewall-profile-expansion.bundle.json"
EVIDENCE_SLOT_CONTRACTS_FILENAME = "external-evidence-slot-contracts.v20.json"
EXTERNAL_EVIDENCE_BUNDLE_SCHEMA_FILENAME = "external-evidence.bundle.schema.json"
INDEPENDENT_REBUILD_RECEIPT_SCHEMA_FILENAME = "independent-rebuild-receipt.schema.json"
FIREWALL_PROFILE_REVIEW_SCHEMA_FILENAME = "firewall-profile-review.schema.json"
VERIFIER_VECTOR_CLAIM_USABLE_SCHEMA_FILENAME = "verifier-vector-claim-usable.schema.json"
PINNED_ATTESTATION_SCHEMA_FILENAME = "pinned-attestation.schema.json"
EXTERNAL_REBUILD_RECEIPT_SCHEMA_FILENAME = "external_rebuild_receipt.v20.json"
EXTERNAL_EVIDENCE_PROTOCOL_FILENAME = "DAYLIGHT_V20_EXTERNAL_EVIDENCE_PROTOCOL.md"
REVIEWER_PACKET_FILENAME = "DAYLIGHT_V20_REVIEWER_PACKET.md"
INDEPENDENT_REBUILD_RECEIPT_DOC_FILENAME = "DAYLIGHT_V20_INDEPENDENT_REBUILD_RECEIPT.md"
REBUILD_RECEIPT_PROTOCOL_DOC_FILENAME = "DAYLIGHT_V20_REBUILD_RECEIPT_PROTOCOL.md"
FIREWALL_PROFILE_REVIEW_DOC_FILENAME = "DAYLIGHT_V20_FIREWALL_PROFILE_REVIEW.md"
VERIFIER_VECTOR_CONTRACT_DOC_FILENAME = "DAYLIGHT_V20_VERIFIER_VECTOR_CONTRACT.md"
VERIFIER_VECTOR_QUORUM_DOC_FILENAME = "DAYLIGHT_V20_VERIFIER_VECTOR_QUORUM.md"
CANONICAL_VERIFIER_OUTPUT_DOC_FILENAME = "DAYLIGHT_V20_CANONICAL_VERIFIER_OUTPUT.md"
ATTESTATION_VERIFICATION_DOC_FILENAME = "DAYLIGHT_V20_ATTESTATION_VERIFICATION.md"
MANIFEST_FILENAME = "public-artifact.manifest.v20.json"
OMEGA_SCORECARD_FILENAME = "omega-field-scorecard.json"
BLOCKER_VECTOR_FILENAME = "singularity-blocker-vector.json"
DECLARATION_GATE_FILENAME = "singularity-declaration-gate.report.json"
EVIDENCE_AUDIT_FILENAME = "evidence-audit.report.json"
SCORE_CEILING_FILENAME = "score-ceiling.report.json"
REVIEWER_GUIDE_FILENAME = "REVIEWER_GUIDE.md"
NON_CLAIMS_FILENAME = "NON_CLAIMS.md"
SHA256SUMS_FILENAME = "SHA256SUMS"
SHA3_512SUMS_FILENAME = "SHA3-512SUMS"
FIREWALL_REPORT_SCHEMA = "daylight-v20-aperture-singularity-firewall-report"

EXTERNAL_EVIDENCE_SCHEMA_FILENAMES = [
    EXTERNAL_EVIDENCE_BUNDLE_SCHEMA_FILENAME,
    INDEPENDENT_REBUILD_RECEIPT_SCHEMA_FILENAME,
    FIREWALL_PROFILE_REVIEW_SCHEMA_FILENAME,
    VERIFIER_VECTOR_CLAIM_USABLE_SCHEMA_FILENAME,
    PINNED_ATTESTATION_SCHEMA_FILENAME,
    EXTERNAL_REBUILD_RECEIPT_SCHEMA_FILENAME,
]

EXTERNAL_EVIDENCE_DOC_FILENAMES = [
    EXTERNAL_EVIDENCE_PROTOCOL_FILENAME,
    REVIEWER_PACKET_FILENAME,
    INDEPENDENT_REBUILD_RECEIPT_DOC_FILENAME,
    REBUILD_RECEIPT_PROTOCOL_DOC_FILENAME,
    FIREWALL_PROFILE_REVIEW_DOC_FILENAME,
    VERIFIER_VECTOR_CONTRACT_DOC_FILENAME,
    VERIFIER_VECTOR_QUORUM_DOC_FILENAME,
    CANONICAL_VERIFIER_OUTPUT_DOC_FILENAME,
    ATTESTATION_VERIFICATION_DOC_FILENAME,
]

EXPECTED_FILES = [
    CAPSULE_FILENAME,
    SCHEMA_FILENAME,
    VERIFIER_SCHEMA_FILENAME,
    EXTERNAL_ATTESTATION_SCHEMA_FILENAME,
    REPRODUCIBLE_BUILD_SCHEMA_FILENAME,
    FALSIFICATION_SCHEMA_FILENAME,
    BOUNDARY_DEBT_SCHEMA_FILENAME,
    FIREWALL_PROFILE_SCHEMA_FILENAME,
    *EXTERNAL_EVIDENCE_SCHEMA_FILENAMES,
    *EXTERNAL_EVIDENCE_DOC_FILENAMES,
    VERIFIER_BUNDLE_FILENAME,
    EXTERNAL_ATTESTATION_FILENAME,
    REPRODUCIBLE_BUILD_FILENAME,
    FALSIFICATION_FILENAME,
    BOUNDARY_DEBT_FILENAME,
    FIREWALL_PROFILE_FILENAME,
    EVIDENCE_SLOT_CONTRACTS_FILENAME,
    MANIFEST_FILENAME,
    OMEGA_SCORECARD_FILENAME,
    BLOCKER_VECTOR_FILENAME,
    DECLARATION_GATE_FILENAME,
    EVIDENCE_AUDIT_FILENAME,
    SCORE_CEILING_FILENAME,
    REVIEWER_GUIDE_FILENAME,
    NON_CLAIMS_FILENAME,
    SHA256SUMS_FILENAME,
    SHA3_512SUMS_FILENAME,
]

MANIFEST_EXCLUDED_FROM_FILE_ENTRIES = {
    MANIFEST_FILENAME,
    SHA256SUMS_FILENAME,
    SHA3_512SUMS_FILENAME,
}

EVIDENCE_SCHEMA_FILENAMES = [
    SCHEMA_FILENAME,
    VERIFIER_SCHEMA_FILENAME,
    EXTERNAL_ATTESTATION_SCHEMA_FILENAME,
    REPRODUCIBLE_BUILD_SCHEMA_FILENAME,
    FALSIFICATION_SCHEMA_FILENAME,
    BOUNDARY_DEBT_SCHEMA_FILENAME,
    FIREWALL_PROFILE_SCHEMA_FILENAME,
    *EXTERNAL_EVIDENCE_SCHEMA_FILENAMES,
]

FILE_ROLES = {
    CAPSULE_FILENAME: "capsule",
    SCHEMA_FILENAME: "schema",
    VERIFIER_SCHEMA_FILENAME: "schema",
    EXTERNAL_ATTESTATION_SCHEMA_FILENAME: "schema",
    REPRODUCIBLE_BUILD_SCHEMA_FILENAME: "schema",
    FALSIFICATION_SCHEMA_FILENAME: "schema",
    BOUNDARY_DEBT_SCHEMA_FILENAME: "schema",
    FIREWALL_PROFILE_SCHEMA_FILENAME: "schema",
    EXTERNAL_EVIDENCE_BUNDLE_SCHEMA_FILENAME: "schema",
    INDEPENDENT_REBUILD_RECEIPT_SCHEMA_FILENAME: "schema",
    FIREWALL_PROFILE_REVIEW_SCHEMA_FILENAME: "schema",
    VERIFIER_VECTOR_CLAIM_USABLE_SCHEMA_FILENAME: "schema",
    PINNED_ATTESTATION_SCHEMA_FILENAME: "schema",
    EXTERNAL_REBUILD_RECEIPT_SCHEMA_FILENAME: "schema",
    EXTERNAL_EVIDENCE_PROTOCOL_FILENAME: "reviewer_doc",
    REVIEWER_PACKET_FILENAME: "reviewer_doc",
    INDEPENDENT_REBUILD_RECEIPT_DOC_FILENAME: "reviewer_doc",
    REBUILD_RECEIPT_PROTOCOL_DOC_FILENAME: "reviewer_doc",
    FIREWALL_PROFILE_REVIEW_DOC_FILENAME: "reviewer_doc",
    VERIFIER_VECTOR_CONTRACT_DOC_FILENAME: "reviewer_doc",
    VERIFIER_VECTOR_QUORUM_DOC_FILENAME: "reviewer_doc",
    CANONICAL_VERIFIER_OUTPUT_DOC_FILENAME: "reviewer_doc",
    ATTESTATION_VERIFICATION_DOC_FILENAME: "reviewer_doc",
    VERIFIER_BUNDLE_FILENAME: "evidence_bundle",
    EXTERNAL_ATTESTATION_FILENAME: "evidence_bundle",
    REPRODUCIBLE_BUILD_FILENAME: "evidence_bundle",
    FALSIFICATION_FILENAME: "evidence_bundle",
    BOUNDARY_DEBT_FILENAME: "evidence_bundle",
    FIREWALL_PROFILE_FILENAME: "evidence_bundle",
    EVIDENCE_SLOT_CONTRACTS_FILENAME: "evidence_slot_contracts",
    OMEGA_SCORECARD_FILENAME: "derived_report",
    BLOCKER_VECTOR_FILENAME: "derived_report",
    DECLARATION_GATE_FILENAME: "derived_report",
    EVIDENCE_AUDIT_FILENAME: "derived_report",
    SCORE_CEILING_FILENAME: "derived_report",
    REVIEWER_GUIDE_FILENAME: "reviewer_doc",
    NON_CLAIMS_FILENAME: "reviewer_doc",
    MANIFEST_FILENAME: "manifest",
    SHA256SUMS_FILENAME: "digest_sums",
    SHA3_512SUMS_FILENAME: "digest_sums",
}

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
        "1. Run `src.cli verify-public-artifact` against this directory or its deterministic tarball.\n"
        "2. Inspect `public-artifact.manifest.v20.json` for file, schema, and release-tag bindings.\n"
        "3. Verify `aperture-singularity-capsule.v20.json` with `src.cli verify-capsule`.\n"
        "4. Read `singularity-blocker-vector.json` before considering any declaration language.\n"
        "5. Treat every blocker as release-stopping until machine-verified evidence closes it.\n\n"
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


def _schema_digests(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name in EVIDENCE_SCHEMA_FILENAMES:
        sha256, sha3_512, size = hash_file_dual(root / name)
        out.append(
            {
                "path": name,
                "size": size,
                "sha256": sha256,
                "sha3_512": sha3_512,
            }
        )
    return out


def _evidence_slot_contracts(capsule: dict[str, Any]) -> dict[str, Any]:
    field_by_id = {
        field["field_id"]: field
        for field in capsule["proof_fields"]
        if isinstance(field, dict) and isinstance(field.get("field_id"), str)
    }
    return {
        "schema_id": "daylight-v20-external-evidence-slot-contracts",
        "schema_version": "0.1.0",
        "capsule_digest": capsule["capsule_digest"],
        "release_tag": capsule["release_tag"],
        "declaration_allowed": capsule["declaration_allowed"],
        "non_claims": boundary_debt.NON_CLAIMS,
        "slots": [
            {
                "slot_id": "reproducible_build.non_fixture_subject_bound_rebuilds",
                "proof_field": "reproducible_build",
                "required_bundle": REPRODUCIBLE_BUILD_FILENAME,
                "current_open_atoms": field_by_id["reproducible_build"]["open_atoms"],
                "machine_checks": [
                    "receipt_digest recomputes for every receipt",
                    "at least two independent builders",
                    "distinct build environments",
                    "source commit matches capsule source_commit",
                    "artifact SHA-256, SHA3-512, and size match capsule subject",
                    "fixture is false",
                    "claim_usable is true",
                ],
            },
            {
                "slot_id": "aperture_firewall_boundary.external_profile_expansion",
                "proof_field": "aperture_firewall_boundary",
                "required_bundle": FIREWALL_PROFILE_FILENAME,
                "current_open_atoms": field_by_id["aperture_firewall_boundary"]["open_atoms"],
                "machine_checks": [
                    "repo-owned negative matrix remains complete",
                    "external firewall profile expansion evidence is present",
                    "profile digest remains pinned",
                    "no forbidden claim is introduced",
                ],
            },
            {
                "slot_id": "independent_verifier_quorum.claim_usable_3_of_3",
                "proof_field": "independent_verifier_quorum",
                "required_bundle": VERIFIER_BUNDLE_FILENAME,
                "current_open_atoms": field_by_id["independent_verifier_quorum"]["open_atoms"],
                "machine_checks": [
                    "at least three verifier vectors",
                    "three distinct verifier families",
                    "all canonical output digests match",
                    "bundle subject matches release_tag",
                    "every vector declares the v20 capsule output schema",
                    "vector_digest recomputes for every vector",
                    "fixture is false for every vector",
                    "claim_usable is true for every vector",
                ],
            },
            {
                "slot_id": "external_attestation.pinned_cryptographic_verification",
                "proof_field": "external_attestation",
                "required_bundle": EXTERNAL_ATTESTATION_FILENAME,
                "current_open_atoms": field_by_id["external_attestation"]["open_atoms"],
                "machine_checks": [
                    "attestation statement_digest recomputes",
                    "signer is not self-scoped",
                    "attestation scope is explicit",
                    "all required non-claims are acknowledged",
                    "a real pinned cryptographic signature verifier accepts the signature",
                    "verification_status text alone is insufficient",
                ],
            },
        ],
    }


def _manifest_file_entries(root: Path, capsule_digest: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name in MANIFEST_EXCLUDED_FROM_FILE_ENTRIES:
            continue
        sha256, sha3_512, size = hash_file_dual(path)
        entries.append(
            {
                "path": path.name,
                "role": FILE_ROLES[path.name],
                "size": size,
                "sha256": sha256,
                "sha3_512": sha3_512,
                "capsule_digest": capsule_digest,
            }
        )
    return entries


def _bundle_digest_bindings(root: Path, capsule: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    bindings = [
        (
            VERIFIER_BUNDLE_FILENAME,
            "input_verifier_agreement_bundle_digest",
            lambda value: canonical_sha256(value, D_VERIFIER_AGREEMENT),
        ),
        (
            EXTERNAL_ATTESTATION_FILENAME,
            "input_external_attestation_bundle_digest",
            lambda value: canonical_sha256(value, D_EXTERNAL_ATTESTATION),
        ),
        (
            REPRODUCIBLE_BUILD_FILENAME,
            "input_reproducible_build_bundle_digest",
            lambda value: canonical_sha256(value, D_REPRODUCIBLE_BUILD),
        ),
        (
            FALSIFICATION_FILENAME,
            "input_falsification_bundle_digest",
            lambda value: canonical_sha256(value, D_FALSIFICATION),
        ),
        (
            BOUNDARY_DEBT_FILENAME,
            "input_boundary_debt_report_digest",
            lambda value: canonical_sha256(value, D_BOUNDARY_DEBT),
        ),
        (
            FIREWALL_PROFILE_FILENAME,
            "input_firewall_profile_expansion_digest",
            firewall_profile.bundle_digest,
        ),
    ]
    for filename, capsule_field, digest_func in bindings:
        try:
            payload = load_json_no_floats(root / filename)
            digest = digest_func(payload)
        except (OSError, ValueError) as exc:
            blockers.append(f"{filename} invalid: {exc}")
            continue
        if digest != capsule[capsule_field]:
            blockers.append(f"{filename} canonical digest does not match capsule {capsule_field}")
    return blockers


def _public_artifact_manifest(root: Path, capsule: dict[str, Any]) -> dict[str, Any]:
    file_entries = _manifest_file_entries(root, capsule["capsule_digest"])
    slot_sha256, slot_sha3_512, slot_size = hash_file_dual(root / EVIDENCE_SLOT_CONTRACTS_FILENAME)
    return {
        "schema_id": "daylight-v20-public-artifact-manifest",
        "schema_version": "0.1.0",
        "artifact_type": "daylight-v20-aperture-singularity-public-review",
        "capsule_digest": capsule["capsule_digest"],
        "release_tag": capsule["release_tag"],
        "source_commit": capsule["source_commit"],
        "declaration_allowed": capsule["declaration_allowed"],
        "expected_files": EXPECTED_FILES,
        "manifest_excluded_from_file_entries": sorted(MANIFEST_EXCLUDED_FROM_FILE_ENTRIES),
        "files": file_entries,
        "schema_digests": _schema_digests(root),
        "external_evidence_slot_contract": {
            "path": EVIDENCE_SLOT_CONTRACTS_FILENAME,
            "size": slot_size,
            "sha256": slot_sha256,
            "sha3_512": slot_sha3_512,
        },
        "release_tag_consistency": {
            "capsule_release_tag": capsule["release_tag"],
            "verifier_expected_subject": capsule["verifier_agreement"]["expected_subject"],
            "verifier_subject": capsule["verifier_agreement"]["subject"],
            "passed": capsule["release_tag"] == capsule["verifier_agreement"]["subject"],
        },
        "non_claims": boundary_debt.NON_CLAIMS,
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


def _safe_tar_member_name(name: str) -> str:
    if not name or name.startswith("/") or "\\" in name:
        raise PublicArtifactError(f"unsafe tar member name: {name!r}")
    path = Path(name)
    if len(path.parts) != 1 or path.parts[0] in {"", ".", ".."}:
        raise PublicArtifactError(f"unsafe tar member path: {name!r}")
    if any(part == ".." for part in path.parts):
        raise PublicArtifactError(f"unsafe tar member traversal: {name!r}")
    if name.startswith("."):
        raise PublicArtifactError(f"hidden tar member rejected: {name!r}")
    return name


def _extract_tar_gz_safely(tar_path: Path, out: Path) -> None:
    with tarfile.open(tar_path, mode="r:gz") as archive:
        seen: set[str] = set()
        for member in archive.getmembers():
            name = _safe_tar_member_name(member.name)
            if name in seen:
                raise PublicArtifactError(f"duplicate tar member: {name}")
            seen.add(name)
            if member.issym() or member.islnk():
                raise PublicArtifactError(f"tar link member rejected: {name}")
            if not member.isfile():
                raise PublicArtifactError(f"non-file tar member rejected: {name}")
            if member.size < 0 or member.size > 5_000_000:
                raise PublicArtifactError(f"tar member size rejected: {name}")
            source = archive.extractfile(member)
            if source is None:
                raise PublicArtifactError(f"unreadable tar member: {name}")
            data = source.read()
            if len(data) != member.size:
                raise PublicArtifactError(f"tar member size mismatch: {name}")
            atomic_write_bytes(out / name, data)


def _require_outside_public_root(target: Path, root: Path, name: str) -> None:
    resolved_root = root.resolve()
    resolved_target = target.parent.resolve() / target.name
    if resolved_target == resolved_root or resolved_root in resolved_target.parents:
        raise PublicArtifactError(f"{name} must be written outside the public root")


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
        for schema_name in EVIDENCE_SCHEMA_FILENAMES:
            _copy_json(PACKAGE_ROOT / "schema" / schema_name, out / schema_name)
        for doc_name in EXTERNAL_EVIDENCE_DOC_FILENAMES:
            atomic_write_bytes(out / doc_name, (REPO_ROOT / "docs" / doc_name).read_bytes())
        _copy_json(Path(verifier_bundle_path) if verifier_bundle_path is not None else DEFAULT_VERIFIER_BUNDLE, out / VERIFIER_BUNDLE_FILENAME)
        _copy_json(Path(external_attestation_path) if external_attestation_path is not None else DEFAULT_EXTERNAL_ATTESTATION, out / EXTERNAL_ATTESTATION_FILENAME)
        _copy_json(Path(reproducible_build_path) if reproducible_build_path is not None else DEFAULT_REPRODUCIBLE_BUILDS, out / REPRODUCIBLE_BUILD_FILENAME)
        _copy_json(Path(falsification_path) if falsification_path is not None else DEFAULT_FALSIFICATION, out / FALSIFICATION_FILENAME)
        _copy_json(Path(boundary_debt_path) if boundary_debt_path is not None else DEFAULT_BOUNDARY_DEBT, out / BOUNDARY_DEBT_FILENAME)
        _copy_json(Path(firewall_profile_path) if firewall_profile_path is not None else DEFAULT_FIREWALL_PROFILE_EXPANSION, out / FIREWALL_PROFILE_FILENAME)
        bundle_blockers = _bundle_digest_bindings(out, capsule)
        if bundle_blockers:
            raise PublicArtifactError("; ".join(bundle_blockers))
        atomic_write_bytes(out / OMEGA_SCORECARD_FILENAME, json_bytes(_omega_scorecard(capsule)))
        atomic_write_bytes(out / BLOCKER_VECTOR_FILENAME, json_bytes(_blocker_vector(capsule)))
        atomic_write_bytes(out / DECLARATION_GATE_FILENAME, json_bytes(declaration_report(capsule)))
        atomic_write_bytes(out / EVIDENCE_AUDIT_FILENAME, json_bytes(evidence_audit.audit_capsule(capsule)))
        atomic_write_bytes(out / SCORE_CEILING_FILENAME, json_bytes(evidence_audit.score_ceiling_report(capsule)))
        atomic_write_bytes(out / REVIEWER_GUIDE_FILENAME, _reviewer_guide(capsule).encode("utf-8"))
        atomic_write_bytes(out / NON_CLAIMS_FILENAME, _non_claims_text(boundary_debt.NON_CLAIMS).encode("utf-8"))
        atomic_write_bytes(out / EVIDENCE_SLOT_CONTRACTS_FILENAME, json_bytes(_evidence_slot_contracts(capsule)))
        atomic_write_bytes(out / MANIFEST_FILENAME, json_bytes(_public_artifact_manifest(out, capsule)))
        sha256sums_sha256, sha3sums_sha256 = _write_sums(out)
        tar_target = Path(tar_path) if tar_path is not None else out.with_suffix(".tar.gz")
        _require_outside_public_root(tar_target, out, "tarball")
        firewall = run_firewall(out, report_path=firewall_report_path)
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


def _validate_manifest(
    root: Path,
    manifest: dict[str, Any],
    *,
    expected_release_tag: str | None = None,
    expected_capsule_digest: str | None = None,
) -> list[str]:
    blockers: list[str] = []
    if set(manifest) != {
        "schema_id",
        "schema_version",
        "artifact_type",
        "capsule_digest",
        "release_tag",
        "source_commit",
        "declaration_allowed",
        "expected_files",
        "manifest_excluded_from_file_entries",
        "files",
        "schema_digests",
        "external_evidence_slot_contract",
        "release_tag_consistency",
        "non_claims",
    }:
        blockers.append("manifest field set invalid")
        return blockers
    if manifest["schema_id"] != "daylight-v20-public-artifact-manifest" or manifest["schema_version"] != "0.1.0":
        blockers.append("manifest schema unsupported")
    if manifest["artifact_type"] != "daylight-v20-aperture-singularity-public-review":
        blockers.append("manifest artifact_type unsupported")
    if manifest["expected_files"] != EXPECTED_FILES:
        blockers.append("manifest expected file list mismatch")
    if set(manifest["manifest_excluded_from_file_entries"]) != MANIFEST_EXCLUDED_FROM_FILE_ENTRIES:
        blockers.append("manifest exclusion set mismatch")
    if expected_release_tag is not None and manifest["release_tag"] != expected_release_tag:
        blockers.append("manifest release_tag does not match expected release tag")
    if expected_capsule_digest is not None and manifest["capsule_digest"] != expected_capsule_digest:
        blockers.append("manifest capsule_digest does not match expected capsule digest")
    capsule = load_capsule(root / CAPSULE_FILENAME)
    if manifest["capsule_digest"] != capsule["capsule_digest"]:
        blockers.append("manifest capsule_digest does not match capsule")
    if manifest["release_tag"] != capsule["release_tag"]:
        blockers.append("manifest release_tag does not match capsule")
    if manifest["source_commit"] != capsule["source_commit"]:
        blockers.append("manifest source_commit does not match capsule")
    if manifest["declaration_allowed"] != capsule["declaration_allowed"]:
        blockers.append("manifest declaration_allowed does not match capsule")
    blockers.extend(_bundle_digest_bindings(root, capsule))
    if not isinstance(manifest["release_tag_consistency"], dict) or manifest["release_tag_consistency"].get("passed") is not True:
        blockers.append("manifest release tag consistency failed")
    else:
        consistency = manifest["release_tag_consistency"]
        if consistency.get("capsule_release_tag") != capsule["release_tag"]:
            blockers.append("manifest capsule release tag consistency mismatch")
        if consistency.get("verifier_subject") != capsule["verifier_agreement"]["subject"]:
            blockers.append("manifest verifier subject consistency mismatch")
        if consistency.get("verifier_expected_subject") != capsule["verifier_agreement"]["expected_subject"]:
            blockers.append("manifest verifier expected subject consistency mismatch")
    if not boundary_debt.REQUIRED_NON_CLAIMS.issubset(set(manifest["non_claims"])):
        blockers.append("manifest non-claims incomplete")

    actual_files = {item.name for item in root.iterdir() if item.is_file()}
    if actual_files != set(EXPECTED_FILES):
        blockers.append("manifest actual file set mismatch")
    expected_manifest_paths = sorted(actual_files - MANIFEST_EXCLUDED_FROM_FILE_ENTRIES)
    file_entries = manifest["files"]
    if not isinstance(file_entries, list):
        blockers.append("manifest files must be a list")
        file_entries = []
    if [entry.get("path") for entry in file_entries if isinstance(entry, dict)] != expected_manifest_paths:
        blockers.append("manifest file entries are not canonical")
    for entry in file_entries:
        if not isinstance(entry, dict):
            blockers.append("manifest file entry is not an object")
            continue
        if set(entry) != {"path", "role", "size", "sha256", "sha3_512", "capsule_digest"}:
            blockers.append(f"manifest file entry field set invalid: {entry.get('path')}")
            continue
        path = root / entry["path"]
        if entry["role"] != FILE_ROLES.get(entry["path"]):
            blockers.append(f"manifest file role mismatch: {entry['path']}")
        sha256, sha3_512, size = hash_file_dual(path)
        if entry["size"] != size:
            blockers.append(f"manifest file size mismatch: {entry['path']}")
        if entry["sha256"] != sha256:
            blockers.append(f"manifest file SHA-256 mismatch: {entry['path']}")
        if entry["sha3_512"] != sha3_512:
            blockers.append(f"manifest file SHA3-512 mismatch: {entry['path']}")
        if entry["capsule_digest"] != capsule["capsule_digest"]:
            blockers.append(f"manifest file capsule binding mismatch: {entry['path']}")

    schema_digests = manifest["schema_digests"]
    if not isinstance(schema_digests, list):
        blockers.append("manifest schema_digests must be a list")
        schema_digests = []
    if [entry.get("path") for entry in schema_digests if isinstance(entry, dict)] != EVIDENCE_SCHEMA_FILENAMES:
        blockers.append("manifest schema digest entries are not canonical")
    for entry in schema_digests:
        if not isinstance(entry, dict):
            blockers.append("manifest schema digest entry is not an object")
            continue
        sha256, sha3_512, size = hash_file_dual(root / entry["path"])
        if entry.get("size") != size or entry.get("sha256") != sha256 or entry.get("sha3_512") != sha3_512:
            blockers.append(f"manifest schema digest mismatch: {entry.get('path')}")

    slot = load_json_no_floats(root / EVIDENCE_SLOT_CONTRACTS_FILENAME)
    if slot.get("schema_id") != "daylight-v20-external-evidence-slot-contracts":
        blockers.append("external evidence slot contract schema mismatch")
    if slot.get("capsule_digest") != capsule["capsule_digest"]:
        blockers.append("external evidence slot contract capsule mismatch")
    if slot.get("release_tag") != capsule["release_tag"]:
        blockers.append("external evidence slot contract release tag mismatch")
    slot_sha256, slot_sha3_512, slot_size = hash_file_dual(root / EVIDENCE_SLOT_CONTRACTS_FILENAME)
    manifest_slot = manifest["external_evidence_slot_contract"]
    if not isinstance(manifest_slot, dict) or manifest_slot != {
        "path": EVIDENCE_SLOT_CONTRACTS_FILENAME,
        "size": slot_size,
        "sha256": slot_sha256,
        "sha3_512": slot_sha3_512,
    }:
        blockers.append("manifest external evidence slot digest mismatch")
    return blockers


def verify_public_artifact(
    artifact: Path | str,
    *,
    expected_release_tag: str | None = None,
    expected_capsule_digest: str | None = None,
) -> dict[str, Any]:
    source = Path(artifact)
    tar_sha256: str | None = None
    with tempfile.TemporaryDirectory() as tmp:
        if source.is_dir():
            root = source
            artifact_type = "directory"
        elif source.is_file() and source.name.endswith(".tar.gz"):
            root = Path(tmp) / "public"
            root.mkdir()
            _extract_tar_gz_safely(source, root)
            tar_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            artifact_type = "tar.gz"
        else:
            raise PublicArtifactError(f"unsupported public artifact path: {source}")

        blockers: list[str] = []
        firewall = scan_public_root(root)
        if not firewall["ok"]:
            blockers.extend(f"{item['path']}: {item['reason']}" for item in firewall["violations"])
        try:
            manifest = load_json_no_floats(root / MANIFEST_FILENAME)
            blockers.extend(
                _validate_manifest(
                    root,
                    manifest,
                    expected_release_tag=expected_release_tag,
                    expected_capsule_digest=expected_capsule_digest,
                )
            )
        except (OSError, ValueError) as exc:
            blockers.append(f"manifest invalid: {exc}")
        capsule_digest = firewall.get("capsule_digest")
        return {
            "schema_id": "daylight-v20-public-artifact-verification-report",
            "schema_version": "0.1.0",
            "artifact": source.as_posix(),
            "artifact_type": artifact_type,
            "ok": not blockers,
            "capsule_digest": capsule_digest,
            "tar_sha256": tar_sha256,
            "file_count": firewall.get("file_count"),
            "blockers": blockers,
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
