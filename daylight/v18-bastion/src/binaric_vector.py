"""Daylight v18 Binaric Vector measurement and verification."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical_json import canonical_sha256, load_json_no_floats, reject_floats_recursive


VERSION = "daylight-v18-binaric-vector-v0.1"
D_BINARIC_VECTOR = "DAYLIGHT-v18-BINARIC-VECTOR:"
D_BASTION_POLICY = "DAYLIGHT-v18-BASTION-POLICY:"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
DEFAULT_EVENT_HORIZON_SCORECARD = REPO_ROOT / "daylight" / "v17-singularity" / "examples" / "expected-scorecard.current.v17.json"

DEFAULT_POLICY = {
    "policy_version": "daylight-v18-bastion-policy-v0.1",
    "host_trust_level": "H0-untrusted-host",
    "mode": "measurement-only",
    "production_allowed": False,
}
DEFAULT_POLICY_DIGEST = canonical_sha256(DEFAULT_POLICY, D_BASTION_POLICY)

REQUIRED_KEYS = {
    "version",
    "subject_kind",
    "subject_path_normalized",
    "file_sha256",
    "file_sha3_512",
    "size_bytes",
    "executable_metadata",
    "section_digests",
    "dependency_digests",
    "event_horizon_scorecard_digest",
    "policy_digest",
    "vector_digest",
}
OPTIONAL_KEYS = {
    "previous_vector_digest",
    "user_verification_digest",
}
ALLOWED_KEYS = REQUIRED_KEYS | OPTIONAL_KEYS
HEX64 = set("0123456789abcdef")
HEX128 = HEX64


class BinaricVectorError(ValueError):
    pass


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise BinaricVectorError(f"{name} must be boolean")
    return value


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BinaricVectorError(f"{name} must be an integer")
    if value < 0:
        raise BinaricVectorError(f"{name} must be nonnegative")
    return value


def _require_digest(value: Any, name: str, *, length: int = 64) -> str:
    if not isinstance(value, str) or len(value) != length:
        raise BinaricVectorError(f"{name} must be lowercase hex digest length {length}")
    allowed = HEX128 if length == 128 else HEX64
    if set(value) - allowed:
        raise BinaricVectorError(f"{name} must be lowercase hex")
    return value


def _normalize_subject_path(path_text: str | Path) -> str:
    path = Path(path_text)
    if path.is_absolute():
        raise BinaricVectorError("subject path must be relative")
    if ".." in path.parts:
        raise BinaricVectorError("subject path must not contain ..")
    normalized = PurePosixPath(path.as_posix())
    if str(normalized) in ("", "."):
        raise BinaricVectorError("subject path must name a file")
    return str(normalized)


def _safe_subject(path_text: str | Path, *, base_dir: Path | str = Path.cwd()) -> tuple[str, Path]:
    normalized = _normalize_subject_path(path_text)
    base = Path(base_dir).resolve()
    candidate = base / normalized
    if candidate.is_symlink():
        raise BinaricVectorError("subject symlink rejected")
    subject = candidate.resolve()
    if subject != base and base not in subject.parents:
        raise BinaricVectorError("subject path escapes base directory")
    if not subject.exists():
        raise BinaricVectorError(f"subject missing: {normalized}")
    if not subject.is_file():
        raise BinaricVectorError("subject must be a regular file")
    return normalized, subject


def _hashes(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.sha3_512(data).hexdigest()


def _scorecard_digest(path: Path | str | None) -> str:
    if path is None:
        path = DEFAULT_EVENT_HORIZON_SCORECARD
    payload = load_json_no_floats(path)
    if isinstance(payload, dict) and isinstance(payload.get("scorecard_digest"), str):
        return _require_digest(payload["scorecard_digest"], "scorecard_digest")
    if isinstance(payload, dict):
        return canonical_sha256(payload, "DAYLIGHT-v18-EVENT-HORIZON-SCORECARD-FILE:")
    raise BinaricVectorError("event horizon scorecard must be a JSON object")


def _file_format(data: bytes) -> str:
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xfe\xed\xfa\xcf"):
        return "macho"
    if data.startswith(b"#!"):
        return "script"
    return "opaque-binary"


def measure_subject(
    *,
    subject_path: Path | str,
    out_path: Path | str | None = None,
    base_dir: Path | str = Path.cwd(),
    event_horizon_scorecard_path: Path | str | None = None,
    policy_digest: str = DEFAULT_POLICY_DIGEST,
    previous_vector_digest: str | None = None,
    user_verification_digest: str | None = None,
) -> dict[str, Any]:
    normalized, subject = _safe_subject(subject_path, base_dir=base_dir)
    _require_digest(policy_digest, "policy_digest")
    if previous_vector_digest is not None:
        _require_digest(previous_vector_digest, "previous_vector_digest")
    if user_verification_digest is not None:
        _require_digest(user_verification_digest, "user_verification_digest")
    data = subject.read_bytes()
    file_sha256, file_sha3_512 = _hashes(data)
    mode = subject.stat().st_mode
    vector = {
        "version": VERSION,
        "subject_kind": "file",
        "subject_path_normalized": normalized,
        "file_sha256": file_sha256,
        "file_sha3_512": file_sha3_512,
        "size_bytes": len(data),
        "executable_metadata": {
            "format": _file_format(data),
            "mode_octal": format(mode & 0o777, "04o"),
            "executable_bit": bool(mode & (stat_exec_bits())),
            "host_trust_level": "H0-untrusted-host",
            "runtime_containment_claim": False,
        },
        "section_digests": [
            {
                "id": "whole_file",
                "offset": 0,
                "size_bytes": len(data),
                "sha256": file_sha256,
                "sha3_512": file_sha3_512,
            }
        ],
        "dependency_digests": [],
        "event_horizon_scorecard_digest": _scorecard_digest(event_horizon_scorecard_path),
        "policy_digest": policy_digest,
    }
    if previous_vector_digest is not None:
        vector["previous_vector_digest"] = previous_vector_digest
    if user_verification_digest is not None:
        vector["user_verification_digest"] = user_verification_digest
    vector["vector_digest"] = vector_digest(vector)
    if out_path is not None:
        from .canonical_json import json_bytes

        Path(out_path).write_bytes(json_bytes(vector))
    return vector


def stat_exec_bits() -> int:
    return 0o111


def vector_digest(vector: dict[str, Any]) -> str:
    reject_floats_recursive(vector, "binaric_vector")
    body = {key: value for key, value in vector.items() if key != "vector_digest"}
    return canonical_sha256(body, D_BINARIC_VECTOR)


def validate_vector_shape(vector: dict[str, Any]) -> None:
    reject_floats_recursive(vector, "binaric_vector")
    if not isinstance(vector, dict):
        raise BinaricVectorError("binaric vector must be an object")
    unknown = set(vector) - ALLOWED_KEYS
    if unknown:
        raise BinaricVectorError(f"unknown critical fields: {sorted(unknown)}")
    missing = REQUIRED_KEYS - set(vector)
    if missing:
        raise BinaricVectorError(f"missing vector fields: {sorted(missing)}")
    if vector["version"] != VERSION:
        raise BinaricVectorError("unsupported binaric vector version")
    if vector["subject_kind"] != "file":
        raise BinaricVectorError("unsupported subject_kind")
    _normalize_subject_path(vector["subject_path_normalized"])
    _require_digest(vector["file_sha256"], "file_sha256")
    _require_digest(vector["file_sha3_512"], "file_sha3_512", length=128)
    _require_int(vector["size_bytes"], "size_bytes")
    _require_digest(vector["event_horizon_scorecard_digest"], "event_horizon_scorecard_digest")
    _require_digest(vector["policy_digest"], "policy_digest")
    if "previous_vector_digest" in vector:
        _require_digest(vector["previous_vector_digest"], "previous_vector_digest")
    if "user_verification_digest" in vector:
        _require_digest(vector["user_verification_digest"], "user_verification_digest")
    metadata = vector["executable_metadata"]
    if not isinstance(metadata, dict):
        raise BinaricVectorError("executable_metadata must be an object")
    for key in ("format", "mode_octal", "host_trust_level"):
        if not isinstance(metadata.get(key), str):
            raise BinaricVectorError(f"executable_metadata.{key} must be string")
    _require_bool(metadata.get("executable_bit"), "executable_metadata.executable_bit")
    _require_bool(metadata.get("runtime_containment_claim"), "executable_metadata.runtime_containment_claim")
    if metadata.get("runtime_containment_claim") is True:
        raise BinaricVectorError("runtime containment claim is not allowed in v18.0 vector")
    sections = vector["section_digests"]
    if not isinstance(sections, list) or not sections:
        raise BinaricVectorError("section_digests must be a non-empty list")
    for index, section in enumerate(sections):
        if not isinstance(section, dict):
            raise BinaricVectorError(f"section_digests[{index}] must be an object")
        if not isinstance(section.get("id"), str) or not section["id"]:
            raise BinaricVectorError(f"section_digests[{index}].id must be string")
        _require_int(section.get("offset"), f"section_digests[{index}].offset")
        _require_int(section.get("size_bytes"), f"section_digests[{index}].size_bytes")
        _require_digest(section.get("sha256"), f"section_digests[{index}].sha256")
        _require_digest(section.get("sha3_512"), f"section_digests[{index}].sha3_512", length=128)
    if not isinstance(vector["dependency_digests"], list):
        raise BinaricVectorError("dependency_digests must be a list")
    for index, dep in enumerate(vector["dependency_digests"]):
        if not isinstance(dep, dict):
            raise BinaricVectorError(f"dependency_digests[{index}] must be an object")
    _require_digest(vector["vector_digest"], "vector_digest")
    if vector_digest(vector) != vector["vector_digest"]:
        raise BinaricVectorError("vector_digest mismatch")


def load_vector(path: Path | str) -> dict[str, Any]:
    vector = load_json_no_floats(path)
    validate_vector_shape(vector)
    return vector


def verify_vector(vector: dict[str, Any], *, base_dir: Path | str = Path.cwd()) -> dict[str, Any]:
    validate_vector_shape(vector)
    normalized, subject = _safe_subject(vector["subject_path_normalized"], base_dir=base_dir)
    data = subject.read_bytes()
    file_sha256, file_sha3_512 = _hashes(data)
    blockers: list[str] = []
    if normalized != vector["subject_path_normalized"]:
        blockers.append("subject path normalization mismatch")
    if len(data) != vector["size_bytes"]:
        blockers.append("size_bytes mismatch")
    if file_sha256 != vector["file_sha256"]:
        blockers.append("file_sha256 mismatch")
    if file_sha3_512 != vector["file_sha3_512"]:
        blockers.append("file_sha3_512 mismatch")
    whole = vector["section_digests"][0]
    if whole.get("id") != "whole_file":
        blockers.append("whole_file section missing")
    else:
        if whole["size_bytes"] != len(data):
            blockers.append("whole_file section size mismatch")
        if whole["sha256"] != file_sha256:
            blockers.append("whole_file section sha256 mismatch")
        if whole["sha3_512"] != file_sha3_512:
            blockers.append("whole_file section sha3_512 mismatch")
    return {
        "verified": not blockers,
        "blockers": blockers,
        "subject_path_normalized": vector["subject_path_normalized"],
        "vector_digest": vector["vector_digest"],
        "file_sha256": vector["file_sha256"],
    }


def verify_vector_file(path: Path | str, *, base_dir: Path | str = Path.cwd()) -> dict[str, Any]:
    return verify_vector(load_vector(path), base_dir=base_dir)


def inspect_vector(path: Path | str) -> dict[str, Any]:
    vector = load_vector(path)
    return {
        "version": vector["version"],
        "subject_kind": vector["subject_kind"],
        "subject_path_normalized": vector["subject_path_normalized"],
        "size_bytes": vector["size_bytes"],
        "file_sha256": vector["file_sha256"],
        "file_sha3_512": vector["file_sha3_512"],
        "executable_metadata": vector["executable_metadata"],
        "event_horizon_scorecard_digest": vector["event_horizon_scorecard_digest"],
        "policy_digest": vector["policy_digest"],
        "previous_vector_digest": vector.get("previous_vector_digest"),
        "user_verification_digest": vector.get("user_verification_digest"),
        "vector_digest": vector["vector_digest"],
        "boundary": {
            "host_clean_claim": False,
            "runtime_containment_claim": False,
            "production_cryptography_claim": False,
            "external_certification_claim": False,
            "whole_system_pq_safety_claim": False,
        },
    }
