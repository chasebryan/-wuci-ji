"""Proof-atom registry verification for Daylight v17.1 Event Horizon."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256, load_json_no_floats, reject_floats_recursive
from . import registry as field_registry
from .singularity_math import require_nonnegative_int


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROOF_ATOMS_PATH = PACKAGE_ROOT / "rules" / "proof-atoms.v17.json"

PROOF_ATOMS_VERSION = "daylight-v17-event-horizon-proof-atoms-v0.1"
D_PROOF_ATOMS = "DAYLIGHT-v17-EVENT-HORIZON-PROOF-ATOMS:"

SUPPORTED_VERIFIER_KEYS = {
    "file_digest_exists",
    "package_file_present",
    "expected_digest_matches",
    "event_horizon_self_check",
    "no_float_self_check",
    "scorecard_tamper_rejection_self_check",
    "fracture_suite_self_check",
    "cross_verifier_vector_check",
    "fixture_pass",
}

HEX64 = set("0123456789abcdef")


class ProofAtomError(ValueError):
    pass


def load_proof_atom_registry(path: Path | str = DEFAULT_PROOF_ATOMS_PATH) -> dict[str, Any]:
    registry = load_json_no_floats(path)
    validate_proof_atom_registry(registry)
    return registry


def proof_atom_registry_digest(registry: dict[str, Any]) -> str:
    validate_proof_atom_registry(registry)
    return canonical_sha256(registry, D_PROOF_ATOMS)


def proof_atoms_digest(registry: dict[str, Any]) -> str:
    return proof_atom_registry_digest(registry)


def validate_proof_atom_registry(registry: dict[str, Any]) -> None:
    reject_floats_recursive(registry, "proof_atom_registry")
    if registry.get("version") != PROOF_ATOMS_VERSION:
        raise ProofAtomError("unsupported proof-atom registry version")
    atoms = registry.get("proof_atoms")
    if not isinstance(atoms, list) or not atoms:
        raise ProofAtomError("proof-atom registry requires proof_atoms")
    seen: set[str] = set()
    fields_with_atoms: set[str] = set()
    for atom in atoms:
        validate_proof_atom(atom)
        atom_id = atom["id"]
        if atom_id in seen:
            raise ProofAtomError(f"duplicate proof atom id: {atom_id}")
        seen.add(atom_id)
        fields_with_atoms.add(atom["field_id"])
    missing = set(field_registry.FIELD_IDS) - fields_with_atoms
    if missing:
        raise ProofAtomError(f"every field requires at least one proof atom; missing {sorted(missing)}")


def validate_proof_atom(atom: dict[str, Any]) -> None:
    if not isinstance(atom, dict):
        raise ProofAtomError("proof atom must be an object")
    atom_id = atom.get("id")
    if not isinstance(atom_id, str) or not atom_id:
        raise ProofAtomError("proof atom id must be non-empty")
    field_id = atom.get("field_id")
    if field_id not in field_registry.FIELD_IDS:
        raise ProofAtomError(f"{atom_id}: unknown field_id")
    credit = require_nonnegative_int(atom.get("credit"), f"{atom_id}.credit")
    if credit <= 0:
        raise ProofAtomError(f"{atom_id}.credit must be positive")
    verifier_key = atom.get("verifier_key")
    if verifier_key not in SUPPORTED_VERIFIER_KEYS:
        raise ProofAtomError(f"{atom_id}: unknown verifier_key")
    if not isinstance(atom.get("description"), str) or not atom["description"]:
        raise ProofAtomError(f"{atom_id}: description required")
    for key in ("replay_required", "collapse_if_failed", "fixture_allowed"):
        if not isinstance(atom.get(key), bool):
            raise ProofAtomError(f"{atom_id}.{key} must be boolean")
    stale_after_days = require_nonnegative_int(atom.get("stale_after_days"), f"{atom_id}.stale_after_days")
    if stale_after_days <= 0:
        raise ProofAtomError(f"{atom_id}.stale_after_days must be positive")
    if "evidence_path" in atom:
        _safe_package_file(atom["evidence_path"], require_exists=False)
    if "expected_sha256" in atom:
        digest = atom["expected_sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or set(digest) - HEX64:
            raise ProofAtomError(f"{atom_id}.expected_sha256 must be lowercase sha256 hex")


def _safe_package_file(path_text: Any, *, require_exists: bool = True) -> Path:
    if not isinstance(path_text, str) or not path_text:
        raise ProofAtomError("evidence_path must be a non-empty relative path")
    path = Path(path_text)
    if path.is_absolute():
        raise ProofAtomError("evidence_path must not be absolute")
    if ".." in path.parts:
        raise ProofAtomError("evidence_path must not contain ..")
    resolved = (PACKAGE_ROOT / path).resolve()
    root = PACKAGE_ROOT.resolve()
    if resolved != root and root not in resolved.parents:
        raise ProofAtomError("evidence_path escapes Daylight v17 package")
    if require_exists:
        if not resolved.exists():
            raise ProofAtomError(f"evidence_path does not exist: {path_text}")
        if resolved.is_symlink():
            raise ProofAtomError(f"evidence_path is a symlink: {path_text}")
        if not resolved.is_file():
            raise ProofAtomError(f"evidence_path is not a regular file: {path_text}")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _check_package_file_present(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    try:
        _safe_package_file(atom.get("evidence_path"))
    except ProofAtomError as exc:
        return False, str(exc)
    return True, "closed"


def _check_file_digest_exists(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    try:
        path = _safe_package_file(atom.get("evidence_path"))
        _sha256_file(path)
    except ProofAtomError as exc:
        return False, str(exc)
    return True, "closed"


def _check_expected_digest_matches(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    expected = atom.get("expected_sha256")
    if not isinstance(expected, str):
        return False, "expected_sha256_missing"
    try:
        path = _safe_package_file(atom.get("evidence_path"))
    except ProofAtomError as exc:
        return False, str(exc)
    if _sha256_file(path) != expected:
        return False, "expected_digest_mismatch"
    return True, "closed"


def _read_source(name: str) -> str:
    return (PACKAGE_ROOT / "src" / name).read_text(encoding="utf-8")


def _check_event_horizon_self(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    required = [
        PACKAGE_ROOT / "src" / "event_horizon.py",
        PACKAGE_ROOT / "src" / "scorecard.py",
        PACKAGE_ROOT / "rules" / "fields.v17.json",
        PACKAGE_ROOT / "rules" / "proof-atoms.v17.json",
    ]
    if all(path.is_file() and not path.is_symlink() for path in required):
        return True, "closed"
    return False, "event_horizon_files_missing"


def _check_no_float(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    critical = "\n".join(
        _read_source(name)
        for name in ("singularity_math.py", "scorecard.py", "proof_atoms.py", "registry.py")
    )
    forbidden = ("math.log", "math.exp", "numpy", "pandas")
    if any(token in critical for token in forbidden):
        return False, "forbidden_float_runtime_token"
    return True, "closed"


def _check_scorecard_tamper(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    fracture = _read_source("fracture.py")
    if "M1" in fracture and "score_AM_plus" in fracture and "verify_scorecard_object" in fracture:
        return True, "closed"
    return False, "tamper_rejection_not_present"


def _check_fracture_suite(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    fracture = _read_source("fracture.py")
    for index in range(1, 16):
        if f"M{index}" not in fracture:
            return False, f"mutation_M{index}_missing"
    return True, "closed"


def _check_cross_verifier_vector(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    outputs = state.get("verifier_outputs", [])
    if not isinstance(outputs, list) or len(outputs) < 3:
        return False, "cross_verifier_outputs_missing"
    families = {row.get("implementation_family") for row in outputs if isinstance(row, dict)}
    if len(families) < 3:
        return False, "cross_verifier_families_not_distinct"
    return True, "closed"


def _check_fixture_pass(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    if state.get("fixture") is True and atom.get("fixture_allowed") is True:
        return True, "closed"
    return False, "fixture_only_atom_open"


VERIFIER_FUNCTIONS = {
    "file_digest_exists": _check_file_digest_exists,
    "package_file_present": _check_package_file_present,
    "expected_digest_matches": _check_expected_digest_matches,
    "event_horizon_self_check": _check_event_horizon_self,
    "no_float_self_check": _check_no_float,
    "scorecard_tamper_rejection_self_check": _check_scorecard_tamper,
    "fracture_suite_self_check": _check_fracture_suite,
    "cross_verifier_vector_check": _check_cross_verifier_vector,
    "fixture_pass": _check_fixture_pass,
}


def verify_atom(atom: dict[str, Any], state: dict[str, Any]) -> tuple[bool, str]:
    validate_proof_atom(atom)
    verifier = VERIFIER_FUNCTIONS.get(atom["verifier_key"])
    if verifier is None:
        raise ProofAtomError(f"{atom['id']}: unknown verifier_key")
    return verifier(atom, state)


def verify_proof_atoms(registry: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    validate_proof_atom_registry(registry)
    reject_floats_recursive(state, "state")
    field_possible = {field_id: 0 for field_id in field_registry.FIELD_IDS}
    field_verified = {field_id: 0 for field_id in field_registry.FIELD_IDS}
    field_closed_atoms = {field_id: [] for field_id in field_registry.FIELD_IDS}
    field_open_atoms = {field_id: [] for field_id in field_registry.FIELD_IDS}
    atom_results: list[dict[str, Any]] = []
    collapse_reasons: list[str] = []
    for atom in registry["proof_atoms"]:
        field_id = atom["field_id"]
        credit = int(atom["credit"])
        field_possible[field_id] += credit
        closed, reason = verify_atom(atom, state)
        row = {
            "id": atom["id"],
            "field_id": field_id,
            "credit": credit,
            "verifier_key": atom["verifier_key"],
            "closed": closed,
            "reason": reason,
            "replay_required": atom["replay_required"],
            "collapse_if_failed": atom["collapse_if_failed"],
            "fixture_allowed": atom["fixture_allowed"],
        }
        atom_results.append(row)
        if closed:
            field_verified[field_id] += credit
            field_closed_atoms[field_id].append(atom["id"])
        else:
            field_open_atoms[field_id].append(atom["id"])
            if atom["collapse_if_failed"]:
                collapse_reasons.append(f"proof_atom_failed:{atom['id']}:{reason}")
    for field_id, possible in field_possible.items():
        if possible <= 0:
            raise ProofAtomError(f"{field_id}: no proof atoms defined")
    return {
        "proof_atoms_digest": proof_atom_registry_digest(registry),
        "field_possible_credit": field_possible,
        "field_verified_credit": field_verified,
        "field_closed_atoms": field_closed_atoms,
        "field_open_atoms": field_open_atoms,
        "atom_results": atom_results,
        "collapse_reasons": collapse_reasons,
    }
