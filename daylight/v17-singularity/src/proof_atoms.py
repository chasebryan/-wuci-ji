"""Proof-atom registry verification for the v17.1 Event Horizon kernel."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256, load_json_no_floats, reject_python_floats
from . import registry as field_registry
from .singularity_math import require_nonnegative_int


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROOF_ATOMS_PATH = PACKAGE_ROOT / "rules" / "proof-atoms.v17.json"

PROOF_ATOMS_VERSION = "daylight-v17.1-event-horizon-proof-atoms-v0.1"
EVIDENCE_BUNDLE_VERSION = "daylight-v17.1-event-horizon-proof-evidence-v0.1"
D_PROOF_ATOMS = "DAYLIGHT-v17.1-EVENT-HORIZON-PROOF-ATOMS:"
D_EVIDENCE_RECORD = "DAYLIGHT-v17.1-EVENT-HORIZON-EVIDENCE-RECORD:"

KNOWN_VERIFIERS = {
    "record-valid",
    "record-valid-signed-external",
    "boundary-nonclaim",
    "implementation-agreement",
}

HEX64 = set("0123456789abcdef")


class ProofAtomError(ValueError):
    pass


def _repo_path(path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path
    return REPO_ROOT / path


def evidence_record_digest(record: dict[str, Any]) -> str:
    return canonical_sha256(record, D_EVIDENCE_RECORD)


def load_proof_atom_registry(path: Path | str = DEFAULT_PROOF_ATOMS_PATH) -> dict[str, Any]:
    registry = load_json_no_floats(path)
    validate_proof_atom_registry(registry)
    return registry


def proof_atom_registry_digest(registry: dict[str, Any]) -> str:
    validate_proof_atom_registry(registry)
    return canonical_sha256(registry, D_PROOF_ATOMS)


def validate_proof_atom_registry(registry: dict[str, Any]) -> None:
    reject_python_floats(registry, "proof_atom_registry")
    if registry.get("version") != PROOF_ATOMS_VERSION:
        raise ProofAtomError("unsupported proof-atom registry version")
    atoms = registry.get("proof_atoms")
    if not isinstance(atoms, list) or not atoms:
        raise ProofAtomError("proof-atom registry requires proof_atoms")
    seen: set[str] = set()
    for atom in atoms:
        if not isinstance(atom, dict):
            raise ProofAtomError("proof atom must be an object")
        atom_id = atom.get("id")
        if not isinstance(atom_id, str) or not atom_id:
            raise ProofAtomError("proof atom id must be non-empty")
        if atom_id in seen:
            raise ProofAtomError(f"duplicate proof atom id: {atom_id}")
        seen.add(atom_id)
        if atom.get("field") not in field_registry.FIELD_IDS:
            raise ProofAtomError(f"{atom_id}: unknown field")
        require_nonnegative_int(atom.get("credit"), f"{atom_id}.credit")
        if atom["credit"] <= 0:
            raise ProofAtomError(f"{atom_id}.credit must be positive")
        if atom.get("verifier_command") not in KNOWN_VERIFIERS:
            raise ProofAtomError(f"{atom_id}: missing or unsupported verifier")
        if not isinstance(atom.get("evidence_path"), str) or not atom["evidence_path"]:
            raise ProofAtomError(f"{atom_id}: evidence_path required")
        if (
            not isinstance(atom.get("evidence_digest"), str)
            or len(atom["evidence_digest"]) != 64
            or set(atom["evidence_digest"]) - HEX64
        ):
            raise ProofAtomError(f"{atom_id}: evidence_digest must be sha256 hex")
        if not isinstance(atom.get("replay_required"), bool):
            raise ProofAtomError(f"{atom_id}: replay_required must be boolean")
        stale = require_nonnegative_int(atom.get("stale_after_days"), f"{atom_id}.stale_after_days")
        if stale <= 0:
            raise ProofAtomError(f"{atom_id}.stale_after_days must be positive")
        if not isinstance(atom.get("collapse_if_failed"), bool):
            raise ProofAtomError(f"{atom_id}: collapse_if_failed must be boolean")


def load_evidence_bundle(path: Path | str) -> dict[str, Any]:
    bundle = load_json_no_floats(path)
    reject_python_floats(bundle, "proof_evidence")
    if bundle.get("version") != EVIDENCE_BUNDLE_VERSION:
        raise ProofAtomError("unsupported proof evidence bundle version")
    records = bundle.get("records")
    if not isinstance(records, list):
        raise ProofAtomError("proof evidence bundle records must be a list")
    return bundle


def _record_map(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for record in bundle["records"]:
        if not isinstance(record, dict):
            raise ProofAtomError("evidence record must be an object")
        atom_id = record.get("atom_id")
        if not isinstance(atom_id, str) or not atom_id:
            raise ProofAtomError("evidence record atom_id required")
        if atom_id in out:
            raise ProofAtomError(f"duplicate evidence record for atom: {atom_id}")
        out[atom_id] = record
    return out


def _record_verifies(atom: dict[str, Any], record: dict[str, Any]) -> tuple[bool, str]:
    if evidence_record_digest(record) != atom["evidence_digest"]:
        return False, "evidence_digest_mismatch"
    if record.get("valid") is not True:
        return False, "record_not_valid"
    if int(record.get("age_days", atom["stale_after_days"] + 1)) > int(atom["stale_after_days"]):
        return False, "stale_proof"
    if atom["replay_required"] and record.get("replay", {}).get("valid") is not True:
        return False, "replay_required"
    command = atom["verifier_command"]
    if command == "record-valid":
        return True, "closed"
    if command == "record-valid-signed-external":
        if record.get("signed") is True and record.get("fixture_material_used") is False:
            return True, "closed"
        return False, "external_record_not_signed"
    if command == "boundary-nonclaim":
        boundary = record.get("boundary", {})
        if not isinstance(boundary, dict):
            return False, "boundary_record_missing"
        if any(boundary.get(key) is True for key in (
            "production_allowed",
            "runtime_containment_claim",
            "whole_system_post_quantum_safety_claim",
            "external_certification_claim",
        )):
            return False, "boundary_overclaim"
        return True, "closed"
    if command == "implementation-agreement":
        if record.get("implementation_disagreement") is True:
            return False, "implementation_disagreement"
        families = record.get("families", [])
        if isinstance(families, list) and set(families) >= {"python", "rust", "third"}:
            return True, "closed"
        return False, "implementation_families_incomplete"
    return False, "unsupported_verifier"


def verify_proof_atoms(registry: dict[str, Any]) -> dict[str, Any]:
    validate_proof_atom_registry(registry)
    bundles: dict[str, dict[str, Any]] = {}
    record_maps: dict[str, dict[str, dict[str, Any]]] = {}
    field_possible = {field_id: 0 for field_id in field_registry.FIELD_IDS}
    field_verified = {field_id: 0 for field_id in field_registry.FIELD_IDS}
    atom_results: list[dict[str, Any]] = []
    collapse_reasons: list[str] = []
    for atom in registry["proof_atoms"]:
        field_id = atom["field"]
        field_possible[field_id] += int(atom["credit"])
        evidence_path = atom["evidence_path"]
        path = _repo_path(evidence_path)
        if evidence_path not in bundles:
            try:
                bundles[evidence_path] = load_evidence_bundle(path)
                record_maps[evidence_path] = _record_map(bundles[evidence_path])
            except OSError:
                bundles[evidence_path] = {"version": EVIDENCE_BUNDLE_VERSION, "records": []}
                record_maps[evidence_path] = {}
        record = record_maps[evidence_path].get(atom["id"])
        if record is None:
            closed = False
            reason = "missing_evidence"
        else:
            closed, reason = _record_verifies(atom, record)
        if closed:
            field_verified[field_id] += int(atom["credit"])
        elif atom["collapse_if_failed"]:
            collapse_reasons.append(f"proof_atom_failed:{atom['id']}:{reason}")
        atom_results.append({
            "id": atom["id"],
            "field": field_id,
            "credit": atom["credit"],
            "closed": closed,
            "reason": reason,
            "collapse_if_failed": atom["collapse_if_failed"],
        })
    for field_id, possible in field_possible.items():
        if possible <= 0:
            raise ProofAtomError(f"{field_id}: no proof atoms defined")
    return {
        "proof_atom_registry_digest": proof_atom_registry_digest(registry),
        "field_possible_credit": field_possible,
        "field_verified_credit": field_verified,
        "atom_results": atom_results,
        "collapse_reasons": collapse_reasons,
    }
