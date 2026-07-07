"""Obligation registry and evidence-derived q-value resolution for Daylight v15+ Solstice.

In Daylight v14C+ each q-value was an asserted ``target`` constant, gated only by
the *presence* of required evidence types. That left a manual-score loophole: a
reviewer could inflate every target to ``1000/1000`` with the same evidence and the
harness would emit a perfect score.

Meridian removes the loophole. Every q-value is *derived*:

    q_i = (sum of weights of closed obligations in dimension i) / 1000

An obligation is closed only by a witnessed, transcript-bound evidence item that
names the obligation id in ``closes_obligations``. Editing a number closes nothing;
only evidence moves the score. ``external`` obligations are closeable only by an
``external_attestation`` whose ``external_signer_id`` differs from the harness
identity, so the harness cannot self-certify the external frontier.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable

from .canonical_json import canonical_sha256, load_json_file_no_duplicates


REGISTRY_VERSION = "daylight-v15-solstice-obligations-v0.1"
REGISTRY_DOMAIN = "DAYLIGHT-v15-SOLSTICE-OBLIGATIONS:"
DIMENSION_THOUSANDTHS = 1000

Q_IDS = (
    "q1_doctrine_master_law",
    "q2_formalism_mathematical_density",
    "q3_negative_evidence_subtractive_capability",
    "q4_gate_algebra_fail_closed_enforcement",
    "q5_evidence_sheaf_release_engineering",
    "q6_surface_closure_boundary_semantics",
    "q7_adversarial_survival_model",
    "q8_cryptographic_number_theoretic_margin",
    "q9_statistical_confidence_reproducibility",
    "q10_implementation_traceability",
    "q11_external_falsification_readiness",
    "q12_communication_overall",
)
VALID_SCOPES = {"internal", "external"}
VALID_EVIDENCE_KINDS = {"ledger", "corpus"}
EXTERNAL_EVIDENCE_CLASS = "external_attestation"


class ObligationError(ValueError):
    pass


def _require_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ObligationError(f"{where} must be an integer weight (no floats), got {value!r}")
    return value


def load_registry(path: Path) -> dict[str, Any]:
    data = load_json_file_no_duplicates(path, "Solstice obligation registry")
    if data.get("version") != REGISTRY_VERSION:
        raise ObligationError("unsupported obligation registry version")
    if not data.get("harness_identity"):
        raise ObligationError("obligation registry missing harness_identity")
    if data.get("scale") != "thousandths":
        raise ObligationError("obligation registry scale must be thousandths")
    dimensions = data.get("dimensions")
    if not isinstance(dimensions, dict):
        raise ObligationError("obligation registry missing dimensions")
    if tuple(dimensions.keys()) != Q_IDS:
        raise ObligationError("obligation registry dimensions must match the canonical q-id order")
    seen_ids: set[str] = set()
    for q_id in Q_IDS:
        spec = dimensions[q_id]
        obligations = spec.get("obligations")
        if not isinstance(obligations, list) or not obligations:
            raise ObligationError(f"{q_id}: obligations must be a non-empty list")
        total = 0
        for obligation in obligations:
            ob_id = obligation.get("id")
            if not isinstance(ob_id, str) or not ob_id:
                raise ObligationError(f"{q_id}: obligation id must be a non-empty string")
            if ob_id in seen_ids:
                raise ObligationError(f"duplicate obligation id: {ob_id}")
            seen_ids.add(ob_id)
            weight = _require_int(obligation.get("weight"), f"{ob_id}.weight")
            if weight <= 0:
                raise ObligationError(f"{ob_id}: weight must be positive")
            total += weight
            scope = obligation.get("scope")
            if scope not in VALID_SCOPES:
                raise ObligationError(f"{ob_id}: scope must be one of {sorted(VALID_SCOPES)}")
            kind = obligation.get("evidence_kind")
            if kind not in VALID_EVIDENCE_KINDS:
                raise ObligationError(f"{ob_id}: evidence_kind must be one of {sorted(VALID_EVIDENCE_KINDS)}")
            evidence_class = obligation.get("evidence_class")
            if not isinstance(evidence_class, str) or not evidence_class:
                raise ObligationError(f"{ob_id}: evidence_class must be a non-empty string")
            if scope == "external":
                if kind != "ledger" or evidence_class != EXTERNAL_EVIDENCE_CLASS:
                    raise ObligationError(
                        f"{ob_id}: external obligations must be closed by ledger external_attestation evidence"
                    )
                external_role = obligation.get("external_role")
                if not isinstance(external_role, str) or not external_role:
                    raise ObligationError(f"{ob_id}: external obligations must name external_role")
        if total != DIMENSION_THOUSANDTHS:
            raise ObligationError(f"{q_id}: obligation weights must sum to 1000, got {total}")
    return data


def registry_digest(registry: dict[str, Any]) -> str:
    return canonical_sha256(registry, REGISTRY_DOMAIN)


def iter_obligations(registry: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for q_id in Q_IDS:
        for obligation in registry["dimensions"][q_id]["obligations"]:
            yield q_id, obligation


def labels(registry: dict[str, Any]) -> dict[str, str]:
    return {q_id: registry["dimensions"][q_id]["label"] for q_id in Q_IDS}


def internal_ceiling_q_vector(registry: dict[str, Any]) -> list[tuple[str, Fraction]]:
    """The q-vector when every internal obligation is closed and every external one stays open."""
    closed = {
        obligation["id"]
        for _, obligation in iter_obligations(registry)
        if obligation["scope"] == "internal"
    }
    return derive_q_vector(registry, closed)


def perfect_q_vector(registry: dict[str, Any]) -> list[tuple[str, Fraction]]:
    closed = {obligation["id"] for _, obligation in iter_obligations(registry)}
    return derive_q_vector(registry, closed)


def derive_q_vector(registry: dict[str, Any], closed_ids: Iterable[str]) -> list[tuple[str, Fraction]]:
    """q_i = (sum of closed-obligation weights in dimension i) / 1000."""
    closed = set(closed_ids)
    known = {obligation["id"] for _, obligation in iter_obligations(registry)}
    unknown = sorted(closed - known)
    if unknown:
        raise ObligationError(f"unknown obligation ids cannot contribute to a score: {', '.join(unknown)}")
    result: list[tuple[str, Fraction]] = []
    for q_id in Q_IDS:
        earned = 0
        for obligation in registry["dimensions"][q_id]["obligations"]:
            if obligation["id"] in closed:
                earned += int(obligation["weight"])
        result.append((q_id, Fraction(earned, DIMENSION_THOUSANDTHS)))
    return result


def _names_obligation(record: dict[str, Any], obligation_id: str) -> bool:
    closes = record.get("closes_obligations", [])
    return isinstance(closes, list) and obligation_id in closes


def resolve_closed_obligations(
    registry: dict[str, Any],
    ledger_entries: list[dict[str, Any]],
    corpus_snapshot: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return {obligation_id: closing-evidence record} for every closed obligation.

    Fail-closed: a self-signed external attestation (signer absent or equal to the
    harness identity) that names an external obligation is refused outright, because
    that is an attempt to manufacture the external frontier from inside.
    """
    harness_identity = registry["harness_identity"]
    corpus_entries = list(corpus_snapshot.get("entries", []))

    # Refuse self-signed external attestations up front (no silent skipping).
    external_ids = {
        obligation["id"]
        for _, obligation in iter_obligations(registry)
        if obligation["scope"] == "external"
    }
    for entry in ledger_entries:
        if entry.get("entry_type") != EXTERNAL_EVIDENCE_CLASS:
            continue
        named_external = [oid for oid in entry.get("closes_obligations", []) if oid in external_ids]
        if not named_external:
            continue
        signer = entry.get("external_signer_id")
        if not signer or signer == harness_identity:
            raise ObligationError(
                "external attestation cannot be self-signed by the harness: "
                f"{entry.get('entry_id')} names {sorted(named_external)}"
            )

    closed: dict[str, dict[str, Any]] = {}
    for q_id, obligation in iter_obligations(registry):
        ob_id = obligation["id"]
        evidence_class = obligation["evidence_class"]
        if obligation["evidence_kind"] == "ledger":
            candidates = [
                entry
                for entry in ledger_entries
                if entry.get("entry_type") == evidence_class and _names_obligation(entry, ob_id)
            ]
            if obligation["scope"] == "external":
                candidates = [
                    entry
                    for entry in candidates
                    if entry.get("external_signer_id") and entry.get("external_signer_id") != harness_identity
                ]
            key = "artifact_digest"
        else:
            candidates = [
                entry
                for entry in corpus_entries
                if entry.get("category") == evidence_class and _names_obligation(entry, ob_id)
            ]
            key = "input_digest"
        if not candidates:
            continue
        winner = sorted(candidates, key=lambda item: str(item.get(key, "")))[0]
        closed[ob_id] = {
            "obligation_id": ob_id,
            "q_id": q_id,
            "scope": obligation["scope"],
            "weight": int(obligation["weight"]),
            "evidence_kind": obligation["evidence_kind"],
            "evidence_class": evidence_class,
            "evidence_digest": str(winner.get(key, "")),
        }
    return closed
