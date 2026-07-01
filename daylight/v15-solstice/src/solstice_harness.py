"""Hermetic Daylight v15+ Solstice scorecard generation and verification."""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256
from . import corpus as corpus_model
from . import external_attestation
from . import ledger as ledger_model
from . import obligations as obligation_model
from . import scoring
from . import semantic_evidence


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
DEFAULT_OBLIGATIONS = PACKAGE_ROOT / "rules" / "obligations.v15.json"
DEFAULT_ROOTSET = PACKAGE_ROOT / "rules" / "external-rootset.solstice.json"

VERSION = "daylight-v15-solstice-v0.1"
SCORE_BODY_VERSION = "daylight-v15-solstice-score-body-v0.1"
RECEIPT_VERSION = "daylight-v15-solstice-receipt-v0.1"
SCORECARD_VERSION = "daylight-v15-solstice-scorecard-v0.1"
RESOLUTION_VERSION = "daylight-v15-solstice-resolution-v0.1"
PERFECT_SCORE_M = scoring.M_SCALE
FIXED_CREATED_AT = "2026-07-01T00:00:00Z"
CANDIDATE_LABEL = "DAYLIGHT v15+ SOLSTICE HERMETIC FRONTIER"

D_OBLIGATIONS = "DAYLIGHT-v15-SOLSTICE-OBLIGATIONS:"
D_WEIGHTS = "DAYLIGHT-v15-SOLSTICE-WEIGHTS:"
D_RESOLUTION = "DAYLIGHT-v15-SOLSTICE-RESOLUTION:"
D_SCORE_BODY = "DAYLIGHT-v15-SOLSTICE-SCORE-BODY:"
D_RECEIPT = "DAYLIGHT-v15-SOLSTICE-RECEIPT:"
D_SCORECARD = "DAYLIGHT-v15-SOLSTICE-SCORECARD:"
D_LEDGER_ENTRY = "DAYLIGHT-v15-SOLSTICE-LEDGER-ENTRY:"


class SolsticeError(ValueError):
    pass


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _obligations_digest(registry: dict[str, Any]) -> str:
    return canonical_sha256(registry, D_OBLIGATIONS)


def _load_weights(path: Path) -> tuple[dict[str, Any], list[tuple[str, Fraction]], str]:
    document = _load_json(path)
    scoring.reject_float(document, "weights")
    weights = scoring.load_weights(path)
    if [name for name, _ in weights] != list(obligation_model.Q_IDS):
        raise SolsticeError("weight vector dimensions must match the canonical q-id order")
    return document, weights, canonical_sha256(document, D_WEIGHTS)


def _q_text_vector(q_vector: list[tuple[str, Fraction]]) -> list[list[str]]:
    return [[name, scoring.fraction_text(value)] for name, value in q_vector]


def _known_obligations(registry: dict[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    return {ob["id"]: (q_id, ob) for q_id, ob in obligation_model.iter_obligations(registry)}


def validate_corpus_semantics(
    corpus_entries: list[dict[str, Any]],
    ledger_entries: list[dict[str, Any]],
    registry: dict[str, Any],
) -> None:
    known = _known_obligations(registry)
    closeable_corpus = {
        ob_id
        for ob_id, (_, obligation) in known.items()
        if obligation.get("evidence_kind") == "corpus"
    }
    ledger_ids = {entry.get("entry_id") for entry in ledger_entries}
    seen: set[str] = set()
    for entry in corpus_entries:
        entry_id = entry.get("corpus_entry_id")
        if entry_id in seen:
            raise SolsticeError(f"duplicate corpus entry id: {entry_id}")
        seen.add(str(entry_id))
        if entry.get("linked_ledger_entry") not in ledger_ids:
            raise SolsticeError(f"corpus entry links missing ledger entry: {entry_id}")
        closes = entry.get("closes_obligations", [])
        if not isinstance(closes, list):
            raise SolsticeError("corpus closes_obligations must be a list")
        unknown = [oid for oid in closes if oid not in closeable_corpus]
        if unknown:
            raise SolsticeError(f"corpus entry names non-corpus-closeable obligations: {', '.join(unknown)}")
        if closes:
            if not entry.get("replay_command") or not entry.get("expected_stage"):
                raise SolsticeError(f"score-closing corpus entry is not replay-bound: {entry_id}")
            if not semantic_evidence.is_hex_sha256(entry.get("result_digest")):
                raise SolsticeError(f"score-closing corpus entry result_digest is invalid: {entry_id}")


def _open_row(q_id: str, obligation: dict[str, Any]) -> dict[str, Any]:
    row = {
        "obligation_id": obligation["id"],
        "q_id": q_id,
        "scope": obligation["scope"],
        "weight": int(obligation["weight"]),
        "evidence_kind": obligation["evidence_kind"],
        "evidence_class": obligation["evidence_class"],
    }
    if obligation.get("external_role"):
        row["external_role"] = obligation["external_role"]
    return row


def _ledger_closed_row(q_id: str, obligation: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    row = _open_row(q_id, obligation)
    row["evidence_digest"] = str(entry.get("artifact_digest", ""))
    row["semantic_verifier_digest"] = semantic_evidence.semantic_verifier_digest(obligation["evidence_class"])
    return row


def _corpus_closed_row(q_id: str, obligation: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    row = _open_row(q_id, obligation)
    row["evidence_digest"] = str(entry.get("input_digest", ""))
    row["semantic_verifier_digest"] = semantic_evidence.semantic_verifier_digest(obligation["evidence_class"])
    return row


def _external_closed_row(
    q_id: str,
    obligation: dict[str, Any],
    attestations: list[dict[str, Any]],
) -> dict[str, Any]:
    row = _open_row(q_id, obligation)
    row["evidence_digest"] = external_attestation.attestation_set_digest(attestations)
    row["semantic_verifier_digest"] = semantic_evidence.semantic_verifier_digest("external_attestation")
    row["attestation_set_digest"] = external_attestation.attestation_set_digest(attestations)
    return row


def resolve_closed_obligations(
    registry: dict[str, Any],
    ledger_entries: list[dict[str, Any]],
    corpus_snapshot: dict[str, Any],
    rootset: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    harness_identity = registry["harness_identity"]
    corpus_entries = list(corpus_snapshot.get("entries", []))
    ledger_by_id = {entry.get("entry_id"): entry for entry in ledger_entries}
    closed: dict[str, dict[str, Any]] = {}

    for q_id, obligation in obligation_model.iter_obligations(registry):
        ob_id = obligation["id"]
        evidence_class = obligation["evidence_class"]
        if obligation["scope"] == "external":
            attestations = external_attestation.closing_attestation_set(
                obligation,
                ledger_entries,
                rootset,
                harness_identity,
            )
            if attestations:
                closed[ob_id] = _external_closed_row(q_id, obligation, attestations)
            continue

        if obligation["evidence_kind"] == "ledger":
            candidates = []
            for entry in ledger_entries:
                projection = semantic_evidence.ledger_projection(entry)
                if entry.get("entry_type") == evidence_class and semantic_evidence.semantic_evidence_valid(obligation, projection):
                    candidates.append(entry)
            if candidates:
                winner = sorted(candidates, key=lambda item: str(item.get("artifact_digest", "")))[0]
                closed[ob_id] = _ledger_closed_row(q_id, obligation, winner)
        elif obligation["evidence_kind"] == "corpus":
            candidates = []
            for entry in corpus_entries:
                linked = ledger_by_id.get(entry.get("linked_ledger_entry"))
                projection = semantic_evidence.corpus_projection(entry, linked)
                if entry.get("category") == evidence_class and semantic_evidence.semantic_evidence_valid(obligation, projection):
                    candidates.append(entry)
            if candidates:
                winner = sorted(candidates, key=lambda item: str(item.get("input_digest", "")))[0]
                closed[ob_id] = _corpus_closed_row(q_id, obligation, winner)
    return closed


def _frontier_contribution_M(weight_by_q: dict[str, Fraction], q_id: str, obligation_weight: int) -> int:
    term = Fraction(PERFECT_SCORE_M, 1) * weight_by_q[q_id] * Fraction(obligation_weight, obligation_model.DIMENSION_THOUSANDTHS)
    if term.denominator != 1:
        raise SolsticeError(f"frontier contribution for {q_id} is not an integer M value")
    return term.numerator


def _residue_values(
    registry: dict[str, Any],
    weights: list[tuple[str, Fraction]],
    closed_ids: set[str],
) -> tuple[int, int, int, int]:
    weight_by_q = dict(weights)
    open_internal = 0
    open_external = 0
    external_ceiling = 0
    for q_id, obligation in obligation_model.iter_obligations(registry):
        contribution = _frontier_contribution_M(weight_by_q, q_id, int(obligation["weight"]))
        if obligation["scope"] == "external":
            external_ceiling += contribution
        if obligation["id"] in closed_ids:
            continue
        if obligation["scope"] == "external":
            open_external += contribution
        else:
            open_internal += contribution
    internal_score = scoring.compute_score(
        obligation_model.internal_ceiling_q_vector(registry),
        weights,
        obligation_model.labels(registry),
    )["final_score_M"]
    return open_internal, open_external, internal_score, external_ceiling


def build_resolution(
    *,
    registry: dict[str, Any],
    weights_digest: str,
    obligations_digest: str,
    input_ledger_head: str,
    corpus_snapshot_digest: str,
    rootset_digest: str | None,
    closed: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    closed_ids = set(closed)
    open_rows = [
        _open_row(q_id, obligation)
        for q_id, obligation in obligation_model.iter_obligations(registry)
        if obligation["id"] not in closed_ids
    ]
    return {
        "resolution_version": RESOLUTION_VERSION,
        "obligations_digest": obligations_digest,
        "weight_vector_digest": weights_digest,
        "input_ledger_head": input_ledger_head,
        "corpus_snapshot_digest": corpus_snapshot_digest,
        "external_rootset_digest": rootset_digest,
        "closed_obligations": sorted(closed.values(), key=lambda row: row["obligation_id"]),
        "open_obligations": sorted(open_rows, key=lambda row: row["obligation_id"]),
    }


def resolution_digest(resolution: dict[str, Any]) -> str:
    return canonical_sha256(resolution, D_RESOLUTION)


def _status_for(final_score_M: int, open_internal_residue_M: int, open_external_residue_M: int, external_ceiling_M: int) -> str:
    if open_internal_residue_M > 0:
        return "solstice_partial_internal_evidence"
    if final_score_M == PERFECT_SCORE_M and open_external_residue_M == 0:
        return "solstice_perfect_external_closed"
    if open_external_residue_M == external_ceiling_M:
        return "solstice_internal_ceiling_external_frontier_open"
    if 0 < open_external_residue_M < external_ceiling_M:
        return "solstice_external_partially_closed"
    return "solstice_rejected"


def build_score_body(
    *,
    registry: dict[str, Any],
    weights: list[tuple[str, Fraction]],
    obligations_digest: str,
    weights_digest: str,
    input_ledger_head: str,
    corpus_snapshot_digest: str,
    rootset_digest: str | None,
    resolution: dict[str, Any],
    resolution_digest_value: str,
) -> dict[str, Any]:
    closed_ids = {row["obligation_id"] for row in resolution["closed_obligations"]}
    q_vector = obligation_model.derive_q_vector(registry, closed_ids)
    score = scoring.compute_score(q_vector, weights, obligation_model.labels(registry))
    final_score_M = score["final_score_M"]
    residue_M = PERFECT_SCORE_M - final_score_M
    open_internal, open_external, internal_ceiling, external_ceiling = _residue_values(registry, weights, closed_ids)
    if residue_M != open_internal + open_external:
        raise SolsticeError("residue does not match open obligation frontier")
    return {
        "score_body_version": SCORE_BODY_VERSION,
        "obligations_version": registry["version"],
        "obligations_digest": obligations_digest,
        "weight_vector_ref": "daylight-v13-weight-vector",
        "weight_vector_digest": weights_digest,
        "input_ledger_head": input_ledger_head,
        "corpus_snapshot_digest": corpus_snapshot_digest,
        "external_rootset_digest": rootset_digest,
        "evidence_resolution_digest": resolution_digest_value,
        "q_vector": score["q_vector"],
        "term_contributions_M": score["term_contributions_M"],
        "unified_score_rational": score["unified_score_rational"],
        "unified_score_decimal": score["unified_score_decimal"],
        "final_score_M": final_score_M,
        "perfect_score_M": PERFECT_SCORE_M,
        "residue_to_perfect_M": residue_M,
        "open_internal_residue_M": open_internal,
        "open_external_residue_M": open_external,
        "internal_ceiling_M": internal_ceiling,
        "external_residue_M": external_ceiling,
        "closed_obligations": resolution["closed_obligations"],
        "open_obligations": resolution["open_obligations"],
        "claim_boundary": {
            "production_allowed": False,
            "runtime_containment_claim": False,
            "whole_system_post_quantum_safety_claim": False,
            "external_certification_claim": False,
        },
    }


def score_body_digest(score_body: dict[str, Any]) -> str:
    return canonical_sha256(score_body, D_SCORE_BODY)


def build_receipt(
    *,
    score_body_digest_value: str,
    input_ledger_head: str,
    corpus_snapshot_digest: str,
    obligations_digest: str,
    weights_digest: str,
    rootset_digest: str | None,
    command: str,
) -> dict[str, Any]:
    return {
        "receipt_version": RECEIPT_VERSION,
        "score_body_digest": score_body_digest_value,
        "input_ledger_head": input_ledger_head,
        "corpus_snapshot_digest": corpus_snapshot_digest,
        "obligations_digest": obligations_digest,
        "weight_vector_digest": weights_digest,
        "external_rootset_digest": rootset_digest,
        "command": command,
        "environment_digest": canonical_sha256({"python": "stdlib", "math": "fractions.Fraction"}, D_RECEIPT),
        "source_digest": canonical_sha256({"package": "daylight/v15-solstice", "version": VERSION}, D_RECEIPT),
        "harness_digest": canonical_sha256({"harness": "src.solstice_harness.generate_scorecard"}, D_RECEIPT),
        "created_at_utc": FIXED_CREATED_AT,
        "result": "pass",
    }


def receipt_digest(receipt: dict[str, Any]) -> str:
    return canonical_sha256(receipt, D_RECEIPT)


def build_score_entry(
    ledger_entries: list[dict[str, Any]],
    *,
    score_body_digest_value: str,
    receipt_digest_value: str,
    input_ledger_head: str,
    corpus_snapshot_digest: str,
    obligations_digest: str,
    weights_digest: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    scorecard_entries, output_head = ledger_model.append_entry(
        ledger_entries,
        entry_type="scorecard",
        artifact_digest=score_body_digest_value,
        witness={"witness_type": "solstice_generated_scorecard", "witness_digest": receipt_digest_value},
        transcript_digest=canonical_sha256(
            {
                "score_body_digest": score_body_digest_value,
                "receipt_digest": receipt_digest_value,
                "input_ledger_head": input_ledger_head,
                "corpus_snapshot_digest": corpus_snapshot_digest,
                "obligations_digest": obligations_digest,
                "weight_vector_digest": weights_digest,
            },
            D_LEDGER_ENTRY,
        ),
        evidence_binding=corpus_snapshot_digest,
        timestamp_utc=FIXED_CREATED_AT,
        entry_id="ledger-entry-scorecard-v15-solstice-v0.1",
    )
    return scorecard_entries[-1], scorecard_entries, output_head


def scorecard_digest(scorecard: dict[str, Any]) -> str:
    # ``artifact_manifest_digest`` is intentionally excluded to avoid a
    # scorecard <-> manifest hash cycle. Artifact verification binds it.
    payload = {
        key: value
        for key, value in scorecard.items()
        if key not in {"scorecard_digest", "artifact_manifest_digest"}
    }
    return canonical_sha256(payload, D_SCORECARD)


def generate_scorecard(
    *,
    ledger_path: Path,
    corpus_path: Path,
    weights_path: Path = DEFAULT_WEIGHTS,
    obligations_path: Path = DEFAULT_OBLIGATIONS,
    rootset_path: Path | None = DEFAULT_ROOTSET,
    command: str,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    ledger_entries, input_head = ledger_model.frozen_head(ledger_path)
    corpus_entries_before = corpus_model.load_jsonl(corpus_path)
    registry = obligation_model.load_registry(obligations_path)
    validate_corpus_semantics(corpus_entries_before, ledger_entries, registry)
    corpus_snapshot = corpus_model.freeze_corpus(corpus_entries_before)
    corpus_digest = corpus_snapshot["corpus_snapshot_digest"]
    _, weights, weights_digest = _load_weights(weights_path)
    obligations_digest = _obligations_digest(registry)
    rootset = external_attestation.load_rootset(rootset_path) if rootset_path else None
    rootset_digest = external_attestation.rootset_digest(rootset)

    closed = resolve_closed_obligations(registry, ledger_entries, corpus_snapshot, rootset)
    resolution = build_resolution(
        registry=registry,
        weights_digest=weights_digest,
        obligations_digest=obligations_digest,
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        rootset_digest=rootset_digest,
        closed=closed,
    )
    resolution_digest_value = resolution_digest(resolution)
    score_body = build_score_body(
        registry=registry,
        weights=weights,
        obligations_digest=obligations_digest,
        weights_digest=weights_digest,
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        rootset_digest=rootset_digest,
        resolution=resolution,
        resolution_digest_value=resolution_digest_value,
    )
    body_digest = score_body_digest(score_body)
    receipt = build_receipt(
        score_body_digest_value=body_digest,
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        obligations_digest=obligations_digest,
        weights_digest=weights_digest,
        rootset_digest=rootset_digest,
        command=command,
    )
    receipt_hash = receipt_digest(receipt)
    score_entry, output_ledger, output_head = build_score_entry(
        ledger_entries,
        score_body_digest_value=body_digest,
        receipt_digest_value=receipt_hash,
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        obligations_digest=obligations_digest,
        weights_digest=weights_digest,
    )
    status = _status_for(
        score_body["final_score_M"],
        score_body["open_internal_residue_M"],
        score_body["open_external_residue_M"],
        score_body["external_residue_M"],
    )
    scorecard = {
        "scorecard_version": SCORECARD_VERSION,
        "candidate": CANDIDATE_LABEL,
        "status": status,
        "generated": True,
        "manual_override": False,
        "manual_edit_allowed": False,
        "score_body": score_body,
        "score_body_digest": body_digest,
        "reproducibility_receipt_digest": receipt_hash,
        "score_entry_digest": score_entry["entry_digest"],
        "input_ledger_head": input_head,
        "output_ledger_head": output_head,
        "artifact_manifest_digest": None,
        "scorecard_digest": "",
    }
    scoring.reject_float(scorecard, "scorecard")
    scorecard["scorecard_digest"] = scorecard_digest(scorecard)
    after_snapshot = corpus_model.freeze_corpus(corpus_model.load_jsonl(corpus_path))
    if after_snapshot["corpus_snapshot_digest"] != corpus_digest:
        raise SolsticeError("corpus mutation during scoring is forbidden")
    return scorecard, receipt, output_ledger


def verify_scorecard(
    scorecard: dict[str, Any],
    *,
    ledger_path: Path,
    corpus_path: Path,
    output_ledger_path: Path,
    weights_path: Path = DEFAULT_WEIGHTS,
    obligations_path: Path = DEFAULT_OBLIGATIONS,
    rootset_path: Path | None = DEFAULT_ROOTSET,
    receipt: dict[str, Any] | None = None,
) -> None:
    scoring.reject_float(scorecard, "scorecard")
    if scorecard.get("manual_edit_allowed") is not False or scorecard.get("manual_override") is not False:
        raise SolsticeError("manual score editing is not allowed")
    if scorecard.get("scorecard_version") != SCORECARD_VERSION:
        raise SolsticeError("unsupported scorecard version")

    ledger_entries, input_head = ledger_model.frozen_head(ledger_path)
    output_ledger = ledger_model.load_jsonl(output_ledger_path)
    corpus_entries = corpus_model.load_jsonl(corpus_path)
    registry = obligation_model.load_registry(obligations_path)
    validate_corpus_semantics(corpus_entries, ledger_entries, registry)
    corpus_snapshot = corpus_model.freeze_corpus(corpus_entries)
    corpus_digest = corpus_snapshot["corpus_snapshot_digest"]
    _, weights, weights_digest = _load_weights(weights_path)
    obligations_digest = _obligations_digest(registry)
    rootset = external_attestation.load_rootset(rootset_path) if rootset_path else None
    rootset_digest = external_attestation.rootset_digest(rootset)

    if input_head != scorecard.get("input_ledger_head"):
        raise SolsticeError("input ledger head mismatch")
    body = scorecard.get("score_body")
    if not isinstance(body, dict):
        raise SolsticeError("scorecard missing score_body")
    if body.get("obligations_digest") != obligations_digest:
        raise SolsticeError("obligation registry digest mismatch")
    if body.get("weight_vector_digest") != weights_digest:
        raise SolsticeError("weight vector digest mismatch")
    if body.get("corpus_snapshot_digest") != corpus_digest:
        raise SolsticeError("corpus snapshot digest mismatch")
    if body.get("external_rootset_digest") != rootset_digest:
        raise SolsticeError("external rootset digest mismatch")

    closed = resolve_closed_obligations(registry, ledger_entries, corpus_snapshot, rootset)
    resolution = build_resolution(
        registry=registry,
        weights_digest=weights_digest,
        obligations_digest=obligations_digest,
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        rootset_digest=rootset_digest,
        closed=closed,
    )
    resolution_digest_value = resolution_digest(resolution)
    if body.get("evidence_resolution_digest") != resolution_digest_value:
        raise SolsticeError("evidence resolution digest mismatch")
    recomputed_body = build_score_body(
        registry=registry,
        weights=weights,
        obligations_digest=obligations_digest,
        weights_digest=weights_digest,
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        rootset_digest=rootset_digest,
        resolution=resolution,
        resolution_digest_value=resolution_digest_value,
    )
    if recomputed_body != body:
        raise SolsticeError("score body does not match recomputed evidence closure")
    body_digest = score_body_digest(recomputed_body)
    if scorecard.get("score_body_digest") != body_digest:
        raise SolsticeError("score body digest mismatch")

    if receipt is not None:
        if receipt_digest(receipt) != scorecard.get("reproducibility_receipt_digest"):
            raise SolsticeError("receipt digest mismatch")
        if receipt.get("score_body_digest") != body_digest:
            raise SolsticeError("receipt score_body_digest mismatch")
        if receipt.get("weight_vector_digest") != weights_digest:
            raise SolsticeError("receipt weight_vector_digest mismatch")
        if receipt.get("obligations_digest") != obligations_digest:
            raise SolsticeError("receipt obligations_digest mismatch")

    score_entry, recomputed_output, output_head = build_score_entry(
        ledger_entries,
        score_body_digest_value=body_digest,
        receipt_digest_value=str(scorecard.get("reproducibility_receipt_digest")),
        input_ledger_head=input_head,
        corpus_snapshot_digest=corpus_digest,
        obligations_digest=obligations_digest,
        weights_digest=weights_digest,
    )
    if score_entry["entry_digest"] != scorecard.get("score_entry_digest"):
        raise SolsticeError("score entry digest mismatch")
    if output_head != scorecard.get("output_ledger_head"):
        raise SolsticeError("output ledger head mismatch")
    if recomputed_output != output_ledger:
        raise SolsticeError("output ledger does not equal input ledger plus score entry")
    if ledger_model.verify_entries(output_ledger) != scorecard.get("output_ledger_head"):
        raise SolsticeError("output ledger structural head mismatch")

    expected_status = _status_for(
        body["final_score_M"],
        body["open_internal_residue_M"],
        body["open_external_residue_M"],
        body["external_residue_M"],
    )
    if scorecard.get("status") != expected_status:
        raise SolsticeError("status does not match recomputed residue state")
    if scorecard_digest(scorecard) != scorecard.get("scorecard_digest"):
        raise SolsticeError("scorecard digest mismatch")
    boundary = body.get("claim_boundary", {})
    if boundary.get("production_allowed") is True:
        raise SolsticeError("production_allowed requires separate production authority proof")
    if boundary.get("runtime_containment_claim") is True:
        raise SolsticeError("runtime containment claim requires separate proof")
    if boundary.get("whole_system_post_quantum_safety_claim") is True:
        raise SolsticeError("post-quantum safety claim requires separate proof and external crypto audit")
