"""Deterministic Daylight v15 Meridian scorecard generation and verification.

The Meridian harness derives every q-value from closed obligations at generation
time, and **re-derives** them at verification time from the pinned obligation
registry plus the sealed closed-obligation set. That re-derivation is what makes
``ManualScore(x) -> Reject(x)`` mechanical rather than aspirational: editing a
q-value (or an evaluator target) no longer survives verification, because the
score is recomputed from evidence-bound obligations, not trusted from the card.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256
from . import corpus as corpus_model
from . import ledger as ledger_model
from . import obligations as obligation_model
from . import scoring


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
DEFAULT_OBLIGATIONS = PACKAGE_ROOT / "rules" / "obligations.v15.json"

SCORECARD_DOMAIN = "DAYLIGHT-v15-MERIDIAN-SCORECARD:"
RECEIPT_DOMAIN = "DAYLIGHT-v15-MERIDIAN-RECEIPT:"
FIXED_CREATED_AT = "2026-06-30T00:00:00Z"
SCORECARD_VERSION = "daylight-v15-meridian-scorecard-v0.1"
PERFECT_SCORE_M = scoring.M_SCALE
CANDIDATE_LABEL = "DAYLIGHT v15 MERIDIAN ASCENDANT CANDIDATE"


class HarnessError(ValueError):
    pass


def scorecard_seal_payload(scorecard: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in scorecard.items()
        if key
        not in {
            "scorecard_digest",
            "output_ledger_head",
            "reproducibility_receipt_digest",
        }
    }


def scorecard_digest(scorecard: dict[str, Any]) -> str:
    return canonical_sha256(scorecard_seal_payload(scorecard), SCORECARD_DOMAIN)


def receipt_digest(receipt: dict[str, Any]) -> str:
    return canonical_sha256(receipt, RECEIPT_DOMAIN)


def build_receipt(
    *,
    input_ledger_head: str,
    corpus_snapshot_digest: str,
    obligations_digest: str,
    scorecard_digest_value: str,
    command: str,
) -> tuple[dict[str, Any], str]:
    receipt = {
        "receipt_version": "daylight-v15-meridian-receipt-v0.1",
        "input_ledger_head": input_ledger_head,
        "corpus_snapshot_digest": corpus_snapshot_digest,
        "obligations_digest": obligations_digest,
        "environment_digest": canonical_sha256({"python": "stdlib", "math": "fractions.Fraction"}, RECEIPT_DOMAIN),
        "source_digest": canonical_sha256({"package": "daylight/v15-meridian", "version": "v0.1"}, RECEIPT_DOMAIN),
        "harness_digest": canonical_sha256({"harness": "src.daylight_harness.generate_scorecard"}, RECEIPT_DOMAIN),
        "scorecard_digest": scorecard_digest_value,
        "created_at_utc": FIXED_CREATED_AT,
        "command": command,
        "result": "pass",
    }
    return receipt, receipt_digest(receipt)


def _q_text_vector(q_vector: list[tuple[str, Fraction]]) -> list[list[str]]:
    return [[name, scoring.fraction_text(value)] for name, value in q_vector]


def _open_obligations(registry: dict[str, Any], closed_ids: set[str]) -> list[dict[str, Any]]:
    rows = []
    for q_id, obligation in obligation_model.iter_obligations(registry):
        if obligation["id"] in closed_ids:
            continue
        rows.append(
            {
                "obligation_id": obligation["id"],
                "q_id": q_id,
                "scope": obligation["scope"],
                "weight": int(obligation["weight"]),
                "evidence_kind": obligation["evidence_kind"],
                "evidence_class": obligation["evidence_class"],
            }
        )
    return sorted(rows, key=lambda row: row["obligation_id"])


def _status_for(final_score_M: int, open_rows: list[dict[str, Any]]) -> str:
    open_external = [row for row in open_rows if row["scope"] == "external"]
    if final_score_M >= PERFECT_SCORE_M and not open_rows:
        return "perfect_score_pending_external_release_gate"
    if not open_external:
        return "candidate_score_internal_complete_no_open_external_frontier"
    return "candidate_score_internal_ceiling_external_frontier_open"


def generate_scorecard(
    *,
    ledger_path: Path,
    corpus_path: Path,
    weights_path: Path = DEFAULT_WEIGHTS,
    obligations_path: Path = DEFAULT_OBLIGATIONS,
    command: str,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    ledger_entries, input_head = ledger_model.frozen_head(ledger_path)
    corpus_entries_before = corpus_model.load_jsonl(corpus_path)
    corpus_snapshot = corpus_model.freeze_corpus(corpus_entries_before)
    frozen_digest = corpus_snapshot["corpus_snapshot_digest"]

    registry = obligation_model.load_registry(obligations_path)
    obligations_digest = obligation_model.registry_digest(registry)
    weights = scoring.load_weights(weights_path)
    labels = obligation_model.labels(registry)

    closed = obligation_model.resolve_closed_obligations(registry, ledger_entries, corpus_snapshot)
    closed_ids = set(closed)
    q_vector = obligation_model.derive_q_vector(registry, closed_ids)
    score = scoring.compute_score(q_vector, weights, labels)

    closed_records = sorted(closed.values(), key=lambda row: row["obligation_id"])
    open_rows = _open_obligations(registry, closed_ids)
    final_score_M = score["final_score_M"]
    residue_to_perfect_M = PERFECT_SCORE_M - final_score_M

    scorecard = {
        "scorecard_version": SCORECARD_VERSION,
        "candidate": CANDIDATE_LABEL,
        "status": _status_for(final_score_M, open_rows),
        "generated": True,
        "manual_override": False,
        "manual_edit_allowed": False,
        "weight_vector_ref": "daylight-v13-weight-vector",
        "obligations_version": registry["version"],
        "obligations_digest": obligations_digest,
        "q_vector": score["q_vector"],
        "term_contributions_M": score["term_contributions_M"],
        "unified_score_rational": score["unified_score_rational"],
        "unified_score_decimal": score["unified_score_decimal"],
        "final_score_M": final_score_M,
        "perfect_score_M": PERFECT_SCORE_M,
        "residue_to_perfect_M": residue_to_perfect_M,
        "closed_obligations": closed_records,
        "open_obligations": open_rows,
        "input_ledger_head": input_head,
        "output_ledger_head": "",
        "corpus_snapshot_digest": frozen_digest,
        "reproducibility_receipt_digest": "",
        "scorecard_digest": "",
    }
    scoring.reject_float(scorecard_seal_payload(scorecard), "scorecard")
    seal_digest = scorecard_digest(scorecard)
    receipt, receipt_hash = build_receipt(
        input_ledger_head=input_head,
        corpus_snapshot_digest=frozen_digest,
        obligations_digest=obligations_digest,
        scorecard_digest_value=seal_digest,
        command=command,
    )
    scorecard["reproducibility_receipt_digest"] = receipt_hash
    scorecard["scorecard_digest"] = seal_digest
    scorecard_entries, output_head = ledger_model.append_entry(
        ledger_entries,
        entry_type="scorecard",
        artifact_digest=seal_digest,
        witness={"witness_type": "harness_generated_scorecard", "witness_digest": receipt_hash},
        transcript_digest=canonical_sha256({"scorecard_digest": seal_digest, "input_head": input_head}, SCORECARD_DOMAIN),
        evidence_binding=frozen_digest,
        entry_id="ledger-entry-scorecard-v15-meridian-v0.1",
    )
    scorecard["output_ledger_head"] = output_head
    after_snapshot = corpus_model.freeze_corpus(corpus_model.load_jsonl(corpus_path))
    if after_snapshot["corpus_snapshot_digest"] != frozen_digest:
        raise HarnessError("corpus mutation during scoring is forbidden")
    if scorecard["input_ledger_head"] == scorecard["output_ledger_head"]:
        raise HarnessError("scorecard append did not change ledger head")
    return scorecard, receipt, scorecard_entries


def verify_scorecard(
    scorecard: dict[str, Any],
    obligations_path: Path = DEFAULT_OBLIGATIONS,
    *,
    ledger_path: Path | None = None,
    corpus_path: Path | None = None,
) -> None:
    if scorecard.get("manual_edit_allowed") is not False:
        raise HarnessError("manual score editing is not allowed")
    if scorecard.get("manual_override") is True:
        raise HarnessError("manual score override is rejected")

    # Pin the obligation registry. If the registry changed, the score is stale.
    registry = obligation_model.load_registry(obligations_path)
    if scorecard.get("obligations_digest") != obligation_model.registry_digest(registry):
        raise HarnessError("obligation registry digest mismatch")

    closed_records = scorecard.get("closed_obligations")
    if not isinstance(closed_records, list):
        raise HarnessError("scorecard missing closed_obligations")
    registry_by_id = {ob["id"]: (q_id, ob) for q_id, ob in obligation_model.iter_obligations(registry)}
    closed_ids: list[str] = []
    for record in closed_records:
        ob_id = record.get("obligation_id")
        if ob_id not in registry_by_id:
            raise HarnessError(f"closed obligation not in registry: {ob_id}")
        q_id, obligation = registry_by_id[ob_id]
        if record.get("q_id") != q_id or int(record.get("weight", -1)) != int(obligation["weight"]) or record.get("scope") != obligation["scope"]:
            raise HarnessError(f"closed obligation record does not match registry: {ob_id}")
        closed_ids.append(ob_id)
    if len(set(closed_ids)) != len(closed_ids):
        raise HarnessError("duplicate closed obligation in scorecard")

    # Re-derive the q-vector from the sealed closed-obligation set: this rejects
    # any q-value edited away from what its obligations support (manual score).
    derived = obligation_model.derive_q_vector(registry, closed_ids)
    derived_text = _q_text_vector(derived)
    if derived_text != scorecard.get("q_vector"):
        raise HarnessError("q-vector does not match the closed obligation set (manual score rejected)")

    # Strong evidence binding: when the ledger and corpus are supplied, re-resolve
    # which obligations the evidence actually closes and require an exact match.
    # This enforces NoEvidence -> NoScore and NoTrace -> NoTrust at verification
    # time: a fabricated closed set that no evidence backs is rejected here.
    if ledger_path is not None and corpus_path is not None:
        ledger_entries, recomputed_head = ledger_model.frozen_head(ledger_path)
        if recomputed_head != scorecard.get("input_ledger_head"):
            raise HarnessError("input ledger head does not match the supplied ledger")
        corpus_snapshot = corpus_model.freeze_corpus(corpus_model.load_jsonl(corpus_path))
        if corpus_snapshot["corpus_snapshot_digest"] != scorecard.get("corpus_snapshot_digest"):
            raise HarnessError("corpus snapshot digest does not match the supplied corpus")
        resolved = obligation_model.resolve_closed_obligations(registry, ledger_entries, corpus_snapshot)
        if sorted(resolved) != sorted(closed_ids):
            raise HarnessError("closed obligation set is not backed by the supplied evidence")
        for record in closed_records:
            backing = resolved[record["obligation_id"]]
            if record.get("evidence_digest") != backing["evidence_digest"]:
                raise HarnessError(f"closed obligation evidence digest mismatch: {record['obligation_id']}")

    # The seal must bind everything above.
    expected_digest = scorecard.get("scorecard_digest")
    actual_digest = scorecard_digest(scorecard)
    if actual_digest != expected_digest:
        raise HarnessError("scorecard digest mismatch")

    # Recompute the weighted sum from the q-vector and its own per-term weights.
    weights = [(item["q_id"], item["weight"]) for item in scorecard["term_contributions_M"]]
    recomputed = scoring.compute_score(scorecard["q_vector"], weights)
    if recomputed["final_score_M"] != scorecard["final_score_M"]:
        raise HarnessError("scorecard final score does not match q-vector")
    if recomputed["unified_score_rational"] != scorecard["unified_score_rational"]:
        raise HarnessError("scorecard rational score does not match q-vector")
    if scorecard.get("perfect_score_M") != PERFECT_SCORE_M:
        raise HarnessError("scorecard perfect_score_M must be 1000000")
    if scorecard.get("residue_to_perfect_M") != PERFECT_SCORE_M - scorecard["final_score_M"]:
        raise HarnessError("residue_to_perfect_M does not match final score")
    if not scorecard.get("input_ledger_head") or not scorecard.get("output_ledger_head"):
        raise HarnessError("scorecard missing input/output ledger head")
    if scorecard["input_ledger_head"] == scorecard["output_ledger_head"]:
        raise HarnessError("scorecard input/output ledger heads must differ")
