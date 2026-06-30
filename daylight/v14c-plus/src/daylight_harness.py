"""Deterministic Daylight v14C+ scorecard generation harness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256
from . import corpus as corpus_model
from . import ledger as ledger_model
from . import scoring


SCORECARD_DOMAIN = "DAYLIGHT-v14C+-SCORECARD:"
RECEIPT_DOMAIN = "DAYLIGHT-v14C+-RECEIPT:"
FIXED_CREATED_AT = "2026-06-30T00:00:00Z"


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
    scorecard_digest_value: str,
    command: str,
) -> tuple[dict[str, Any], str]:
    receipt = {
        "receipt_version": "daylight-v14c-plus-receipt-v0.2",
        "input_ledger_head": input_ledger_head,
        "corpus_snapshot_digest": corpus_snapshot_digest,
        "environment_digest": canonical_sha256({"python": "stdlib", "math": "fractions.Fraction"}, RECEIPT_DOMAIN),
        "source_digest": canonical_sha256({"package": "daylight/v14c-plus", "version": "v0.2"}, RECEIPT_DOMAIN),
        "harness_digest": canonical_sha256({"harness": "src.daylight_harness.generate_scorecard"}, RECEIPT_DOMAIN),
        "scorecard_digest": scorecard_digest_value,
        "created_at_utc": FIXED_CREATED_AT,
        "command": command,
        "result": "pass",
    }
    return receipt, receipt_digest(receipt)


def generate_scorecard(
    *,
    ledger_path: Path,
    corpus_path: Path,
    weights_path: Path,
    evaluators_path: Path,
    command: str,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    ledger_entries, input_head = ledger_model.frozen_head(ledger_path)
    corpus_entries_before = corpus_model.load_jsonl(corpus_path)
    corpus_snapshot = corpus_model.freeze_corpus(corpus_entries_before)
    frozen_digest = corpus_snapshot["corpus_snapshot_digest"]
    weights = scoring.load_weights(weights_path)
    evaluators = scoring.load_q_evaluators(evaluators_path)
    q_vector = scoring.evaluate_q(evaluators, ledger_entries, corpus_snapshot)
    score = scoring.compute_score(q_vector, weights)
    scorecard = {
        "scorecard_version": "daylight-v14c-plus-scorecard-v0.2",
        "candidate": "DAYLIGHT v14C+ ASCENDANT CANDIDATE",
        "status": "candidate_score_pending_generated_execution",
        "generated": True,
        "manual_override": False,
        "weight_vector_ref": "daylight-v13-weight-vector",
        "q_vector": score["q_vector"],
        "term_contributions_M": score["term_contributions_M"],
        "unified_score_rational": score["unified_score_rational"],
        "unified_score_decimal": score["unified_score_decimal"],
        "final_score_M": score["final_score_M"],
        "input_ledger_head": input_head,
        "output_ledger_head": "",
        "corpus_snapshot_digest": frozen_digest,
        "reproducibility_receipt_digest": "",
        "scorecard_digest": "",
        "manual_edit_allowed": False,
    }
    seal_digest = scorecard_digest(scorecard)
    receipt, receipt_hash = build_receipt(
        input_ledger_head=input_head,
        corpus_snapshot_digest=frozen_digest,
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
        entry_id="ledger-entry-scorecard-v14c-plus-v0.2",
    )
    scorecard["output_ledger_head"] = output_head
    after_snapshot = corpus_model.freeze_corpus(corpus_model.load_jsonl(corpus_path))
    if after_snapshot["corpus_snapshot_digest"] != frozen_digest:
        raise HarnessError("corpus mutation during scoring is forbidden")
    if scorecard["input_ledger_head"] == scorecard["output_ledger_head"]:
        raise HarnessError("scorecard append did not change ledger head")
    return scorecard, receipt, scorecard_entries


def verify_scorecard(scorecard: dict[str, Any]) -> None:
    if scorecard.get("manual_edit_allowed") is not False:
        raise HarnessError("manual score editing is not allowed")
    if scorecard.get("manual_override") is True:
        raise HarnessError("manual score override is rejected")
    expected_digest = scorecard.get("scorecard_digest")
    actual_digest = scorecard_digest(scorecard)
    if actual_digest != expected_digest:
        raise HarnessError("scorecard digest mismatch")
    weights = [(name, value["weight"]) for name, value in ((item["q_id"], item) for item in scorecard["term_contributions_M"])]
    recomputed = scoring.compute_score(scorecard["q_vector"], weights)
    if recomputed["final_score_M"] != scorecard["final_score_M"]:
        raise HarnessError("scorecard final score does not match q-vector")
    if recomputed["unified_score_rational"] != scorecard["unified_score_rational"]:
        raise HarnessError("scorecard rational score does not match q-vector")
    if not scorecard.get("input_ledger_head") or not scorecard.get("output_ledger_head"):
        raise HarnessError("scorecard missing input/output ledger head")
    if scorecard["input_ledger_head"] == scorecard["output_ledger_head"]:
        raise HarnessError("scorecard input/output ledger heads must differ")

