"""Upstream Daylight evidence reference checks for Aperture capsules.

Aperture consumes upstream evidence, it does not re-implement upstream
scoring. Each check here is a fail-closed consistency gate:

- v18 binaric vectors: recompute the canonical vector digest with the v18
  domain string and refuse a broken previous-vector chain.
- v18 transition ledgers: recompute genesis and per-entry head linkage.
- v15 Meridian scorecards: refuse manual-edit markers, refuse scores that do
  not equal their own term contributions, and refuse perfect scores without
  genuinely external (non-self-signed) closure. Full q-vector re-derivation
  stays with the Meridian verifier (`make daylight-meridian-verify`).
- v17 Event Horizon scorecards: refuse fixture scorecards marked claim-usable,
  refuse the reserved perfect AM+ value, and refuse declared status without
  cross-verifier agreement.
"""

from __future__ import annotations

import re
from typing import Any

from .canonical_json import canonical_sha256, loads_json_no_floats

D_V18_VECTOR = "DAYLIGHT-v18-BINARIC-VECTOR:"
D_V18_HEAD = "DAYLIGHT-v18-BASTION-TRANSITION-HEAD:"
EVENT_HORIZON_MAX_DECLARABLE_AM_PLUS = 999_999_999
SELF_SIGNER_RE = re.compile(r"^(self|internal|local|repo|harness|wuci-ji)([:._-]|$)", re.IGNORECASE)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceRefError(ValueError):
    pass


def _require_hex64(value: Any, name: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise EvidenceRefError(f"{name} must be lowercase hex digest length 64")
    return value


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceRefError(f"{name} must be an integer")
    return value


def check_binaric_vector_chain(vectors: list[dict[str, Any]]) -> str:
    """Verify vector digests and previous-vector chaining; return head digest."""
    if not vectors:
        raise EvidenceRefError("binaric vector chain must not be empty")
    previous_digest: str | None = None
    for index, vector in enumerate(vectors):
        label = f"binaric vector [{index}]"
        if not isinstance(vector, dict):
            raise EvidenceRefError(f"{label} must be an object")
        recorded = _require_hex64(vector.get("vector_digest"), f"{label}.vector_digest")
        body = {key: value for key, value in vector.items() if key != "vector_digest"}
        if canonical_sha256(body, D_V18_VECTOR) != recorded:
            raise EvidenceRefError(f"{label} vector_digest mismatch")
        if index > 0:
            linked = vector.get("previous_vector_digest")
            if linked is None:
                raise EvidenceRefError(f"{label} missing previous_vector_digest chain link")
            if linked != previous_digest:
                raise EvidenceRefError(f"{label} previous-vector chain break")
        previous_digest = recorded
    assert previous_digest is not None
    return previous_digest


def check_transition_ledger(text: str) -> str:
    """Verify a v18 transition ledger's head chain; return the final head."""
    records = [loads_json_no_floats(line) for line in text.splitlines() if line.strip()]
    if not records:
        raise EvidenceRefError("transition ledger is empty")
    genesis = records[0]
    if not isinstance(genesis, dict) or set(genesis) != {"ledger_version", "genesis_head"}:
        raise EvidenceRefError("transition ledger genesis record malformed")
    if not isinstance(genesis["ledger_version"], str) or not genesis["ledger_version"]:
        raise EvidenceRefError("transition ledger version malformed")
    genesis_head = _require_hex64(genesis["genesis_head"], "genesis_head")
    if canonical_sha256({"genesis": genesis["ledger_version"]}, D_V18_HEAD) != genesis_head:
        raise EvidenceRefError("transition ledger genesis head mismatch")
    head = genesis_head
    for index, entry in enumerate(records[1:], start=1):
        label = f"transition ledger entry [{index}]"
        if not isinstance(entry, dict):
            raise EvidenceRefError(f"{label} must be an object")
        previous_head = _require_hex64(entry.get("previous_head"), f"{label}.previous_head")
        entry_digest = _require_hex64(entry.get("entry_digest"), f"{label}.entry_digest")
        entry_head = _require_hex64(entry.get("head"), f"{label}.head")
        _require_hex64(entry.get("transition_digest"), f"{label}.transition_digest")
        if previous_head != head:
            raise EvidenceRefError(f"{label} previous_head chain break")
        expected = canonical_sha256(
            {"previous_head": previous_head, "entry_digest": entry_digest}, D_V18_HEAD
        )
        if entry_head != expected:
            raise EvidenceRefError(f"{label} head mismatch")
        head = entry_head
    return head


def _external_attestation_is_genuine(obligation: dict[str, Any]) -> bool:
    attestation = obligation.get("attestation")
    if not isinstance(attestation, dict):
        return False
    if attestation.get("self_signed") is True:
        return False
    signer_id = attestation.get("signer_id")
    if not isinstance(signer_id, str) or not signer_id:
        return False
    return not SELF_SIGNER_RE.match(signer_id)


def check_meridian_scorecard(scorecard: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scorecard, dict):
        raise EvidenceRefError("meridian scorecard must be an object")
    if scorecard.get("manual_edit_allowed") is not False:
        raise EvidenceRefError("meridian scorecard permits manual edits: ManualScore(x) -> Reject(x)")
    if scorecard.get("manual_override") not in (False, None):
        raise EvidenceRefError("meridian scorecard carries a manual override: ManualScore(x) -> Reject(x)")
    final_score = _require_int(scorecard.get("final_score_M"), "final_score_M")
    perfect_score = _require_int(scorecard.get("perfect_score_M"), "perfect_score_M")
    terms = scorecard.get("term_contributions_M")
    if not isinstance(terms, list) or not terms:
        raise EvidenceRefError("meridian scorecard missing term_contributions_M")
    contribution_sum = 0
    for index, term in enumerate(terms):
        if not isinstance(term, dict):
            raise EvidenceRefError(f"term_contributions_M[{index}] must be an object")
        contribution_sum += _require_int(term.get("contribution_M"), f"term_contributions_M[{index}].contribution_M")
    if contribution_sum != final_score:
        raise EvidenceRefError("meridian final_score_M does not equal its term contributions: score edit rejected")
    open_obligations = scorecard.get("open_obligations")
    closed_obligations = scorecard.get("closed_obligations")
    if not isinstance(open_obligations, list) or not isinstance(closed_obligations, list):
        raise EvidenceRefError("meridian scorecard obligations malformed")
    if final_score >= perfect_score:
        if open_obligations:
            raise EvidenceRefError("perfect meridian score with open obligations rejected")
        external_closed = [
            obligation
            for obligation in closed_obligations
            if isinstance(obligation, dict) and obligation.get("scope") == "external"
        ]
        if not external_closed:
            raise EvidenceRefError("perfect meridian score without external evidence rejected")
        for obligation in external_closed:
            if not _external_attestation_is_genuine(obligation):
                raise EvidenceRefError(
                    "perfect meridian score requires non-self-signed external attestations"
                )
    return {
        "final_score_M": final_score,
        "perfect_score_M": perfect_score,
        "open_obligation_count": len(open_obligations),
    }


def check_event_horizon_scorecard(scorecard: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scorecard, dict):
        raise EvidenceRefError("event horizon scorecard must be an object")
    _require_hex64(scorecard.get("scorecard_digest"), "scorecard_digest")
    fixture = scorecard.get("fixture")
    claim_usable = scorecard.get("claim_usable")
    if fixture is True and claim_usable is True:
        raise EvidenceRefError("fixture event horizon scorecard cannot be claim-usable")
    score = scorecard.get("score_AM_plus")
    if score is not None:
        score = _require_int(score, "score_AM_plus")
        if score < 0 or score > EVENT_HORIZON_MAX_DECLARABLE_AM_PLUS:
            raise EvidenceRefError("event horizon score exceeds the reserved AM+ maximum")
    if scorecard.get("declared") is True and scorecard.get("cross_verifier_agreement_passed") is not True:
        raise EvidenceRefError("declared event horizon scorecard without cross-verifier agreement rejected")
    return {
        "scorecard_digest": scorecard["scorecard_digest"],
        "fixture": bool(fixture),
        "score_AM_plus": score,
    }
