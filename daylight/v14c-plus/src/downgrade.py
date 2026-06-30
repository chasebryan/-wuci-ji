"""Executable downgrade rules for Daylight v14C+."""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from .scoring import parse_fraction


STATE_ORDER = {
    "rejected": 0,
    "provisional": 1,
    "candidate": 2,
    "sovereign": 3,
}


def _lower_state(current: str, target: str) -> str:
    if STATE_ORDER[target] < STATE_ORDER[current]:
        return target
    return current


def evaluate_downgrade(
    *,
    claimed_q: list[list[str]],
    recomputed_q: list[list[str]],
    claim_state: str = "candidate",
    scorecard_digest_valid: bool = True,
    ledger_trace_valid: bool = True,
    unresolved_external_falsification: bool = False,
) -> dict[str, Any]:
    if claim_state not in STATE_ORDER:
        raise ValueError(f"unsupported claim state: {claim_state}")
    state = claim_state
    events = []
    if not scorecard_digest_valid:
        events.append({"reason": "manual_score_mutation", "new_state": "rejected"})
        state = "rejected"
    if not ledger_trace_valid:
        events.append({"reason": "missing_trace", "new_state": "rejected"})
        state = "rejected"
    if unresolved_external_falsification:
        state = _lower_state(state, "provisional")
        events.append({"reason": "external_falsification_unresolved", "new_state": state})
    claimed = {name: parse_fraction(value) for name, value in claimed_q}
    recomputed = {name: parse_fraction(value) for name, value in recomputed_q}
    for q_name, claimed_value in sorted(claimed.items()):
        current_value = recomputed.get(q_name)
        if current_value is None:
            state = "rejected"
            events.append({"q_id": q_name, "reason": "missing_recomputed_q", "new_state": state})
            continue
        if current_value < claimed_value:
            state = _lower_state(state, "provisional")
            events.append(
                {
                    "q_id": q_name,
                    "reason": "recomputed_q_below_claimed_q",
                    "claimed": f"{claimed_value.numerator}/{claimed_value.denominator}",
                    "recomputed": f"{current_value.numerator}/{current_value.denominator}",
                    "new_state": state,
                }
            )
    return {"claim_state": state, "events": events}

