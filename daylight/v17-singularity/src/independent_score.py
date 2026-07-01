"""Independent in-repo re-derivation of the Daylight v17 scoring layer.

This module is a deliberately separate implementation of the v17.1 Event
Horizon scoring assembly. It re-derives the score-relevant quantities of a
scorecard directly from the raw registry, proof atoms, and state, following the
written specification in ``specs/daylight-v17-singularity-math.md`` rather than
calling :mod:`scorecard`.

Independence boundary (stated honestly):

* This shares the low-level ``Decimal`` ln/exp kernel in
  :mod:`singularity_math`. It is *not* an independent external verifier and it
  is *not* a second-language verifier. Both remain future work.
* What it does provide is a second, structurally separate derivation of the
  field aggregation, weakest-field governor, effective omega, AM+ integer, and
  collapse decision, so that a divergence between what a scorecard *claims* and
  what the evidence actually produces is detectable instead of assumed.

To harden the headline AM+ integer specifically, the score is computed by two
independent arithmetic routes and cross-checked:

* Route A: ``floor(B * (1 - exp(-omega_eff)))`` (the reference form).
* Route B: ``B - ceil(B * exp(-omega_eff))`` (an algebraically equal form that
  never multiplies ``1 - residue``).

If the two routes disagree the derivation raises, because that would itself be
an implementation disagreement.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR
from typing import Any

from . import proof_atoms as proof_atoms_mod
from . import registry as registry_mod
from .singularity_math import (
    B,
    DECLARATION_TARGET_AM_PLUS,
    OMEGA_THRESHOLD,
    debt_uomega_to_decimal,
    decimal_text,
    field_closure,
    fraction_to_decimal,
    parse_rational_alpha,
    require_decimal_runtime,
)
from .scorecard import COLLAPSE_FLAGS


class IndependentScoreError(ValueError):
    pass


def _threshold_pass(*, verified: int, possible: int, perfect: bool, closure: Decimal, threshold) -> bool:
    """Decide threshold closure without trusting the scorecard's stored flag.

    For the ordinary case this is a pure integer cross-multiplication
    (``verified/possible >= num/den``), independent of any decimal rounding. The
    perfect-reserve case (closure just below one) is compared against the
    threshold decimal directly.
    """

    if perfect:
        return closure >= fraction_to_decimal(threshold)
    return verified * threshold.denominator >= threshold.numerator * possible


def _score_two_routes(omega_eff: Decimal, *, collapse: bool) -> int:
    """Compute the AM+ integer twice and require the two routes to agree."""

    if collapse or omega_eff <= 0:
        return 0

    residue = (-omega_eff).exp()

    raw_a = Decimal(B) * (Decimal(1) - residue)
    score_a = int(raw_a.to_integral_value(rounding=ROUND_FLOOR))

    ceil_b_residue = int((Decimal(B) * residue).to_integral_value(rounding=ROUND_CEILING))
    score_b = B - ceil_b_residue

    if score_a != score_b:
        raise IndependentScoreError(
            f"independent score arithmetic disagreement: floor route {score_a} != ceil route {score_b}"
        )

    score = score_a
    if score < 0:
        score = 0
    if omega_eff >= OMEGA_THRESHOLD:
        score = DECLARATION_TARGET_AM_PLUS
    if score > DECLARATION_TARGET_AM_PLUS:
        score = DECLARATION_TARGET_AM_PLUS
    return score


def _collapse_reasons(state: dict[str, Any], atom_collapse: list[str]) -> list[str]:
    reasons: list[str] = []
    if int(state.get("contradiction_debt", 0)) > 0:
        reasons.append("contradiction_debt")
    if int(state.get("critical_break_debt", 0)) > 0:
        reasons.append("critical_break_debt")
    flags = state.get("collapse_flags", {})
    for key in COLLAPSE_FLAGS:
        if flags.get(key, False):
            reasons.append(key)
    return reasons + list(atom_collapse)


def rederive_scoring(
    state: dict[str, Any],
    fields_registry: dict[str, Any],
    proof_atom_registry: dict[str, Any],
) -> dict[str, Any]:
    """Return the score-relevant quantities re-derived from raw inputs."""

    require_decimal_runtime()
    registry_mod.validate_fields_registry(fields_registry)
    atom_result = proof_atoms_mod.verify_proof_atoms(proof_atom_registry)
    thresholds = registry_mod.field_thresholds(fields_registry)
    epsilon_denominator = int(fields_registry["epsilon_denominator"])
    kappa = int(fields_registry["weak_governor_kappa"])

    fields: list[dict[str, Any]] = []
    omega_sum = Decimal(0)
    omega_min: Decimal | None = None
    for field_def in fields_registry["fields"]:
        field_id = field_def["id"]
        closure = field_closure(
            verified_credit=atom_result["field_verified_credit"][field_id],
            possible_credit=atom_result["field_possible_credit"][field_id],
            epsilon_denominator=epsilon_denominator,
        )
        weighted = fraction_to_decimal(parse_rational_alpha(field_def["alpha"])) * closure["omega"]
        omega_sum += weighted
        if omega_min is None or closure["omega"] < omega_min:
            omega_min = closure["omega"]
        fields.append({
            "id": field_id,
            "closure_decimal": decimal_text(closure["closure"]),
            "verified_credit": closure["verified_credit"],
            "possible_credit": closure["possible_credit"],
            "threshold_pass": _threshold_pass(
                verified=closure["verified_credit"],
                possible=closure["possible_credit"],
                perfect=closure["perfect_reserve_applied"],
                closure=closure["closure"],
                threshold=thresholds[field_id],
            ),
        })
    if omega_min is None:
        raise IndependentScoreError("no fields available")

    omega_weak = Decimal(kappa) * omega_min
    governed = min(omega_sum, omega_weak)
    debts = (
        debt_uomega_to_decimal(state.get("debt_uomega", 0), "debt_uomega")
        + debt_uomega_to_decimal(state.get("overclaim_debt_uomega", 0), "overclaim_debt_uomega")
        + debt_uomega_to_decimal(state.get("staleness_debt_uomega", 0), "staleness_debt_uomega")
    )
    omega_eff = governed - debts
    if omega_eff < 0:
        omega_eff = Decimal(0)

    collapse_reasons = _collapse_reasons(state, atom_result["collapse_reasons"])
    collapse = bool(collapse_reasons)
    score = _score_two_routes(omega_eff, collapse=collapse)

    return {
        "fields": fields,
        "omega_sum_decimal": decimal_text(omega_sum),
        "omega_weak_decimal": decimal_text(omega_weak),
        "omega_decimal": decimal_text(Decimal(0) if collapse else omega_eff),
        "score_AM_plus": score,
        "collapse": collapse,
    }
