"""Decimal-only mathematics for Daylight v17.1 Event Horizon."""

from __future__ import annotations

from decimal import Decimal, ROUND_FLOOR, getcontext
from fractions import Fraction
from typing import Any


getcontext().prec = 100

B = 1_000_000_000
PERFECT_RESERVED_AM_PLUS = 1_000_000_000
DECLARATION_TARGET_AM_PLUS = 999_999_999
UNIT = "AM+"
VERSION = "daylight-v17-event-horizon-scorecard-v0.1"
EPSILON_DENOMINATOR = 1_000_000_000_000
EPSILON = Decimal(1) / Decimal(EPSILON_DENOMINATOR)
KAPPA = 5
WEAK_GOVERNOR_KAPPA = KAPPA
UOMEGA_DENOMINATOR = 1_000_000
LN_1E9_DECIMAL_TEXT = "20.723265836946411156161923092159277868409913397658"
OMEGA_THRESHOLD_DECIMAL_TEXT = LN_1E9_DECIMAL_TEXT
LN_1E9 = Decimal(LN_1E9_DECIMAL_TEXT)
OMEGA_THRESHOLD = LN_1E9


class SingularityMathError(ValueError):
    pass


def require_decimal_runtime() -> None:
    if not hasattr(Decimal(1), "ln") or not hasattr(Decimal(1), "exp"):
        raise SingularityMathError("Daylight v17 Event Horizon requires Python with Decimal.ln/exp support.")


def decimal_text(value: Decimal) -> str:
    text = format(+value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def parse_rational(value: Any, name: str = "rational") -> Fraction:
    if not isinstance(value, str):
        raise SingularityMathError(f"{name} must be a rational string")
    if "/" not in value:
        raise SingularityMathError(f"{name} must use numerator/denominator form")
    numerator_text, denominator_text = value.split("/", 1)
    try:
        numerator = int(numerator_text)
        denominator = int(denominator_text)
    except ValueError as exc:
        raise SingularityMathError(f"{name} must contain integer numerator and denominator") from exc
    if numerator < 0 or denominator <= 0:
        raise SingularityMathError(f"{name} must be nonnegative with positive denominator")
    return Fraction(numerator, denominator)


def parse_rational_alpha(value: Any) -> Fraction:
    fraction = parse_rational(value, "field alpha")
    if fraction <= 0:
        raise SingularityMathError("field alpha must be positive")
    return fraction


def fraction_to_decimal(value: Fraction) -> Decimal:
    return Decimal(value.numerator) / Decimal(value.denominator)


def require_nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SingularityMathError(f"{name} must be an integer")
    if value < 0:
        raise SingularityMathError(f"{name} must be nonnegative")
    return value


def require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SingularityMathError(f"{name} must be an integer")
    return value


def debt_uomega_to_decimal(value: Any, name: str) -> Decimal:
    uomega = require_nonnegative_int(value, name)
    return Decimal(uomega) / Decimal(UOMEGA_DENOMINATOR)


def field_closure(
    *,
    verified_credit: Any,
    possible_credit: Any,
    epsilon_denominator: int = EPSILON_DENOMINATOR,
) -> dict[str, Any]:
    verified = require_nonnegative_int(verified_credit, "verified_credit")
    possible = require_nonnegative_int(possible_credit, "possible_credit")
    if possible <= 0:
        raise SingularityMathError("possible_credit must be greater than zero")
    if verified > possible:
        raise SingularityMathError("verified_credit must be <= possible_credit")
    perfect_reserve_applied = verified == possible
    if perfect_reserve_applied:
        closure = Decimal(1) - (Decimal(1) / Decimal(epsilon_denominator))
    else:
        closure = Decimal(verified) / Decimal(possible)
    residue = max(Decimal(1) / Decimal(epsilon_denominator), Decimal(1) - closure)
    omega = -residue.ln()
    return {
        "verified_credit": verified,
        "possible_credit": possible,
        "closure": closure,
        "residue": residue,
        "omega": omega,
        "perfect_reserve_applied": perfect_reserve_applied,
    }


def field_curvature(closure: Decimal, *, epsilon: Decimal = EPSILON) -> Decimal:
    if closure < 0 or closure >= 1:
        raise SingularityMathError("field closure must be in [0, 1)")
    residue = max(epsilon, Decimal(1) - closure)
    return -residue.ln()


def effective_omega(
    *,
    omega_sum: Decimal,
    omega_min: Decimal,
    debt_omega: Decimal,
    overclaim_debt_omega: Decimal,
    staleness_debt_omega: Decimal,
    kappa: int = KAPPA,
) -> dict[str, Decimal]:
    omega_weak = Decimal(kappa) * omega_min
    governed = min(omega_sum, omega_weak)
    effective = governed - debt_omega - overclaim_debt_omega - staleness_debt_omega
    if effective < 0:
        effective = Decimal(0)
    return {
        "omega_weak": omega_weak,
        "omega_governed": governed,
        "omega_eff": effective,
    }


def score_from_omega(omega_eff: Decimal, *, collapse: bool = False) -> tuple[int, Decimal]:
    if collapse or omega_eff <= 0:
        return 0, Decimal(1)
    residue = (-omega_eff).exp()
    raw_score = Decimal(B) * (Decimal(1) - residue)
    score = int(raw_score.to_integral_value(rounding=ROUND_FLOOR))
    if score < 0:
        score = 0
    if omega_eff >= LN_1E9:
        score = DECLARATION_TARGET_AM_PLUS
    if score > DECLARATION_TARGET_AM_PLUS:
        score = DECLARATION_TARGET_AM_PLUS
    return score, residue


def declared(
    *,
    omega_eff: Decimal | None = None,
    omega: Decimal | None = None,
    score_am_plus: int,
    field_thresholds_pass: bool,
    contradiction_debt: int,
    critical_break_debt: int,
    score_inflation_M: int,
    collapse: bool,
    fracture_suite_passed: bool = True,
    cross_verifier_agreement_passed: bool = True,
    claim_usable: bool = True,
    fixture: bool = False,
) -> bool:
    value = omega_eff if omega_eff is not None else omega
    if value is None:
        raise SingularityMathError("omega_eff is required")
    return (
        value >= LN_1E9
        and score_am_plus == DECLARATION_TARGET_AM_PLUS
        and field_thresholds_pass
        and contradiction_debt == 0
        and critical_break_debt == 0
        and score_inflation_M == 0
        and not collapse
        and fracture_suite_passed
        and cross_verifier_agreement_passed
        and claim_usable
        and not fixture
    )


def status_for_score(*, score_am_plus: int, is_declared: bool, collapse: bool) -> str:
    if collapse:
        return "singularity_collapsed"
    if is_declared:
        return "singularity_declared"
    if score_am_plus >= 900_000_000:
        return "singularity_candidate"
    if score_am_plus > 0:
        return "singularity_accumulating"
    return "singularity_zero"
