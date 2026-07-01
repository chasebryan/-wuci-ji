"""Decimal-only mathematics for Daylight v17 Singularity."""

from __future__ import annotations

from decimal import Decimal, ROUND_FLOOR, getcontext
from fractions import Fraction
from typing import Any


getcontext().prec = 100

B = 1_000_000_000
PERFECT_RESERVED_AM_PLUS = 1_000_000_000
DECLARATION_TARGET_AM_PLUS = 999_999_999
UNIT = "AM+"
VERSION = "daylight-v17-singularity-scorecard-v0.1"
EPSILON_DENOMINATOR = 1_000_000_000_000
UOMEGA_DENOMINATOR = 1_000_000
OMEGA_THRESHOLD_DECIMAL_TEXT = "20.723265836946411156161923092159277868409913397658"
OMEGA_THRESHOLD = Decimal(OMEGA_THRESHOLD_DECIMAL_TEXT)


class SingularityMathError(ValueError):
    pass


def require_decimal_runtime() -> None:
    if not hasattr(Decimal(1), "ln") or not hasattr(Decimal(1), "exp"):
        raise SingularityMathError("Daylight v17 Singularity requires Decimal.ln/exp, available in Python >= 3.11")


def decimal_text(value: Decimal) -> str:
    text = format(+value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def parse_rational_alpha(value: Any) -> Fraction:
    if not isinstance(value, str):
        raise SingularityMathError("field alpha must be a rational string")
    if "/" not in value:
        raise SingularityMathError("field alpha must use numerator/denominator form")
    numerator_text, denominator_text = value.split("/", 1)
    try:
        numerator = int(numerator_text)
        denominator = int(denominator_text)
    except ValueError as exc:
        raise SingularityMathError("field alpha must contain integer numerator and denominator") from exc
    if numerator <= 0 or denominator <= 0:
        raise SingularityMathError("field alpha must be positive")
    return Fraction(numerator, denominator)


def fraction_to_decimal(value: Fraction) -> Decimal:
    return Decimal(value.numerator) / Decimal(value.denominator)


def require_nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SingularityMathError(f"{name} must be an integer")
    if value < 0:
        raise SingularityMathError(f"{name} must be nonnegative")
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
    residue = Decimal(1) - closure
    omega = -residue.ln()
    return {
        "verified_credit": verified,
        "possible_credit": possible,
        "closure": closure,
        "residue": residue,
        "omega": omega,
        "perfect_reserve_applied": perfect_reserve_applied,
    }


def field_curvature(closure: Decimal) -> Decimal:
    if closure < 0 or closure >= 1:
        raise SingularityMathError("field closure must be in [0, 1)")
    return -(Decimal(1) - closure).ln()


def score_from_omega(omega: Decimal, *, collapse: bool = False) -> tuple[int, Decimal]:
    if collapse:
        return 0, Decimal(1)
    residue = (-omega).exp()
    raw_score = Decimal(B) * (Decimal(1) - residue)
    score = int(raw_score.to_integral_value(rounding=ROUND_FLOOR))
    if score < 0:
        score = 0
    if omega >= OMEGA_THRESHOLD:
        score = DECLARATION_TARGET_AM_PLUS
    if score > DECLARATION_TARGET_AM_PLUS:
        score = DECLARATION_TARGET_AM_PLUS
    return score, residue


def declared(
    *,
    omega: Decimal,
    score_am_plus: int,
    contradiction_debt: int,
    critical_break_debt: int,
    score_inflation_M: int,
    collapse: bool,
) -> bool:
    return (
        omega >= OMEGA_THRESHOLD
        and score_am_plus == DECLARATION_TARGET_AM_PLUS
        and contradiction_debt == 0
        and critical_break_debt == 0
        and score_inflation_M == 0
        and not collapse
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
