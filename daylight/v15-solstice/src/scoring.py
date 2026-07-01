"""Exact rational scoring for Daylight v15 Meridian.

The arithmetic kernel is unchanged from v14C+: a weighted sum over exact rational
q-values with no floating point anywhere. What changed is the *source* of the
q-values. In Meridian they are never asserted; they are derived from closed
obligations (see :mod:`src.obligations`) and re-derived at verification time.
"""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Mapping


M_SCALE = 1_000_000
WEIGHT_VECTOR_VERSION = "daylight-v13-weight-vector"


class ScoreError(ValueError):
    pass


def reject_float(value: Any, path: str = "value") -> None:
    if isinstance(value, float):
        raise ScoreError(f"float rejected in exact score path at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_float(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_float(item, f"{path}[{index}]")
    elif isinstance(value, tuple):
        for index, item in enumerate(value):
            reject_float(item, f"{path}[{index}]")


def parse_fraction(value: Any) -> Fraction:
    reject_float(value)
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value, 1)
    if isinstance(value, str):
        if "/" in value:
            numerator, denominator = value.split("/", 1)
            return Fraction(int(numerator), int(denominator))
        if "." in value:
            whole, fractional = value.split(".", 1)
            sign = -1 if whole.startswith("-") else 1
            digits = whole.lstrip("-") + fractional
            return Fraction(sign * int(digits), 10 ** len(fractional))
        return Fraction(int(value), 1)
    raise ScoreError(f"unsupported rational value: {value!r}")


def fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def decimal_text(value: Fraction, places: int = 4) -> str:
    scaled = value * (10 ** places)
    if scaled.denominator != 1:
        raise ScoreError("score cannot be rendered exactly at requested precision")
    integer = scaled.numerator
    return f"{integer // (10 ** places)}.{integer % (10 ** places):0{places}d}"


def load_weights(path: Path) -> list[tuple[str, Fraction]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    reject_float(data, "weights")
    if data.get("version") != WEIGHT_VECTOR_VERSION:
        raise ScoreError("unsupported weight vector version")
    weights = [(str(name), parse_fraction(value)) for name, value in data["weights"]]
    if sum(weight for _, weight in weights) != Fraction(1, 1):
        raise ScoreError("weight vector must sum to one")
    return weights


def compute_score(
    q_values: Iterable[tuple[str, Any]],
    weights: Iterable[tuple[str, Any]],
    labels: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    label_map = dict(labels or {})
    q_list = [(name, parse_fraction(value)) for name, value in q_values]
    w_list = [(name, parse_fraction(value)) for name, value in weights]
    if [name for name, _ in q_list] != [name for name, _ in w_list]:
        raise ScoreError("q-vector and weight vector dimensions do not match")
    term_contributions = []
    total = Fraction(0, 1)
    for (q_name, q_value), (_, weight) in zip(q_list, w_list):
        if q_value < 0 or q_value > 1:
            raise ScoreError(f"q-value for {q_name} must lie in [0, 1]")
        term = Fraction(M_SCALE, 1) * weight * q_value
        if term.denominator != 1:
            raise ScoreError(f"term contribution for {q_name} is not an integer M value")
        total += term
        term_contributions.append(
            {
                "q_id": q_name,
                "label": label_map.get(q_name, q_name),
                "weight": fraction_text(weight),
                "q_value": fraction_text(q_value),
                "contribution_M": term.numerator,
            }
        )
    if total.denominator != 1:
        raise ScoreError("final score is not an integer M value")
    unified = total / M_SCALE
    return {
        "q_vector": [[name, fraction_text(value)] for name, value in q_list],
        "term_contributions_M": term_contributions,
        "unified_score_rational": fraction_text(unified),
        "unified_score_decimal": decimal_text(unified, places=6),
        "final_score_M": total.numerator,
    }
