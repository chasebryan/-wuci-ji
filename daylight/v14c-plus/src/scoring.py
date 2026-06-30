"""Exact rational scoring for Daylight v14C+."""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable

from . import corpus as corpus_model
from . import ledger as ledger_model


M_SCALE = 1_000_000
TARGET_Q_VECTOR = [
    ("q1_doctrine_master_law", "1000/1000"),
    ("q2_formalism_mathematical_density", "998/1000"),
    ("q3_negative_evidence_subtractive_capability", "1000/1000"),
    ("q4_gate_algebra_fail_closed_enforcement", "1000/1000"),
    ("q5_evidence_sheaf_release_engineering", "997/1000"),
    ("q6_surface_closure_boundary_semantics", "995/1000"),
    ("q7_adversarial_survival_model", "995/1000"),
    ("q8_cryptographic_number_theoretic_margin", "998/1000"),
    ("q9_statistical_confidence_reproducibility", "997/1000"),
    ("q10_implementation_traceability", "997/1000"),
    ("q11_external_falsification_readiness", "990/1000"),
    ("q12_communication_overall", "997/1000"),
]
CHALLENGER_C_VECTOR = [
    ("q1_doctrine_master_law", "1000/1000"),
    ("q2_formalism_mathematical_density", "995/1000"),
    ("q3_negative_evidence_subtractive_capability", "1000/1000"),
    ("q4_gate_algebra_fail_closed_enforcement", "995/1000"),
    ("q5_evidence_sheaf_release_engineering", "990/1000"),
    ("q6_surface_closure_boundary_semantics", "995/1000"),
    ("q7_adversarial_survival_model", "995/1000"),
    ("q8_cryptographic_number_theoretic_margin", "990/1000"),
    ("q9_statistical_confidence_reproducibility", "995/1000"),
    ("q10_implementation_traceability", "995/1000"),
    ("q11_external_falsification_readiness", "990/1000"),
    ("q12_communication_overall", "995/1000"),
]
LABELS = {
    "q1_doctrine_master_law": "Doctrine & Master Law",
    "q2_formalism_mathematical_density": "Formalism & Mathematical Density",
    "q3_negative_evidence_subtractive_capability": "Negative Evidence / Subtractive Capability",
    "q4_gate_algebra_fail_closed_enforcement": "Gate Algebra & Fail-Closed Enforcement",
    "q5_evidence_sheaf_release_engineering": "Evidence Sheaf & Release Engineering",
    "q6_surface_closure_boundary_semantics": "Surface Closure & Boundary Semantics",
    "q7_adversarial_survival_model": "Adversarial Survival Model",
    "q8_cryptographic_number_theoretic_margin": "Cryptographic / Number-Theoretic Margin",
    "q9_statistical_confidence_reproducibility": "Statistical Confidence & Reproducibility",
    "q10_implementation_traceability": "Implementation Traceability",
    "q11_external_falsification_readiness": "External Falsification Readiness",
    "q12_communication_overall": "Communication / Overall",
}


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
    if data.get("version") != "daylight-v13-weight-vector":
        raise ScoreError("unsupported weight vector version")
    weights = [(str(name), parse_fraction(value)) for name, value in data["weights"]]
    if sum(weight for _, weight in weights) != Fraction(1, 1):
        raise ScoreError("weight vector must sum to one")
    return weights


def load_q_evaluators(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    reject_float(data, "q_evaluators")
    if data.get("version") != "daylight-v14c-plus-q-evaluators-v0.2":
        raise ScoreError("unsupported q evaluator version")
    return data["evaluators"]


def evaluate_q(
    evaluators: dict[str, dict[str, Any]],
    ledger_entries: list[dict[str, Any]],
    corpus_snapshot: dict[str, Any],
) -> list[tuple[str, Fraction]]:
    corpus_model.verify_snapshot(corpus_snapshot)
    available_types = ledger_model.entry_types(ledger_entries)
    available_categories = set(corpus_snapshot.get("categories", []))
    results: list[tuple[str, Fraction]] = []
    for q_name, _ in TARGET_Q_VECTOR:
        spec = evaluators.get(q_name)
        if not spec:
            raise ScoreError(f"missing q evaluator: {q_name}")
        required_types = set(spec.get("requires", []))
        missing_types = sorted(required_types - available_types)
        if missing_types:
            raise ScoreError(f"NoEvidence({q_name}): missing ledger entry types: {', '.join(missing_types)}")
        required_categories = set(spec.get("minimum_corpus_categories", []))
        missing_categories = sorted(required_categories - available_categories)
        if missing_categories:
            raise ScoreError(f"NoEvidence({q_name}): missing corpus categories: {', '.join(missing_categories)}")
        results.append((q_name, parse_fraction(spec["target"])))
    return results


def compute_score(q_values: Iterable[tuple[str, Any]], weights: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    q_list = [(name, parse_fraction(value)) for name, value in q_values]
    w_list = [(name, parse_fraction(value)) for name, value in weights]
    if [name for name, _ in q_list] != [name for name, _ in w_list]:
        raise ScoreError("q-vector and weight vector dimensions do not match")
    term_contributions = []
    total = Fraction(0, 1)
    for (q_name, q_value), (_, weight) in zip(q_list, w_list):
        term = Fraction(M_SCALE, 1) * weight * q_value
        if term.denominator != 1:
            raise ScoreError(f"term contribution for {q_name} is not an integer M value")
        total += term
        term_contributions.append(
            {
                "q_id": q_name,
                "label": LABELS[q_name],
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
        "unified_score_decimal": decimal_text(unified),
        "final_score_M": total.numerator,
    }

