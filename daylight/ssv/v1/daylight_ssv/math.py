"""Decimal scoring math for DaylightSSV v1."""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP, getcontext
from typing import Any, Iterable

from .model import (
    DOMAIN_DEFINITIONS,
    DOMAIN_NAMES,
    DOMAIN_ORDER,
    DOMAIN_WEIGHTS,
    EVIDENCE_QUALITY_VALUES,
    RESULT_VALUES,
    SEVERITY_WEIGHTS,
    CheckResult,
)

getcontext().prec = 28

ONE_DECIMAL = Decimal("0.1")
FOUR_DECIMALS = Decimal("0.0001")


class ScoreModelError(ValueError):
    """Raised when scoring inputs violate the DaylightSSV model."""


def decimal_text(value: Decimal) -> str:
    """Render a Decimal without exponent notation and with at least one decimal."""

    text = format(value, "f")
    if "." not in text:
        return text + ".0"
    while len(text.rsplit(".", 1)[1]) > 1 and text.endswith("0"):
        text = text[:-1]
    return text


def quantized_text(value: Decimal, places: int = 1) -> str:
    quantum = Decimal("1").scaleb(-places)
    return format(value.quantize(quantum, rounding=ROUND_HALF_UP), f".{places}f")


def public_score(value: Decimal) -> Decimal:
    return value.quantize(ONE_DECIMAL, rounding=ROUND_HALF_UP)


def check_value(result: str, evidence_quality: str) -> Decimal:
    if result not in RESULT_VALUES:
        raise ScoreModelError(f"invalid result: {result}")
    if evidence_quality not in EVIDENCE_QUALITY_VALUES:
        raise ScoreModelError(f"invalid evidence quality: {evidence_quality}")
    return RESULT_VALUES[result] * EVIDENCE_QUALITY_VALUES[evidence_quality]


def domain_weight_total(weights: dict[str, Decimal] | None = None) -> Decimal:
    values = weights or DOMAIN_WEIGHTS
    return sum(values.values(), Decimal("0.0"))


def validate_domain_weights(weights: dict[str, Decimal] | None = None) -> None:
    values = weights or DOMAIN_WEIGHTS
    if set(values) != set(DOMAIN_ORDER):
        raise ScoreModelError("domain weights must exactly match DaylightSSV v1 domains")
    if domain_weight_total(values) != Decimal("100.0"):
        raise ScoreModelError("domain weights must total exactly 100.0")


def _severity_weight(severity: str) -> int:
    if severity not in SEVERITY_WEIGHTS:
        raise ScoreModelError(f"invalid severity: {severity}")
    return SEVERITY_WEIGHTS[severity]


def _validate_check(check: CheckResult) -> None:
    if check.domain_id not in DOMAIN_WEIGHTS:
        raise ScoreModelError(f"invalid domain: {check.domain_id}")
    _severity_weight(check.severity)
    check_value(check.result, check.evidence_quality)


def _loss_for(check: CheckResult, denominator: Decimal) -> Decimal:
    severity_weight = Decimal(_severity_weight(check.severity))
    value = check_value(check.result, check.evidence_quality)
    return DOMAIN_WEIGHTS[check.domain_id] * severity_weight * (Decimal("1.0") - value) / denominator


def score_checks(checks: Iterable[CheckResult]) -> dict[str, Any]:
    """Score checks and return deterministic report components."""

    validate_domain_weights()
    check_list = sorted(checks, key=lambda item: (DOMAIN_ORDER.index(item.domain_id), item.id))
    for check in check_list:
        _validate_check(check)

    by_domain: dict[str, list[CheckResult]] = defaultdict(list)
    for check in check_list:
        by_domain[check.domain_id].append(check)

    domain_rows: list[dict[str, Any]] = []
    reasons_with_sort: list[tuple[Decimal, str, str, dict[str, Any]]] = []
    finding_rows: list[dict[str, Any]] = []
    raw_score = Decimal("0.0")

    for domain_id, name, weight in DOMAIN_DEFINITIONS:
        domain_checks = by_domain.get(domain_id, [])
        denominator = sum((Decimal(_severity_weight(check.severity)) for check in domain_checks), Decimal("0.0"))
        weighted_value = sum(
            Decimal(_severity_weight(check.severity)) * check_value(check.result, check.evidence_quality)
            for check in domain_checks
        )
        domain_score = Decimal("0.0") if denominator == 0 else weighted_value / denominator
        domain_points = weight * domain_score
        raw_score += domain_points

        check_rows: list[dict[str, Any]] = []
        for check in domain_checks:
            value = check_value(check.result, check.evidence_quality)
            loss = Decimal("0.0") if denominator == 0 else _loss_for(check, denominator)
            check_row = {
                "id": check.id,
                "severity": check.severity,
                "severity_weight": _severity_weight(check.severity),
                "result": check.result,
                "result_value": decimal_text(RESULT_VALUES[check.result]),
                "evidence_quality": check.evidence_quality,
                "evidence_quality_value": decimal_text(EVIDENCE_QUALITY_VALUES[check.evidence_quality]),
                "check_value": decimal_text(value),
                "loss": quantized_text(loss, 1),
                "evidence": [entry.as_dict() for entry in sorted(check.evidence, key=lambda item: (item.source, item.type, item.value_summary))],
                "reason": check.reason,
                "safe_remediation_hint": check.safe_remediation_hint,
            }
            check_rows.append(check_row)
            if value != Decimal("1.0"):
                reason_row = {
                    "id": check.id,
                    "domain": name,
                    "domain_id": domain_id,
                    "loss": quantized_text(loss, 1),
                    "reason": check.reason,
                }
                reasons_with_sort.append((loss, domain_id, check.id, reason_row))
                finding_rows.append(
                    {
                        "id": check.id,
                        "domain": domain_id,
                        "severity": check.severity,
                        "result": check.result,
                        "loss": quantized_text(loss, 1),
                        "reason": check.reason,
                    }
                )

        domain_rows.append(
            {
                "id": domain_id,
                "name": name,
                "weight": quantized_text(weight, 1),
                "domain_score": quantized_text(domain_score, 4),
                "domain_points": quantized_text(domain_points, 4),
                "checks": check_rows,
            }
        )

    final_score = public_score(raw_score)
    total_checks = len(check_list)
    coverage_count = sum(1 for check in check_list if check.evidence_quality in {"strong", "medium"})
    evidence_coverage = Decimal("0.0") if total_checks == 0 else Decimal(coverage_count) / Decimal(total_checks) * Decimal("100")

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = sorted(
        finding_rows,
        key=lambda item: (severity_rank[item["severity"]], item["domain"], item["id"]),
    )
    reasons = [
        row
        for _, _, _, row in sorted(
            reasons_with_sort,
            key=lambda item: (-item[0], item[1], item[2]),
        )
    ]

    return {
        "raw_score": raw_score,
        "final_score": final_score,
        "summary": {
            "domains_total": len(DOMAIN_DEFINITIONS),
            "checks_total": total_checks,
            "checks_pass": sum(1 for check in check_list if check.result == "pass"),
            "checks_partial": sum(1 for check in check_list if check.result == "partial"),
            "checks_fail": sum(1 for check in check_list if check.result == "fail"),
            "checks_unknown": sum(1 for check in check_list if check.result == "unknown"),
            "evidence_coverage": quantized_text(evidence_coverage, 1),
        },
        "domains": domain_rows,
        "findings": findings,
        "reasons": reasons,
    }

