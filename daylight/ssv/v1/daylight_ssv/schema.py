"""Report validation for DaylightSSV v1."""

from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from . import TOOL, VERSION
from .math import ScoreModelError, check_value, public_score, validate_domain_weights
from .model import DOMAIN_NAMES, DOMAIN_ORDER, DOMAIN_WEIGHTS, EVIDENCE_QUALITY_VALUES, RESULT_VALUES, SEVERITY_WEIGHTS

SCORE_RE = re.compile(r"^(?:100\.0|[0-9]?\d\.[0-9])$")
WARNING_LEVELS = {"Low", "Guarded", "Elevated", "High", "Severe", "Critical"}


class ReportValidationError(ValueError):
    """Raised when a DaylightSSV report is invalid."""


def _decimal(value: Any, field: str) -> Decimal:
    if not isinstance(value, str):
        raise ReportValidationError(f"{field} must be a string decimal")
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise ReportValidationError(f"{field} must be decimal") from exc


def _validate_public_score_text(text: Any, field: str = "score") -> Decimal:
    if not isinstance(text, str) or not SCORE_RE.fullmatch(text):
        raise ReportValidationError(f"{field} must be within 0.0-100.0 with exactly one decimal place")
    value = Decimal(text)
    if value < Decimal("0.0") or value > Decimal("100.0"):
        raise ReportValidationError(f"{field} outside 0.0-100.0")
    return value


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"invalid JSON: {exc}") from exc


def validate_report(report: dict[str, Any]) -> None:
    if not isinstance(report, dict):
        raise ReportValidationError("report must be an object")
    if report.get("schema") != "daylight.ssv.v1.report":
        raise ReportValidationError("schema must be daylight.ssv.v1.report")
    if report.get("tool") != TOOL:
        raise ReportValidationError("tool must be DaylightSSV")
    if report.get("version") != VERSION:
        raise ReportValidationError("version must be 1")
    if report.get("result") != "completed":
        raise ReportValidationError("result must be completed")

    score = _validate_public_score_text(report.get("score"))
    warning = report.get("warning")
    if not isinstance(warning, dict) or warning.get("level") not in WARNING_LEVELS or not warning.get("message"):
        raise ReportValidationError("warning level and message are required")

    domains = report.get("domains")
    if not isinstance(domains, list) or len(domains) != len(DOMAIN_ORDER):
        raise ReportValidationError("report must contain all 10 domains")
    if [domain.get("id") for domain in domains] != list(DOMAIN_ORDER):
        raise ReportValidationError("domains must be in configured order")

    weights: dict[str, Decimal] = {}
    raw_score = Decimal("0.0")
    for domain in domains:
        if not isinstance(domain, dict):
            raise ReportValidationError("domain entry must be object")
        domain_id = domain.get("id")
        if domain_id not in DOMAIN_WEIGHTS:
            raise ReportValidationError("domain id invalid")
        if domain.get("name") != DOMAIN_NAMES[domain_id]:
            raise ReportValidationError(f"domain name invalid: {domain_id}")
        weight = _decimal(domain.get("weight"), f"domain {domain_id} weight")
        weights[domain_id] = weight
        checks = domain.get("checks")
        if not isinstance(checks, list):
            raise ReportValidationError(f"domain {domain_id} checks must be list")
        denominator = Decimal("0.0")
        numerator = Decimal("0.0")
        for check in checks:
            if not isinstance(check, dict):
                raise ReportValidationError("check entry must be object")
            severity = check.get("severity")
            if severity not in SEVERITY_WEIGHTS:
                raise ReportValidationError("check severity invalid")
            if check.get("severity_weight") != SEVERITY_WEIGHTS[severity]:
                raise ReportValidationError("check severity weight mismatch")
            result = check.get("result")
            evidence_quality = check.get("evidence_quality")
            if result not in RESULT_VALUES:
                raise ReportValidationError("check result invalid")
            if evidence_quality not in EVIDENCE_QUALITY_VALUES:
                raise ReportValidationError("check evidence quality invalid")
            result_value = _decimal(check.get("result_value"), "result_value")
            evidence_quality_value = _decimal(check.get("evidence_quality_value"), "evidence_quality_value")
            if result_value != RESULT_VALUES[result]:
                raise ReportValidationError("result_value mismatch")
            if evidence_quality_value != EVIDENCE_QUALITY_VALUES[evidence_quality]:
                raise ReportValidationError("evidence_quality_value mismatch")
            value = _decimal(check.get("check_value"), "check_value")
            expected_value = check_value(result, evidence_quality)
            if value != expected_value:
                raise ReportValidationError("check_value mismatch")
            if value < Decimal("0.0") or value > Decimal("1.0"):
                raise ReportValidationError("check_value outside [0.0, 1.0]")
            if not isinstance(check.get("reason"), str) or not check.get("reason"):
                raise ReportValidationError("check reason required")
            if not isinstance(check.get("safe_remediation_hint"), str):
                raise ReportValidationError("safe_remediation_hint required")
            evidence = check.get("evidence")
            if not isinstance(evidence, list):
                raise ReportValidationError("check evidence must be list")
            for entry in evidence:
                if not isinstance(entry, dict):
                    raise ReportValidationError("evidence entry must be object")
                for key in ("type", "source", "value_summary"):
                    if not isinstance(entry.get(key), str):
                        raise ReportValidationError(f"evidence {key} required")
                source = entry["source"]
                summary = entry["value_summary"]
                if source.startswith("/") or "/home/" in source or "/Users/" in source:
                    raise ReportValidationError("evidence source must not contain absolute local path")
                if "-----BEGIN" in summary or "sk-" in summary or "github_pat_" in summary:
                    raise ReportValidationError("evidence summary must not contain secret material")
            denominator += Decimal(SEVERITY_WEIGHTS[severity])
            numerator += Decimal(SEVERITY_WEIGHTS[severity]) * value
        domain_score = Decimal("0.0") if denominator == 0 else numerator / denominator
        raw_score += weight * domain_score
    try:
        validate_domain_weights(weights)
    except ScoreModelError as exc:
        raise ReportValidationError(str(exc)) from exc

    if public_score(raw_score) != score:
        raise ReportValidationError("score does not recompute from domain checks")

    summary = report.get("summary")
    if not isinstance(summary, dict) or summary.get("domains_total") != 10:
        raise ReportValidationError("summary missing domains_total")
    reasons = report.get("reasons")
    if not isinstance(reasons, list):
        raise ReportValidationError("reasons must be list")
    if score < Decimal("100.0") and not reasons:
        raise ReportValidationError("score below 100.0 requires reasons")

    boundary = report.get("non_claim_boundary")
    if not isinstance(boundary, dict):
        raise ReportValidationError("non_claim_boundary required")
    for key in (
        "certifies_security",
        "certifies_production_readiness",
        "certifies_audit_status",
        "certifies_post_quantum_security",
        "implies_agency_endorsement",
        "proves_mathematical_finality",
    ):
        if boundary.get(key) is not False:
            raise ReportValidationError(f"non_claim_boundary {key} must be false")


def validate_report_file(path: Path) -> None:
    data = _load_json(path)
    validate_report(data)
