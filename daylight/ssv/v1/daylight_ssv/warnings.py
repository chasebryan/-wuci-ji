"""Warning level derivation for DaylightSSV v1."""

from __future__ import annotations

from decimal import Decimal
from typing import Iterable

from .model import CheckResult

WARNING_MESSAGES = {
    "Low": "Low warning - strong evidence posture",
    "Guarded": "Guarded - mostly controlled, review remaining issues",
    "Elevated": "Elevated - notable hardening gaps",
    "High": "High - significant security gaps",
    "Severe": "Severe - major exposure or missing evidence",
    "Critical": "Critical - immediate review required",
}

WARNING_RANK = {
    "Low": 0,
    "Guarded": 1,
    "Elevated": 2,
    "High": 3,
    "Severe": 4,
    "Critical": 5,
}


def base_warning(score: Decimal) -> str:
    if score >= Decimal("93.0"):
        return "Low"
    if score >= Decimal("85.0"):
        return "Guarded"
    if score >= Decimal("75.0"):
        return "Elevated"
    if score >= Decimal("65.0"):
        return "High"
    if score >= Decimal("50.0"):
        return "Severe"
    return "Critical"


def _at_least(current: str, minimum: str) -> str:
    return minimum if WARNING_RANK[minimum] > WARNING_RANK[current] else current


def warning_for(score: Decimal, checks: Iterable[CheckResult], evidence_coverage_percent: Decimal) -> dict[str, object]:
    level = base_warning(score)
    overrides: list[str] = []
    check_list = list(checks)

    if any(check.severity == "critical" and check.result == "fail" for check in check_list):
        level = _at_least(level, "Critical")
        overrides.append("critical_failed_check")
    if any("exposed_secret" in check.flags for check in check_list):
        level = _at_least(level, "Critical")
        overrides.append("exposed_secret")
    if any("remote_unauthenticated_admin_path" in check.flags for check in check_list):
        level = _at_least(level, "Critical")
        overrides.append("remote_unauthenticated_admin_path")
    if any(check.severity == "high" and check.result == "fail" for check in check_list):
        level = _at_least(level, "High")
        overrides.append("high_failed_check")
    if evidence_coverage_percent < Decimal("80.0"):
        level = _at_least(level, "Elevated")
        overrides.append("evidence_coverage_below_80_percent")

    return {
        "level": level,
        "message": WARNING_MESSAGES[level],
        "overrides": sorted(dict.fromkeys(overrides)),
    }

