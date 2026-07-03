from __future__ import annotations

from typing import Iterable

from daylight_ssv.model import DOMAIN_ORDER, CheckResult, Evidence
from daylight_ssv.report import build_report_from_checks


def make_check(
    domain: str,
    check_id: str,
    *,
    severity: str = "medium",
    result: str = "pass",
    evidence_quality: str = "strong",
    flags: Iterable[str] = (),
) -> CheckResult:
    return CheckResult(
        id=check_id,
        domain_id=domain,
        severity=severity,
        result=result,
        evidence_quality=evidence_quality,
        evidence=(Evidence("generated_report", f"test:{check_id}", "test evidence"),),
        reason=f"{check_id} reason",
        safe_remediation_hint=f"{check_id} hint",
        flags=frozenset(flags),
    )


def domain_checks(*, result: str = "pass", evidence_quality: str = "strong", severity: str = "medium") -> list[CheckResult]:
    return [
        make_check(domain, f"{domain}.fixture", severity=severity, result=result, evidence_quality=evidence_quality)
        for domain in DOMAIN_ORDER
    ]


def report_for(checks: list[CheckResult]) -> dict:
    return build_report_from_checks(checks)

