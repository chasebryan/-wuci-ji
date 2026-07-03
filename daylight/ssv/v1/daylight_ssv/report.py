"""Deterministic report generation for DaylightSSV v1."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable

from . import TOOL, VERSION
from .checks import build_checks
from .collectors import collect_all
from .math import quantized_text, score_checks
from .model import CheckResult
from .schema import validate_report
from .warnings import warning_for

NON_CLAIM_STATEMENT = (
    "DaylightSSV v1 produces an evidence-derived system security posture score. "
    "It does not certify security. It does not prove the system is secure. "
    "It does not replace penetration testing, formal verification, external audit, "
    "or operational review. It reports what the scanner could verify from available "
    "evidence at runtime."
)


def dumps_stable(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def build_report_from_checks(checks: Iterable[CheckResult]) -> dict[str, Any]:
    check_list = list(checks)
    scored = score_checks(check_list)
    evidence_coverage = Decimal(scored["summary"]["evidence_coverage"])
    warning = warning_for(scored["final_score"], check_list, evidence_coverage)
    report = {
        "schema": "daylight.ssv.v1.report",
        "tool": TOOL,
        "version": VERSION,
        "result": "completed",
        "score": quantized_text(scored["final_score"], 1),
        "warning": warning,
        "summary": scored["summary"],
        "domains": scored["domains"],
        "findings": scored["findings"],
        "reasons": scored["reasons"],
        "non_claim_boundary": {
            "certifies_security": False,
            "certifies_production_readiness": False,
            "certifies_audit_status": False,
            "certifies_post_quantum_security": False,
            "implies_agency_endorsement": False,
            "proves_mathematical_finality": False,
            "statement": NON_CLAIM_STATEMENT,
        },
    }
    validate_report(report)
    return report


def build_live_report(repo_root: Path | None = None) -> dict[str, Any]:
    facts = collect_all(repo_root)
    return build_report_from_checks(build_checks(facts))


def write_report(path: Path, report: dict[str, Any]) -> None:
    validate_report(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(dumps_stable(report), encoding="utf-8")
    tmp.replace(path)


def pretty_summary(report: dict[str, Any]) -> str:
    warning = report["warning"]
    lines = [
        f"DaylightSSV v1 ({report['tool']})",
        f"Score: {report['score']} / 100.0",
        f"Warning: {warning['message']}",
        f"Overrides: {', '.join(warning['overrides']) if warning['overrides'] else 'none'}",
        f"Checks: {report['summary']['checks_total']} total; pass={report['summary']['checks_pass']}; partial={report['summary']['checks_partial']}; fail={report['summary']['checks_fail']}; unknown={report['summary']['checks_unknown']}",
        f"Evidence coverage: {report['summary']['evidence_coverage']}%",
        NON_CLAIM_STATEMENT,
    ]
    if report["reasons"]:
        lines.append("Largest losses:")
        for reason in report["reasons"][:10]:
            lines.append(f"- {reason['domain']} lost {reason['loss']} points because {reason['reason']}")
    return "\n".join(lines) + "\n"


def report_warning_exit_code(report: dict[str, Any]) -> int:
    return 1 if report["warning"]["level"] in {"Severe", "Critical"} else 0

