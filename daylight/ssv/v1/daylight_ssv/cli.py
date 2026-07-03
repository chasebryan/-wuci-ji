"""CLI for DaylightSSV v1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import FULL_NAME, TOOL, VERSION
from .math import domain_weight_total, quantized_text, validate_domain_weights
from .model import DOMAIN_DEFINITIONS
from .report import build_live_report, dumps_stable, pretty_summary, report_warning_exit_code, write_report
from .schema import ReportValidationError, validate_report, validate_report_file

DEFAULT_REPORT = Path("build/daylight/ssv-v1/daylight-ssv.report.json")


class CommandError(Exception):
    """Expected CLI error."""


def _load_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CommandError(f"could not read report: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CommandError(f"invalid report JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CommandError("report must be a JSON object")
    return data


def cmd_audit(args: argparse.Namespace) -> int:
    report = build_live_report(Path(args.repo_root) if args.repo_root else None)
    if args.out:
        write_report(Path(args.out), report)
    if args.json:
        sys.stdout.write(dumps_stable(report))
    elif args.pretty or not args.out:
        sys.stdout.write(pretty_summary(report))
    return report_warning_exit_code(report)


def cmd_explain(args: argparse.Namespace) -> int:
    path = Path(args.report)
    report = _load_report(path)
    validate_report(report)
    target = args.finding_id
    for reason in report.get("reasons", []):
        if reason.get("id") == target:
            print(f"{reason['id']}: {reason['domain']} lost {reason['loss']} points because {reason['reason']}")
            return 0
    for finding in report.get("findings", []):
        if finding.get("id") == target:
            print(f"{finding['id']}: {finding['domain']} {finding['severity']} {finding['result']} - {finding['reason']}")
            return 0
    raise CommandError(f"finding not found: {target}")


def cmd_check_model(args: argparse.Namespace) -> int:
    validate_domain_weights()
    print(f"{TOOL} v{VERSION}: {FULL_NAME}")
    print(f"domain_weights_total: {quantized_text(domain_weight_total(), 1)}")
    print("rounding: ROUND_HALF_UP to one decimal place")
    print("non_claim_boundary: score validator, not a security certificate")
    return 0


def cmd_list_domains(args: argparse.Namespace) -> int:
    for domain_id, name, weight in DOMAIN_DEFINITIONS:
        print(f"{domain_id}\t{quantized_text(weight, 1)}\t{name}")
    return 0


def cmd_validate_report(args: argparse.Namespace) -> int:
    validate_report_file(Path(args.report))
    print(f"valid: {args.report}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight_ssv", description="DaylightSSV v1 local system security posture score validator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="run a local read-only posture audit")
    audit.add_argument("--out", help="write deterministic report JSON")
    audit.add_argument("--json", action="store_true", help="print report JSON to stdout")
    audit.add_argument("--pretty", action="store_true", help="print human-readable summary")
    audit.add_argument("--repo-root", help="repository root to inspect")
    audit.set_defaults(func=cmd_audit)

    explain = subparsers.add_parser("explain", help="explain a finding id from a report")
    explain.add_argument("finding_id")
    explain.add_argument("--report", default=str(DEFAULT_REPORT), help="report path")
    explain.set_defaults(func=cmd_explain)

    check_model = subparsers.add_parser("check-model", help="validate the fixed scoring model")
    check_model.set_defaults(func=cmd_check_model)

    list_domains = subparsers.add_parser("list-domains", help="list fixed top-level domains")
    list_domains.set_defaults(func=cmd_list_domains)

    validate = subparsers.add_parser("validate-report", help="validate and recompute a report")
    validate.add_argument("report")
    validate.set_defaults(func=cmd_validate_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CommandError, ReportValidationError, ValueError) as exc:
        print(f"daylight_ssv: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

