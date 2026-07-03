"""Command line interface for DaylightNPT v1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .classify import FINDING_EXPLANATIONS
from .registry import RegistryError, load_registry, validate_registry
from .report import dumps_stable, scan

DEFAULT_INPUTS = ["README.md", "BUILD_NOTES.md", "SECURITY.md", "docs", "daylight", "site", "data"]
DEFAULT_REGISTRY = "daylight/npt/v1/number-claims.registry.json"
DEFAULT_OUT = "build/daylight/npt-v1/daylight-npt.report.json"


def _repo_root() -> Path:
    return Path.cwd()


def cmd_scan(args: argparse.Namespace) -> int:
    root = _repo_root()
    registry_path = root / args.registry
    try:
        registry = load_registry(registry_path)
        report = scan(registry, registry_path, args.inputs or DEFAULT_INPUTS, root)
    except (RegistryError, OSError, ValueError) as exc:
        print(f"daylight-npt: internal/configuration error: {exc}", file=sys.stderr)
        return 2
    result_text = dumps_stable(report)
    if args.out:
        out_path = root / args.out
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result_text, encoding="utf-8")
    if args.json:
        print(result_text, end="")
    elif not args.out:
        print(f"result: {report['result']}")
        print(f"errors: {report['summary']['errors']}")
        print(f"warnings: {report['summary']['warnings']}")
    if report["summary"]["errors"] or (args.strict and report["summary"]["warnings"]):
        return 1
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    text = FINDING_EXPLANATIONS.get(args.finding_id)
    if text is None:
        print(f"unknown finding code: {args.finding_id}", file=sys.stderr)
        return 2
    print(f"{args.finding_id}: {text}")
    return 0


def cmd_check_registry(args: argparse.Namespace) -> int:
    try:
        validate_registry(load_registry(Path(args.registry)))
    except (RegistryError, OSError, ValueError) as exc:
        print(f"registry invalid: {exc}", file=sys.stderr)
        return 2
    print("registry: OK")
    return 0


def cmd_list_claims(args: argparse.Namespace) -> int:
    try:
        registry = load_registry(Path(args.registry))
    except (RegistryError, OSError, ValueError) as exc:
        print(f"registry invalid: {exc}", file=sys.stderr)
        return 2
    for claim in registry.get("claims", []):
        print(f"{claim['id']}\t{claim['status']}\t{claim['claim_type']}\t{claim['value_raw']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight_npt")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("inputs", nargs="*")
    scan_parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    scan_parser.add_argument("--out", default=None)
    scan_parser.add_argument("--strict", action="store_true")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.set_defaults(func=cmd_scan)

    explain = sub.add_parser("explain")
    explain.add_argument("finding_id")
    explain.set_defaults(func=cmd_explain)

    check = sub.add_parser("check-registry")
    check.add_argument("--registry", default=DEFAULT_REGISTRY)
    check.set_defaults(func=cmd_check_registry)

    list_claims = sub.add_parser("list-claims")
    list_claims.add_argument("--registry", default=DEFAULT_REGISTRY)
    list_claims.set_defaults(func=cmd_list_claims)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

