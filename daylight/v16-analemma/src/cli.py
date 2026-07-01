"""Command-line interface for Daylight v16 Analemma."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import analemma
from . import solstice_bridge


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SOLSTICE_ARTIFACT = REPO_ROOT / "build" / "daylight" / "v15-solstice"
DEFAULT_ANALEMMA_OUT = REPO_ROOT / "build" / "daylight" / "v16-analemma"

CLI_ERRORS = (
    analemma.AnalemmaError,
    solstice_bridge.SolsticeBridgeError,
    FileNotFoundError,
    json.JSONDecodeError,
)


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value else None


def _json_dump(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _basis_points_to_one_decimal_percent(value: int) -> str:
    sign = "+" if value >= 0 else "-"
    tenths = abs(value) // 10
    return f"{sign}{tenths // 10}.{tenths % 10}%"


def _summary(report: dict[str, Any]) -> str:
    return (
        f"{report['name']}\n"
        f"  D_claim_M:                  {report['D_claim_M']} / 1000000\n"
        f"  A_self_A:                   {report['A_self_A']}A\n"
        f"  proof_mass_growth:          {_basis_points_to_one_decimal_percent(report['proof_mass_growth_basis_points'])}\n"
        f"  E_trust_M:                  {report['E_trust_M']} / 1000000\n"
        f"  C_level:                    {report['C_level']}\n"
        f"  proof_mass:                 {report['proof_mass']}\n"
        f"  delta_since_baseline_A:     {report['delta_since_baseline_A']}A\n"
        f"  regression_debt_A:          {report['regression_debt_A']}A\n"
        f"  staleness_debt_A:           {report['staleness_debt_A']}A\n"
        f"  score_inflation_M:          {report['score_inflation_M']}"
    )


def cmd_verify_artifact(args: argparse.Namespace) -> int:
    report, _ = analemma.build_report(
        Path(args.artifact_dir),
        registry_path=Path(args.registry),
        evidence_path=_optional_path(args.evidence),
        history_path=_optional_path(args.history),
    )
    if args.json:
        _json_dump(report)
    else:
        print(_summary(report))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    manifest = analemma.build_report_artifact(
        Path(args.artifact_dir),
        out_dir=Path(args.out_dir),
        registry_path=Path(args.registry),
        evidence_path=_optional_path(args.evidence),
        history_path=_optional_path(args.history),
    )
    print(f"analemma report written to {args.out_dir}")
    print(f"  D_claim_M: {manifest['D_claim_M']} / 1000000")
    print(f"  A_self_A: {manifest['A_self_A']}A")
    print(f"  E_trust_M: {manifest['E_trust_M']} / 1000000")
    print(f"  C_level: {manifest['C_level']}")
    return 0


def cmd_verify_report(args: argparse.Namespace) -> int:
    analemma.verify_report_dir(Path(args.report_dir))
    print("analemma report: pass")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-analemma", description="Daylight v16 Analemma self-progress verifier")
    parser.add_argument("--version", action="version", version=f"daylight-analemma {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify-artifact", help="verify a Solstice artifact and compute Analemma self-progress")
    verify.add_argument("artifact_dir", nargs="?", default=str(DEFAULT_SOLSTICE_ARTIFACT))
    verify.add_argument("--registry", default=str(analemma.DEFAULT_REGISTRY), help="Analemma proof-unit registry")
    verify.add_argument("--evidence", help="optional Analemma evidence JSON")
    verify.add_argument("--history", help="optional Analemma history JSON")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify_artifact)

    report = sub.add_parser("report", help="write Analemma report, resolution, manifest, and SHA256SUMS")
    report.add_argument("artifact_dir", nargs="?", default=str(DEFAULT_SOLSTICE_ARTIFACT))
    report.add_argument("--registry", default=str(analemma.DEFAULT_REGISTRY), help="Analemma proof-unit registry")
    report.add_argument("--evidence", help="optional Analemma evidence JSON")
    report.add_argument("--history", help="optional Analemma history JSON")
    report.add_argument("--out-dir", default=str(DEFAULT_ANALEMMA_OUT))
    report.set_defaults(func=cmd_report)

    verify_report = sub.add_parser("verify-report", help="verify a generated Analemma report directory")
    verify_report.add_argument("report_dir", nargs="?", default=str(DEFAULT_ANALEMMA_OUT))
    verify_report.set_defaults(func=cmd_verify_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CLI_ERRORS as exc:
        print(f"daylight-analemma: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
