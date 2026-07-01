"""Command-line interface for Daylight v16 Zenith."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import solstice_bridge
from . import zenith_verifier


DEFAULT_SOLSTICE_ARTIFACT = Path(__file__).resolve().parents[3] / "build" / "daylight" / "v15-solstice"
DEFAULT_ZENITH_OUT = Path(__file__).resolve().parents[3] / "build" / "daylight" / "v16-zenith"


CLI_ERRORS = (
    zenith_verifier.ZenithError,
    solstice_bridge.SolsticeBridgeError,
    FileNotFoundError,
    json.JSONDecodeError,
)


def _json_dump(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _summary(report: dict[str, Any]) -> str:
    return (
        f"{report['name']}\n"
        f"  solstice_score_M:        {report['solstice_score_M']} / 1000000\n"
        f"  zenith_adjusted_score_M: {report['zenith_adjusted_score_M']} / 1000000\n"
        f"  score_inflation_M:       {report['score_inflation_M']}\n"
        f"  zenith_assurance_M:      {report['zenith_assurance_M']} / 1000000\n"
        f"  zenith_level:            {report['zenith_level']}\n"
        f"  dz1_pass:                {report['dz1_pass']}\n"
        f"  dz2_production_eligible: {report['dz2_production_eligible']}"
    )


def cmd_verify_artifact(args: argparse.Namespace) -> int:
    report, _ = zenith_verifier.build_report(
        Path(args.artifact_dir),
        evidence_path=Path(args.evidence) if args.evidence else None,
    )
    if args.json:
        _json_dump(report)
    else:
        print(_summary(report))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    manifest = zenith_verifier.build_report_artifact(
        solstice_artifact_dir=Path(args.artifact_dir),
        out_dir=Path(args.out_dir),
        evidence_path=Path(args.evidence) if args.evidence else None,
    )
    print(f"zenith report written to {args.out_dir}")
    print(f"  solstice_score_M: {manifest['solstice_score_M']} / 1000000")
    print(f"  zenith_assurance_M: {manifest['zenith_assurance_M']} / 1000000")
    print(f"  zenith_level: {manifest['zenith_level']}")
    return 0


def cmd_verify_report(args: argparse.Namespace) -> int:
    zenith_verifier.verify_report_dir(Path(args.report_dir))
    print("zenith report: pass")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-zenith", description="Daylight v16 Zenith verifier")
    parser.add_argument("--version", action="version", version=f"daylight-zenith {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify-artifact", help="verify a Solstice artifact and compute Zenith assurance")
    verify.add_argument("artifact_dir", nargs="?", default=str(DEFAULT_SOLSTICE_ARTIFACT))
    verify.add_argument("--evidence", help="optional Zenith evidence JSON")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify_artifact)

    report = sub.add_parser("report", help="write Zenith report, resolution, manifest, and SHA256SUMS")
    report.add_argument("artifact_dir", nargs="?", default=str(DEFAULT_SOLSTICE_ARTIFACT))
    report.add_argument("--evidence", help="optional Zenith evidence JSON")
    report.add_argument("--out-dir", default=str(DEFAULT_ZENITH_OUT))
    report.set_defaults(func=cmd_report)

    verify_report = sub.add_parser("verify-report", help="verify a generated Zenith report directory")
    verify_report.add_argument("report_dir", nargs="?", default=str(DEFAULT_ZENITH_OUT))
    verify_report.set_defaults(func=cmd_verify_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CLI_ERRORS as exc:
        print(f"daylight-zenith: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
