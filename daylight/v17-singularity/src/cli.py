"""Command-line interface for Daylight v17 Singularity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import singularity
from .canonical_json import CanonicalJSONError, json_bytes, load_json_path


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SOLSTICE = REPO_ROOT / "build" / "daylight" / "v15-solstice"
DEFAULT_ZENITH = REPO_ROOT / "build" / "daylight" / "v16-zenith"
DEFAULT_ANALEMMA = REPO_ROOT / "build" / "daylight" / "v16-analemma"
DEFAULT_OUT = REPO_ROOT / "build" / "daylight" / "v17-singularity"


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value else None


def _json_dump(value: Any) -> None:
    sys.stdout.buffer.write(json_bytes(value))


def _summary(scorecard: dict[str, Any]) -> str:
    collapse = scorecard["collapse_state"]
    return (
        f"{scorecard['name']}\n"
        f"  score_AM_plus:       {scorecard['score_AM_plus']} / {scorecard['perfect_reserved_AM_plus']}\n"
        f"  declared:            {scorecard['declared']}\n"
        f"  omega:               {scorecard['omega']}\n"
        f"  residue:             {scorecard['residue']}\n"
        f"  threshold_ln_B:      {scorecard['threshold_ln_B']}\n"
        f"  collapsed:           {collapse['collapsed']}\n"
        f"  collapse_reasons:    {', '.join(collapse['reasons']) if collapse['reasons'] else 'none'}"
    )


def cmd_score(args: argparse.Namespace) -> int:
    scorecard, _ = singularity.build_scorecard(
        solstice_artifact_dir=Path(args.solstice_artifact),
        zenith_report_dir=_optional_path(args.zenith_report),
        analemma_report_dir=_optional_path(args.analemma_report),
        evidence_path=_optional_path(args.evidence),
        registry_path=Path(args.registry),
    )
    if args.json:
        _json_dump(scorecard)
    else:
        print(_summary(scorecard))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    manifest = singularity.build_report_artifact(
        solstice_artifact_dir=Path(args.solstice_artifact),
        zenith_report_dir=_optional_path(args.zenith_report),
        analemma_report_dir=_optional_path(args.analemma_report),
        evidence_path=_optional_path(args.evidence),
        registry_path=Path(args.registry),
        out_dir=Path(args.out_dir),
    )
    print(f"singularity report written to {args.out_dir}")
    print(f"  score_AM_plus: {manifest['score_AM_plus']} / {singularity.S_PERFECT_RESERVED}")
    print(f"  declared: {manifest['declared']}")
    print(f"  collapsed: {manifest['collapse_state']['collapsed']}")
    return 0


def cmd_verify_report(args: argparse.Namespace) -> int:
    singularity.verify_report_dir(Path(args.report_dir))
    print("singularity report: pass")
    return 0


def cmd_verify_scorecard(args: argparse.Namespace) -> int:
    scorecard = load_json_path(args.scorecard)
    singularity.verify_scorecard_integrity(scorecard)
    print("singularity scorecard: pass")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-singularity", description="Daylight v17 Singularity residue-collapse verifier")
    parser.add_argument("--version", action="version", version=f"daylight-singularity {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common: dict[str, Any] = {}
    score = sub.add_parser("score", help="compute the v17 Singularity scorecard")
    score.add_argument("--solstice-artifact", default=str(DEFAULT_SOLSTICE))
    score.add_argument("--zenith-report", default=str(DEFAULT_ZENITH))
    score.add_argument("--analemma-report", default=str(DEFAULT_ANALEMMA))
    score.add_argument("--evidence")
    score.add_argument("--registry", default=str(singularity.DEFAULT_REGISTRY))
    score.add_argument("--json", action="store_true")
    score.set_defaults(func=cmd_score)

    report = sub.add_parser("report", help="write Singularity scorecard, resolution, manifest, and SHA256SUMS")
    report.add_argument("--solstice-artifact", default=str(DEFAULT_SOLSTICE))
    report.add_argument("--zenith-report", default=str(DEFAULT_ZENITH))
    report.add_argument("--analemma-report", default=str(DEFAULT_ANALEMMA))
    report.add_argument("--evidence")
    report.add_argument("--registry", default=str(singularity.DEFAULT_REGISTRY))
    report.add_argument("--out-dir", default=str(DEFAULT_OUT))
    report.set_defaults(func=cmd_report)

    verify_report = sub.add_parser("verify-report", help="verify a generated Singularity report directory")
    verify_report.add_argument("report_dir", nargs="?", default=str(DEFAULT_OUT))
    verify_report.set_defaults(func=cmd_verify_report)

    verify_scorecard = sub.add_parser("verify-scorecard", help="verify internal scorecard anti-fake invariants")
    verify_scorecard.add_argument("scorecard")
    verify_scorecard.set_defaults(func=cmd_verify_scorecard)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, KeyError, ValueError, CanonicalJSONError, singularity.SingularityError) as exc:
        print(f"daylight-singularity: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

