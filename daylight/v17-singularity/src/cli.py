"""Command-line interface for Daylight v17 Singularity."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .canonical_json import json_bytes, load_json_no_floats
from . import registry
from . import scorecard
from .singularity_math import OMEGA_THRESHOLD, decimal_text, require_decimal_runtime


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE_STATE = PACKAGE_ROOT / "examples" / "state.baseline.json"
DEFAULT_BASELINE_SCORECARD = PACKAGE_ROOT / "examples" / "expected-scorecard.baseline.v17.json"
DEFAULT_FIXTURE_STATE = PACKAGE_ROOT / "examples" / "state.declaration-fixture.json"
DEFAULT_FIXTURE_SCORECARD = PACKAGE_ROOT / "examples" / "expected-scorecard.declaration-fixture.v17.json"


def _print_json(value: Any) -> None:
    sys.stdout.buffer.write(json_bytes(value))


def _text_summary(card: dict[str, Any]) -> str:
    return (
        "Daylight v17 Singularity\n"
        f"score_AM_plus: {card['score_AM_plus']}\n"
        f"unit: {card['unit']}\n"
        f"omega: {card['omega_decimal']}\n"
        f"residue: {card['residue_decimal']}\n"
        f"declared: {str(card['declared']).lower()}\n"
        f"status: {card['status']}\n"
        "boundary: research scoring layer, not certification"
    )


def _write_or_print(card: dict[str, Any], out: str | None, output_format: str) -> None:
    if out:
        Path(out).write_bytes(json_bytes(card))
    if output_format == "json":
        _print_json(card)
    else:
        print(_text_summary(card))


def cmd_score(args: argparse.Namespace) -> int:
    card = scorecard.build_scorecard_from_paths(state_path=args.state, fields_path=args.fields)
    _write_or_print(card, args.out, args.format)
    return 0


def cmd_verify_scorecard(args: argparse.Namespace) -> int:
    scorecard.verify_scorecard_path(scorecard_path=args.scorecard, state_path=args.state, fields_path=args.fields)
    if args.format == "json":
        _print_json({"ok": True, "scorecard": str(args.scorecard)})
    else:
        print("daylight-v17-singularity: scorecard verified")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    card = load_json_no_floats(args.scorecard)
    if args.format == "json":
        _print_json(card)
    else:
        print(_text_summary(card))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    require_decimal_runtime()
    fields_registry = registry.load_fields_registry(args.fields)
    payload = {
        "ok": True,
        "decimal_ln_exp": True,
        "alpha_sum": f"{registry.alpha_sum(fields_registry).numerator}/{registry.alpha_sum(fields_registry).denominator}",
        "omega_threshold_decimal": decimal_text(OMEGA_THRESHOLD),
        "fields_digest": registry.proof_registry_digest(fields_registry),
    }
    if args.format == "json":
        _print_json(payload)
    else:
        print("daylight-v17-singularity: doctor pass")
        print(f"alpha_sum: {payload['alpha_sum']}")
        print(f"omega_threshold_decimal: {payload['omega_threshold_decimal']}")
    return 0


def cmd_fixture_demo(args: argparse.Namespace) -> int:
    card = scorecard.build_scorecard_from_paths(state_path=args.state, fields_path=args.fields)
    if not card["fixture"] or card["claim_usable"] is not False:
        raise ValueError("fixture demo state must be fixture=true and claim_usable=false")
    _write_or_print(card, args.out, args.format)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-v17-singularity")
    parser.add_argument("--version", action="version", version=f"daylight-v17-singularity {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    score = sub.add_parser("score")
    score.add_argument("--state", required=True)
    score.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    score.add_argument("--out")
    score.add_argument("--format", choices=("text", "json"), default="text")
    score.set_defaults(func=cmd_score)

    verify = sub.add_parser("verify-scorecard")
    verify.add_argument("scorecard")
    verify.add_argument("--state", required=True)
    verify.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    verify.add_argument("--format", choices=("text", "json"), default="text")
    verify.set_defaults(func=cmd_verify_scorecard)

    explain = sub.add_parser("explain")
    explain.add_argument("--scorecard", required=True)
    explain.add_argument("--format", choices=("text", "json"), default="text")
    explain.set_defaults(func=cmd_explain)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.set_defaults(func=cmd_doctor)

    fixture = sub.add_parser("fixture-demo")
    fixture.add_argument("--state", default=str(DEFAULT_FIXTURE_STATE))
    fixture.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    fixture.add_argument("--out", default=str(DEFAULT_FIXTURE_SCORECARD))
    fixture.add_argument("--format", choices=("text", "json"), default="text")
    fixture.set_defaults(func=cmd_fixture_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, KeyError, ValueError) as exc:
        print(f"daylight-v17-singularity: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
