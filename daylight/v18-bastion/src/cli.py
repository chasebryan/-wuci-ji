"""CLI for Daylight v18 Binaric Bastion."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .canonical_json import json_bytes
from . import binaric_vector
from . import tamper_logic
from . import transition_ledger
from . import user_ceremony


def _print_json(value: Any) -> None:
    sys.stdout.buffer.write(json_bytes(value))


def _print_text(value: dict[str, Any]) -> None:
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            continue
        print(f"{key}: {item}")
    if value.get("blockers"):
        print("blockers:")
        for blocker in value["blockers"]:
            print(f"  - {blocker}")


def _emit(value: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        _print_json(value)
    else:
        _print_text(value)


def cmd_measure(args: argparse.Namespace) -> int:
    vector = binaric_vector.measure_subject(
        subject_path=args.subject,
        out_path=args.out,
        base_dir=Path.cwd(),
        event_horizon_scorecard_path=args.event_horizon_scorecard,
        policy_digest=args.policy_digest,
        previous_vector_digest=args.previous_vector_digest,
        user_verification_digest=args.user_verification_digest,
    )
    _emit(vector, args.format)
    return 0


def cmd_verify_vector(args: argparse.Namespace) -> int:
    result = binaric_vector.verify_vector_file(args.vector, base_dir=Path.cwd())
    _emit(result, args.format)
    return 0 if result["verified"] else 1


def cmd_inspect_vector(args: argparse.Namespace) -> int:
    result = binaric_vector.inspect_vector(args.vector)
    _emit(result, args.format)
    return 0


def cmd_tamper_check(args: argparse.Namespace) -> int:
    passphrase = None
    if args.transition and args.ledger and not args.legacy_digest_marker:
        try:
            passphrase = user_ceremony.passphrase_from_env(args.passphrase_env)
        except user_ceremony.UserCeremonyError:
            passphrase = None
    result = tamper_logic.tamper_check_files(
        args.before,
        args.after,
        transition_path=args.transition,
        ledger_path=args.ledger,
        passphrase=passphrase,
        legacy_digest_marker=args.legacy_digest_marker,
    )
    _emit(result, args.format)
    return 0 if result["transition_allowed"] else 1


def cmd_user_challenge(args: argparse.Namespace) -> int:
    before = binaric_vector.load_vector(args.before)
    after = binaric_vector.load_vector(args.after)
    challenge = transition_ledger.make_challenge(before, after, args.reason)
    Path(args.out).write_bytes(json_bytes(challenge))
    _emit(challenge, args.format)
    return 0


def cmd_transition_propose(args: argparse.Namespace) -> int:
    before = binaric_vector.load_vector(args.before)
    after = binaric_vector.load_vector(args.after)
    transition = transition_ledger.propose_transition(
        before,
        after,
        reason=args.reason,
        transition_id=args.transition_id,
        user_id=args.user_id,
    )
    Path(args.out).write_bytes(json_bytes(transition))
    _emit(transition, args.format)
    return 0


def cmd_transition_sign(args: argparse.Namespace) -> int:
    transition = transition_ledger.load_transition(args.transition, require_proof=False)
    passphrase = user_ceremony.passphrase_from_env(args.passphrase_env)
    signed = transition_ledger.sign_transition(transition, passphrase)
    Path(args.out).write_bytes(json_bytes(signed))
    _emit({"transition_digest": transition_ledger.transition_digest(signed), "signed": True}, args.format)
    return 0


def cmd_transition_verify(args: argparse.Namespace) -> int:
    before = binaric_vector.load_vector(args.before)
    after = binaric_vector.load_vector(args.after)
    transition = transition_ledger.load_transition(args.transition)
    try:
        passphrase = user_ceremony.passphrase_from_env(args.passphrase_env)
    except user_ceremony.UserCeremonyError:
        passphrase = None
    result = transition_ledger.verify_transition(before, after, transition, passphrase=passphrase)
    _emit(result, args.format)
    return 0 if result["transition_valid"] else 1


def cmd_transition_ledger_init(args: argparse.Namespace) -> int:
    genesis = transition_ledger.init_ledger(args.out)
    _emit(genesis, args.format)
    return 0


def cmd_transition_ledger_append(args: argparse.Namespace) -> int:
    transition = transition_ledger.load_transition(args.transition)
    entry = transition_ledger.append_transition(args.ledger, transition)
    _emit(entry, args.format)
    return 0


def cmd_transition_ledger_verify(args: argparse.Namespace) -> int:
    result = transition_ledger.verify_ledger_file(args.ledger)
    _emit(result, args.format)
    return 0 if result["ledger_valid"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-v18-bastion")
    parser.add_argument("--version", action="version", version=f"daylight-v18-bastion {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    measure = sub.add_parser("measure")
    measure.add_argument("--subject", required=True)
    measure.add_argument("--out", required=True)
    measure.add_argument("--event-horizon-scorecard")
    measure.add_argument("--policy-digest", default=binaric_vector.DEFAULT_POLICY_DIGEST)
    measure.add_argument("--previous-vector-digest")
    measure.add_argument("--user-verification-digest")
    measure.add_argument("--format", choices=("text", "json"), default="text")
    measure.set_defaults(func=cmd_measure)

    verify = sub.add_parser("verify-vector")
    verify.add_argument("vector")
    verify.add_argument("--format", choices=("text", "json"), default="text")
    verify.set_defaults(func=cmd_verify_vector)

    inspect = sub.add_parser("inspect-vector")
    inspect.add_argument("vector")
    inspect.add_argument("--format", choices=("text", "json"), default="text")
    inspect.set_defaults(func=cmd_inspect_vector)

    tamper = sub.add_parser("tamper-check")
    tamper.add_argument("--before", required=True)
    tamper.add_argument("--after", required=True)
    tamper.add_argument("--transition")
    tamper.add_argument("--ledger")
    tamper.add_argument("--passphrase-env", default="DAYLIGHT_BASTION_PASSPHRASE")
    tamper.add_argument("--legacy-digest-marker", action="store_true")
    tamper.add_argument("--format", choices=("text", "json"), default="text")
    tamper.set_defaults(func=cmd_tamper_check)

    challenge = sub.add_parser("user-challenge")
    challenge.add_argument("--before", required=True)
    challenge.add_argument("--after", required=True)
    challenge.add_argument("--out", required=True)
    challenge.add_argument("--reason", default="user-approved binary update")
    challenge.add_argument("--format", choices=("text", "json"), default="text")
    challenge.set_defaults(func=cmd_user_challenge)

    propose = sub.add_parser("transition-propose")
    propose.add_argument("--before", required=True)
    propose.add_argument("--after", required=True)
    propose.add_argument("--reason", required=True)
    propose.add_argument("--out", required=True)
    propose.add_argument("--transition-id", default="transition-0001")
    propose.add_argument("--user-id", default="local-user")
    propose.add_argument("--format", choices=("text", "json"), default="text")
    propose.set_defaults(func=cmd_transition_propose)

    sign = sub.add_parser("transition-sign")
    sign.add_argument("--transition", required=True)
    sign.add_argument("--passphrase-env", default="DAYLIGHT_BASTION_PASSPHRASE")
    sign.add_argument("--out", required=True)
    sign.add_argument("--format", choices=("text", "json"), default="text")
    sign.set_defaults(func=cmd_transition_sign)

    transition_verify = sub.add_parser("transition-verify")
    transition_verify.add_argument("--before", required=True)
    transition_verify.add_argument("--after", required=True)
    transition_verify.add_argument("--transition", required=True)
    transition_verify.add_argument("--passphrase-env", default="DAYLIGHT_BASTION_PASSPHRASE")
    transition_verify.add_argument("--format", choices=("text", "json"), default="text")
    transition_verify.set_defaults(func=cmd_transition_verify)

    ledger_init = sub.add_parser("transition-ledger-init")
    ledger_init.add_argument("--out", required=True)
    ledger_init.add_argument("--format", choices=("text", "json"), default="text")
    ledger_init.set_defaults(func=cmd_transition_ledger_init)

    ledger_append = sub.add_parser("transition-ledger-append")
    ledger_append.add_argument("--ledger", required=True)
    ledger_append.add_argument("--transition", required=True)
    ledger_append.add_argument("--format", choices=("text", "json"), default="text")
    ledger_append.set_defaults(func=cmd_transition_ledger_append)

    ledger_verify = sub.add_parser("transition-ledger-verify")
    ledger_verify.add_argument("--ledger", required=True)
    ledger_verify.add_argument("--format", choices=("text", "json"), default="text")
    ledger_verify.set_defaults(func=cmd_transition_ledger_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (
        OSError,
        ValueError,
        tamper_logic.TamperLogicError,
        transition_ledger.TransitionLedgerError,
        user_ceremony.UserCeremonyError,
    ) as exc:
        print(f"daylight-v18-bastion: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
