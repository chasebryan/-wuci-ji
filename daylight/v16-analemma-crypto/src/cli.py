"""Small CLI for the executable D16-AWE mechanics slice."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .auth import authorization_tag, make_recipient_public_key
from .canonical import load_json
from .envelope import inspect
from .errors import D16AWEError, UnsupportedCryptoBackend
from .evidence import verify_daylight_v16_evidence


def _read_json(path: str) -> object:
    return load_json(Path(path).read_text(encoding="utf-8"))


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run_evidence_context(args: argparse.Namespace) -> int:
    artifact = _read_json(args.evidence)
    policy = _read_json(args.policy)
    _print_json(verify_daylight_v16_evidence(artifact, policy))
    return 0


def run_derive_auth_tag(args: argparse.Namespace) -> int:
    artifact = _read_json(args.evidence)
    policy = _read_json(args.policy)
    context = verify_daylight_v16_evidence(artifact, policy)
    pkR = make_recipient_public_key(bytes.fromhex(args.pk_mlkem), bytes.fromhex(args.pk_dh))
    _print_json({"authorization_tag": authorization_tag(context, policy, pkR)})
    return 0


def run_inspect(args: argparse.Namespace) -> int:
    envelope = _read_json(args.envelope)
    _print_json(inspect(envelope))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="daylight-v16-awe")
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evidence-context")
    ev.add_argument("--evidence", required=True)
    ev.add_argument("--policy", required=True)
    ev.set_defaults(func=run_evidence_context)

    auth = sub.add_parser("derive-auth-tag")
    auth.add_argument("--evidence", required=True)
    auth.add_argument("--policy", required=True)
    auth.add_argument("--pk-mlkem", required=True)
    auth.add_argument("--pk-dh", required=True)
    auth.set_defaults(func=run_derive_auth_tag)

    ins = sub.add_parser("inspect")
    ins.add_argument("--envelope", required=True)
    ins.set_defaults(func=run_inspect)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, json.JSONDecodeError, D16AWEError, UnsupportedCryptoBackend) as exc:
        print(f"daylight-v16-awe: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
