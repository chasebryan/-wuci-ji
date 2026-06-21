#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

import frost_secp256k1_workflow as frost
import wuci_receipt_contract as receipt_contract


ROOT_SCHEMA = "wuci-authority-root-v1"
ROOT_FIELDS = (
    "schema",
    "suite",
    "production",
    "authority-id",
    "group-public-key",
    "allow-open",
    "allow-release",
    "allow-trust",
    "allow-publish",
)
HEX_RE = re.compile(r"^[0-9a-f]+$")


class AuthorityRootError(RuntimeError):
    pass


def read_ascii(path: Path, context: str) -> str:
    try:
        return path.read_text(encoding="ascii")
    except OSError as exc:
        raise AuthorityRootError(f"could not read {context} {path}") from exc
    except UnicodeDecodeError as exc:
        raise AuthorityRootError(f"{context} is not ASCII") from exc


def write_new_ascii(path: Path, value: str) -> None:
    if path.exists():
        raise AuthorityRootError(f"refusing to overwrite existing authority root {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise AuthorityRootError(f"could not write authority root {path}") from exc


def require_hex(value: str, chars: int, context: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        raise AuthorityRootError(f"{context} must be {chars} lowercase hex characters")


def authority_id(group_public_key: str) -> str:
    require_hex(group_public_key, 66, "group-public-key")
    if group_public_key[:2] not in {"02", "03"}:
        raise AuthorityRootError("group-public-key must be a compressed SEC1 point")
    return hashlib.sha256(bytes.fromhex(group_public_key)).hexdigest()


def validate_fields(fields: dict[str, str]) -> None:
    if tuple(fields) != ROOT_FIELDS:
        raise AuthorityRootError("authority root fields are not in canonical order")
    if fields["schema"] != ROOT_SCHEMA:
        raise AuthorityRootError("authority root has unsupported schema")
    if fields["suite"] != frost.SUITE:
        raise AuthorityRootError("authority root has unsupported suite")
    if fields["production"] != "false":
        raise AuthorityRootError("authority root must set production to false")
    require_hex(fields["authority-id"], 64, "authority-id")
    require_hex(fields["group-public-key"], 66, "group-public-key")
    if fields["group-public-key"][:2] not in {"02", "03"}:
        raise AuthorityRootError("group-public-key must be a compressed SEC1 point")
    if fields["authority-id"] != authority_id(fields["group-public-key"]):
        raise AuthorityRootError("authority-id does not match group-public-key")
    for label in ("allow-open", "allow-release"):
        if fields[label] not in {"true", "false"}:
            raise AuthorityRootError(f"authority root must set {label} to true or false")
    for label in ("allow-trust", "allow-publish"):
        if fields[label] != "false":
            raise AuthorityRootError(f"authority root must set {label} to false")


def format_root(
    group_public_key: str,
    *,
    allow_open: str = "true",
    allow_release: str = "false",
) -> str:
    fields = {
        "schema": ROOT_SCHEMA,
        "suite": frost.SUITE,
        "production": "false",
        "authority-id": authority_id(group_public_key),
        "group-public-key": group_public_key,
        "allow-open": allow_open,
        "allow-release": allow_release,
        "allow-trust": "false",
        "allow-publish": "false",
    }
    validate_fields(fields)
    return "".join(f"{label}: {fields[label]}\n" for label in ROOT_FIELDS)


def parse_root(text: str) -> dict[str, str]:
    if "\r" in text:
        raise AuthorityRootError("authority root must not contain CRLF")
    if not text.endswith("\n"):
        raise AuthorityRootError("authority root must end with one trailing newline")
    if text.endswith("\n\n"):
        raise AuthorityRootError("authority root must end with exactly one trailing newline")

    lines = text[:-1].split("\n")
    if len(lines) != len(ROOT_FIELDS):
        raise AuthorityRootError("authority root has unexpected field count")

    fields: dict[str, str] = {}
    for index, (line, expected_label) in enumerate(zip(lines, ROOT_FIELDS), start=1):
        if ": " not in line:
            raise AuthorityRootError(f"authority root line {index} is not label: value")
        label, value = line.split(": ", 1)
        if label != expected_label:
            raise AuthorityRootError(
                f"authority root line {index} expected label {expected_label}"
            )
        if label in fields:
            raise AuthorityRootError(f"authority root duplicates label {label}")
        if value == "":
            raise AuthorityRootError(f"authority root field {label} is empty")
        fields[label] = value

    validate_fields(fields)
    return fields


def group_key_from_contract(path: Path) -> str:
    try:
        fields = receipt_contract.parse_contract(
            receipt_contract.read_ascii(path, "receipt contract")
        )
    except receipt_contract.ContractError as exc:
        raise AuthorityRootError(str(exc)) from exc
    return fields["group-public-key"]


def run_emit(args: argparse.Namespace) -> int:
    group_public_key = args.group_public_key
    if args.contract is not None:
        group_public_key = group_key_from_contract(Path(args.contract))
    if group_public_key is None:
        raise AuthorityRootError("emit requires --contract or --group-public-key")
    root_text = format_root(
        group_public_key,
        allow_open=args.allow_open,
        allow_release=args.allow_release,
    )
    authority_path = Path(args.authority)
    write_new_ascii(authority_path, root_text)
    if not args.quiet:
        print(f"authority root: {authority_path}")
        print(f"authority-id: {authority_id(group_public_key)}")
        print(f"group-public-key: {group_public_key}")
        print(f"allow-open: {args.allow_open}")
        print(f"allow-release: {args.allow_release}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    parse_root(read_ascii(Path(args.authority), "authority root"))
    if not args.quiet:
        print("valid")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Emit or verify flat WUCI-ROOT authority files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    emit = subparsers.add_parser("emit", help="write a canonical authority root")
    source = emit.add_mutually_exclusive_group(required=True)
    source.add_argument("--contract", help="flat receipt contract to trust")
    source.add_argument("--group-public-key", help="compressed SEC1 quorum key hex")
    emit.add_argument("--authority", required=True, help="authority root path")
    emit.add_argument(
        "--allow-open",
        choices=("true", "false"),
        default="true",
        help="open authority bit; defaults to true",
    )
    emit.add_argument(
        "--allow-release",
        choices=("true", "false"),
        default="false",
        help="release authority bit; defaults to false",
    )
    emit.add_argument("--quiet", action="store_true", help="suppress success output")

    verify = subparsers.add_parser("verify", help="verify an authority root")
    verify.add_argument("--authority", required=True, help="authority root path")
    verify.add_argument("--quiet", action="store_true", help="suppress success output")

    args = parser.parse_args()
    try:
        if args.command == "emit":
            return run_emit(args)
        if args.command == "verify":
            return run_verify(args)
        raise AuthorityRootError(f"unsupported command: {args.command}")
    except AuthorityRootError as exc:
        print(f"wuci authority root: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
