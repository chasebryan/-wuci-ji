#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import wuci_frost_authorize as warrant
import wuci_gate as gate


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
CONTRACT_SCHEMA = "wuci-gate-receipt-contract-v1"
CONTRACT_FIELDS = (
    "schema",
    "action",
    "artifact-sha256",
    "authorization-message-sha256",
    "receipt-sha256",
    "artifact-manifest-sha256",
    "group-public-key",
    "group-commitment",
    "challenge",
    "signature-commitment",
    "signature-scalar",
)
HEX64_FIELDS = {
    "artifact-sha256",
    "authorization-message-sha256",
    "receipt-sha256",
    "artifact-manifest-sha256",
    "challenge",
    "signature-scalar",
}
COMPRESSED_SEC1_FIELDS = {
    "group-public-key",
    "group-commitment",
    "signature-commitment",
}
HEX_RE = re.compile(r"^[0-9a-f]+$")


class ContractError(RuntimeError):
    pass


def read_ascii(path: Path, context: str) -> str:
    try:
        return path.read_text(encoding="ascii")
    except OSError as exc:
        raise ContractError(f"could not read {context} {path}") from exc
    except UnicodeDecodeError as exc:
        raise ContractError(f"{context} is not ASCII") from exc


def write_new_ascii(path: Path, value: str) -> None:
    if path.exists():
        raise ContractError(f"refusing to overwrite existing contract {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise ContractError(f"could not write contract {path}") from exc


def require_hex(value: str, chars: int, context: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        raise ContractError(f"{context} must be {chars} lowercase hex characters")


def validate_contract_fields(fields: dict[str, str]) -> None:
    if tuple(fields) != CONTRACT_FIELDS:
        raise ContractError("receipt contract fields are not in canonical order")
    if fields["schema"] != CONTRACT_SCHEMA:
        raise ContractError("receipt contract has unsupported schema")
    if fields["action"] not in warrant.ALLOWED_ACTIONS:
        raise ContractError("receipt contract has unsupported action")
    for label in HEX64_FIELDS:
        require_hex(fields[label], 64, label)
    for label in COMPRESSED_SEC1_FIELDS:
        require_hex(fields[label], 66, label)
        if fields[label][:2] not in {"02", "03"}:
            raise ContractError(f"{label} must be a compressed SEC1 point")
    gate.reject_private_material(fields, "receipt contract")


def format_contract(fields: dict[str, str]) -> str:
    validate_contract_fields(fields)
    return "".join(f"{label}: {fields[label]}\n" for label in CONTRACT_FIELDS)


def parse_contract(text: str) -> dict[str, str]:
    if "\r" in text:
        raise ContractError("receipt contract must not contain CRLF")
    if not text.endswith("\n"):
        raise ContractError("receipt contract must end with one trailing newline")
    if text.endswith("\n\n"):
        raise ContractError("receipt contract must end with exactly one trailing newline")

    lines = text[:-1].split("\n")
    if len(lines) != len(CONTRACT_FIELDS):
        raise ContractError("receipt contract has unexpected field count")

    fields: dict[str, str] = {}
    for index, (line, expected_label) in enumerate(zip(lines, CONTRACT_FIELDS), start=1):
        if ": " not in line:
            raise ContractError(f"receipt contract line {index} is not label: value")
        label, value = line.split(": ", 1)
        if label != expected_label:
            raise ContractError(
                f"receipt contract line {index} expected label {expected_label}"
            )
        if label in fields:
            raise ContractError(f"receipt contract duplicates label {label}")
        if value == "":
            raise ContractError(f"receipt contract field {label} is empty")
        fields[label] = value

    validate_contract_fields(fields)
    return fields


def derive_contract(
    *,
    bin_path: Path,
    artifact_path: Path,
    action: str,
    receipt_path: Path,
) -> dict[str, str]:
    try:
        receipt = gate.load_receipt(receipt_path)
        decision = gate.gate_decision(
            bin_path=bin_path,
            artifact_path=artifact_path,
            action=action,
            receipt_path=receipt_path,
        )
    except gate.GateError as exc:
        raise ContractError(str(exc)) from exc
    except warrant.AuthorizationError as exc:
        raise ContractError(str(exc)) from exc

    fields = {
        "schema": CONTRACT_SCHEMA,
        "action": decision["action"],
        "artifact-sha256": decision["artifact-sha256"],
        "authorization-message-sha256": decision["authorization-message-sha256"],
        "receipt-sha256": decision["receipt-sha256"],
        "artifact-manifest-sha256": receipt["artifact_manifest_sha256"],
        "group-public-key": receipt["group_public_key"],
        "group-commitment": receipt["group_commitment"],
        "challenge": receipt["challenge"],
        "signature-commitment": receipt["signature_commitment"],
        "signature-scalar": receipt["signature_scalar"],
    }
    validate_contract_fields(fields)
    return fields


def run_emit(args: argparse.Namespace) -> int:
    fields = derive_contract(
        bin_path=Path(args.bin),
        artifact_path=Path(args.artifact),
        action=args.action,
        receipt_path=Path(args.receipt),
    )
    contract_text = format_contract(fields)
    contract_path = Path(args.contract)
    write_new_ascii(contract_path, contract_text)
    if not args.quiet:
        print(f"contract: {contract_path}")
        print(f"action: {fields['action']}")
        print(f"artifact-sha256: {fields['artifact-sha256']}")
        print(f"authorization-message-sha256: {fields['authorization-message-sha256']}")
        print(f"receipt-sha256: {fields['receipt-sha256']}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    contract_path = Path(args.contract)
    actual_fields = parse_contract(read_ascii(contract_path, "receipt contract"))
    expected_fields = derive_contract(
        bin_path=Path(args.bin),
        artifact_path=Path(args.artifact),
        action=args.action,
        receipt_path=Path(args.receipt),
    )
    for label in CONTRACT_FIELDS:
        if actual_fields[label] != expected_fields[label]:
            raise ContractError(
                f"receipt contract field does not match derived value: {label}"
            )

    actual_text = read_ascii(contract_path, "receipt contract")
    expected_text = format_contract(expected_fields)
    if actual_text != expected_text:
        raise ContractError("receipt contract bytes are not canonical")
    if not args.quiet:
        print("valid")
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument("--artifact", required=True, help="sealed artifact path")
    parser.add_argument("--action", required=True, choices=warrant.ALLOWED_ACTIONS)
    parser.add_argument("--receipt", required=True, help="authorization receipt JSON")
    parser.add_argument("--contract", required=True, help="flat receipt contract path")
    parser.add_argument("--quiet", action="store_true", help="suppress success output")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Derive or verify the fixed flat WUCI-GATE receipt contract from "
            "a validated WUCI-WARRANT JSON receipt."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    emit_parser = subparsers.add_parser(
        "emit",
        help="verify a receipt and write a new flat receipt contract",
    )
    add_common_args(emit_parser)
    emit_parser.set_defaults(func=run_emit)

    verify_parser = subparsers.add_parser(
        "verify",
        help="verify an existing flat receipt contract against a receipt",
    )
    add_common_args(verify_parser)
    verify_parser.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except ContractError as exc:
        print(f"wuci receipt contract: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
