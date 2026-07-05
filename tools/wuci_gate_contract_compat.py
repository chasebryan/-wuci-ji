#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import wuci_frost_authorize as warrant
import wuci_gate
import wuci_receipt_contract as receipt_contract
import wuci_safeio


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
HEX_RE = re.compile(r"^[0-9a-f]+$")


class CompatError(RuntimeError):
    pass


def read_bytes(path: Path, context: str) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(path, context, reject_symlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise CompatError(str(exc)) from exc


def read_ascii(path: Path, context: str) -> str:
    try:
        return wuci_safeio.read_regular_ascii(path, context, reject_symlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise CompatError(str(exc)) from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, context: str) -> str:
    return sha256_bytes(read_bytes(path, context))


def runner_from_args(args: argparse.Namespace) -> list[str]:
    if getattr(args, "runner", None):
        return shlex.split(args.runner)
    return shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


def run_wuci(
    *,
    bin_path: Path,
    runner: list[str],
    argv: list[str],
    input_bytes: bytes | None = None,
) -> bytes:
    try:
        proc = subprocess.run(
            [*runner, str(bin_path), *argv],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            cwd=REPO_ROOT,
        )
    except OSError as exc:
        raise CompatError(f"could not execute {bin_path}") from exc
    if proc.returncode != 0:
        detail = (
            proc.stderr.decode("utf-8", "replace").strip()
            or proc.stdout.decode("utf-8", "replace").strip()
            or f"exit status {proc.returncode}"
        )
        raise CompatError(detail)
    return proc.stdout


def run_wuci_expect_silent(
    *,
    bin_path: Path,
    runner: list[str],
    argv: list[str],
    input_bytes: bytes | None = None,
) -> None:
    stdout = run_wuci(
        bin_path=bin_path,
        runner=runner,
        argv=argv,
        input_bytes=input_bytes,
    )
    if stdout:
        raise CompatError("command produced unexpected stdout")


def require_hash(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        raise CompatError(f"{label} mismatch")


def require_hex(value: str, chars: int, label: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        raise CompatError(f"{label} must be {chars} lowercase hex characters")


def load_receipt(path: Path) -> dict[str, object]:
    try:
        receipt = warrant.load_json_file(path, "authorization receipt")
        wuci_gate.reject_private_material(receipt, "authorization receipt")
        return warrant.validate_receipt_shape(receipt)
    except (warrant.AuthorizationError, wuci_gate.GateError) as exc:
        raise CompatError(str(exc)) from exc


def parse_contract_loose(path: Path) -> dict[str, str]:
    text = read_ascii(path, "receipt contract")
    if "\r" in text:
        raise CompatError("receipt contract must not contain CRLF")
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise CompatError("receipt contract must end with exactly one trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) != len(receipt_contract.CONTRACT_FIELDS):
        raise CompatError("receipt contract has unexpected field count")

    fields: dict[str, str] = {}
    for index, (line, expected_label) in enumerate(
        zip(lines, receipt_contract.CONTRACT_FIELDS), start=1
    ):
        if ": " not in line:
            raise CompatError(f"receipt contract line {index} is not label: value")
        label, value = line.split(": ", 1)
        if label != expected_label:
            raise CompatError(f"receipt contract line {index} expected label {expected_label}")
        if label in fields:
            raise CompatError(f"receipt contract duplicates label {label}")
        if value == "":
            raise CompatError(f"receipt contract field {label} is empty")
        fields[label] = value

    if fields["schema"] != receipt_contract.CONTRACT_SCHEMA:
        raise CompatError("receipt contract has unsupported schema")
    if fields["action"] not in warrant.ALLOWED_ACTIONS:
        raise CompatError("receipt contract has unsupported action")
    for label in receipt_contract.HEX64_FIELDS:
        require_hex(fields[label], 64, label)
    for label in receipt_contract.COMPRESSED_SEC1_FIELDS:
        require_hex(fields[label], 66, label)
        if fields[label][:2] not in {"02", "03"}:
            raise CompatError(f"{label} must be a compressed SEC1 point")
    try:
        wuci_gate.reject_private_material(fields, "receipt contract")
    except wuci_gate.GateError as exc:
        raise CompatError(str(exc)) from exc
    return fields


def build_contract_fields(args: argparse.Namespace) -> dict[str, str]:
    bin_path = Path(args.bin)
    artifact_path = Path(args.artifact)
    receipt_path = Path(args.receipt)
    runner = runner_from_args(args)
    receipt = load_receipt(receipt_path)
    action = str(receipt["action"])

    artifact_hash = sha256_file(artifact_path, "sealed artifact")
    receipt_bytes = read_bytes(receipt_path, "authorization receipt")
    manifest = run_wuci(bin_path=bin_path, runner=runner, argv=["manifest-file", str(artifact_path)])
    manifest_hash = sha256_bytes(manifest)
    require_hash(manifest_hash, str(receipt["artifact_manifest_sha256"]), "artifact-manifest-sha256")

    warrant_bytes = run_wuci(
        bin_path=bin_path,
        runner=runner,
        argv=["warrant-message-file", action, str(artifact_path)],
    )
    warrant_hash = sha256_bytes(warrant_bytes)
    require_hash(
        warrant_hash,
        str(receipt["authorization_message_sha256"]),
        "authorization-message-sha256",
    )

    group_commitment = str(receipt["group_commitment"])
    signature_commitment = str(receipt["signature_commitment"])
    if group_commitment != signature_commitment:
        raise CompatError("SignatureCommitmentMismatch")
    challenge = run_wuci(
        bin_path=bin_path,
        runner=runner,
        argv=[
            "frost-secp256k1-challenge",
            group_commitment,
            str(receipt["group_public_key"]),
        ],
        input_bytes=warrant_bytes,
    ).strip().decode("ascii")
    if challenge != str(receipt["challenge"]):
        raise CompatError("ChallengeMismatch")

    verify = subprocess.run(
        [
            *runner,
            str(bin_path),
            "frost-secp256k1-verify",
            signature_commitment,
            str(receipt["group_public_key"]),
            str(receipt["signature_scalar"]),
            str(receipt["challenge"]),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
    )
    if verify.returncode != 0 or verify.stdout.strip() != b"valid":
        raise CompatError("InvalidSignature")

    return {
        "schema": receipt_contract.CONTRACT_SCHEMA,
        "action": action,
        "artifact-sha256": artifact_hash,
        "authorization-message-sha256": str(receipt["authorization_message_sha256"]),
        "receipt-sha256": sha256_bytes(receipt_bytes),
        "artifact-manifest-sha256": str(receipt["artifact_manifest_sha256"]),
        "group-public-key": str(receipt["group_public_key"]),
        "group-commitment": group_commitment,
        "challenge": str(receipt["challenge"]),
        "signature-commitment": signature_commitment,
        "signature-scalar": str(receipt["signature_scalar"]),
    }


def run_emit(args: argparse.Namespace) -> int:
    fields = build_contract_fields(args)
    receipt_contract.write_new_ascii(Path(args.contract), receipt_contract.format_contract(fields))
    if not args.quiet:
        print(f"contract: {args.contract}")
        print(f"action: {fields['action']}")
        print(f"artifact-sha256: {fields['artifact-sha256']}")
        print(f"authorization-message-sha256: {fields['authorization-message-sha256']}")
        print(f"receipt-sha256: {fields['receipt-sha256']}")
    return 0


def verify_fields(args: argparse.Namespace) -> dict[str, str]:
    actual = parse_contract_loose(Path(args.contract))
    bin_path = Path(args.bin)
    artifact_path = Path(args.artifact)
    receipt_path = Path(args.receipt)
    runner = runner_from_args(args)

    require_hash(
        sha256_file(artifact_path, "sealed artifact"),
        actual["artifact-sha256"],
        "artifact-sha256",
    )
    require_hash(
        sha256_file(receipt_path, "authorization receipt"),
        actual["receipt-sha256"],
        "receipt-sha256",
    )

    manifest = run_wuci(bin_path=bin_path, runner=runner, argv=["manifest-file", str(artifact_path)])
    require_hash(
        sha256_bytes(manifest),
        actual["artifact-manifest-sha256"],
        "artifact-manifest-sha256",
    )
    warrant_bytes = run_wuci(
        bin_path=bin_path,
        runner=runner,
        argv=["warrant-message-file", actual["action"], str(artifact_path)],
    )
    require_hash(
        sha256_bytes(warrant_bytes),
        actual["authorization-message-sha256"],
        "authorization-message-sha256",
    )
    if actual["signature-commitment"] != actual["group-commitment"]:
        raise CompatError("SignatureCommitmentMismatch")
    challenge = run_wuci(
        bin_path=bin_path,
        runner=runner,
        argv=[
            "frost-secp256k1-challenge",
            actual["group-commitment"],
            actual["group-public-key"],
        ],
        input_bytes=warrant_bytes,
    ).strip().decode("ascii")
    if challenge != actual["challenge"]:
        raise CompatError("ChallengeMismatch")

    verify = subprocess.run(
        [
            *runner,
            str(bin_path),
            "frost-secp256k1-verify",
            actual["signature-commitment"],
            actual["group-public-key"],
            actual["signature-scalar"],
            actual["challenge"],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
    )
    if verify.returncode != 0 or verify.stdout.strip() != b"valid":
        raise CompatError("InvalidSignature")

    expected_text = receipt_contract.format_contract(actual)
    actual_text = read_ascii(Path(args.contract), "receipt contract")
    if actual_text != expected_text:
        raise CompatError("receipt contract bytes are not canonical")
    return actual


def run_verify(args: argparse.Namespace) -> int:
    verify_fields(args)
    if not args.quiet:
        print("valid")
    return 0


def run_open(args: argparse.Namespace) -> int:
    fields = verify_fields(args)
    if fields["action"] != "open":
        raise CompatError("gate contract open requires action open")
    out_path = Path(args.out)
    if os.path.lexists(out_path):
        raise CompatError(f"refusing to overwrite existing output {out_path}")
    if not out_path.parent.exists() or not out_path.parent.is_dir():
        raise CompatError(f"output parent directory does not exist {out_path.parent}")
    run_wuci_expect_silent(
        bin_path=Path(args.bin),
        runner=runner_from_args(args),
        argv=[
            "open-file-keyfile",
            str(args.keyfile),
            str(args.artifact),
            str(out_path),
        ],
    )
    print("valid")
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--runner")
    parser.add_argument("--quiet", action="store_true")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compatibility front-end for the WUCI-GATE contract verifier."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    emit = subparsers.add_parser("emit")
    add_common_args(emit)
    emit.set_defaults(func=run_emit)

    verify = subparsers.add_parser("verify")
    add_common_args(verify)
    verify.set_defaults(func=run_verify)

    open_parser = subparsers.add_parser("open")
    add_common_args(open_parser)
    open_parser.add_argument("--keyfile", required=True)
    open_parser.add_argument("--out", required=True)
    open_parser.set_defaults(func=run_open)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (CompatError, receipt_contract.ContractError, warrant.AuthorizationError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
