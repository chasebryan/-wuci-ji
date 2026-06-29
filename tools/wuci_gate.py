#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

import wuci_frost_authorize as warrant
import wuci_progress
import wuci_safeio
import wuci_verifier_identity


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
PRIVATE_MARKERS = (
    "group_secret",
    "share",
    "hiding",
    "binding",
    "hiding_nonce",
    "binding_nonce",
    "signature_share",
)


class GateError(RuntimeError):
    pass


def read_file_bytes(path: Path, context: str) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(path, context, reject_symlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise GateError(str(exc)) from exc


def nested_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for item in value.values():
            keys.update(nested_keys(item))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(nested_keys(item))
        return keys
    return set()


def reject_private_material(value: Any, context: str) -> None:
    keys = nested_keys(value)
    for marker in PRIVATE_MARKERS:
        if marker in keys:
            raise GateError(f"{context} contains private material marker: {marker}")
    encoded = json.dumps(value, sort_keys=True)
    for marker in PRIVATE_MARKERS:
        if marker in encoded:
            raise GateError(f"{context} contains private material marker: {marker}")


def load_receipt(path: Path) -> dict[str, Any]:
    raw_receipt = warrant.load_json_file(path, "authorization receipt")
    reject_private_material(raw_receipt, "authorization receipt")
    return warrant.validate_receipt_shape(raw_receipt)


def gate_decision(
    *,
    bin_path: Path,
    artifact_path: Path,
    action: str,
    receipt_path: Path,
    ticker_mode: str = "auto",
) -> dict[str, str]:
    try:
        with wuci_progress.stage("GATE receipt verification", ticker_mode):
            receipt = load_receipt(receipt_path)
            warrant.verify_receipt(
                bin_path=bin_path,
                artifact_path=artifact_path,
                action=action,
                receipt_path=receipt_path,
            )
        with wuci_progress.stage("GATE authorization manifest", ticker_mode):
            auth_message, auth_message_bytes = warrant.build_authorization(
                bin_path,
                artifact_path,
                action,
            )
    except warrant.AuthorizationError as exc:
        raise GateError(str(exc)) from exc

    receipt_bytes = read_file_bytes(receipt_path, "authorization receipt")
    artifact_manifest = auth_message["artifact_manifest"]
    artifact_sha256 = artifact_manifest.get("artifact_sha256")
    if not artifact_sha256:
        raise GateError("artifact manifest is missing artifact_sha256")

    decision = {
        "authorized": "true",
        "action": receipt["action"],
        "artifact-sha256": artifact_sha256,
        "authorization-message-sha256": hashlib.sha256(
            auth_message_bytes
        ).hexdigest(),
        "receipt-sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }
    reject_private_material(decision, "gate decision")
    return decision


def print_decision(decision: dict[str, str]) -> None:
    for key in (
        "authorized",
        "action",
        "artifact-sha256",
        "authorization-message-sha256",
        "receipt-sha256",
    ):
        print(f"{key}: {decision[key]}")


def json_decision(*, schema: str, decision: dict[str, str], **extra: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": schema,
        "authorized": decision["authorized"] == "true",
        "action": decision["action"],
        "artifact_sha256": decision["artifact-sha256"],
        "authorization_message_sha256": decision["authorization-message-sha256"],
        "receipt_sha256": decision["receipt-sha256"],
    }
    value.update(extra)
    reject_private_material(value, "gate JSON decision")
    return value


def print_json(value: dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True))


def run_open_file_keyfile(
    *,
    bin_path: Path,
    keyfile_path: Path,
    artifact_path: Path,
    out_path: Path,
    ticker_mode: str = "auto",
) -> None:
    try:
        proc = wuci_progress.run_process(
            [
                *RUNNER,
                str(bin_path),
                "open-file-keyfile",
                str(keyfile_path),
                str(artifact_path),
                str(out_path),
            ],
            ticker_mode=ticker_mode,
            label="GATE open-file-keyfile",
        )
    except OSError as exc:
        raise GateError(f"could not execute {bin_path}") from exc
    if proc.returncode != 0:
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        detail = stderr or stdout or f"exit status {proc.returncode}"
        raise GateError(f"open-file-keyfile failed: {detail}")
    if proc.stdout:
        raise GateError("open-file-keyfile produced unexpected stdout")


def validate_output_path(out_path: Path) -> None:
    if os.path.lexists(out_path):
        raise GateError(f"refusing to overwrite existing output {out_path}")

    parent = out_path.parent
    if not parent.exists():
        raise GateError(f"output parent directory does not exist {parent}")
    if not parent.is_dir():
        raise GateError(f"output parent is not a directory {parent}")


def run_check(args: argparse.Namespace) -> int:
    ticker_mode = getattr(args, "ticker", "auto")
    decision = gate_decision(
        bin_path=Path(args.bin),
        artifact_path=Path(args.artifact),
        action=args.action,
        receipt_path=Path(args.receipt),
        ticker_mode=ticker_mode,
    )
    if args.json:
        print_json(json_decision(schema="wuci-gate-check-v1", decision=decision))
    else:
        print_decision(decision)
    return 0


def run_open(args: argparse.Namespace) -> int:
    ticker_mode = getattr(args, "ticker", "auto")
    decision = gate_decision(
        bin_path=Path(args.bin),
        artifact_path=Path(args.artifact),
        action=args.action,
        receipt_path=Path(args.receipt),
        ticker_mode=ticker_mode,
    )
    if decision["action"] != "open" or args.action != "open":
        raise GateError("gate open requires an authorization receipt for action open")

    out_path = Path(args.out)
    validate_output_path(out_path)

    run_open_file_keyfile(
        bin_path=Path(args.bin),
        keyfile_path=Path(args.keyfile),
        artifact_path=Path(args.artifact),
        out_path=out_path,
        ticker_mode=ticker_mode,
    )
    if args.json:
        print_json(
            json_decision(
                schema="wuci-gate-open-v1",
                decision=decision,
                opened_path=str(out_path),
            )
        )
    else:
        print_decision(decision)
        print(f"opened: {out_path}")
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument("--artifact", required=True, help="sealed artifact path")
    parser.add_argument("--action", required=True, choices=warrant.ALLOWED_ACTIONS)
    parser.add_argument(
        "--allow-reserved-action",
        action="store_true",
        help="allow reserved trust/publish compatibility outside strict mode",
    )
    parser.add_argument("--receipt", required=True, help="authorization receipt JSON")
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON")
    wuci_progress.add_ticker_arg(parser)
    wuci_verifier_identity.add_strict_args(parser)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "WUCI-GATE preview: verify a WUCI-WARRANT receipt before allowing "
            "a controlled no-overwrite open."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check",
        help="verify a receipt and print the gate decision",
    )
    add_common_args(check_parser)
    check_parser.set_defaults(func=run_check)

    open_parser = subparsers.add_parser(
        "open",
        help="verify an open receipt, then open the artifact to a new file",
    )
    add_common_args(open_parser)
    open_parser.add_argument("--keyfile", required=True, help="64-hex key file")
    open_parser.add_argument("--out", required=True, help="new plaintext output path")
    open_parser.set_defaults(func=run_open)

    args = parser.parse_args()
    try:
        strict = wuci_verifier_identity.is_strict(args.strict_proof)
        wuci_verifier_identity.enforce_args(args, Path(args.bin))
        warrant.require_action_allowed(
            args.action,
            allow_reserved=args.allow_reserved_action,
            strict=strict,
        )
        return args.func(args)
    except (
        GateError,
        warrant.AuthorizationError,
        wuci_verifier_identity.VerifierIdentityError,
    ) as exc:
        print(f"wuci gate: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
