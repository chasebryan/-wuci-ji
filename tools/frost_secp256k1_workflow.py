#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
SUITE = "FROST-secp256k1-SHA256-v1"
MODE = "deterministic-2of2-fixture"
DEFAULT_MESSAGE = b"wuci-ji frost integration"

FIXTURE_GROUP_SECRET = 5
FIXTURE_SIGNERS = (
    {"id": 1, "share": 12, "hiding": 2, "binding": 3},
    {"id": 2, "share": 19, "hiding": 4, "binding": 5},
)


class WorkflowError(RuntimeError):
    pass


def scalar_hex(value: int) -> str:
    if value < 0 or value >= 1 << 256:
        raise WorkflowError(f"scalar fixture value out of range: {value}")
    return f"{value:064x}"


def parse_labels(output: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in output.splitlines():
        if ": " not in line:
            raise WorkflowError(f"unexpected labeled output line: {line!r}")
        label, value = line.split(": ", 1)
        labels[label] = value
    return labels


class WuciJiCli:
    def __init__(self, bin_path: Path) -> None:
        self.bin_path = bin_path

    def run(self, args: list[str], stdin: bytes = b"") -> str:
        if not self.bin_path.exists():
            raise WorkflowError(
                f"{self.bin_path} does not exist; run `make` first or pass --bin"
            )
        try:
            proc = subprocess.run(
                [str(self.bin_path), *args],
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except FileNotFoundError as exc:
            raise WorkflowError(f"could not execute {self.bin_path}") from exc

        if proc.returncode != 0:
            stdout = proc.stdout.decode("utf-8", "replace").strip()
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            detail = stderr or stdout or f"exit status {proc.returncode}"
            raise WorkflowError(f"{args[0]} failed: {detail}")
        return proc.stdout.decode("ascii")

    def run_scalar(self, args: list[str], stdin: bytes = b"") -> str:
        return self.run(args, stdin).strip()

    def run_labels(self, args: list[str], stdin: bytes = b"") -> dict[str, str]:
        return parse_labels(self.run(args, stdin))


def compressed_basepoint_mul(cli: WuciJiCli, scalar: int) -> str:
    point = cli.run_labels(
        ["secp256k1-projective-basepoint-mul", scalar_hex(scalar)]
    )
    return cli.run_scalar(
        ["secp256k1-point-encode-compressed", point["x"], point["y"]]
    )


def run_fixture_workflow(cli: WuciJiCli, message: bytes) -> dict[str, Any]:
    group_public_key = compressed_basepoint_mul(cli, FIXTURE_GROUP_SECRET)
    signers: list[dict[str, Any]] = [dict(item) for item in FIXTURE_SIGNERS]

    for signer in signers:
        commitments = cli.run_labels(
            [
                "frost-secp256k1-commit",
                scalar_hex(signer["hiding"]),
                scalar_hex(signer["binding"]),
            ]
        )
        signer["D"] = commitments["hiding_nonce_commitment"]
        signer["E"] = commitments["binding_nonce_commitment"]

    commitment_hash = cli.run_scalar(
        [
            "frost-secp256k1-commitment-hash",
            *(
                item
                for signer in signers
                for item in (scalar_hex(signer["id"]), signer["D"], signer["E"])
            ),
        ]
    )
    message_hash = cli.run_scalar(["frost-secp256k1-h4"], message)

    for signer in signers:
        rho = cli.run_scalar(
            [
                "frost-secp256k1-binding-factor",
                group_public_key,
                message_hash,
                commitment_hash,
                scalar_hex(signer["id"]),
            ]
        )
        signer["rho"] = rho

    group_commitment = cli.run_labels(
        [
            "frost-secp256k1-group-commitment",
            *(
                item
                for signer in signers
                for item in (
                    scalar_hex(signer["id"]),
                    signer["D"],
                    signer["E"],
                    signer["rho"],
                )
            ),
        ]
    )["group_commitment"]

    challenge = cli.run_scalar(
        ["frost-secp256k1-challenge", group_commitment, group_public_key],
        message,
    )

    for signer in signers:
        lagrange = cli.run_scalar(
            [
                "frost-secp256k1-lagrange",
                scalar_hex(signer["id"]),
                *(scalar_hex(item["id"]) for item in signers),
            ]
        )
        signer["lagrange"] = lagrange
        signer["z"] = cli.run_scalar(
            [
                "frost-secp256k1-signing-share",
                scalar_hex(signer["hiding"]),
                scalar_hex(signer["binding"]),
                signer["rho"],
                signer["lagrange"],
                scalar_hex(signer["share"]),
                challenge,
            ]
        )

    signature = cli.run_labels(
        [
            "frost-secp256k1-aggregate",
            group_commitment,
            *(signer["z"] for signer in signers),
        ]
    )

    verification = cli.run(
        [
            "frost-secp256k1-verify",
            signature["signature_commitment"],
            group_public_key,
            signature["signature_scalar"],
            challenge,
        ]
    ).strip()
    if verification != "valid":
        raise WorkflowError(f"verification failed: {verification}")

    return {
        "suite": SUITE,
        "mode": MODE,
        "message_hex": message.hex(),
        "group_public_key": group_public_key,
        "commitment_hash": commitment_hash,
        "message_hash": message_hash,
        "signers": [
            {
                "id": scalar_hex(signer["id"]),
                "hiding_nonce_commitment": signer["D"],
                "binding_nonce_commitment": signer["E"],
                "binding_factor": signer["rho"],
                "lagrange": signer["lagrange"],
                "signature_share": signer["z"],
            }
            for signer in signers
        ],
        "group_commitment": group_commitment,
        "challenge": challenge,
        "signature_commitment": signature["signature_commitment"],
        "signature_scalar": signature["signature_scalar"],
        "verification": verification,
    }


def text_lines(result: dict[str, Any]) -> list[str]:
    lines = [
        f"suite: {result['suite']}",
        f"mode: {result['mode']}",
        f"message_hex: {result['message_hex']}",
        f"group_public_key: {result['group_public_key']}",
        f"commitment_hash: {result['commitment_hash']}",
        f"message_hash: {result['message_hash']}",
    ]
    for index, signer in enumerate(result["signers"], start=1):
        lines.extend(
            [
                f"signer_{index}_id: {signer['id']}",
                f"signer_{index}_hiding_nonce_commitment: {signer['hiding_nonce_commitment']}",
                f"signer_{index}_binding_nonce_commitment: {signer['binding_nonce_commitment']}",
                f"signer_{index}_binding_factor: {signer['binding_factor']}",
                f"signer_{index}_lagrange: {signer['lagrange']}",
                f"signer_{index}_signature_share: {signer['signature_share']}",
            ]
        )
    lines.extend(
        [
            f"group_commitment: {result['group_commitment']}",
            f"challenge: {result['challenge']}",
            f"signature_commitment: {result['signature_commitment']}",
            f"signature_scalar: {result['signature_scalar']}",
            f"verification: {result['verification']}",
        ]
    )
    return lines


def parse_message(args: argparse.Namespace) -> bytes:
    if args.message_hex is not None:
        try:
            return bytes.fromhex(args.message_hex)
        except ValueError as exc:
            raise WorkflowError("--message-hex must be even-length hexadecimal") from exc
    if args.stdin:
        return sys.stdin.buffer.read()
    if args.message is not None:
        return args.message.encode("utf-8")
    return DEFAULT_MESSAGE


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the deterministic 2-of-2 FROST(secp256k1,SHA-256) demo workflow "
            "against the wuci-ji assembly CLI primitives."
        )
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    message_group = parser.add_mutually_exclusive_group()
    message_group.add_argument(
        "--message",
        help="UTF-8 message to sign; defaults to the regression fixture message",
    )
    message_group.add_argument(
        "--message-hex",
        help="hex-encoded message to sign",
    )
    message_group.add_argument(
        "--stdin",
        action="store_true",
        help="read the message bytes from stdin",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON transcript instead of label/value text",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="run the workflow without printing the transcript",
    )
    args = parser.parse_args()

    try:
        result = run_fixture_workflow(WuciJiCli(Path(args.bin)), parse_message(args))
    except WorkflowError as exc:
        print(f"frost workflow: {exc}", file=sys.stderr)
        return 1

    if args.quiet:
        return 0
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print("\n".join(text_lines(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
