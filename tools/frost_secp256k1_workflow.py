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
FIXTURE_WARNING = (
    "NON-PRODUCTION deterministic fixture material only; do not use for real signatures."
)

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


def fixture_manifest() -> dict[str, Any]:
    return {
        "suite": SUITE,
        "mode": MODE,
        "production": False,
        "warning": FIXTURE_WARNING,
        "group_secret": scalar_hex(FIXTURE_GROUP_SECRET),
        "signers": [
            {
                "id": scalar_hex(signer["id"]),
                "share": scalar_hex(signer["share"]),
                "hiding_nonce": scalar_hex(signer["hiding"]),
                "binding_nonce": scalar_hex(signer["binding"]),
            }
            for signer in FIXTURE_SIGNERS
        ],
    }


def require_exact_keys(
    value: dict[str, Any],
    expected_keys: set[str],
    context: str,
) -> None:
    actual_keys = set(value)
    unknown = actual_keys - expected_keys
    missing = expected_keys - actual_keys
    if unknown:
        raise WorkflowError(f"{context} contains unsupported field: {sorted(unknown)[0]}")
    if missing:
        raise WorkflowError(f"{context} is missing required field: {sorted(missing)[0]}")


def validate_fixture_manifest(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WorkflowError("fixture manifest must be a JSON object")

    require_exact_keys(
        raw,
        {"suite", "mode", "production", "warning", "group_secret", "signers"},
        "fixture manifest",
    )
    expected = fixture_manifest()
    for field in ("suite", "mode", "warning", "group_secret"):
        if raw[field] != expected[field]:
            raise WorkflowError(f"fixture manifest field {field!r} does not match the built-in fixture")
    if raw["production"] is not False:
        raise WorkflowError("fixture manifest must set production to false")
    if not isinstance(raw["signers"], list):
        raise WorkflowError("fixture manifest signers must be a list")
    if len(raw["signers"]) != len(expected["signers"]):
        raise WorkflowError("fixture manifest must contain exactly two signers")

    signer_keys = {"id", "share", "hiding_nonce", "binding_nonce"}
    for index, (actual, expected_signer) in enumerate(
        zip(raw["signers"], expected["signers"], strict=True), start=1
    ):
        if not isinstance(actual, dict):
            raise WorkflowError(f"fixture manifest signer {index} must be an object")
        require_exact_keys(actual, signer_keys, f"fixture manifest signer {index}")
        for field in sorted(signer_keys):
            if actual[field] != expected_signer[field]:
                raise WorkflowError(
                    f"fixture manifest signer {index} field {field!r} does not match the built-in fixture"
                )
    return expected


def load_fixture_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return validate_fixture_manifest(json.load(handle))
    except OSError as exc:
        raise WorkflowError(f"could not read fixture manifest {path}") from exc
    except json.JSONDecodeError as exc:
        raise WorkflowError(f"fixture manifest is not valid JSON: {exc.msg}") from exc


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


def signer_values(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": int(signer["id"], 16),
            "share": int(signer["share"], 16),
            "hiding": int(signer["hiding_nonce"], 16),
            "binding": int(signer["binding_nonce"], 16),
        }
        for signer in manifest["signers"]
    ]


def run_fixture_workflow(
    cli: WuciJiCli,
    message: bytes,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    group_public_key = compressed_basepoint_mul(cli, int(manifest["group_secret"], 16))
    signers = signer_values(manifest)

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
        "production": False,
        "fixture_warning": FIXTURE_WARNING,
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
        f"production: {str(result['production']).lower()}",
        f"fixture_warning: {result['fixture_warning']}",
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
    parser.add_argument(
        "--fixture-manifest",
        help=(
            "load the exact non-production fixture manifest; modified signer "
            "material is rejected"
        ),
    )
    parser.add_argument(
        "--print-fixture-manifest",
        action="store_true",
        help="print the exact non-production fixture manifest and exit",
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

    if args.print_fixture_manifest:
        print(json.dumps(fixture_manifest(), indent=2, sort_keys=True))
        return 0

    try:
        manifest = (
            load_fixture_manifest(Path(args.fixture_manifest))
            if args.fixture_manifest is not None
            else fixture_manifest()
        )
        result = run_fixture_workflow(
            WuciJiCli(Path(args.bin)),
            parse_message(args),
            manifest,
        )
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
