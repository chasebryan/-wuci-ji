#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import frost_secp256k1_workflow as frost


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
AUTH_MESSAGE_SCHEMA = "wuci-frost-authorization-message-v1"
RECEIPT_SCHEMA = "wuci-frost-authorization-v1"
ALLOWED_ACTIONS = ("open", "release", "trust", "publish")


class AuthorizationError(RuntimeError):
    pass


class WuciJi:
    def __init__(self, bin_path: Path) -> None:
        self.bin_path = bin_path

    def run(self, args: list[str], stdin: bytes = b"") -> str:
        if not self.bin_path.exists():
            raise AuthorizationError(
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
            raise AuthorizationError(f"could not execute {self.bin_path}") from exc
        if proc.returncode != 0:
            stdout = proc.stdout.decode("utf-8", "replace").strip()
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            detail = stderr or stdout or f"exit status {proc.returncode}"
            raise AuthorizationError(f"{args[0]} failed: {detail}")
        return proc.stdout.decode("ascii")

    def run_scalar(self, args: list[str], stdin: bytes = b"") -> str:
        return self.run(args, stdin).strip()


def parse_labels(output: str, context: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in output.splitlines():
        if ": " not in line:
            raise AuthorizationError(f"{context} contains unexpected line: {line!r}")
        label, value = line.split(": ", 1)
        if label in labels:
            raise AuthorizationError(f"{context} contains duplicate label: {label}")
        labels[label] = value
    return labels


def artifact_manifest(bin_path: Path, artifact_path: Path) -> tuple[bytes, dict[str, str]]:
    manifest_text = WuciJi(bin_path).run(["manifest-file", str(artifact_path)])
    manifest_bytes = manifest_text.encode("ascii")
    parsed = {
        label.replace("-", "_"): value
        for label, value in parse_labels(manifest_text, "artifact manifest").items()
    }
    return manifest_bytes, parsed


def build_authorization(
    bin_path: Path,
    artifact_path: Path,
    action: str,
) -> tuple[dict[str, Any], bytes]:
    manifest_bytes, manifest = artifact_manifest(bin_path, artifact_path)
    auth_message_bytes = WuciJi(bin_path).run(
        ["warrant-message-file", action, str(artifact_path)]
    ).encode("ascii")
    manifest_prefix = b"artifact-manifest:\n"
    if not auth_message_bytes.endswith(manifest_prefix + manifest_bytes):
        raise AuthorizationError(
            "assembly warrant message does not match manifest-file output"
        )
    authorization = {
        "schema": AUTH_MESSAGE_SCHEMA,
        "suite": frost.SUITE,
        "production": False,
        "action": action,
        "artifact_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "artifact_manifest": manifest,
    }
    return authorization, auth_message_bytes


def load_json_file(path: Path, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise AuthorizationError(f"could not read {context} {path}") from exc
    except json.JSONDecodeError as exc:
        raise AuthorizationError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise AuthorizationError(f"refusing to overwrite existing receipt {path}")
    frost.write_json_atomic(path, value)


def require_exact_keys(
    value: dict[str, Any],
    expected_keys: set[str],
    context: str,
) -> None:
    actual_keys = set(value)
    unknown = actual_keys - expected_keys
    missing = expected_keys - actual_keys
    if unknown:
        raise AuthorizationError(f"{context} contains unsupported field: {sorted(unknown)[0]}")
    if missing:
        raise AuthorizationError(f"{context} is missing required field: {sorted(missing)[0]}")


def make_receipt(
    *,
    auth_message: dict[str, Any],
    auth_message_bytes: bytes,
    workflow: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "suite": frost.SUITE,
        "mode": frost.MODE,
        "production": False,
        "warning": frost.FIXTURE_WARNING,
        "action": auth_message["action"],
        "authorization_message_schema": AUTH_MESSAGE_SCHEMA,
        "authorization_message_sha256": hashlib.sha256(auth_message_bytes).hexdigest(),
        "artifact_manifest_sha256": auth_message["artifact_manifest_sha256"],
        "artifact_manifest": auth_message["artifact_manifest"],
        "group_public_key": workflow["group_public_key"],
        "group_commitment": workflow["group_commitment"],
        "challenge": workflow["challenge"],
        "signature_commitment": workflow["signature_commitment"],
        "signature_scalar": workflow["signature_scalar"],
        "verification": workflow["verification"],
    }


def validate_receipt_shape(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise AuthorizationError("authorization receipt must be a JSON object")
    require_exact_keys(
        raw,
        {
            "schema",
            "suite",
            "mode",
            "production",
            "warning",
            "action",
            "authorization_message_schema",
            "authorization_message_sha256",
            "artifact_manifest_sha256",
            "artifact_manifest",
            "group_public_key",
            "group_commitment",
            "challenge",
            "signature_commitment",
            "signature_scalar",
            "verification",
        },
        "authorization receipt",
    )
    if raw["schema"] != RECEIPT_SCHEMA:
        raise AuthorizationError("authorization receipt has unsupported schema")
    if raw["suite"] != frost.SUITE:
        raise AuthorizationError("authorization receipt has unsupported suite")
    if raw["mode"] != frost.MODE:
        raise AuthorizationError("authorization receipt has unsupported mode")
    if raw["production"] is not False:
        raise AuthorizationError("authorization receipt must set production to false")
    if raw["warning"] != frost.FIXTURE_WARNING:
        raise AuthorizationError("authorization receipt warning does not match")
    if raw["authorization_message_schema"] != AUTH_MESSAGE_SCHEMA:
        raise AuthorizationError(
            "authorization receipt has unsupported authorization message schema"
        )
    if raw["action"] not in ALLOWED_ACTIONS:
        raise AuthorizationError("authorization receipt has unsupported action")
    if raw["verification"] != "valid":
        raise AuthorizationError("authorization receipt is not marked valid")
    if raw["signature_commitment"] != raw["group_commitment"]:
        raise AuthorizationError(
            "authorization receipt signature commitment does not match challenge commitment"
        )
    if not isinstance(raw["artifact_manifest"], dict):
        raise AuthorizationError("authorization receipt artifact_manifest must be an object")
    return raw


def verify_receipt(
    *,
    bin_path: Path,
    artifact_path: Path,
    action: str,
    receipt_path: Path,
) -> None:
    receipt = validate_receipt_shape(
        load_json_file(receipt_path, "authorization receipt")
    )
    if receipt["action"] != action:
        raise AuthorizationError("authorization receipt action does not match request")

    auth_message, auth_message_bytes = build_authorization(
        bin_path,
        artifact_path,
        action,
    )
    expected_auth_hash = hashlib.sha256(auth_message_bytes).hexdigest()
    if receipt["artifact_manifest_sha256"] != auth_message["artifact_manifest_sha256"]:
        raise AuthorizationError(
            "authorization receipt artifact manifest digest does not match artifact"
        )
    if receipt["artifact_manifest"] != auth_message["artifact_manifest"]:
        raise AuthorizationError(
            "authorization receipt artifact manifest does not match artifact"
        )
    if receipt["authorization_message_sha256"] != expected_auth_hash:
        raise AuthorizationError(
            "authorization receipt message digest does not match artifact/action"
        )

    cli = WuciJi(bin_path)
    challenge = cli.run_scalar(
        [
            "frost-secp256k1-challenge",
            receipt["group_commitment"],
            receipt["group_public_key"],
        ],
        auth_message_bytes,
    )
    if receipt["challenge"] != challenge:
        raise AuthorizationError("authorization receipt challenge does not match")

    verification = cli.run(
        [
            "frost-secp256k1-verify",
            receipt["signature_commitment"],
            receipt["group_public_key"],
            receipt["signature_scalar"],
            challenge,
        ]
    ).strip()
    if verification != "valid":
        raise AuthorizationError(f"authorization receipt verification failed: {verification}")


def run_signing_flow(args: argparse.Namespace) -> dict[str, Any]:
    if args.transcript_manifest is None:
        raise AuthorizationError("--receipt requires --transcript-manifest")
    receipt_path = Path(args.receipt)
    if receipt_path.exists():
        raise AuthorizationError(f"refusing to overwrite existing receipt {receipt_path}")
    auth_message, auth_message_bytes = build_authorization(
        Path(args.bin),
        Path(args.artifact),
        args.action,
    )
    try:
        manifest = (
            frost.load_fixture_manifest(Path(args.fixture_manifest))
            if args.fixture_manifest is not None
            else frost.fixture_manifest()
        )
        transcript_manifest = frost.load_transcript_manifest(
            Path(args.transcript_manifest)
        )
        workflow = frost.run_fixture_workflow(
            frost.WuciJiCli(Path(args.bin)),
            auth_message_bytes,
            manifest,
            transcript_manifest,
        )
        if args.update_transcript_manifest:
            frost.write_json_atomic(
                Path(args.transcript_manifest),
                workflow["transcript_manifest"],
            )
    except frost.WorkflowError as exc:
        raise AuthorizationError(str(exc)) from exc
    receipt = make_receipt(
        auth_message=auth_message,
        auth_message_bytes=auth_message_bytes,
        workflow=workflow,
    )
    write_new_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or verify WUCI-WARRANT FROST authorization receipts over "
            "wuci-ji artifact manifests."
        )
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to the wuci-ji binary; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    parser.add_argument("--artifact", required=True, help="sealed artifact path")
    parser.add_argument("--action", required=True, choices=ALLOWED_ACTIONS)
    parser.add_argument(
        "--fixture-manifest",
        help="load the exact non-production FROST fixture manifest",
    )
    parser.add_argument(
        "--transcript-manifest",
        help="require an exact unspent FROST transcript manifest before signing",
    )
    parser.add_argument(
        "--update-transcript-manifest",
        action="store_true",
        help="after a successful receipt run, mark the transcript manifest spent",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--print-auth-message",
        action="store_true",
        help="print the exact canonical authorization message bytes and exit",
    )
    mode.add_argument(
        "--print-transcript-manifest",
        action="store_true",
        help="print the unspent FROST transcript manifest for this warrant and exit",
    )
    mode.add_argument("--receipt", help="write a new authorization receipt JSON file")
    mode.add_argument("--verify-receipt", help="verify an authorization receipt JSON file")
    args = parser.parse_args()

    if args.update_transcript_manifest and args.receipt is None:
        parser.error("--update-transcript-manifest requires --receipt")

    try:
        auth_message, auth_message_bytes = build_authorization(
            Path(args.bin),
            Path(args.artifact),
            args.action,
        )
        if args.print_auth_message:
            sys.stdout.buffer.write(auth_message_bytes)
            return 0
        if args.print_transcript_manifest:
            try:
                manifest = (
                    frost.load_fixture_manifest(Path(args.fixture_manifest))
                    if args.fixture_manifest is not None
                    else frost.fixture_manifest()
                )
                transcript, _signers = frost.build_fixture_transcript(
                    frost.WuciJiCli(Path(args.bin)),
                    auth_message_bytes,
                    manifest,
                )
            except frost.WorkflowError as exc:
                raise AuthorizationError(str(exc)) from exc
            print(json.dumps(transcript, indent=2, sort_keys=True))
            return 0
        if args.verify_receipt is not None:
            verify_receipt(
                bin_path=Path(args.bin),
                artifact_path=Path(args.artifact),
                action=args.action,
                receipt_path=Path(args.verify_receipt),
            )
            print("valid")
            return 0

        run_signing_flow(args)
    except AuthorizationError as exc:
        print(f"wuci warrant: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
