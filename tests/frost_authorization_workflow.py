#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
MESSAGE_SCHEMA = "wuci-frost-authorization-message-v1"
RECEIPT_SCHEMA = "wuci-frost-authorization-v1"


def run_tool(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(TOOL), "--bin", str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_wuci(args: list[str], stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(BIN), *args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def load_json(data: bytes) -> dict[str, Any]:
    value = json.loads(data.decode("ascii"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


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


def assert_private_fixture_material_absent(receipt: dict[str, Any]) -> None:
    forbidden = {
        "group_secret",
        "share",
        "hiding",
        "binding",
        "hiding_nonce",
        "binding_nonce",
        "signature_share",
    }
    assert not (nested_keys(receipt) & forbidden)
    encoded = json.dumps(receipt, sort_keys=True)
    for forbidden_text in (
        "group_secret",
        "hiding_nonce",
        "binding_nonce",
        "signature_share",
    ):
        assert forbidden_text not in encoded


def assert_verify_fails(
    artifact_path: Path,
    receipt_path: Path,
    expected_stderr: bytes,
    action: str = "open",
) -> None:
    proc = run_tool(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--verify-receipt",
            str(receipt_path),
        ]
    )
    assert proc.returncode != 0
    assert expected_stderr in proc.stderr, proc.stderr.decode("utf-8", "replace")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check WUCI-WARRANT manifest-bound FROST authorization receipts."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress receipt output")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        plain_path = tmp / "plain.txt"
        artifact_path = tmp / "sealed.wj"
        transcript_path = tmp / "auth-transcript.json"
        receipt_path = tmp / "auth-receipt.json"
        plain_path.write_bytes(b"wuci warrant artifact\n")

        key = "11" * 32
        key_id = "2233445566778899aabbccddeeff0011"
        sealed = run_wuci(
            [
                "seal-file-v2",
                key,
                key_id,
                str(plain_path),
                str(artifact_path),
            ]
        )
        assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
        assert sealed.stdout == b""

        manifest = run_wuci(["manifest-file", str(artifact_path)])
        assert manifest.returncode == 0, manifest.stderr.decode("utf-8", "replace")
        manifest_sha256 = hashlib.sha256(manifest.stdout).hexdigest()

        auth_message_proc = run_tool(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--print-auth-message",
            ]
        )
        assert auth_message_proc.returncode == 0, auth_message_proc.stderr.decode(
            "utf-8", "replace"
        )
        auth_message = load_json(auth_message_proc.stdout)
        assert auth_message["schema"] == MESSAGE_SCHEMA
        assert auth_message["action"] == "open"
        assert auth_message["production"] is False
        assert auth_message["artifact_manifest_sha256"] == manifest_sha256
        assert auth_message["artifact_manifest"]["key_id"] == key_id
        assert auth_message["artifact_manifest"]["artifact_sha256"]
        assert auth_message["artifact_manifest"]["ciphertext_sha256"]
        assert auth_message_proc.stdout.endswith(b"\n")

        transcript_proc = run_tool(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--print-transcript-manifest",
            ]
        )
        assert transcript_proc.returncode == 0, transcript_proc.stderr.decode(
            "utf-8", "replace"
        )
        transcript = load_json(transcript_proc.stdout)
        assert transcript["message_hex"] == auth_message_proc.stdout.hex()
        assert transcript["signing_shares_emitted"] is False
        write_json(transcript_path, transcript)

        receipt_proc = run_tool(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--transcript-manifest",
                str(transcript_path),
                "--update-transcript-manifest",
                "--receipt",
                str(receipt_path),
            ]
        )
        assert receipt_proc.returncode == 0, receipt_proc.stderr.decode(
            "utf-8", "replace"
        )
        assert receipt_proc.stdout == b""
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert receipt["schema"] == RECEIPT_SCHEMA
        assert receipt["production"] is False
        assert receipt["action"] == "open"
        assert receipt["artifact_manifest_sha256"] == manifest_sha256
        assert receipt["artifact_manifest"] == auth_message["artifact_manifest"]
        assert receipt["authorization_message_sha256"] == hashlib.sha256(
            auth_message_proc.stdout
        ).hexdigest()
        assert receipt["verification"] == "valid"
        assert_private_fixture_material_absent(receipt)

        updated_transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
        assert updated_transcript["signing_shares_emitted"] is True

        verify = run_tool(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--verify-receipt",
                str(receipt_path),
            ]
        )
        assert verify.returncode == 0, verify.stderr.decode("utf-8", "replace")
        assert verify.stdout == b"valid\n"

        assert_verify_fails(
            artifact_path,
            receipt_path,
            b"action does not match",
            action="release",
        )

        tampered_artifact_path = tmp / "tampered.wj"
        tampered_artifact = bytearray(artifact_path.read_bytes())
        tampered_artifact[-1] ^= 1
        tampered_artifact_path.write_bytes(tampered_artifact)
        assert_verify_fails(
            tampered_artifact_path,
            receipt_path,
            b"artifact manifest",
        )

        for field in ("artifact_sha256", "ciphertext_sha256", "nonce", "tag"):
            bad_receipt = json.loads(json.dumps(receipt))
            bad_receipt["artifact_manifest"][field] = "00"
            bad_receipt_path = tmp / f"bad-{field}.json"
            write_json(bad_receipt_path, bad_receipt)
            assert_verify_fails(artifact_path, bad_receipt_path, b"artifact manifest")

        bad_receipt = json.loads(json.dumps(receipt))
        bad_receipt["artifact_manifest_sha256"] = "00" * 32
        bad_receipt_path = tmp / "bad-manifest-digest.json"
        write_json(bad_receipt_path, bad_receipt)
        assert_verify_fails(artifact_path, bad_receipt_path, b"manifest digest")

        bad_receipt = json.loads(json.dumps(receipt))
        bad_receipt["signature_scalar"] = "00" * 32
        bad_receipt_path = tmp / "bad-signature-scalar.json"
        write_json(bad_receipt_path, bad_receipt)
        assert_verify_fails(artifact_path, bad_receipt_path, b"invalid")

        reused_receipt_path = tmp / "reused-receipt.json"
        reused = run_tool(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--transcript-manifest",
                str(transcript_path),
                "--receipt",
                str(reused_receipt_path),
            ]
        )
        assert reused.returncode != 0
        assert b"already emitted signing shares" in reused.stderr
        assert not reused_receipt_path.exists()

    if args.quiet:
        return
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
