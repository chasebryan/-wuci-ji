#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
GATE = REPO_ROOT / "tools" / "wuci_gate.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
PRIVATE_MARKERS = (
    b"group_secret",
    b"share",
    b"hiding",
    b"binding",
    b"hiding_nonce",
    b"binding_nonce",
    b"signature_share",
)


def run_wuci(args: list[str], stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(BIN), *args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_authorize(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(AUTHORIZE), "--bin", str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_gate(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    assert args
    return subprocess.run(
        [sys.executable, str(GATE), args[0], "--bin", str(BIN), *args[1:]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def output_labels(stdout: bytes) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in stdout.decode("ascii").splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            labels[label] = value
    return labels


def assert_no_private_material(data: bytes) -> None:
    for marker in PRIVATE_MARKERS:
        assert marker not in data


def assert_fails_without_plaintext(
    proc: subprocess.CompletedProcess[bytes],
    out_path: Path,
    expected_stderr: bytes,
) -> None:
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert expected_stderr in proc.stderr, proc.stderr.decode("utf-8", "replace")
    assert not out_path.exists()


def make_receipt(tmp: Path, artifact_path: Path, action: str) -> Path:
    transcript_path = tmp / f"{action}-transcript.json"
    receipt_path = tmp / f"{action}-receipt.json"
    transcript_proc = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--print-transcript-manifest",
        ]
    )
    assert transcript_proc.returncode == 0, transcript_proc.stderr.decode(
        "utf-8", "replace"
    )
    transcript_path.write_bytes(transcript_proc.stdout)

    receipt_proc = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--transcript-manifest",
            str(transcript_path),
            "--update-transcript-manifest",
            "--receipt",
            str(receipt_path),
        ]
    )
    assert receipt_proc.returncode == 0, receipt_proc.stderr.decode("utf-8", "replace")
    assert receipt_proc.stdout == b""
    return receipt_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check WUCI-GATE receipt-enforced open workflow."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress decision output")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        key_path = tmp / "artifact.key"
        bad_key_path = tmp / "bad.key"
        plain_path = tmp / "plain.txt"
        artifact_path = tmp / "sealed.wj"
        opened_path = tmp / "opened.txt"
        plain = b"wuci gate authorized plaintext\n"
        key_hex = "11" * 32
        key_id = "2233445566778899aabbccddeeff0011"
        key_path.write_text(key_hex + "\n", encoding="ascii")
        bad_key_path.write_text(("22" * 32) + "\n", encoding="ascii")
        plain_path.write_bytes(plain)

        sealed = run_wuci(
            [
                "seal-file-keyfile-v2",
                str(key_path),
                key_id,
                str(plain_path),
                str(artifact_path),
            ]
        )
        assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
        assert sealed.stdout == b""

        open_receipt_path = make_receipt(tmp, artifact_path, "open")
        release_receipt_path = make_receipt(tmp, artifact_path, "release")

        asm_message = run_wuci(["warrant-message-file", "open", str(artifact_path)])
        assert asm_message.returncode == 0, asm_message.stderr.decode(
            "utf-8", "replace"
        )
        tool_message = run_authorize(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--print-auth-message",
            ]
        )
        assert tool_message.returncode == 0, tool_message.stderr.decode(
            "utf-8", "replace"
        )
        assert asm_message.stdout == tool_message.stdout

        check = run_gate(
            [
                "check",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
            ]
        )
        assert check.returncode == 0, check.stderr.decode("utf-8", "replace")
        labels = output_labels(check.stdout)
        assert labels["authorized"] == "true"
        assert labels["action"] == "open"
        assert len(labels["artifact-sha256"]) == 64
        assert len(labels["authorization-message-sha256"]) == 64
        assert len(labels["receipt-sha256"]) == 64
        assert_no_private_material(check.stdout)

        check_json = run_gate(
            [
                "check",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--json",
            ]
        )
        assert check_json.returncode == 0, check_json.stderr.decode("utf-8", "replace")
        check_data = json.loads(check_json.stdout.decode("utf-8"))
        assert check_data["schema"] == "wuci-gate-check-v1"
        assert check_data["authorized"] is True
        assert check_data["action"] == "open"
        assert check_data["artifact_sha256"] == labels["artifact-sha256"]
        assert check_data["authorization_message_sha256"] == labels[
            "authorization-message-sha256"
        ]
        assert check_data["receipt_sha256"] == labels["receipt-sha256"]
        assert_no_private_material(check_json.stdout)

        opened = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(opened_path),
            ]
        )
        assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
        assert opened_path.read_bytes() == plain
        assert_no_private_material(opened.stdout)

        opened_json_path = tmp / "opened-json.txt"
        opened_json = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(opened_json_path),
                "--json",
            ]
        )
        assert opened_json.returncode == 0, opened_json.stderr.decode("utf-8", "replace")
        assert opened_json_path.read_bytes() == plain
        opened_data = json.loads(opened_json.stdout.decode("utf-8"))
        assert opened_data["schema"] == "wuci-gate-open-v1"
        assert opened_data["authorized"] is True
        assert opened_data["opened_path"] == str(opened_json_path)
        assert_no_private_material(opened_json.stdout)

        release_out = tmp / "release-opened.txt"
        release_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "release",
                "--receipt",
                str(release_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(release_out),
            ]
        )
        assert_fails_without_plaintext(
            release_open,
            release_out,
            b"gate open requires",
        )

        tampered_artifact_path = tmp / "tampered.wj"
        tampered_artifact = bytearray(artifact_path.read_bytes())
        tampered_artifact[-1] ^= 1
        tampered_artifact_path.write_bytes(tampered_artifact)
        tampered_out = tmp / "tampered-opened.txt"
        tampered_open = run_gate(
            [
                "open",
                "--artifact",
                str(tampered_artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(tampered_out),
            ]
        )
        assert_fails_without_plaintext(
            tampered_open,
            tampered_out,
            b"artifact manifest",
        )

        receipt = json.loads(open_receipt_path.read_text(encoding="utf-8"))
        bad_metadata = json.loads(json.dumps(receipt))
        bad_metadata["artifact_manifest"]["nonce"] = "00"
        bad_metadata_path = tmp / "bad-metadata.json"
        write_json(bad_metadata_path, bad_metadata)
        bad_metadata_out = tmp / "bad-metadata-opened.txt"
        bad_metadata_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(bad_metadata_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(bad_metadata_out),
            ]
        )
        assert_fails_without_plaintext(
            bad_metadata_open,
            bad_metadata_out,
            b"artifact manifest",
        )

        bad_signature = json.loads(json.dumps(receipt))
        bad_signature["signature_scalar"] = "00" * 32
        bad_signature_path = tmp / "bad-signature.json"
        write_json(bad_signature_path, bad_signature)
        bad_signature_out = tmp / "bad-signature-opened.txt"
        bad_signature_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(bad_signature_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(bad_signature_out),
            ]
        )
        assert_fails_without_plaintext(
            bad_signature_open,
            bad_signature_out,
            b"invalid",
        )

        wrong_key_out = tmp / "wrong-key-opened.txt"
        wrong_key_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(bad_key_path),
                "--out",
                str(wrong_key_out),
            ]
        )
        assert_fails_without_plaintext(
            wrong_key_open,
            wrong_key_out,
            b"envelope authentication failed",
        )

        existing_out = tmp / "existing.txt"
        existing_out.write_bytes(b"do-not-touch")
        existing_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(existing_out),
            ]
        )
        assert existing_open.returncode != 0
        assert b"refusing to overwrite" in existing_open.stderr
        assert existing_out.read_bytes() == b"do-not-touch"

        existing_dir_out = tmp / "existing-dir"
        existing_dir_out.mkdir()
        existing_dir_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(existing_dir_out),
            ]
        )
        assert existing_dir_open.returncode != 0
        assert existing_dir_open.stdout == b""
        assert b"refusing to overwrite" in existing_dir_open.stderr
        assert existing_dir_out.is_dir()

        dangling_target = tmp / "missing-symlink-target.txt"
        dangling_out = tmp / "dangling-output.txt"
        dangling_out.symlink_to(dangling_target)
        dangling_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(dangling_out),
            ]
        )
        assert dangling_open.returncode != 0
        assert dangling_open.stdout == b""
        assert b"refusing to overwrite" in dangling_open.stderr
        assert dangling_out.is_symlink()
        assert not dangling_target.exists()

        missing_parent_out = tmp / "missing-parent" / "opened.txt"
        missing_parent_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(missing_parent_out),
            ]
        )
        assert_fails_without_plaintext(
            missing_parent_open,
            missing_parent_out,
            b"output parent directory does not exist",
        )
        assert not missing_parent_out.parent.exists()

        parent_file = tmp / "parent-file"
        parent_file.write_bytes(b"not-a-directory")
        parent_file_out = parent_file / "opened.txt"
        parent_file_open = run_gate(
            [
                "open",
                "--artifact",
                str(artifact_path),
                "--action",
                "open",
                "--receipt",
                str(open_receipt_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(parent_file_out),
            ]
        )
        assert_fails_without_plaintext(
            parent_file_open,
            parent_file_out,
            b"output parent is not a directory",
        )
        assert parent_file.read_bytes() == b"not-a-directory"

    if args.quiet:
        return
    print(check.stdout.decode("ascii"), end="")


if __name__ == "__main__":
    main()
