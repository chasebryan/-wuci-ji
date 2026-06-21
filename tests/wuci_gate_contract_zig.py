#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
CONTRACT_TOOL = REPO_ROOT / "tools" / "wuci_receipt_contract.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
ZIG_CONTRACT = Path(
    os.environ.get("WUCI_GATE_CONTRACT_BIN", REPO_ROOT / "build" / "wuci-gate-contract")
)


def run_cmd(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    env["WUCI_JI_RUNNER"] = " ".join(RUNNER)
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
        env=env,
    )


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([*RUNNER, str(BIN), *args])


def run_authorize(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(AUTHORIZE), "--bin", str(BIN), *args])


def run_python_contract(command: str, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd(
        [sys.executable, str(CONTRACT_TOOL), command, "--bin", str(BIN), *args]
    )


def run_zig_contract(command: str, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd(
        [
            str(ZIG_CONTRACT),
            command,
            "--bin",
            str(BIN),
            *args,
        ]
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def make_receipt(tmp: Path, artifact_path: Path) -> Path:
    transcript_path = tmp / "open-transcript.json"
    receipt_path = tmp / "open-receipt.json"
    transcript = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--print-transcript-manifest",
        ]
    )
    assert_ok(transcript, "write transcript manifest")
    transcript_path.write_bytes(transcript.stdout)

    receipt = run_authorize(
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
    assert_ok(receipt, "write receipt")
    assert receipt.stdout == b""
    return receipt_path


def write_artifact(tmp: Path) -> tuple[Path, Path, bytes]:
    key_path = tmp / "artifact.key"
    plain_path = tmp / "plain.txt"
    artifact_path = tmp / "sealed.wj"
    plain = b"wuci zig gate contract plaintext\n"
    key_path.write_text(("11" * 32) + "\n", encoding="ascii")
    plain_path.write_bytes(plain)
    sealed = run_wuci(
        [
            "seal-file-keyfile-v2",
            str(key_path),
            "2233445566778899aabbccddeeff0011",
            str(plain_path),
            str(artifact_path),
        ]
    )
    assert_ok(sealed, "seal artifact")
    assert sealed.stdout == b""
    return key_path, artifact_path, plain


def emit_contract(artifact_path: Path, receipt_path: Path, contract_path: Path) -> None:
    emitted = run_python_contract(
        "emit",
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "open",
            "--receipt",
            str(receipt_path),
            "--contract",
            str(contract_path),
            "--quiet",
        ],
    )
    assert_ok(emitted, "emit Python flat contract")


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def mutate_contract(
    base: bytes,
    path: Path,
    mutator: Callable[[str], str],
) -> Path:
    path.write_text(mutator(base.decode("ascii")), encoding="ascii")
    return path


def assert_zig_verify_fails(
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
    expected_stderr: bytes,
) -> None:
    proc = run_zig_contract(
        "verify",
        [
            "--artifact",
            str(artifact_path),
            "--receipt",
            str(receipt_path),
            "--contract",
            str(contract_path),
        ],
    )
    assert proc.returncode != 0
    assert expected_stderr in proc.stderr, proc.stderr.decode("utf-8", "replace")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the Zig WUCI-GATE flat-contract verifier."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        key_path, artifact_path, plain = write_artifact(tmp)
        receipt_path = make_receipt(tmp, artifact_path)
        contract_path = tmp / "receipt-contract.txt"
        emit_contract(artifact_path, receipt_path, contract_path)

        valid = run_zig_contract(
            "verify",
            [
                "--artifact",
                str(artifact_path),
                "--receipt",
                str(receipt_path),
                "--contract",
                str(contract_path),
            ],
        )
        assert_ok(valid, "Zig verify")
        assert valid.stdout == b"valid\n"

        opened_path = tmp / "opened.txt"
        opened = run_zig_contract(
            "open",
            [
                "--artifact",
                str(artifact_path),
                "--receipt",
                str(receipt_path),
                "--contract",
                str(contract_path),
                "--keyfile",
                str(key_path),
                "--out",
                str(opened_path),
            ],
        )
        assert_ok(opened, "Zig contract open")
        assert opened.stdout == b"valid\n"
        assert opened_path.read_bytes() == plain

        base_contract = contract_path.read_bytes()
        assert_zig_verify_fails(
            artifact_path,
            receipt_path,
            mutate_contract(
                base_contract,
                tmp / "bad-artifact-digest.txt",
                lambda text: replace_value(text, "artifact-sha256", "00" * 32),
            ),
            b"artifact-sha256 mismatch",
        )
        assert_zig_verify_fails(
            artifact_path,
            receipt_path,
            mutate_contract(
                base_contract,
                tmp / "bad-signature-commitment.txt",
                lambda text: replace_value(
                    text,
                    "signature-commitment",
                    "02" + ("01" * 32),
                ),
            ),
            b"SignatureCommitmentMismatch",
        )
        assert_zig_verify_fails(
            artifact_path,
            receipt_path,
            mutate_contract(
                base_contract,
                tmp / "bad-challenge.txt",
                lambda text: replace_value(text, "challenge", "00" * 32),
            ),
            b"ChallengeMismatch",
        )
        assert_zig_verify_fails(
            artifact_path,
            receipt_path,
            mutate_contract(
                base_contract,
                tmp / "bad-signature-scalar.txt",
                lambda text: replace_value(text, "signature-scalar", "00" * 32),
            ),
            b"InvalidSignature",
        )

        tampered_receipt = tmp / "tampered-receipt.json"
        tampered_receipt.write_bytes(receipt_path.read_bytes() + b"\n")
        assert_zig_verify_fails(
            artifact_path,
            tampered_receipt,
            contract_path,
            b"receipt-sha256 mismatch",
        )

        tampered_artifact = tmp / "tampered.wj"
        data = bytearray(artifact_path.read_bytes())
        data[-1] ^= 1
        tampered_artifact.write_bytes(data)
        assert_zig_verify_fails(
            tampered_artifact,
            receipt_path,
            contract_path,
            b"artifact-sha256 mismatch",
        )

    if not args.quiet:
        print("wuci zig gate contract tests passed")


if __name__ == "__main__":
    main()
