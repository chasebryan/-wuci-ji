#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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
AUTHORITY_TOOL = REPO_ROOT / "tools" / "wuci_authority_root.py"
ANCHOR_TOOL = REPO_ROOT / "tools" / "wuci_authority_anchor.py"
ANCHOR = REPO_ROOT / "authority" / "wuci-root.fixture.txt"
ANCHOR_SHA256 = REPO_ROOT / "authority" / "wuci-root.fixture.sha256"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


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


def run_contract(command: str, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(CONTRACT_TOOL), command, "--bin", str(BIN), *args])


def run_authority(command: str, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(AUTHORITY_TOOL), command, *args])


def run_anchor(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(ANCHOR_TOOL), "check", *args])


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def read_value(text: str, label: str) -> str:
    prefix = f"{label}: "
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    raise AssertionError(f"missing label {label}")


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def authority_id(group_public_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(group_public_key)).hexdigest()


def authority_text(
    group_public_key: str,
    *,
    allow_open: str = "true",
    allow_release: str = "false",
) -> str:
    return (
        "schema: wuci-authority-root-v1\n"
        "suite: FROST-secp256k1-SHA256-v1\n"
        "production: false\n"
        f"authority-id: {authority_id(group_public_key)}\n"
        f"group-public-key: {group_public_key}\n"
        f"allow-open: {allow_open}\n"
        f"allow-release: {allow_release}\n"
        "allow-trust: false\n"
        "allow-publish: false\n"
    )


def mutate_text(base: bytes, path: Path, mutator: Callable[[str], str]) -> Path:
    path.write_text(mutator(base.decode("ascii")), encoding="ascii")
    return path


def write_artifact(tmp: Path) -> tuple[Path, Path, Path, bytes]:
    key_path = tmp / "artifact.key"
    plain_path = tmp / "plain.txt"
    artifact_path = tmp / "sealed.wj"
    plain = b"wuci anchored gate plaintext\n"
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
    return key_path, plain_path, artifact_path, plain


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
    assert_ok(transcript, "write open transcript")
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
    assert_ok(receipt, "write open receipt")
    return receipt_path


def emit_contract(artifact_path: Path, receipt_path: Path, contract_path: Path) -> None:
    emitted = run_contract(
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
    assert_ok(emitted, "emit open contract")


def assert_anchor_fails(
    authority_path: Path,
    contract_path: Path,
    context: str = "anchor failure",
) -> None:
    proc = run_anchor(
        [
            "--authority",
            str(authority_path),
            "--contract",
            str(contract_path),
            "--quiet",
        ]
    )
    assert proc.returncode != 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )
    assert proc.stdout == b"", context
    assert b"wuci authority anchor:" in proc.stderr, context


def assert_strict_anchor_fails(authority_path: Path, contract_path: Path) -> None:
    proc = run_anchor(
        [
            "--authority",
            str(authority_path),
            "--sha256",
            str(ANCHOR_SHA256),
            "--contract",
            str(contract_path),
            "--strict-fixture-path",
            "--quiet",
        ]
    )
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"wuci authority anchor:" in proc.stderr


def assert_rooted_verify_fails(authority_path: Path, artifact_path: Path, contract_path: Path) -> None:
    proc = run_wuci(
        [
            "gate-contract-verify-rooted",
            str(authority_path),
            str(artifact_path),
            str(contract_path),
        ]
    )
    assert proc.returncode != 0
    assert proc.stdout == b""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check anchored WUCI-ROOT authority behavior."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        key_path, _plain_path, artifact_path, plain = write_artifact(tmp)
        receipt_path = make_receipt(tmp, artifact_path)
        contract_path = tmp / "receipt-contract.txt"
        emit_contract(artifact_path, receipt_path, contract_path)

        contract_text = contract_path.read_text(encoding="ascii")
        fixture_key = read_value(ANCHOR.read_text(encoding="ascii"), "group-public-key")
        contract_key = read_value(contract_text, "group-public-key")
        group_commitment = read_value(contract_text, "group-commitment")
        assert contract_key == fixture_key

        anchor = run_anchor(
            [
                "--authority",
                str(ANCHOR),
                "--sha256",
                str(ANCHOR_SHA256),
                "--contract",
                str(contract_path),
                "--strict-fixture-path",
                "--quiet",
            ]
        )
        assert_ok(anchor, "strict committed anchor check")

        asm_authority = run_wuci(["authority-root-verify", str(ANCHOR)])
        assert_ok(asm_authority, "assembly authority verify")
        rooted = run_wuci(
            [
                "gate-contract-verify-rooted",
                str(ANCHOR),
                str(artifact_path),
                str(contract_path),
            ]
        )
        assert_ok(rooted, "assembly rooted verify with anchor")
        opened_path = tmp / "opened.txt"
        opened = run_wuci(
            [
                "open-authorized-rooted",
                str(ANCHOR),
                str(key_path),
                str(artifact_path),
                str(contract_path),
                str(opened_path),
            ]
        )
        assert_ok(opened, "assembly rooted open with anchor")
        assert opened_path.read_bytes() == plain

        self_derived_authority = tmp / "self-derived-authority.txt"
        derived = run_authority(
            "emit",
            [
                "--contract",
                str(contract_path),
                "--authority",
                str(self_derived_authority),
                "--quiet",
            ],
        )
        assert_ok(derived, "emit self-derived authority")
        assert self_derived_authority.read_text(encoding="ascii") == ANCHOR.read_text(
            encoding="ascii"
        )
        assert_strict_anchor_fails(self_derived_authority, contract_path)

        mismatch_authority = tmp / "mismatch-authority.txt"
        mismatch_authority.write_text(authority_text(group_commitment), encoding="ascii")
        assert_anchor_fails(mismatch_authority, contract_path, "group-key mismatch")
        assert_rooted_verify_fails(mismatch_authority, artifact_path, contract_path)

        anchor_base = ANCHOR.read_bytes()
        for name, mutator in (
            (
                "authority-id-mismatch",
                lambda text: replace_value(text, "authority-id", "00" * 32),
            ),
            ("allow-open-false", lambda text: replace_value(text, "allow-open", "false")),
            ("allow-release-true", lambda text: replace_value(text, "allow-release", "true")),
            (
                "reordered-fields",
                lambda text: "".join(
                    [text.splitlines(keepends=True)[1]]
                    + [text.splitlines(keepends=True)[0]]
                    + text.splitlines(keepends=True)[2:]
                ),
            ),
            ("crlf", lambda text: text.replace("\n", "\r\n")),
        ):
            bad_authority = mutate_text(anchor_base, tmp / f"{name}.txt", mutator)
            assert_anchor_fails(bad_authority, contract_path, name)

        missing_authority = tmp / "missing-authority.txt"
        assert_anchor_fails(missing_authority, contract_path, "missing authority")

        bad_contract = mutate_text(
            contract_path.read_bytes(),
            tmp / "tampered-contract.txt",
            lambda text: replace_value(text, "signature-scalar", "00" * 32),
        )
        assert_rooted_verify_fails(ANCHOR, artifact_path, bad_contract)

    if not args.quiet:
        print("wuci authority anchor: PASS")


if __name__ == "__main__":
    main()
