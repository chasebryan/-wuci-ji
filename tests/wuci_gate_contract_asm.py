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


def write_artifact(tmp: Path) -> tuple[Path, Path, Path, bytes]:
    key_path = tmp / "artifact.key"
    plain_path = tmp / "plain.txt"
    artifact_path = tmp / "sealed.wj"
    plain = b"wuci asm gate contract plaintext\n"
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
    return key_path, plain_path, artifact_path, plain


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


def read_value(text: str, label: str) -> str:
    prefix = f"{label}: "
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    raise AssertionError(f"missing label {label}")


def mutate_contract(
    base: bytes,
    path: Path,
    mutator: Callable[[str], str],
) -> Path:
    path.write_text(mutator(base.decode("ascii")), encoding="ascii")
    return path


def assert_verify_fails(artifact_path: Path, contract_path: Path) -> None:
    proc = run_wuci(["gate-contract-verify", str(artifact_path), str(contract_path)])
    assert proc.returncode != 0
    assert b"gate contract verification failed" in proc.stderr


def assert_open_fails_without_plaintext(
    *,
    key_path: Path,
    artifact_path: Path,
    contract_path: Path,
    out_path: Path,
) -> None:
    proc = run_wuci(
        [
            "open-authorized-contract",
            str(key_path),
            str(artifact_path),
            str(contract_path),
            str(out_path),
        ]
    )
    assert proc.returncode != 0
    assert not out_path.exists(), f"unexpected plaintext output: {out_path}"


def assert_auth_mutation_rejected(
    *,
    key_path: Path,
    artifact_path: Path,
    contract_path: Path,
    out_path: Path,
) -> None:
    assert_verify_fails(artifact_path, contract_path)
    assert_open_fails_without_plaintext(
        key_path=key_path,
        artifact_path=artifact_path,
        contract_path=contract_path,
        out_path=out_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the assembly WUCI-GATE flat-contract verifier."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        key_path, plain_path, artifact_path, plain = write_artifact(tmp)
        receipt_path = make_receipt(tmp, artifact_path)
        contract_path = tmp / "receipt-contract.txt"
        emit_contract(artifact_path, receipt_path, contract_path)

        valid = run_wuci(
            ["gate-contract-verify", str(artifact_path), str(contract_path)]
        )
        assert_ok(valid, "assembly contract verify")
        assert valid.stdout == b"valid\n"

        opened_path = tmp / "opened.txt"
        opened = run_wuci(
            [
                "open-authorized-contract",
                str(key_path),
                str(artifact_path),
                str(contract_path),
                str(opened_path),
            ]
        )
        assert_ok(opened, "assembly contract open")
        assert opened.stdout == b""
        assert opened_path.read_bytes() == plain

        base_contract = contract_path.read_bytes()
        base_text = base_contract.decode("ascii")
        group_public_key = read_value(base_text, "group-public-key")

        cases: list[tuple[str, Callable[[str], str]]] = [
            (
                "malformed",
                lambda text: text.replace("schema: ", "schema=", 1),
            ),
            (
                "reordered-fields",
                lambda text: "".join(
                    [text.splitlines(keepends=True)[1]]
                    + [text.splitlines(keepends=True)[0]]
                    + text.splitlines(keepends=True)[2:]
                ),
            ),
            ("crlf", lambda text: text.replace("\n", "\r\n")),
            ("extra-newline", lambda text: text + "\n"),
            (
                "unsupported-schema",
                lambda text: replace_value(text, "schema", "wuci-gate-v2"),
            ),
            ("wrong-action", lambda text: replace_value(text, "action", "release")),
            (
                "wrong-artifact-hash",
                lambda text: replace_value(text, "artifact-sha256", "00" * 32),
            ),
            (
                "wrong-manifest-hash",
                lambda text: replace_value(
                    text, "artifact-manifest-sha256", "00" * 32
                ),
            ),
            (
                "wrong-authorization-message-hash",
                lambda text: replace_value(
                    text, "authorization-message-sha256", "00" * 32
                ),
            ),
            (
                "wrong-group-commitment",
                lambda text: replace_value(
                    replace_value(text, "group-commitment", group_public_key),
                    "signature-commitment",
                    group_public_key,
                ),
            ),
            (
                "wrong-signature-commitment",
                lambda text: replace_value(
                    text, "signature-commitment", group_public_key
                ),
            ),
            (
                "wrong-challenge",
                lambda text: replace_value(text, "challenge", "00" * 32),
            ),
            (
                "tampered-signature-scalar",
                lambda text: replace_value(text, "signature-scalar", "00" * 32),
            ),
        ]

        for name, mutator in cases:
            bad_contract = mutate_contract(
                base_contract,
                tmp / f"{name}.txt",
                mutator,
            )
            assert_auth_mutation_rejected(
                key_path=key_path,
                artifact_path=artifact_path,
                contract_path=bad_contract,
                out_path=tmp / f"{name}.opened",
            )

        wrong_key = tmp / "wrong.key"
        wrong_key.write_text(("22" * 32) + "\n", encoding="ascii")
        assert_open_fails_without_plaintext(
            key_path=wrong_key,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "wrong-key.opened",
        )

        existing_out = tmp / "existing.txt"
        existing_out.write_text("keep me\n", encoding="ascii")
        exists = run_wuci(
            [
                "open-authorized-contract",
                str(key_path),
                str(artifact_path),
                str(contract_path),
                str(existing_out),
            ]
        )
        assert exists.returncode != 0
        assert existing_out.read_text(encoding="ascii") == "keep me\n"

        dangling_link = tmp / "dangling-link"
        dangling_target = tmp / "missing-target"
        dangling_link.symlink_to(dangling_target)
        link_proc = run_wuci(
            [
                "open-authorized-contract",
                str(key_path),
                str(artifact_path),
                str(contract_path),
                str(dangling_link),
            ]
        )
        assert link_proc.returncode != 0
        assert not dangling_target.exists()

        assert_open_fails_without_plaintext(
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "missing-parent" / "opened.txt",
        )

        assert_open_fails_without_plaintext(
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=plain_path / "opened.txt",
        )

    if not args.quiet:
        print("wuci asm gate contract tests passed")


if __name__ == "__main__":
    main()
