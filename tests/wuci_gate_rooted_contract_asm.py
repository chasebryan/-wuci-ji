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


def make_receipt(tmp: Path, artifact_path: Path, action: str) -> Path:
    transcript_path = tmp / f"{action}-transcript.json"
    receipt_path = tmp / f"{action}-receipt.json"
    reserved_args = ["--allow-reserved-action"] if action in {"trust", "publish"} else []
    transcript = run_authorize(
        [
            *reserved_args,
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--print-transcript-manifest",
        ]
    )
    assert_ok(transcript, f"write {action} transcript manifest")
    transcript_path.write_bytes(transcript.stdout)

    receipt = run_authorize(
        [
            *reserved_args,
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
    assert_ok(receipt, f"write {action} receipt")
    assert receipt.stdout == b""
    return receipt_path


def write_artifact(tmp: Path) -> tuple[Path, Path, Path, bytes]:
    key_path = tmp / "artifact.key"
    plain_path = tmp / "plain.txt"
    artifact_path = tmp / "sealed.wj"
    plain = b"wuci rooted gate plaintext\n"
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


def emit_contract(
    artifact_path: Path,
    receipt_path: Path,
    contract_path: Path,
    action: str,
) -> None:
    reserved_args = ["--allow-reserved-action"] if action in {"trust", "publish"} else []
    emitted = run_contract(
        "emit",
        [
            *reserved_args,
            "--artifact",
            str(artifact_path),
            "--action",
            action,
            "--receipt",
            str(receipt_path),
            "--contract",
            str(contract_path),
            "--quiet",
        ],
    )
    assert_ok(emitted, f"emit {action} flat contract")


def emit_authority(
    contract_path: Path,
    authority_path: Path,
    *,
    allow_open: str = "true",
    allow_release: str = "false",
) -> None:
    emitted = run_authority(
        "emit",
        [
            "--contract",
            str(contract_path),
            "--authority",
            str(authority_path),
            "--allow-open",
            allow_open,
            "--allow-release",
            allow_release,
            "--quiet",
        ],
    )
    assert_ok(emitted, "emit authority root")


def mutate_text(base: bytes, path: Path, mutator: Callable[[str], str]) -> Path:
    path.write_text(mutator(base.decode("ascii")), encoding="ascii")
    return path


def assert_authority_fails(authority_path: Path) -> None:
    proc = run_wuci(["authority-root-verify", str(authority_path)])
    assert proc.returncode != 0
    assert b"authority root verification failed" in proc.stderr
    assert proc.stdout == b""


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


def assert_rooted_release_fails(
    authority_path: Path,
    artifact_path: Path,
    contract_path: Path,
) -> None:
    proc = run_wuci(
        [
            "release-authorized-rooted",
            str(authority_path),
            str(artifact_path),
            str(contract_path),
        ]
    )
    assert proc.returncode != 0
    assert proc.stdout == b""


def assert_rooted_open_fails_without_plaintext(
    *,
    authority_path: Path,
    key_path: Path,
    artifact_path: Path,
    contract_path: Path,
    out_path: Path,
) -> None:
    proc = run_wuci(
        [
            "open-authorized-rooted",
            str(authority_path),
            str(key_path),
            str(artifact_path),
            str(contract_path),
            str(out_path),
        ]
    )
    assert proc.returncode != 0
    assert not out_path.exists(), f"unexpected plaintext output: {out_path}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check assembly rooted WUCI-GATE contract enforcement."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        key_path, plain_path, artifact_path, plain = write_artifact(tmp)
        receipt_path = make_receipt(tmp, artifact_path, "open")
        contract_path = tmp / "receipt-contract.txt"
        emit_contract(artifact_path, receipt_path, contract_path, "open")

        authority_path = tmp / "authority-root.txt"
        emit_authority(contract_path, authority_path)
        authority_text_base = authority_path.read_bytes()
        contract_base = contract_path.read_bytes()
        contract_text = contract_base.decode("ascii")

        tool_verify = run_authority(
            "verify",
            ["--authority", str(authority_path), "--quiet"],
        )
        assert_ok(tool_verify, "Python authority root verify")

        authority = run_wuci(["authority-root-verify", str(authority_path)])
        assert_ok(authority, "assembly authority root verify")
        assert authority.stdout == b"valid\n"

        rooted_valid = run_wuci(
            [
                "gate-contract-verify-rooted",
                str(authority_path),
                str(artifact_path),
                str(contract_path),
            ]
        )
        assert_ok(rooted_valid, "assembly rooted contract verify")
        assert rooted_valid.stdout == b"valid\n"

        opened_path = tmp / "opened.txt"
        opened = run_wuci(
            [
                "open-authorized-rooted",
                str(authority_path),
                str(key_path),
                str(artifact_path),
                str(contract_path),
                str(opened_path),
            ]
        )
        assert_ok(opened, "assembly rooted contract open")
        assert opened.stdout == b""
        assert opened_path.read_bytes() == plain

        group_public_key = read_value(contract_text, "group-public-key")
        group_commitment = read_value(contract_text, "group-commitment")
        mismatched_authority = tmp / "authority-mismatched-group.txt"
        mismatched_authority.write_text(authority_text(group_commitment), encoding="ascii")
        assert_rooted_verify_fails(mismatched_authority, artifact_path, contract_path)
        assert_rooted_open_fails_without_plaintext(
            authority_path=mismatched_authority,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "mismatch.opened",
        )

        authority_cases: list[tuple[str, Callable[[str], str]]] = [
            ("malformed", lambda text: text.replace("schema: ", "schema=", 1)),
            (
                "reordered-fields",
                lambda text: "".join(
                    [text.splitlines(keepends=True)[1]]
                    + [text.splitlines(keepends=True)[0]]
                    + text.splitlines(keepends=True)[2:]
                ),
            ),
            ("crlf", lambda text: text.replace("\n", "\r\n")),
            (
                "unsupported-schema",
                lambda text: replace_value(text, "schema", "wuci-authority-root-v0"),
            ),
            (
                "unsupported-suite",
                lambda text: replace_value(text, "suite", "FROST-test-v0"),
            ),
            (
                "wrong-authority-id",
                lambda text: replace_value(text, "authority-id", "00" * 32),
            ),
            (
                "bad-group-key",
                lambda text: replace_value(text, "group-public-key", "00" * 33),
            ),
        ]
        for name, mutator in authority_cases:
            bad_authority = mutate_text(
                authority_text_base,
                tmp / f"{name}.authority.txt",
                mutator,
            )
            assert_authority_fails(bad_authority)
            assert_rooted_open_fails_without_plaintext(
                authority_path=bad_authority,
                key_path=key_path,
                artifact_path=artifact_path,
                contract_path=contract_path,
                out_path=tmp / f"{name}.opened",
            )

        open_denied_authority = tmp / "authority-open-denied.txt"
        open_denied_authority.write_text(
            authority_text(group_public_key, allow_open="false"),
            encoding="ascii",
        )
        open_denied = run_wuci(["authority-root-verify", str(open_denied_authority)])
        assert_ok(open_denied, "authority with open denied still parses")
        assert_rooted_verify_fails(open_denied_authority, artifact_path, contract_path)
        assert_rooted_open_fails_without_plaintext(
            authority_path=open_denied_authority,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "open-denied.opened",
        )

        release_receipt_path = make_receipt(tmp, artifact_path, "release")
        release_contract_path = tmp / "release-contract.txt"
        emit_contract(artifact_path, release_receipt_path, release_contract_path, "release")
        release_authority_path = tmp / "release-authority-root.txt"
        emit_authority(
            release_contract_path,
            release_authority_path,
            allow_open="false",
            allow_release="true",
        )
        release_authority = run_wuci(
            ["authority-root-verify", str(release_authority_path)]
        )
        assert_ok(release_authority, "assembly release authority root verify")
        release_rooted = run_wuci(
            [
                "release-authorized-rooted",
                str(release_authority_path),
                str(artifact_path),
                str(release_contract_path),
            ]
        )
        assert_ok(release_rooted, "assembly rooted release")
        release_text = release_rooted.stdout.decode("ascii")
        assert release_text.startswith("authorized: true\naction: release\n")
        assert (
            f"artifact-sha256: {read_value(release_contract_path.read_text(encoding='ascii'), 'artifact-sha256')}\n"
            in release_text
        )

        assert_rooted_verify_fails(authority_path, artifact_path, release_contract_path)
        assert_rooted_release_fails(authority_path, artifact_path, release_contract_path)
        assert_rooted_open_fails_without_plaintext(
            authority_path=authority_path,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=release_contract_path,
            out_path=tmp / "release-contract.opened",
        )
        assert_rooted_open_fails_without_plaintext(
            authority_path=release_authority_path,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "release-authority-opened",
        )
        assert_rooted_release_fails(release_authority_path, artifact_path, contract_path)

        release_mismatch_authority = tmp / "release-authority-mismatched-group.txt"
        release_mismatch_authority.write_text(
            authority_text(
                group_commitment,
                allow_open="false",
                allow_release="true",
            ),
            encoding="ascii",
        )
        assert_rooted_release_fails(
            release_mismatch_authority,
            artifact_path,
            release_contract_path,
        )

        for action in ("trust", "publish"):
            action_receipt_path = make_receipt(tmp, artifact_path, action)
            action_contract_path = tmp / f"{action}-contract.txt"
            emit_contract(artifact_path, action_receipt_path, action_contract_path, action)
            assert_rooted_release_fails(
                release_authority_path,
                artifact_path,
                action_contract_path,
            )

        for name, mutator in (
            (
                "release-wrong-challenge",
                lambda text: replace_value(text, "challenge", "00" * 32),
            ),
            (
                "release-tampered-signature-scalar",
                lambda text: replace_value(text, "signature-scalar", "00" * 32),
            ),
        ):
            bad_release_contract = mutate_text(
                release_contract_path.read_bytes(),
                tmp / f"{name}.txt",
                mutator,
            )
            assert_rooted_release_fails(
                release_authority_path,
                artifact_path,
                bad_release_contract,
            )

        signature_tamper = mutate_text(
            contract_base,
            tmp / "signature-tamper.txt",
            lambda text: replace_value(text, "signature-scalar", "00" * 32),
        )
        assert_rooted_verify_fails(authority_path, artifact_path, signature_tamper)
        assert_rooted_open_fails_without_plaintext(
            authority_path=authority_path,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=signature_tamper,
            out_path=tmp / "signature-tamper.opened",
        )

        artifact_tamper_path = tmp / "tampered.wj"
        artifact_data = bytearray(artifact_path.read_bytes())
        artifact_data[-1] ^= 1
        artifact_tamper_path.write_bytes(artifact_data)
        assert_rooted_verify_fails(authority_path, artifact_tamper_path, contract_path)
        assert_rooted_open_fails_without_plaintext(
            authority_path=authority_path,
            key_path=key_path,
            artifact_path=artifact_tamper_path,
            contract_path=contract_path,
            out_path=tmp / "artifact-tamper.opened",
        )

        wrong_key = tmp / "wrong.key"
        wrong_key.write_text(("22" * 32) + "\n", encoding="ascii")
        assert_rooted_open_fails_without_plaintext(
            authority_path=authority_path,
            key_path=wrong_key,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "wrong-key.opened",
        )

        existing_out = tmp / "existing.txt"
        existing_out.write_text("keep me\n", encoding="ascii")
        exists = run_wuci(
            [
                "open-authorized-rooted",
                str(authority_path),
                str(key_path),
                str(artifact_path),
                str(contract_path),
                str(existing_out),
            ]
        )
        assert exists.returncode != 0
        assert existing_out.read_text(encoding="ascii") == "keep me\n"

        assert_rooted_open_fails_without_plaintext(
            authority_path=authority_path,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=tmp / "missing-parent" / "opened.txt",
        )

        assert_rooted_open_fails_without_plaintext(
            authority_path=authority_path,
            key_path=key_path,
            artifact_path=artifact_path,
            contract_path=contract_path,
            out_path=plain_path / "opened.txt",
        )

        assert group_public_key != group_commitment

    if not args.quiet:
        print("wuci rooted asm gate contract tests passed")


if __name__ == "__main__":
    main()
