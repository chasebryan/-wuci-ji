#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
CONTRACT_TOOL = REPO_ROOT / "tools" / "wuci_receipt_contract.py"
WITNESS_TOOL = REPO_ROOT / "tools" / "wuci_witness.py"
RELEASE_AUTHORITY = REPO_ROOT / "authority" / "wuci-release-root.fixture.txt"
OPEN_AUTHORITY = REPO_ROOT / "authority" / "wuci-root.fixture.txt"
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


def run_contract(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(CONTRACT_TOOL), "emit", "--bin", str(BIN), *args])


def run_witness(command: str, bundle_dir: Path) -> subprocess.CompletedProcess[bytes]:
    return run_cmd(
        [
            sys.executable,
            str(WITNESS_TOOL),
            command,
            "--bin",
            str(BIN),
            "--bundle",
            str(bundle_dir),
        ]
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def mutate_text(path: Path, mutator: Callable[[str], str]) -> None:
    path.write_text(mutator(path.read_text(encoding="ascii")), encoding="ascii")


def build_public_witness_bundle(bundle_dir: Path, work_dir: Path) -> None:
    bundle_dir.mkdir(parents=True)
    work_dir.mkdir(parents=True)

    key_path = work_dir / "artifact.key"
    transcript_path = work_dir / "release-transcript.json"
    artifact_path = bundle_dir / "wuci-ji.self.wj"
    manifest_path = bundle_dir / "manifest.txt"
    warrant_path = bundle_dir / "warrant-message.txt"
    receipt_path = bundle_dir / "release-receipt.json"
    contract_path = bundle_dir / "receipt-contract.txt"
    authority_path = bundle_dir / "authority-root.txt"
    decision_path = bundle_dir / "release-decision.txt"

    key_path.write_text(("11" * 32) + "\n", encoding="ascii")
    assert_ok(
        run_wuci(
            [
                "seal-file-keyfile-v2",
                str(key_path),
                "2233445566778899aabbccddeeff0011",
                str(BIN),
                str(artifact_path),
            ]
        ),
        "seal binary",
    )

    manifest = run_wuci(["manifest-file", str(artifact_path)])
    assert_ok(manifest, "manifest artifact")
    manifest_path.write_bytes(manifest.stdout)

    warrant = run_wuci(["warrant-message-file", "release", str(artifact_path)])
    assert_ok(warrant, "release warrant message")
    warrant_path.write_bytes(warrant.stdout)

    transcript = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "release",
            "--print-transcript-manifest",
        ]
    )
    assert_ok(transcript, "release transcript")
    transcript_path.write_bytes(transcript.stdout)

    receipt = run_authorize(
        [
            "--artifact",
            str(artifact_path),
            "--action",
            "release",
            "--transcript-manifest",
            str(transcript_path),
            "--update-transcript-manifest",
            "--receipt",
            str(receipt_path),
        ]
    )
    assert_ok(receipt, "release receipt")

    assert_ok(
        run_contract(
            [
                "--artifact",
                str(artifact_path),
                "--action",
                "release",
                "--receipt",
                str(receipt_path),
                "--contract",
                str(contract_path),
                "--quiet",
            ]
        ),
        "release contract",
    )

    shutil.copyfile(RELEASE_AUTHORITY, authority_path)

    decision = run_wuci(
        [
            "release-authorized-rooted",
            str(authority_path),
            str(artifact_path),
            str(contract_path),
        ]
    )
    assert_ok(decision, "rooted release decision")
    decision_path.write_bytes(decision.stdout)

    key_path.unlink()
    transcript_path.unlink()

    assert_ok(run_witness("index", bundle_dir), "write witness publish index")
    assert_ok(run_witness("attest", bundle_dir), "write witness attestation")
    assert_ok(run_witness("verify", bundle_dir), "verify witness bundle")


def assert_witness_verify_fails(bundle_dir: Path) -> None:
    proc = run_witness("verify", bundle_dir)
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"wuci witness:" in proc.stderr


def copy_case(base: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(base, case_dir)
    return case_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check public WUCI-WITNESS publish bundle verification."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        base = tmp / "base"
        build_public_witness_bundle(base, tmp / "work")

        assert not (base / "artifact.key").exists()
        assert not (base / "opened-wuci-ji").exists()
        assert not (base / "auth-transcript.json").exists()
        assert not (base / "release-transcript.json").exists()

        portable_copy = copy_case(base, tmp, "portable-copy")
        assert_ok(run_witness("verify", portable_copy), "verify copied witness bundle")

        private_key = copy_case(base, tmp, "private-key-present")
        (private_key / "artifact.key").write_text(("11" * 32) + "\n", encoding="ascii")
        assert_witness_verify_fails(private_key)

        opened_binary = copy_case(base, tmp, "opened-binary-present")
        (opened_binary / "opened-wuci-ji").write_bytes(b"not public witness evidence\n")
        assert_witness_verify_fails(opened_binary)

        missing_index = copy_case(base, tmp, "missing-index")
        (missing_index / "publish-index.txt").unlink()
        assert_witness_verify_fails(missing_index)

        malformed_index = copy_case(base, tmp, "malformed-index")
        with (malformed_index / "publish-index.txt").open("a", encoding="ascii") as handle:
            handle.write("\n")
        assert_witness_verify_fails(malformed_index)

        index_hash_mismatch = copy_case(base, tmp, "index-hash-mismatch")
        mutate_text(
            index_hash_mismatch / "publish-index.txt",
            lambda text: replace_value(text, "manifest-sha256", "00" * 32),
        )
        assert_witness_verify_fails(index_hash_mismatch)

        manifest_tamper = copy_case(base, tmp, "manifest-tamper")
        with (manifest_tamper / "manifest.txt").open("ab") as handle:
            handle.write(b"# tamper\n")
        assert_witness_verify_fails(manifest_tamper)

        warrant_tamper = copy_case(base, tmp, "warrant-tamper")
        with (warrant_tamper / "warrant-message.txt").open("ab") as handle:
            handle.write(b"# tamper\n")
        assert_witness_verify_fails(warrant_tamper)

        decision_tamper = copy_case(base, tmp, "decision-tamper")
        mutate_text(
            decision_tamper / "release-decision.txt",
            lambda text: replace_value(text, "artifact-sha256", "00" * 32),
        )
        assert_witness_verify_fails(decision_tamper)

        authority_mismatch = copy_case(base, tmp, "authority-mismatch")
        shutil.copyfile(OPEN_AUTHORITY, authority_mismatch / "authority-root.txt")
        assert_witness_verify_fails(authority_mismatch)

        authority_release_disabled = copy_case(base, tmp, "authority-release-disabled")
        mutate_text(
            authority_release_disabled / "authority-root.txt",
            lambda text: replace_value(text, "allow-release", "false"),
        )
        assert_witness_verify_fails(authority_release_disabled)

        contract_group_mismatch = copy_case(base, tmp, "contract-group-mismatch")
        mutate_text(
            contract_group_mismatch / "receipt-contract.txt",
            lambda text: replace_value(
                text,
                "group-public-key",
                "02" + ("00" * 32),
            ),
        )
        assert_witness_verify_fails(contract_group_mismatch)

        receipt_action_tamper = copy_case(base, tmp, "receipt-action-tamper")
        receipt_path = receipt_action_tamper / "release-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["action"] = "open"
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        assert_witness_verify_fails(receipt_action_tamper)

        contract_action_tamper = copy_case(base, tmp, "contract-action-tamper")
        mutate_text(
            contract_action_tamper / "receipt-contract.txt",
            lambda text: replace_value(text, "action", "open"),
        )
        assert_witness_verify_fails(contract_action_tamper)

    if not args.quiet:
        print("wuci witness: PASS")


if __name__ == "__main__":
    main()
