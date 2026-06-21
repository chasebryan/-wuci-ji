#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
CONTRACT_TOOL = REPO_ROOT / "tools" / "wuci_receipt_contract.py"
AUTHORITY_TOOL = REPO_ROOT / "tools" / "wuci_authority_root.py"
PUBLISH_TOOL = REPO_ROOT / "tools" / "wuci_publish_attest.py"
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


def run_authority(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(AUTHORITY_TOOL), "emit", *args])


def run_publish(command: str, bundle_dir: Path) -> subprocess.CompletedProcess[bytes]:
    return run_cmd(
        [
            sys.executable,
            str(PUBLISH_TOOL),
            "--bin",
            str(BIN),
            "--bundle-dir",
            str(bundle_dir),
            "--attestation",
            str(bundle_dir / "attestation.json"),
            command,
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


def build_publish_bundle(bundle_dir: Path) -> None:
    bundle_dir.mkdir(parents=True)
    key_path = bundle_dir / "artifact.key"
    artifact_path = bundle_dir / "wuci-ji.self.wj"
    manifest_path = bundle_dir / "manifest.txt"
    warrant_path = bundle_dir / "warrant-message.txt"
    transcript_path = bundle_dir / "release-transcript.json"
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

    assert_ok(
        run_authority(
            [
                "--contract",
                str(contract_path),
                "--authority",
                str(authority_path),
                "--allow-open",
                "false",
                "--allow-release",
                "true",
                "--quiet",
            ]
        ),
        "release authority",
    )

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

    assert_ok(run_publish("attest", bundle_dir), "write publish attestation")
    assert_ok(run_publish("verify", bundle_dir), "verify publish attestation")


def assert_publish_verify_fails(bundle_dir: Path) -> None:
    proc = run_publish("verify", bundle_dir)
    assert proc.returncode != 0
    assert proc.stdout == b""
    assert b"wuci publish:" in proc.stderr


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check rooted WUCI publish bundle attestations."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        base = tmp / "base"
        build_publish_bundle(base)

        decision_tamper = tmp / "decision-tamper"
        shutil.copytree(base, decision_tamper)
        decision_path = decision_tamper / "release-decision.txt"
        decision_path.write_text(
            replace_value(
                decision_path.read_text(encoding="ascii"),
                "artifact-sha256",
                "00" * 32,
            ),
            encoding="ascii",
        )
        assert_publish_verify_fails(decision_tamper)

        contract_tamper = tmp / "contract-tamper"
        shutil.copytree(base, contract_tamper)
        contract_path = contract_tamper / "receipt-contract.txt"
        contract_path.write_text(
            replace_value(
                contract_path.read_text(encoding="ascii"),
                "action",
                "open",
            ),
            encoding="ascii",
        )
        assert_publish_verify_fails(contract_tamper)

        authority_tamper = tmp / "authority-tamper"
        shutil.copytree(base, authority_tamper)
        authority_path = authority_tamper / "authority-root.txt"
        authority_path.write_text(
            replace_value(
                authority_path.read_text(encoding="ascii"),
                "allow-release",
                "false",
            ),
            encoding="ascii",
        )
        assert_publish_verify_fails(authority_tamper)

    if not args.quiet:
        print("wuci publish attestation: PASS")


if __name__ == "__main__":
    main()
