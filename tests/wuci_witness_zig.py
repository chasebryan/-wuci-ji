#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WITNESS = REPO_ROOT / "build" / "wuci-witness"
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"


def run_witness(witness_bin: Path, wuci_bin: Path, bundle: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            str(witness_bin),
            "verify",
            str(bundle),
            "--bin",
            str(wuci_bin),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
        env=os.environ.copy(),
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_verify_fails(witness_bin: Path, wuci_bin: Path, bundle: Path) -> None:
    proc = run_witness(witness_bin, wuci_bin, bundle)
    assert proc.returncode != 0
    assert proc.stdout == b""


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


def copy_case(base: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(base, case_dir)
    return case_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check the Zig WUCI-WITNESS verifier rejects public bundle tampering."
    )
    parser.add_argument("--bundle", required=True, help="existing public witness bundle")
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="wuci-ji binary used by the witness verifier",
    )
    parser.add_argument(
        "--witness-bin",
        default=os.environ.get("WUCI_WITNESS_BIN", str(DEFAULT_WITNESS)),
        help="Zig witness verifier binary",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    base = Path(args.bundle)
    wuci_bin = Path(args.bin)
    witness_bin = Path(args.witness_bin)

    assert_ok(run_witness(witness_bin, wuci_bin, base), "valid witness bundle")

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)

        private_key = copy_case(base, tmp, "private-key-present")
        (private_key / "artifact.key").write_text(("11" * 32) + "\n", encoding="ascii")
        assert_verify_fails(witness_bin, wuci_bin, private_key)

        index_hash_mismatch = copy_case(base, tmp, "index-hash-mismatch")
        mutate_text(
            index_hash_mismatch / "publish-index.txt",
            lambda text: replace_value(text, "manifest-sha256", "00" * 32),
        )
        assert_verify_fails(witness_bin, wuci_bin, index_hash_mismatch)

        decision_tamper = copy_case(base, tmp, "decision-tamper")
        mutate_text(
            decision_tamper / "release-decision.txt",
            lambda text: replace_value(text, "artifact-sha256", "00" * 32),
        )
        assert_verify_fails(witness_bin, wuci_bin, decision_tamper)

        attestation_tamper = copy_case(base, tmp, "attestation-tamper")
        mutate_text(
            attestation_tamper / "attestation.json",
            lambda text: text.replace('"witness_bundle_complete": true', '"witness_bundle_complete": false'),
        )
        assert_verify_fails(witness_bin, wuci_bin, attestation_tamper)

    if not args.quiet:
        print("wuci witness zig: PASS")


if __name__ == "__main__":
    main()
