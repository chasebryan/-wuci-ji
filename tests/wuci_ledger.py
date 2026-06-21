#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*RUNNER, str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], expected: str, context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )
    assert proc.stdout == f"{expected}\n".encode("ascii"), context
    assert proc.stderr == b"", context


def assert_fails(
    proc: subprocess.CompletedProcess[bytes],
    context: str,
    stderr_contains: bytes | None = None,
) -> None:
    assert proc.returncode != 0, context
    assert proc.stdout == b"", context
    if stderr_contains is not None:
        assert stderr_contains in proc.stderr, context


def leaf_hash(entry: bytes) -> str:
    return hashlib.sha256(b"\x00" + entry).hexdigest()


def node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check assembly WUCI-LEDGER Merkle hashing primitives."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        entry = (
            b"schema: wuci-ledger-entry-v1\n"
            b"sequence: 0\n"
            b"artifact-sha256: " + (b"01" * 32) + b"\n"
            b"manifest-sha256: " + (b"02" * 32) + b"\n"
            b"warrant-message-sha256: " + (b"03" * 32) + b"\n"
            b"release-receipt-sha256: " + (b"04" * 32) + b"\n"
            b"receipt-contract-sha256: " + (b"05" * 32) + b"\n"
            b"authority-root-sha256: " + (b"06" * 32) + b"\n"
            b"release-decision-sha256: " + (b"07" * 32) + b"\n"
            b"attestation-sha256: " + (b"08" * 32) + b"\n"
            b"release-authority-group-public-key: "
            + b"022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
            + b"\n"
        )
        entry_path = tmp / "entry.txt"
        entry_path.write_bytes(entry)

        large_entry = (b"schema: wuci-ledger-entry-v1\nsequence: 1\n" + b"a" * 12000)
        large_entry_path = tmp / "large-entry.txt"
        large_entry_path.write_bytes(large_entry)

        empty_expected = hashlib.sha256(b"").hexdigest()
        assert_ok(run_wuci(["ledger-empty-root"]), empty_expected, "empty root")

        first_leaf = leaf_hash(entry)
        second_leaf = leaf_hash(large_entry)
        assert_ok(
            run_wuci(["ledger-leaf-file", str(entry_path)]),
            first_leaf,
            "small ledger leaf",
        )
        assert_ok(
            run_wuci(["ledger-leaf-file", str(large_entry_path)]),
            second_leaf,
            "streamed ledger leaf",
        )

        expected_node = node_hash(first_leaf, second_leaf)
        assert_ok(
            run_wuci(["ledger-node", first_leaf, second_leaf]),
            expected_node,
            "ledger node",
        )

        assert_fails(
            run_wuci(["ledger-node", "00", second_leaf]),
            "short ledger node hash rejected",
            b"invalid ledger hash argument",
        )
        assert_fails(
            run_wuci(["ledger-leaf-file", str(tmp / "missing-entry.txt")]),
            "missing ledger entry file rejected",
        )
        assert_fails(run_wuci(["ledger-empty-root", "extra"]), "bad arity rejected")

    help_proc = run_wuci(["--help"])
    assert help_proc.returncode == 0
    help_text = help_proc.stdout.decode("ascii")
    for snippet in (
        "ledger-empty-root              print SHA-256 Merkle root for an empty WUCI-LEDGER",
        "ledger-leaf-file <entry>       print SHA-256(00 || entry bytes) for a ledger entry",
        "ledger-node <left> <right>     print SHA-256(01 || left || right); inputs are 64 hex",
    ):
        assert snippet in help_text

    if not args.quiet:
        print("wuci ledger: PASS")


if __name__ == "__main__":
    main()
