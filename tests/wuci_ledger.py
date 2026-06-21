#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
LEDGER_TOOL = REPO_ROOT / "tools" / "wuci_ledger.py"


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*RUNNER, str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_ledger(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    env["WUCI_JI_RUNNER"] = " ".join(RUNNER)
    return subprocess.run(
        [sys.executable, str(LEDGER_TOOL), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        cwd=REPO_ROOT,
        env=env,
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


def assert_cmd_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_cmd_fails(
    proc: subprocess.CompletedProcess[bytes],
    context: str,
    stderr_contains: bytes | None = b"wuci ledger:",
) -> None:
    assert proc.returncode != 0, context
    if stderr_contains is not None:
        assert stderr_contains in proc.stderr, (
            context,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )


def leaf_hash(entry: bytes) -> str:
    return hashlib.sha256(b"\x00" + entry).hexdigest()


def node_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(
        b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
    ).hexdigest()


def replace_value(text: str, label: str, value: str) -> str:
    prefix = f"{label}: "
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = f"{prefix}{value}\n"
            return "".join(lines)
    raise AssertionError(f"missing label {label}")


def mutate_text(path: Path, label: str, value: str) -> None:
    path.write_text(
        replace_value(path.read_text(encoding="ascii"), label, value),
        encoding="ascii",
    )


def copy_case(base: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(base, case_dir)
    return case_dir


def load_witness_helpers():
    helper_path = REPO_ROOT / "tests" / "wuci_witness.py"
    spec = importlib.util.spec_from_file_location("wuci_witness_test_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_primitives() -> None:
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


def check_full_ledger() -> None:
    helpers = load_witness_helpers()
    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        bundle = tmp / "witness-bundle"
        helpers.build_public_witness_bundle(bundle, tmp / "work")

        ledger = tmp / "ledger"
        assert_cmd_ok(
            run_ledger(["init", "--bin", str(BIN), "--ledger", str(ledger)]),
            "initialize ledger",
        )
        assert (ledger / "ledger-head.txt").is_file()
        assert (ledger / "heads" / "00000000000000000000.txt").is_file()

        assert_cmd_ok(
            run_ledger(
                [
                    "append",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--witness-bundle",
                    str(bundle),
                ]
            ),
            "append first witness bundle",
        )
        head1 = tmp / "head1.txt"
        shutil.copyfile(ledger / "ledger-head.txt", head1)
        entry0 = ledger / "entries" / "00000000000000000000.txt"

        inclusion0 = tmp / "inclusion0.txt"
        assert_cmd_ok(
            run_ledger(
                [
                    "prove-inclusion",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--sequence",
                    "0",
                    "--out",
                    str(inclusion0),
                ]
            ),
            "prove first inclusion",
        )
        assert_cmd_ok(
            run_ledger(
                [
                    "verify-inclusion",
                    "--bin",
                    str(BIN),
                    "--entry",
                    str(entry0),
                    "--proof",
                    str(inclusion0),
                    "--head",
                    str(head1),
                ]
            ),
            "verify first inclusion",
        )

        consistency01 = tmp / "consistency01.txt"
        assert_cmd_ok(
            run_ledger(
                [
                    "prove-consistency",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--from-head",
                    str(ledger / "previous-ledger-head.txt"),
                    "--to-head",
                    str(head1),
                    "--out",
                    str(consistency01),
                ]
            ),
            "prove empty-to-first consistency",
        )
        assert_cmd_ok(
            run_ledger(
                [
                    "verify-consistency",
                    "--bin",
                    str(BIN),
                    "--proof",
                    str(consistency01),
                ]
            ),
            "verify empty-to-first consistency",
        )

        assert_cmd_ok(
            run_ledger(
                [
                    "append",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--witness-bundle",
                    str(bundle),
                ]
            ),
            "append second witness bundle",
        )
        head2 = tmp / "head2.txt"
        shutil.copyfile(ledger / "ledger-head.txt", head2)
        entry1 = ledger / "entries" / "00000000000000000001.txt"

        inclusion0_size2 = tmp / "inclusion0-size2.txt"
        assert_cmd_ok(
            run_ledger(
                [
                    "prove-inclusion",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--sequence",
                    "0",
                    "--out",
                    str(inclusion0_size2),
                ]
            ),
            "prove inclusion in two-leaf tree",
        )
        assert_cmd_ok(
            run_ledger(
                [
                    "verify-inclusion",
                    "--bin",
                    str(BIN),
                    "--entry",
                    str(entry0),
                    "--proof",
                    str(inclusion0_size2),
                    "--head",
                    str(head2),
                ]
            ),
            "verify inclusion in two-leaf tree",
        )

        inclusion1 = tmp / "inclusion1.txt"
        assert_cmd_ok(
            run_ledger(
                [
                    "prove-inclusion",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--sequence",
                    "1",
                    "--out",
                    str(inclusion1),
                ]
            ),
            "prove second inclusion",
        )
        assert_cmd_ok(
            run_ledger(
                [
                    "verify-inclusion",
                    "--bin",
                    str(BIN),
                    "--entry",
                    str(entry1),
                    "--proof",
                    str(inclusion1),
                    "--head",
                    str(head2),
                ]
            ),
            "verify second inclusion",
        )

        consistency12 = tmp / "consistency12.txt"
        assert_cmd_ok(
            run_ledger(
                [
                    "prove-consistency",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--from-head",
                    str(head1),
                    "--to-head",
                    str(head2),
                    "--out",
                    str(consistency12),
                ]
            ),
            "prove append-only consistency",
        )
        assert_cmd_ok(
            run_ledger(
                [
                    "verify-consistency",
                    "--bin",
                    str(BIN),
                    "--proof",
                    str(consistency12),
                ]
            ),
            "verify append-only consistency",
        )

        tampered_entry = tmp / "tampered-entry.txt"
        shutil.copyfile(entry0, tampered_entry)
        mutate_text(tampered_entry, "artifact-sha256", "00" * 32)
        assert_cmd_fails(
            run_ledger(
                [
                    "verify-inclusion",
                    "--bin",
                    str(BIN),
                    "--entry",
                    str(tampered_entry),
                    "--proof",
                    str(inclusion0_size2),
                    "--head",
                    str(head2),
                ]
            ),
            "tampered ledger entry rejected",
        )

        wrong_root_proof = tmp / "wrong-root-inclusion.txt"
        shutil.copyfile(inclusion0_size2, wrong_root_proof)
        mutate_text(wrong_root_proof, "root-hash", "00" * 32)
        assert_cmd_fails(
            run_ledger(
                [
                    "verify-inclusion",
                    "--bin",
                    str(BIN),
                    "--entry",
                    str(entry0),
                    "--proof",
                    str(wrong_root_proof),
                    "--head",
                    str(head2),
                ]
            ),
            "inclusion proof for wrong root rejected",
        )

        bad_path_proof = tmp / "bad-path-inclusion.txt"
        proof_lines = inclusion0_size2.read_text(encoding="ascii").splitlines(
            keepends=True
        )
        proof_lines[-1] = ("00" * 32) + "\n"
        bad_path_proof.write_text("".join(proof_lines), encoding="ascii")
        assert_cmd_fails(
            run_ledger(
                [
                    "verify-inclusion",
                    "--bin",
                    str(BIN),
                    "--entry",
                    str(entry0),
                    "--proof",
                    str(bad_path_proof),
                    "--head",
                    str(head2),
                ]
            ),
            "assembly node mismatch rejected",
        )

        forked_consistency = tmp / "forked-consistency.txt"
        shutil.copyfile(consistency12, forked_consistency)
        mutate_text(forked_consistency, "second-root-hash", "00" * 32)
        assert_cmd_fails(
            run_ledger(
                [
                    "verify-consistency",
                    "--bin",
                    str(BIN),
                    "--proof",
                    str(forked_consistency),
                ]
            ),
            "forked consistency head rejected",
        )

        wrong_sequence_ledger = copy_case(ledger, tmp, "wrong-sequence-ledger")
        mutate_text(
            wrong_sequence_ledger / "entries" / "00000000000000000000.txt",
            "sequence",
            "9",
        )
        assert_cmd_fails(
            run_ledger(
                [
                    "prove-inclusion",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(wrong_sequence_ledger),
                    "--sequence",
                    "0",
                    "--out",
                    str(tmp / "wrong-sequence-proof.txt"),
                ]
            ),
            "wrong sequence rejected",
        )

        reordered_ledger = copy_case(ledger, tmp, "reordered-ledger")
        first_bytes = (
            reordered_ledger / "entries" / "00000000000000000000.txt"
        ).read_bytes()
        second_bytes = (
            reordered_ledger / "entries" / "00000000000000000001.txt"
        ).read_bytes()
        (reordered_ledger / "entries" / "00000000000000000000.txt").write_bytes(
            second_bytes
        )
        (reordered_ledger / "entries" / "00000000000000000001.txt").write_bytes(
            first_bytes
        )
        assert_cmd_fails(
            run_ledger(
                [
                    "prove-consistency",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(reordered_ledger),
                    "--from-head",
                    str(head1),
                    "--to-head",
                    str(head2),
                    "--out",
                    str(tmp / "reordered-consistency.txt"),
                ]
            ),
            "reordered entries rejected",
        )

        non_prefix_ledger = copy_case(ledger, tmp, "non-prefix-ledger")
        fork_entry0 = (
            non_prefix_ledger / "entries" / "00000000000000000000.txt"
        ).read_text(encoding="ascii")
        fork_entry0 = replace_value(fork_entry0, "artifact-sha256", "ab" * 32)
        (
            non_prefix_ledger / "entries" / "00000000000000000000.txt"
        ).write_text(fork_entry0, encoding="ascii")
        assert_cmd_fails(
            run_ledger(
                [
                    "prove-consistency",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(non_prefix_ledger),
                    "--from-head",
                    str(head1),
                    "--to-head",
                    str(head2),
                    "--out",
                    str(tmp / "non-prefix-consistency.txt"),
                ]
            ),
            "non-prefix history rejected",
        )

        bad_index_bundle = copy_case(bundle, tmp, "bad-index-bundle")
        mutate_text(bad_index_bundle / "publish-index.txt", "manifest-sha256", "00" * 32)
        assert_cmd_fails(
            run_ledger(
                [
                    "append",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--witness-bundle",
                    str(bad_index_bundle),
                ]
            ),
            "tampered publish index rejected",
        )

        bad_attestation_bundle = copy_case(bundle, tmp, "bad-attestation-bundle")
        attestation_path = bad_attestation_bundle / "attestation.json"
        attestation_path.write_text(
            attestation_path.read_text(encoding="utf-8").replace(
                '"witness_bundle_complete": true',
                '"witness_bundle_complete": false',
                1,
            ),
            encoding="utf-8",
        )
        assert_cmd_fails(
            run_ledger(
                [
                    "append",
                    "--bin",
                    str(BIN),
                    "--ledger",
                    str(ledger),
                    "--witness-bundle",
                    str(bad_attestation_bundle),
                ]
            ),
            "tampered attestation rejected",
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check WUCI-LEDGER assembly primitives and transparency log."
    )
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    parser.add_argument(
        "--primitives-only",
        action="store_true",
        help="run only assembly Merkle primitive checks",
    )
    parser.add_argument(
        "--ledger-only",
        action="store_true",
        help="run only full ledger append/proof checks",
    )
    args = parser.parse_args()

    if args.primitives_only and args.ledger_only:
        raise SystemExit("--primitives-only and --ledger-only are mutually exclusive")

    if not args.ledger_only:
        check_primitives()
    if not args.primitives_only:
        check_full_ledger()

    if not args.quiet:
        print("wuci ledger: PASS")


if __name__ == "__main__":
    main()
