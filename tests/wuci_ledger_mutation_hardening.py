#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER_TOOL = REPO_ROOT / "tools" / "wuci_ledger.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))


def run_ledger(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    return subprocess.run(
        [sys.executable, str(LEDGER_TOOL), *args, "--bin", str(BIN)],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_ledger_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context
    assert b"wuci ledger:" in proc.stderr, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def load_witness_helpers():
    helper_path = REPO_ROOT / "tests" / "wuci_witness.py"
    spec = importlib.util.spec_from_file_location("wuci_witness_test_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_ledger(tmp: Path) -> tuple[Path, Path]:
    helpers = load_witness_helpers()
    bundle = tmp / "bundle"
    ledger = tmp / "ledger"
    helpers.build_public_witness_bundle(bundle, tmp / "work")
    assert_ok(run_ledger(["init", "--ledger", str(ledger)]), "init ledger")
    assert_ok(
        run_ledger(["append", "--ledger", str(ledger), "--witness-bundle", str(bundle)]),
        "append ledger",
    )
    assert_ok(run_ledger(["verify-history", "--ledger", str(ledger)]), "verify history")
    return ledger, bundle


def copy_case(base: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(base, case_dir)
    return case_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-LEDGER mutation hardening.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        ledger, bundle = build_ledger(tmp)

        deleted = copy_case(ledger, tmp, "deleted-entry")
        (deleted / "entries" / "00000000000000000000.txt").unlink()
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(deleted)]),
            "deleted entry rejected",
        )

        modified = copy_case(ledger, tmp, "modified-entry")
        with (modified / "entries" / "00000000000000000000.txt").open("a", encoding="ascii") as handle:
            handle.write("# tamper\n")
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(modified)]),
            "modified entry rejected",
        )

        missing_head = copy_case(ledger, tmp, "missing-head")
        (missing_head / "heads" / "00000000000000000000.txt").unlink()
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(missing_head)]),
            "missing head rejected",
        )

        forked_head = copy_case(ledger, tmp, "forked-head")
        head_path = forked_head / "heads" / "00000000000000000001.txt"
        text = head_path.read_text(encoding="ascii")
        head_path.write_text(text.replace("root-hash: ", "root-hash: 00", 1), encoding="ascii")
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(forked_head)]),
            "forked head rejected",
        )

        unexpected_entry = copy_case(ledger, tmp, "unexpected-entry")
        (unexpected_entry / "entries" / "extra.txt").write_text("extra\n", encoding="ascii")
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(unexpected_entry)]),
            "unexpected entry file rejected",
        )

        unexpected_head = copy_case(ledger, tmp, "unexpected-head")
        (unexpected_head / "heads" / "extra.txt").write_text("extra\n", encoding="ascii")
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(unexpected_head)]),
            "unexpected head file rejected",
        )

        hardlinked_entry = copy_case(ledger, tmp, "hardlinked-entry")
        entry_path = hardlinked_entry / "entries" / "00000000000000000000.txt"
        original = entry_path.read_text(encoding="ascii")
        entry_path.unlink()
        outside = tmp / "outside-entry.txt"
        outside.write_text(original, encoding="ascii")
        os.link(outside, entry_path)
        assert_ledger_fails(
            run_ledger(["verify-history", "--ledger", str(hardlinked_entry)]),
            "hardlinked ledger entry rejected",
        )

        locked = copy_case(ledger, tmp, "locked-ledger")
        (locked / ".wuci-ledger.lock").write_text("locked\n", encoding="ascii")
        assert_ledger_fails(
            run_ledger(["append", "--ledger", str(locked), "--witness-bundle", str(bundle)]),
            "stale lock blocks append",
        )

    if not args.quiet:
        print("wuci ledger mutation hardening: PASS")


if __name__ == "__main__":
    main()
