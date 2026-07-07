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
WITNESS_TOOL = REPO_ROOT / "tools" / "wuci_witness.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
PUBLIC_FILES = (
    "manifest.txt",
    "warrant-message.txt",
    "release-receipt.json",
    "receipt-contract.txt",
    "authority-root.txt",
    "release-decision.txt",
    "publish-index.txt",
    "attestation.json",
)


def run_witness(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    return subprocess.run(
        [sys.executable, str(WITNESS_TOOL), *args],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


def assert_witness_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context
    assert b"wuci witness:" in proc.stderr, (
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


def copy_case(base: Path, tmp: Path, name: str) -> Path:
    case_dir = tmp / name
    shutil.copytree(base, case_dir)
    return case_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-WITNESS file hardening.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    helpers = load_witness_helpers()
    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        base = tmp / "base"
        helpers.build_public_witness_bundle(base, tmp / "work")

        for filename in PUBLIC_FILES:
            case_dir = copy_case(base, tmp, f"symlink-{filename}")
            original = case_dir / filename
            equivalent = tmp / f"equivalent-{filename}"
            equivalent.write_bytes(original.read_bytes())
            original.unlink()
            original.symlink_to(equivalent)
            assert_witness_fails(
                run_witness(["verify", "--bin", str(BIN), "--bundle", str(case_dir)]),
                f"symlink {filename} rejected",
            )

        hardlink_case = copy_case(base, tmp, "hardlink-public")
        original = hardlink_case / "manifest.txt"
        equivalent = tmp / "hardlink-equivalent-manifest.txt"
        equivalent.write_bytes(original.read_bytes())
        original.unlink()
        os.link(equivalent, original)
        assert_witness_fails(
            run_witness(
                [
                    "verify",
                    "--bin",
                    str(BIN),
                    "--bundle",
                    str(hardlink_case),
                ]
            ),
            "public hardlink rejected",
        )

        unexpected = copy_case(base, tmp, "unexpected-file")
        (unexpected / "extra.txt").write_text("extra\n", encoding="ascii")
        assert_witness_fails(
            run_witness(["verify", "--bin", str(BIN), "--bundle", str(unexpected)]),
            "unexpected file rejected",
        )

        forbidden = copy_case(base, tmp, "forbidden-private")
        (forbidden / "artifact.key").write_text(("11" * 32) + "\n", encoding="ascii")
        assert_witness_fails(
            run_witness(["verify", "--bin", str(BIN), "--bundle", str(forbidden)]),
            "forbidden private file rejected",
        )

        private_marker = copy_case(base, tmp, "private-marker")
        with (private_marker / "release-receipt.json").open("a", encoding="ascii") as handle:
            handle.write('"signature_share": "forbidden"\n')
        assert_witness_fails(
            run_witness(["verify", "--bin", str(BIN), "--bundle", str(private_marker)]),
            "private marker rejected",
        )

        if hasattr(os, "symlink"):
            root_link = tmp / "bundle-root-link"
            root_link.symlink_to(base, target_is_directory=True)
            assert_witness_fails(
                run_witness(["verify", "--bin", str(BIN), "--bundle", str(root_link)]),
                "symlink bundle root rejected",
            )

    if not args.quiet:
        print("wuci witness symlink hardening: PASS")


if __name__ == "__main__":
    main()
