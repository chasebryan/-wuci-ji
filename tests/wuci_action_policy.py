#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))


def run_cmd(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    return subprocess.run(
        args,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


def run_authorize(artifact: Path, action: str) -> subprocess.CompletedProcess[bytes]:
    return run_cmd(
        [
            sys.executable,
            str(AUTHORIZE),
            "--bin",
            str(BIN),
            "--artifact",
            str(artifact),
            "--action",
            action,
            "--print-auth-message",
        ]
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context


def load_witness_helpers():
    helper_path = REPO_ROOT / "tests" / "wuci_witness.py"
    spec = importlib.util.spec_from_file_location("wuci_witness_test_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI reserved action policy.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    helpers = load_witness_helpers()
    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        bundle = tmp / "bundle"
        helpers.build_public_witness_bundle(bundle, tmp / "work")
        artifact = bundle / "wuci-ji.self.wj"

        assert_ok(run_authorize(artifact, "open"), "open action remains allowed")
        assert_ok(run_authorize(artifact, "release"), "release action remains allowed")
        assert_fails(run_authorize(artifact, "trust"), "trust action reserved")
        assert_fails(run_authorize(artifact, "publish"), "publish action reserved")

        decision = (bundle / "release-decision.txt").read_text(encoding="ascii")
        assert "action: release\n" in decision
        assert "action: publish\n" not in decision
        assert "action: trust\n" not in decision

        attestation = (bundle / "attestation.json").read_text(encoding="utf-8")
        assert "release witness bundle" in attestation
        assert "publish authority" not in attestation

    if not args.quiet:
        print("wuci action policy: PASS")


if __name__ == "__main__":
    main()
