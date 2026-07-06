#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_verifier_identity.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import wuci_verifier_identity


def run_tool(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def assert_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context
    assert b"wuci verifier identity:" in proc.stderr


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI verifier identity pinning.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    digest = wuci_verifier_identity.sha256_file(BIN)
    identity = run_tool(["identity", "--bin", str(BIN)])
    assert_ok(identity, "identity")
    output = identity.stdout.decode("ascii")
    assert "schema: wuci-verifier-identity-v1\n" in output
    assert f"bin-sha256: {digest}\n" in output

    assert_ok(
        run_tool(["verify", "--bin", str(BIN), "--trusted-bin-sha256", digest]),
        "verify matching digest",
    )
    assert_fails(
        run_tool(["verify", "--bin", str(BIN), "--trusted-bin-sha256", "00" * 32]),
        "verify mismatched digest",
    )
    try:
        wuci_verifier_identity.require_trusted_verifier(BIN, None, "", strict=True)
    except wuci_verifier_identity.VerifierIdentityError:
        pass
    else:
        raise AssertionError("strict mode must reject missing trusted hash")

    assert_ok(run_tool(["check-runner", "--runner", ""]), "empty runner")
    assert_ok(run_tool(["check-runner", "--runner", "qemu-x86_64"]), "qemu runner")
    assert_ok(run_tool(["check-runner", "--runner", "qemu-x86_64 -cpu Haswell-v4"]), "qemu cpu runner")
    assert_fails(
        run_tool(["check-runner", "--runner", "malicious-runner"]),
        "unknown runner rejected",
    )
    try:
        wuci_verifier_identity.validate_runner("malicious-runner", strict=False)
    except wuci_verifier_identity.VerifierIdentityError:
        pass
    else:
        raise AssertionError("non-strict proof mode must reject unknown runners")

    if not args.quiet:
        print("wuci verifier identity: PASS")


if __name__ == "__main__":
    main()
