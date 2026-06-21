#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTHORIZE = REPO_ROOT / "tools" / "wuci_frost_authorize.py"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))


def run_authorize(args: list[str], *, strict: bool = False) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["WUCI_JI_BIN"] = str(BIN)
    if strict:
        env["WUCI_STRICT"] = "1"
    return subprocess.run(
        [sys.executable, str(AUTHORIZE), "--bin", str(BIN), *args],
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


def assert_warrant_fails(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode != 0, context
    assert b"wuci warrant:" in proc.stderr


def load_witness_helpers():
    helper_path = REPO_ROOT / "tests" / "wuci_witness.py"
    spec = importlib.util.spec_from_file_location("wuci_witness_test_helpers", helper_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verifier_sha256() -> str:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import wuci_verifier_identity

    return wuci_verifier_identity.sha256_file(BIN)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check fixture authority quarantine.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    helpers = load_witness_helpers()
    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        bundle = tmp / "bundle"
        helpers.build_public_witness_bundle(bundle, tmp / "work")
        attestation = json.loads((bundle / "attestation.json").read_text(encoding="utf-8"))
        assert attestation["production"] is False
        assert attestation["fixture_authority"] is True
        assert attestation["trust_level"] == "test-only"
        assert attestation["quantum_safe"] is False
        assert attestation["runtime_sandbox_enforced"] is False

        artifact = bundle / "wuci-ji.self.wj"
        assert_warrant_fails(
            run_authorize(
                [
                    "--artifact",
                    str(artifact),
                    "--action",
                    "trust",
                    "--print-auth-message",
                ]
            ),
            "trust reserved by default",
        )
        assert_warrant_fails(
            run_authorize(
                [
                    "--artifact",
                    str(artifact),
                    "--action",
                    "publish",
                    "--allow-reserved-action",
                    "--trusted-bin-sha256",
                    verifier_sha256(),
                    "--print-auth-message",
                ],
                strict=True,
            ),
            "publish reserved in strict mode",
        )
        assert_warrant_fails(
            run_authorize(
                [
                    "--artifact",
                    str(artifact),
                    "--action",
                    "release",
                    "--trusted-bin-sha256",
                    verifier_sha256(),
                    "--print-auth-message",
                ],
                strict=True,
            ),
            "strict fixture release needs explicit test proof",
        )
        assert_ok(
            run_authorize(
                [
                    "--artifact",
                    str(artifact),
                    "--action",
                    "release",
                    "--trusted-bin-sha256",
                    verifier_sha256(),
                    "--fixture-test-proof",
                    "--print-auth-message",
                ],
                strict=True,
            ),
            "strict fixture release explicit test proof",
        )

    if not args.quiet:
        print("wuci fixture quarantine: PASS")


if __name__ == "__main__":
    main()
