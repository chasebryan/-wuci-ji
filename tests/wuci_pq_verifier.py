#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_pq_verifier.py"
PINS = REPO_ROOT / "docs" / "wuci_pq_verifier_pins.json"


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check local PQ verifier detection.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="wuci-pq-") as tmp_name:
        evidence = Path(tmp_name) / "pq-verifier.json"
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "detect",
                    "--out",
                    str(evidence),
                    "--quiet",
                ]
            ),
            "detect PQ verifier",
        )
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    "--evidence",
                    str(evidence),
                    "--quiet",
                ]
            ),
            "verify PQ verifier evidence",
        )
        value = json.loads(evidence.read_text(encoding="utf-8"))
        assert value["schema"] == "wuci-pq-verifier-detection-v1"
        assert value["quantum_safe_claim_allowed"] is False
        if not value["real_pq_signature_verifier_available"]:
            required = run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "verify",
                    "--evidence",
                    str(evidence),
                    "--require-real",
                    "--quiet",
                ]
            )
            assert required.returncode != 0
            assert b"no real pinned PQ signature verifier" in required.stderr

        fake_binary = Path(tmp_name) / "fake-pq-verifier"
        fake_binary.write_bytes(b"not a pq verifier\n")
        kat_public_key = Path(tmp_name) / "kat-pub.bin"
        kat_message = Path(tmp_name) / "kat-msg.bin"
        kat_signature = Path(tmp_name) / "kat-sig.bin"
        kat_public_key.write_bytes(b"not a real pq public key\n")
        kat_message.write_bytes(b"wuci pq kat message\n")
        kat_signature.write_bytes(b"not a real pq signature\n")
        fake_evidence = Path(tmp_name) / "fake-real-pq-evidence.json"
        fake_evidence.write_text(
            json.dumps(
                {
                    "schema": "wuci-real-pq-verifier-evidence-v2",
                    "algorithm": "ML-DSA",
                    "implementation_name": "fake-test-verifier",
                    "implementation_version": "0",
                    "verifier_protocol": "wuci-pq-external-verify-v1",
                    "standard_reference": "NIST FIPS 204",
                    "known_answer_test": True,
                    "no_stub_mode": True,
                    "offline_verification": True,
                    "network_required": False,
                    "binary_path": str(fake_binary),
                    "binary_sha256": sha256_bytes(fake_binary.read_bytes()),
                    "kat": {
                        "public_key_path": str(kat_public_key),
                        "public_key_sha256": sha256_bytes(kat_public_key.read_bytes()),
                        "message_path": str(kat_message),
                        "message_sha256": sha256_bytes(kat_message.read_bytes()),
                        "signature_path": str(kat_signature),
                        "signature_sha256": sha256_bytes(kat_signature.read_bytes()),
                        "verified": True,
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        pins = json.loads(PINS.read_text(encoding="utf-8"))
        assert pins["schema"] == "wuci-pq-verifier-pins-v1"
        assert pins["allowed_verifiers"] == []
        real = run_cmd(
            [
                sys.executable,
                str(TOOL),
                "verify-real",
                "--evidence",
                str(fake_evidence),
                "--pins",
                str(PINS),
                "--quiet",
            ]
        )
        assert real.returncode != 0
        assert b"not pinned as reviewed" in real.stderr

        failing_verifier = Path(tmp_name) / "failing-pq-verifier"
        failing_verifier.write_text("#!/bin/sh\nexit 7\n", encoding="ascii")
        failing_verifier.chmod(0o755)
        attest = run_cmd(
            [
                sys.executable,
                str(TOOL),
                "attest-real",
                "--verifier",
                str(failing_verifier),
                "--algorithm",
                "ML-DSA",
                "--public-key",
                str(kat_public_key),
                "--message",
                str(kat_message),
                "--signature",
                str(kat_signature),
                "--implementation-name",
                "failing-test-verifier",
                "--implementation-version",
                "0",
                "--out",
                str(Path(tmp_name) / "should-not-write.json"),
                "--quiet",
            ]
        )
        assert attest.returncode != 0
        assert b"external PQ verifier KAT failed" in attest.stderr

    if not args.quiet:
        print("wuci pq verifier: PASS")


if __name__ == "__main__":
    main()
