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
TOOL = REPO_ROOT / "tools" / "wuci_production_authority.py"
FIXTURE_ROOT = REPO_ROOT / "authority" / "wuci-root.fixture.txt"
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def run_tool(*args: str) -> subprocess.CompletedProcess[bytes]:
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


def deterministic_group_key() -> str:
    for x in range(2, 10000):
        rhs = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
        y = pow(rhs, (SECP256K1_P + 1) // 4, SECP256K1_P)
        if (y * y) % SECP256K1_P == rhs:
            prefix = "03" if y & 1 else "02"
            return prefix + f"{x:064x}"
    raise AssertionError("could not find deterministic secp256k1 point")


def authority_id(group_public_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(group_public_key)).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI production authority evidence tooling.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    fixture_check = run_tool("verify", "--authority", str(FIXTURE_ROOT), "--quiet")
    assert fixture_check.returncode != 0
    assert b"not production authority" in fixture_check.stderr

    fixture_key = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
    fixture_emit = run_tool(
        "emit-root",
        "--group-public-key",
        fixture_key,
        "--allow-open",
        "--out",
        "/tmp/wuci-prod-authority-fixture.txt",
        "--quiet",
    )
    assert fixture_emit.returncode != 0
    assert b"fixture" in fixture_emit.stderr

    with tempfile.TemporaryDirectory(prefix="wuci-prod-authority-") as tmp_name:
        tmp = Path(tmp_name)
        group_public_key = deterministic_group_key()
        authority = tmp / "prod-authority.txt"
        ceremony = tmp / "prod-authority-ceremony.json"

        assert_ok(
            run_tool(
                "emit-root",
                "--group-public-key",
                group_public_key,
                "--allow-open",
                "--allow-release",
                "--out",
                str(authority),
                "--quiet",
            ),
            "emit production authority root",
        )
        text = authority.read_text(encoding="ascii")
        assert "production: true\n" in text
        assert f"authority-id: {authority_id(group_public_key)}\n" in text
        assert f"group-public-key: {group_public_key}\n" in text

        trust_emit = run_tool(
            "emit-root",
            "--group-public-key",
            group_public_key,
            "--allow-trust",
            "--out",
            str(tmp / "trust-authority.txt"),
            "--quiet",
        )
        assert trust_emit.returncode != 0
        assert b"trust/publish authority requires assembly Gate" in trust_emit.stderr

        assert_ok(
            run_tool(
                "ceremony",
                "--authority",
                str(authority),
                "--operator",
                "external authority operator",
                "--ceremony-id",
                "prod-auth-test-v1",
                "--threshold",
                "2",
                "--signer-count",
                "3",
                "--created-utc",
                "2026-06-27T00:00:00Z",
                "--out",
                str(ceremony),
                "--quiet",
            ),
            "write production authority ceremony",
        )
        unsigned = run_tool(
            "verify",
            "--authority",
            str(authority),
            "--ceremony",
            str(ceremony),
            "--quiet",
        )
        assert unsigned.returncode != 0
        assert b"signed ceremony evidence" in unsigned.stderr

        assert_ok(
            run_tool(
                "verify",
                "--authority",
                str(authority),
                "--ceremony",
                str(ceremony),
                "--allow-unsigned-ceremony",
                "--json",
            ),
            "verify unsigned production authority in explicit test mode",
        )

        tampered = tmp / "tampered-ceremony.json"
        value = json.loads(ceremony.read_text(encoding="utf-8"))
        value["fixture_material_used"] = True
        tampered.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        bad = run_tool(
            "verify",
            "--authority",
            str(authority),
            "--ceremony",
            str(tampered),
            "--allow-unsigned-ceremony",
            "--quiet",
        )
        assert bad.returncode != 0
        assert b"reject fixture material" in bad.stderr

    if not args.quiet:
        print("wuci production authority: PASS")


if __name__ == "__main__":
    main()
