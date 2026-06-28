#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CRYPTO = REPO_ROOT / "daylight-equation" / "rust" / "daylight-crypto"

PREFIX = {
    "WJSEAL-v1": b"WJSEAL\x01\x01",
    "WJSEAL-v2": b"WJSEAL\x02\x01",
    "WJSEAL-v3": b"WJSEAL\x03\x01",
}


def sample(version: str) -> bytes:
    value = bytearray(PREFIX[version])
    if version == "WJSEAL-v2":
        value.extend(b"\x22" * 16)
    if version == "WJSEAL-v3":
        value.extend(b"\x33" * 32)
        value.extend(b"\x44" * 16)
    value.extend(b"\x55" * 12)
    value.extend(b"ciphertext")
    value.extend(b"\x66" * 16)
    return bytes(value)


def run_boundary(path: Path) -> dict[str, str]:
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--offline",
            "--quiet",
            "--",
            "wuci-daylight-envelope-boundary",
            "--file",
            str(path),
        ],
        cwd=CRYPTO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    fields: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("=")
        assert sep == "=", line
        fields[key] = value
    return fields


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-DAYLIGHT envelope bridge.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        for version in ("WJSEAL-v1", "WJSEAL-v2", "WJSEAL-v3"):
            artifact = tmp / f"{version}.wj"
            artifact.write_bytes(sample(version))
            fields = run_boundary(artifact)

            assert fields["schema"] == "wuci-daylight-envelope-boundary-v1"
            assert fields["daylight_score"] == "8250"
            assert fields["daylight_score_max"] == "10000"
            assert fields["production_allowed"] == "false"
            assert fields["runtime_containment_claim"] == "false"
            assert fields["whole_system_post_quantum_safety_claim"] == "false"
            assert fields["external_review_claim"] == "false"
            assert fields["official_endorsement_claim"] == "false"
            assert fields["envelope_version"] == version
            assert fields["aead_algorithm"] == "ChaCha20-Poly1305"
            assert fields["tag_verified"] == "false"
            assert fields["daylight_authorized_state_required"] == "true"
            assert fields["daylight_private_open_authorized"] == "false"
            assert fields["wuci_gate_required_for_plaintext_release"] == "true"
            assert fields["ciphertext_len"] == str(len(b"ciphertext"))
            assert len(fields["envelope_sha256_hex"]) == 64
            assert len(fields["envelope_sha3_512_hex"]) == 128

        bad = tmp / "bad.wj"
        bad.write_bytes(b"WJSEAL\x09\x01" + b"\x00" * 28)
        proc = subprocess.run(
            [
                "cargo",
                "run",
                "--offline",
                "--quiet",
                "--",
                "wuci-daylight-envelope-boundary",
                "--file",
                str(bad),
            ],
            cwd=CRYPTO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert proc.returncode != 0
        assert "UnknownEnvelopeVersion" in proc.stderr

    if not args.quiet:
        print("wuci daylight bridge: PASS")


if __name__ == "__main__":
    main()
