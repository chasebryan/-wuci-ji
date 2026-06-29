#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PRISM = REPO_ROOT / "tools" / "wuci-prism"
WJSEAL_PREFIX_LEN = 8
KEY_ID_LEN = 16
EPHEMERAL_PUBLIC_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(PRISM), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def sample_v1() -> bytes:
    return (
        b"WJSEAL\x01\x01"
        + bytes(range(0x00, 0x0C))
        + b"prism-v1-ciphertext"
        + bytes(range(0xF0, 0x100))
    )


def sample_v2() -> bytes:
    return (
        b"WJSEAL\x02\x01"
        + bytes(range(0x20, 0x30))
        + bytes(range(0x30, 0x3C))
        + b"prism-v2-ciphertext"
        + bytes(range(0xE0, 0xF0))
    )


def sample_v3() -> bytes:
    return (
        b"WJSEAL\x03\x01"
        + bytes(range(0x40, 0x60))
        + bytes(range(0x60, 0x70))
        + bytes(range(0x70, 0x7C))
        + b"prism-v3-ciphertext"
        + bytes(range(0xD0, 0xE0))
    )


def write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    return path


def expected_manifest(payload: bytes, version: int) -> str:
    if version == 1:
        header_len = WJSEAL_PREFIX_LEN + NONCE_LEN
        nonce = payload[WJSEAL_PREFIX_LEN:header_len]
        header_lines: list[str] = []
    elif version == 2:
        header_len = WJSEAL_PREFIX_LEN + KEY_ID_LEN + NONCE_LEN
        key_id = payload[WJSEAL_PREFIX_LEN : WJSEAL_PREFIX_LEN + KEY_ID_LEN]
        nonce = payload[WJSEAL_PREFIX_LEN + KEY_ID_LEN : header_len]
        header_lines = [f"key-id: {key_id.hex()}"]
    else:
        header_len = WJSEAL_PREFIX_LEN + EPHEMERAL_PUBLIC_LEN + KEY_ID_LEN + NONCE_LEN
        public = payload[
            WJSEAL_PREFIX_LEN : WJSEAL_PREFIX_LEN + EPHEMERAL_PUBLIC_LEN
        ]
        key_start = WJSEAL_PREFIX_LEN + EPHEMERAL_PUBLIC_LEN
        key_id = payload[key_start : key_start + KEY_ID_LEN]
        nonce = payload[key_start + KEY_ID_LEN : header_len]
        header_lines = [
            f"ephemeral-public: {public.hex()}",
            f"key-id: {key_id.hex()}",
        ]

    ciphertext = payload[header_len:-TAG_LEN]
    tag = payload[-TAG_LEN:]
    lines = [
        f"version: {version}",
        "algorithm: 1",
        f"header-length: {header_len}",
        *header_lines,
        f"artifact-sha256: {hashlib.sha256(payload).hexdigest()}",
        f"ciphertext-length: {len(ciphertext)}",
        f"ciphertext-sha256: {hashlib.sha256(ciphertext).hexdigest()}",
        f"nonce: {nonce.hex()}",
        f"tag: {tag.hex()}",
    ]
    return "\n".join(lines) + "\n"


def assert_manifest_matches(path: Path, payload: bytes, version: int) -> None:
    proc = run(["manifest", str(path)])
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert proc.stderr == b""
    assert proc.stdout.decode("ascii") == expected_manifest(payload, version)


def assert_inspect_json(path: Path, payload: bytes) -> None:
    proc = run(["inspect", str(path), "--json"])
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert proc.stderr == b""
    report = json.loads(proc.stdout.decode("utf-8"))
    manifest = expected_manifest(payload, 3)

    assert report["schema"] == "wuci-prism-report-v1"
    assert report["tool"] == "Wuci-Prism"
    assert report["wjseal"]["version"] == 3
    assert report["wjseal"]["version_name"] == "WJSEAL-v3"
    assert report["public_header"]["ephemeral_public"] == bytes(range(0x40, 0x60)).hex()
    assert report["public_header"]["key_id"] == bytes(range(0x60, 0x70)).hex()
    assert report["public_header"]["nonce"] == bytes(range(0x70, 0x7C)).hex()
    assert report["ciphertext"]["length"] == len(b"prism-v3-ciphertext")
    assert report["tag"]["offset"] == len(payload) - TAG_LEN
    assert report["artifact"]["digest_vector"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert report["artifact"]["digest_vector"]["sha384"] == hashlib.sha384(payload).hexdigest()
    assert report["artifact"]["digest_vector"]["sha512"] == hashlib.sha512(payload).hexdigest()
    assert report["artifact_manifest_sha256"] == hashlib.sha256(
        manifest.encode("ascii")
    ).hexdigest()
    assert report["gate"]["required_for_plaintext_release"] is True
    assert report["gate"]["required_status"] == "required-for-plaintext-release"
    assert report["boundary"]["secret_key_input"] == "unsupported"
    assert report["boundary"]["plaintext_output"] == "unsupported"
    assert report["boundary"]["decrypts"] is False
    assert report["boundary"]["plaintext_released"] is False
    assert report["boundary"]["tag_verified"] is False


def assert_ticker_stays_on_stderr(path: Path) -> None:
    inspect_proc = run(["inspect", str(path), "--ticker", "always"])
    assert inspect_proc.returncode == 0, inspect_proc.stderr.decode("utf-8", "replace")
    assert b"schema: wuci-prism-report-v1\n" in inspect_proc.stdout
    assert b"\x1b[" in inspect_proc.stderr
    assert chr(0x25B2).encode("utf-8") in inspect_proc.stderr
    assert b"wuci-prism 100%" in inspect_proc.stderr
    assert b"schema:" not in inspect_proc.stderr

    json_proc = run(["inspect", str(path), "--json", "--ticker", "always"])
    assert json_proc.returncode == 0, json_proc.stderr.decode("utf-8", "replace")
    report = json.loads(json_proc.stdout.decode("utf-8"))
    assert report["schema"] == "wuci-prism-report-v1"
    assert b"\x1b[" in json_proc.stderr
    assert b'"schema"' not in json_proc.stderr


def assert_text_commands(path: Path) -> None:
    inspect_proc = run(["inspect", str(path)])
    assert inspect_proc.returncode == 0, inspect_proc.stderr.decode("utf-8", "replace")
    assert inspect_proc.stderr == b""
    inspect_text = inspect_proc.stdout.decode("ascii")
    assert "schema: wuci-prism-report-v1\n" in inspect_text
    assert "tool: Wuci-Prism\n" in inspect_text
    assert "artifact-sha384: " in inspect_text
    assert "artifact-sha512: " in inspect_text
    assert "gate-required-status: required-for-plaintext-release\n" in inspect_text
    assert "secret-key-input: unsupported\n" in inspect_text
    assert "plaintext-output: unsupported\n" in inspect_text

    boundary_proc = run(["boundary", str(path)])
    assert boundary_proc.returncode == 0, boundary_proc.stderr.decode("utf-8", "replace")
    assert boundary_proc.stderr == b""
    boundary_text = boundary_proc.stdout.decode("ascii")
    assert "mode: keyless-public-artifact-inspection\n" in boundary_text
    assert "decrypts: false\n" in boundary_text
    assert "runtime-sandboxing-claimed: false\n" in boundary_text
    assert "quantum-safe-claimed: false\n" in boundary_text

    explain_proc = run(["explain", str(path)])
    assert explain_proc.returncode == 0, explain_proc.stderr.decode("utf-8", "replace")
    assert explain_proc.stderr == b""
    explain_text = explain_proc.stdout.decode("ascii")
    assert "Wuci-Prism refracts sealed WJSEAL artifacts" in explain_text
    assert "plaintext release: WUCI-GATE required\n" in explain_text


def assert_rejections(tmp: Path, good_path: Path) -> None:
    bad = write(tmp / "bad.wj", b"BADSEAL\x01\x01" + b"\0" * 32)
    bad_proc = run(["inspect", str(bad)])
    assert bad_proc.returncode != 0
    assert bad_proc.stdout == b""
    assert b"unsupported WJSEAL" in bad_proc.stderr

    short = write(tmp / "short-v3.wj", b"WJSEAL\x03\x01" + b"\0" * 16)
    short_proc = run(["inspect", str(short)])
    assert short_proc.returncode != 0
    assert short_proc.stdout == b""
    assert b"truncated WJSEAL" in short_proc.stderr

    decrypt_proc = run(["decrypt", str(good_path)])
    assert decrypt_proc.returncode != 0
    assert decrypt_proc.stdout == b""
    assert b"invalid choice" in decrypt_proc.stderr

    if hasattr(os, "symlink"):
        link = tmp / "artifact-link.wj"
        link.symlink_to(good_path)
        link_proc = run(["inspect", str(link)])
        assert link_proc.returncode != 0
        assert link_proc.stdout == b""
        assert b"symlink" in link_proc.stderr


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Wuci-Prism.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    assert PRISM.exists()
    assert os.access(PRISM, os.X_OK)

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        v1 = sample_v1()
        v2 = sample_v2()
        v3 = sample_v3()
        v1_path = write(tmp / "sealed-v1.wj", v1)
        v2_path = write(tmp / "sealed-v2.wj", v2)
        v3_path = write(tmp / "sealed-v3.wj", v3)

        assert_manifest_matches(v1_path, v1, 1)
        assert_manifest_matches(v2_path, v2, 2)
        assert_manifest_matches(v3_path, v3, 3)
        assert_inspect_json(v3_path, v3)
        assert_ticker_stays_on_stderr(v3_path)
        assert_text_commands(v3_path)
        assert_rejections(tmp, v3_path)

    if not args.quiet:
        print("wuci prism: PASS")


if __name__ == "__main__":
    main()
