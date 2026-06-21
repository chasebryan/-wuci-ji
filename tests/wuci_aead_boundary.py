#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
AEAD_OPEN_MAX = 1048576
ENVELOPE_PREFIX = b"WJSEAL\x01\x01"
ENVELOPE_HEADER_LEN = len(ENVELOPE_PREFIX) + 12
ENVELOPE_TAG_LEN = 16
KEY = bytes.fromhex("00" * 32)


def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*RUNNER, str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def seal_and_open(tmp: Path, size: int, name: str) -> None:
    plain = tmp / f"{name}.plain"
    sealed = tmp / f"{name}.wj"
    opened = tmp / f"{name}.opened"
    plain.write_bytes((b"wuci-boundary-" * ((size // 14) + 1))[:size])
    sealed_proc = run(["seal-file", KEY.hex(), str(plain), str(sealed)])
    assert sealed_proc.returncode == 0, sealed_proc.stderr.decode("utf-8", "replace")
    assert sealed.stat().st_size <= AEAD_OPEN_MAX
    open_proc = run(["open-file", KEY.hex(), str(sealed), str(opened)])
    assert open_proc.returncode == 0, open_proc.stderr.decode("utf-8", "replace")
    assert opened.read_bytes() == plain.read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    exact_plain_size = AEAD_OPEN_MAX - ENVELOPE_HEADER_LEN - ENVELOPE_TAG_LEN
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        seal_and_open(tmp, exact_plain_size - 1, "below-max")
        seal_and_open(tmp, exact_plain_size, "exact-max")

        plain = tmp / "oversized.plain"
        sealed = tmp / "oversized.wj"
        oversized = tmp / "oversized-plus-one.wj"
        opened = tmp / "oversized.opened"
        plain.write_bytes(b"x" * exact_plain_size)
        sealed_proc = run(["seal-file", KEY.hex(), str(plain), str(sealed)])
        assert sealed_proc.returncode == 0, sealed_proc.stderr.decode("utf-8", "replace")
        oversized.write_bytes(sealed.read_bytes() + b"x")
        assert oversized.stat().st_size == AEAD_OPEN_MAX + 1
        open_proc = run(["open-file", KEY.hex(), str(oversized), str(opened)])
        assert open_proc.returncode != 0
        assert open_proc.stdout == b""
        assert not opened.exists()

    if not args.quiet:
        print("wuci AEAD boundary: PASS")


if __name__ == "__main__":
    main()
