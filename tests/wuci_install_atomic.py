#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_install  # noqa: E402


def expect_fail(fn) -> None:
    try:
        fn()
    except wuci_install.InstallError:
        return
    raise AssertionError("expected failure")


def main() -> None:
    argparse.ArgumentParser().add_argument("--quiet", action="store_true")
    tmp_root = REPO / "build" / "test-tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tmp_root) as tmp_name:
        tmp = Path(tmp_name)
        target = tmp / "bin" / "wuci-ji"
        wuci_install.atomic_install_bytes(target, b"one", mode=0o755, context="binary")
        assert target.read_bytes() == b"one"
        assert os.stat(target).st_mode & 0o777 == 0o755
        wuci_install.atomic_install_bytes(target, b"two", mode=0o755, context="binary")
        assert target.read_bytes() == b"two"
        symlink = tmp / "bin" / "link"
        symlink.symlink_to(target)
        expect_fail(lambda: wuci_install.atomic_install_bytes(symlink, b"bad", mode=0o755, context="binary"))


if __name__ == "__main__":
    main()
