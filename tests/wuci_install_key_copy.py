#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        local = tmp / "install-root.pub"
        expect_fail(lambda: wuci_install.trust_key_check(local, quiet=True))
        local.write_bytes((REPO / "install" / "wuci-install-root.v1.pub").read_bytes())
        assert len(wuci_install.trust_key_check(local, quiet=True)) == 64
        bad = tmp / "bad.pub"
        bad.write_text("ssh-ed25519 AAAA bad\n", encoding="ascii")
        expect_fail(lambda: wuci_install.trust_key_check(bad, quiet=True))
        link = tmp / "link.pub"
        link.symlink_to(local)
        expect_fail(lambda: wuci_install.trust_key_check(link, quiet=True))


if __name__ == "__main__":
    main()
