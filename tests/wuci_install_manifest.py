#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
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
    text = (REPO / "install" / "wuci-install-manifest.v1").read_text(encoding="ascii")
    fields = wuci_install.parse_manifest(text)
    assert wuci_install.canonical_manifest(fields) == text
    assert fields["runtime-sandbox-claimed"] == "false"
    assert fields["quantum-safe-claimed"] == "false"
    assert fields["binary-sha256"] == wuci_install.sha256_file(REPO / "build" / "wuci-ji")
    assert fields["binary-sha384"] == wuci_install.sha384_file(REPO / "build" / "wuci-ji")
    assert fields["binary-sha512"] == wuci_install.sha512_file(REPO / "build" / "wuci-ji")
    expect_fail(lambda: wuci_install.parse_manifest(text.rstrip("\n")))
    expect_fail(lambda: wuci_install.parse_manifest(text.replace("\n", "\r\n")))
    expect_fail(lambda: wuci_install.parse_manifest(text + "extra: field\n"))
    expect_fail(lambda: wuci_install.parse_manifest(text.replace(fields["binary-sha256"], "0" * 63)))


if __name__ == "__main__":
    main()
