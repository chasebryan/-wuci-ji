#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
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
    text = (REPO / "install" / "wuci-install-manifest.v1").read_text(encoding="ascii")
    fields = wuci_install.parse_manifest(text)
    assert wuci_install.canonical_manifest(fields) == text
    assert fields["runtime-sandbox-claimed"] == "false"
    assert fields["quantum-safe-claimed"] == "false"

    current_bin = REPO / "build" / "wuci-ji"
    live_fields = wuci_install.manifest_fields_for_binary(current_bin)
    live_text = wuci_install.canonical_manifest(live_fields)
    live_manifest = wuci_install.parse_manifest(live_text)
    assert live_manifest["binary-sha256"] == wuci_install.sha256_file(current_bin)
    assert live_manifest["binary-sha384"] == wuci_install.sha384_file(current_bin)
    assert live_manifest["binary-sha512"] == wuci_install.sha512_file(current_bin)

    with tempfile.TemporaryDirectory(prefix="wuci-install-json-") as tmp_name:
        out = Path(tmp_name) / "install-manifest.v1"
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            assert (
                wuci_install.run_manifest(
                    argparse.Namespace(bin=str(current_bin), out=str(out), json=True)
                )
                == 0
            )
        data = json.loads(capture.getvalue())
        assert data["schema"] == "wuci-install-manifest-output-v1"
        assert data["out"] == str(out)
        assert data["manifest"]["binary-sha256"] == live_manifest["binary-sha256"]
        assert wuci_install.parse_manifest(out.read_text(encoding="ascii")) == data["manifest"]

    expect_fail(lambda: wuci_install.parse_manifest(text.rstrip("\n")))
    expect_fail(lambda: wuci_install.parse_manifest(text.replace("\n", "\r\n")))
    expect_fail(lambda: wuci_install.parse_manifest(text + "extra: field\n"))
    expect_fail(lambda: wuci_install.parse_manifest(text.replace(fields["binary-sha256"], "0" * 63)))


if __name__ == "__main__":
    main()
