#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
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
    assert live_fields["binary-path"] == "build/wuci-ji"
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

    ssh = shutil.which("ssh-keygen")
    assert ssh is not None
    with tempfile.TemporaryDirectory(prefix="wuci-install-sign-") as tmp_name:
        tmp = Path(tmp_name)
        key = tmp / "install-root"
        subprocess.run(
            [ssh, "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        pub = Path(str(key) + ".pub")
        sidecar = tmp / "install-root.pub.sha256"
        sidecar.write_text(
            f"{wuci_install.sha256_file(pub)}  install/wuci-install-root.v1.pub\n",
            encoding="ascii",
        )
        manifest_out = tmp / "install-manifest.v1"
        signature_out = tmp / "install-manifest.v1.sig"
        old_root = wuci_install.DEFAULT_REPO_ROOT_KEY
        old_sidecar = wuci_install.DEFAULT_REPO_ROOT_KEY_SHA256
        try:
            wuci_install.DEFAULT_REPO_ROOT_KEY = pub
            wuci_install.DEFAULT_REPO_ROOT_KEY_SHA256 = sidecar
            with contextlib.redirect_stdout(io.StringIO()):
                assert (
                    wuci_install.run_manifest(
                        argparse.Namespace(bin=str(current_bin), out=str(manifest_out), json=False)
                    )
                    == 0
                )
            sign_capture = io.StringIO()
            with contextlib.redirect_stdout(sign_capture):
                assert (
                    wuci_install.run_sign_manifest(
                        argparse.Namespace(
                            install_root_key=str(pub),
                            signing_key=str(key),
                            manifest=str(manifest_out),
                            signature=str(signature_out),
                            ssh_keygen=ssh,
                            json=True,
                        )
                    )
                    == 0
                )
            sign_data = json.loads(sign_capture.getvalue())
            assert sign_data["schema"] == "wuci-install-manifest-sign-v1"
            assert sign_data["signature_verified"] is True
            assert sign_data["signature_path"] == str(signature_out)
            assert signature_out.read_text(encoding="ascii").startswith("-----BEGIN SSH SIGNATURE-----")
            with contextlib.redirect_stdout(io.StringIO()):
                assert (
                    wuci_install.run_verify_manifest(
                        argparse.Namespace(
                            install_root_key=str(pub),
                            bin=str(current_bin),
                            manifest=str(manifest_out),
                            signature=str(signature_out),
                            ssh_keygen=ssh,
                            json=True,
                        )
                    )
                    == 0
                )
            bad_bin = tmp / "wrong-wuci-ji"
            bad_bin.write_bytes(b"wrong binary\n")
            expect_fail(
                lambda: wuci_install.run_verify_manifest(
                    argparse.Namespace(
                        install_root_key=str(pub),
                        bin=str(bad_bin),
                        manifest=str(manifest_out),
                        signature=str(signature_out),
                        ssh_keygen=ssh,
                        json=True,
                    )
                )
            )
            manifest_link = tmp / "install-manifest.v1.hardlink"
            os.link(manifest_out, manifest_link)
            try:
                expect_fail(
                    lambda: wuci_install.run_verify_manifest(
                        argparse.Namespace(
                            install_root_key=str(pub),
                            bin=str(current_bin),
                            manifest=str(manifest_link),
                            signature=str(signature_out),
                            ssh_keygen=ssh,
                            json=False,
                        )
                    )
                )
            finally:
                manifest_link.unlink()
            signature_link = tmp / "install-manifest.v1.sig.hardlink"
            os.link(signature_out, signature_link)
            try:
                expect_fail(
                    lambda: wuci_install.run_verify_manifest(
                        argparse.Namespace(
                            install_root_key=str(pub),
                            bin=str(current_bin),
                            manifest=str(manifest_out),
                            signature=str(signature_link),
                            ssh_keygen=ssh,
                            json=False,
                        )
                    )
                )
            finally:
                signature_link.unlink()
            pub_link = tmp / "install-root.pub.hardlink"
            os.link(pub, pub_link)
            try:
                expect_fail(
                    lambda: wuci_install.run_verify_manifest(
                        argparse.Namespace(
                            install_root_key=str(pub_link),
                            bin=str(current_bin),
                            manifest=str(manifest_out),
                            signature=str(signature_out),
                            ssh_keygen=ssh,
                            json=False,
                        )
                    )
                )
            finally:
                pub_link.unlink()
        finally:
            wuci_install.DEFAULT_REPO_ROOT_KEY = old_root
            wuci_install.DEFAULT_REPO_ROOT_KEY_SHA256 = old_sidecar

    expect_fail(lambda: wuci_install.parse_manifest(text.rstrip("\n")))
    expect_fail(lambda: wuci_install.parse_manifest(text.replace("\n", "\r\n")))
    expect_fail(lambda: wuci_install.parse_manifest(text + "extra: field\n"))
    expect_fail(lambda: wuci_install.parse_manifest(text.replace(fields["binary-sha256"], "0" * 63)))


if __name__ == "__main__":
    main()
