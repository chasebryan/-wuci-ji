#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
import shutil
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


def make_prefix(prefix: Path) -> dict:
    binary = prefix / "bin" / "wuci-ji"
    binary.parent.mkdir(parents=True)
    shutil.copy2(REPO / "build" / "wuci-ji", binary)
    binary.chmod(0o755)
    share = prefix / "share" / "wuci-ji"
    share.mkdir(parents=True)
    shutil.copy2(REPO / "install" / "wuci-install-root.v1.pub", share / "install-root.pub")
    shutil.copy2(REPO / "install" / "wuci-install-manifest.v1", share / "wuci-install-manifest.v1")
    shutil.copy2(REPO / "install" / "wuci-install-manifest.v1.sig", share / "wuci-install-manifest.v1.sig")
    receipt = {
        "schema": "wuci-install-receipt-v1",
        "product": "无此机 / Wuci-ji",
        "version": "0.1",
        "installed": True,
        "install_status": "nominal",
        "prefix": str(prefix),
        "binary_path": str(binary),
        "audit_command": str(prefix / "bin" / "wuci-ji-audit"),
        "install_root_key_sha256": wuci_install.sha256_file(share / "install-root.pub"),
        "install_manifest_sha512": wuci_install.sha512_file(share / "wuci-install-manifest.v1"),
        "install_signature_verified": True,
        "binary_sha256": wuci_install.sha256_file(binary),
        "binary_sha384": wuci_install.sha384_file(binary),
        "binary_sha512": wuci_install.sha512_file(binary),
        "selftest": True,
        "harden_proof": True,
        "cage_proof": True,
        "qcage_compat_proof": True,
        "witness_bundle": True,
        "ledger_history": True,
        "runtime_sandbox_claimed": False,
        "quantum_safe_claimed": False,
    }
    (share / "install-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return receipt


def main() -> None:
    argparse.ArgumentParser().add_argument("--quiet", action="store_true")
    with tempfile.TemporaryDirectory() as tmp_name:
        prefix = Path(tmp_name)
        make_prefix(prefix)
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            assert wuci_install.run_audit(argparse.Namespace(prefix=str(prefix), ssh_keygen=None)) == 0
        output = capture.getvalue()
        assert "无此机 / Wuci-ji systems nominal." in output
        assert "Version 0.1 installed." in output
        for line in (
            "install-root-key-copied: PASS",
            "install-manifest-signature: PASS",
            "selftest: PASS",
            "harden-proof: PASS",
            "cage-proof: PASS",
            "qcage-compat-proof: PASS",
            "witness-bundle: PASS",
            "ledger-history: PASS",
            "runtime-sandbox-claimed: false",
            "quantum-safe-claimed: false",
        ):
            assert line in output
        (prefix / "bin" / "wuci-ji").write_bytes(b"tampered")
        expect_fail(lambda: wuci_install.run_audit(argparse.Namespace(prefix=str(prefix), ssh_keygen=None)))


if __name__ == "__main__":
    main()
