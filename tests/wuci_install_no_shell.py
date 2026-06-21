#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_install  # noqa: E402


class FakeProc:
    returncode = 0
    stdout = b"Good signature\n"
    stderr = b""


def main() -> None:
    argparse.ArgumentParser().add_argument("--quiet", action="store_true")
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeProc()

    original = wuci_install.subprocess.run
    try:
        wuci_install.subprocess.run = fake_run
        key = REPO / "install" / "wuci-install-root.v1.pub"
        wuci_install.verify_manifest_signature(
            install_root_key=key,
            manifest_path=REPO / "install" / "wuci-install-manifest.v1",
            signature_path=REPO / "install" / "wuci-install-manifest.v1.sig",
            ssh_keygen="/usr/bin/ssh-keygen",
            quiet=True,
        )
        wuci_install.run_checked(["/bin/echo", "ok;touch /tmp/nope"], "fake")
    finally:
        wuci_install.subprocess.run = original

    assert calls
    for args, kwargs in calls:
        assert isinstance(args[0], list)
        assert kwargs.get("shell") is not True
    try:
        wuci_install.prefix_path("/tmp/wuci;touch-nope", allow_prefix=False)
    except wuci_install.InstallError:
        pass
    else:
        raise AssertionError("malicious prefix should be rejected without --allow-prefix")


if __name__ == "__main__":
    main()
