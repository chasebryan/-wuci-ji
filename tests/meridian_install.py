#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "meridian-install"


def assert_shell_syntax() -> None:
    result = subprocess.run(
        ["sh", "-n", str(INSTALLER)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def assert_generated_helpers_quote_installer_paths(tmp: Path) -> None:
    marker = tmp / "injection-ran"
    prefix = Path(str(tmp / "prefix with spaces") + f";touch {marker};#")
    env = os.environ.copy()
    env["MERIDIAN_VAULT"] = str(tmp / "vault with spaces") + f";touch {marker};#"
    result = subprocess.run(
        [str(INSTALLER), "--prefix", str(prefix), "--vault", "--yes"],
        cwd=REPO,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists(), result.stdout + result.stderr

    launcher = prefix / "bin" / "daylight-meridian"
    uninstaller = prefix / "bin" / "uninstall-meridian"
    for script in (launcher, uninstaller):
        syntax = subprocess.run(
            ["sh", "-n", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert syntax.returncode == 0, syntax.stderr

    uninstall = subprocess.run(
        [str(uninstaller)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert uninstall.returncode == 0, uninstall.stderr
    assert not marker.exists(), uninstall.stdout + uninstall.stderr


def assert_symlink_prefix_rejected(tmp: Path) -> None:
    real_prefix = tmp / "real-prefix"
    real_prefix.mkdir()
    link_prefix = tmp / "link-prefix"
    link_prefix.symlink_to(real_prefix, target_is_directory=True)
    result = subprocess.run(
        [str(INSTALLER), "--prefix", str(link_prefix), "--vault", "--yes"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "symlink" in result.stderr


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="meridian-install-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_shell_syntax()
        assert_generated_helpers_quote_installer_paths(tmp)
        assert_symlink_prefix_rejected(tmp)
    if "--quiet" not in sys.argv:
        print("meridian-install tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
