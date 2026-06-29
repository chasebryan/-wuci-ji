#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
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


def assert_terminal_plan() -> None:
    ready = wuci_install.terminal_setup_plan(
        host_id="linux:fedora",
        command_paths={"kitty": "/usr/bin/kitty", "ghostty": None},
    )
    assert ready["schema"] == "wuci-terminal-setup-v1"
    assert ready["ready"] is True
    assert ready["selected"] == "kitty"
    assert ready["package_manager_commands"] == []

    missing = wuci_install.terminal_setup_plan(
        host_id="linux:debian",
        command_paths={"kitty": None, "ghostty": None, "apt-get": "/usr/bin/apt-get"},
    )
    assert missing["ready"] is False
    assert missing["status"] == "missing-terminal"
    assert missing["commands_executed"] == []
    assert missing["package_manager_commands"]
    for command in missing["package_manager_commands"]:
        assert isinstance(command["argv"], list)
        assert command["argv"]


def assert_root_key_copy(tmp: Path) -> None:
    local_key = tmp / "install-root.pub"
    key_hash = wuci_install.copy_local_install_root_key(local_key)
    assert key_hash == wuci_install.trust_key_check(local_key, quiet=True)

    if hasattr(os, "symlink"):
        link = tmp / "install-root-link.pub"
        link.symlink_to(local_key)
        expect_fail(lambda: wuci_install.copy_local_install_root_key(link))

    if hasattr(os, "link"):
        hard_source = tmp / "install-root-hard-source.pub"
        hard_link = tmp / "install-root-hard-link.pub"
        hard_source.write_bytes(local_key.read_bytes())
        try:
            os.link(hard_source, hard_link)
        except OSError:
            return
        expect_fail(lambda: wuci_install.copy_local_install_root_key(hard_source))


def assert_bootstrap_json(tmp: Path) -> None:
    prefix = tmp / "prefix"
    install_key = tmp / "config" / "install-root.pub"

    def fake_perform_install(args: argparse.Namespace) -> dict:
        assert args.install_root_key == str(install_key)
        assert args.prefix == str(prefix)
        return {
            "schema": "wuci-install-install-v1",
            "installed": True,
            "prefix": str(prefix),
            "binary_sha256": "a" * 64,
            "binary_sha384": "b" * 96,
            "binary_sha512": "c" * 128,
            "receipt": {},
        }

    def fake_terminal_setup_plan() -> dict:
        return {
            "schema": "wuci-terminal-setup-v1",
            "host": "test",
            "ready": False,
            "status": "missing-terminal",
            "found": {},
            "selected": None,
            "acceptable_terminals": ["kitty", "ghostty"],
            "package_manager_commands": [
                {"manager": "test", "argv": ["pkg", "install", "kitty"], "terminals": ["kitty"]}
            ],
            "commands_executed": [],
            "notes": ["test"],
        }

    old_perform = wuci_install.perform_install
    old_terminal = wuci_install.terminal_setup_plan
    try:
        wuci_install.perform_install = fake_perform_install
        wuci_install.terminal_setup_plan = fake_terminal_setup_plan
        args = argparse.Namespace(
            install_root_key=str(install_key),
            prefix=str(prefix),
            version=wuci_install.VERSION,
            manifest=str(wuci_install.DEFAULT_MANIFEST),
            signature=str(wuci_install.DEFAULT_SIGNATURE),
            ssh_keygen=None,
            allow_prefix=True,
            require_terminal=False,
            json=True,
            ticker="never",
        )
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            assert wuci_install.run_bootstrap(args) == 0
    finally:
        wuci_install.perform_install = old_perform
        wuci_install.terminal_setup_plan = old_terminal

    payload = json.loads(capture.getvalue())
    assert payload["schema"] == "wuci-install-bootstrap-v1"
    assert payload["installed"] is True
    assert payload["install_root_key"] == str(install_key)
    assert payload["terminal_setup"]["commands_executed"] == []
    setup_path = Path(payload["terminal_setup_path"])
    assert setup_path.exists()
    assert json.loads(setup_path.read_text(encoding="utf-8"))["schema"] == "wuci-terminal-setup-v1"


def main() -> None:
    argparse.ArgumentParser(description="Check WUCI install bootstrap.").add_argument(
        "--quiet", action="store_true"
    )
    assert_terminal_plan()
    with tempfile.TemporaryDirectory(prefix="wuci-install-bootstrap-") as tmp_name:
        tmp = Path(tmp_name)
        assert_root_key_copy(tmp)
        assert_bootstrap_json(tmp)


if __name__ == "__main__":
    main()
