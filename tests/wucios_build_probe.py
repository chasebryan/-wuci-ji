#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tarfile
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_PROBE = REPO_ROOT / "tools/wucios/trial_collectors/build_probe.py"


def load_build_probe():
    spec = importlib.util.spec_from_file_location("wucios_build_probe", BUILD_PROBE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_symlink_rejected(probe, tmp: Path) -> None:
    if not hasattr(os, "symlink"):
        return
    rootfs = tmp / "rootfs-symlink"
    rootfs.mkdir()
    target = rootfs / "target.txt"
    target.write_text("target\n", encoding="utf-8")
    (rootfs / "link.txt").symlink_to(target)
    try:
        probe.tar_rootfs(rootfs, tmp / "symlink.tar.gz")
    except RuntimeError as exc:
        assert "symlink" in str(exc), exc
    else:
        raise AssertionError("build probe archived a symlinked rootfs member")


def assert_hardlink_rejected(probe, tmp: Path) -> None:
    rootfs = tmp / "rootfs-hardlink"
    rootfs.mkdir()
    source = rootfs / "source.txt"
    source.write_text("source\n", encoding="utf-8")
    hardlink = rootfs / "hardlink.txt"
    try:
        os.link(source, hardlink)
    except (OSError, NotImplementedError):
        return
    try:
        probe.tar_rootfs(rootfs, tmp / "hardlink.tar.gz")
    except RuntimeError as exc:
        assert "hardlinked" in str(exc), exc
    else:
        raise AssertionError("build probe archived a hardlinked rootfs member")


def assert_debian_probe_uses_https_mirror(probe, tmp: Path) -> None:
    captured: list[list[str]] = []
    original_run_command = probe.run_command
    original_geteuid = getattr(probe.os, "geteuid", None)

    def fake_run_command(command, _log_path):
        captured.append(list(command))
        return 1

    probe.run_command = fake_run_command
    if original_geteuid is not None:
        probe.os.geteuid = lambda: 0
    try:
        status, blockers = probe.attempt_debian(
            tmp / "debian-out",
            tmp / "debian-work",
            [{"name": "debootstrap", "present": True}, {"name": "tar", "present": True}],
            tmp / "debian.log",
        )
    finally:
        probe.run_command = original_run_command
        if original_geteuid is not None:
            probe.os.geteuid = original_geteuid
    assert status == "BUILD_ATTEMPTED_FAILED", status
    assert blockers == ["BUILD_COMMAND_FAILED"], blockers
    assert captured and "https://deb.debian.org/debian" in captured[0], captured
    assert "http://deb.debian.org/debian" not in captured[0], captured


def main() -> None:
    probe = load_build_probe()
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        rootfs = tmp / "rootfs"
        (rootfs / "etc").mkdir(parents=True)
        (rootfs / "etc/os-release").write_text("NAME=wucios-test\n", encoding="utf-8")
        archive = tmp / "rootfs.tar.gz"
        probe.tar_rootfs(rootfs, archive)
        with tarfile.open(archive, "r:gz") as tar:
            names = set(tar.getnames())
        assert "." in names and "etc/os-release" in names, names
        assert_symlink_rejected(probe, tmp)
        assert_hardlink_rejected(probe, tmp)
        assert_debian_probe_uses_https_mirror(probe, tmp)
    print("wucios build probe: PASS")


if __name__ == "__main__":
    main()
