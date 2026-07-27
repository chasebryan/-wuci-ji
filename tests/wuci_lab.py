#!/usr/bin/env python3
"""Security and contract tests for the Wuci lab VM supervisor."""

from __future__ import annotations

import argparse
import copy
import contextlib
import hashlib
import io
import json
import os
import pty
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import wuci_lab  # noqa: E402


def assert_raises(
    expected: type[BaseException],
    function: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> BaseException:
    try:
        function(*args, **kwargs)
    except expected as exc:
        return exc
    except BaseException as exc:
        raise AssertionError(
            f"expected {expected.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {expected.__name__}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trusted_kvm_status(*, trusted: bool = True) -> dict[str, Any]:
    return {
        "path": "/dev/kvm",
        "expected_path": "/dev/kvm",
        "exact_path": True,
        "character_device": trusted,
        "owner_uid": 0 if trusted else None,
        "owner_gid": 993 if trusted else None,
        "root_owned": trusted,
        "mode": "0660" if trusted else None,
        "device_major": 10 if trusted else None,
        "device_minor": 232 if trusted else None,
        "expected_device_major": 10,
        "expected_device_minor": 232,
        "major_minor_match": trusted,
        "world_readable": False,
        "world_writable": False,
        "unprivileged_user": True,
        "readable": trusted,
        "writable": trusted,
        "readable_by_current_user": trusted,
        "writable_by_current_user": trusted,
        "trusted": trusted,
        "reason": None if trusted else "fixture missing trusted KVM device",
    }


class LabFixture:
    def __init__(self) -> None:
        (REPO_ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="wuci-lab-test.",
            dir=REPO_ROOT / "build",
        )
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.state = self.root / "state"
        self.kernel = self._write("vmlinuz-lts", b"fixture kernel\n")
        self.initrd = self._write("initramfs-lts", b"fixture initramfs\n")
        self.base = self._write("wuci-root.ext4", b"\0" * (2 * 1024 * 1024))
        self.qemu = self.root / "qemu-system-x86_64"
        self.qemu_img = self.root / "qemu-img"
        self.mke2fs = self.root / "mke2fs"
        self.debugfs = self.root / "debugfs"
        self.qemu.write_text(
            """#!/usr/bin/python3
import sys
if sys.argv[1:] == ["--version"] or (
    len(sys.argv) == 4
    and sys.argv[1] == "-sandbox"
    and sys.argv[3] == "--version"
):
    print("QEMU emulator version 9.2.0 fixture")
elif sys.argv[1:] == ["-machine", "help"]:
    print("q35  Standard PC (Q35 + ICH9, 2009)")
elif sys.argv[1:] == ["-accel", "help"]:
    print("Accelerators supported in QEMU binary:")
    print("tcg")
    print("kvm")
elif sys.argv[1:] == ["--help"]:
    print("-sandbox on|off")
else:
    raise SystemExit(64)
""",
            encoding="utf-8",
        )
        self.qemu.chmod(0o700)
        self.qemu_img.write_text(
            """#!/usr/bin/python3
import json
import os
import sys

args = sys.argv[1:]
if args and args[0] == "create":
    base = args[-2]
    output = args[-1]
    with open(output, "r+b") as stream:
        stream.seek(0)
        stream.truncate()
        stream.write((json.dumps({"base": base}) + "\\n").encode("utf-8"))
    raise SystemExit(0)
if args[:2] == ["info", "--output=json"]:
    overlay = args[-1]
    with open(overlay, "rb") as stream:
        record = json.loads(stream.read().decode("utf-8"))
    base = record["base"]
    print(json.dumps({
        "filename": overlay,
        "format": "qcow2",
        "backing-filename": base,
        "full-backing-filename": base,
        "backing-filename-format": "raw",
        "virtual-size": os.stat(base).st_size,
        "actual-size": os.stat(overlay).st_size,
        "format-specific": {
            "type": "qcow2",
            "data": {
                "compat": "1.1",
                "lazy-refcounts": False,
                "corrupt": False
            }
        }
    }))
    raise SystemExit(0)
raise SystemExit(64)
""",
            encoding="utf-8",
        )
        self.qemu_img.chmod(0o700)
        self.mke2fs.write_text(
            """#!/usr/bin/python3
import os
import sys

args = sys.argv[1:]
if args == ["-V"]:
    sys.stderr.write("mke2fs 1.47.0 (5-Feb-2023)\\n")
    sys.stderr.write("\\tUsing EXT2FS Library version 1.47.0\\n")
    raise SystemExit(0)
os.execv("/usr/sbin/mke2fs", ["/usr/sbin/mke2fs", *args])
""",
            encoding="utf-8",
        )
        self.mke2fs.chmod(0o700)
        self.debugfs.write_text(
            """#!/usr/bin/python3
import os
import sys

args = sys.argv[1:]
if args == ["-V"]:
    sys.stderr.write("debugfs 1.47.0 (5-Feb-2023)\\n")
    sys.stderr.write("\\tUsing EXT2FS Library version 1.47.0\\n")
    raise SystemExit(0)
os.execv("/usr/sbin/debugfs", ["/usr/sbin/debugfs", *args])
""",
            encoding="utf-8",
        )
        self.debugfs.chmod(0o700)

    def _write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def close(self) -> None:
        self.temporary.cleanup()

    def boot_args(self) -> dict[str, Any]:
        return {
            "kernel": self.kernel,
            "kernel_sha256": sha256(self.kernel),
            "initrd": self.initrd,
            "initrd_sha256": sha256(self.initrd),
            "base_image": self.base,
            "base_sha256": sha256(self.base),
            "state_root": self.state,
            "qemu": str(self.qemu),
            "qemu_img": str(self.qemu_img),
        }

    def capabilities(
        self,
        *,
        kvm: bool = True,
        sandbox: bool = True,
        q35: bool = True,
        non_root: bool = True,
        bubblewrap: bool = True,
    ) -> dict[str, Any]:
        return {
            "qemu_available": True,
            "qemu_path": str(self.qemu),
            "qemu_version": "fixture",
            "q35_supported": q35,
            "qemu_sandbox_supported": sandbox,
            "kvm_accel_supported": kvm,
            "tcg_accel_supported": True,
            "kvm_device": trusted_kvm_status(trusted=kvm and non_root),
            "bubblewrap": {
                "available": bubblewrap,
                "trusted": bubblewrap,
                "path": str(wuci_lab.TRUSTED_BWRAP),
                "version": "bubblewrap 0.9.0 fixture" if bubblewrap else None,
                "reason": None if bubblewrap else "fixture bubblewrap unavailable",
            },
            "system_tools": {
                "qemu": {
                    "trusted": True,
                    "path": str(wuci_lab.TRUSTED_QEMU),
                    "expected_path": str(wuci_lab.TRUSTED_QEMU),
                    "reason": None,
                },
                "qemu_img": {
                    "trusted": True,
                    "path": str(wuci_lab.TRUSTED_QEMU_IMG),
                    "expected_path": str(wuci_lab.TRUSTED_QEMU_IMG),
                    "reason": None,
                },
            },
            "non_root_user": non_root,
            "probe_error": None,
        }


@contextlib.contextmanager
def fixture() -> Any:
    value = LabFixture()
    try:
        yield value
    finally:
        value.close()


@contextlib.contextmanager
def trust_fixture_hostile_tools(value: LabFixture) -> Any:
    expected_paths = {
        wuci_lab.TRUSTED_QEMU: value.qemu,
        wuci_lab.TRUSTED_QEMU_IMG: value.qemu_img,
        wuci_lab.TRUSTED_MKE2FS: value.mke2fs,
        wuci_lab.TRUSTED_DEBUGFS: value.debugfs,
    }

    def trusted(
        candidate: str | os.PathLike[str],
        expected: Path,
        label: str,
    ) -> Path:
        path = wuci_lab.absolute_path(candidate, label)
        if expected in {
            wuci_lab.TRUSTED_MKE2FS,
            wuci_lab.TRUSTED_DEBUGFS,
        } and path == expected:
            return expected_paths[expected]
        if expected not in expected_paths or path != expected_paths[expected]:
            raise wuci_lab.LabError(
                f"fixture refused unexpected trusted-tool request: {path}"
            )
        return path

    with mock.patch.object(
        wuci_lab,
        "_trusted_system_executable",
        side_effect=trusted,
    ):
        yield


def make_overlay(value: LabFixture, name: str = "workbench") -> dict[str, Any]:
    return wuci_lab.create_overlay(
        state_root=value.state,
        name=name,
        base_image=value.base,
        base_sha256=sha256(value.base),
        qemu_img=str(value.qemu_img),
    )


def test_names_and_paths_reject_traversal_and_ambiguity() -> None:
    assert wuci_lab.validate_overlay_name("lab-01") == "lab-01"
    for name in (
        "",
        ".",
        "..",
        "../lab",
        "lab/other",
        "/absolute",
        "Lab",
        "-lab",
        "lab_1",
        "a" * 49,
    ):
        assert_raises(wuci_lab.LabError, wuci_lab.validate_overlay_name, name)
    for path in (
        "../escape",
        "./member",
        "nested//member",
        "/tmp/../escape",
        "/tmp/a,b",
        "/tmp/a\\b",
        "//tmp/member",
        "bad\nmember",
    ):
        assert_raises(wuci_lab.LabError, wuci_lab.absolute_path, path, "fixture")


def test_bound_files_reject_symlinks_hardlinks_and_digest_mismatch() -> None:
    with fixture() as value:
        digest = sha256(value.kernel)
        accepted = wuci_lab.validate_bound_file(
            value.kernel,
            digest,
            "kernel",
            max_bytes=wuci_lab.MAX_KERNEL_BYTES,
        )
        assert accepted.sha256 == digest

        symlink = value.root / "kernel-link"
        symlink.symlink_to(value.kernel)
        error = assert_raises(
            wuci_lab.LabError,
            wuci_lab.validate_bound_file,
            symlink,
            digest,
            "kernel",
            max_bytes=wuci_lab.MAX_KERNEL_BYTES,
        )
        assert "symlink" in str(error)

        hardlink = value.root / "kernel-hardlink"
        os.link(value.kernel, hardlink)
        error = assert_raises(
            wuci_lab.LabError,
            wuci_lab.validate_bound_file,
            value.kernel,
            digest,
            "kernel",
            max_bytes=wuci_lab.MAX_KERNEL_BYTES,
        )
        assert "hardlink" in str(error)
        hardlink.unlink()

        mismatch = assert_raises(
            wuci_lab.LabError,
            wuci_lab.validate_bound_file,
            value.kernel,
            "0" * 64,
            "kernel",
            max_bytes=wuci_lab.MAX_KERNEL_BYTES,
        )
        assert "digest mismatch" in str(mismatch)
        assert_raises(
            wuci_lab.LabError,
            wuci_lab.validate_bound_file,
            value.kernel,
            digest.upper(),
            "kernel",
            max_bytes=wuci_lab.MAX_KERNEL_BYTES,
        )


def test_run_capture_has_combined_byte_cap_and_text_contract() -> None:
    newline_code = (
        "import os; "
        "os.write(1, b'out\\r\\nline\\r'); "
        "os.write(2, b'failure\\r\\nnext\\r'); "
        "raise SystemExit(7)"
    )
    command = [sys.executable, "-c", newline_code]
    result = wuci_lab._run_capture(command, timeout=5, allow_failure=True)
    assert result.args == command
    assert result.returncode == 7
    assert result.stdout == "out\nline\n"
    assert result.stderr == "failure\nnext\n"
    nonzero = assert_raises(
        wuci_lab.LabError,
        wuci_lab._run_capture,
        command,
        timeout=5,
    )
    assert "command exited 7" in str(nonzero)
    assert "failure" in str(nonzero)

    exact_code = (
        "import os; "
        "os.write(1, b'a' * 512); "
        "os.write(2, b'b' * 512)"
    )
    overflow_code = (
        "import os; "
        "os.write(1, b'a' * 512); "
        "os.write(2, b'b' * 513)"
    )
    with mock.patch.object(wuci_lab, "MAX_TOOL_OUTPUT_BYTES", 1024):
        exact = wuci_lab._run_capture(
            [sys.executable, "-c", exact_code],
            timeout=5,
        )
        assert len(exact.stdout.encode("utf-8")) == 512
        assert len(exact.stderr.encode("utf-8")) == 512
        overflow = assert_raises(
            wuci_lab.LabError,
            wuci_lab._run_capture,
            [sys.executable, "-c", overflow_code],
            timeout=5,
        )
    assert "combined stdout/stderr exceeds" in str(overflow)
    assert "1024-byte safety limit" in str(overflow)

    invalid_utf8 = assert_raises(
        wuci_lab.LabError,
        wuci_lab._run_capture,
        [sys.executable, "-c", "import os; os.write(1, b'\\xff')"],
        timeout=5,
    )
    assert "not valid UTF-8" in str(invalid_utf8)


def test_run_capture_timeout_kills_process_group_and_reaps_child() -> None:
    with fixture() as value:
        pid_file = value.root / "capture-pids.txt"
        escaped_marker = value.root / "capture-descendant-escaped.txt"
        child_code = (
            "import pathlib,sys,time; "
            "time.sleep(0.5); "
            "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
        )
        parent_code = (
            "import os,pathlib,subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[3]]); "
            "pathlib.Path(sys.argv[1]).write_text("
            "f'{os.getpid()} {child.pid}', encoding='utf-8'); "
            "time.sleep(60)"
        )
        started = time.monotonic()
        timeout_error = assert_raises(
            wuci_lab.LabError,
            wuci_lab._run_capture,
            [
                sys.executable,
                "-c",
                parent_code,
                str(pid_file),
                child_code,
                str(escaped_marker),
            ],
            timeout=0.15,
        )
        elapsed = time.monotonic() - started
        assert "timed out" in str(timeout_error)
        assert elapsed < 3
        parent_pid, child_pid = (
            int(item) for item in pid_file.read_text(encoding="utf-8").split()
        )
        assert_raises(ChildProcessError, os.waitpid, parent_pid, os.WNOHANG)
        time.sleep(0.7)
        assert not escaped_marker.exists()
        child_status = Path(f"/proc/{child_pid}/stat")
        if child_status.exists():
            fields = child_status.read_text(encoding="utf-8").split()
            assert len(fields) >= 3 and fields[2] == "Z"


def test_run_capture_defers_signal_until_child_publication_and_reaps() -> None:
    previous_mask = wuci_lab.signal.pthread_sigmask(
        wuci_lab.signal.SIG_UNBLOCK,
        wuci_lab.HOSTILE_HANDLED_SIGNALS,
    )
    spawned_pid: int | None = None
    real_popen = subprocess.Popen
    interrupted_command = [
        sys.executable,
        "-c",
        "import time; time.sleep(60)",
    ]

    def signal_after_spawn(
        argv: list[str], *positional: Any, **keywords: Any
    ) -> subprocess.Popen[bytes]:
        nonlocal spawned_pid
        assert argv == interrupted_command
        assert positional == ()
        assert keywords["shell"] is False
        process = real_popen(argv, *positional, **keywords)
        spawned_pid = process.pid
        os.kill(os.getpid(), wuci_lab.signal.SIGTERM)
        return process

    def run_interrupted_capture() -> None:
        with wuci_lab._hostile_launch_cleanup_boundary():
            wuci_lab._run_capture(
                interrupted_command,
                timeout=10,
            )

    try:
        mask_probe = wuci_lab._run_capture(
            [
                sys.executable,
                "-c",
                (
                    "import signal; "
                    "print(int(signal.SIGTERM in "
                    "signal.pthread_sigmask(signal.SIG_BLOCK, ())))"
                ),
            ],
            timeout=5,
        )
        assert mask_probe.stdout == "0\n"

        with mock.patch.object(
            wuci_lab.subprocess,
            "Popen",
            side_effect=signal_after_spawn,
        ):
            error = assert_raises(
                wuci_lab.LabError,
                run_interrupted_capture,
            )
        assert str(error) == "hostile launch interrupted by handled SIGTERM"
        assert spawned_pid is not None
        assert not wuci_lab._hostile_console_process_group_exists(spawned_pid)
        assert_raises(ChildProcessError, os.waitpid, spawned_pid, os.WNOHANG)
    finally:
        if spawned_pid is not None:
            try:
                os.killpg(spawned_pid, wuci_lab.signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(spawned_pid, 0)
            except ChildProcessError:
                pass
        wuci_lab.signal.pthread_sigmask(
            wuci_lab.signal.SIG_SETMASK,
            previous_mask,
        )


def test_probe_host_rejects_untrusted_qemu_before_any_execution() -> None:
    unavailable_bwrap = {
        "available": False,
        "trusted": False,
        "path": str(wuci_lab.TRUSTED_BWRAP),
        "version": None,
        "reason": "fixture unavailable",
    }

    def rejected_report(
        *,
        resolved: Path,
        info: mock.Mock | None = None,
    ) -> dict[str, Any]:
        patches = [
            mock.patch.object(wuci_lab, "_find_executable", return_value=resolved),
            mock.patch.object(
                wuci_lab,
                "probe_bwrap",
                return_value=unavailable_bwrap,
            ),
            mock.patch.object(
                wuci_lab,
                "_kvm_device_status",
                return_value=trusted_kvm_status(),
            ),
            mock.patch.object(wuci_lab, "_run_capture"),
        ]
        if info is not None:
            patches.append(
                mock.patch.object(wuci_lab, "_regular_lstat", return_value=info)
            )
        with contextlib.ExitStack() as stack:
            active = [stack.enter_context(patch) for patch in patches]
            report = wuci_lab.probe_host(str(resolved))
        active[3].assert_not_called()
        assert report["qemu_available"] is False
        assert report["qemu_path"] == str(resolved)
        assert report["system_tools"]["qemu"]["trusted"] is False
        return report

    with fixture() as value:
        non_exact = rejected_report(resolved=value.qemu)
    assert f"must be exact {wuci_lab.TRUSTED_QEMU}" in non_exact["probe_error"]

    user_owned = rejected_report(
        resolved=wuci_lab.TRUSTED_QEMU,
        info=mock.Mock(st_uid=1000, st_mode=stat.S_IFREG | 0o755),
    )
    assert "must be root-owned" in user_owned["probe_error"]

    setid = rejected_report(
        resolved=wuci_lab.TRUSTED_QEMU,
        info=mock.Mock(st_uid=0, st_mode=stat.S_IFREG | 0o4755),
    )
    assert "must not be setuid or setgid" in setid["probe_error"]


def test_probe_host_executes_only_after_exact_qemu_trust_is_established() -> None:
    commands: list[list[str]] = []

    def capture(
        argv: list[str],
        *,
        timeout: float,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        del timeout, allow_failure
        commands.append(argv)
        arguments = argv[1:]
        if arguments == ["--version"] or arguments == [
            "-sandbox",
            wuci_lab.QEMU_SANDBOX,
            "--version",
        ]:
            output = "QEMU emulator version fixture\n"
        elif arguments == ["-machine", "help"]:
            output = "q35  Standard PC fixture\n"
        elif arguments == ["-accel", "help"]:
            output = "kvm\ntcg\n"
        elif arguments == ["--help"]:
            output = "-sandbox on|off\n"
        else:
            raise AssertionError(f"unexpected QEMU probe: {argv}")
        return subprocess.CompletedProcess(argv, 0, output, "")

    trusted_info = mock.Mock(st_uid=0, st_mode=stat.S_IFREG | 0o755)
    with (
        mock.patch.object(
            wuci_lab,
            "_find_executable",
            return_value=wuci_lab.TRUSTED_QEMU,
        ),
        mock.patch.object(wuci_lab, "_regular_lstat", return_value=trusted_info),
        mock.patch.object(wuci_lab, "_run_capture", side_effect=capture),
        mock.patch.object(
            wuci_lab,
            "probe_bwrap",
            return_value={
                "available": False,
                "trusted": False,
                "path": str(wuci_lab.TRUSTED_BWRAP),
                "version": None,
                "reason": "fixture unavailable",
            },
        ),
        mock.patch.object(
            wuci_lab,
            "_kvm_device_status",
            return_value=trusted_kvm_status(),
        ),
        mock.patch.object(wuci_lab.os, "access", return_value=True),
    ):
        report = wuci_lab.probe_host()
    assert report["qemu_available"] is True
    assert report["qemu_path"] == str(wuci_lab.TRUSTED_QEMU)
    assert report["system_tools"]["qemu"]["trusted"] is True
    assert len(commands) == 5
    assert all(command[0] == str(wuci_lab.TRUSTED_QEMU) for command in commands)


def test_symlinked_state_root_and_loose_permissions_are_rejected() -> None:
    with fixture() as value:
        real = value.root / "real-state"
        real.mkdir(mode=0o700)
        link = value.root / "state-link"
        link.symlink_to(real, target_is_directory=True)
        assert_raises(wuci_lab.LabError, wuci_lab.ensure_state_root, link)

        loose = value.root / "loose-state"
        loose.mkdir(mode=0o755)
        error = assert_raises(wuci_lab.LabError, wuci_lab.ensure_state_root, loose)
        assert "0700" in str(error)

        outside = Path(tempfile.gettempdir()) / "wuci-lab-outside"
        assert_raises(wuci_lab.LabError, wuci_lab.ensure_state_root, outside)


def test_overlay_create_inspect_and_collision_fail_closed() -> None:
    with fixture() as value:
        original_digest = sha256(value.base)
        created = make_overlay(value)
        assert created["status"] == "valid"
        assert created["manifest"]["base_image"]["sha256"] == original_digest
        assert created["boundary"]["guest_writes_persist"] is True
        assert created["boundary"]["base_image_mutated"] is False
        assert sha256(value.base) == original_digest
        image = Path(created["image"]["path"])
        manifest = image.with_suffix(".json")
        assert stat.S_IMODE(image.lstat().st_mode) == 0o600
        assert stat.S_IMODE(manifest.lstat().st_mode) == 0o600
        assert image.lstat().st_nlink == 1
        assert manifest.lstat().st_nlink == 1

        inspected = wuci_lab.inspect_overlay(
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=original_digest,
            qemu_img=str(value.qemu_img),
        )
        assert inspected["image"]["format"] == "qcow2"
        collision = assert_raises(
            wuci_lab.LabError,
            make_overlay,
            value,
        )
        assert "collision" in str(collision)


def test_overlay_create_rolls_back_both_committed_files_and_can_retry() -> None:
    with fixture() as value:
        observed_commit: dict[str, Path] = {}

        def fail_after_manifest(*args: Any, **kwargs: Any) -> Any:
            state = kwargs["state"]
            paths = wuci_lab.overlay_paths(state, kwargs["name"])
            assert paths["image"].is_file()
            assert paths["manifest"].is_file()
            observed_commit.update(
                {"image": paths["image"], "manifest": paths["manifest"]}
            )
            raise wuci_lab.LabError("fixture post-manifest inspection failure")

        with mock.patch.object(
            wuci_lab,
            "_inspect_overlay_unlocked",
            side_effect=fail_after_manifest,
        ):
            error = assert_raises(wuci_lab.LabError, make_overlay, value)
        assert "post-manifest inspection failure" in str(error)
        assert observed_commit
        assert not observed_commit["image"].exists()
        assert not observed_commit["manifest"].exists()
        overlay_directory = value.state / "overlays"
        assert list(overlay_directory.iterdir()) == []

        retry = make_overlay(value)
        assert retry["status"] == "valid"
        assert Path(retry["image"]["path"]).is_file()
        assert Path(retry["image"]["path"]).with_suffix(".json").is_file()


def test_overlay_rejects_hardlinks_symlinks_and_manifest_drift() -> None:
    with fixture() as value:
        created = make_overlay(value)
        image = Path(created["image"]["path"])
        manifest = image.with_suffix(".json")
        extra = value.root / "extra-overlay-link"
        os.link(image, extra)
        error = assert_raises(
            wuci_lab.LabError,
            wuci_lab.inspect_overlay,
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=sha256(value.base),
            qemu_img=str(value.qemu_img),
        )
        assert "hardlink" in str(error)
        extra.unlink()

        saved = image.with_suffix(".saved")
        image.rename(saved)
        image.symlink_to(saved)
        error = assert_raises(
            wuci_lab.LabError,
            wuci_lab.inspect_overlay,
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=sha256(value.base),
            qemu_img=str(value.qemu_img),
        )
        assert "symlink" in str(error)
        image.unlink()
        saved.rename(image)

        record = json.loads(manifest.read_text(encoding="utf-8"))
        record["base_image"]["sha256"] = "0" * 64
        manifest.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest.chmod(0o600)
        error = assert_raises(
            wuci_lab.LabError,
            wuci_lab.inspect_overlay,
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=sha256(value.base),
            qemu_img=str(value.qemu_img),
        )
        assert "base-image" in str(error)


def test_overlay_lock_rejects_concurrent_supervisors() -> None:
    with fixture() as value:
        make_overlay(value)
        with wuci_lab.overlay_lock(value.state, "workbench"):
            error = assert_raises(
                wuci_lab.LabError,
                wuci_lab.inspect_overlay,
                state_root=value.state,
                name="workbench",
                base_image=value.base,
                base_sha256=sha256(value.base),
                qemu_img=str(value.qemu_img),
            )
        assert "busy" in str(error)


def test_overlay_remove_and_reset_are_exact_confirmed_and_base_bound() -> None:
    with fixture() as value:
        created = make_overlay(value)
        image = Path(created["image"]["path"])
        manifest = image.with_suffix(".json")
        sentinel = image.parent / "operator-note.txt"
        sentinel.write_text("preserve me\n", encoding="utf-8")
        sentinel.chmod(0o600)
        digest = sha256(value.base)
        remove_confirmation = wuci_lab.overlay_confirmation(
            "remove", "workbench", digest
        )
        reset_confirmation = wuci_lab.overlay_confirmation(
            "reset", "workbench", digest
        )

        wrong_confirmation = assert_raises(
            wuci_lab.LabError,
            wuci_lab.remove_overlay,
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=digest,
            confirmation="remove:workbench:" + "0" * 64,
            qemu_img=str(value.qemu_img),
        )
        assert "destructive" in str(wrong_confirmation)
        assert image.is_file() and manifest.is_file() and sentinel.is_file()

        alternate_base = value._write("alternate-base.ext4", value.base.read_bytes())
        base_mismatch = assert_raises(
            wuci_lab.LabError,
            wuci_lab.remove_overlay,
            state_root=value.state,
            name="workbench",
            base_image=alternate_base,
            base_sha256=digest,
            confirmation=remove_confirmation,
            qemu_img=str(value.qemu_img),
        )
        assert "base-image" in str(base_mismatch)
        assert image.is_file() and manifest.is_file() and sentinel.is_file()

        reset = wuci_lab.reset_overlay(
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=digest,
            confirmation=reset_confirmation,
            qemu_img=str(value.qemu_img),
        )
        assert reset["schema"] == wuci_lab.OVERLAY_RESET_SCHEMA
        assert reset["status"] == "reset"
        assert reset["removed"]["status"] == "removed"
        assert reset["overlay"]["status"] == "valid"
        assert manifest.is_file() and sentinel.read_text(encoding="utf-8") == "preserve me\n"

        removed = wuci_lab.remove_overlay(
            state_root=value.state,
            name="workbench",
            base_image=value.base,
            base_sha256=digest,
            confirmation=remove_confirmation,
            qemu_img=str(value.qemu_img),
        )
        assert removed["schema"] == wuci_lab.OVERLAY_REMOVAL_SCHEMA
        assert removed["removed_paths"] == [str(image), str(manifest)]
        assert not image.exists() and not manifest.exists()
        assert sentinel.read_text(encoding="utf-8") == "preserve me\n"

        make_overlay(value)
        with mock.patch.object(
            wuci_lab,
            "_create_overlay_unlocked",
            side_effect=wuci_lab.LabError("fixture fresh-create failure"),
        ):
            reset_error = assert_raises(
                wuci_lab.LabError,
                wuci_lab.reset_overlay,
                state_root=value.state,
                name="workbench",
                base_image=value.base,
                base_sha256=digest,
                confirmation=reset_confirmation,
                qemu_img=str(value.qemu_img),
            )
        assert "removed the old persistent state" in str(reset_error)
        assert not image.exists() and not manifest.exists()
        assert sentinel.is_file()

        make_overlay(value)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli_result = wuci_lab.main(
                [
                    "overlay",
                    "remove",
                    "workbench",
                    "--base-image",
                    str(value.base),
                    "--base-sha256",
                    digest,
                    "--state-root",
                    str(value.state),
                    "--qemu-img",
                    str(value.qemu_img),
                    "--confirm",
                    remove_confirmation,
                ]
            )
        assert cli_result == 0
        assert json.loads(output.getvalue())["status"] == "removed"
        assert not image.exists() and not manifest.exists()
        assert sentinel.is_file()


def test_volatile_and_persistent_root_disks_are_distinct() -> None:
    with fixture() as value:
        args = value.boot_args()
        volatile = wuci_lab.launch_plan(
            **args,
            capabilities=value.capabilities(kvm=False),
        )
        assert volatile["storage"]["mode"] == "volatile"
        assert volatile["storage"]["root_disk"] is None
        assert volatile["storage"]["root_format"] == "qcow2"
        assert volatile["storage"]["qemu_temporary_snapshot"] is False
        assert volatile["storage"]["explicit_private_volatile_overlay"] is True
        assert volatile["storage"]["volatile_overlay_deferred_until_real_launch"] is True
        assert (
            volatile["storage"]["volatile_overlay_cleanup_on_supervisor_unwind"]
            is True
        )
        assert (
            volatile["storage"][
                "volatile_overlay_cleanup_after_sigkill_or_host_crash"
            ]
            is False
        )
        assert volatile["storage"]["guest_writes_persist"] is False
        assert volatile["argv_materialized"] is False
        assert "-snapshot" not in volatile["argv"]
        drive = volatile["argv"][volatile["argv"].index("-drive") + 1]
        assert "format=qcow2" in drive
        assert wuci_lab.DEFERRED_VOLATILE_ROOT in drive
        assert "snapshot=on" not in drive

        make_overlay(value, "persistent-lab")
        persistent = wuci_lab.launch_plan(
            **args,
            storage="persistent",
            overlay="persistent-lab",
            capabilities=value.capabilities(kvm=True),
        )
        assert persistent["storage"]["mode"] == "persistent"
        assert persistent["storage"]["root_disk"].endswith(
            "/overlays/persistent-lab.qcow2"
        )
        assert persistent["storage"]["root_disk"] != str(value.base)
        assert persistent["storage"]["root_format"] == "qcow2"
        assert persistent["argv_materialized"] is True
        assert persistent["storage"]["guest_writes_persist"] is True
        drive = persistent["argv"][persistent["argv"].index("-drive") + 1]
        assert "format=qcow2" in drive
        assert "snapshot=on" not in drive
        assert "-snapshot" not in persistent["argv"]


def test_volatile_cleanup_rejects_a_same_uid_hardlink_fail_closed() -> None:
    with fixture() as value:
        base = wuci_lab.validate_bound_file(
            value.base,
            sha256(value.base),
            "fixture base image",
            max_bytes=wuci_lab.MAX_BASE_BYTES,
        )
        overlay_path: Path | None = None
        retained_path: Path | None = None

        def add_hardlink_during_use() -> None:
            nonlocal overlay_path, retained_path
            with wuci_lab.private_volatile_overlay(
                state_root=value.state,
                base=base,
                qemu_img_path=value.qemu_img,
            ) as overlay:
                overlay_path = Path(overlay["path"])
                retained_path = overlay_path.with_name("retained-hardlink.qcow2")
                os.link(overlay_path, retained_path, follow_symlinks=False)
                assert overlay_path.stat().st_nlink == 2

        error = assert_raises(
            wuci_lab.LabError,
            add_hardlink_during_use,
        )
        assert "must remain a single-link regular file" in str(error)
        assert overlay_path is not None and overlay_path.is_file()
        assert retained_path is not None and retained_path.is_file()
        assert overlay_path.samefile(retained_path)
        assert overlay_path.stat().st_nlink == 2

        retained_path.unlink()
        overlay_path.unlink()


def test_network_matrix_is_explicit_and_hostile_is_offline() -> None:
    with fixture() as value:
        args = value.boot_args()
        offline = wuci_lab.launch_plan(
            **args,
            capabilities=value.capabilities(kvm=False),
        )
        nic_index = offline["argv"].index("-nic")
        assert offline["argv"][nic_index + 1] == "none"
        assert (
            offline["argv"][offline["argv"].index("-cpu") + 1]
            == wuci_lab.TCG_CPU_MODEL
        )
        assert "max" not in offline["argv"]
        assert offline["network"]["guest_internet_enabled"] is False

        internet = wuci_lab.launch_plan(
            **args,
            profile="analysis",
            network="internet",
            capabilities=value.capabilities(kvm=False),
        )
        netdev = internet["argv"][internet["argv"].index("-netdev") + 1]
        assert netdev == wuci_lab.QEMU_USER_NETDEV
        assert netdev == (
            "user,id=wuci-net,restrict=off,ipv6=off,"
            "net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,"
            "dhcpstart=10.0.2.15"
        )
        assert "hostfwd" not in netdev
        assert internet["network"]["guest_internet_enabled"] is True
        assert internet["network"]["inbound_host_forwarding"] is False
        assert (
            internet["argv"][internet["argv"].index("-cpu") + 1]
            == wuci_lab.TCG_CPU_MODEL
        )

        error = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            network="internet",
            capabilities=value.capabilities(kvm=True),
        )
        assert "forbids internet" in str(error)


def test_hostile_requires_kvm_non_root_and_volatile_storage() -> None:
    with fixture() as value:
        args = value.boot_args()
        missing_kvm = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            capabilities=value.capabilities(kvm=False),
        )
        assert "hostile mode refused" in str(missing_kvm)
        assert "KVM" in str(missing_kvm)

        root_refusal = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            capabilities=value.capabilities(kvm=True, non_root=False),
        )
        assert "refuses to run as root" in str(root_refusal)

        persistent = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            storage="persistent",
            overlay="hostile-state",
            capabilities=value.capabilities(kvm=True),
        )
        assert "forbids persistent storage" in str(persistent)

        untrusted = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            capabilities=value.capabilities(kvm=True),
        )
        assert "must be exact /usr/bin/qemu-system-x86_64" in str(untrusted)

        with trust_fixture_hostile_tools(value):
            accepted = wuci_lab.launch_plan(
                **args,
                profile="hostile",
                capabilities=value.capabilities(kvm=True),
            )
        assert accepted["acceleration"]["selected"] == "kvm"
        assert accepted["acceleration"]["tcg_fallback"] is False
        assert (
            accepted["argv"][accepted["argv"].index("-cpu") + 1]
            == "host"
        )
        assert accepted["network"]["mode"] == "none"
        assert accepted["storage"]["mode"] == "volatile"


def test_hostile_requires_trusted_exact_bubblewrap() -> None:
    with fixture() as value:
        args = value.boot_args()
        missing = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            capabilities=value.capabilities(kvm=True, bubblewrap=False),
        )
        assert "trusted exact /usr/bin/bwrap" in str(missing)

        wrong_path = value.capabilities(kvm=True)
        wrong_path["bubblewrap"]["path"] = str(value.root / "bwrap")
        rejected = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **args,
            profile="hostile",
            capabilities=wrong_path,
        )
        assert "trusted exact /usr/bin/bwrap" in str(rejected)


def test_trusted_bubblewrap_rejects_setuid_and_setgid_modes() -> None:
    for setid_bit in (stat.S_ISUID, stat.S_ISGID):
        info = mock.Mock(
            st_uid=0,
            st_mode=stat.S_IFREG | 0o755 | setid_bit,
        )
        with mock.patch.object(wuci_lab, "_regular_lstat", return_value=info):
            rejected = assert_raises(wuci_lab.LabError, wuci_lab._trusted_bwrap)
        assert "without setuid/setgid bits" in str(rejected)


def test_kvm_device_status_requires_exact_identity_permissions_and_access() -> None:
    def probe(
        *,
        path: str = "/dev/kvm",
        uid: int = 0,
        permissions: int = 0o660,
        device_major: int = 10,
        device_minor: int = 232,
        readable: bool = True,
        writable: bool = True,
        euid: int = 1000,
    ) -> dict[str, Any]:
        info = mock.Mock(
            st_mode=stat.S_IFCHR | permissions,
            st_uid=uid,
            st_gid=993,
            st_rdev=os.makedev(device_major, device_minor),
        )

        def access(
            candidate: Path,
            access_mode: int,
            *,
            effective_ids: bool = False,
        ) -> bool:
            assert candidate == Path(path)
            assert effective_ids is True
            if access_mode == os.R_OK:
                return readable
            if access_mode == os.W_OK:
                return writable
            raise AssertionError(f"unexpected access mode: {access_mode}")

        with (
            mock.patch.object(wuci_lab, "reject_symlink_components"),
            mock.patch.object(wuci_lab.os, "lstat", return_value=info),
            mock.patch.object(wuci_lab.os, "access", side_effect=access),
            mock.patch.object(wuci_lab.os, "geteuid", return_value=euid),
        ):
            return wuci_lab._kvm_device_status(path)

    valid = probe()
    assert valid == trusted_kvm_status()
    assert wuci_lab._trusted_kvm_device_record(valid) is True

    failures = (
        (probe(path="/dev/not-kvm"), "path is not exact /dev/kvm"),
        (probe(device_major=1), "device number is 1:232, expected 10:232"),
        (probe(device_minor=231), "device number is 10:231, expected 10:232"),
        (probe(uid=1000), "not root-owned"),
        (probe(permissions=0o664), "world-readable"),
        (probe(permissions=0o662), "world-writable"),
        (probe(readable=False), "not readable by the current unprivileged user"),
        (probe(writable=False), "not writable by the current unprivileged user"),
        (probe(euid=0), "current user is root"),
    )
    for status, expected_reason in failures:
        assert status["trusted"] is False
        assert wuci_lab._trusted_kvm_device_record(status) is False
        assert expected_reason in status["reason"]


def test_hostile_plan_rejects_untrusted_kvm_identity_or_world_access() -> None:
    with fixture() as value:
        mutations = (
            ("device_major", 1),
            ("device_minor", 231),
            ("owner_uid", 1000),
            ("world_readable", True),
            ("world_writable", True),
        )
        with trust_fixture_hostile_tools(value):
            for field, replacement in mutations:
                capabilities = value.capabilities(kvm=True)
                capabilities["kvm_device"][field] = replacement
                rejected = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab.launch_plan,
                    **value.boot_args(),
                    profile="hostile",
                    capabilities=capabilities,
                )
                assert "trusted exact root-owned /dev/kvm" in str(rejected)

            accepted = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                capabilities=value.capabilities(kvm=True),
            )
        assert accepted["acceleration"]["selected"] == "kvm"


def test_hostile_requires_exact_root_owned_system_qemu_tools() -> None:
    with fixture() as value:
        for candidate, expected, label in (
            (value.qemu, wuci_lab.TRUSTED_QEMU, "hostile QEMU"),
            (value.qemu_img, wuci_lab.TRUSTED_QEMU_IMG, "hostile qemu-img"),
        ):
            wrong_path = assert_raises(
                wuci_lab.LabError,
                wuci_lab._trusted_system_executable,
                candidate,
                expected,
                label,
            )
            assert f"must be exact {expected}" in str(wrong_path)
            untrusted_owner = assert_raises(
                wuci_lab.LabError,
                wuci_lab._trusted_system_executable,
                candidate,
                candidate,
                label,
            )
            assert "must be root-owned" in str(untrusted_owner)
            candidate.chmod(0o722)
            writable = assert_raises(
                wuci_lab.LabError,
                wuci_lab._trusted_system_executable,
                candidate,
                candidate,
                label,
            )
            assert "must not be group/world writable" in str(writable)
            candidate.chmod(0o700)

        capabilities = value.capabilities(kvm=True)
        capabilities["system_tools"]["qemu_img"]["trusted"] = False
        capabilities["system_tools"]["qemu_img"]["reason"] = (
            "fixture qemu-img is not trusted"
        )
        refusal = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **value.boot_args(),
            profile="hostile",
            capabilities=capabilities,
        )
        assert f"trusted exact {wuci_lab.TRUSTED_QEMU_IMG}" in str(refusal)


def test_hostile_payload_plan_is_bounded_deferred_and_read_only() -> None:
    with fixture() as value:
        payload = value._write("sample.bin", b"bounded hostile fixture\n")
        payload_digest = sha256(payload)
        with trust_fixture_hostile_tools(value):
            with mock.patch.object(
                wuci_lab,
                "_run_capture",
                return_value=subprocess.CompletedProcess(
                    [str(value.mke2fs), "-V"],
                    0,
                    "",
                    "mke2fs 1.46.0 fixture\n",
                ),
            ):
                version_error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._trusted_mke2fs,
                    wuci_lab.TRUSTED_MKE2FS,
                    "fixture mke2fs",
                )
        assert "exact e2fsprogs version 1.47.0" in str(version_error)
        with trust_fixture_hostile_tools(value):
            with mock.patch.object(
                wuci_lab,
                "_run_capture",
                return_value=subprocess.CompletedProcess(
                    [str(value.debugfs), "-V"],
                    0,
                    "",
                    "debugfs 1.46.0 fixture\n",
                ),
            ):
                debugfs_version_error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._trusted_debugfs,
                    wuci_lab.TRUSTED_DEBUGFS,
                    "fixture debugfs",
                )
        assert "exact e2fsprogs version 1.47.0" in str(
            debugfs_version_error
        )
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=payload_digest,
                capabilities=value.capabilities(kvm=True),
            )
        assert plan["payload_ingress"]["source"]["sha256"] == payload_digest
        assert plan["payload_ingress"]["media"] is None
        assert plan["payload_ingress"]["guest_device"] == "/dev/vdb"
        assert plan["payload_ingress"]["guest_read_only"] is True
        assert plan["payload_ingress"]["host_source_shared"] is False
        assert plan["supervisor"]["mke2fs_path"] == str(value.mke2fs)
        assert plan["supervisor"]["mke2fs_version"] == "1.47.0"
        assert plan["supervisor"]["debugfs_path"] == str(value.debugfs)
        assert plan["supervisor"]["debugfs_version"] == "1.47.0"
        assert str(payload) not in plan["argv"]
        assert plan["argv"].count(wuci_lab.DEFERRED_HOSTILE_PAYLOAD) == 1
        assert wuci_lab.DEFERRED_HOSTILE_PAYLOAD not in plan["qemu_argv"]
        payload_drives = [
            plan["qemu_argv"][index + 1]
            for index, item in enumerate(plan["qemu_argv"])
            if item == "-drive" and "wuci-payload" in plan["qemu_argv"][index + 1]
        ]
        assert payload_drives == [
            f"file={wuci_lab.HOSTILE_PAYLOAD_GUEST_MEDIA},if=none,"
            "id=wuci-payload,format=raw,readonly=on,cache=writeback,aio=threads"
        ]
        assert not value.state.exists()

        cli = [
            "launch",
            "--kernel",
            str(value.kernel),
            "--kernel-sha256",
            sha256(value.kernel),
            "--initrd",
            str(value.initrd),
            "--initrd-sha256",
            sha256(value.initrd),
            "--base-image",
            str(value.base),
            "--base-sha256",
            sha256(value.base),
            "--state-root",
            str(value.state),
            "--profile",
            "hostile",
            "--accel",
            "kvm",
            "--qemu",
            str(value.qemu),
            "--qemu-img",
            str(value.qemu_img),
            "--hostile-payload",
            str(payload),
            "--hostile-payload-sha256",
            payload_digest,
            "--dry-run",
        ]
        output = io.StringIO()
        with trust_fixture_hostile_tools(value):
            with (
                contextlib.redirect_stdout(output),
                mock.patch.object(
                    wuci_lab,
                    "probe_host",
                    return_value=value.capabilities(kvm=True),
                ),
            ):
                assert wuci_lab.main(cli) == 0
        cli_plan = json.loads(output.getvalue())
        assert cli_plan["payload_ingress"]["source"]["sha256"] == payload_digest
        assert cli_plan["argv_materialized"] is False
        assert not value.state.exists()

        for changes, fragment in (
            ({"profile": "analysis"}, "restricted to the hostile profile"),
            ({"network": "internet"}, "forbids internet"),
            ({"storage": "persistent", "overlay": "workbench"}, "forbids persistent"),
            ({"acceleration": "tcg"}, "forbids TCG"),
        ):
            arguments = {
                **value.boot_args(),
                "profile": "hostile",
                "hostile_payload": payload,
                "hostile_payload_sha256": payload_digest,
                "capabilities": value.capabilities(kvm=True),
                **changes,
            }
            with trust_fixture_hostile_tools(value):
                error = assert_raises(
                    wuci_lab.LabError, wuci_lab.launch_plan, **arguments
                )
            assert fragment in str(error)

        missing_digest = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **value.boot_args(),
            profile="hostile",
            hostile_payload=payload,
            capabilities=value.capabilities(kvm=True),
        )
        assert "required together" in str(missing_digest)

        extra_link = value.root / "sample-hardlink.bin"
        os.link(payload, extra_link)
        hardlink = assert_raises(
            wuci_lab.LabError,
            wuci_lab.launch_plan,
            **value.boot_args(),
            profile="hostile",
            hostile_payload=payload,
            hostile_payload_sha256=payload_digest,
            capabilities=value.capabilities(kvm=True),
        )
        assert "hardlink" in str(hardlink)


def test_private_hostile_payload_media_binds_manifest_and_cleans_exactly() -> None:
    with fixture() as value:
        payload = value._write("sample.bin", b"payload bytes\x00\xff")
        source = wuci_lab.validate_bound_file(
            payload,
            sha256(payload),
            "fixture hostile payload",
            max_bytes=wuci_lab.MAX_HOSTILE_PAYLOAD_BYTES,
        )
        original = payload.read_bytes()
        with wuci_lab.private_hostile_payload_media(
            state_root=value.state,
            source=source,
            mke2fs_path=value.mke2fs,
            debugfs_path=value.debugfs,
        ) as report:
            media = Path(report["media"]["path"])
            assert media.is_file()
            assert stat.S_IMODE(media.lstat().st_mode) == 0o400
            assert media.lstat().st_nlink == 1
            assert report["source"] == source.public()
            assert report["manifest"]["source"] == {
                "sha256": source.sha256,
                "size": source.size,
            }
            assert report["manifest"]["boundary"] == {
                "host_execution": False,
                "host_source_shared": False,
                "guest_media_read_only": True,
                "network_enabled": False,
                "persistent_storage_enabled": False,
            }
            assert report["media"]["qemu_read_only"] is True
            assert report["media"]["guest_device"] == "/dev/vdb"
            manifest_bytes = wuci_lab.canonical_json(
                report["manifest"]
            ).encode("utf-8")
            assert report["semantic_readback"] == {
                "filesystem": "ext4",
                "debugfs_path": str(value.debugfs),
                "debugfs_version": "1.47.0",
                "payload": {
                    "guest_path": "/payload.bin",
                    "size": source.size,
                    "sha256": source.sha256,
                },
                "manifest": {
                    "guest_path": "/manifest.json",
                    "size": len(manifest_bytes),
                    "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                },
                "exact_guest_file_bytes_verified": True,
            }
            operation = media.parent
            assert (operation / "root" / "payload.bin").read_bytes() == original
            assert stat.S_IMODE(
                (operation / "root" / "payload.bin").lstat().st_mode
            ) == 0o400
        assert payload.read_bytes() == original
        assert list((value.state / "payloads").iterdir()) == []

        value.mke2fs.write_text(
            """#!/usr/bin/python3
import sys
with open(sys.argv[-1], "r+b") as stream:
    stream.seek(0)
    stream.write(b"NOT-AN-EXT4-FILESYSTEM")
raise SystemExit(0)
""",
            encoding="utf-8",
        )
        value.mke2fs.chmod(0o700)

        def accept_corrupt_media() -> None:
            with wuci_lab.private_hostile_payload_media(
                state_root=value.state,
                source=source,
                mke2fs_path=value.mke2fs,
                debugfs_path=value.debugfs,
            ):
                raise AssertionError("non-ext4 media unexpectedly yielded")

        corrupt = assert_raises(
            wuci_lab.LabError,
            accept_corrupt_media,
        )
        assert "debugfs" in str(corrupt)
        assert list((value.state / "payloads").iterdir()) == []

        def build_failed_media() -> None:
            with wuci_lab.private_hostile_payload_media(
                state_root=value.state,
                source=source,
                mke2fs_path=value.mke2fs,
                debugfs_path=value.debugfs,
            ):
                raise AssertionError("fixture mke2fs failure unexpectedly yielded")

        with mock.patch.object(
            wuci_lab,
            "_run_capture",
            side_effect=wuci_lab.LabError("fixture mke2fs failure"),
        ):
            failure = assert_raises(
                wuci_lab.LabError,
                build_failed_media,
            )
        assert "fixture mke2fs failure" in str(failure)
        assert list((value.state / "payloads").iterdir()) == []


def test_hostile_payload_real_launch_uses_one_ro_binding_and_cleans_media() -> None:
    with fixture() as value:
        payload = value._write("sample.bin", b"never execute this fixture\n")
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=sha256(payload),
                capabilities=value.capabilities(kvm=True),
            )
        observed: dict[str, Any] = {}

        def dispatch(
            argv: list[str], *positional: Any, **keywords: Any
        ) -> int:
            separator = argv.index("--")
            qemu_argv = argv[separator + 1 :]
            payload_drive = next(
                qemu_argv[index + 1]
                for index, item in enumerate(qemu_argv)
                if item == "-drive" and "wuci-payload" in qemu_argv[index + 1]
            )
            assert payload_drive.startswith(
                f"file={wuci_lab.HOSTILE_PAYLOAD_GUEST_MEDIA},"
            )
            assert "readonly=on" in payload_drive
            pairs = [
                (argv[index + 1], argv[index + 2])
                for index, item in enumerate(argv)
                if item == "--ro-bind"
            ]
            payload_pairs = [
                pair
                for pair in pairs
                if pair[1] == str(wuci_lab.HOSTILE_PAYLOAD_GUEST_MEDIA)
            ]
            assert len(payload_pairs) == 1
            media = Path(payload_pairs[0][0])
            assert media.is_file()
            assert media.parent.parent == value.state / "payloads"
            assert stat.S_IMODE(media.lstat().st_mode) == 0o400
            assert str(payload) not in argv
            assert wuci_lab.DEFERRED_HOSTILE_PAYLOAD not in argv
            observed.update({"media": media, "argv": argv})
            return 29

        with trust_fixture_hostile_tools(value):
            with (
                mock.patch.object(
                    wuci_lab,
                    "_run_hostile_console_relay",
                    side_effect=dispatch,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_trusted_bwrap",
                    return_value=wuci_lab.TRUSTED_BWRAP,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_kvm_device_status",
                    return_value=trusted_kvm_status(),
                ),
            ):
                result = wuci_lab.run_launch(plan, cwd=value.state)
        assert result == 29
        assert observed
        assert not observed["media"].exists()
        assert list((value.state / "payloads").iterdir()) == []
        assert list((value.state / "volatile").iterdir()) == []

        payload.write_bytes(b"changed after plan creation\n")
        payload.chmod(0o600)
        with trust_fixture_hostile_tools(value):
            with mock.patch.object(
                wuci_lab,
                "_trusted_bwrap",
                return_value=wuci_lab.TRUSTED_BWRAP,
            ):
                drift = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab.run_launch,
                    plan,
                    cwd=value.state,
                )
        assert "digest mismatch" in str(drift)
        assert list((value.state / "payloads").iterdir()) == []


def test_hostile_payload_final_boundary_rereads_media_semantics() -> None:
    with fixture() as value:
        payload = value._write(
            "semantic-boundary-sample.bin",
            b"benign semantic-boundary fixture\n",
        )
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=sha256(payload),
                capabilities=value.capabilities(kvm=True),
            )
        state = wuci_lab.ensure_state_root(value.state)
        source = wuci_lab._validated_plan_payload_source(plan)
        base = wuci_lab._validated_plan_base(plan)
        assert source is not None
        with (
            wuci_lab.private_hostile_payload_media(
                state_root=state,
                source=source,
                mke2fs_path=value.mke2fs,
                debugfs_path=value.debugfs,
            ) as payload_report,
            wuci_lab.private_volatile_overlay(
                state_root=state,
                base=base,
                qemu_img_path=value.qemu_img,
            ) as overlay,
        ):
            materialized = wuci_lab._materialize_volatile_plan(
                plan,
                overlay,
                payload_report,
            )
            media_path = Path(
                materialized["payload_ingress"]["media"]["media"]["path"]
            )
            media_path.chmod(0o600)
            with media_path.open("r+b") as stream:
                stream.seek(1024 + 56)
                stream.write(b"\x00\x00")
                stream.flush()
                os.fsync(stream.fileno())
            media_path.chmod(0o400)
            changed_digest = sha256(media_path)
            materialized["payload_ingress"]["media"]["media"][
                "sha256"
            ] = changed_digest
            with trust_fixture_hostile_tools(value):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._validated_materialized_payload_media,
                    materialized,
                    state,
                )
            assert "debugfs" in str(error)
        assert list((value.state / "payloads").iterdir()) == []
        assert list((value.state / "volatile").iterdir()) == []


def test_hostile_sigterm_during_payload_materialization_reaps_and_cleans() -> None:
    with fixture() as value:
        payload = value._write("signal-sample.bin", b"benign signal fixture\n")
        marker = value.root / "mke2fs-running.pid"
        child_error = value.root / "signal-child-error.txt"
        value.mke2fs.write_text(
            """#!/usr/bin/python3
import os
import sys
import time

if sys.argv[1:] == ["-V"]:
    sys.stderr.write("mke2fs 1.47.0 (5-Feb-2023)\\n")
    sys.stderr.write("\\tUsing EXT2FS Library version 1.47.0\\n")
    raise SystemExit(0)
with open("""
            + repr(str(marker))
            + """, "w", encoding="ascii") as stream:
    stream.write(str(os.getpid()))
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(60)
""",
            encoding="utf-8",
        )
        value.mke2fs.chmod(0o700)
        with (
            trust_fixture_hostile_tools(value),
            mock.patch.object(
                wuci_lab,
                "_trusted_bwrap",
                return_value=wuci_lab.TRUSTED_BWRAP,
            ),
        ):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=sha256(payload),
                capabilities=value.capabilities(kvm=True),
            )
            supervisor_pid = os.fork()
            if supervisor_pid == 0:
                try:
                    error = assert_raises(
                        wuci_lab.LabError,
                        wuci_lab.run_launch,
                        plan,
                        cwd=value.state,
                    )
                    if str(error) != (
                        "hostile launch interrupted by handled SIGTERM"
                    ):
                        child_error.write_text(str(error), encoding="utf-8")
                        os._exit(82)
                    for name in ("payloads", "volatile"):
                        directory = value.state / name
                        if directory.exists() and any(directory.iterdir()):
                            os._exit(83)
                    os._exit(0)
                except BaseException:
                    os._exit(84)

            status: int | None = None
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not marker.exists():
                    waited, status_value = os.waitpid(
                        supervisor_pid, os.WNOHANG
                    )
                    if waited == supervisor_pid:
                        status = status_value
                        break
                    time.sleep(0.02)
                assert marker.exists(), (
                    "fixture mke2fs did not enter its blocking materialization "
                    f"phase (supervisor wait status: {status!r}; "
                    f"error: {child_error.read_text(encoding='utf-8') if child_error.exists() else None!r})"
                )
                os.kill(supervisor_pid, wuci_lab.signal.SIGTERM)
                deadline = time.monotonic() + 10
                while status is None and time.monotonic() < deadline:
                    waited, status_value = os.waitpid(
                        supervisor_pid, os.WNOHANG
                    )
                    if waited == supervisor_pid:
                        status = status_value
                        break
                    time.sleep(0.02)
                assert status is not None, (
                    "hostile supervisor did not finish handled-signal cleanup"
                )
            finally:
                if status is None:
                    try:
                        os.kill(supervisor_pid, wuci_lab.signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.waitpid(supervisor_pid, 0)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 0
        mke2fs_pid = int(marker.read_text(encoding="ascii"))
        assert not Path(f"/proc/{mke2fs_pid}").exists()
        for name in ("payloads", "volatile"):
            directory = value.state / name
            assert not directory.exists() or list(directory.iterdir()) == []


def test_hostile_sigterm_after_transient_materialization_cleans_both() -> None:
    with fixture() as value:
        payload = value._write(
            "materialized-signal-sample.bin",
            b"benign post-materialization signal fixture\n",
        )
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=sha256(payload),
                capabilities=value.capabilities(kvm=True),
            )
        observed: dict[str, Path] = {}

        def interrupt_after_materialization(
            _plan: dict[str, Any],
            overlay: dict[str, Any],
            payload_report: dict[str, Any],
        ) -> dict[str, Any]:
            overlay_path = Path(overlay["path"])
            media_path = Path(payload_report["media"]["path"])
            assert overlay_path.is_file()
            assert media_path.is_file()
            observed.update(overlay=overlay_path, media=media_path)
            handler = wuci_lab.signal.getsignal(wuci_lab.signal.SIGTERM)
            assert callable(handler)
            handler(wuci_lab.signal.SIGTERM, None)
            raise AssertionError("handled SIGTERM returned")

        with (
            trust_fixture_hostile_tools(value),
            mock.patch.object(
                wuci_lab,
                "_trusted_bwrap",
                return_value=wuci_lab.TRUSTED_BWRAP,
            ),
            mock.patch.object(
                wuci_lab,
                "_materialize_volatile_plan",
                side_effect=interrupt_after_materialization,
            ),
        ):
            error = assert_raises(
                wuci_lab.LabError,
                wuci_lab.run_launch,
                plan,
                cwd=value.state,
            )
        assert str(error) == "hostile launch interrupted by handled SIGTERM"
        assert set(observed) == {"overlay", "media"}
        assert not observed["overlay"].exists()
        assert not observed["media"].exists()
        assert list((value.state / "payloads").iterdir()) == []
        assert list((value.state / "volatile").iterdir()) == []


def test_hostile_allocation_return_signals_leave_no_untracked_state() -> None:
    with fixture() as value:
        payload = value._write(
            "allocation-signal-sample.bin",
            b"benign allocation-window fixture\n",
        )
        with trust_fixture_hostile_tools(value):
            payload_plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=sha256(payload),
                capabilities=value.capabilities(kvm=True),
            )
            overlay_plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                capabilities=value.capabilities(kvm=True),
            )

        real_mkdtemp = tempfile.mkdtemp

        def signal_after_mkdtemp(*args: Any, **kwargs: Any) -> str:
            path = real_mkdtemp(*args, **kwargs)
            os.kill(os.getpid(), wuci_lab.signal.SIGTERM)
            return path

        with (
            trust_fixture_hostile_tools(value),
            mock.patch.object(
                wuci_lab,
                "_trusted_bwrap",
                return_value=wuci_lab.TRUSTED_BWRAP,
            ),
            mock.patch.object(
                wuci_lab.tempfile,
                "mkdtemp",
                side_effect=signal_after_mkdtemp,
            ),
        ):
            payload_error = assert_raises(
                wuci_lab.LabError,
                wuci_lab.run_launch,
                payload_plan,
                cwd=value.state,
            )
        assert str(payload_error) == (
            "hostile launch interrupted by handled SIGTERM"
        )
        assert list((value.state / "payloads").iterdir()) == []

        real_mkstemp = tempfile.mkstemp

        def signal_after_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
            descriptor, path = real_mkstemp(*args, **kwargs)
            os.kill(os.getpid(), wuci_lab.signal.SIGTERM)
            return descriptor, path

        with (
            trust_fixture_hostile_tools(value),
            mock.patch.object(
                wuci_lab,
                "_trusted_bwrap",
                return_value=wuci_lab.TRUSTED_BWRAP,
            ),
            mock.patch.object(
                wuci_lab.tempfile,
                "mkstemp",
                side_effect=signal_after_mkstemp,
            ),
        ):
            overlay_error = assert_raises(
                wuci_lab.LabError,
                wuci_lab.run_launch,
                overlay_plan,
                cwd=value.state,
            )
        assert str(overlay_error) == (
            "hostile launch interrupted by handled SIGTERM"
        )
        assert list((value.state / "volatile").iterdir()) == []


def test_hostile_file_allocation_signals_roll_back_exact_payload_state() -> None:
    with fixture() as value:
        payload = value._write(
            "file-allocation-signal.bin",
            b"benign file-allocation signal fixture\n",
        )
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                hostile_payload=payload,
                hostile_payload_sha256=sha256(payload),
                capabilities=value.capabilities(kvm=True),
            )
        real_open = os.open
        for target_name in ("payload.bin", "manifest.json", "payload.ext4"):
            triggered = False

            def signal_after_target_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                *args: Any,
                **kwargs: Any,
            ) -> int:
                nonlocal triggered
                descriptor = real_open(path, flags, *args, **kwargs)
                path_name = Path(os.fsdecode(path)).name
                if not triggered and path_name == target_name:
                    triggered = True
                    os.kill(os.getpid(), wuci_lab.signal.SIGTERM)
                return descriptor

            with (
                trust_fixture_hostile_tools(value),
                mock.patch.object(
                    wuci_lab,
                    "_trusted_bwrap",
                    return_value=wuci_lab.TRUSTED_BWRAP,
                ),
                mock.patch.object(
                    wuci_lab.os,
                    "open",
                    side_effect=signal_after_target_open,
                ),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab.run_launch,
                    plan,
                    cwd=value.state,
                )
            assert triggered
            assert str(error) == (
                "hostile launch interrupted by handled SIGTERM"
            )
            assert list((value.state / "payloads").iterdir()) == []
            volatile = value.state / "volatile"
            assert not volatile.exists() or list(volatile.iterdir()) == []


def test_hostile_binding_caps_match_validated_artifact_classes() -> None:
    with fixture() as value:
        inputs = wuci_lab.validate_boot_inputs(
            value.kernel,
            sha256(value.kernel),
            value.initrd,
            sha256(value.initrd),
            value.base,
            sha256(value.base),
        )
        observed: list[dict[str, Any]] = []

        def capture_binding(
            source: Path,
            destination: Path,
            *,
            kind: str,
            label: str,
            max_bytes: int | None,
            expected_bound: wuci_lab.BoundFile | None = None,
        ) -> dict[str, Any]:
            observed.append(
                {
                    "source": source,
                    "destination": destination,
                    "kind": kind,
                    "label": label,
                    "max_bytes": max_bytes,
                    "expected_bound": expected_bound,
                }
            )
            return {
                "source": str(source),
                "destination": str(destination),
                "kind": kind,
            }

        with mock.patch.object(
            wuci_lab,
            "_hostile_runtime_binding",
            side_effect=capture_binding,
        ):
            wuci_lab._hostile_read_only_bindings(value.qemu, inputs)

        expected_artifacts = {
            "hostile bound kernel": ("kernel", wuci_lab.MAX_KERNEL_BYTES),
            "hostile bound initrd": ("initrd", wuci_lab.MAX_INITRD_BYTES),
            "hostile bound base image": ("base_image", wuci_lab.MAX_BASE_BYTES),
        }
        artifact_labels_seen: set[str] = set()
        for request in observed:
            label = request["label"]
            if label in expected_artifacts:
                key, maximum = expected_artifacts[label]
                bound = inputs[key]
                artifact_labels_seen.add(label)
                assert request["kind"] == "file"
                assert request["source"] == bound.path
                assert request["destination"] == bound.path
                assert request["max_bytes"] == maximum
                assert request["expected_bound"] is bound
            elif request["kind"] == "directory":
                assert request["max_bytes"] is None
                assert request["expected_bound"] is None
            else:
                assert label in {
                    "hostile QEMU executable",
                    "hostile QEMU runtime file",
                }
                assert request["max_bytes"] == (
                    wuci_lab.MAX_HOSTILE_RUNTIME_FILE_BYTES
                )
                assert request["expected_bound"] is None
        assert artifact_labels_seen == set(expected_artifacts)

    with tempfile.TemporaryDirectory(
        prefix="wuci-hostile-binding-cap.",
        dir="/tmp",
    ) as raw:
        root = Path(raw)

        def sparse_file(name: str, size: int) -> tuple[Path, os.stat_result]:
            path = root / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            descriptor = os.open(path, flags, 0o600)
            try:
                os.ftruncate(descriptor, size)
            finally:
                os.close(descriptor)
            info = os.lstat(path)
            assert info.st_size == size
            assert info.st_blocks * 512 < size
            return path, info

        canonical_size = 8 * 1024 * 1024 * 1024
        canonical, canonical_info = sparse_file(
            "canonical-8g-base.ext4",
            canonical_size,
        )
        bound = wuci_lab.BoundFile(
            path=canonical,
            sha256="0" * 64,
            size=canonical_info.st_size,
            mode=stat.S_IMODE(canonical_info.st_mode),
            device=canonical_info.st_dev,
            inode=canonical_info.st_ino,
        )
        accepted = wuci_lab._hostile_runtime_binding(
            canonical,
            canonical,
            kind="file",
            label="hostile bound base image",
            max_bytes=wuci_lab.MAX_BASE_BYTES,
            expected_bound=bound,
        )
        assert accepted["size"] == canonical_size
        assert accepted["device"] == bound.device
        assert accepted["inode"] == bound.inode

        generic_limit = assert_raises(
            wuci_lab.LabError,
            wuci_lab._hostile_runtime_binding,
            canonical,
            canonical,
            kind="file",
            label="hostile QEMU runtime file",
            max_bytes=wuci_lab.MAX_HOSTILE_RUNTIME_FILE_BYTES,
        )
        assert (
            f"exceeds the {wuci_lab.MAX_HOSTILE_RUNTIME_FILE_BYTES}-byte limit"
            in str(generic_limit)
        )

        bound_fields = {
            "path": bound.path,
            "sha256": bound.sha256,
            "size": bound.size,
            "mode": bound.mode,
            "device": bound.device,
            "inode": bound.inode,
        }
        for field, replacement in (
            ("path", root / "different-base.ext4"),
            ("size", bound.size + 1),
            ("mode", bound.mode ^ stat.S_IXUSR),
            ("device", bound.device + 1),
            ("inode", bound.inode + 1),
        ):
            changed = wuci_lab.BoundFile(
                **{**bound_fields, field: replacement}
            )
            identity_error = assert_raises(
                wuci_lab.LabError,
                wuci_lab._hostile_runtime_binding,
                canonical,
                canonical,
                kind="file",
                label="hostile bound base image",
                max_bytes=wuci_lab.MAX_BASE_BYTES,
                expected_bound=changed,
            )
            assert "changed after boot-input validation" in str(identity_error)

        oversize, _oversize_info = sparse_file(
            "oversize-base.ext4",
            wuci_lab.MAX_BASE_BYTES + 1,
        )
        oversize_error = assert_raises(
            wuci_lab.LabError,
            wuci_lab._hostile_runtime_binding,
            oversize,
            oversize,
            kind="file",
            label="hostile bound base image",
            max_bytes=wuci_lab.MAX_BASE_BYTES,
        )
        assert (
            f"exceeds the {wuci_lab.MAX_BASE_BYTES}-byte limit"
            in str(oversize_error)
        )


def test_hostile_plan_has_exact_outer_namespace_and_resource_policy() -> None:
    with fixture() as value:
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                capabilities=value.capabilities(kvm=True),
            )
        argv = plan["argv"]
        assert argv[0] == "/usr/bin/bwrap"
        for option in wuci_lab.HOSTILE_BWRAP_FLAGS:
            assert argv.count(option) == 1
        assert "--share-net" not in argv
        assert argv.count("--") == 1
        separator = argv.index("--")
        assert argv[separator + 1 :] == plan["qemu_argv"]

        tmpfs_destinations = {
            argv[index + 1]
            for index, item in enumerate(argv)
            if item == "--tmpfs"
        }
        assert tmpfs_destinations == {"/", "/tmp", "/run", "/var/tmp"}
        assert argv.count("--bind") == 1
        bind_index = argv.index("--bind")
        assert argv[bind_index + 1 : bind_index + 3] == [
            wuci_lab.DEFERRED_VOLATILE_ROOT,
            wuci_lab.DEFERRED_VOLATILE_ROOT,
        ]
        assert argv.count("--dev-bind") == 1
        device_index = argv.index("--dev-bind")
        assert argv[device_index + 1 : device_index + 3] == [
            "/dev/kvm",
            "/dev/kvm",
        ]
        assert argv.count("--remount-ro") == 1
        assert argv[argv.index("--remount-ro") + 1] == "/"

        read_only_pairs = {
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv)
            if item == "--ro-bind"
        }
        expected_pairs = {
            (str(value.qemu), str(value.qemu)),
            (str(value.kernel), str(value.kernel)),
            (str(value.initrd), str(value.initrd)),
            (str(value.base), str(value.base)),
            *((str(path), str(path)) for path in wuci_lab.HOSTILE_RUNTIME_DIRECTORIES),
            *(
                (str(source), str(destination))
                for source, destination in wuci_lab.HOSTILE_RUNTIME_DIRECTORY_ALIASES
            ),
            *(
                (str(source), str(destination))
                for source, destination in wuci_lab.HOSTILE_RUNTIME_FILES
            ),
        }
        assert read_only_pairs == expected_pairs
        assert ("/", "/") not in read_only_pairs
        assert all(source not in {"/home", str(REPO_ROOT)} for source, _ in read_only_pairs)

        setenv_records = [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv)
            if item == "--setenv"
        ]
        assert len({key for key, _value in setenv_records}) == len(setenv_records)
        assert dict(setenv_records) == {
            "HOME": "/tmp",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin",
            "XDG_CONFIG_HOME": "/tmp",
        }
        assert all("proxy" not in key.lower() for key, _value in setenv_records)

        qemu_argv = plan["qemu_argv"]
        assert qemu_argv[qemu_argv.index("-machine") + 1] == "q35,accel=kvm"
        assert qemu_argv[qemu_argv.index("-append") + 1] == wuci_lab.KERNEL_APPEND
        assert "nosoftlockup" not in qemu_argv[
            qemu_argv.index("-append") + 1
        ].split()
        assert qemu_argv[qemu_argv.index("-nic") + 1] == "none"
        assert qemu_argv[qemu_argv.index("-monitor") + 1] == "none"
        assert qemu_argv[qemu_argv.index("-sandbox") + 1] == wuci_lab.QEMU_SANDBOX
        assert "-netdev" not in qemu_argv
        assert "-virtfs" not in qemu_argv
        assert "-fsdev" not in qemu_argv
        assert "vfio-pci" not in qemu_argv

        limits = plan["host_resource_limits"]
        assert limits == {
            "address_space_bytes": (
                wuci_lab.DEFAULT_MEMORY_MIB * 1024 * 1024 * 2
                + wuci_lab.HOSTILE_ADDRESS_SPACE_OVERHEAD_BYTES
            ),
            "locked_memory_bytes": wuci_lab.HOSTILE_LOCKED_MEMORY_BYTES,
            "file_size_bytes": (
                value.base.stat().st_size
                + wuci_lab.HOSTILE_FILE_SIZE_OVERHEAD_BYTES
            ),
            "open_files": wuci_lab.HOSTILE_OPEN_FILES,
            "processes": wuci_lab.HOSTILE_ACCOUNT_TASK_LIMIT,
            "core_bytes": 0,
        }
        assert plan["outer_boundary"]["host_resource_limits"] == {
            "applied_before_bubblewrap_exec": True,
            "inherited_by_qemu": True,
            "limits": limits,
        }
        assert plan["controls"]["hostile_console_rendering"] == (
            wuci_lab.HOSTILE_CONSOLE_RENDERING
        )
        assert (
            plan["controls"]["hostile_console_forwarded_byte_allowlist"]
            == list(wuci_lab.HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST)
        )
        assert (
            plan["controls"][
                "hostile_non_allowlisted_console_bytes_forwarded"
            ]
            is False
        )
        assert plan["controls"]["hostile_console_stderr_merged"] is True
        assert plan["controls"]["hostile_console_byte_limit"] == (
            wuci_lab.MAX_HOSTILE_CONSOLE_BYTES
        )
        assert plan["controls"][
            "hostile_console_input_buffer_byte_limit"
        ] == wuci_lab.MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES
        assert plan["controls"]["hostile_stdin_one_way_pipe"] is True
        assert (
            plan["controls"]["hostile_tty_restoration_on_handled_exit"]
            is True
        )
        assert (
            plan["controls"]["hostile_tty_input_flushed_before_handoff"]
            is True
        )
        assert (
            plan["controls"]["hostile_process_group_absence_checked"]
            is True
        )
        assert plan["controls"]["hostile_handled_signals"] == [
            "SIGHUP",
            "SIGINT",
            "SIGQUIT",
            "SIGTERM",
            "SIGTSTP",
        ]
        assert plan["controls"][
            "hostile_console_descendant_drain_timeout_seconds"
        ] == wuci_lab.HOSTILE_CONSOLE_DESCENDANT_DRAIN_TIMEOUT_SECONDS
        assert plan["controls"][
            "hostile_console_leader_exit_confirm_timeout_seconds"
        ] == wuci_lab.HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS


def test_hostile_real_launch_uses_safe_relay_limits_and_cleans_overlay() -> None:
    with fixture() as value:
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                capabilities=value.capabilities(kvm=True),
            )
        observed: dict[str, Any] = {}

        def dispatch(
            argv: list[str], *positional: Any, **keywords: Any
        ) -> int:
            assert argv[0] == str(wuci_lab.TRUSTED_BWRAP)
            assert positional == ()
            separator = argv.index("--")
            qemu_argv = argv[separator + 1 :]
            drive = qemu_argv[qemu_argv.index("-drive") + 1]
            overlay = Path(drive.split("file=", 1)[1].split(",", 1)[0])
            bind_index = argv.index("--bind")
            assert argv[bind_index + 1 : bind_index + 3] == [
                str(overlay),
                str(overlay),
            ]
            assert overlay.parent == value.state / "volatile"
            assert overlay.is_file()
            assert stat.S_IMODE(overlay.lstat().st_mode) == 0o600
            assert wuci_lab.DEFERRED_VOLATILE_ROOT not in "\n".join(argv)
            assert callable(keywords["preexec_fn"])
            observed.update(
                {"argv": argv, "keywords": keywords, "overlay": overlay}
            )
            return 23

        kvm_status = trusted_kvm_status()
        with trust_fixture_hostile_tools(value):
            with (
                mock.patch.object(
                    wuci_lab,
                    "_run_hostile_console_relay",
                    side_effect=dispatch,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_trusted_bwrap",
                    return_value=wuci_lab.TRUSTED_BWRAP,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_kvm_device_status",
                    return_value=kvm_status,
                ),
            ):
                result = wuci_lab.run_launch(plan, cwd=value.state)
        assert result == 23
        assert observed
        assert observed["keywords"]["environment"] == (
            wuci_lab._sanitized_environment()
        )
        assert observed["keywords"]["cwd"] == value.state
        assert not observed["overlay"].exists()
        assert list((value.state / "volatile").iterdir()) == []

        with mock.patch.object(wuci_lab.resource, "setrlimit") as set_limit:
            apply_limits = wuci_lab._resource_limit_preexec(
                plan["host_resource_limits"]
            )
            apply_limits()
        assert set_limit.call_count == 6
        observed_limits = {
            limit_constant: pair
            for limit_constant, pair in (call.args for call in set_limit.call_args_list)
        }
        assert observed_limits[wuci_lab.resource.RLIMIT_CORE] == (0, 0)
        assert observed_limits[wuci_lab.resource.RLIMIT_AS] == (
            plan["host_resource_limits"]["address_space_bytes"],
            plan["host_resource_limits"]["address_space_bytes"],
        )
        with mock.patch.object(
            wuci_lab,
            "_real_uid_task_count",
            return_value=(
                wuci_lab.HOSTILE_ACCOUNT_TASK_LIMIT
                - wuci_lab.HOSTILE_MIN_ACCOUNT_TASK_HEADROOM
                + 1
            ),
        ):
            headroom_error = assert_raises(
                wuci_lab.LabError,
                wuci_lab._resource_limit_preexec,
                plan["host_resource_limits"],
            )
        assert "account-wide RLIMIT_NPROC ceiling" in str(headroom_error)


def test_hostile_outer_and_qemu_policy_tampering_is_rejected_before_exec() -> None:
    with fixture() as value:
        with trust_fixture_hostile_tools(value):
            plan = wuci_lab.launch_plan(
                **value.boot_args(),
                profile="hostile",
                capabilities=value.capabilities(kvm=True),
            )
        state = wuci_lab.ensure_state_root(value.state)
        base = wuci_lab._validated_plan_base(plan)
        kvm_status = trusted_kvm_status()
        with wuci_lab.private_volatile_overlay(
            state_root=state,
            base=base,
            qemu_img_path=value.qemu_img,
        ) as overlay:
            materialized = wuci_lab._materialize_volatile_plan(plan, overlay)
            outer_tamper = copy.deepcopy(materialized)
            separator = outer_tamper["argv"].index("--")
            outer_tamper["argv"][separator:separator] = [
                "--ro-bind",
                "/",
                "/host",
            ]
            qemu_tamper = copy.deepcopy(materialized)
            qemu_tamper["qemu_argv"].extend(["-device", "vfio-pci"])
            with trust_fixture_hostile_tools(value):
                with (
                    mock.patch.object(
                        wuci_lab,
                        "_trusted_bwrap",
                        return_value=wuci_lab.TRUSTED_BWRAP,
                    ),
                    mock.patch.object(
                        wuci_lab,
                        "_kvm_device_status",
                        return_value=kvm_status,
                    ),
                    mock.patch.object(wuci_lab.subprocess, "run") as execute,
                    mock.patch.object(
                        wuci_lab, "_run_hostile_console_relay"
                    ) as relay,
                ):
                    outer_error = assert_raises(
                        wuci_lab.LabError,
                        wuci_lab._execute_launch,
                        outer_tamper,
                        state,
                    )
                    qemu_error = assert_raises(
                        wuci_lab.LabError,
                        wuci_lab._execute_launch,
                        qemu_tamper,
                        state,
                    )
            assert "exact outer policy" in str(outer_error)
            assert "exact policy inputs" in str(qemu_error)
            execute.assert_not_called()
            relay.assert_not_called()


def test_hostile_console_relay_escapes_terminal_controls_and_is_bounded() -> None:
    renderer = wuci_lab._EscapedAsciiConsoleRenderer()
    assert renderer.render(b"line\r") == "line"
    assert renderer.render(b"\nnext\rX", final=True) == (
        "\nnext\\x0dX"
    )

    with tempfile.TemporaryDirectory(prefix="wuci-relay-") as directory:
        child = (
            "import os; "
            "os.write(1, b'LOVELACE_LABORATORY_CONSOLE_READY\\r\\n"
            "\\tplain\\x1b]52;c;YQ==\\x07\\x9b[31m\\x7f\\xff'); "
            "os.write(2, b'\\x1bP1;2|dcs\\x1b\\\\\\\\')"
        )
        real_popen = subprocess.Popen
        observed: dict[str, Any] = {}

        def captured_popen(
            argv: list[str], *positional: Any, **keywords: Any
        ) -> subprocess.Popen[bytes]:
            observed.update({"argv": argv, "keywords": keywords})
            return real_popen(argv, *positional, **keywords)

        output = io.StringIO()
        restored: list[tuple[int, list[Any]] | None] = []
        snapshot: tuple[int, list[Any]] = (123, ["fixture"])
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(output),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab.subprocess,
                    "Popen",
                    side_effect=captured_popen,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_prepare_stdin_termios",
                    return_value=snapshot,
                ),
                mock.patch.object(wuci_lab, "_enter_stdin_raw_mode"),
                mock.patch.object(
                    wuci_lab,
                    "_restore_stdin_termios",
                    side_effect=lambda value: restored.append(value),
                ),
            ):
                result = wuci_lab._run_hostile_console_relay(
                    [sys.executable, "-c", child],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
        assert result == 0
        rendered = output.getvalue()
        assert rendered.startswith(
            "LOVELACE_LABORATORY_CONSOLE_READY\n\tplain"
        )
        for escaped in (
            "\\x1b",
            "\\x07",
            "\\x9b",
            "\\x7f",
            "\\xff",
        ):
            assert escaped in rendered
        assert all(
            character in {"\n", "\t"} or 0x20 <= ord(character) <= 0x7E
            for character in rendered
        )
        assert "\x1b" not in rendered
        assert "\x07" not in rendered
        assert "\r" not in rendered
        assert restored == [snapshot]
        keywords = observed["keywords"]
        assert keywords["stdin"] is subprocess.PIPE
        assert keywords["stdout"] is subprocess.PIPE
        assert keywords["stderr"] is subprocess.STDOUT
        assert keywords["shell"] is False
        assert keywords["start_new_session"] is True
        assert keywords["env"] == wuci_lab._sanitized_environment()

        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab, "MAX_HOSTILE_CONSOLE_BYTES", 4
                ),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", "print('oversized')"],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
        assert "console output exceeds the 4-byte limit" in str(error)


def test_hostile_console_relay_forwards_bounded_input_without_tty_write_access() -> None:
    with tempfile.TemporaryDirectory(prefix="wuci-relay-input-") as directory:
        with tempfile.TemporaryFile("w+b") as operator_input:
            operator_input.write(b"operator-line\n")
            operator_input.seek(0)
            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
            ):
                result = wuci_lab._run_hostile_console_relay(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os; data=os.read(0, 64); "
                            "os.write(1, b'GUEST_INPUT:' + data)"
                        ),
                    ],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
        assert result == 0
        assert output.getvalue() == "GUEST_INPUT:operator-line\n"

        with tempfile.TemporaryFile("w+b") as operator_input:
            operator_input.write(b"oversized")
            operator_input.seek(0)
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab,
                    "MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES",
                    4,
                ),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
        assert "operator-input buffer exceeds the 4-byte limit" in str(error)


def test_hostile_console_relay_handles_signals_and_reports_tty_restore_failure() -> None:
    snapshot: tuple[int, list[Any]] = (123, ["fixture"])
    restored: list[tuple[int, list[Any]] | None] = []
    captured: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def captured_popen(
        argv: list[str], *positional: Any, **keywords: Any
    ) -> subprocess.Popen[bytes]:
        process = real_popen(argv, *positional, **keywords)
        captured.append(process)
        return process

    def trigger_sigterm(*_args: Any, **_kwargs: Any) -> list[Any]:
        handler = wuci_lab.signal.getsignal(wuci_lab.signal.SIGTERM)
        assert callable(handler)
        handler(wuci_lab.signal.SIGTERM, None)
        raise AssertionError("handled SIGTERM returned")

    previous = wuci_lab.signal.getsignal(wuci_lab.signal.SIGTERM)
    with tempfile.TemporaryDirectory(prefix="wuci-relay-signal-") as directory:
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab.subprocess,
                    "Popen",
                    side_effect=captured_popen,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_prepare_stdin_termios",
                    return_value=snapshot,
                ),
                mock.patch.object(wuci_lab, "_enter_stdin_raw_mode"),
                mock.patch.object(
                    wuci_lab,
                    "_restore_stdin_termios",
                    side_effect=lambda value: restored.append(value),
                ),
                mock.patch.object(
                    wuci_lab.selectors.SelectSelector,
                    "select",
                    side_effect=trigger_sigterm,
                ),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
    assert "interrupted by handled SIGTERM" in str(error)
    assert restored == [snapshot]
    assert len(captured) == 1
    assert captured[0].poll() is not None
    assert not wuci_lab._hostile_console_process_group_exists(
        captured[0].pid
    )
    assert wuci_lab.signal.getsignal(wuci_lab.signal.SIGTERM) == previous

    raw_mode_restore: list[tuple[int, list[Any]] | None] = []

    def interrupt_during_raw_mode(
        _descriptor: int, *, when: int
    ) -> None:
        assert when == wuci_lab.termios.TCSANOW
        handler = wuci_lab.signal.getsignal(wuci_lab.signal.SIGTERM)
        assert callable(handler)
        handler(wuci_lab.signal.SIGTERM, None)

    with tempfile.TemporaryDirectory(prefix="wuci-relay-raw-") as directory:
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab,
                    "_stdin_termios_snapshot",
                    return_value=snapshot,
                ),
                mock.patch.object(
                    wuci_lab.tty,
                    "setraw",
                    side_effect=interrupt_during_raw_mode,
                ),
                mock.patch.object(
                    wuci_lab,
                    "_restore_stdin_termios",
                    side_effect=lambda value: raw_mode_restore.append(value),
                ),
                mock.patch.object(wuci_lab.subprocess, "Popen") as popen,
            ):
                raw_mode_error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
    assert "interrupted by handled SIGTERM" in str(raw_mode_error)
    assert raw_mode_restore == [snapshot]
    popen.assert_not_called()

    with mock.patch.object(wuci_lab.termios, "tcsetattr") as restore:
        wuci_lab._restore_stdin_termios(snapshot)
    restore.assert_called_once_with(
        snapshot[0], wuci_lab.termios.TCSAFLUSH, snapshot[1]
    )

    with mock.patch.object(
        wuci_lab.termios,
        "tcsetattr",
        side_effect=wuci_lab.termios.error(5, "fixture restore failure"),
    ):
        restore_error = assert_raises(
            wuci_lab.LabError,
            wuci_lab._restore_stdin_termios,
            snapshot,
        )
    assert "could not restore host terminal state" in str(restore_error)

    with tempfile.TemporaryDirectory(prefix="wuci-relay-errors-") as directory:
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab, "MAX_HOSTILE_CONSOLE_BYTES", 0
                ),
                mock.patch.object(
                    wuci_lab,
                    "_restore_stdin_termios",
                    side_effect=wuci_lab.LabError(
                        "fixture terminal restore failed"
                    ),
                ),
            ):
                combined_error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", "print('fixture')"],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
    combined_text = str(combined_error)
    assert "primary failure and cleanup failure" in combined_text
    assert "console output exceeds the 0-byte limit" in combined_text
    assert "fixture terminal restore failed" in combined_text


def test_hostile_console_relay_flushes_tty_input_before_handoff() -> None:
    master, slave = pty.openpty()
    original = wuci_lab.termios.tcgetattr(slave)
    injected = b"HOST_CROSSOVER\n"
    real_terminate = wuci_lab._terminate_hostile_console_process

    def terminate_after_injection(
        process: subprocess.Popen[bytes],
    ) -> None:
        os.write(master, injected)
        real_terminate(process)

    def trigger_sigterm(*_args: Any, **_kwargs: Any) -> list[Any]:
        handler = wuci_lab.signal.getsignal(wuci_lab.signal.SIGTERM)
        assert callable(handler)
        handler(wuci_lab.signal.SIGTERM, None)
        raise AssertionError("handled SIGTERM returned")

    try:
        with os.fdopen(os.dup(slave), "rb", buffering=0) as operator_input:
            with tempfile.TemporaryDirectory(
                prefix="wuci-relay-pty-"
            ) as directory:
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    mock.patch.object(
                        wuci_lab.sys, "stdin", operator_input
                    ),
                    mock.patch.object(
                        wuci_lab.selectors.SelectSelector,
                        "select",
                        side_effect=trigger_sigterm,
                    ),
                    mock.patch.object(
                        wuci_lab,
                        "_terminate_hostile_console_process",
                        side_effect=terminate_after_injection,
                    ),
                ):
                    error = assert_raises(
                        wuci_lab.LabError,
                        wuci_lab._run_hostile_console_relay,
                        [
                            sys.executable,
                            "-c",
                            "import time; time.sleep(60)",
                        ],
                        cwd=Path(directory),
                        environment=wuci_lab._sanitized_environment(),
                        preexec_fn=lambda: None,
                    )
        assert "interrupted by handled SIGTERM" in str(error)
        assert wuci_lab.termios.tcgetattr(slave) == original
        os.set_blocking(slave, False)
        try:
            queued = os.read(slave, 65536)
        except BlockingIOError:
            queued = b""
        assert queued == b""
    finally:
        os.close(master)
        os.close(slave)


def test_hostile_console_relay_rejects_and_kills_surviving_descendants() -> None:
    def wait_for_pid_absence(pid: int) -> bool:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not Path(f"/proc/{pid}").exists():
                return True
            time.sleep(0.05)
        return not Path(f"/proc/{pid}").exists()

    with tempfile.TemporaryDirectory(prefix="wuci-relay-child-") as directory:
        root = Path(directory)
        closed_pipe_pid = root / "closed-pipe.pid"
        closed_pipe_script = f"""
import os
import pathlib
import time

pid = os.fork()
if pid == 0:
    os.close(1)
    os.close(2)
    time.sleep(60)
    os._exit(0)
pathlib.Path({str(closed_pipe_pid)!r}).write_text(str(pid), encoding="ascii")
os._exit(0)
"""
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", closed_pipe_script],
                    cwd=root,
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
        assert "process-group member remained" in str(error)
        closed_pipe_child = int(
            closed_pipe_pid.read_text(encoding="ascii")
        )
        assert wait_for_pid_absence(closed_pipe_child)

        held_pipe_pid = root / "held-pipe.pid"
        held_pipe_script = f"""
import os
import pathlib
import time

pid = os.fork()
if pid == 0:
    time.sleep(60)
    os._exit(0)
pathlib.Path({str(held_pipe_pid)!r}).write_text(str(pid), encoding="ascii")
os._exit(0)
"""
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
                mock.patch.object(
                    wuci_lab,
                    "HOSTILE_CONSOLE_DESCENDANT_DRAIN_TIMEOUT_SECONDS",
                    0.05,
                ),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", held_pipe_script],
                    cwd=root,
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
        assert "kept the transcript pipe open" in str(error)
        held_pipe_child = int(held_pipe_pid.read_text(encoding="ascii"))
        assert wait_for_pid_absence(held_pipe_child)


def test_hostile_console_relay_rejects_console_eof_from_live_leader() -> None:
    with tempfile.TemporaryDirectory(prefix="wuci-relay-eof-") as directory:
        script = (
            "import os,time; os.close(1); os.close(2); time.sleep(60)"
        )
        with open(os.devnull, "rb") as operator_input:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(wuci_lab.sys, "stdin", operator_input),
            ):
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._run_hostile_console_relay,
                    [sys.executable, "-c", script],
                    cwd=Path(directory),
                    environment=wuci_lab._sanitized_environment(),
                    preexec_fn=lambda: None,
                )
    assert "console pipe closed while the launch leader remained" in str(
        error
    )


def test_hardened_argv_and_fixed_resource_bounds() -> None:
    with fixture() as value:
        args = value.boot_args()
        plan = wuci_lab.launch_plan(
            **args,
            profile="analysis",
            capabilities=value.capabilities(kvm=False),
            memory_mib=wuci_lab.MAX_MEMORY_MIB,
            cpus=wuci_lab.MAX_CPUS,
        )
        argv = plan["argv"]
        for option in (
            "-nodefaults",
            "-no-user-config",
            "-monitor",
            "-nographic",
            "-serial",
            "-sandbox",
            "-kernel",
            "-initrd",
            "-append",
        ):
            assert option in argv
        assert argv[argv.index("-monitor") + 1] == "none"
        assert argv[argv.index("-serial") + 1] == "stdio"
        assert argv[argv.index("-sandbox") + 1] == wuci_lab.QEMU_SANDBOX
        assert argv[argv.index("-append") + 1].startswith(
            "root=/dev/vda rw rootfstype=ext4"
        )
        assert argv[argv.index("-append") + 1].split() == [
            *wuci_lab.KERNEL_APPEND.split(),
            "nosoftlockup",
        ]
        assert (
            wuci_lab._kernel_append_for_acceleration("kvm").split()
            == wuci_lab.KERNEL_APPEND.split()
        )
        assert "nosoftlockup" not in wuci_lab._kernel_append_for_acceleration(
            "kvm"
        ).split()
        assert_raises(
            wuci_lab.LabError,
            wuci_lab._kernel_append_for_acceleration,
            "fixture-invalid",
        )
        assert argv[argv.index("-machine") + 1] == "q35,accel=tcg"
        assert argv[argv.index("-cpu") + 1] == wuci_lab.TCG_CPU_MODEL
        assert plan["acceleration"]["tcg_fallback"] is True
        assert "TCG" in plan["acceleration"]["label"]
        forbidden = ("-virtfs", "-fsdev", "-chardev", "-monitor stdio")
        assert all(item not in argv for item in forbidden)
        assert plan["controls"]["host_shares"] is False
        assert plan["controls"]["shell"] is False

        for memory in (wuci_lab.MIN_MEMORY_MIB - 1, wuci_lab.MAX_MEMORY_MIB + 1):
            assert_raises(
                wuci_lab.LabError,
                wuci_lab.launch_plan,
                **args,
                capabilities=value.capabilities(kvm=False),
                memory_mib=memory,
            )
        for cpus in (wuci_lab.MIN_CPUS - 1, wuci_lab.MAX_CPUS + 1):
            assert_raises(
                wuci_lab.LabError,
                wuci_lab.launch_plan,
                **args,
                capabilities=value.capabilities(kvm=False),
                cpus=cpus,
            )


def test_final_exec_rehashes_every_boot_input_and_rejects_byte_tampering() -> None:
    with fixture() as value:
        make_overlay(value, "digest-check")
        plan = wuci_lab.launch_plan(
            **value.boot_args(),
            storage="persistent",
            overlay="digest-check",
            capabilities=value.capabilities(kvm=False),
        )
        for label, path in (
            ("kernel", value.kernel),
            ("initrd", value.initrd),
            ("base_image", value.base),
        ):
            original = path.read_bytes()
            replacement = bytes([original[0] ^ 0xFF]) + original[1:]
            assert len(replacement) == len(original)
            path.write_bytes(replacement)
            path.chmod(0o600)
            with mock.patch.object(wuci_lab.subprocess, "run") as execute:
                error = assert_raises(
                    wuci_lab.LabError,
                    wuci_lab._execute_launch,
                    plan,
                    value.state,
                )
            assert label in str(error)
            assert "digest mismatch" in str(error)
            execute.assert_not_called()
            path.write_bytes(original)
            path.chmod(0o600)
            assert sha256(path) == plan["inputs"][label]["sha256"]


def test_status_and_plans_do_not_overclaim() -> None:
    with fixture() as value:
        args = value.boot_args()
        status_args = {
            key: item
            for key, item in args.items()
            if key
            in {
                "kernel",
                "kernel_sha256",
                "initrd",
                "initrd_sha256",
                "base_image",
                "base_sha256",
                "qemu",
            }
        }
        status = wuci_lab.status_report(
            **status_args,
            capabilities=value.capabilities(kvm=False),
        )
        plan = wuci_lab.launch_plan(
            **args,
            capabilities=value.capabilities(kvm=False),
        )
        for record in (status, plan):
            assert record["claims"]["production_ready_claimed"] is False
            assert record["claims"]["runtime_sandbox_claimed"] is False
            assert record["claims"]["safe_for_arbitrary_malware_claimed"] is False
            text = json.dumps(record, sort_keys=True)
            assert "vulnerability-free" in text
            assert "arbitrary malware" in text
        assert status["profiles"]["developer"]["launchable"] is True
        assert status["profiles"]["developer"]["acceleration"]["tcg_fallback"] is True
        assert status["profiles"]["hostile"]["launchable"] is False


def test_dry_run_emits_json_and_never_launches_qemu() -> None:
    with fixture() as value:
        arguments = [
            "launch",
            "--kernel",
            str(value.kernel),
            "--kernel-sha256",
            sha256(value.kernel),
            "--initrd",
            str(value.initrd),
            "--initrd-sha256",
            sha256(value.initrd),
            "--base-image",
            str(value.base),
            "--base-sha256",
            sha256(value.base),
            "--qemu",
            str(value.qemu),
            "--qemu-img",
            str(value.qemu_img),
            "--state-root",
            str(value.state),
            "--dry-run",
        ]
        assert not value.state.exists()
        output = io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            mock.patch.object(
                wuci_lab,
                "probe_host",
                return_value=value.capabilities(kvm=False),
            ),
        ):
            result = wuci_lab.main(arguments)
        assert result == 0
        plan = json.loads(output.getvalue())
        assert plan["decision"] == "launch-plan-valid"
        assert plan["storage"]["mode"] == "volatile"
        assert plan["storage"]["root_disk"] is None
        assert plan["storage"]["volatile_overlay_deferred_until_real_launch"] is True
        assert plan["network"]["mode"] == "none"
        assert plan["acceleration"]["selected"] == "tcg"
        assert plan["argv_materialized"] is False
        assert not value.state.exists()


def test_real_launch_uses_fixed_argv_shell_false_and_sanitized_environment() -> None:
    with fixture() as value:
        plan = wuci_lab.launch_plan(
            **value.boot_args(),
            capabilities=value.capabilities(kvm=False),
        )
        base_digest = sha256(value.base)
        real_run = subprocess.run
        observed: dict[str, Any] = {}

        def dispatch(argv: list[str], *positional: Any, **keywords: Any) -> Any:
            if argv[0] != str(value.qemu):
                return real_run(argv, *positional, **keywords)
            drive = argv[argv.index("-drive") + 1]
            overlay = Path(drive.split("file=", 1)[1].split(",", 1)[0])
            assert overlay.parent == value.state / "volatile"
            assert overlay.is_file()
            assert stat.S_IMODE(overlay.lstat().st_mode) == 0o600
            assert "format=qcow2" in drive
            assert "snapshot=on" not in drive
            assert "-snapshot" not in argv
            assert wuci_lab.DEFERRED_VOLATILE_ROOT not in drive
            observed.update({"argv": argv, "keywords": keywords, "overlay": overlay})
            return subprocess.CompletedProcess(argv, 17)

        with mock.patch.object(wuci_lab.subprocess, "run", side_effect=dispatch):
            result = wuci_lab.run_launch(plan, cwd=value.state)
        assert result == 17
        assert observed
        keywords = observed["keywords"]
        assert keywords["shell"] is False
        assert keywords["env"] == wuci_lab._sanitized_environment()
        assert keywords["close_fds"] is True
        assert keywords["cwd"] == value.state
        assert "LD_PRELOAD" not in keywords["env"]
        assert "QEMU_AUDIO_DRV" not in keywords["env"]
        assert not observed["overlay"].exists()
        assert list((value.state / "volatile").iterdir()) == []
        assert sha256(value.base) == base_digest


def test_volatile_overlay_is_removed_when_qemu_launch_fails() -> None:
    with fixture() as value:
        plan = wuci_lab.launch_plan(
            **value.boot_args(),
            capabilities=value.capabilities(kvm=False),
        )
        real_run = subprocess.run
        observed_overlay: list[Path] = []

        def dispatch(argv: list[str], *positional: Any, **keywords: Any) -> Any:
            if argv[0] != str(value.qemu):
                return real_run(argv, *positional, **keywords)
            drive = argv[argv.index("-drive") + 1]
            overlay = Path(drive.split("file=", 1)[1].split(",", 1)[0])
            assert overlay.is_file()
            observed_overlay.append(overlay)
            raise OSError("fixture QEMU launch failure")

        with mock.patch.object(wuci_lab.subprocess, "run", side_effect=dispatch):
            error = assert_raises(
                wuci_lab.LabError,
                wuci_lab.run_launch,
                plan,
                cwd=value.state,
            )
        assert "QEMU launch failed" in str(error)
        assert len(observed_overlay) == 1
        assert not observed_overlay[0].exists()
        assert list((value.state / "volatile").iterdir()) == []


TESTS = (
    test_names_and_paths_reject_traversal_and_ambiguity,
    test_bound_files_reject_symlinks_hardlinks_and_digest_mismatch,
    test_run_capture_has_combined_byte_cap_and_text_contract,
    test_run_capture_timeout_kills_process_group_and_reaps_child,
    test_run_capture_defers_signal_until_child_publication_and_reaps,
    test_probe_host_rejects_untrusted_qemu_before_any_execution,
    test_probe_host_executes_only_after_exact_qemu_trust_is_established,
    test_symlinked_state_root_and_loose_permissions_are_rejected,
    test_overlay_create_inspect_and_collision_fail_closed,
    test_overlay_create_rolls_back_both_committed_files_and_can_retry,
    test_overlay_rejects_hardlinks_symlinks_and_manifest_drift,
    test_overlay_lock_rejects_concurrent_supervisors,
    test_overlay_remove_and_reset_are_exact_confirmed_and_base_bound,
    test_volatile_and_persistent_root_disks_are_distinct,
    test_volatile_cleanup_rejects_a_same_uid_hardlink_fail_closed,
    test_network_matrix_is_explicit_and_hostile_is_offline,
    test_hostile_requires_kvm_non_root_and_volatile_storage,
    test_hostile_requires_trusted_exact_bubblewrap,
    test_trusted_bubblewrap_rejects_setuid_and_setgid_modes,
    test_kvm_device_status_requires_exact_identity_permissions_and_access,
    test_hostile_plan_rejects_untrusted_kvm_identity_or_world_access,
    test_hostile_requires_exact_root_owned_system_qemu_tools,
    test_hostile_payload_plan_is_bounded_deferred_and_read_only,
    test_private_hostile_payload_media_binds_manifest_and_cleans_exactly,
    test_hostile_payload_real_launch_uses_one_ro_binding_and_cleans_media,
    test_hostile_payload_final_boundary_rereads_media_semantics,
    test_hostile_sigterm_during_payload_materialization_reaps_and_cleans,
    test_hostile_sigterm_after_transient_materialization_cleans_both,
    test_hostile_allocation_return_signals_leave_no_untracked_state,
    test_hostile_file_allocation_signals_roll_back_exact_payload_state,
    test_hostile_binding_caps_match_validated_artifact_classes,
    test_hostile_plan_has_exact_outer_namespace_and_resource_policy,
    test_hostile_real_launch_uses_safe_relay_limits_and_cleans_overlay,
    test_hostile_outer_and_qemu_policy_tampering_is_rejected_before_exec,
    test_hostile_console_relay_escapes_terminal_controls_and_is_bounded,
    test_hostile_console_relay_forwards_bounded_input_without_tty_write_access,
    test_hostile_console_relay_handles_signals_and_reports_tty_restore_failure,
    test_hostile_console_relay_flushes_tty_input_before_handoff,
    test_hostile_console_relay_rejects_and_kills_surviving_descendants,
    test_hostile_console_relay_rejects_console_eof_from_live_leader,
    test_hardened_argv_and_fixed_resource_bounds,
    test_final_exec_rehashes_every_boot_input_and_rejects_byte_tampering,
    test_status_and_plans_do_not_overclaim,
    test_dry_run_emits_json_and_never_launches_qemu,
    test_real_launch_uses_fixed_argv_shell_false_and_sanitized_environment,
    test_volatile_overlay_is_removed_when_qemu_launch_fails,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    for test in TESTS:
        test()
        if not args.quiet:
            print(f"PASS {test.__name__}")
    if not args.quiet:
        print(f"Wuci lab supervisor tests: PASS ({len(TESTS)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
