#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
import wuci_progress  # noqa: E402


@contextlib.contextmanager
def env(name: str, value: str | None):
    old = os.environ.get(name)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old


def capture_stderr(func):
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = func()
    return result, stderr.getvalue()


def assert_streaming_read(tmp: Path) -> None:
    artifact = tmp / "artifact.bin"
    payload = b"wuci-progress" * 8192
    artifact.write_bytes(payload)

    result, stderr = capture_stderr(
        lambda: wuci_progress.read_regular_bytes(
            artifact,
            "progress test artifact",
            ticker_mode="always",
            label="wuci-progress-test",
        )
    )
    assert result == payload
    assert "\x1b[" in stderr
    assert chr(0x25B2) in stderr
    assert "wuci-progress-test 100%" in stderr
    assert "progress test artifact" not in stderr

    _, quiet_stderr = capture_stderr(
        lambda: wuci_progress.read_regular_bytes(
            artifact,
            "progress test artifact",
            ticker_mode="never",
            label="wuci-progress-test",
        )
    )
    assert quiet_stderr == ""


def assert_env_override(tmp: Path) -> None:
    artifact = tmp / "env.bin"
    artifact.write_bytes(b"env override")
    with env("WUCI_TICKER", "always"):
        _, stderr = capture_stderr(
            lambda: wuci_progress.digest_file(
                artifact,
                "sha256",
                "env override artifact",
                ticker_mode="auto",
                label="wuci-progress-env",
            )
        )
    assert "wuci-progress-env 100%" in stderr


def assert_subprocess_stays_stdout_clean() -> None:
    proc, stderr = capture_stderr(
        lambda: wuci_progress.run_process(
            [sys.executable, "-c", "print('ok')"],
            ticker_mode="always",
            label="wuci-progress-run",
        )
    )
    assert isinstance(proc, subprocess.CompletedProcess)
    assert proc.returncode == 0
    assert proc.stdout == b"ok\n"
    assert proc.stderr == b""
    assert "wuci-progress-run PASS" in stderr
    assert "ok" not in stderr


def assert_argparse_helper() -> None:
    parser = argparse.ArgumentParser()
    wuci_progress.add_ticker_arg(parser)
    args = parser.parse_args(["--ticker", "never"])
    assert args.ticker == "never"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI shared progress helper.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="wuci-progress-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_streaming_read(tmp)
        assert_env_override(tmp)
        assert_subprocess_stays_stdout_clean()
        assert_argparse_helper()
    if not args.quiet:
        print("wuci progress: PASS")


if __name__ == "__main__":
    main()
