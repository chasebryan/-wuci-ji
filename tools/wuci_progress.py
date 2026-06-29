#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator

import wuci_safeio


READ_CHUNK_SIZE = 1024 * 1024
TICKER_MODES = ("auto", "always", "never")
TICKER_COLORS = ("31", "33", "32", "36", "34", "35")
TRIANGLE_FRAMES = tuple(chr(value) for value in (0x25B2, 0x25B6, 0x25BC, 0x25C0))


def resolve_mode(mode: str | None) -> str:
    candidate = mode or "auto"
    env_mode = os.environ.get("WUCI_TICKER")
    if env_mode in TICKER_MODES:
        candidate = env_mode
    if candidate not in TICKER_MODES:
        candidate = "auto"
    return candidate


def enabled(mode: str | None) -> bool:
    resolved = resolve_mode(mode)
    return resolved == "always" or (resolved == "auto" and sys.stderr.isatty())


def add_ticker_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ticker",
        choices=TICKER_MODES,
        default="auto",
        help=(
            "show a rainbow triangle progress ticker on stderr; "
            "also configurable with WUCI_TICKER"
        ),
    )


class TriangleTicker:
    def __init__(self, mode: str | None = "auto", *, label: str = "wuci-ji") -> None:
        self.label = label
        self.enabled = enabled(mode)
        self.frame_index = 0
        self.last_percent = -1

    def _frame(self) -> str:
        frame = TRIANGLE_FRAMES[self.frame_index % len(TRIANGLE_FRAMES)]
        color = TICKER_COLORS[self.frame_index % len(TICKER_COLORS)]
        self.frame_index += 1
        return f"\x1b[{color}m{frame}\x1b[0m"

    def tick(self, completed: int, total: int | None = None, *, detail: str = "") -> None:
        if not self.enabled:
            return
        if total is None:
            percent_text = "..."
        else:
            safe_total = max(total, 0)
            percent = (
                100
                if safe_total == 0
                else min(100, (completed * 100) // safe_total)
            )
            if percent == self.last_percent and completed < safe_total:
                return
            self.last_percent = percent
            percent_text = f"{percent:3d}%"
        suffix = f" {detail}" if detail else ""
        sys.stderr.write(f"\r{self._frame()} {self.label} {percent_text}{suffix}")
        sys.stderr.flush()

    def pulse(self, *, detail: str = "") -> None:
        if not self.enabled:
            return
        suffix = f" {detail}" if detail else ""
        sys.stderr.write(f"\r{self._frame()} {self.label} ...{suffix}")
        sys.stderr.flush()

    def finish(self, *, ok: bool = True) -> None:
        if not self.enabled:
            return
        state = "PASS" if ok else "FAIL"
        sys.stderr.write(f"\r{self._frame()} {self.label} {state}\n")
        sys.stderr.flush()


@contextlib.contextmanager
def stage(label: str, ticker_mode: str | None = "auto") -> Iterator[None]:
    ticker = TriangleTicker(ticker_mode, label=label)
    ticker.pulse()
    try:
        yield
    except BaseException:
        ticker.finish(ok=False)
        raise
    else:
        ticker.finish(ok=True)


def read_regular_bytes(
    path: Path,
    context: str,
    *,
    ticker_mode: str | None = "auto",
    label: str = "wuci-ji",
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> bytes:
    info = wuci_safeio.lstat_regular_file(
        path,
        context,
        reject_symlink=reject_symlink,
        reject_hardlink=reject_hardlink,
        max_bytes=max_bytes,
    )
    ticker = TriangleTicker(ticker_mode, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise wuci_safeio.SafeIOError(f"could not open {context}: {path}") from exc
    try:
        opened_info = os.fstat(fd)
        if not stat.S_ISREG(opened_info.st_mode):
            raise wuci_safeio.SafeIOError(f"{context} must be a regular file: {path}")
        if reject_hardlink and opened_info.st_nlink != 1:
            raise wuci_safeio.SafeIOError(f"{context} must not be hardlinked: {path}")
        if max_bytes is not None and opened_info.st_size > max_bytes:
            raise wuci_safeio.SafeIOError(f"{context} exceeds maximum size: {path}")
        chunks: list[bytes] = []
        total = 0
        ticker.tick(0, info.st_size, detail=f"0/{info.st_size} bytes")
        while True:
            chunk = os.read(fd, READ_CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            ticker.tick(total, info.st_size, detail=f"{total}/{info.st_size} bytes")
        ticker.finish()
        return b"".join(chunks)
    finally:
        os.close(fd)


def digest_file(
    path: Path,
    algorithm: str,
    context: str,
    *,
    ticker_mode: str | None = "auto",
    label: str = "wuci-ji",
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> str:
    digest = hashlib.new(algorithm)
    info = wuci_safeio.lstat_regular_file(
        path,
        context,
        reject_symlink=reject_symlink,
        reject_hardlink=reject_hardlink,
        max_bytes=max_bytes,
    )
    ticker = TriangleTicker(ticker_mode, label=label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise wuci_safeio.SafeIOError(f"could not open {context}: {path}") from exc
    try:
        opened_info = os.fstat(fd)
        if not stat.S_ISREG(opened_info.st_mode):
            raise wuci_safeio.SafeIOError(f"{context} must be a regular file: {path}")
        if reject_hardlink and opened_info.st_nlink != 1:
            raise wuci_safeio.SafeIOError(f"{context} must not be hardlinked: {path}")
        if max_bytes is not None and opened_info.st_size > max_bytes:
            raise wuci_safeio.SafeIOError(f"{context} exceeds maximum size: {path}")
        total = 0
        ticker.tick(0, info.st_size, detail=f"{algorithm} 0/{info.st_size} bytes")
        while True:
            chunk = os.read(fd, READ_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            ticker.tick(
                total,
                info.st_size,
                detail=f"{algorithm} {total}/{info.st_size} bytes",
            )
        ticker.finish()
        return digest.hexdigest()
    finally:
        os.close(fd)


def run_process(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    ticker_mode: str | None = "auto",
    label: str = "wuci-ji wait",
) -> subprocess.CompletedProcess[bytes]:
    ticker = TriangleTicker(ticker_mode, label=label)
    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    while True:
        try:
            stdout, stderr = proc.communicate(timeout=0.15)
            ticker.finish(ok=proc.returncode == 0)
            return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            if timeout is not None and time.monotonic() - started >= timeout:
                proc.kill()
                stdout, stderr = proc.communicate()
                ticker.finish(ok=False)
                raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr)
            ticker.pulse()
