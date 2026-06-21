#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable


class SafeIOError(RuntimeError):
    pass


def _nofollow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _cloexec() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _fsync_parent(path: Path) -> None:
    try:
        fd = os.open(str(path.parent), os.O_RDONLY | _cloexec())
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_under_directory(path: Path, root: Path, context: str) -> Path:
    try:
        resolved = path.resolve(strict=False)
        resolved_root = root.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise SafeIOError(f"{context} must stay under {root}: {path}") from exc
    return resolved


def file_stat(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise SafeIOError(f"could not stat {context}: {path}") from exc
    if reject_symlink and stat.S_ISLNK(info.st_mode):
        raise SafeIOError(f"{context} must not be a symlink: {path}")
    return info


def require_regular_file(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> os.stat_result:
    info = file_stat(path, context, reject_symlink=reject_symlink)
    if not stat.S_ISREG(info.st_mode):
        raise SafeIOError(f"{context} must be a regular file: {path}")
    if reject_hardlink and info.st_nlink != 1:
        raise SafeIOError(f"{context} must not be hardlinked: {path}")
    if max_bytes is not None and info.st_size > max_bytes:
        raise SafeIOError(f"{context} exceeds maximum size: {path}")
    return info


def lstat_regular_file(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> os.stat_result:
    return require_regular_file(
        path,
        context,
        reject_symlink=reject_symlink,
        reject_hardlink=reject_hardlink,
        max_bytes=max_bytes,
    )


def reject_group_world_readable(path: Path, context: str) -> None:
    info = lstat_regular_file(path, context, reject_symlink=True)
    if info.st_mode & 0o077:
        raise SafeIOError(f"{context} must not be group/world accessible: {path}")


def read_regular_bytes(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> bytes:
    lstat_regular_file(
        path,
        context,
        reject_symlink=reject_symlink,
        reject_hardlink=reject_hardlink,
        max_bytes=max_bytes,
    )
    flags = os.O_RDONLY | _cloexec()
    if reject_symlink:
        flags |= _nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SafeIOError(f"could not open {context}: {path}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SafeIOError(f"{context} must be a regular file: {path}")
        if reject_hardlink and info.st_nlink != 1:
            raise SafeIOError(f"{context} must not be hardlinked: {path}")
        if max_bytes is not None and info.st_size > max_bytes:
            raise SafeIOError(f"{context} exceeds maximum size: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise SafeIOError(f"{context} exceeds maximum size: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_regular_ascii(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> str:
    data = read_regular_bytes(
        path,
        context,
        reject_symlink=reject_symlink,
        reject_hardlink=reject_hardlink,
        max_bytes=max_bytes,
    )
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SafeIOError(f"{context} is not ASCII") from exc


def _hash_file(path: Path, algorithm: str, context: str) -> str:
    digest = hashlib.new(algorithm)
    data = read_regular_bytes(path, context, reject_symlink=True)
    digest.update(data)
    return digest.hexdigest()


def sha256_file(path: Path, context: str = "file") -> str:
    return _hash_file(path, "sha256", context)


def sha384_file(path: Path, context: str = "file") -> str:
    return _hash_file(path, "sha384", context)


def sha512_file(path: Path, context: str = "file") -> str:
    return _hash_file(path, "sha512", context)


def write_new_bytes(
    path: Path,
    data: bytes,
    context: str,
    *,
    mode: int = 0o600,
    fsync_parent: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise SafeIOError(f"could not create new {context}: {path}") from exc
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise SafeIOError(f"could not set {context} mode: {path}") from exc
    if fsync_parent:
        _fsync_parent(path)


def write_new_text(
    path: Path,
    text: str,
    context: str,
    *,
    mode: int = 0o600,
    fsync_parent: bool = True,
) -> None:
    write_new_bytes(
        path,
        text.encode("ascii"),
        context,
        mode=mode,
        fsync_parent=fsync_parent,
    )


def write_json_new(
    path: Path,
    value: dict[str, Any],
    context: str,
    *,
    mode: int = 0o600,
    fsync_parent: bool = True,
) -> None:
    write_new_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        context,
        mode=mode,
        fsync_parent=fsync_parent,
    )


def atomic_replace_text(
    path: Path,
    text: str,
    context: str,
    *,
    mode: int = 0o600,
    fsync_parent: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="ascii",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        if fsync_parent:
            _fsync_parent(path)
    except OSError as exc:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise SafeIOError(f"could not atomically write {context}: {path}") from exc


def reject_private_markers_bytes(
    data: bytes,
    context: str,
    markers: Iterable[str],
) -> None:
    for marker in markers:
        if marker.encode("ascii") in data:
            raise SafeIOError(f"{context} contains private material marker: {marker}")


def require_private_file_mode(path: Path, context: str) -> None:
    reject_group_world_readable(path, context)
