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


def _reject_symlink_ancestor(path: Path, context: str) -> None:
    parent = path.parent
    if not parent:
        return
    current = Path(parent.anchor) if parent.is_absolute() else Path(".")
    parts = parent.parts
    if parent.is_absolute():
        parts = parts[1:]
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SafeIOError(f"could not stat {context} parent: {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise SafeIOError(f"{context} parent must not be a symlink: {current}")
        if not stat.S_ISDIR(info.st_mode):
            raise SafeIOError(f"{context} parent must be a directory: {current}")


def ensure_parent_directory(path: Path, context: str, *, mode: int = 0o700) -> None:
    _reject_symlink_ancestor(path, context)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=mode)
    except OSError as exc:
        raise SafeIOError(f"could not create {context} parent: {path.parent}") from exc
    _reject_symlink_ancestor(path, context)


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
    expected = lstat_regular_file(
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
        if (expected.st_dev, expected.st_ino) != (info.st_dev, info.st_ino):
            raise SafeIOError(f"{context} changed while being opened: {path}")
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


def iter_regular_chunks(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
    chunk_size: int = 1024 * 1024,
) -> Iterable[bytes]:
    expected = lstat_regular_file(
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
        if (expected.st_dev, expected.st_ino) != (info.st_dev, info.st_ino):
            raise SafeIOError(f"{context} changed while being opened: {path}")
        if reject_hardlink and info.st_nlink != 1:
            raise SafeIOError(f"{context} must not be hardlinked: {path}")
        if max_bytes is not None and info.st_size > max_bytes:
            raise SafeIOError(f"{context} exceeds maximum size: {path}")
        total = 0
        while True:
            chunk = os.read(fd, chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise SafeIOError(f"{context} exceeds maximum size: {path}")
            yield chunk
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


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SafeIOError(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def loads_json_no_duplicates(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
    except SafeIOError:
        raise
    except json.JSONDecodeError as exc:
        raise SafeIOError(f"{context} is not valid JSON: {exc.msg}") from exc


def read_regular_json(
    path: Path,
    context: str,
    *,
    reject_symlink: bool = True,
    reject_hardlink: bool = False,
    max_bytes: int | None = None,
) -> Any:
    data = read_regular_bytes(
        path,
        context,
        reject_symlink=reject_symlink,
        reject_hardlink=reject_hardlink,
        max_bytes=max_bytes,
    )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SafeIOError(f"{context} is not UTF-8") from exc
    return loads_json_no_duplicates(text, context)


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
    ensure_parent_directory(path, context)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise SafeIOError(f"could not create new {context}: {path}") from exc
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
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
    ensure_parent_directory(path, context)
    try:
        target_info = os.lstat(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SafeIOError(f"could not stat {context}: {path}") from exc
    else:
        if stat.S_ISLNK(target_info.st_mode):
            raise SafeIOError(f"{context} target must not be a symlink: {path}")
        if not stat.S_ISREG(target_info.st_mode):
            raise SafeIOError(f"{context} target must be a regular file: {path}")
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
