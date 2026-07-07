"""Path safety, hashing, and atomic-write helpers for Aperture Bastion."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath


class PathSafetyError(ValueError):
    pass


def normalize_rel_path(path_text: str | Path) -> str:
    text = str(path_text)
    if "\\" in text or "\x00" in text:
        raise PathSafetyError("path must not contain backslash or NUL")
    if len(text) >= 2 and text[1] == ":":
        raise PathSafetyError(f"drive-letter path rejected: {text}")
    path = PurePosixPath(text)
    if path.is_absolute():
        raise PathSafetyError(f"absolute path rejected: {text}")
    if not path.parts or str(path) == ".":
        raise PathSafetyError("empty path rejected")
    for part in path.parts:
        if part in ("..", "."):
            raise PathSafetyError(f"path traversal rejected: {text}")
    return str(path)


def resolve_under_base(rel_path: str, base_dir: Path | str) -> Path:
    normalized = normalize_rel_path(rel_path)
    base = Path(base_dir).resolve()
    current = base
    for part in PurePosixPath(normalized).parts:
        current = current / part
        if current.is_symlink():
            raise PathSafetyError(f"symlink component rejected: {normalized}")
    resolved = current.resolve()
    if resolved != base and base not in resolved.parents:
        raise PathSafetyError(f"path escapes base directory: {normalized}")
    return current


def require_regular_file(path: Path, label: str, *, reject_hardlink: bool = True) -> os.stat_result:
    try:
        st = path.lstat()
    except OSError as exc:
        raise PathSafetyError(f"unreadable file: {label}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise PathSafetyError(f"symlink rejected: {label}")
    if not stat.S_ISREG(st.st_mode):
        raise PathSafetyError(f"not a regular file: {label}")
    if reject_hardlink and st.st_nlink > 1:
        raise PathSafetyError(f"hardlink rejected: {label}")
    return st


def read_public_bytes(
    path: Path | str,
    label: str,
    *,
    max_bytes: int | None = None,
    reject_hardlink: bool = True,
) -> bytes:
    target = Path(path)
    before = require_regular_file(target, label, reject_hardlink=reject_hardlink)
    if max_bytes is not None and before.st_size > max_bytes:
        raise PathSafetyError(f"{label} exceeds size limit: {target}")
    try:
        with target.open("rb") as handle:
            after = os.fstat(handle.fileno())
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise PathSafetyError(f"{label} changed while opening: {target}")
            chunks: list[bytes] = []
            total = 0
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise PathSafetyError(f"{label} exceeds size limit: {target}")
                chunks.append(chunk)
            return b"".join(chunks)
    except OSError as exc:
        raise PathSafetyError(f"could not read {label}: {target}: {exc}") from exc


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    target = Path(path)
    before = require_regular_file(target, str(target))
    with target.open("rb") as handle:
        after = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise PathSafetyError(f"file changed while opening: {target}")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_file_dual(path: Path | str) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    sha3_512 = hashlib.sha3_512()
    size = 0
    target = Path(path)
    before = require_regular_file(target, str(target))
    with target.open("rb") as handle:
        after = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise PathSafetyError(f"file changed while opening: {target}")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha3_512.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), sha3_512.hexdigest(), size


def atomic_write_bytes(path: Path | str, data: bytes, *, force: bool = False, mode: int = 0o644) -> None:
    path = Path(path)
    current = path.parent
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise PathSafetyError(f"output parent must not be a symlink: {current}")
        current = current.parent
    if path.exists() or path.is_symlink():
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            raise PathSafetyError(f"refusing to write through symlink: {path}")
        if not stat.S_ISREG(st.st_mode):
            raise PathSafetyError(f"refusing to overwrite non-regular output: {path}")
        if not force:
            raise PathSafetyError(f"refusing to overwrite existing output without --force: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
