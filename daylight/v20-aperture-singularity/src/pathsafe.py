"""Repository-relative path validation for v20 public evidence contexts."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path, PurePosixPath


class PathSafetyError(ValueError):
    pass


def normalize_repo_relative(path_text: str | Path) -> str:
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
        if part in ("", ".", ".."):
            raise PathSafetyError(f"path traversal rejected: {text}")
        if part.startswith("."):
            raise PathSafetyError(f"hidden path component rejected: {text}")
    return str(path)


def resolve_under_base(rel_path: str, base_dir: Path | str) -> Path:
    normalized = normalize_repo_relative(rel_path)
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


def require_regular_public_file(path: Path, label: str, *, reject_hardlink: bool = True) -> os.stat_result:
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


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_file_dual(path: Path | str) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    sha3_512 = hashlib.sha3_512()
    size = 0
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha3_512.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), sha3_512.hexdigest(), size


def atomic_write_bytes(path: Path | str, data: bytes, *, force: bool = False, mode: int = 0o644) -> None:
    target = Path(path)
    if target.is_symlink():
        raise PathSafetyError(f"refusing to write through symlink: {target}")
    if target.exists() and not force:
        raise PathSafetyError(f"refusing to overwrite existing output without --force: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=target.name + ".", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
