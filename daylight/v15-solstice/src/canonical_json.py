"""Canonical JSON and domain-separated SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from typing import Any


class CanonicalJSONError(ValueError):
    """Security-sensitive JSON input was ambiguous or unsafe to read."""


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalJSONError(f"duplicate JSON key rejected: {key}")
        out[key] = value
    return out


def loads_json_no_duplicates(text: str | bytes, context: str) -> Any:
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs)
    except UnicodeDecodeError as exc:
        raise CanonicalJSONError(f"{context} is not UTF-8 JSON: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalJSONError(f"{context} is not valid JSON: {exc}") from exc


def read_regular_bytes(path: Any, context: str, *, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    path = os.fspath(path)
    try:
        expected = os.lstat(path)
    except OSError as exc:
        raise CanonicalJSONError(f"{context} is unreadable: {path}") from exc
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
        raise CanonicalJSONError(f"{context} must be a regular non-symlink file: {path}")
    if expected.st_nlink != 1:
        raise CanonicalJSONError(f"{context} must not be hardlinked: {path}")
    if expected.st_size > max_bytes:
        raise CanonicalJSONError(f"{context} exceeds {max_bytes} bytes: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise CanonicalJSONError(f"{context} changed while opening: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise CanonicalJSONError(f"{context} exceeds {max_bytes} bytes: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_json_file_no_duplicates(path: Any, context: str) -> Any:
    return loads_json_no_duplicates(read_regular_bytes(path, context), context)


def canonical_bytes(obj: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(obj: Any, domain: str) -> str:
    if not isinstance(domain, str) or not domain:
        raise ValueError("domain must be a non-empty string")
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(canonical_bytes(obj))
    return digest.hexdigest()
