"""Canonical JSON and domain-separated SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
