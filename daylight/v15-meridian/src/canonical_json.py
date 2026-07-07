"""Canonical JSON and domain-separated SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalJSONError(ValueError):
    """JSON input is not canonical enough for security-sensitive proof reads."""


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
