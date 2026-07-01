"""Deterministic canonical encoding for the D16-AWE executable slice."""

from __future__ import annotations

import json
from typing import Any

from .errors import D16AWEError

BYTES_TAG = "__daylight_bytes_hex__"


class CanonicalError(D16AWEError):
    """Value cannot be represented in deterministic canonical Daylight form."""


def _reject_float(value: str) -> None:
    raise CanonicalError(f"floats are not allowed in D16-AWE JSON: {value}")


def _reject_constant(value: str) -> None:
    raise CanonicalError(f"non-finite number is not allowed in D16-AWE JSON: {value}")


def load_json(text: str) -> Any:
    """Load JSON while rejecting duplicate keys, floats, NaN, and infinities."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise CanonicalError(f"duplicate map key: {key}")
            out[key] = value
        return out

    return json.loads(
        text,
        object_pairs_hook=object_pairs,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )


def normalize(value: Any) -> Any:
    """Normalize supported Python values into unique JSON-compatible form."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalError("floats are not allowed")
    if isinstance(value, bytes):
        return {BYTES_TAG: value.hex()}
    if isinstance(value, bytearray):
        return {BYTES_TAG: bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("canonical map keys must be strings")
            if key in out:
                raise CanonicalError(f"duplicate map key: {key}")
            out[key] = normalize(item)
        return out
    raise CanonicalError(f"unsupported canonical value type: {type(value).__name__}")


def dumps(value: Any) -> str:
    """Return canonical JSON text."""
    normalized = normalize(value)
    return json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def encode(value: Any) -> bytes:
    """Return canonical bytes."""
    return dumps(value).encode("utf-8")


def require_keys(obj: dict[str, Any], *, required: set[str], optional: set[str] = frozenset()) -> None:
    missing = sorted(required - set(obj))
    if missing:
        raise CanonicalError("missing required field(s): " + ", ".join(missing))
    allowed = required | optional
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise CanonicalError("unknown critical field(s): " + ", ".join(unknown))
