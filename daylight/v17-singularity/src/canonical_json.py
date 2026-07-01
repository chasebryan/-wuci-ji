"""Strict canonical JSON helpers for Daylight v17 Singularity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class CanonicalJSONError(ValueError):
    pass


def _reject_float(value: str) -> None:
    raise CanonicalJSONError(f"floats are not allowed: {value}")


def _reject_constant(value: str) -> None:
    raise CanonicalJSONError(f"non-finite number is not allowed: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalJSONError(f"duplicate map key: {key}")
        out[key] = value
    return out


def load_json_text(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_object_pairs,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )


def load_json_path(path: Path | str) -> Any:
    return load_json_text(Path(path).read_text(encoding="utf-8"))


def reject_float(value: Any, path: str = "value") -> None:
    if isinstance(value, float):
        raise CanonicalJSONError(f"float rejected at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_float(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_float(item, f"{path}[{index}]")


def canonical_bytes(obj: Any) -> bytes:
    reject_float(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(obj: Any, domain: str) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(canonical_bytes(obj))
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(obj: Any) -> bytes:
    reject_float(obj)
    return (json.dumps(obj, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")

