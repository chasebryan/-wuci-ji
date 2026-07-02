"""Canonical JSON helpers for Daylight v19 Aperture Bastion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def reject_float(value: str) -> None:
    raise ValueError(f"JSON floats are not allowed: {value}")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON map key: {key}")
        out[key] = value
    return out


def loads_json_no_floats(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_object_pairs,
        parse_float=reject_float,
        parse_constant=_reject_constant,
    )


def load_json_no_floats(path: Path | str) -> Any:
    return loads_json_no_floats(Path(path).read_text(encoding="utf-8"))


def reject_floats_recursive(value: Any, path: str = "value") -> None:
    if isinstance(value, float):
        raise ValueError(f"Python float rejected at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_floats_recursive(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_floats_recursive(item, f"{path}[{index}]")


def dumps_canonical(obj: Any) -> bytes:
    reject_floats_recursive(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(obj: Any, domain: str) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(dumps_canonical(obj))
    return digest.hexdigest()


def json_bytes(obj: Any) -> bytes:
    reject_floats_recursive(obj)
    return (json.dumps(obj, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
