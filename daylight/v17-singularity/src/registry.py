"""Daylight v17 Singularity field registry validation."""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any

from .canonical_json import canonical_sha256, load_json_no_floats, reject_python_floats
from .singularity_math import (
    B,
    DECLARATION_TARGET_AM_PLUS,
    EPSILON_DENOMINATOR,
    PERFECT_RESERVED_AM_PLUS,
    UNIT,
    parse_rational_alpha,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIELDS_PATH = PACKAGE_ROOT / "rules" / "fields.v17.json"
D_FIELDS = "DAYLIGHT-v17-SINGULARITY-FIELDS:"
FIELDS_VERSION = "daylight-v17-singularity-fields-v0.1"
FIELD_IDS = [f"F{index}" for index in range(1, 11)]
FIELD_NAMES = [
    "ClaimClosure",
    "SelfProgress",
    "HermeticArtifact",
    "ReplayDepth",
    "MultiImplementation",
    "AdversarialFuzzing",
    "FormalProof",
    "CryptoConstruction",
    "PublicFalsification",
    "BoundaryDiscipline",
]
EXPECTED_ALPHA = ["1/1", "5/4", "3/2", "5/4", "3/2", "5/4", "3/2", "3/2", "5/4", "3/2"]
EXPECTED_ALPHA_SUM = Fraction(27, 2)


class RegistryError(ValueError):
    pass


def load_fields_registry(path: Path | str = DEFAULT_FIELDS_PATH) -> dict[str, Any]:
    registry = load_json_no_floats(path)
    validate_fields_registry(registry)
    return registry


def validate_fields_registry(registry: dict[str, Any]) -> None:
    reject_python_floats(registry, "fields_registry")
    if registry.get("version") != FIELDS_VERSION:
        raise RegistryError("unsupported Daylight v17 field registry version")
    if registry.get("unit") != UNIT:
        raise RegistryError("field registry unit mismatch")
    if registry.get("scale") != B:
        raise RegistryError("field registry scale mismatch")
    if registry.get("perfect_reserved") != PERFECT_RESERVED_AM_PLUS:
        raise RegistryError("field registry perfect reserve mismatch")
    if registry.get("declaration_target") != DECLARATION_TARGET_AM_PLUS:
        raise RegistryError("field registry declaration target mismatch")
    if registry.get("epsilon_denominator") != EPSILON_DENOMINATOR:
        raise RegistryError("field registry epsilon denominator mismatch")
    fields = registry.get("fields")
    if not isinstance(fields, list) or len(fields) != 10:
        raise RegistryError("field registry must contain exactly ten fields")
    alpha_sum = Fraction(0, 1)
    seen: set[str] = set()
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            raise RegistryError("field registry entries must be objects")
        expected_id = FIELD_IDS[index]
        expected_name = FIELD_NAMES[index]
        expected_alpha = EXPECTED_ALPHA[index]
        if field.get("id") != expected_id:
            raise RegistryError(f"field {index + 1} id must be {expected_id}")
        if field.get("name") != expected_name:
            raise RegistryError(f"{expected_id} name must be {expected_name}")
        if field["id"] in seen:
            raise RegistryError(f"duplicate field id: {field['id']}")
        seen.add(field["id"])
        if field.get("alpha") != expected_alpha:
            raise RegistryError(f"{expected_id} alpha must be {expected_alpha}")
        alpha_sum += parse_rational_alpha(field.get("alpha"))
        if not isinstance(field.get("description"), str) or not field["description"]:
            raise RegistryError(f"{expected_id} requires a description")
    if alpha_sum != EXPECTED_ALPHA_SUM:
        raise RegistryError("field alpha sum must equal 27/2")


def alpha_sum(registry: dict[str, Any]) -> Fraction:
    validate_fields_registry(registry)
    total = Fraction(0, 1)
    for field in registry["fields"]:
        total += parse_rational_alpha(field["alpha"])
    return total


def proof_registry_digest(registry: dict[str, Any]) -> str:
    validate_fields_registry(registry)
    return canonical_sha256(registry, D_FIELDS)

