"""Registry loading and matching for DaylightNPT v1."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .extract import NumberToken


SUPPORTED_CHECKS = frozenset(
    {
        "json_equals",
        "json_ratio_percent",
        "contains_all",
        "digest_format",
        "digest_equals",
        "quorum_contract",
        "version_path_consistency",
        "exact_text_non_claim",
        "exempt_with_rationale",
    }
)


class RegistryError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_registry(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError(f"registry JSON invalid: {exc}") from exc
    validate_registry(data)
    return data


def validate_registry(registry: dict[str, Any]) -> None:
    if not isinstance(registry, dict):
        raise RegistryError("registry must be an object")
    if registry.get("schema") != "daylight.npt.v1.registry":
        raise RegistryError("registry schema must be daylight.npt.v1.registry")
    if registry.get("version") != "1":
        raise RegistryError("registry version must be 1")
    claims = registry.get("claims")
    if not isinstance(claims, list):
        raise RegistryError("registry claims must be a list")
    seen: set[str] = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise RegistryError("registry claim must be an object")
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id:
            raise RegistryError("registry claim id missing")
        if claim_id in seen:
            raise RegistryError(f"duplicate registry claim id: {claim_id}")
        seen.add(claim_id)
        if claim.get("status") not in {"verified", "non_claim", "illustrative", "exempt"}:
            raise RegistryError(f"claim {claim_id} status invalid")
        if claim.get("claim_type") not in {"score", "percent", "quorum", "version", "digest", "count", "date", "other"}:
            raise RegistryError(f"claim {claim_id} claim_type invalid")
        allowed_files = claim.get("allowed_files")
        if not isinstance(allowed_files, list) or not all(isinstance(item, str) for item in allowed_files):
            raise RegistryError(f"claim {claim_id} allowed_files invalid")
        if not isinstance(claim.get("context_regex"), str):
            raise RegistryError(f"claim {claim_id} context_regex invalid")
        check = claim.get("check")
        if check not in SUPPORTED_CHECKS:
            raise RegistryError(f"claim {claim_id} unsupported check: {check}")
        if claim.get("claim_type") == "score" and claim.get("status") == "verified":
            evidence = claim.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                raise RegistryError(f"score claim {claim_id} requires generated evidence")
        if claim.get("status") in {"non_claim", "illustrative", "exempt"}:
            rationale = claim.get("rationale")
            if not isinstance(rationale, str) or not rationale.strip():
                raise RegistryError(f"exemption claim {claim_id} requires rationale")
            if not allowed_files or any(item in {"*", "**"} for item in allowed_files):
                raise RegistryError(f"exemption claim {claim_id} allowed_files too broad")
            if any(item.endswith("/") or "**" in item for item in allowed_files):
                raise RegistryError(f"exemption claim {claim_id} path coverage too broad")
            if claim["context_regex"].strip() in {".*", "^.*$", ".+", "^.+$"}:
                raise RegistryError(f"exemption claim {claim_id} context_regex too broad")


def pointer_get(data: Any, pointer: str) -> Any:
    if pointer in ("", "/"):
        return data
    if not pointer.startswith("/"):
        raise RegistryError(f"invalid JSON pointer: {pointer}")
    current = data
    for part in pointer.strip("/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise RegistryError(f"JSON pointer crosses scalar: {pointer}")
    return current


def file_allowed(patterns: list[str], path: str) -> bool:
    return any(pattern == path or pattern == "*" for pattern in patterns)


def matching_claims(registry: dict[str, Any], token: NumberToken) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for claim in registry.get("claims", []):
        if not file_allowed(claim["allowed_files"], token.path):
            continue
        raw = str(claim.get("value_raw", ""))
        canonical = str(claim.get("value_canonical", ""))
        if raw and raw != token.value_raw:
            continue
        if canonical and canonical != token.value_canonical:
            continue
        if not re.search(claim["context_regex"], token.context):
            continue
        matches.append(claim)
    return matches
