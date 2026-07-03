"""Evidence checks for DaylightNPT v1 registry claims."""

from __future__ import annotations

import json
import re
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from .registry import RegistryError, pointer_get, sha256_file

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError(f"evidence JSON invalid: {path}: {exc}") from exc


def _evidence_path(root: Path, entry: dict[str, Any]) -> Path:
    raw = entry.get("path")
    if not isinstance(raw, str) or not raw:
        raise RegistryError("evidence path missing")
    path = root / raw
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise RegistryError(f"evidence path escapes repository: {raw}") from exc
    if not path.is_file():
        raise RegistryError(f"evidence path missing: {raw}")
    expected_sha = entry.get("sha256")
    if expected_sha:
        if sha256_file(path) != expected_sha:
            raise RegistryError(f"evidence sha256 mismatch: {raw}")
    return path


def digest_literal_valid(value: str) -> bool:
    compact = value.split(":", 1)[-1].split("=", 1)[-1].strip()
    compact = compact.split()[-1] if compact.split() else compact
    if "sha3" in value.lower():
        return len(compact) == 128 and bool(HEX_RE.fullmatch(compact))
    return len(compact) == 64 and bool(HEX_RE.fullmatch(compact))


def evaluate_claim(claim: dict[str, Any], repo_root: Path) -> tuple[bool, str]:
    check = claim["check"]
    evidence = claim.get("evidence", [])
    if check in {"exact_text_non_claim", "exempt_with_rationale", "version_path_consistency"}:
        return True, "registry exemption accepted"
    if check == "digest_format":
        return digest_literal_valid(str(claim.get("value_raw", ""))), "digest format check"
    if not isinstance(evidence, list) or not evidence:
        return False, "claim has no evidence entries"

    try:
        if check == "json_equals":
            entry = evidence[0]
            data = _load_json(_evidence_path(repo_root, entry))
            value = pointer_get(data, entry.get("json_pointer", ""))
            return str(value) == str(entry.get("expected_value")), "json_equals"
        if check == "json_ratio_percent":
            entry = evidence[0]
            data = _load_json(_evidence_path(repo_root, entry))
            numerator = Decimal(str(pointer_get(data, entry["numerator_pointer"])))
            denominator = Decimal(str(pointer_get(data, entry["denominator_pointer"])))
            precision = int(entry.get("precision", 2))
            percent = (numerator / denominator * Decimal("100")).quantize(
                Decimal("1").scaleb(-precision), rounding=ROUND_HALF_UP
            )
            return str(percent) == str(entry.get("expected_value")), "json_ratio_percent"
        if check == "contains_all":
            entry = evidence[0]
            text = _evidence_path(repo_root, entry).read_text(encoding="utf-8")
            return all(str(item) in text for item in entry.get("contains", [])), "contains_all"
        if check == "digest_equals":
            entry = evidence[0]
            actual = sha256_file(_evidence_path(repo_root, entry))
            return actual == str(entry.get("expected_value")), "digest_equals"
        if check == "quorum_contract":
            entry = evidence[0]
            data = _load_json(_evidence_path(repo_root, entry))
            value = pointer_get(data, entry.get("json_pointer", ""))
            return str(value) == str(entry.get("expected_value")), "quorum_contract"
    except (KeyError, ValueError, TypeError, RegistryError) as exc:
        return False, str(exc)
    return False, f"unsupported evidence check: {check}"
