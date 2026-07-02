"""Falsification corpus evaluation for v20."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .boundary_debt import REQUIRED_NON_CLAIMS
from .canonical import canonical_sha256, load_json_no_floats, reject_floats_recursive

SCHEMA_ID = "daylight-v20-falsification-survival-bundle"
SCHEMA_VERSION = "0.1.0"
D_RESULT = "DAYLIGHT-v20-FALSIFICATION-RESULT:"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
PASSING_OUTCOMES = {"rejected", "blocked"}

REQUIRED_CASES: list[tuple[str, str]] = [
    ("digest_edit", "digest edit"),
    ("manifest_edit", "manifest edit"),
    ("public_file_drift", "public file drift"),
    ("hidden_file", "hidden file"),
    ("symlink", "symlink"),
    ("hardlink", "hardlink"),
    ("private_filename", "private filename"),
    ("private_directory", "private directory"),
    ("private_content_marker", "private content marker"),
    ("path_traversal", "path traversal"),
    ("absolute_path", "absolute path"),
    ("duplicate_json_key", "duplicate JSON key"),
    ("json_float", "JSON float"),
    ("manual_score_edit", "manual score edit"),
    ("fixture_laundering", "fixture laundering"),
    ("fake_external_attestation", "fake external attestation"),
    ("self_signed_external_closure", "self-signed external closure"),
    ("reserved_perfect_am_plus_value", "reserved perfect AM+ value"),
    ("verifier_vector_mismatch", "verifier vector mismatch"),
    ("duplicate_verifier_family", "duplicate verifier family"),
    ("critical_boundary_debt", "critical boundary debt"),
]


class FalsificationError(ValueError):
    pass


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise FalsificationError(f"{name} must be a non-empty string")
    return value


def _require_hex64(value: Any, name: str) -> str:
    text = _require_str(value, name)
    if not HEX64_RE.fullmatch(text):
        raise FalsificationError(f"{name} must be a lowercase SHA-256 hex digest")
    return text


def result_digest(result: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "case_id": result["case_id"],
            "description": result["description"],
            "outcome": result["outcome"],
        },
        D_RESULT,
    )


def evaluate_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    reject_floats_recursive(bundle, "falsification")
    if not isinstance(bundle, dict):
        raise FalsificationError("falsification bundle must be an object")
    required = {
        "schema_id",
        "schema_version",
        "fixture",
        "claim_usable",
        "authority_scope",
        "non_claims_acknowledged",
        "results",
    }
    if set(bundle) != required:
        raise FalsificationError("falsification bundle field set invalid")
    if bundle["schema_id"] != SCHEMA_ID or bundle["schema_version"] != SCHEMA_VERSION:
        raise FalsificationError("unsupported falsification bundle schema")
    if not isinstance(bundle["fixture"], bool):
        raise FalsificationError("fixture must be boolean")
    if not isinstance(bundle["claim_usable"], bool):
        raise FalsificationError("claim_usable must be boolean")
    if bundle["authority_scope"] != "repo-owned-negative-corpus":
        raise FalsificationError("authority_scope must remain repo-owned-negative-corpus")
    acknowledged = bundle["non_claims_acknowledged"]
    if not isinstance(acknowledged, list):
        raise FalsificationError("non_claims_acknowledged must be a list")
    for item in acknowledged:
        _require_str(item, "non_claims_acknowledged item")
    results = bundle["results"]
    if not isinstance(results, list):
        raise FalsificationError("results must be a list")

    blockers: list[str] = []
    by_case: dict[str, dict[str, Any]] = {}
    digest_ok_by_case: dict[str, bool] = {}
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise FalsificationError(f"results[{index}] must be an object")
        reject_floats_recursive(result, f"results[{index}]")
        required_fields = {"case_id", "description", "outcome", "evidence_digest"}
        if set(result) != required_fields:
            raise FalsificationError(f"results[{index}] field set invalid")
        case_id = _require_str(result["case_id"], f"results[{index}].case_id")
        _require_str(result["description"], f"results[{index}].description")
        outcome = _require_str(result["outcome"], f"results[{index}].outcome")
        _require_hex64(result["evidence_digest"], f"results[{index}].evidence_digest")
        if case_id in by_case:
            raise FalsificationError(f"duplicate falsification case: {case_id}")
        digest_ok = result["evidence_digest"] == result_digest(result)
        if not digest_ok:
            blockers.append(f"falsification evidence digest mismatch: {case_id}")
        if outcome not in PASSING_OUTCOMES:
            blockers.append(f"falsification case did not fail closed: {case_id}")
        by_case[case_id] = result
        digest_ok_by_case[case_id] = digest_ok

    if bundle["fixture"] is True:
        blockers.append("falsification corpus is fixture evidence")
    if bundle["claim_usable"] is not True:
        blockers.append("falsification corpus is not claim-usable")
    if not REQUIRED_NON_CLAIMS.issubset(set(acknowledged)):
        blockers.append("falsification corpus non-claims incomplete")

    atoms: dict[str, bool] = {}
    for case_id, _description in REQUIRED_CASES:
        result = by_case.get(case_id)
        atoms[case_id] = (
            result is not None
            and result.get("outcome") in PASSING_OUTCOMES
            and digest_ok_by_case.get(case_id) is True
        )
        if result is None:
            blockers.append(f"missing falsification case: {case_id}")

    return {
        "schema_id": SCHEMA_ID,
        "passed": not blockers,
        "blockers": blockers,
        "fixture": bundle["fixture"],
        "claim_usable": bundle["claim_usable"],
        "required_case_count": len(REQUIRED_CASES),
        "present_case_count": sum(1 for case_id, _ in REQUIRED_CASES if case_id in by_case),
        "survived_case_count": sum(1 for case_id, _ in REQUIRED_CASES if atoms[case_id]),
        "atoms": atoms,
    }


def load_and_evaluate(path: Path | str) -> dict[str, Any]:
    return evaluate_bundle(load_json_no_floats(path))
