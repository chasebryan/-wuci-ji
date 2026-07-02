"""Reproducible build receipt evaluation for v20."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .boundary_debt import REQUIRED_NON_CLAIMS
from .canonical import canonical_sha256, load_json_no_floats, reject_floats_recursive

SCHEMA_ID = "daylight-v20-reproducible-build-bundle"
SCHEMA_VERSION = "0.1.0"
D_RECEIPT = "DAYLIGHT-v20-REPRODUCIBLE-BUILD-RECEIPT:"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
REQUIRED_RECEIPT_FIELDS = {
    "receipt_id",
    "builder_id",
    "builder_family",
    "environment_digest",
    "source_commit",
    "build_instructions_digest",
    "artifact_sha256",
    "artifact_sha3_512",
    "artifact_size",
    "byte_identical_output",
    "receipt_digest",
}


class ReproducibleBuildError(ValueError):
    pass


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReproducibleBuildError(f"{name} must be a non-empty string")
    return value


def _require_hex(value: Any, name: str, regex: re.Pattern[str]) -> str:
    text = _require_str(value, name)
    if not regex.fullmatch(text):
        raise ReproducibleBuildError(f"{name} must be a lowercase hex digest of expected length")
    return text


def _validate_receipt(receipt: dict[str, Any], index: int) -> None:
    if not isinstance(receipt, dict):
        raise ReproducibleBuildError(f"receipts[{index}] must be an object")
    reject_floats_recursive(receipt, f"receipts[{index}]")
    if set(receipt) != REQUIRED_RECEIPT_FIELDS:
        raise ReproducibleBuildError(f"receipts[{index}] field set invalid")
    for key in ("receipt_id", "builder_id", "builder_family"):
        _require_str(receipt[key], f"receipts[{index}].{key}")
    _require_hex(receipt["environment_digest"], f"receipts[{index}].environment_digest", HEX64_RE)
    _require_hex(receipt["source_commit"], f"receipts[{index}].source_commit", HEX40_RE)
    _require_hex(receipt["build_instructions_digest"], f"receipts[{index}].build_instructions_digest", HEX64_RE)
    _require_hex(receipt["artifact_sha256"], f"receipts[{index}].artifact_sha256", HEX64_RE)
    _require_hex(receipt["artifact_sha3_512"], f"receipts[{index}].artifact_sha3_512", HEX128_RE)
    if isinstance(receipt["artifact_size"], bool) or not isinstance(receipt["artifact_size"], int) or receipt["artifact_size"] < 0:
        raise ReproducibleBuildError(f"receipts[{index}].artifact_size must be a nonnegative integer")
    if not isinstance(receipt["byte_identical_output"], bool):
        raise ReproducibleBuildError(f"receipts[{index}].byte_identical_output must be boolean")
    _require_hex(receipt["receipt_digest"], f"receipts[{index}].receipt_digest", HEX64_RE)


def receipt_digest(receipt: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "receipt_id": receipt["receipt_id"],
            "builder_id": receipt["builder_id"],
            "builder_family": receipt["builder_family"],
            "environment_digest": receipt["environment_digest"],
            "source_commit": receipt["source_commit"],
            "build_instructions_digest": receipt["build_instructions_digest"],
            "artifact_sha256": receipt["artifact_sha256"],
            "artifact_sha3_512": receipt["artifact_sha3_512"],
            "artifact_size": receipt["artifact_size"],
            "byte_identical_output": receipt["byte_identical_output"],
        },
        D_RECEIPT,
    )


def _optional_expected(value: Any, name: str, regex: re.Pattern[str] | None = None) -> str | None:
    if value is None:
        return None
    text = _require_str(value, name)
    if regex is not None and not regex.fullmatch(text):
        raise ReproducibleBuildError(f"{name} must be a lowercase hex digest of expected length")
    return text


def evaluate_bundle(
    bundle: dict[str, Any],
    *,
    expected_source_commit: Any = None,
    expected_artifact_sha256: Any = None,
    expected_artifact_sha3_512: Any = None,
    expected_artifact_size: Any = None,
) -> dict[str, Any]:
    reject_floats_recursive(bundle, "reproducible_builds")
    if not isinstance(bundle, dict):
        raise ReproducibleBuildError("reproducible build bundle must be an object")
    required = {
        "schema_id",
        "schema_version",
        "fixture",
        "claim_usable",
        "authority_scope",
        "non_claims_acknowledged",
        "receipts",
    }
    if set(bundle) != required:
        raise ReproducibleBuildError("reproducible build bundle field set invalid")
    if bundle["schema_id"] != SCHEMA_ID or bundle["schema_version"] != SCHEMA_VERSION:
        raise ReproducibleBuildError("unsupported reproducible build bundle schema")
    if not isinstance(bundle["fixture"], bool):
        raise ReproducibleBuildError("fixture must be boolean")
    if not isinstance(bundle["claim_usable"], bool):
        raise ReproducibleBuildError("claim_usable must be boolean")
    _require_str(bundle["authority_scope"], "authority_scope")
    acknowledged = bundle["non_claims_acknowledged"]
    if not isinstance(acknowledged, list):
        raise ReproducibleBuildError("non_claims_acknowledged must be a list")
    for item in acknowledged:
        _require_str(item, "non_claims_acknowledged item")
    expected_source = _optional_expected(expected_source_commit, "expected_source_commit", HEX40_RE)
    expected_sha256 = _optional_expected(expected_artifact_sha256, "expected_artifact_sha256", HEX64_RE)
    expected_sha3 = _optional_expected(expected_artifact_sha3_512, "expected_artifact_sha3_512", HEX128_RE)
    if expected_artifact_size is not None and (
        isinstance(expected_artifact_size, bool)
        or not isinstance(expected_artifact_size, int)
        or expected_artifact_size < 0
    ):
        raise ReproducibleBuildError("expected_artifact_size must be a nonnegative integer")
    receipts = bundle["receipts"]
    if not isinstance(receipts, list):
        raise ReproducibleBuildError("receipts must be a list")

    blockers: list[str] = []
    valid_receipts: list[dict[str, Any]] = []
    receipt_digests_ok = True
    for index, receipt in enumerate(receipts):
        try:
            _validate_receipt(receipt, index)
        except ValueError as exc:
            blockers.append(f"receipt {index} invalid: {exc}")
            continue
        if receipt["receipt_digest"] != receipt_digest(receipt):
            receipt_digests_ok = False
            blockers.append(f"receipt {index} digest mismatch")
        valid_receipts.append(receipt)

    builder_keys = {(item["builder_id"], item["builder_family"]) for item in valid_receipts}
    environment_digests = {item["environment_digest"] for item in valid_receipts}
    source_commits = {item["source_commit"] for item in valid_receipts}
    instruction_digests = {item["build_instructions_digest"] for item in valid_receipts}
    sha256s = {item["artifact_sha256"] for item in valid_receipts}
    sha3s = {item["artifact_sha3_512"] for item in valid_receipts}
    sizes = {item["artifact_size"] for item in valid_receipts}
    byte_identical = bool(valid_receipts) and all(item["byte_identical_output"] is True for item in valid_receipts)
    source_matches_expected = expected_source is not None and source_commits == {expected_source}
    sha256_matches_expected = expected_sha256 is not None and sha256s == {expected_sha256}
    sha3_matches_expected = expected_sha3 is not None and sha3s == {expected_sha3}
    size_matches_expected = expected_artifact_size is not None and sizes == {expected_artifact_size}

    if len(builder_keys) < 2:
        blockers.append("reproducible build independence missing: fewer than two independent builders")
    if len(environment_digests) < 2:
        blockers.append("reproducible build independence missing: environments are not distinct")
    if len(source_commits) != 1:
        blockers.append("reproducible build receipts do not share one source commit")
    if len(instruction_digests) != 1:
        blockers.append("reproducible build receipts do not share one build instructions digest")
    if len(sha256s) != 1:
        blockers.append("reproducible build artifact SHA-256 mismatch")
    if len(sha3s) != 1:
        blockers.append("reproducible build artifact SHA3-512 mismatch")
    if not byte_identical:
        blockers.append("reproducible build receipts do not claim byte-identical output")
    if not (bool(valid_receipts) and receipt_digests_ok):
        blockers.append("reproducible build receipt digest mismatch")
    if bundle["fixture"] is True:
        blockers.append("reproducible build receipts are fixture evidence")
    if bundle["claim_usable"] is not True:
        blockers.append("reproducible build receipts are not claim-usable")
    if not REQUIRED_NON_CLAIMS.issubset(set(acknowledged)):
        blockers.append("reproducible build non-claims incomplete")
    if not source_matches_expected:
        blockers.append("reproducible build source commit does not match capsule source commit")
    if not sha256_matches_expected:
        blockers.append("reproducible build artifact SHA-256 does not match capsule subject")
    if not sha3_matches_expected:
        blockers.append("reproducible build artifact SHA3-512 does not match capsule subject")
    if not size_matches_expected:
        blockers.append("reproducible build artifact size does not match capsule subject")

    atoms = {
        "receipts_present": bool(valid_receipts),
        "receipt_statement_digests_verified": bool(valid_receipts) and receipt_digests_ok,
        "receipts_non_fixture": bundle["fixture"] is False,
        "receipts_claim_usable": bundle["claim_usable"] is True,
        "at_least_two_independent_builders": len(builder_keys) >= 2,
        "distinct_build_environments": len(environment_digests) >= 2,
        "same_source_commit": len(source_commits) == 1 and bool(valid_receipts),
        "source_commit_matches_capsule": source_matches_expected,
        "same_build_instructions_digest": len(instruction_digests) == 1 and bool(valid_receipts),
        "same_artifact_sha256": len(sha256s) == 1 and bool(valid_receipts),
        "artifact_sha256_matches_subject": sha256_matches_expected,
        "same_artifact_sha3_512": len(sha3s) == 1 and bool(valid_receipts),
        "artifact_sha3_512_matches_subject": sha3_matches_expected,
        "artifact_size_matches_subject": size_matches_expected,
        "byte_identical_outputs_claimed": byte_identical,
    }
    return {
        "schema_id": SCHEMA_ID,
        "passed": not blockers,
        "blockers": blockers,
        "receipt_count": len(receipts),
        "valid_receipt_count": len(valid_receipts),
        "fixture": bundle["fixture"],
        "claim_usable": bundle["claim_usable"],
        "independent_builder_count": len(builder_keys),
        "distinct_environment_count": len(environment_digests),
        "source_commit": next(iter(source_commits)) if len(source_commits) == 1 else None,
        "build_instructions_digest": next(iter(instruction_digests)) if len(instruction_digests) == 1 else None,
        "artifact_sha256": next(iter(sha256s)) if len(sha256s) == 1 else None,
        "artifact_sha3_512": next(iter(sha3s)) if len(sha3s) == 1 else None,
        "atoms": atoms,
    }


def load_and_evaluate(path: Path | str) -> dict[str, Any]:
    return evaluate_bundle(load_json_no_floats(path))
