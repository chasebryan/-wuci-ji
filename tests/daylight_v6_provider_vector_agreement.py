#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
VECTOR_ROOT = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "vectors"
EVIDENCE = REPO / "daylight-equation" / "evidence" / "daylight-v6-provider-vector-agreement.v1.json"

KEM_VECTOR = VECTOR_ROOT / "daylight-v6-provider-kem-evidence-v1.txt"
PRIVATE_VECTOR = VECTOR_ROOT / "daylight-v6-provider-private-roundtrip-evidence-v1.txt"
REFERENCE_VECTOR = VECTOR_ROOT / "daylight-v6-reference-seal-open-evidence-v1.txt"
NEGATIVE_VECTOR = VECTOR_ROOT / "daylight-v6-reference-negative-corpus-v1.txt"


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def parse_vector(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            raise AssertionError(f"{path}:{line_number}: expected key=value line")
        key, value = line.split("=", 1)
        if key in fields:
            raise AssertionError(f"{path}:{line_number}: duplicate field {key}")
        fields[key] = value
    return fields


def file_sha3_512(path: Path) -> str:
    return hashlib.sha3_512(path.read_bytes()).hexdigest()


def require_field(fields: dict[str, str], key: str, value: str, label: str) -> None:
    actual = fields.get(key)
    if actual != value:
        raise AssertionError(f"{label}: expected {key}={value}, got {actual!r}")


def require_auth_msg(fields: dict[str, str], label: str) -> None:
    h1 = fields["h1_hex"]
    auth_msg = fields["AuthMsg_hex"]
    if not auth_msg.endswith(h1):
        raise AssertionError(f"{label}: AuthMsg does not end with h1")
    if len(h1) != 128:
        raise AssertionError(f"{label}: h1 must be SHA3-512 sized")


def generate() -> dict[str, Any]:
    kem = parse_vector(KEM_VECTOR)
    private = parse_vector(PRIVATE_VECTOR)
    reference = parse_vector(REFERENCE_VECTOR)
    negative = parse_vector(NEGATIVE_VECTOR)

    require_field(kem, "version", "daylight-v6-provider-kem-evidence-v1", "kem")
    require_field(kem, "expected_result", "not_open", "kem")
    require_field(kem, "provider_backed_kem", "true", "kem")
    require_field(kem, "provider_backed_reference_seal_open", "false", "kem")
    require_field(kem, "production_allowed", "false", "kem")
    require_field(kem, "schema_expected_rejection_stage", "REJECT_AUTH_SIGNATURE", "kem")
    require_field(kem, "schema_private_kem_allowed", "false", "kem")
    require_field(kem, "schema_aead_dec_allowed", "false", "kem")
    require_field(kem, "mlkem1024_decaps_matches", "true", "kem")
    require_field(kem, "dhkem_p384_decaps_matches", "true", "kem")

    require_field(private, "version", "daylight-v6-provider-private-roundtrip-evidence-v1", "private")
    require_field(private, "expected_result", "private_roundtrip_only", "private")
    require_field(private, "provider_backed_private_roundtrip", "true", "private")
    require_field(private, "provider_backed_reference_seal_open", "false", "private")
    require_field(private, "production_allowed", "false", "private")
    require_field(private, "public_precheck_rejection_stage", "REJECT_AUTH_SIGNATURE", "private")
    require_field(private, "opened_artifact_matches", "true", "private")
    require_field(private, "commitment_matches", "true", "private")
    require_field(private, "aead_roundtrip_matches", "true", "private")
    require_auth_msg(private, "private")

    require_field(reference, "version", "daylight-v6-reference-seal-open-evidence-v1", "reference")
    require_field(reference, "profile", "nonproduction-external-public-precheck", "reference")
    require_field(reference, "expected_result", "reference_seal_open", "reference")
    require_field(reference, "provider_backed_reference_seal_open", "true", "reference")
    require_field(reference, "public_authority_external", "true", "reference")
    require_field(reference, "production_allowed", "false", "reference")
    require_field(reference, "public_precheck_rejection_stage", "REJECT_AUTH_SIGNATURE", "reference")
    require_field(reference, "opened_artifact_matches", "true", "reference")
    require_auth_msg(reference, "reference")

    require_field(negative, "version", "daylight-v6-reference-negative-corpus-v1", "negative")
    require_field(negative, "profile", "nonproduction-external-public-precheck", "negative")
    require_field(negative, "provider_backed_reference_seal_open", "true", "negative")
    require_field(negative, "public_authority_external", "true", "negative")
    require_field(negative, "production_allowed", "false", "negative")
    require_field(negative, "total_cases", "14", "negative")
    require_field(negative, "all_fail_closed", "true", "negative")
    for index in range(1, 15):
        case = negative[f"case_{index:02}"]
        if "|expected=" not in case or "|actual=" not in case:
            raise AssertionError(f"negative: case_{index:02} missing expected/actual failure")
        expected = case.split("|expected=", 1)[1].split("|", 1)[0]
        actual = case.split("|actual=", 1)[1].split("|", 1)[0]
        if expected != actual:
            raise AssertionError(f"negative: case_{index:02} did not fail closed as expected")

    artifact_hash = private["artifact_sha3_512_hex"]
    if private["opened_artifact_sha3_512_hex"] != artifact_hash:
        raise AssertionError("private: opened artifact hash disagrees with artifact hash")
    if reference["artifact_sha3_512_hex"] != artifact_hash:
        raise AssertionError("reference: artifact hash disagrees with private vector")
    if reference["opened_artifact_sha3_512_hex"] != artifact_hash:
        raise AssertionError("reference: opened artifact hash disagrees with artifact hash")
    if private["ciphertext_sha3_512_hex"] == reference["ciphertext_sha3_512_hex"]:
        raise AssertionError("reference Seal/Open ciphertext unexpectedly matches private-roundtrip vector")
    if private["com_a_hex"] == reference["com_a_hex"]:
        raise AssertionError("reference Seal/Open commitment unexpectedly matches private-roundtrip vector")
    if private["nonce_sha3_512_hex"] != kem["base_nonce_sha3_512_hex"]:
        raise AssertionError("private roundtrip nonce hash must agree with provider KEM base nonce")

    inputs = [
        {"path": str(KEM_VECTOR.relative_to(REPO)), "sha3_512": file_sha3_512(KEM_VECTOR)},
        {"path": str(PRIVATE_VECTOR.relative_to(REPO)), "sha3_512": file_sha3_512(PRIVATE_VECTOR)},
        {"path": str(REFERENCE_VECTOR.relative_to(REPO)), "sha3_512": file_sha3_512(REFERENCE_VECTOR)},
        {"path": str(NEGATIVE_VECTOR.relative_to(REPO)), "sha3_512": file_sha3_512(NEGATIVE_VECTOR)},
    ]
    return {
        "as_of": "2026-06-28",
        "inputs": inputs,
        "schema_version": 1,
        "subject": "Daylight_v0.6_provider_vector_agreement",
        "summary": {
            "artifact_hash": artifact_hash,
            "auth_messages_bound_to_h1": True,
            "provider_backed_kem": True,
            "provider_backed_private_roundtrip": True,
            "provider_backed_reference_seal_open": True,
            "public_authority_external": True,
            "public_precheck_rejection_stage": "REJECT_AUTH_SIGNATURE",
            "reference_negative_cases": 14,
            "reference_negative_corpus_all_fail_closed": True,
            "production_allowed": False,
            "same_artifact_opened": True,
            "seal_outputs_domain_separated_from_private_roundtrip": True,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Daylight v6 provider vector agreement evidence.")
    parser.add_argument("--write", action="store_true", help="rewrite the checked-in evidence file")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    evidence = generate()
    encoded = canonical_json(evidence)

    if args.write:
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(encoded, encoding="utf-8")
    else:
        existing = EVIDENCE.read_text(encoding="utf-8")
        if existing != encoded:
            raise AssertionError("provider vector agreement evidence is stale; rerun with --write")

    if not args.quiet:
        print("daylight-v6-provider-vector-agreement: PASS")


if __name__ == "__main__":
    main()
