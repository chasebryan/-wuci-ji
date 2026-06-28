#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
VECTOR = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "vectors" / "nightlight-v6-equation-battery-v1.txt"
MAKEFILE = REPO / "Makefile"
README = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "README.md"
BUILD_TARGETS = REPO / "docs" / "BUILD_TARGETS.md"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
EVIDENCE_README = REPO / "daylight-equation" / "evidence" / "README.md"


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


def require_field(fields: dict[str, str], key: str, expected: str) -> None:
    actual = fields.get(key)
    if actual != expected:
        raise AssertionError(f"expected {key}={expected}, got {actual!r}")


def require_hash(fields: dict[str, str], key: str) -> None:
    value = fields[key]
    if len(value) != 128:
        raise AssertionError(f"{key} must be SHA3-512 sized")
    int(value, 16)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the Nightlight v6 equation battery.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    fields = parse_vector(VECTOR)
    require_field(fields, "version", "nightlight-v6-equation-battery-v1")
    require_field(fields, "subject", "Nightlight_Daylight_v6_equation_battery")
    require_field(fields, "profile", "defensive-equation-battery")
    require_field(fields, "scope", "no-network-no-offensive-logic")
    require_field(fields, "expected_result", "defensive_battery_ready")
    require_field(fields, "score_delta", "0")
    require_field(fields, "production_allowed", "false")
    require_field(fields, "runtime_containment_claim", "false")
    require_field(fields, "whole_system_post_quantum_safety_claim", "false")
    require_field(fields, "offensive_logic_added", "false")
    require_field(fields, "network_required", "false")
    require_field(fields, "open_ended_gate", "true")
    require_field(fields, "equation_checks_failed", "0")
    require_field(fields, "equation_holds", "true")
    require_field(fields, "efficiency_checks_failed", "0")
    require_field(fields, "efficiency_holds", "true")
    require_field(fields, "defensive_battery_ready", "true")
    require_field(fields, "provider_backed_kem", "true")
    require_field(fields, "provider_backed_private_roundtrip", "true")
    require_field(fields, "provider_backed_reference_seal_open", "true")
    require_field(fields, "public_authority_external", "true")
    require_field(fields, "schema_public_precheck_rejection_stage", "REJECT_AUTH_SIGNATURE")
    require_field(fields, "private_public_precheck_rejection_stage", "REJECT_AUTH_SIGNATURE")
    require_field(fields, "reference_public_precheck_rejection_stage", "REJECT_AUTH_SIGNATURE")

    equation_total = int(fields["equation_checks_total"])
    efficiency_total = int(fields["efficiency_checks_total"])
    if equation_total < 22:
        raise AssertionError("Nightlight equation check count regressed")
    if efficiency_total < 11:
        raise AssertionError("Nightlight efficiency check count regressed")

    minimum_negative = int(fields["minimum_reference_negative_cases"])
    minimum_public = int(fields["minimum_public_simulation_cases"])
    total_negative = int(fields["total_negative_cases"])
    fail_closed_negative = int(fields["fail_closed_negative_cases"])
    public_total = int(fields["public_simulation_cases_total"])
    public_fail_closed = int(fields["public_simulation_fail_closed_cases"])
    adversarial_total = int(fields["adversarial_cases_total"])
    adversarial_fail_closed = int(fields["adversarial_cases_fail_closed"])
    public_stops = int(fields["public_precheck_stop_count"])
    private_mutations = int(fields["private_path_mutation_count"])
    private_reached = int(fields["private_path_reach_count"])

    if minimum_negative < 12 or minimum_public < 40:
        raise AssertionError("Nightlight open-ended minimums regressed")
    if total_negative < minimum_negative:
        raise AssertionError("Nightlight reference negative corpus fell below minimum")
    if fail_closed_negative != total_negative:
        raise AssertionError("Nightlight reference negative corpus is not all fail-closed")
    if public_total < minimum_public:
        raise AssertionError("Nightlight public simulation corpus fell below minimum")
    if public_fail_closed != public_total:
        raise AssertionError("Nightlight public simulation corpus is not all fail-closed")
    require_field(fields, "public_simulation_all_fail_closed", "true")
    if adversarial_total != total_negative + public_total:
        raise AssertionError("Nightlight adversarial total does not compose")
    if adversarial_fail_closed != fail_closed_negative + public_fail_closed:
        raise AssertionError("Nightlight fail-closed adversarial total does not compose")
    if public_stops < 10 or private_mutations < 2:
        raise AssertionError("Nightlight efficiency baseline regressed")
    if private_reached != private_mutations:
        raise AssertionError("Nightlight private-path reach count must equal private mutation count")

    failure_counts = {
        key.removeprefix("failure_count_"): int(value)
        for key, value in fields.items()
        if key.startswith("failure_count_")
    }
    if sum(failure_counts.values()) != total_negative:
        raise AssertionError("Nightlight failure counts do not sum to total cases")
    for failure_name in ("AuthQ", "Gate", "Policy", "Install", "Witness", "Log", "Claim", "NoDowngrade", "Aead", "Commit"):
        if failure_counts.get(failure_name, 0) < 1:
            raise AssertionError(f"Nightlight missing failure coverage for {failure_name}")

    public_stage_counts = {
        key.removeprefix("public_stage_count_"): int(value)
        for key, value in fields.items()
        if key.startswith("public_stage_count_")
    }
    if sum(public_stage_counts.values()) != public_total:
        raise AssertionError("Nightlight public stage counts do not sum to public simulation total")
    for stage_name in (
        "REJECT_PARSE",
        "REJECT_SCHEMA",
        "REJECT_SUITE",
        "REJECT_AUX_HASH",
        "REJECT_POLICY",
        "REJECT_CLAIMS",
        "REJECT_KEM_BLOCK",
        "REJECT_AUTH_BLOCK",
        "REJECT_AUTH_SIGNATURE",
        "REJECT_REVIEW",
        "REJECT_DOWNGRADE",
        "REJECT_LOG",
        "REJECT_WITNESS",
    ):
        if public_stage_counts.get(stage_name, 0) < 1:
            raise AssertionError(f"Nightlight missing public-stage coverage for {stage_name}")

    public_cases = [
        (key, value)
        for key, value in fields.items()
        if key.startswith("public_simulation_case_")
        and key.removeprefix("public_simulation_case_").isdigit()
    ]
    if len(public_cases) != public_total:
        raise AssertionError("Nightlight public simulation case inventory is incomplete")
    for key, value in public_cases:
        if "|expected=" not in value or "|actual=" not in value:
            raise AssertionError(f"{key} missing expected/actual stage")
        expected = value.split("|expected=", 1)[1].split("|", 1)[0]
        actual = value.split("|actual=", 1)[1].split("|", 1)[0]
        if expected != actual:
            raise AssertionError(f"{key} did not fail closed at the expected stage")
        if "|fail_closed=true|" not in value or not value.endswith("|private_path_reached=false"):
            raise AssertionError(f"{key} must be fail-closed before private path")

    for key in (
        "artifact_sha3_512_hex",
        "schema_omega_sha3_512_hex",
        "private_omega_sha3_512_hex",
        "reference_omega_sha3_512_hex",
        "private_ciphertext_sha3_512_hex",
        "reference_ciphertext_sha3_512_hex",
        "private_com_a_sha3_512_hex",
        "reference_com_a_sha3_512_hex",
        "negative_case_set_sha3_512_hex",
        "public_simulation_case_set_sha3_512_hex",
        "battery_sha3_512_hex",
    ):
        require_hash(fields, key)

    if fields["private_ciphertext_sha3_512_hex"] == fields["reference_ciphertext_sha3_512_hex"]:
        raise AssertionError("Nightlight private/reference ciphertext hashes must be domain-separated")
    if fields["private_com_a_sha3_512_hex"] == fields["reference_com_a_sha3_512_hex"]:
        raise AssertionError("Nightlight private/reference commitments must be domain-separated")

    makefile = MAKEFILE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    evidence_readme = EVIDENCE_README.read_text(encoding="utf-8")

    assert "daylight-v6-nightlight-battery-test:" in makefile
    assert "cargo run --offline -- nightlight-v6-equation-battery" in readme
    assert "daylight-v6-nightlight-battery-test" in build_targets
    assert "nightlight-v6-equation-battery-v1.txt" in scorecard
    assert "nightlight-v6-defensive-assault-assessment.md" in scorecard
    assert "nightlight-v6-equation-battery-v1.txt" in evidence_readme

    if not args.quiet:
        print("Nightlight v6 equation battery: PASS")


if __name__ == "__main__":
    main()
