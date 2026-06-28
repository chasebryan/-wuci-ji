#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
VECTOR = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "vectors" / "nightlight-v6-deep-assault-assessment-v1.txt"
MAKEFILE = REPO / "Makefile"
README = REPO / "daylight-equation" / "rust" / "daylight-crypto" / "README.md"
BUILD_TARGETS = REPO / "docs" / "BUILD_TARGETS.md"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
EVIDENCE_README = REPO / "daylight-equation" / "evidence" / "README.md"
ASSESSMENT_DOC = REPO / "daylight-equation" / "analysis" / "nightlight-v6-defensive-assault-assessment.md"


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


def parse_kv_parts(value: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for part in value.split("|"):
        if "=" in part:
            key, part_value = part.split("=", 1)
            parsed[key] = part_value
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the Nightlight v6 deep assessment.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    fields = parse_vector(VECTOR)
    require_field(fields, "version", "nightlight-v6-deep-assault-assessment-v1")
    require_field(fields, "subject", "Nightlight_Daylight_v6_deep_learning_assessment")
    require_field(fields, "algorithm", "deterministic-coverage-learning-v1")
    require_field(fields, "expected_result", "learning_guided_gap_assessment")
    require_field(fields, "defensive_only", "true")
    require_field(fields, "learning_enabled", "true")
    require_field(fields, "offensive_logic_added", "false")
    require_field(fields, "network_required", "false")
    require_field(fields, "score_delta", "0")

    input_cases = int(fields["input_adversarial_cases"])
    fail_closed_cases = int(fields["fail_closed_cases"])
    learning_epochs = int(fields["learning_epochs"])
    learning_arms_total = int(fields["learning_arms_total"])
    public_stage_target_total = int(fields["public_stage_target_total"])
    public_stage_covered = int(fields["public_stage_covered"])
    public_stage_gap_count = int(fields["public_stage_gap_count"])
    private_failure_target_total = int(fields["private_failure_target_total"])
    private_failure_covered = int(fields["private_failure_covered"])
    private_failure_gap_count = int(fields["private_failure_gap_count"])
    recommendations_total = int(fields["recommendations_total"])
    top_priority = int(fields["top_priority"])

    if input_cases < 57 or fail_closed_cases != input_cases:
        raise AssertionError("deep assessment must consume an all fail-closed adversarial corpus")
    if learning_epochs < 8:
        raise AssertionError("deep assessment must keep at least eight learning epochs")
    if learning_arms_total < 20:
        raise AssertionError("deep assessment learning arm inventory regressed")
    if public_stage_target_total != 14:
        raise AssertionError("public-stage target set changed unexpectedly")
    if public_stage_covered < 13:
        raise AssertionError("deep assessment lost public-stage coverage")
    if public_stage_gap_count != public_stage_target_total - public_stage_covered:
        raise AssertionError("public-stage gap count does not match coverage")
    if private_failure_target_total != 4:
        raise AssertionError("private-failure target set changed unexpectedly")
    if private_failure_covered < 2:
        raise AssertionError("deep assessment lost private-failure coverage")
    if private_failure_gap_count != private_failure_target_total - private_failure_covered:
        raise AssertionError("private-failure gap count does not match coverage")
    if recommendations_total < 3 or top_priority < 900:
        raise AssertionError("deep assessment did not emit high-priority gap recommendations")

    arm_lines = [
        (key, value)
        for key, value in fields.items()
        if key.startswith("learning_arm_")
        and key.removeprefix("learning_arm_").isdigit()
    ]
    epoch_lines = [
        (key, value)
        for key, value in fields.items()
        if key.startswith("learning_epoch_")
        and key.removeprefix("learning_epoch_").isdigit()
    ]
    recommendation_lines = [
        (key, value)
        for key, value in fields.items()
        if key.startswith("learning_recommendation_")
        and key.removeprefix("learning_recommendation_").isdigit()
    ]
    if len(arm_lines) != learning_arms_total:
        raise AssertionError("learning arm inventory is incomplete")
    if len(epoch_lines) != learning_epochs:
        raise AssertionError("learning epoch inventory is incomplete")
    if len(recommendation_lines) != recommendations_total:
        raise AssertionError("learning recommendation inventory is incomplete")

    priorities: list[int] = []
    arm_ids: set[str] = set()
    for key, value in sorted(arm_lines):
        parts = value.split("|")
        if len(parts) < 3:
            raise AssertionError(f"{key} is malformed")
        arm_id = parts[0]
        arm_ids.add(arm_id)
        parsed = parse_kv_parts(value)
        cases = int(parsed["cases"])
        fail_closed = int(parsed["fail_closed"])
        priority = int(parsed["priority"])
        if cases < 1 or fail_closed != cases:
            raise AssertionError(f"{key} must remain all fail-closed")
        if priority < 1:
            raise AssertionError(f"{key} must have positive learned priority")
        priorities.append(priority)
    if priorities != sorted(priorities, reverse=True):
        raise AssertionError("learning arms must be sorted by learned priority")

    for key, value in sorted(epoch_lines):
        parsed = parse_kv_parts(value)
        selected_arm = parsed["arm"]
        if selected_arm not in arm_ids:
            raise AssertionError(f"{key} selects an unknown learning arm")
        if int(parsed["priority"]) < 1:
            raise AssertionError(f"{key} must have positive priority")
        if "rationale=" not in value:
            raise AssertionError(f"{key} is missing rationale")

    recommendation_ids = {value.split("|", 1)[0] for _, value in recommendation_lines}
    required_recommendations = {
        "missing_public_install_stage",
        "missing_private_derive_failure",
        "missing_private_leak_failure",
    }
    if not required_recommendations.issubset(recommendation_ids):
        raise AssertionError("deep assessment is missing required gap recommendations")
    for key, value in sorted(recommendation_lines):
        parsed = parse_kv_parts(value)
        if int(parsed["priority"]) < 1:
            raise AssertionError(f"{key} must have positive priority")
        if "target=" not in value or "rationale=" not in value:
            raise AssertionError(f"{key} is missing target or rationale")

    require_hash(fields, "learning_hash_hex")

    makefile = MAKEFILE.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    evidence_readme = EVIDENCE_README.read_text(encoding="utf-8")
    assessment_doc = ASSESSMENT_DOC.read_text(encoding="utf-8")

    assert "daylight-v6-nightlight-deep-assessment-test:" in makefile
    assert "cargo run --offline -- nightlight-v6-deep-assault-assessment" in readme
    assert "daylight-v6-nightlight-deep-assessment-test" in build_targets
    assert "nightlight-v6-deep-assault-assessment-v1.txt" in scorecard
    assert "daylight_v6_nightlight_deep_assessment.py" in scorecard
    assert "nightlight-v6-deep-assault-assessment-v1.txt" in evidence_readme
    assert "deterministic-coverage-learning-v1" in assessment_doc
    assert "missing_public_install_stage" in assessment_doc

    if not args.quiet:
        print("Nightlight v6 deep assessment: PASS")


if __name__ == "__main__":
    main()
