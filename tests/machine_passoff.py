#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PASSOFF = REPO / "docs" / "MACHINE_PASSOFF.md"
README = REPO / "README.md"
BUILD_NOTES = REPO / "BUILD_NOTES.md"
MAKEFILE = REPO / "Makefile"


REQUIRED_PATHS = (
    "README.md",
    "BUILD_NOTES.md",
    "docs/SECURITY_BOUNDARY.md",
    "docs/PRODUCTION_READINESS.md",
    "docs/BUILD_TARGETS.md",
    "daylight-equation/SCORECARD.md",
    "daylight-equation/research/daylight-v06-cap-removal-plan.md",
    "daylight-equation/research/daylight-v06-cap-removal-plan.v1.json",
    "tools/daylight_cap_removal.py",
    "tests/daylight_cap_removal.py",
)

REQUIRED_COMMANDS = (
    "make daylight-v06-cap-removal-test",
    "make daylight-v06-peer-review-score-test",
    "make daylight-v06-authority-verifier-test",
    "make production-readiness-gates",
    "make wuci-daylight-bridge-test",
    "make daylight-v06-1000-claim-gate-test",
)

REQUIRED_BOUNDARY_TEXT = (
    "ProductionAllowed = 0",
    "RuntimeContainmentClaim = 0",
    "WholeSystemPostQuantumSafetyClaim = 0",
    "ExternalReviewClaim = 0",
    "OfficialEndorsementClaim = 0",
    "Daylight_v0.6_peer_review_evaluation_score = 8250 / 10000",
    "Daylight_v0.6_research_score = 975 / 1000",
    "ScoreIncreaseAuthorized = 0",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check machine passoff continuation document.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    passoff = PASSOFF.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    build_notes = BUILD_NOTES.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert "docs/MACHINE_PASSOFF.md" in readme
    assert "docs/MACHINE_PASSOFF.md" in build_notes
    assert "git clone https://github.com/chasebryan/-wuci-ji" in passoff
    assert "git pull --ff-only origin main" in passoff
    assert "git push origin main" in passoff
    assert "gh run watch <run-id> --exit-status" in passoff
    assert "Continue assembly-backed publish/trust Gate work without enabling production claims." in passoff
    assert "Prepare positive production publish/trust authority prerequisites without enabling production claims." in passoff
    assert "implemented only for fail-closed decisions" in passoff
    assert "publish-authorized-rooted" in passoff
    assert "trust-authorized-rooted" in passoff
    assert "fixture authority cannot satisfy publish/trust authority" in passoff
    assert "Do not add exploit generation" in passoff
    assert "Do not describe CAGE as OS containment" in passoff
    assert "Do not describe classical signatures as quantum-safe" in passoff

    for rel_path in REQUIRED_PATHS:
        assert (REPO / rel_path).exists(), rel_path
        assert rel_path in passoff or f"../{rel_path}" in passoff, rel_path

    for command in REQUIRED_COMMANDS:
        target = command.removeprefix("make ")
        assert command in passoff
        assert f"{target}:" in makefile

    for text in REQUIRED_BOUNDARY_TEXT:
        assert text in passoff

    for fixture_path in (
        "authority/wuci-root.fixture.txt",
        "authority/wuci-release-root.fixture.txt",
    ):
        assert fixture_path in passoff

    if not args.quiet:
        print("machine passoff: PASS")


if __name__ == "__main__":
    main()
