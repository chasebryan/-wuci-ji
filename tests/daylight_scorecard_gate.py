#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"


def require(pattern: str, text: str, label: str) -> re.Match[str]:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing scorecard field: {label}")
    return match


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    text = SCORECARD.read_text(encoding="utf-8")
    score = int(
        require(
            r"^Daylight_v0\.6_research_score\s*=\s*(\d+)\s*/\s*1000$",
            text,
            "Daylight_v0.6_research_score",
        ).group(1)
    )

    for claim_name in (
        "ProductionAllowed",
        "RuntimeContainmentClaim",
        "WholeSystemPostQuantumSafetyClaim",
        "ExternalReviewClaim",
    ):
        require(rf"^{claim_name}\s*=\s*0$", text, claim_name)

    hard_blockers = (
        "RealCryptoProvider = 0",
        "M1Progress = partial",
        "No formal model is tracked.",
        "No external reviews are tracked.",
        "still lacks a second independent parser",
        "not yet a complete provider-backed reference `Seal`/`Open`",
    )
    missing = [blocker for blocker in hard_blockers if blocker not in text]
    if missing:
        raise AssertionError("scorecard dropped hard blocker text: " + ", ".join(missing))

    if score >= 1000:
        raise AssertionError("scorecard claims 1000 while hard blockers remain documented")
    if score > 860:
        raise AssertionError("scorecard exceeds recorded upper estimate without new gate evidence")

    if not args.quiet:
        print(f"Daylight scorecard gate OK: {score}/1000")


if __name__ == "__main__":
    main()
