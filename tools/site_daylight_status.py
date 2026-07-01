#!/usr/bin/env python3
"""Regenerate the website's machine-readable Daylight status from evidence.

The website hero and Daylight ladder publish a single headline number (the
current AM+ score). Per Daylight doctrine that number must be regenerable from
committed evidence, not hand-copied. This tool derives ``site/daylight-status.json``
directly from the committed v17 scorecard so the site cannot silently drift.

Usage::

    python3 tools/site_daylight_status.py            # rewrite the status file
    python3 tools/site_daylight_status.py --check     # fail if it is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCORECARD = REPO_ROOT / "daylight" / "v17-singularity" / "examples" / "current-scorecard.v17.json"
STATUS_FILE = REPO_ROOT / "site" / "daylight-status.json"
SCORECARD_REL = "daylight/v17-singularity/examples/current-scorecard.v17.json"


def build_status(scorecard: dict) -> dict:
    declared = bool(scorecard["declared"])
    return {
        "layer": "daylight-v17-singularity",
        "kernel": "daylight-v17.1-event-horizon",
        "unit": scorecard["unit"],
        "score_AM_plus": int(scorecard["score_AM_plus"]),
        "declaration_target_AM_plus": int(scorecard["declaration_target_AM_plus"]),
        "perfect_reserved_AM_plus": int(scorecard["perfect_reserved_AM_plus"]),
        "declared": declared,
        "declaration": "declared" if declared else "refused",
        "status": scorecard["status"],
        "weakest_field": scorecard["weakest_field"],
        "scorecard_digest": scorecard["scorecard_digest"],
        "source": SCORECARD_REL,
        "regenerate": "make site-daylight-status",
        "boundary": "research scoring layer; not production certification",
    }


def render(status: dict) -> str:
    return json.dumps(status, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Regenerate site/daylight-status.json from the committed v17 scorecard.")
    parser.add_argument("--check", action="store_true", help="fail if the committed status file is stale")
    args = parser.parse_args(argv)

    scorecard = json.loads(SCORECARD.read_text(encoding="utf-8"))
    rendered = render(build_status(scorecard))

    if args.check:
        current = STATUS_FILE.read_text(encoding="utf-8") if STATUS_FILE.exists() else ""
        if current != rendered:
            print(
                "site/daylight-status.json is stale; run `make site-daylight-status`",
                file=sys.stderr,
            )
            return 1
        print(f"site-daylight-status: OK ({build_status(scorecard)['score_AM_plus']} AM+)")
        return 0

    STATUS_FILE.write_text(rendered, encoding="utf-8")
    print(f"wrote {STATUS_FILE.relative_to(REPO_ROOT)} ({build_status(scorecard)['score_AM_plus']} AM+)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
