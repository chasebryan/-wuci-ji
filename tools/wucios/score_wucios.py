#!/usr/bin/env python3
"""Generate Daylight/WuciOS score material without fabricating values."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REVIEW_DIR = ROOT / "build/wucios/review"

CATEGORIES = [
    ("Surface Minimization", 20.0),
    ("Reproducibility / Pinning", 20.0),
    ("Integrity / Provenance", 15.0),
    ("Runtime Default Safety", 15.0),
    ("Auditability", 15.0),
    ("Claim Discipline", 10.0),
    ("Reviewer Usability", 5.0),
]

REQUIRED_INPUTS = [
    "package-manifest.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "surface-report.json",
    "substrate-matrix.json",
]

NON_CLAIMS = [
    "No release-authoritative score exists without a current artifact hash.",
    "No numeric score is generated when required inputs are missing.",
    "A diagnostic host scan is not a WuciOS release score.",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def missing_inputs() -> list[str]:
    missing: list[str] = []
    for name in REQUIRED_INPUTS:
        path = REVIEW_DIR / name
        if not path.is_file():
            missing.append(name)
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "NOT_MEASURED" in text:
            missing.append(f"{name}: contains NOT_MEASURED")
    return missing


def build_payload(artifact: Path | None) -> dict[str, Any]:
    if artifact is None:
        status = "INVALID_WITHOUT_ARTIFACT"
        warning = "No release-authoritative score exists because no current artifact was scanned."
        artifact_payload = {"path": "NOT_MEASURED", "sha256": "NOT_MEASURED"}
        missing = REQUIRED_INPUTS
    else:
        artifact_payload = {"path": str(artifact), "sha256": sha256_file(artifact)}
        missing = missing_inputs()
        status = "ARTIFACT_BOUND_INCOMPLETE" if missing else "ARTIFACT_BOUND_PENDING_SCORING_RULES"
        warning = "Artifact hash was recorded, but required measured inputs are missing." if missing else "Artifact hash and required inputs exist, but this implementation does not assign a numeric score without reviewed scoring rules."

    categories = [
        {
            "name": name,
            "weight": weight,
            "value": "NOT_MEASURED",
            "evidence": "NOT_MEASURED",
        }
        for name, weight in CATEGORIES
    ]

    return {
        "schema": "wucios.daylight.score.v1",
        "score_valid": False,
        "score_value": None,
        "score_scale": "0.0-100.0",
        "score_precision": "one decimal place",
        "score_status": status,
        "artifact": artifact_payload,
        "warning_level": "UNASSESSED" if artifact is None else "HIGH",
        "warning_text": warning,
        "categories": categories if artifact is not None else [],
        "missing_inputs": missing,
        "non_claims": NON_CLAIMS,
    }


def write_outputs(payload: dict[str, Any]) -> None:
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    (REVIEW_DIR / "daylight-wucios-score.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Daylight/WuciOS Score",
        "",
        f"Score valid: `{str(payload['score_valid']).lower()}`",
        f"Score value: `{payload['score_value']}`",
        f"Score status: `{payload['score_status']}`",
        f"Warning level: `{payload['warning_level']}`",
        "",
        payload["warning_text"],
        "",
        "## Artifact",
        "",
        f"- Path: `{payload['artifact']['path']}`",
        f"- SHA-256: `{payload['artifact']['sha256']}`",
        "",
        "## Categories",
        "",
    ]
    if payload["categories"]:
        lines.extend(["| Category | Weight | Value | Evidence |", "| --- | ---: | --- | --- |"])
        for category in payload["categories"]:
            lines.append(f"| {category['name']} | {category['weight']:.1f} | {category['value']} | {category['evidence']} |")
    else:
        lines.append("No categories are scored without an artifact.")
    if payload.get("missing_inputs"):
        lines.extend(["", "## Missing Inputs", ""])
        lines.extend(f"- `{item}`" for item in payload["missing_inputs"])
    lines.extend(["", "## Non-Claims", ""])
    lines.extend(f"- {item}" for item in payload["non_claims"])
    lines.append("")
    (REVIEW_DIR / "daylight-wucios-score.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", help="Current WuciOS artifact to hash and bind to score material")
    args = parser.parse_args()

    artifact = None
    if args.artifact:
        artifact = Path(args.artifact)
        if not artifact.is_file():
            print(f"WuciOS score: artifact not found: {artifact}", file=sys.stderr)
            return 2
    payload = build_payload(artifact)
    write_outputs(payload)
    print(f"WuciOS score: {payload['score_status']}")
    print(f"- score_valid: {payload['score_valid']}")
    print(f"- score_value: {payload['score_value']}")
    print(f"- artifact_sha256: {payload['artifact']['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
