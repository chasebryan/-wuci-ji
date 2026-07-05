#!/usr/bin/env python3
"""Generate the WuciOS Euclid substrate matrix."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SUBSTRATE_DIR = ROOT / "wucios/substrates"
REVIEW_DIR = ROOT / "build/wucios/review"
REQUIRED_FIELDS = [
    "schema",
    "id",
    "display_name",
    "status",
    "substrate_class",
    "linux_based",
    "package_manager",
    "init_or_supervision",
    "libc",
    "reason_to_test",
    "expected_risks",
]


def load_substrates() -> tuple[list[dict[str, Any]], list[str]]:
    failures: list[str] = []
    substrates: list[dict[str, Any]] = []
    for path in sorted(SUBSTRATE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"{path.relative_to(ROOT)} invalid JSON: {exc}")
            continue
        missing = [field for field in REQUIRED_FIELDS if field not in data]
        if missing:
            failures.append(f"{path.relative_to(ROOT)} missing fields: {', '.join(missing)}")
        if data.get("status") != "CANDIDATE_SUBSTRATE":
            failures.append(f"{path.relative_to(ROOT)} must be CANDIDATE_SUBSTRATE")
        substrates.append(data)
    return substrates, failures


def measured_status(substrate_id: str) -> str:
    report = ROOT / "build/wucios/substrates" / substrate_id / "substrate-report.json"
    if report.is_file():
        return "MEASURED"
    return "NOT_MEASURED"


def decision_status() -> str:
    for path in [ROOT / "build/wucios/substrate-decision.json", ROOT / "wucios/substrates/decision.json"]:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return "NO_SUBSTRATE_SELECTED"
            return str(data.get("decision", "NO_SUBSTRATE_SELECTED"))
    return "NO_SUBSTRATE_SELECTED"


def write_outputs(substrates: list[dict[str, Any]], failures: list[str]) -> None:
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for substrate in substrates:
        rows.append(
            {
                "id": substrate.get("id", "UNKNOWN"),
                "display_name": substrate.get("display_name", "UNKNOWN"),
                "status": substrate.get("status", "UNKNOWN"),
                "substrate_class": substrate.get("substrate_class", "UNKNOWN"),
                "linux_based": substrate.get("linux_based", "UNKNOWN"),
                "package_manager": substrate.get("package_manager", "UNKNOWN"),
                "init_or_supervision": substrate.get("init_or_supervision", "UNKNOWN"),
                "libc": substrate.get("libc", "UNKNOWN"),
                "reason_to_test": substrate.get("reason_to_test", []),
                "expected_risks": substrate.get("expected_risks", []),
                "measured_status": measured_status(str(substrate.get("id", "UNKNOWN"))),
            }
        )

    payload = {
        "schema": "wucios.substrate_matrix.v1",
        "selection_status": decision_status(),
        "ranked": False,
        "ranking_reason": "No ranking is generated without measured trial evidence.",
        "candidates": rows,
        "validation_failures": failures,
    }
    (REVIEW_DIR / "substrate-matrix.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Euclid Substrate Trial Matrix",
        "",
        f"Selection status: `{payload['selection_status']}`",
        "",
        "| ID | Display Name | Class | Linux Based | Package Manager | Init/Supervision | Libc | Reason To Test | Expected Risks | Measured Status |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        reason = "<br>".join(str(item) for item in row["reason_to_test"])
        risks = "<br>".join(str(item) for item in row["expected_risks"])
        lines.append(
            "| {id} | {display_name} | {substrate_class} | {linux_based} | {package_manager} | {init_or_supervision} | {libc} | {reason} | {risks} | {measured_status} |".format(
                reason=reason,
                risks=risks,
                **row,
            )
        )
    if failures:
        lines.extend(["", "## Validation Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)
    lines.append("")
    (REVIEW_DIR / "substrate-matrix.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    substrates, failures = load_substrates()
    write_outputs(substrates, failures)
    if failures:
        print("WuciOS substrate matrix: generated with validation failures")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("WuciOS substrate matrix: generated")
    print(f"- candidates: {len(substrates)}")
    print(f"- selection: {decision_status()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
