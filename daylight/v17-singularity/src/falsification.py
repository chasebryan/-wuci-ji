"""Public falsification ledger checks for Daylight v17.1."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical_json import loads_json_no_floats, reject_python_floats


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OPEN_BREAKS = PACKAGE_ROOT / "falsification" / "open-breaks.jsonl"

CRITICAL_BREAK_CLASSES = {
    "B5_forged_scorecard_accepted",
    "B6_opens_without_policy_evidence",
    "B7_production_pq_runtime_overclaim",
}


class FalsificationError(ValueError):
    pass


def load_open_breaks(path: Path | str = DEFAULT_OPEN_BREAKS) -> list[dict[str, Any]]:
    path = Path(path)
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        raise FalsificationError(f"missing open break ledger: {path}")
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = loads_json_no_floats(line)
        reject_python_floats(row, f"open_breaks[{line_number}]")
        if not isinstance(row, dict):
            raise FalsificationError(f"open break row {line_number} must be an object")
        rows.append(row)
    return rows

def verify_no_critical_open_breaks(path: Path | str = DEFAULT_OPEN_BREAKS) -> dict[str, Any]:
    rows = load_open_breaks(path)
    critical = [
        row for row in rows
        if row.get("status") == "open" and row.get("class") in CRITICAL_BREAK_CLASSES
    ]
    return {
        "passed": not critical,
        "open_break_count": len([row for row in rows if row.get("status") == "open"]),
        "open_critical_breaks": len(critical),
        "critical_break_ids": [row.get("id") for row in critical],
    }
