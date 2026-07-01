"""Negative-evidence corpus freezing for Daylight v15+ Solstice.

Forked from v14C+. Corpus entries may now carry an optional ``closes_obligations``
list so a negative-evidence item can discharge a corpus-bound obligation (for
example the modeled-adversary or transcript-mismatch survival obligations). The
field is part of the frozen snapshot body, so the snapshot digest covers it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .canonical_json import canonical_sha256


SNAPSHOT_DOMAIN = "DAYLIGHT-v15-SOLSTICE-CORPUS:"
SUPPORTED_CATEGORIES = {
    "boundary_violation",
    "proof_failure",
    "adversarial_input",
    "statistical_outlier",
    "transcript_mismatch",
    "downgrade_trigger",
    "manual_score_mutation",
    "reproducibility_failure",
}


class CorpusError(ValueError):
    pass


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not path.exists():
        return entries
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise CorpusError(f"invalid corpus JSON at line {line_no}: {exc}") from exc
        validate_entry(entry)
        entries.append(entry)
    return entries


def validate_entry(entry: dict[str, Any]) -> None:
    required = (
        "corpus_entry_id",
        "category",
        "generator",
        "input_digest",
        "observed_behavior",
        "classification",
        "coverage_contribution",
        "linked_ledger_entry",
        "timestamp_utc",
    )
    missing = [field for field in required if field not in entry]
    if missing:
        raise CorpusError("corpus entry missing fields: " + ", ".join(missing))
    if entry["category"] not in SUPPORTED_CATEGORIES:
        raise CorpusError(f"unsupported corpus category: {entry['category']}")
    closes = entry.get("closes_obligations", [])
    if not isinstance(closes, list) or any(not isinstance(item, str) or not item for item in closes):
        raise CorpusError("closes_obligations must be a list of non-empty strings")


def _snapshot_body(entries: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(entries, key=lambda item: str(item.get("corpus_entry_id", "")))
    return {
        "snapshot_version": "daylight-v15-solstice-corpus-snapshot-v0.1",
        "frozen": True,
        "entry_count": len(ordered),
        "categories": sorted({str(entry["category"]) for entry in ordered}),
        "entries": ordered,
    }


def freeze_corpus(entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    materialized = list(entries)
    for entry in materialized:
        validate_entry(entry)
    snapshot = _snapshot_body(materialized)
    snapshot["corpus_snapshot_digest"] = canonical_sha256(snapshot, SNAPSHOT_DOMAIN)
    return snapshot


def verify_snapshot(snapshot: dict[str, Any]) -> None:
    if not snapshot.get("frozen"):
        raise CorpusError("corpus snapshot is not frozen")
    expected = snapshot.get("corpus_snapshot_digest")
    body = {key: value for key, value in snapshot.items() if key != "corpus_snapshot_digest"}
    actual = canonical_sha256(body, SNAPSHOT_DOMAIN)
    if actual != expected:
        raise CorpusError("corpus snapshot digest mismatch")


def freeze_path(path: Path) -> dict[str, Any]:
    return freeze_corpus(load_jsonl(path))
