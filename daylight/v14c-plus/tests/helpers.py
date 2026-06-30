from __future__ import annotations

from pathlib import Path
from typing import Any

from src import corpus, ledger
from src.canonical_json import canonical_sha256


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
EVALUATORS = PACKAGE_ROOT / "rules" / "q-evaluators.json"


def witness(label: str) -> dict[str, str]:
    return {
        "witness_type": label,
        "witness_digest": canonical_sha256({"witness": label}, "DAYLIGHT-v14C+-TEST-WITNESS:"),
    }


def transcript(label: str) -> str:
    return canonical_sha256({"transcript": label}, "DAYLIGHT-v14C+-TEST-TRANSCRIPT:")


def artifact(label: str) -> str:
    return canonical_sha256({"artifact": label}, "DAYLIGHT-v14C+-TEST-ARTIFACT:")


def seed_ledger_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for entry_type in (
        "source",
        "build",
        "test",
        "adversarial_run",
        "harness_execution",
        "corpus_snapshot",
        "claim",
        "downgrade",
    ):
        entries, _ = ledger.append_entry(
            entries,
            entry_type=entry_type,
            artifact_digest=artifact(entry_type),
            witness=witness(entry_type),
            transcript_digest=transcript(entry_type),
        )
    return entries


def seed_corpus_entries() -> list[dict[str, str]]:
    entries = []
    for category in sorted(corpus.SUPPORTED_CATEGORIES):
        entries.append(
            {
                "corpus_entry_id": f"corpus-{category}",
                "category": category,
                "generator": "daylight-v14c-plus-seed",
                "input_digest": artifact(category),
                "observed_behavior": "rejected",
                "classification": "negative-evidence",
                "coverage_contribution": "required",
                "linked_ledger_entry": "ledger-entry-0004-adversarial_run",
                "timestamp_utc": ledger.FIXED_TIMESTAMP,
            }
        )
    return entries


def write_seed_inputs(root: Path) -> tuple[Path, Path]:
    ledger_path = root / "ledger.seed.jsonl"
    corpus_path = root / "corpus.seed.jsonl"
    ledger.write_jsonl(ledger_path, seed_ledger_entries())
    corpus_lines = "".join(__import__("json").dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in seed_corpus_entries())
    corpus_path.write_text(corpus_lines, encoding="utf-8")
    return ledger_path, corpus_path

