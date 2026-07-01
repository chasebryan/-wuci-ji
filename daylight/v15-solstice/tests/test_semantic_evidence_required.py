from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import ledger, solstice_harness
from tests import helpers


class SemanticEvidenceRequiredTests(unittest.TestCase):
    def test_named_obligation_without_semantic_digest_shape_does_not_close(self) -> None:
        entries = []
        for entry_type, closes in helpers.INTERNAL_LEDGER_PLAN:
            entries, _ = ledger.append_entry(
                entries,
                entry_type=entry_type,
                artifact_digest="not-a-sha256" if entry_type == "source" else helpers.artifact(entry_type),
                witness=helpers.witness(entry_type),
                transcript_digest=helpers.transcript(entry_type),
                closes_obligations=closes,
            )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path = root / "ledger.jsonl"
            corpus_path = root / "corpus.jsonl"
            ledger.write_jsonl(ledger_path, entries)
            helpers.write_corpus(corpus_path, helpers.seed_corpus_entries())
            scorecard, _, _ = solstice_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                command="test",
            )
        body = scorecard["score_body"]
        self.assertLess(body["final_score_M"], 998900)
        self.assertIn("o.q8.classical_margin_source", {row["obligation_id"] for row in body["open_obligations"]})


if __name__ == "__main__":
    unittest.main()
