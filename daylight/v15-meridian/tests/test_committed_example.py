from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src import daylight_harness
from tests.helpers import PACKAGE_ROOT, write_seed_inputs

EXAMPLES = PACKAGE_ROOT / "examples"


class CommittedExampleTests(unittest.TestCase):
    def test_committed_scorecard_is_evidence_bound_and_998900(self) -> None:
        scorecard = json.loads((EXAMPLES / "expected-scorecard.v15-meridian.json").read_text(encoding="utf-8"))
        self.assertEqual(scorecard["final_score_M"], 998900)
        daylight_harness.verify_scorecard(
            scorecard,
            ledger_path=EXAMPLES / "ledger.seed.jsonl",
            corpus_path=EXAMPLES / "corpus.seed.jsonl",
        )

    def test_committed_perfect_scorecard_is_evidence_bound_and_1000000(self) -> None:
        scorecard = json.loads((EXAMPLES / "expected-scorecard.perfect.v15-meridian.json").read_text(encoding="utf-8"))
        self.assertEqual(scorecard["final_score_M"], 1000000)
        daylight_harness.verify_scorecard(
            scorecard,
            ledger_path=EXAMPLES / "ledger.perfect.jsonl",
            corpus_path=EXAMPLES / "corpus.seed.jsonl",
        )

    def test_committed_scorecard_matches_fresh_regeneration(self) -> None:
        committed = json.loads((EXAMPLES / "expected-scorecard.v15-meridian.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = write_seed_inputs(Path(tmp))
            fresh, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path, corpus_path=corpus_path, command="score"
            )
        self.assertEqual(committed["scorecard_digest"], fresh["scorecard_digest"])
        self.assertEqual(committed["q_vector"], fresh["q_vector"])


if __name__ == "__main__":
    unittest.main()
