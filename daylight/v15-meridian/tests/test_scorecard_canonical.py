from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import daylight_harness
from tests.helpers import write_seed_inputs


class ScorecardCanonicalTests(unittest.TestCase):
    def _seed_scorecard(self, root: Path):
        ledger_path, corpus_path = write_seed_inputs(root)
        return daylight_harness.generate_scorecard(
            ledger_path=ledger_path, corpus_path=corpus_path, command="test"
        )[0]

    def test_scorecard_digest_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard = self._seed_scorecard(Path(tmp))
        first = daylight_harness.scorecard_digest(scorecard)
        second = daylight_harness.scorecard_digest(copy.deepcopy(scorecard))
        self.assertEqual(first, second)
        self.assertEqual(first, scorecard["scorecard_digest"])

    def test_verify_rejects_tampered_final_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scorecard = self._seed_scorecard(Path(tmp))
        scorecard["final_score_M"] = 998901
        with self.assertRaises(daylight_harness.HarnessError):
            daylight_harness.verify_scorecard(scorecard)


if __name__ == "__main__":
    unittest.main()
