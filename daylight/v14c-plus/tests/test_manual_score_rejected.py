from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import daylight_harness
from tests.helpers import EVALUATORS, WEIGHTS, write_seed_inputs


class ManualScoreRejectedTests(unittest.TestCase):
    def test_manual_override_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = write_seed_inputs(Path(tmp))
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                weights_path=WEIGHTS,
                evaluators_path=EVALUATORS,
                command="test",
            )
        scorecard["manual_override"] = True
        with self.assertRaises(daylight_harness.HarnessError):
            daylight_harness.verify_scorecard(scorecard)


if __name__ == "__main__":
    unittest.main()
