from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import daylight_harness
from tests.helpers import EVALUATORS, WEIGHTS, write_seed_inputs


class InputOutputHeadTests(unittest.TestCase):
    def test_scorecard_has_distinct_input_and_output_heads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = write_seed_inputs(Path(tmp))
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                weights_path=WEIGHTS,
                evaluators_path=EVALUATORS,
                command="test",
            )
        self.assertTrue(scorecard["input_ledger_head"])
        self.assertTrue(scorecard["output_ledger_head"])
        self.assertNotEqual(scorecard["input_ledger_head"], scorecard["output_ledger_head"])


if __name__ == "__main__":
    unittest.main()
