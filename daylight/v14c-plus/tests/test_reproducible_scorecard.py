from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import daylight_harness
from tests.helpers import EVALUATORS, WEIGHTS, write_seed_inputs


class ReproducibleScorecardTests(unittest.TestCase):
    def test_same_frozen_inputs_regenerate_same_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = write_seed_inputs(Path(tmp))
            first, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                weights_path=WEIGHTS,
                evaluators_path=EVALUATORS,
                command="test",
            )
            second, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                weights_path=WEIGHTS,
                evaluators_path=EVALUATORS,
                command="test",
            )
        self.assertEqual(first, second)
        self.assertEqual(first["scorecard_digest"], second["scorecard_digest"])


if __name__ == "__main__":
    unittest.main()
