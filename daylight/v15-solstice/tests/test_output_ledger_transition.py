from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import ledger, solstice_harness
from tests import helpers


class OutputLedgerTransitionTests(unittest.TestCase):
    def test_output_ledger_must_equal_input_plus_score_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path, corpus_path = helpers.write_seed_inputs(root)
            scorecard, receipt, output_ledger = solstice_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                command="test",
            )
            output_path = root / "output.jsonl"
            ledger.write_jsonl(output_path, output_ledger)
            solstice_harness.verify_scorecard(
                scorecard,
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                output_ledger_path=output_path,
                receipt=receipt,
            )

            truncated_path = root / "output.truncated.jsonl"
            ledger.write_jsonl(truncated_path, output_ledger[:-1])
            with self.assertRaises(solstice_harness.SolsticeError):
                solstice_harness.verify_scorecard(
                    scorecard,
                    ledger_path=ledger_path,
                    corpus_path=corpus_path,
                    output_ledger_path=truncated_path,
                    receipt=receipt,
                )


if __name__ == "__main__":
    unittest.main()
