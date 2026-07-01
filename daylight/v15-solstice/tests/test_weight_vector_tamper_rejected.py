from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src import ledger, solstice_harness
from tests import helpers


class WeightVectorTamperTests(unittest.TestCase):
    def test_weight_vector_digest_is_pinned_at_verification(self) -> None:
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

            tampered_weights = json.loads(helpers.WEIGHTS.read_text(encoding="utf-8"))
            tampered_weights["weights"][0][1] = "159/1000"
            tampered_weights["weights"][-1][1] = "21/1000"
            tampered_path = root / "weights.tampered.json"
            tampered_path.write_text(json.dumps(tampered_weights, sort_keys=True), encoding="utf-8")

            with self.assertRaises(solstice_harness.SolsticeError):
                solstice_harness.verify_scorecard(
                    scorecard,
                    ledger_path=ledger_path,
                    corpus_path=corpus_path,
                    output_ledger_path=output_path,
                    weights_path=tampered_path,
                    receipt=receipt,
                )


if __name__ == "__main__":
    unittest.main()
