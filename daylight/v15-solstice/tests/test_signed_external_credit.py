from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import ledger, solstice_harness
from tests import helpers


class SignedExternalCreditTests(unittest.TestCase):
    def test_signed_external_attestation_closes_one_external_obligation(self) -> None:
        obligation_id = "o.q2.external_formal_methods_audit"
        role = "formal-methods-auditor"
        entries = helpers.append_signed_external_attestation(
            helpers.seed_ledger_entries(),
            obligation_id=obligation_id,
            role=role,
            signer="ext:formal-methods-auditor",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path = root / "ledger.jsonl"
            corpus_path = root / "corpus.jsonl"
            rootset_path = root / "rootset.json"
            output_path = root / "output.jsonl"
            ledger.write_jsonl(ledger_path, entries)
            helpers.write_corpus(corpus_path, helpers.seed_corpus_entries())
            helpers.write_rootset(rootset_path, helpers.demo_rootset(role))
            scorecard, receipt, output_ledger = solstice_harness.generate_scorecard(
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                rootset_path=rootset_path,
                command="test",
            )
            ledger.write_jsonl(output_path, output_ledger)
            solstice_harness.verify_scorecard(
                scorecard,
                ledger_path=ledger_path,
                corpus_path=corpus_path,
                output_ledger_path=output_path,
                rootset_path=rootset_path,
                receipt=receipt,
            )
        body = scorecard["score_body"]
        self.assertEqual(body["final_score_M"], 999010)
        self.assertEqual(scorecard["status"], "solstice_external_partially_closed")
        self.assertIn(obligation_id, {row["obligation_id"] for row in body["closed_obligations"]})


if __name__ == "__main__":
    unittest.main()
