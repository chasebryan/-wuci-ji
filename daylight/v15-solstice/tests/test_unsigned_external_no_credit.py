from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import ledger, solstice_harness
from tests import helpers


class UnsignedExternalNoCreditTests(unittest.TestCase):
    def test_unsigned_external_attestation_names_obligation_but_gets_no_credit(self) -> None:
        entries = helpers.seed_ledger_entries()
        entries, _ = ledger.append_entry(
            entries,
            entry_type="external_attestation",
            artifact_digest=helpers.artifact("unsigned-external"),
            witness=helpers.witness("external_attestation"),
            transcript_digest=helpers.transcript("unsigned-external"),
            closes_obligations=["o.q7.external_red_team"],
            external_signer_id="ext:red-team",
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
        self.assertEqual(body["final_score_M"], 998900)
        self.assertIn("o.q7.external_red_team", {row["obligation_id"] for row in body["open_obligations"]})


if __name__ == "__main__":
    unittest.main()
