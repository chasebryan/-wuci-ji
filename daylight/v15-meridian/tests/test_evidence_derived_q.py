from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import corpus, daylight_harness, ledger, obligations, scoring
from tests import helpers
from tests.helpers import OBLIGATIONS, WEIGHTS


class EvidenceDerivedQTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = obligations.load_registry(OBLIGATIONS)
        self.weights = scoring.load_weights(WEIGHTS)

    def test_no_evidence_yields_zero_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty_ledger = root / "empty.jsonl"
            empty_corpus = root / "empty-corpus.jsonl"
            ledger.write_jsonl(empty_ledger, [])
            empty_corpus.write_text("", encoding="utf-8")
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=empty_ledger, corpus_path=empty_corpus, command="test"
            )
        self.assertEqual(scorecard["final_score_M"], 0)
        self.assertEqual(scorecard["closed_obligations"], [])
        self.assertTrue(all(value == "0/1" for _, value in scorecard["q_vector"]))

    def test_dropping_one_evidence_class_lowers_exactly_that_dimension(self) -> None:
        # Build a ledger that closes every internal obligation except the proof entry.
        entries: list = []
        for entry_type, closes in helpers.INTERNAL_LEDGER_PLAN:
            if entry_type == "proof":
                continue
            entries, _ = ledger.append_entry(
                entries,
                entry_type=entry_type,
                artifact_digest=helpers.artifact(entry_type),
                witness=helpers.witness(entry_type),
                transcript_digest=helpers.transcript(entry_type),
                closes_obligations=closes,
            )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path = root / "no-proof.jsonl"
            corpus_path = root / "corpus.seed.jsonl"
            ledger.write_jsonl(ledger_path, entries)
            helpers.write_corpus(corpus_path, helpers.seed_corpus_entries())
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path, corpus_path=corpus_path, command="test"
            )
        q_map = dict(scorecard["q_vector"])
        # o.q2.exact_rational_proof (500) is open; o.q2.formal_density_tests (499) stays closed.
        self.assertEqual(q_map["q2_formalism_mathematical_density"], "499/1000")
        # Other internal-ceiling dimensions are unaffected.
        self.assertEqual(q_map["q1_doctrine_master_law"], "1/1")
        self.assertEqual(q_map["q10_implementation_traceability"], "999/1000")
        self.assertEqual(scorecard["final_score_M"], 998900 - 110 * 500)

    def test_unknown_obligation_id_cannot_contribute(self) -> None:
        with self.assertRaises(obligations.ObligationError):
            obligations.derive_q_vector(self.registry, {"o.does.not.exist"})

    def test_corpus_bound_obligation_requires_corpus_evidence(self) -> None:
        # Without the adversarial_input corpus category, q7's modeled-adversary
        # obligation cannot close.
        corpus_entries = [e for e in helpers.seed_corpus_entries() if e["category"] != "adversarial_input"]
        snapshot = corpus.freeze_corpus(corpus_entries)
        closed = obligations.resolve_closed_obligations(self.registry, helpers.seed_ledger_entries(), snapshot)
        self.assertNotIn("o.q7.modeled_adversary_corpus", closed)
        self.assertIn("o.q7.transcript_survival_corpus", closed)


if __name__ == "__main__":
    unittest.main()
