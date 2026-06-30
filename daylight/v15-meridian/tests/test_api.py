from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import api
from tests import helpers


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = api.load_registry()
        self.weights = api.load_weights()

    def test_derive_and_score_internal_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = helpers.write_seed_inputs(Path(tmp))
            ledger = api.load_ledger(ledger_path)
            corpus = api.load_corpus(corpus_path)
            closed = api.resolve_closed_obligations(self.registry, ledger, corpus)
            q_vector = api.derive_q_vector(self.registry, closed)
            score = api.score_q_vector(q_vector, self.weights, api.labels(self.registry))
        self.assertEqual(score["final_score_M"], 998900)
        self.assertEqual(len(closed), 24)

    def test_generate_and_verify_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = helpers.write_seed_inputs(Path(tmp))
            scorecard, receipt, _ = api.generate_scorecard(ledger_path=ledger_path, corpus_path=corpus_path)
            result = api.verify_scorecard(scorecard, ledger_path=ledger_path, corpus_path=corpus_path)
        self.assertTrue(result.ok)
        self.assertTrue(result.evidence_bound)
        self.assertEqual(scorecard["final_score_M"], 998900)

    def test_verify_returns_result_not_exception_on_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = helpers.write_seed_inputs(Path(tmp))
            scorecard, _, _ = api.generate_scorecard(ledger_path=ledger_path, corpus_path=corpus_path)
        scorecard["final_score_M"] = 999999
        result = api.verify_scorecard(scorecard)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)

    def test_frontier_status_structural_and_evidence(self) -> None:
        structural = api.frontier_status(self.registry)
        self.assertEqual(structural["internal_ceiling_M"], 998900)
        self.assertEqual(structural["perfect_score_M"], 1000000)
        self.assertEqual(structural["structural_external_residue_M"], 1100)
        self.assertEqual(structural["open_internal_residue_M"], 0)
        self.assertEqual(structural["open_external_residue_M"], 1100)

        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = helpers.write_perfect_inputs(Path(tmp))
            ledger = api.load_ledger(ledger_path)
            corpus = api.load_corpus(corpus_path)
            closed = api.resolve_closed_obligations(self.registry, ledger, corpus)
            report = api.frontier_status(self.registry, closed)
        self.assertEqual(report["open_external_residue_M"], 0)
        self.assertEqual(report["open_external_obligations"], [])

    def test_frontier_markdown_renders(self) -> None:
        md = api.frontier_markdown(api.frontier_status(self.registry))
        self.assertIn("Daylight v15 Meridian Frontier Report", md)
        self.assertIn("998900M / 1000000M", md)


if __name__ == "__main__":
    unittest.main()
