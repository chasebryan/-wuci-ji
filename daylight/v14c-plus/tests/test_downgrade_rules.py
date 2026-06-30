from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import corpus, daylight_harness, downgrade, scoring
from tests.helpers import EVALUATORS, WEIGHTS, seed_corpus_entries, seed_ledger_entries, write_seed_inputs


class DowngradeRuleTests(unittest.TestCase):
    def test_recomputed_q_drop_emits_downgrade(self) -> None:
        current = copy.deepcopy(scoring.TARGET_Q_VECTOR)
        current[1] = ("q2_formalism_mathematical_density", "997/1000")
        result = downgrade.evaluate_downgrade(
            claimed_q=[[name, value] for name, value in scoring.TARGET_Q_VECTOR],
            recomputed_q=[[name, value] for name, value in current],
            claim_state="candidate",
        )
        self.assertEqual(result["claim_state"], "provisional")
        self.assertEqual(result["events"][0]["reason"], "recomputed_q_below_claimed_q")

    def test_missing_evaluator_evidence_blocks_score_generation(self) -> None:
        entries = [entry for entry in seed_ledger_entries() if entry["entry_type"] != "adversarial_run"]
        snapshot = corpus.freeze_corpus(seed_corpus_entries())
        evaluators = scoring.load_q_evaluators(EVALUATORS)
        with self.assertRaises(scoring.ScoreError):
            scoring.evaluate_q(evaluators, entries, snapshot)

    def test_corpus_mutation_during_scoring_is_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path, corpus_path = write_seed_inputs(root)
            original = corpus_path.read_text(encoding="utf-8")
            def mutate_after_read(path: Path):
                entries = old_loader(path)
                path.write_text(original + original.splitlines()[0] + "\n", encoding="utf-8")
                return entries
            old_loader = corpus.load_jsonl
            try:
                corpus.load_jsonl = mutate_after_read  # type: ignore[assignment]
                with self.assertRaises(daylight_harness.HarnessError):
                    daylight_harness.generate_scorecard(
                        ledger_path=ledger_path,
                        corpus_path=corpus_path,
                        weights_path=WEIGHTS,
                        evaluators_path=EVALUATORS,
                        command="test",
                    )
            finally:
                corpus.load_jsonl = old_loader  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
