from __future__ import annotations

import copy
import unittest

from src import proof_atoms, registry, scorecard


BASELINE_STATE = "daylight/v17-singularity/examples/state.baseline.json"


class DebtAndCollapseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = registry.load_fields_registry()
        self.atoms = proof_atoms.load_proof_atom_registry()
        self.state = scorecard.load_state(BASELINE_STATE)

    def _score(self, state: dict) -> dict:
        return scorecard.build_scorecard(state, self.registry, self.atoms)

    def test_contradiction_debt_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["contradiction_debt"] = 1
        card = self._score(state)
        self.assertTrue(card["collapse"])
        self.assertEqual(card["score_AM_plus"], 0)

    def test_critical_break_debt_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["critical_break_debt"] = 1
        card = self._score(state)
        self.assertTrue(card["collapse"])
        self.assertEqual(card["score_AM_plus"], 0)

    def test_manual_score_detected_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["collapse_flags"]["manual_score_detected"] = True
        self.assertEqual(self._score(state)["status"], "singularity_collapsed")

    def test_manual_score_accepted_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["collapse_flags"]["manual_score_accepted"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_forged_scorecard_accepted_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["collapse_flags"]["forged_scorecard_accepted"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_unsigned_external_credit_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["collapse_flags"]["unsigned_external_credit"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_opens_without_policy_evidence_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["collapse_flags"]["opens_without_policy_evidence"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_severe_boundary_overclaim_collapses(self) -> None:
        state = copy.deepcopy(self.state)
        state["collapse_flags"]["severe_boundary_overclaim"] = True
        self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_release_boundary_overclaims_collapse(self) -> None:
        for flag in ("production_overclaim", "whole_system_pq_overclaim", "runtime_containment_overclaim"):
            with self.subTest(flag=flag):
                state = copy.deepcopy(self.state)
                state["collapse_flags"][flag] = True
                self.assertEqual(self._score(state)["score_AM_plus"], 0)

    def test_non_severe_debt_lowers_without_collapse(self) -> None:
        clean = self._score(self.state)
        state = copy.deepcopy(self.state)
        state["debt_uomega"] = 1_000_000
        card = self._score(state)
        self.assertFalse(card["collapse"])
        self.assertLess(card["score_AM_plus"], clean["score_AM_plus"])


if __name__ == "__main__":
    unittest.main()
