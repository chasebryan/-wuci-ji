from __future__ import annotations

import copy
from decimal import Decimal
import unittest

from src import event_horizon, proof_atoms, registry, scorecard, singularity_math as sm


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"


class EventHorizonMathTests(unittest.TestCase):
    def test_ln_1e9_constant_matches_decimal_ln(self) -> None:
        computed = Decimal(1_000_000_000).ln()
        self.assertEqual(sm.decimal_text(computed)[:len(sm.LN_1E9_DECIMAL_TEXT)], sm.LN_1E9_DECIMAL_TEXT)
        self.assertEqual(event_horizon.LN_1E9, sm.LN_1E9)

    def test_alpha_sum_equals_27_over_2(self) -> None:
        self.assertEqual(registry.alpha_sum(registry.load_fields_registry()), registry.EXPECTED_ALPHA_SUM)

    def test_epsilon_equals_one_over_10_to_12(self) -> None:
        self.assertEqual(sm.EPSILON, Decimal(1) / Decimal(1_000_000_000_000))

    def test_perfect_reserve_prevents_closure_one(self) -> None:
        result = sm.field_closure(verified_credit=10, possible_credit=10)
        self.assertTrue(result["perfect_reserve_applied"])
        self.assertLess(result["closure"], Decimal(1))

    def test_weak_governor_limits_omega_eff(self) -> None:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(CURRENT_STATE)
        card = scorecard.build_scorecard(state, fields, atoms)
        self.assertLessEqual(Decimal(card["omega_eff_decimal"]), Decimal(card["omega_weak_decimal"]))

    def test_score_at_threshold_returns_target(self) -> None:
        score, _ = sm.score_from_omega(sm.LN_1E9)
        self.assertEqual(score, sm.DECLARATION_TARGET_AM_PLUS)

    def test_score_never_exceeds_target(self) -> None:
        score, _ = sm.score_from_omega(Decimal(1000))
        self.assertEqual(score, sm.DECLARATION_TARGET_AM_PLUS)

    def test_collapse_returns_zero(self) -> None:
        score, residue = sm.score_from_omega(Decimal(1000), collapse=True)
        self.assertEqual(score, 0)
        self.assertEqual(residue, Decimal(1))

    def test_debt_lowers_omega_eff_and_score(self) -> None:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(CURRENT_STATE)
        clean = scorecard.build_scorecard(state, fields, atoms)
        debt_state = copy.deepcopy(state)
        debt_state["debt_uomega"] = 1_000_000
        debt = scorecard.build_scorecard(debt_state, fields, atoms)
        self.assertLess(Decimal(debt["omega_eff_decimal"]), Decimal(clean["omega_eff_decimal"]))
        self.assertLess(debt["score_AM_plus"], clean["score_AM_plus"])

    def test_staleness_debt_lowers_score(self) -> None:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(CURRENT_STATE)
        clean = scorecard.build_scorecard(state, fields, atoms)
        stale_state = copy.deepcopy(state)
        stale_state["staleness_debt_uomega"] = 1_000_000
        stale = scorecard.build_scorecard(stale_state, fields, atoms)
        self.assertLess(stale["score_AM_plus"], clean["score_AM_plus"])

    def test_overclaim_debt_lowers_score(self) -> None:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(CURRENT_STATE)
        clean = scorecard.build_scorecard(state, fields, atoms)
        overclaim_state = copy.deepcopy(state)
        overclaim_state["overclaim_debt_uomega"] = 1_000_000
        overclaim = scorecard.build_scorecard(overclaim_state, fields, atoms)
        self.assertLess(overclaim["score_AM_plus"], clean["score_AM_plus"])

    def test_field_threshold_failure_prevents_declaration(self) -> None:
        self.assertFalse(sm.declared(
            omega_eff=sm.LN_1E9,
            score_am_plus=sm.DECLARATION_TARGET_AM_PLUS,
            field_thresholds_pass=False,
            contradiction_debt=0,
            critical_break_debt=0,
            score_inflation_M=0,
            collapse=False,
            fracture_suite_passed=True,
            cross_verifier_agreement_passed=True,
            claim_usable=True,
            fixture=False,
        ))

    def test_all_hard_declaration_conditions_must_pass(self) -> None:
        kwargs = {
            "omega_eff": sm.LN_1E9,
            "score_am_plus": sm.DECLARATION_TARGET_AM_PLUS,
            "field_thresholds_pass": True,
            "contradiction_debt": 0,
            "critical_break_debt": 0,
            "score_inflation_M": 0,
            "collapse": False,
            "fracture_suite_passed": True,
            "cross_verifier_agreement_passed": True,
            "claim_usable": True,
            "fixture": False,
        }
        self.assertTrue(sm.declared(**kwargs))
        for key, value in [
            ("contradiction_debt", 1),
            ("critical_break_debt", 1),
            ("score_inflation_M", 1),
            ("collapse", True),
            ("fracture_suite_passed", False),
            ("cross_verifier_agreement_passed", False),
            ("claim_usable", False),
            ("fixture", True),
        ]:
            mutated = dict(kwargs)
            mutated[key] = value
            self.assertFalse(sm.declared(**mutated), key)


if __name__ == "__main__":
    unittest.main()
