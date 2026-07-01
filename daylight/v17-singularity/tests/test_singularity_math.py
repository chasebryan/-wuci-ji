from __future__ import annotations

import copy
from decimal import Decimal
import unittest

from src import proof_atoms, registry, scorecard, singularity_math as sm


class SingularityMathTests(unittest.TestCase):
    def test_threshold_constant_matches_decimal_ln(self) -> None:
        computed = sm.decimal_text(Decimal(sm.B).ln())
        self.assertEqual(computed[:len(sm.OMEGA_THRESHOLD_DECIMAL_TEXT)], sm.OMEGA_THRESHOLD_DECIMAL_TEXT)

    def test_score_at_threshold_is_declaration_target(self) -> None:
        score, residue = sm.score_from_omega(sm.OMEGA_THRESHOLD)
        self.assertEqual(score, sm.DECLARATION_TARGET_AM_PLUS)
        self.assertLessEqual(residue, Decimal("0.000000001000000000000000000000000000000000000001"))

    def test_score_never_exceeds_declaration_target(self) -> None:
        score, _ = sm.score_from_omega(Decimal(1000))
        self.assertEqual(score, sm.DECLARATION_TARGET_AM_PLUS)

    def test_effective_omega_uses_weakest_field_governor(self) -> None:
        result = sm.effective_omega(
            omega_sum=Decimal("100"),
            omega_min=Decimal("2"),
            debt_omega=Decimal("0"),
            overclaim_debt_omega=Decimal("0"),
            staleness_debt_omega=Decimal("0"),
        )
        self.assertEqual(result["omega_weak"], Decimal("10"))
        self.assertEqual(result["omega_eff"], Decimal("10"))

    def test_effective_omega_never_goes_negative(self) -> None:
        result = sm.effective_omega(
            omega_sum=Decimal("2"),
            omega_min=Decimal("2"),
            debt_omega=Decimal("3"),
            overclaim_debt_omega=Decimal("0"),
            staleness_debt_omega=Decimal("0"),
        )
        self.assertEqual(result["omega_eff"], Decimal("0"))

    def test_score_is_zero_when_collapse_true(self) -> None:
        score, residue = sm.score_from_omega(Decimal(1000), collapse=True)
        self.assertEqual(score, 0)
        self.assertEqual(residue, Decimal(1))

    def test_debt_lowers_score(self) -> None:
        higher, _ = sm.score_from_omega(Decimal(12))
        lower, _ = sm.score_from_omega(Decimal(11))
        self.assertLess(lower, higher)

    def test_staleness_debt_lowers_score(self) -> None:
        state = scorecard.load_state("daylight/v17-singularity/examples/state.baseline.json")
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        clean = scorecard.build_scorecard(state, fields, atoms)
        stale = copy.deepcopy(state)
        stale["staleness_debt_uomega"] = 1_000_000
        stale_card = scorecard.build_scorecard(stale, fields, atoms)
        self.assertLess(stale_card["score_AM_plus"], clean["score_AM_plus"])

    def test_overclaim_debt_lowers_score(self) -> None:
        state = scorecard.load_state("daylight/v17-singularity/examples/state.baseline.json")
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        clean = scorecard.build_scorecard(state, fields, atoms)
        overclaim = copy.deepcopy(state)
        overclaim["overclaim_debt_uomega"] = 1_000_000
        overclaim_card = scorecard.build_scorecard(overclaim, fields, atoms)
        self.assertLess(overclaim_card["score_AM_plus"], clean["score_AM_plus"])

    def test_perfect_reserve_applies_to_closed_field(self) -> None:
        result = sm.field_closure(verified_credit=10, possible_credit=10)
        self.assertTrue(result["perfect_reserve_applied"])
        self.assertEqual(result["closure"], Decimal(1) - Decimal(1) / Decimal(sm.EPSILON_DENOMINATOR))

    def test_alpha_sum_equals_27_over_2(self) -> None:
        self.assertEqual(registry.alpha_sum(registry.load_fields_registry()), registry.EXPECTED_ALPHA_SUM)

    def test_declaration_requires_hard_debts_clear(self) -> None:
        self.assertTrue(sm.declared(
            omega=sm.OMEGA_THRESHOLD,
            score_am_plus=sm.DECLARATION_TARGET_AM_PLUS,
            field_thresholds_pass=True,
            contradiction_debt=0,
            critical_break_debt=0,
            score_inflation_M=0,
            collapse=False,
        ))
        self.assertFalse(sm.declared(
            omega=sm.OMEGA_THRESHOLD,
            score_am_plus=sm.DECLARATION_TARGET_AM_PLUS,
            field_thresholds_pass=True,
            contradiction_debt=1,
            critical_break_debt=0,
            score_inflation_M=0,
            collapse=False,
        ))
        self.assertFalse(sm.declared(
            omega=sm.OMEGA_THRESHOLD,
            score_am_plus=sm.DECLARATION_TARGET_AM_PLUS,
            field_thresholds_pass=False,
            contradiction_debt=0,
            critical_break_debt=0,
            score_inflation_M=0,
            collapse=False,
        ))


if __name__ == "__main__":
    unittest.main()
