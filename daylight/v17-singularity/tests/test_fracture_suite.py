from __future__ import annotations

import copy
import unittest

from src import fracture, proof_atoms, registry, scorecard


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"


class FractureSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fields = registry.load_fields_registry()
        self.atoms = proof_atoms.load_proof_atom_registry()
        self.state = scorecard.load_state(CURRENT_STATE)
        self.card = scorecard.build_scorecard(self.state, self.fields, self.atoms)

    def test_fracture_suite_passes_for_generated_scorecard(self) -> None:
        result = fracture.run_fracture_suite(self.state, self.fields, self.atoms, self.card)
        self.assertTrue(result["passed"])

    def test_every_listed_mutation_is_rejected(self) -> None:
        result = fracture.run_fracture_suite(self.state, self.fields, self.atoms, self.card)
        self.assertEqual([row["mutation"] for row in result["results"]], fracture.MUTATION_CLASSES)
        self.assertTrue(all(row["passed"] for row in result["results"]))

    def test_removing_proof_atom_changes_digest_and_rejects(self) -> None:
        mutated_atoms = copy.deepcopy(self.atoms)
        mutated_atoms["proof_atoms"] = mutated_atoms["proof_atoms"][1:]
        with self.assertRaises(ValueError):
            scorecard.verify_scorecard_object(self.card, self.state, self.fields, mutated_atoms)

    def test_forged_declaration_rejects(self) -> None:
        forged = copy.deepcopy(self.card)
        forged["declared"] = True
        forged["status"] = "singularity_declared"
        forged["score_AM_plus"] = 999_999_999
        forged["omega_eff_decimal"] = forged["omega_threshold_decimal"]
        forged["scorecard_digest"] = scorecard.scorecard_digest(forged)
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.verify_scorecard_object(forged, self.state, self.fields, self.atoms)


if __name__ == "__main__":
    unittest.main()
