from __future__ import annotations

import copy
import unittest

from src import event_horizon, proof_atoms, registry, scorecard


BASELINE_STATE = "daylight/v17-singularity/examples/state.baseline.json"
FIXTURE_STATE = "daylight/v17-singularity/examples/state.declaration-fixture.json"
FIXTURE_ATOMS = "daylight/v17-singularity/examples/proof-atoms.declaration-fixture.v17.json"


class EventHorizonKernelTests(unittest.TestCase):
    def test_current_declaration_gate_refuses_but_checks_pass(self) -> None:
        result = event_horizon.run_declaration_gate(state_path=BASELINE_STATE)
        self.assertEqual(result["decision"], "declaration_refused")
        self.assertFalse(result["allowed"])
        self.assertTrue(result["fracture_suite"]["passed"])
        self.assertTrue(result["cross_verifier_agreement"]["passed"])
        self.assertEqual(result["falsification"]["open_critical_breaks"], 0)
        self.assertEqual(result["weakest_field"], "F2")

    def test_fixture_score_declares_but_gate_refuses_claim_use(self) -> None:
        result = event_horizon.run_declaration_gate(
            state_path=FIXTURE_STATE,
            proof_atoms_path=FIXTURE_ATOMS,
        )
        self.assertEqual(result["score_AM_plus"], 999_999_999)
        self.assertTrue(result["declared_by_scorecard"])
        self.assertFalse(result["allowed"])
        self.assertEqual(result["decision"], "declaration_refused")

    def test_removed_proof_atom_changes_scorecard_digest(self) -> None:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        state = scorecard.load_state(BASELINE_STATE)
        original = scorecard.build_scorecard(state, fields, atoms)
        mutated = copy.deepcopy(atoms)
        mutated["proof_atoms"] = mutated["proof_atoms"][1:]
        changed = scorecard.build_scorecard(state, fields, mutated)
        self.assertNotEqual(changed["scorecard_digest"], original["scorecard_digest"])


if __name__ == "__main__":
    unittest.main()

