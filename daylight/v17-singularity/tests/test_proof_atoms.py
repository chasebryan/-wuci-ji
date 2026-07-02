from __future__ import annotations

import copy
import unittest

from src import proof_atoms, registry, scorecard


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"
FIXTURE_STATE = "daylight/v17-singularity/examples/state.declaration-fixture.json"


class ProofAtomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fields = registry.load_fields_registry()
        self.atoms = proof_atoms.load_proof_atom_registry()
        self.current_state = scorecard.load_state(CURRENT_STATE)
        self.fixture_state = scorecard.load_state(FIXTURE_STATE)

    def test_every_field_has_at_least_one_atom(self) -> None:
        proof_atoms.validate_proof_atom_registry(self.atoms)
        fields_with_atoms = {atom["field_id"] for atom in self.atoms["proof_atoms"]}
        self.assertEqual(fields_with_atoms, set(registry.FIELD_IDS))

    def test_proof_atom_credit_must_be_positive_integer(self) -> None:
        atoms = copy.deepcopy(self.atoms)
        atoms["proof_atoms"][0]["credit"] = 0
        with self.assertRaises(proof_atoms.ProofAtomError):
            proof_atoms.validate_proof_atom_registry(atoms)

    def test_unknown_verifier_key_rejects(self) -> None:
        atoms = copy.deepcopy(self.atoms)
        atoms["proof_atoms"][0]["verifier_key"] = "shell_command"
        with self.assertRaises(proof_atoms.ProofAtomError):
            proof_atoms.validate_proof_atom_registry(atoms)

    def test_fixture_pass_fails_when_state_fixture_false(self) -> None:
        atom = next(atom for atom in self.atoms["proof_atoms"] if atom["verifier_key"] == "fixture_pass")
        closed, reason = proof_atoms.verify_atom(atom, self.current_state)
        self.assertFalse(closed)
        self.assertEqual(reason, "fixture_only_atom_open")

    def test_fixture_pass_may_pass_when_fixture_true_and_allowed(self) -> None:
        atom = next(atom for atom in self.atoms["proof_atoms"] if atom["verifier_key"] == "fixture_pass")
        closed, reason = proof_atoms.verify_atom(atom, self.fixture_state)
        self.assertTrue(closed)
        self.assertEqual(reason, "closed")

    def test_evidence_paths_cannot_escape_package_directory(self) -> None:
        atoms = copy.deepcopy(self.atoms)
        atom = next(atom for atom in atoms["proof_atoms"] if atom["verifier_key"] == "package_file_present")
        atom["evidence_path"] = "../README.md"
        with self.assertRaises(proof_atoms.ProofAtomError):
            proof_atoms.validate_proof_atom_registry(atoms)

    def test_field_closure_is_derived_from_atoms_not_direct_state_fields(self) -> None:
        state = copy.deepcopy(self.current_state)
        state["fields"] = [{"id": "F1", "verified_credit": 1, "possible_credit": 1}]
        with self.assertRaises(scorecard.ScorecardError):
            scorecard.build_scorecard(state, self.fields, self.atoms)


if __name__ == "__main__":
    unittest.main()
