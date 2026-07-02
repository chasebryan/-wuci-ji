from __future__ import annotations

import unittest

from src import horizon_policy, proof_atoms, registry, scorecard


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"
FIXTURE_STATE = "daylight/v17-singularity/examples/state.declaration-fixture.json"


class HorizonPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        fields = registry.load_fields_registry()
        atoms = proof_atoms.load_proof_atom_registry()
        self.current = scorecard.build_scorecard(scorecard.load_state(CURRENT_STATE), fields, atoms)
        self.fixture = scorecard.build_scorecard(scorecard.load_state(FIXTURE_STATE), fields, atoms)

    def test_research_policy_passes_current_state(self) -> None:
        blockers = horizon_policy.policy_blockers(self.current, horizon_policy.policy_for_mode("research"))
        self.assertEqual(blockers, [])

    def test_declaration_policy_rejects_current_state(self) -> None:
        blockers = horizon_policy.policy_blockers(self.current, horizon_policy.policy_for_mode("declaration"))
        self.assertIn("cross_verifier_agreement_passed=false", blockers)
        self.assertTrue(any("score_AM_plus" in blocker for blocker in blockers))

    def test_fixture_rejected_when_allow_fixture_false(self) -> None:
        blockers = horizon_policy.policy_blockers(self.fixture, horizon_policy.policy_for_mode("research"))
        self.assertIn("fixture evidence is not allowed", blockers)

    def test_required_proof_atom_must_be_closed(self) -> None:
        policy = horizon_policy.policy_for_mode("research")
        policy["required_proof_atoms"] = ["F2.fixture_self_progress_residue"]
        blockers = horizon_policy.policy_blockers(self.current, policy)
        self.assertIn("required proof atoms not closed: F2.fixture_self_progress_residue", blockers)

    def test_policy_digest_is_deterministic(self) -> None:
        first = horizon_policy.policy_digest(horizon_policy.policy_for_mode("research"))
        second = horizon_policy.policy_digest(horizon_policy.policy_for_mode("research"))
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
