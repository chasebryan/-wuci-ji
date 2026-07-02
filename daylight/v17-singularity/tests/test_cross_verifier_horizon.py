from __future__ import annotations

import copy
from decimal import Decimal
from pathlib import Path
import subprocess
import tempfile
import unittest

from src import event_horizon, proof_atoms, registry, scorecard, verifier_vector


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"
FIXTURE_STATE = "daylight/v17-singularity/examples/state.declaration-fixture.json"
REPO_ROOT = Path(__file__).resolve().parents[3]
RUST_MANIFEST = REPO_ROOT / "daylight" / "v17-singularity" / "rust" / "event-horizon-verifier" / "Cargo.toml"
REQUIRED_FAMILIES = ("python-reference", "rust-independent", "zig-or-minimal-c-independent")


def _as_family(vector: dict, family: str) -> dict:
    out = copy.deepcopy(vector)
    out["implementation_family"] = family
    out["implementation_digest"] = verifier_vector.canonical_sha256(
        {"implementation_family": family},
        verifier_vector.D_VERIFIER_VECTOR + "TEST-IMPLEMENTATION:",
    )
    return out


class CrossVerifierHorizonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fields = registry.load_fields_registry()
        self.atoms = proof_atoms.load_proof_atom_registry()
        self.state = scorecard.load_state(CURRENT_STATE)
        self.card = scorecard.build_scorecard(self.state, self.fields, self.atoms)
        self.vector = verifier_vector.generate_python_reference_vector(self.card)

    def _rust_vector(self) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "rust-vector.json"
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--manifest-path",
                    str(RUST_MANIFEST),
                    "--",
                    "--out",
                    str(out),
                ],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            return verifier_vector.load_vector(out)

    def test_blocker_vector_lists_multiple_current_blockers(self) -> None:
        result = event_horizon.run_declaration_gate(state_path=CURRENT_STATE)
        self.assertEqual(result["decision"], "declaration_refused")
        self.assertIn("omega_eff below declaration threshold", result["blockers"])
        self.assertIn("score_AM_plus below declaration target", result["blockers"])
        self.assertIn("cross_verifier_agreement_passed=false", result["blockers"])
        self.assertIn("verifier quorum incomplete: 2/3", result["blockers"])

    def test_current_score_reports_313_residue(self) -> None:
        self.assertEqual(self.card["declaration_residue_AM_plus"], 313)
        self.assertEqual(self.card["declaration_score_gap_AM_plus"], 312)

    def test_omega_gap_is_positive(self) -> None:
        self.assertGreater(Decimal(self.card["omega_gap_to_declaration"]), Decimal(0))

    def test_residue_collapse_factor_is_approximately_313(self) -> None:
        factor = Decimal(self.card["residue_collapse_factor_to_declaration"])
        self.assertGreater(factor, Decimal(300))
        self.assertLess(factor, Decimal(330))

    def test_single_python_vector_does_not_satisfy_agreement(self) -> None:
        result = verifier_vector.verify_cross_verifier_agreement([self.vector])
        self.assertFalse(result["passed"])
        self.assertEqual(result["agreement_status"], "partial_1_of_3")
        self.assertIn("at least three verifier vectors required", result["blockers"])

    def test_duplicate_implementation_family_does_not_satisfy_agreement(self) -> None:
        vectors = [copy.deepcopy(self.vector) for _ in range(3)]
        result = verifier_vector.verify_cross_verifier_agreement(vectors)
        self.assertFalse(result["passed"])
        self.assertEqual(result["agreement_status"], "failed")
        self.assertIn("implementation_family values must be distinct", result["blockers"])

    def test_python_and_rust_vectors_agree_on_current_state(self) -> None:
        rust_vector = self._rust_vector()
        self.assertEqual(rust_vector["implementation_family"], "rust-independent")
        for key in verifier_vector.COMMON_VECTOR_KEYS:
            self.assertEqual(rust_vector[key], self.vector[key], key)

    def test_modified_rust_vector_is_rejected(self) -> None:
        rust_vector = self._rust_vector()
        rust_vector["score_AM_plus"] -= 1
        result = verifier_vector.verify_vectors_against_reference([self.vector, rust_vector], self.vector)
        self.assertFalse(result["passed"])
        self.assertTrue(
            any("scorecard_predigest mismatch" in blocker or "score_AM_plus does not match reference" in blocker for blocker in result["blockers"])
        )

    def test_python_plus_rust_only_is_partial_two_of_three(self) -> None:
        rust_vector = self._rust_vector()
        result = verifier_vector.verify_cross_verifier_agreement([self.vector, rust_vector])
        self.assertFalse(result["passed"])
        self.assertEqual(result["agreement_status"], "partial_2_of_3")
        self.assertEqual(result["quorum"], "2/3")
        self.assertIn("verifier quorum incomplete: 2/3", result["blockers"])

    def test_mismatched_omega_rejects(self) -> None:
        vectors = [_as_family(self.vector, family) for family in REQUIRED_FAMILIES]
        vectors[1]["omega_eff_decimal"] = "0"
        vectors[1]["scorecard_predigest"] = verifier_vector.scorecard_predigest_from_parts(vectors[1])
        result = verifier_vector.verify_cross_verifier_agreement(vectors)
        self.assertFalse(result["passed"])
        self.assertTrue(any("omega_eff_decimal mismatch" in blocker for blocker in result["blockers"]))

    def test_mismatched_score_rejects(self) -> None:
        vectors = [_as_family(self.vector, family) for family in REQUIRED_FAMILIES]
        vectors[2]["score_AM_plus"] -= 1
        vectors[2]["scorecard_predigest"] = verifier_vector.scorecard_predigest_from_parts(vectors[2])
        result = verifier_vector.verify_cross_verifier_agreement(vectors)
        self.assertFalse(result["passed"])
        self.assertTrue(any("score_AM_plus mismatch" in blocker for blocker in result["blockers"]))

    def test_fixture_vectors_cannot_make_claim_usable_declaration_pass(self) -> None:
        fixture_state = scorecard.load_state(FIXTURE_STATE)
        fixture_card = scorecard.build_scorecard(fixture_state, self.fields, self.atoms)
        fixture_vector = verifier_vector.generate_python_reference_vector(fixture_card)
        fixture_state["verifier_outputs"] = [
            _as_family(fixture_vector, family)
            for family in REQUIRED_FAMILIES
        ]
        card_with_vectors = scorecard.build_scorecard(fixture_state, self.fields, self.atoms)
        self.assertTrue(card_with_vectors["cross_verifier_agreement_passed"])
        self.assertFalse(card_with_vectors["declared"])
        self.assertFalse(card_with_vectors["claim_usable"])
        self.assertTrue(card_with_vectors["fixture"])


if __name__ == "__main__":
    unittest.main()
