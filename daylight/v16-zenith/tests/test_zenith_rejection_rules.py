from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import zenith_verifier
from tests import helpers


class ZenithRejectionRuleTests(unittest.TestCase):
    def _artifact(self, root: Path) -> Path:
        return helpers.build_solstice_artifact(root)

    def test_score_inflation_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {"zenith_adjusted_score_M": 999999})
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_unsigned_external_review_credit_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "review_evidence": [{
                    "review_id": "r1",
                    "review_scope": ["formal_methods"],
                    "closes_zenith_obligations": ["z7.formal_methods_review"],
                }]
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_self_supplied_hmac_external_review_credit_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            review = zenith_verifier.sign_record({
                "review_id": "r1",
                "reviewer_identity": "reviewer-a",
                "reviewed_commit": "0" * 40,
                "review_scope": ["formal_methods"],
                "report_digest": "a" * 64,
                "evidence_digest": "b" * 64,
                "fixture_material_used": False,
                "independent_reviewer": True,
                "offensive_tooling_included": False,
                "signature_namespace": zenith_verifier.REVIEW_NAMESPACE,
                "closes_zenith_obligations": ["z7.formal_methods_review"],
            }, "attacker-key", zenith_verifier.REVIEW_NAMESPACE)
            evidence = helpers.write_evidence(root, {"review_evidence": [review]})
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_rebuild_mismatch_rejected_when_credit_claimed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "rebuild_evidence": [{
                    "rebuild_id": "r1",
                    "builder_identity": "builder-a",
                    "environment_digest": "a" * 64,
                    "source_digest": "b" * 64,
                    "command_digest": "c" * 64,
                    "output_artifact_digest": "d" * 64,
                    "release_artifact_digest": "e" * 64,
                    "transcript_digest": "f" * 64,
                    "closes_zenith_obligations": ["z3.rebuild_one"],
                }]
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_implementation_disagreement_rejected_when_credit_claimed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "implementation_outputs": [{
                    "implementation_id": "python",
                    "implementation_family": "python",
                    "output_vector_digest": "a" * 64,
                    "closes_zenith_obligations": ["z4.python_reference"],
                }]
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_open_fuzz_crash_rejected_when_credit_claimed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "fuzz_evidence": [{
                    "fuzz_id": "f1",
                    "target": "parser",
                    "crash_count": 1,
                    "triaged_crash_count": 0,
                    "closes_zenith_obligations": ["z6.parser_fuzz"],
                }]
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_open_critical_break_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "falsification_program": {"open_critical_breaks": 1}
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_boundary_overclaim_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "boundary_claims": {"production_allowed": True}
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_unsigned_valid_true_production_authority_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "boundary_claims": {"production_allowed": True},
                "production_authority_evidence": {
                    "valid": True,
                    "fixture_material_used": False,
                },
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_self_declared_runtime_containment_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "boundary_claims": {"runtime_containment_claim": True},
                "runtime_containment_evidence": {
                    "valid": True,
                    "negative_tests_pass": True,
                },
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_self_declared_pq_safety_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {
                "boundary_claims": {"whole_system_post_quantum_safety_claim": True},
                "pq_evidence": {
                    "valid": True,
                    "external_crypto_review_valid": True,
                },
            })
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)

    def test_float_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            evidence = helpers.write_evidence(root, {"zenith_adjusted_score_M": 998900.0})
            with self.assertRaises(zenith_verifier.ZenithError):
                zenith_verifier.build_report(artifact, evidence)


if __name__ == "__main__":
    unittest.main()
