import base64
import tempfile
import unittest
from pathlib import Path

from src import external_evidence
from src import verifier_agreement
from src import verifier_quorum
from src.canonical import json_bytes
from tests import support_external_evidence as support


def _bundle_report(bundle: dict, capsule: dict, aperture: dict, registry: dict | None = None) -> dict:
    return verifier_quorum.evaluate_bundle_quorum(
        bundle,
        pinned_material=registry if registry is not None else support.pin_registry_for(bundle),
        capsule=capsule,
        aperture_capsule=aperture,
    )


def _valid_report() -> tuple[dict, dict, dict, dict, dict]:
    bundle, capsule, aperture = support.full_bundle()
    registry = support.pin_registry_for(bundle)
    report = _bundle_report(bundle, capsule, aperture, registry)
    return bundle, capsule, aperture, registry, report


def _resign_attestation(attestation: dict) -> None:
    attestation["statement_digest"] = external_evidence.attestation_statement_digest(attestation)
    signature = support.signature_bytes_for_signer(
        attestation["signer_identity"],
        external_evidence.attestation_statement_bytes(attestation),
    )
    attestation["signature"] = base64.b64encode(signature).decode("ascii")


class VerifierQuorumTests(unittest.TestCase):
    def test_missing_verifier_vectors_keep_quorum_open(self):
        capsule = support.load_capsule()
        report = verifier_quorum.evaluate_quorum([], [], capsule=capsule, aperture_capsule=support.load_aperture())
        self.assertFalse(report["accepted"])
        self.assertIn("verifier_quorum_missing", report["blocker_codes"])
        self.assertIn("verifier_quorum_fewer_than_three", report["blocker_codes"])

    def test_fewer_than_three_vectors_are_rejected(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{}, {}])
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_fewer_than_three", report["blocker_codes"])

    def test_more_than_three_vectors_are_rejected(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{}, {}, {}, {}])
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_more_than_three", report["blocker_codes"])

    def test_duplicate_verifier_family_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{}, {"verifier_family": "alpha-independent"}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_duplicate_family", report["blocker_codes"])

    def test_duplicate_verifier_implementation_digest_is_rejected(self):
        digest = support.sha256_text("same implementation")
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"verifier_implementation_digest": digest}, {"verifier_implementation_digest": digest}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_duplicate_implementation_digest", report["blocker_codes"])

    def test_fixture_vector_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"fixture": True}, {}, {}],
            attestation_over={"fixture": False, "claim_usable": True},
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_fixture_vector", report["blocker_codes"])

    def test_claim_usable_false_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"claim_usable": False}, {}, {}],
            attestation_over={"fixture": False, "claim_usable": True},
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_claim_usable_false", report["blocker_codes"])

    def test_fail_decision_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(vector_overs=[{"decision": "fail"}, {}, {}])
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_decision_not_pass", report["blocker_codes"])

    def test_input_capsule_digest_mismatch_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"input_capsule_digest": support.sha256_text("other capsule")}, {}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_input_capsule_digest_mismatch", report["blocker_codes"])

    def test_output_digest_mismatch_is_rejected(self):
        wrong = support.sha256_text("divergent canonical output")
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"output_digest": wrong, "canonical_output_digest": wrong}, {}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_output_digest_mismatch", report["blocker_codes"])

    def test_placeholder_output_digest_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"output_digest": "0" * 64, "canonical_output_digest": "0" * 64}, {}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_output_digest_placeholder", report["blocker_codes"])

    def test_malformed_implementation_digest_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"verifier_implementation_digest": "not-a-digest"}, {}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_implementation_digest_malformed", report["blocker_codes"])

    def test_placeholder_implementation_digest_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"verifier_implementation_digest": "0" * 64}, {}, {}],
        )
        report = _bundle_report(bundle, capsule, aperture)
        self.assertIn("verifier_quorum_implementation_digest_placeholder", report["blocker_codes"])

    def test_missing_attestation_ref_is_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_report()
        del bundle["claim_usable_verifier_vectors"][0]["attestation_ref"]
        support.reseal(bundle)
        report = _bundle_report(bundle, capsule, aperture, registry)
        self.assertIn("verifier_quorum_missing_attestation", report["blocker_codes"])

    def test_invalid_attestation_is_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_report()
        signature = bytearray(base64.b64decode(bundle["pinned_attestations"][3]["signature"]))
        signature[0] ^= 1
        bundle["pinned_attestations"][3]["signature"] = base64.b64encode(signature).decode("ascii")
        support.reseal(bundle)
        report = _bundle_report(bundle, capsule, aperture, registry)
        self.assertIn("verifier_quorum_attestation_invalid", report["blocker_codes"])

    def test_unpinned_signer_is_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_report()
        registry["pinned_signers"] = []
        report = _bundle_report(bundle, capsule, aperture, registry)
        self.assertIn("verifier_quorum_unpinned_signer", report["blocker_codes"])

    def test_internal_signer_is_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"signer_identity": "internal-verifier.example.org"},
        )
        registry = support.pin_registry_for(bundle)
        report = _bundle_report(bundle, capsule, aperture, registry)
        self.assertIn("verifier_quorum_internal_signer", report["blocker_codes"])

    def test_attestation_subject_digest_mismatch_is_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_report()
        bundle["claim_usable_verifier_vectors"][0]["verifier_implementation_digest"] = support.sha256_text(
            "tampered implementation"
        )
        support.reseal(bundle)
        report = _bundle_report(bundle, capsule, aperture, registry)
        self.assertIn("verifier_quorum_attestation_subject_mismatch", report["blocker_codes"])

    def test_canonical_output_digest_recomputes_deterministically(self):
        capsule = support.load_capsule()
        aperture = support.load_aperture()
        first = verifier_quorum.build_canonical_output(capsule, aperture)
        second = verifier_quorum.build_canonical_output(capsule, aperture)
        self.assertEqual(verifier_quorum.canonical_output_digest(first), verifier_quorum.canonical_output_digest(second))
        self.assertEqual(verifier_quorum.canonical_output_bytes(first), verifier_quorum.canonical_output_bytes(second))

    def test_canonical_output_rejects_floats(self):
        output = verifier_quorum.build_canonical_output(support.load_capsule(), support.load_aperture())
        output["subject"]["artifact_size"] = 1.25
        with self.assertRaises(ValueError):
            verifier_quorum.canonical_output_digest(output)

    def test_canonical_output_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "canonical-output.json"
            path.write_text('{"schema_id":"x","schema_id":"y"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                verifier_quorum.load_canonical_output(path)

    def test_canonical_output_rejects_timestamps_or_environment_fields(self):
        output = verifier_quorum.build_canonical_output(support.load_capsule(), support.load_aperture())
        output["generated_at"] = "2026-07-03T00:00:00Z"
        with self.assertRaises(ValueError):
            verifier_quorum.canonical_output_digest(output)

    def test_exactly_three_valid_signed_external_vectors_close_only_quorum_gate(self):
        _bundle, _capsule, _aperture, _registry, report = _valid_report()
        self.assertTrue(report["accepted"])
        self.assertEqual(report["closed_gates"], [verifier_quorum.QUORUM_GATE])
        self.assertIn("singularity_declaration", report["still_open_gates"])
        self.assertFalse(report["declaration_allowed"])

    def test_valid_verifier_quorum_alone_does_not_open_singularity(self):
        _bundle, _capsule, _aperture, _registry, report = _valid_report()
        self.assertTrue(report["quorum_closed"])
        self.assertFalse(report["declaration_allowed"])
        self.assertIn("verifier_quorum_cannot_open_singularity_alone", report["warning_codes"])

    def test_valid_quorum_plus_rebuild_still_blocks_when_firewall_review_open(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[])
        registry = support.pin_registry_for(bundle)
        report = external_evidence.evaluate_bundle(bundle, pinned_material=registry, capsule=capsule, aperture_capsule=aperture)
        self.assertTrue(report["verifier_quorum_closed"])
        self.assertFalse(report["declaration_allowed"])
        self.assertTrue(support.has_blocker(report, "no external firewall profile review supplied"))

    def test_valid_quorum_plus_firewall_still_blocks_when_rebuild_receipts_open(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[])
        registry = support.pin_registry_for(bundle)
        report = external_evidence.evaluate_bundle(bundle, pinned_material=registry, capsule=capsule, aperture_capsule=aperture)
        self.assertTrue(report["verifier_quorum_closed"])
        self.assertFalse(report["declaration_allowed"])
        self.assertTrue(support.has_blocker(report, "fewer than two independent rebuild receipts"))

    def test_all_blockers_are_reported_in_deterministic_order(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[
                {
                    "fixture": True,
                    "claim_usable": False,
                    "decision": "fail",
                    "output_digest": "0" * 64,
                    "canonical_output_digest": "0" * 64,
                    "verifier_implementation_digest": "bad",
                },
                {"verifier_family": "alpha-independent"},
            ],
            attestation_over={"fixture": False, "claim_usable": True},
        )
        report = _bundle_report(bundle, capsule, aperture)
        order = {code: index for index, code in enumerate(verifier_quorum.BLOCKER_ORDER)}
        self.assertEqual(report["blocker_codes"], sorted(report["blocker_codes"], key=lambda code: order[code]))

    def test_old_repository_fixture_vectors_remain_nonclaim(self):
        report = verifier_agreement.load_and_evaluate(support.ROOT / "examples/verifier-agreement.full-3-of-3.v20.json")
        self.assertFalse(report["passed"])
        self.assertIn("verifier vectors are fixture evidence", report["blockers"])
        self.assertIn("verifier vectors are not claim-usable", report["blockers"])

    def test_committed_quorum_examples_report_expected_blockers(self):
        cases = {
            "external-evidence.verifier-quorum.valid-fixture.json": "verifier_quorum_fixture_vector",
            "external-evidence.verifier-quorum.rejected-two-of-three.json": "verifier_quorum_fewer_than_three",
            "external-evidence.verifier-quorum.rejected-duplicate-family.json": "verifier_quorum_duplicate_family",
            "external-evidence.verifier-quorum.rejected-output-mismatch.json": "verifier_quorum_output_digest_mismatch",
            "external-evidence.verifier-quorum.rejected-fail-decision.json": "verifier_quorum_decision_not_pass",
            "external-evidence.verifier-quorum.rejected-unattested.json": "verifier_quorum_missing_attestation",
            "external-evidence.verifier-quorum.rejected-internal-family.json": "verifier_quorum_family_reserved_identity",
            "external-evidence.verifier-quorum.rejected-placeholder-digest.json": "verifier_quorum_output_digest_placeholder",
            "external-evidence.verifier-quorum.rejected-more-than-three.json": "verifier_quorum_more_than_three",
        }
        for name, code in cases.items():
            bundle = external_evidence._load_bundle_bytes(support.ROOT / "examples" / name)
            report = verifier_quorum.evaluate_bundle_quorum(
                bundle,
                pinned_material=support.load_json_no_floats(
                    support.ROOT / "examples/external-verification-material.signed-nonclaim.v20.json"
                ),
                capsule=support.load_capsule(),
                aperture_capsule=support.load_aperture(),
            )
            self.assertFalse(report["accepted"], name)
            self.assertIn(code, report["blocker_codes"], name)


if __name__ == "__main__":
    unittest.main()
