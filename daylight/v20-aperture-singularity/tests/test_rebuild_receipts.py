import base64
import hashlib
import unittest

from src import external_evidence
from src import rebuild_receipts
from src.canonical import load_json_no_floats
from tests import support_external_evidence as support

EXAMPLES = support.ROOT / "examples"
EXAMPLE_PINNED_MATERIAL = EXAMPLES / "external-verification-material.signed-nonclaim.v20.json"


def _artifact_from_aperture() -> dict:
    aperture = support.load_aperture()
    return {
        "artifact_name": aperture["input_subjects"][0]["subject_path"],
        "sha256": aperture["subject_sha256"],
        "sha3_512": aperture["subject_sha3_512"],
        "byte_count": aperture["subject_size"],
        "public_manifest_digest": aperture["public_sha256sums"],
    }


def _base_receipt(*, fixture: bool = False, claim_usable: bool | None = None) -> dict:
    capsule = support.load_capsule()
    artifact = _artifact_from_aperture()
    if claim_usable is None:
        claim_usable = not fixture
    receipt = {
        "schema_version": rebuild_receipts.SCHEMA_VERSION,
        "receipt_id": "test-external-rebuild-receipt",
        "receipt_kind": rebuild_receipts.RECEIPT_KIND,
        "reviewer_identity": "rebuilder-alpha.example.org",
        "reviewer_independence_class": "external",
        "fixture": fixture,
        "claim_usable": claim_usable,
        "source_repo": "https://github.com/chasebryan/-wuci-ji",
        "source_commit": capsule["source_commit"],
        "source_tag": capsule["release_tag"],
        "clean_checkout_declared": True,
        "build_commands": [
            "make daylight-v20-aperture-singularity-public-artifact",
            "make daylight-v20-aperture-singularity-verify-public-artifact",
        ],
        "environment": {
            "os_name": "test-linux",
            "os_version": "deterministic-fixture",
            "architecture": "x86_64",
            "shell": "posix-sh",
            "tool_versions": {
                "python": "3.x",
                "make": "posix",
            },
            "containerized": False,
            "notes": "deterministic unit-test fixture",
        },
        "expected_artifact": dict(artifact),
        "produced_artifact": dict(artifact),
        "transcript_digest": support.sha256_text("deterministic rebuild transcript"),
        "receipt_statement_digest": "",
        "attestation_ref": {},
        "nonclaim_acknowledgement": {
            "no_production_crypto_claim": True,
            "no_runtime_containment_claim": True,
            "no_whole_system_post_quantum_safety_claim": True,
            "no_external_certification_claim": True,
            "no_perfect_score_claim": True,
            "no_singularity_claim_from_this_receipt_alone": True,
        },
    }
    _reattest(receipt)
    return receipt


def _reattest(receipt: dict, signer: str | None = None) -> None:
    signer = signer or receipt["reviewer_identity"]
    receipt["receipt_statement_digest"] = rebuild_receipts.receipt_statement_digest(receipt)
    public_key = support.public_key_bytes_for_signer(signer)
    public_key_digest = hashlib.sha256(public_key).hexdigest()
    attestation = {
        "attestation_id": f"{receipt['receipt_id']}.attestation",
        "subject_digest": receipt["receipt_statement_digest"],
        "signer_identity": signer,
        "signer_independence_class": "external",
        "signature_algorithm": "ed25519",
        "public_key_digest": public_key_digest,
        "verification_material_ref": external_evidence.PINNED_MATERIAL_REF,
        "fixture": False,
        "claim_usable": True,
    }
    attestation["statement_digest"] = external_evidence.attestation_statement_digest(attestation)
    attestation["signature"] = base64.b64encode(
        support.signature_bytes_for_signer(signer, external_evidence.attestation_statement_bytes(attestation))
    ).decode("ascii")
    receipt["attestation_ref"] = attestation


def _registry_for(receipt: dict) -> dict:
    registry = support.load_registry()
    attestation = receipt["attestation_ref"]
    public_key = support.public_key_bytes_for_digest(attestation["public_key_digest"], attestation["signer_identity"])
    registry["pinned_signers"] = [
        {
            "signer_identity": attestation["signer_identity"],
            "signer_independence_class": "external",
            "signature_algorithm": "ed25519",
            "public_key_digest": attestation["public_key_digest"],
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            "pinned_by_commit": support.load_capsule()["source_commit"],
        }
    ]
    return registry


def _evaluate(receipt: dict, registry: dict | None = None) -> dict:
    return rebuild_receipts.evaluate_receipt(
        receipt,
        pinned_material=registry if registry is not None else _registry_for(receipt),
        capsule=support.load_capsule(),
        aperture_capsule=support.load_aperture(),
    )


class RebuildReceiptIntakeTests(unittest.TestCase):
    def test_valid_signed_fixture_receipt_verifies_cryptographically_but_remains_nonclaim(self):
        receipt = _base_receipt(fixture=True)
        report = _evaluate(receipt)

        self.assertFalse(report["accepted"])
        self.assertTrue(report["attestation_verified"])
        self.assertIn("rebuild_receipt_fixture_not_claim_usable", report["blocker_codes"])
        self.assertIn("rebuild_receipt_claim_usable_false", report["blocker_codes"])
        self.assertIn("singularity_declaration", report["still_open_gates"])

    def test_fixture_receipt_is_rejected_as_claim_usable_evidence(self):
        report = _evaluate(_base_receipt(fixture=True, claim_usable=True))
        self.assertIn("rebuild_receipt_fixture_not_claim_usable", report["blocker_codes"])

    def test_internal_identity_receipt_is_rejected(self):
        receipt = _base_receipt()
        receipt["reviewer_identity"] = "internal-builder.example.org"
        _reattest(receipt, signer="rebuilder-alpha.example.org")

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_internal_identity", report["blocker_codes"])

    def test_unsigned_receipt_is_rejected(self):
        receipt = _base_receipt()
        registry = _registry_for(receipt)
        receipt["attestation_ref"] = {}

        report = _evaluate(receipt, registry=registry)
        self.assertIn("rebuild_receipt_attestation_invalid", report["blocker_codes"])

    def test_unpinned_signer_receipt_is_rejected(self):
        receipt = _base_receipt()
        registry = _registry_for(receipt)
        registry["pinned_signers"] = []

        report = _evaluate(receipt, registry=registry)
        self.assertIn("rebuild_receipt_attestation_invalid", report["blocker_codes"])

    def test_wrong_signature_receipt_is_rejected(self):
        receipt = _base_receipt()
        signature = bytearray(base64.b64decode(receipt["attestation_ref"]["signature"]))
        signature[0] ^= 1
        receipt["attestation_ref"]["signature"] = base64.b64encode(signature).decode("ascii")

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_attestation_invalid", report["blocker_codes"])

    def test_tampered_receipt_statement_digest_is_rejected(self):
        receipt = _base_receipt()
        receipt["receipt_statement_digest"] = support.sha256_text("wrong statement")

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_statement_digest_mismatch", report["blocker_codes"])

    def test_expected_artifact_digest_mismatch_is_rejected(self):
        receipt = _base_receipt()
        receipt["expected_artifact"]["sha256"] = support.sha256_text("wrong expected artifact")
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_expected_artifact_digest_mismatch", report["blocker_codes"])

    def test_produced_artifact_digest_mismatch_is_rejected(self):
        receipt = _base_receipt()
        receipt["produced_artifact"]["sha256"] = support.sha256_text("wrong produced artifact")
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_produced_artifact_digest_mismatch", report["blocker_codes"])

    def test_missing_transcript_digest_is_rejected(self):
        receipt = _base_receipt()
        receipt["transcript_digest"] = ""
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_missing_transcript_digest", report["blocker_codes"])

    def test_placeholder_transcript_digest_is_rejected(self):
        receipt = _base_receipt()
        receipt["transcript_digest"] = "0" * 64
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_placeholder_transcript_digest", report["blocker_codes"])

    def test_missing_source_commit_is_rejected(self):
        receipt = _base_receipt()
        receipt["source_commit"] = ""
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_missing_source_commit", report["blocker_codes"])

    def test_missing_source_tag_is_rejected(self):
        receipt = _base_receipt()
        receipt["source_tag"] = ""
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_missing_source_tag", report["blocker_codes"])

    def test_dirty_checkout_declaration_is_rejected(self):
        receipt = _base_receipt()
        receipt["clean_checkout_declared"] = False
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_dirty_checkout", report["blocker_codes"])

    def test_missing_nonclaim_acknowledgement_is_rejected(self):
        receipt = _base_receipt()
        del receipt["nonclaim_acknowledgement"]["no_perfect_score_claim"]
        _reattest(receipt)

        report = _evaluate(receipt)
        self.assertIn("rebuild_receipt_nonclaim_acknowledgement_missing", report["blocker_codes"])

    def test_valid_rebuild_receipt_closes_only_rebuild_gate(self):
        receipt = _base_receipt()
        report = _evaluate(receipt)

        self.assertTrue(report["accepted"])
        self.assertEqual(report["closed_gates"], [rebuild_receipts.REBUILD_GATE])
        self.assertIn("singularity_declaration", report["still_open_gates"])
        self.assertIn("rebuild_receipt_cannot_open_singularity_alone", report["warning_codes"])
        self.assertFalse(report["declaration_allowed"])
        self.assertEqual(support.load_capsule()["score_inflation_M"], 0)

    def test_schema_file_matches_module_contract(self):
        schema = load_json_no_floats(support.ROOT / "schema/external_rebuild_receipt.v20.json")
        self.assertEqual(schema["$id"], "external_rebuild_receipt.v20.json")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), rebuild_receipts.REQUIRED_RECEIPT_FIELDS)

    def test_committed_examples_report_expected_blockers(self):
        cases = {
            "external-rebuild-receipt.valid-fixture.v20.json": "rebuild_receipt_fixture_not_claim_usable",
            "external-rebuild-receipt.rejected-internal.v20.json": "rebuild_receipt_internal_identity",
            "external-rebuild-receipt.rejected-digest-mismatch.v20.json": "rebuild_receipt_produced_artifact_digest_mismatch",
            "external-rebuild-receipt.rejected-unsigned.v20.json": "rebuild_receipt_attestation_invalid",
            "external-rebuild-receipt.rejected-missing-nonclaims.v20.json": "rebuild_receipt_nonclaim_acknowledgement_missing",
        }
        for name, blocker in cases.items():
            report = rebuild_receipts.load_and_evaluate(
                EXAMPLES / name,
                pinned_material_path=EXAMPLE_PINNED_MATERIAL,
                capsule_path=support.CAPSULE_PATH,
                aperture_capsule_path=support.APERTURE_PATH,
            )
            self.assertFalse(report["accepted"], name)
            self.assertIn(blocker, report["blocker_codes"], name)


if __name__ == "__main__":
    unittest.main()
