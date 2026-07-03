import base64
import hashlib
import unittest
from pathlib import Path

from src import external_evidence
from tests import support_external_evidence as support


ROOT = Path(__file__).resolve().parents[1]


def _blockers(report: dict) -> str:
    return "\n".join(report["blockers"])


def _valid_bundle_report() -> tuple[dict, dict, dict, dict, dict]:
    bundle, capsule, aperture = support.full_bundle()
    registry = support.pin_registry_for(bundle)
    report = support.evaluate(bundle, capsule, aperture, registry=registry)
    return bundle, capsule, aperture, registry, report


def _resign(attestation: dict) -> None:
    attestation["statement_digest"] = external_evidence.attestation_statement_digest(attestation)
    signature = support.signature_bytes_for_signer(
        attestation["signer_identity"],
        external_evidence.attestation_statement_bytes(attestation),
    )
    attestation["signature"] = base64.b64encode(signature).decode("ascii")


class PinnedAttestationVerificationTests(unittest.TestCase):
    def test_rfc8032_test_vector_verifies(self):
        public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

        from src import ed25519_verify

        self.assertTrue(ed25519_verify.verify(public_key, signature, b""))

    def test_ed25519_valid_signature_verifies(self):
        bundle, _capsule, _aperture, registry, report = _valid_bundle_report()
        attestation = bundle["pinned_attestations"][0]
        pin = registry["pinned_signers"][0]

        self.assertEqual(external_evidence.IMPLEMENTED_SIGNATURE_ALGORITHMS, frozenset({"ed25519"}))
        self.assertTrue(external_evidence._verify_signature(attestation, pin))
        self.assertTrue(report["external_attestation_verified"])
        self.assertTrue(report["external_evidence_admissible"])
        self.assertEqual(report["cryptographically_verified_attestation_count"], 6)
        self.assertEqual(report["sections"]["pinned_attestations"]["blockers"], [])

    def test_statement_digest_must_match_signed_statement(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        attestation = bundle["pinned_attestations"][0]
        self.assertEqual(
            attestation["statement_digest"],
            hashlib.sha256(external_evidence.attestation_statement_bytes(attestation)).hexdigest(),
        )
        attestation["statement_digest"] = support.sha256_text("wrong statement digest")
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "statement digest mismatch"))

    def test_tampered_signature_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        signature = bytearray(base64.b64decode(bundle["pinned_attestations"][0]["signature"]))
        signature[0] ^= 1
        bundle["pinned_attestations"][0]["signature"] = base64.b64encode(signature).decode("ascii")
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "ed25519 signature verification failed"))

    def test_wrong_public_key_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        wrong_key = support.public_key_bytes_for_signer("wrong-public-key.example.org")
        wrong_digest = hashlib.sha256(wrong_key).hexdigest()
        registry["pinned_signers"][0]["public_key_digest"] = wrong_digest
        registry["pinned_signers"][0]["public_key_b64"] = base64.b64encode(wrong_key).decode("ascii")
        bundle["pinned_attestations"][0]["public_key_digest"] = wrong_digest
        bundle["pinned_attestations"][0]["statement_digest"] = external_evidence.attestation_statement_digest(
            bundle["pinned_attestations"][0]
        )
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "ed25519 signature verification failed"))

    def test_unpinned_public_key_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        registry["pinned_signers"] = registry["pinned_signers"][1:]

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "public key is not pinned"))

    def test_wrong_message_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        attestation = bundle["pinned_attestations"][0]
        attestation["subject_digest"] = support.sha256_text("same signer changed signed message")
        attestation["statement_digest"] = external_evidence.attestation_statement_digest(attestation)
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "ed25519 signature verification failed"))

    def test_wrong_subject_digest_rejected(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"subject_digest": support.sha256_text("not the bound evidence item")}
        )
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "attestation subject digest does not match evidence item"))

    def test_wrong_statement_digest_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        bundle["pinned_attestations"][0]["statement_digest"] = support.sha256_text("wrong statement")
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "statement digest mismatch"))

    def test_unsupported_signature_algorithm_rejected(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"signature_algorithm": "rsa-sha256"})
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "unsupported signature algorithm: rsa-sha256"))

    def test_internal_signer_rejected_even_with_valid_signature(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"signer_identity": "external-internal-reviewer.example.org"}
        )
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "signer identity is not independent"))

    def test_reserved_signer_identities_rejected_even_with_valid_signature(self):
        for identity in (
            "self-reviewer.example.org",
            "repo-reviewer.example.org",
            "wuci-reviewer.example.org",
            "noxframe-reviewer.example.org",
        ):
            bundle, capsule, aperture = support.full_bundle(attestation_over={"signer_identity": identity})
            registry = support.pin_registry_for(bundle)
            report = support.evaluate(bundle, capsule, aperture, registry=registry)
            self.assertFalse(report["external_attestation_verified"], identity)
            self.assertTrue(support.has_blocker(report, "signer identity is not independent"), identity)

    def test_fixture_attestation_rejected_even_with_valid_signature(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"fixture": True})
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "is fixture evidence"))

    def test_claim_unusable_attestation_rejected_even_with_valid_signature(self):
        bundle, capsule, aperture = support.full_bundle(attestation_over={"claim_usable": False})
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_attestation_verified"])
        self.assertTrue(support.has_blocker(report, "is not claim-usable"))

    def test_duplicate_attestation_id_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        bundle["pinned_attestations"][1]["attestation_id"] = bundle["pinned_attestations"][0]["attestation_id"]
        _resign(bundle["pinned_attestations"][1])
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "duplicate attestation id"))

    def test_duplicate_attestation_public_key_digest_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        bundle["pinned_attestations"][1]["public_key_digest"] = bundle["pinned_attestations"][0]["public_key_digest"]
        _resign(bundle["pinned_attestations"][1])
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "duplicate attestation public key digest"))

    def test_duplicate_pinned_public_key_digest_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        registry["pinned_signers"].append(dict(registry["pinned_signers"][0]))

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["pinned_material_valid"])
        self.assertTrue(support.has_blocker(report, "duplicate pinned public key digest"))

    def test_signature_length_must_be_64_bytes(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        bundle["pinned_attestations"][0]["signature"] = base64.b64encode(bytes(range(63))).decode("ascii")
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "ed25519 signature must be 64 bytes"))

    def test_placeholder_signature_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        bundle["pinned_attestations"][0]["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "signature must not be a placeholder value"))

    def test_public_key_length_must_be_32_bytes(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        short_key = b"short-ed25519-key"
        registry["pinned_signers"][0]["public_key_digest"] = hashlib.sha256(short_key).hexdigest()
        registry["pinned_signers"][0]["public_key_b64"] = base64.b64encode(short_key).decode("ascii")

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "public_key_b64 must decode to 32 bytes"))

    def test_placeholder_public_key_rejected(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        placeholder_key = b"\x00" * 32
        registry["pinned_signers"][0]["public_key_digest"] = hashlib.sha256(placeholder_key).hexdigest()
        registry["pinned_signers"][0]["public_key_b64"] = base64.b64encode(placeholder_key).decode("ascii")

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertTrue(support.has_blocker(report, "public_key_b64 must not decode to placeholder bytes"))

    def test_no_network_or_time_dependency(self):
        source = (ROOT / "src/external_evidence.py").read_text(encoding="utf-8")
        forbidden = (
            "import socket",
            "import urllib",
            "import http.client",
            "import ssl",
            "import time",
            "from time import",
            "import datetime",
            "from datetime import",
            "gethostname(",
            "getuser(",
            "os.environ",
        )
        for token in forbidden:
            self.assertNotIn(token, source)

        verifier = (ROOT / "src/ed25519_verify.py").read_text(encoding="utf-8")
        for token in forbidden:
            self.assertNotIn(token, verifier)

    def test_integration_full_temp_bundle_clears_attestation_blocker(self):
        _bundle, capsule, _aperture, _registry, report = _valid_bundle_report()

        self.assertTrue(report["shape_valid"])
        self.assertTrue(report["bundle_digest_valid"])
        self.assertTrue(report["pinned_material_valid"])
        self.assertTrue(report["external_attestation_verified"])
        self.assertTrue(report["external_evidence_admissible"])
        self.assertFalse(report["declaration_allowed"])
        self.assertEqual(capsule["score_inflation_M"], 0)
        self.assertNotIn("pinned cryptographic attestation verification", _blockers(report))

    def test_integration_wrong_signature_fails(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        bundle["pinned_attestations"][0]["signature"] = base64.b64encode(bytes(range(64))).decode("ascii")
        support.reseal(bundle)

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "ed25519 signature verification failed"))

    def test_integration_wrong_attestation_subject_fails(self):
        bundle, capsule, aperture = support.full_bundle(
            attestation_over={"subject_digest": support.sha256_text("wrong bound subject")}
        )
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "attestation subject digest does not match evidence item"))

    def test_integration_unpinned_signer_fails(self):
        bundle, capsule, aperture, registry, _report = _valid_bundle_report()
        registry["pinned_signers"] = registry["pinned_signers"][1:]

        report = support.evaluate(bundle, capsule, aperture, registry=registry)
        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "public key is not pinned"))

    def test_integration_duplicate_verifier_family_fails(self):
        bundle, capsule, aperture = support.full_bundle(
            vector_overs=[{"verifier_family": "alpha-independent"}, {}, {"verifier_family": "alpha-independent"}]
        )
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "duplicate verifier family: alpha-independent"))

    def test_integration_missing_rebuild_receipt_fails(self):
        bundle, capsule, aperture = support.full_bundle(receipt_overs=[{}])
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "fewer than two independent rebuild receipts"))

    def test_integration_critical_firewall_review_fails(self):
        bundle, capsule, aperture = support.full_bundle(review_overs=[{"finding_level": "critical"}])
        registry = support.pin_registry_for(bundle)
        report = support.evaluate(bundle, capsule, aperture, registry=registry)

        self.assertFalse(report["external_evidence_admissible"])
        self.assertTrue(support.has_blocker(report, "reports blocking finding level: critical"))

    def test_committed_registry_is_valid_and_empty(self):
        registry = support.load_registry()
        pins, blockers = external_evidence.validate_pinned_material(registry)
        self.assertEqual(pins, {})
        self.assertEqual(blockers, [])


if __name__ == "__main__":
    unittest.main()
