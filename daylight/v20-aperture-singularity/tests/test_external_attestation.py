import unittest
from pathlib import Path

from src import external_attestation
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


class ExternalAttestationTests(unittest.TestCase):
    def test_self_signed_attestation_rejects(self):
        result = external_attestation.load_and_evaluate(ROOT / "examples/external-attestation.self-signed.reject.v20.json")
        self.assertFalse(result["verified"])
        self.assertFalse(result["atoms"]["signer_not_self_scoped"])
        self.assertTrue(any("self-scoped signer rejected" in item for item in result["blockers"]))

    def test_verified_status_is_still_not_crypto_verified(self):
        result = external_attestation.load_and_evaluate(ROOT / "examples/external-attestation.verified.fixture-blocked.v20.json")
        self.assertFalse(result["verified"])
        self.assertTrue(result["atoms"]["statement_digest_verified"])
        self.assertFalse(result["atoms"]["cryptographic_signature_verified"])
        self.assertIn("external attestation not cryptographically verified", result["blockers"])

    def test_statement_digest_mismatch_blocks(self):
        bundle = load_json_no_floats(ROOT / "examples/external-attestation.verified.fixture-blocked.v20.json")
        bundle["attestations"][0]["scope"]["release_tag"] = "edited-release"
        result = external_attestation.evaluate_bundle(bundle)
        self.assertFalse(result["atoms"]["statement_digest_verified"])
        self.assertIn("attestation 0 statement digest mismatch", result["blockers"])


if __name__ == "__main__":
    unittest.main()
