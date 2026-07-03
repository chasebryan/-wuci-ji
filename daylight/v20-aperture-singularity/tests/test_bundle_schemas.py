import unittest
from pathlib import Path

from src import boundary_debt
from src import external_attestation
from src import external_evidence
from src import falsification
from src import firewall_profile
from src import public_artifact
from src import rebuild_receipts
from src import reproducible_builds
from src import singularity_gate
from src import verifier_agreement
from src.canonical import load_json_no_floats

ROOT = Path(__file__).resolve().parents[1]


class BundleSchemaTests(unittest.TestCase):
    def test_schema_contracts_are_present_and_aligned(self):
        cases = [
            (
                public_artifact.SCHEMA_FILENAME,
                singularity_gate.SCHEMA_ID,
                singularity_gate.SCHEMA_VERSION,
                singularity_gate.REQUIRED_CAPSULE_KEYS,
            ),
            (
                public_artifact.VERIFIER_SCHEMA_FILENAME,
                verifier_agreement.SCHEMA_ID,
                verifier_agreement.SCHEMA_VERSION,
                {"schema_id", "schema_version", "subject", "vectors"},
            ),
            (
                public_artifact.EXTERNAL_ATTESTATION_SCHEMA_FILENAME,
                external_attestation.SCHEMA_ID,
                external_attestation.SCHEMA_VERSION,
                {"schema_id", "schema_version", "self_scope_aliases", "attestations"},
            ),
            (
                public_artifact.REPRODUCIBLE_BUILD_SCHEMA_FILENAME,
                reproducible_builds.SCHEMA_ID,
                reproducible_builds.SCHEMA_VERSION,
                {
                    "schema_id",
                    "schema_version",
                    "fixture",
                    "claim_usable",
                    "authority_scope",
                    "non_claims_acknowledged",
                    "receipts",
                },
            ),
            (
                public_artifact.FALSIFICATION_SCHEMA_FILENAME,
                falsification.SCHEMA_ID,
                falsification.SCHEMA_VERSION,
                {
                    "schema_id",
                    "schema_version",
                    "fixture",
                    "claim_usable",
                    "authority_scope",
                    "non_claims_acknowledged",
                    "results",
                },
            ),
            (
                public_artifact.BOUNDARY_DEBT_SCHEMA_FILENAME,
                boundary_debt.SCHEMA_ID,
                boundary_debt.SCHEMA_VERSION,
                {
                    "schema_id",
                    "schema_version",
                    "fixture",
                    "claim_usable",
                    "score_inflation_M",
                    "manual_score_override",
                    "reserved_perfect_AM_plus_used",
                    "claim_boundary",
                    "non_claims",
                    "debts",
                },
            ),
            (
                public_artifact.FIREWALL_PROFILE_SCHEMA_FILENAME,
                firewall_profile.SCHEMA_ID,
                firewall_profile.SCHEMA_VERSION,
                {
                    "schema_id",
                    "schema_version",
                    "profile_id",
                    "profile_digest",
                    "fixture",
                    "claim_usable",
                    "authority_scope",
                    "non_claims_acknowledged",
                    "cases",
                },
            ),
            (
                public_artifact.EXTERNAL_EVIDENCE_BUNDLE_SCHEMA_FILENAME,
                external_evidence.SCHEMA_ID,
                external_evidence.SCHEMA_VERSION,
                external_evidence.REQUIRED_BUNDLE_FIELDS,
            ),
        ]
        fragment_cases = [
            (
                public_artifact.INDEPENDENT_REBUILD_RECEIPT_SCHEMA_FILENAME,
                external_evidence.REQUIRED_REBUILD_RECEIPT_FIELDS,
            ),
            (
                public_artifact.FIREWALL_PROFILE_REVIEW_SCHEMA_FILENAME,
                external_evidence.REQUIRED_FIREWALL_REVIEW_FIELDS,
            ),
            (
                public_artifact.VERIFIER_VECTOR_CLAIM_USABLE_SCHEMA_FILENAME,
                external_evidence.REQUIRED_VERIFIER_VECTOR_FIELDS,
            ),
            (
                public_artifact.PINNED_ATTESTATION_SCHEMA_FILENAME,
                external_evidence.REQUIRED_PINNED_ATTESTATION_FIELDS,
            ),
            (
                public_artifact.EXTERNAL_REBUILD_RECEIPT_SCHEMA_FILENAME,
                rebuild_receipts.REQUIRED_RECEIPT_FIELDS,
            ),
        ]
        self.assertEqual(
            {item[0] for item in cases} | {item[0] for item in fragment_cases},
            set(public_artifact.EVIDENCE_SCHEMA_FILENAMES),
        )
        for filename, schema_id, schema_version, required in cases:
            schema = load_json_no_floats(ROOT / "schema" / filename)
            self.assertEqual(schema["$id"], filename)
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["properties"]["schema_id"]["const"], schema_id)
            self.assertEqual(schema["properties"]["schema_version"]["const"], schema_version)
            self.assertEqual(set(schema["required"]), set(required))
        for filename, required in fragment_cases:
            schema = load_json_no_floats(ROOT / "schema" / filename)
            self.assertEqual(schema["$id"], filename)
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(schema["required"]), set(required))

    def test_nested_schema_fields_track_digest_bound_rows(self):
        verifier_schema = load_json_no_floats(ROOT / "schema" / public_artifact.VERIFIER_SCHEMA_FILENAME)
        vector_required = set(verifier_schema["properties"]["vectors"]["items"]["required"])
        self.assertIn("vector_digest", vector_required)

        rebuild_schema = load_json_no_floats(ROOT / "schema" / public_artifact.REPRODUCIBLE_BUILD_SCHEMA_FILENAME)
        receipt_required = set(rebuild_schema["properties"]["receipts"]["items"]["required"])
        self.assertEqual(receipt_required, reproducible_builds.REQUIRED_RECEIPT_FIELDS)

        external_schema = load_json_no_floats(ROOT / "schema" / public_artifact.EXTERNAL_ATTESTATION_SCHEMA_FILENAME)
        attestation_required = set(external_schema["properties"]["attestations"]["items"]["required"])
        self.assertEqual(attestation_required, external_attestation.REQUIRED_ATTESTATION_FIELDS)


if __name__ == "__main__":
    unittest.main()
