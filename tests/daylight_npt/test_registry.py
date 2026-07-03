import sys
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "daylight/npt/v1"))

from daylight_npt.registry import RegistryError, load_registry, matching_claims, validate_registry
from daylight_npt.extract import extract_tokens_from_text


class RegistryTests(unittest.TestCase):
    def test_registry_loads(self):
        registry = load_registry(ROOT / "daylight/npt/v1/number-claims.registry.json")
        self.assertEqual(registry["schema"], "daylight.npt.v1.registry")
        self.assertGreaterEqual(len(registry["claims"]), 5)

    def test_registry_rejects_manual_score_without_evidence(self):
        registry = {
            "schema": "daylight.npt.v1.registry",
            "version": "1",
            "claims": [
                {
                    "id": "bad.score",
                    "status": "verified",
                    "claim_type": "score",
                    "value_raw": "1,000,000M / 1,000,000M",
                    "value_canonical": "1000000M / 1000000M",
                    "unit": "M",
                    "allowed_files": ["*"],
                    "context_regex": ".*",
                    "evidence": [],
                    "check": "json_equals",
                    "rationale": "bad"
                }
            ]
        }
        with self.assertRaises(RegistryError):
            validate_registry(registry)

    def test_matching_claim(self):
        registry = load_registry(ROOT / "daylight/npt/v1/number-claims.registry.json")
        token = extract_tokens_from_text(
            "DaylightNPT positive fixture: registered score `998,200M / 1,000,000M`.",
            "daylight/npt/v1/examples/positive/registered-score.md",
        )[0]
        self.assertEqual(matching_claims(registry, token)[0]["id"], "npt.fixture.registered_score")

    def test_exemptions_are_narrow_and_documented(self):
        registry = load_registry(ROOT / "daylight/npt/v1/number-claims.registry.json")
        for claim in registry["claims"]:
            if claim["status"] not in {"non_claim", "illustrative", "exempt"}:
                continue
            self.assertTrue(claim.get("rationale"))
            self.assertTrue(claim.get("allowed_files"))
            self.assertNotIn("*", claim["allowed_files"])
            self.assertNotIn("**", claim["allowed_files"])
            self.assertNotIn(claim.get("context_regex"), {".*", "^.*$", ".+", "^.+$"})
            self.assertIn("claim_type", claim)
            self.assertIn("status", claim)

    def test_exemption_validation_rejects_broad_entries(self):
        registry = {
            "schema": "daylight.npt.v1.registry",
            "version": "1",
            "claims": [
                {
                    "id": "bad.exempt",
                    "status": "exempt",
                    "claim_type": "other",
                    "value_raw": "7",
                    "value_canonical": "7",
                    "unit": "none",
                    "allowed_files": ["*"],
                    "context_regex": ".*",
                    "evidence": [],
                    "check": "exempt_with_rationale",
                    "rationale": ""
                }
            ]
        }
        with self.assertRaises(RegistryError):
            validate_registry(registry)

    def test_list_claims_shows_exemptions(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "daylight_npt",
                "list-claims",
                "--registry",
                "daylight/npt/v1/number-claims.registry.json",
            ],
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "daylight/npt/v1")},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("npt.fixture.nonclaim_number\tnon_claim\tother\t1", proc.stdout)


if __name__ == "__main__":
    unittest.main()
