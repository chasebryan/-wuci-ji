import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV = {"PYTHONPATH": str(ROOT / "daylight/npt/v1")}
REGISTRY = "daylight/npt/v1/number-claims.registry.json"


def scan_fixture(path):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "daylight_npt",
            "scan",
            "--registry",
            REGISTRY,
            "--json",
            path,
        ],
        cwd=ROOT,
        env=ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode, json.loads(proc.stdout)


class NegativeFixtureTests(unittest.TestCase):
    CASES = {
        "daylight/npt/v1/examples/negative/unsupported-numeric-claim.md": "NPT001_UNSUPPORTED_NUMERIC_CLAIM",
        "daylight/npt/v1/examples/negative/evidence-mismatch.md": "NPT002_EVIDENCE_MISMATCH",
        "daylight/npt/v1/examples/negative/unsupported-score.md": "NPT004_SCORE_NOT_GENERATED",
        "daylight/npt/v1/examples/negative/unsupported-m-scale-score.md": "NPT004_SCORE_NOT_GENERATED",
        "daylight/npt/v1/examples/negative/manual-perfect-score.md": "NPT009_MANUAL_SCORE_ASSERTION",
        "daylight/npt/v1/examples/negative/percent-mismatch.md": "NPT003_PERCENT_RATIO_MISMATCH",
        "daylight/npt/v1/examples/negative/rounded-up-percentage.md": "NPT003_PERCENT_RATIO_MISMATCH",
        "daylight/npt/v1/examples/negative/quorum-mismatch.md": "NPT005_QUORUM_MISMATCH",
        "daylight/npt/v1/examples/negative/version-drift.md": "NPT006_VERSION_DRIFT",
        "daylight/npt/v1/examples/negative/invalid-sha256.md": "NPT007_INVALID_DIGEST_LITERAL",
        "daylight/npt/v1/examples/negative/false-precision.md": "NPT008_FALSE_PRECISION",
        "daylight/npt/v1/examples/negative/volatile-count.md": "NPT010_VOLATILE_PUBLIC_COUNT",
        "daylight/npt/v1/examples/negative/stale-registry-entry.md": "NPT011_REGISTRY_ENTRY_STALE",
        "daylight/npt/v1/examples/negative/ambiguous-numeric-claim.md": "NPT012_AMBIGUOUS_NUMERIC_CLAIM",
        "daylight/npt/v1/examples/negative/adversarial-digest-literals.md": "NPT007_INVALID_DIGEST_LITERAL",
        "daylight/npt/v1/examples/negative/unicode-slash-score.md": "NPT004_SCORE_NOT_GENERATED",
        "daylight/npt/v1/examples/negative/dash-wrapped-score.md": "NPT004_SCORE_NOT_GENERATED",
        "daylight/npt/v1/examples/negative/excessive-precision-percent.md": "NPT008_FALSE_PRECISION",
        "daylight/npt/v1/examples/negative/promotional-score-copy.md": "NPT004_SCORE_NOT_GENERATED",
        "daylight/npt/v1/examples/negative/certification-implication.md": "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
        "daylight/npt/v1/examples/negative/precision-superlative-no-boundary.md": "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
        "daylight/npt/v1/examples/negative/tagged-agency-endorsement.md": "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
        "daylight/npt/v1/examples/negative/production-readiness-implication.md": "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
        "daylight/npt/v1/examples/negative/audit-status-implication.md": "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
        "daylight/npt/v1/examples/negative/post-quantum-security-implication.md": "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
    }

    def test_negative_fixtures_fail_with_expected_codes(self):
        for path, code in self.CASES.items():
            with self.subTest(path=path):
                rc, report = scan_fixture(path)
                self.assertEqual(rc, 1, report)
                codes = {finding["code"] for finding in report["findings"]}
                self.assertIn(code, codes)

    def test_every_negative_markdown_fixture_has_expected_code(self):
        fixtures = {
            path.as_posix()
            for path in (ROOT / "daylight/npt/v1/examples/negative").glob("*.md")
        }
        expected = {str(ROOT / path) for path in self.CASES}
        self.assertEqual(fixtures, expected)

    def test_every_finding_code_is_covered(self):
        required = {f"NPT{number:03d}" for number in range(1, 14)}
        covered = {code.split("_", 1)[0] for code in self.CASES.values()}
        self.assertEqual(covered, required)


if __name__ == "__main__":
    unittest.main()
