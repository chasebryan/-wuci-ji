from __future__ import annotations

import copy
from pathlib import Path
import unittest

from daylight_ssv.schema import ReportValidationError, validate_report, validate_report_file
from .helpers import domain_checks, report_for

ROOT = Path(__file__).resolve().parents[2]


class ReportSchemaTests(unittest.TestCase):
    def test_valid_report_passes_schema(self):
        validate_report(report_for(domain_checks()))

    def test_examples_validate(self):
        for name in ("perfect.json", "mixed-score.json", "critical-override.json", "missing-evidence.json"):
            validate_report_file(ROOT / "daylight/ssv/v1/examples" / name)

    def test_more_than_one_decimal_place_fails(self):
        report = report_for(domain_checks())
        report["score"] = "99.99"
        with self.assertRaises(ReportValidationError):
            validate_report(report)

    def test_score_above_100_fails(self):
        report = report_for(domain_checks())
        report["score"] = "100.1"
        with self.assertRaises(ReportValidationError):
            validate_report(report)

    def test_score_below_0_fails(self):
        report = report_for(domain_checks())
        report["score"] = "-1.0"
        with self.assertRaises(ReportValidationError):
            validate_report(report)

    def test_domain_weights_not_totaling_100_fails(self):
        report = copy.deepcopy(report_for(domain_checks()))
        report["domains"][0]["weight"] = "13.0"
        with self.assertRaises(ReportValidationError):
            validate_report(report)

    def test_report_without_reasons_fails_when_below_100(self):
        report = report_for(domain_checks(result="fail"))
        report["reasons"] = []
        with self.assertRaises(ReportValidationError):
            validate_report(report)


if __name__ == "__main__":
    unittest.main()

