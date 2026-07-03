from __future__ import annotations

import unittest

from daylight_ssv.math import check_value
from .helpers import domain_checks, make_check, report_for


class EvidenceCoverageTests(unittest.TestCase):
    def test_missing_evidence_counts_as_zero_credit(self):
        self.assertEqual(str(check_value("pass", "missing")), "0.00")

    def test_coverage_counts_strong_or_medium(self):
        checks = [
            make_check("identity_privilege_control", "a", evidence_quality="strong"),
            make_check("update_install_integrity", "b", evidence_quality="medium"),
            make_check("cryptography_secrets_handling", "c", evidence_quality="weak"),
            make_check("network_exposure", "d", result="unknown", evidence_quality="missing"),
        ]
        checks.extend(domain_checks()[4:])
        report = report_for(checks)
        self.assertEqual(report["summary"]["checks_total"], 10)
        self.assertEqual(report["summary"]["evidence_coverage"], "80.0")


if __name__ == "__main__":
    unittest.main()

