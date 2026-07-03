from __future__ import annotations

from decimal import Decimal
import unittest

from daylight_ssv.warnings import warning_for
from .helpers import domain_checks, make_check, report_for


class WarningLevelTests(unittest.TestCase):
    def test_high_failed_check_forces_at_least_high(self):
        checks = domain_checks()
        checks[0] = make_check("identity_privilege_control", "identity.high.fail", severity="high", result="fail")
        self.assertIn("high_failed_check", report_for(checks)["warning"]["overrides"])
        self.assertIn(report_for(checks)["warning"]["level"], {"High", "Severe", "Critical"})

    def test_critical_failed_check_forces_critical(self):
        checks = domain_checks()
        checks[0] = make_check("identity_privilege_control", "identity.critical.fail", severity="critical", result="fail")
        self.assertEqual(report_for(checks)["warning"]["level"], "Critical")

    def test_secret_detection_forces_critical(self):
        checks = domain_checks()
        checks[0] = make_check(
            "cryptography_secrets_handling",
            "crypto.secret",
            severity="low",
            result="partial",
            flags={"exposed_secret"},
        )
        report = report_for(checks)
        self.assertEqual(report["warning"]["level"], "Critical")
        self.assertIn("exposed_secret", report["warning"]["overrides"])

    def test_evidence_coverage_below_80_forces_at_least_elevated(self):
        warning = warning_for(Decimal("99.0"), domain_checks(), Decimal("79.9"))
        self.assertEqual(warning["level"], "Elevated")
        self.assertIn("evidence_coverage_below_80_percent", warning["overrides"])


if __name__ == "__main__":
    unittest.main()

