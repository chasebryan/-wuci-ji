from __future__ import annotations

from decimal import Decimal
import unittest

from .helpers import domain_checks, make_check, report_for


class ReasonSortingTests(unittest.TestCase):
    def test_reasons_sorted_by_loss_descending(self):
        checks = domain_checks()[1:]
        checks.append(make_check("identity_privilege_control", "identity.low.fail", severity="low", result="fail"))
        checks.append(make_check("identity_privilege_control", "identity.critical.fail", severity="critical", result="fail"))
        report = report_for(checks)
        losses = [Decimal(item["loss"]) for item in report["reasons"]]
        self.assertEqual(losses, sorted(losses, reverse=True))
        self.assertEqual(report["reasons"][0]["id"], "identity.critical.fail")


if __name__ == "__main__":
    unittest.main()
