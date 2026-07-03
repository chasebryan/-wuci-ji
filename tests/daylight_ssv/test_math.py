from __future__ import annotations

from decimal import Decimal
import unittest

from daylight_ssv.math import check_value, public_score, validate_domain_weights
from .helpers import domain_checks, report_for


class MathTests(unittest.TestCase):
    def test_perfect_evidence_score_produces_100_0(self):
        report = report_for(domain_checks())
        self.assertEqual(report["score"], "100.0")

    def test_all_failed_checks_produce_0_0(self):
        report = report_for(domain_checks(result="fail"))
        self.assertEqual(report["score"], "0.0")

    def test_round_half_up_74_65(self):
        self.assertEqual(str(public_score(Decimal("74.65"))), "74.7")

    def test_round_half_up_74_64(self):
        self.assertEqual(str(public_score(Decimal("74.64"))), "74.6")

    def test_domain_weights_validate(self):
        validate_domain_weights()

    def test_missing_evidence_gives_zero_credit(self):
        self.assertEqual(check_value("pass", "missing"), Decimal("0.00"))


if __name__ == "__main__":
    unittest.main()

