from __future__ import annotations

from decimal import Decimal
import unittest

from daylight_ssv.math import public_score
from daylight_ssv.schema import ReportValidationError, validate_report
from .helpers import domain_checks, report_for


class BoundsTests(unittest.TestCase):
    def test_public_score_rounding_stays_bounded(self):
        self.assertEqual(public_score(Decimal("100.0")), Decimal("100.0"))
        self.assertEqual(public_score(Decimal("0.0")), Decimal("0.0"))

    def test_score_outside_range_rejected(self):
        report = report_for(domain_checks())
        for score in ("100.1", "-1.0", "101.0"):
            with self.subTest(score=score):
                report["score"] = score
                with self.assertRaises(ReportValidationError):
                    validate_report(report)


if __name__ == "__main__":
    unittest.main()

