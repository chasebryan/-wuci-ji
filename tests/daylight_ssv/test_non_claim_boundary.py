from __future__ import annotations

import unittest

from daylight_ssv.report import NON_CLAIM_STATEMENT
from .helpers import domain_checks, report_for


class NonClaimBoundaryTests(unittest.TestCase):
    def test_report_carries_non_claim_boundary(self):
        boundary = report_for(domain_checks())["non_claim_boundary"]
        self.assertFalse(boundary["certifies_security"])
        self.assertFalse(boundary["certifies_production_readiness"])
        self.assertFalse(boundary["certifies_audit_status"])
        self.assertFalse(boundary["certifies_post_quantum_security"])
        self.assertFalse(boundary["implies_agency_endorsement"])
        self.assertFalse(boundary["proves_mathematical_finality"])
        self.assertEqual(boundary["statement"], NON_CLAIM_STATEMENT)


if __name__ == "__main__":
    unittest.main()

