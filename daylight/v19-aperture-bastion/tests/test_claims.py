from __future__ import annotations

import unittest

from src import claims


class ClaimBoundaryTests(unittest.TestCase):
    def test_default_boundary_and_non_claims_validate(self) -> None:
        claims.validate_claim_boundary(claims.claim_boundary())
        claims.validate_non_claims(claims.non_claims())

    def test_every_forbidden_authority_claim_rejects_true(self) -> None:
        for claim in claims.FORBIDDEN_AUTHORITY_CLAIMS:
            boundary = claims.claim_boundary()
            boundary[claim] = True
            with self.assertRaises(claims.ClaimBoundaryError, msg=claim):
                claims.validate_claim_boundary(boundary)

    def test_non_boolean_claim_rejects(self) -> None:
        boundary = claims.claim_boundary()
        boundary["production_cryptography"] = "no"
        with self.assertRaises(claims.ClaimBoundaryError):
            claims.validate_claim_boundary(boundary)

    def test_missing_claim_key_rejects(self) -> None:
        boundary = claims.claim_boundary()
        del boundary["fips_validation"]
        with self.assertRaises(claims.ClaimBoundaryError):
            claims.validate_claim_boundary(boundary)

    def test_unknown_claim_key_rejects(self) -> None:
        boundary = claims.claim_boundary()
        boundary["certified_by_someone"] = True
        with self.assertRaises(claims.ClaimBoundaryError):
            claims.validate_claim_boundary(boundary)

    def test_missing_mandatory_non_claim_rejects(self) -> None:
        for mandatory in claims.MANDATORY_NON_CLAIMS:
            trimmed = [item for item in claims.non_claims() if item != mandatory]
            with self.assertRaises(claims.ClaimBoundaryError, msg=mandatory):
                claims.validate_non_claims(trimmed)

    def test_unsorted_or_duplicate_non_claims_reject(self) -> None:
        unsorted = list(reversed(claims.non_claims()))
        with self.assertRaises(claims.ClaimBoundaryError):
            claims.validate_non_claims(unsorted)
        duplicated = claims.non_claims() + [claims.non_claims()[0]]
        with self.assertRaises(claims.ClaimBoundaryError):
            claims.validate_non_claims(duplicated)


if __name__ == "__main__":
    unittest.main()
