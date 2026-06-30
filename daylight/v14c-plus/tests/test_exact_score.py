from __future__ import annotations

import unittest

from src import scoring
from tests.helpers import WEIGHTS


class ExactScoreTests(unittest.TestCase):
    def test_v14c_plus_score_is_exact(self) -> None:
        weights = scoring.load_weights(WEIGHTS)
        result = scoring.compute_score(scoring.TARGET_Q_VECTOR, weights)
        self.assertEqual(result["final_score_M"], 998200)
        self.assertEqual(result["unified_score_rational"], "4991/5000")
        self.assertEqual(result["unified_score_decimal"], "0.9982")
        self.assertEqual([item["contribution_M"] for item in result["term_contributions_M"]], [
            160000,
            109780,
            160000,
            130000,
            99700,
            69650,
            29850,
            79840,
            49850,
            69790,
            19800,
            19940,
        ])

    def test_incorrect_challenger_c_vector_is_not_998200(self) -> None:
        weights = scoring.load_weights(WEIGHTS)
        result = scoring.compute_score(scoring.CHALLENGER_C_VECTOR, weights)
        self.assertEqual(result["final_score_M"], 995600)
        self.assertNotEqual(result["final_score_M"], 998200)


if __name__ == "__main__":
    unittest.main()
