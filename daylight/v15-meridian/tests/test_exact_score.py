from __future__ import annotations

import unittest

from src import obligations, scoring
from tests.helpers import OBLIGATIONS, WEIGHTS


class ExactScoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = obligations.load_registry(OBLIGATIONS)
        self.weights = scoring.load_weights(WEIGHTS)
        self.labels = obligations.labels(self.registry)

    def test_internal_ceiling_is_exactly_998900(self) -> None:
        q_vector = obligations.internal_ceiling_q_vector(self.registry)
        result = scoring.compute_score(q_vector, self.weights, self.labels)
        self.assertEqual(result["final_score_M"], 998900)
        self.assertEqual(result["unified_score_rational"], "9989/10000")
        self.assertEqual(result["unified_score_decimal"], "0.9989")

    def test_perfect_score_is_exactly_1000000(self) -> None:
        q_vector = obligations.perfect_q_vector(self.registry)
        result = scoring.compute_score(q_vector, self.weights, self.labels)
        self.assertEqual(result["final_score_M"], 1000000)
        self.assertEqual(result["unified_score_rational"], "1/1")
        self.assertEqual(result["unified_score_decimal"], "1.0000")

    def test_internal_ceiling_is_strictly_below_perfect(self) -> None:
        internal = scoring.compute_score(obligations.internal_ceiling_q_vector(self.registry), self.weights)
        perfect = scoring.compute_score(obligations.perfect_q_vector(self.registry), self.weights)
        self.assertLess(internal["final_score_M"], perfect["final_score_M"])
        self.assertEqual(perfect["final_score_M"] - internal["final_score_M"], 1100)

    def test_challenger_vector_recalculates_to_a_different_value(self) -> None:
        # Drop exactly one closed obligation; the validator must recalculate, not
        # accept the narrated ceiling.
        closed = {
            ob["id"]
            for _, ob in obligations.iter_obligations(self.registry)
            if ob["scope"] == "internal" and ob["id"] != "o.q10.traceability_map"
        }
        challenger = obligations.derive_q_vector(self.registry, closed)
        result = scoring.compute_score(challenger, self.weights)
        # q10 loses 600/1000 of its weight (70 thousandths): 998900 - 70*600/1000... exact:
        self.assertEqual(result["final_score_M"], 998900 - 70 * 600)
        self.assertNotEqual(result["final_score_M"], 998900)


if __name__ == "__main__":
    unittest.main()
