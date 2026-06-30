from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from src import obligations, scoring
from tests.helpers import OBLIGATIONS, WEIGHTS


class ObligationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = obligations.load_registry(OBLIGATIONS)
        self.weights = scoring.load_weights(WEIGHTS)

    def test_each_dimension_sums_to_one_thousand(self) -> None:
        for q_id in obligations.Q_IDS:
            total = sum(int(ob["weight"]) for ob in self.registry["dimensions"][q_id]["obligations"])
            self.assertEqual(total, 1000, q_id)

    def test_internal_ceiling_and_perfect_are_known_constants(self) -> None:
        internal = scoring.compute_score(obligations.internal_ceiling_q_vector(self.registry), self.weights)
        perfect = scoring.compute_score(obligations.perfect_q_vector(self.registry), self.weights)
        self.assertEqual(internal["final_score_M"], 998900)
        self.assertEqual(perfect["final_score_M"], 1000000)

    def test_registry_digest_is_stable(self) -> None:
        first = obligations.registry_digest(self.registry)
        second = obligations.registry_digest(copy.deepcopy(self.registry))
        self.assertEqual(first, second)

    def _write_registry(self, root: Path, data: dict) -> Path:
        path = root / "obligations.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_duplicate_obligation_id_is_rejected(self) -> None:
        broken = copy.deepcopy(self.registry)
        broken["dimensions"]["q1_doctrine_master_law"]["obligations"][0]["id"] = "o.q1.doctrine_claim_bound"
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_registry(Path(tmp), broken)
            with self.assertRaises(obligations.ObligationError):
                obligations.load_registry(path)

    def test_weight_sum_other_than_1000_is_rejected(self) -> None:
        broken = copy.deepcopy(self.registry)
        broken["dimensions"]["q1_doctrine_master_law"]["obligations"][0]["weight"] = 701
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_registry(Path(tmp), broken)
            with self.assertRaises(obligations.ObligationError):
                obligations.load_registry(path)

    def test_external_scope_must_bind_external_attestation(self) -> None:
        broken = copy.deepcopy(self.registry)
        target = broken["dimensions"]["q11_external_falsification_readiness"]["obligations"][-1]
        self.assertEqual(target["scope"], "external")
        target["evidence_class"] = "test"
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_registry(Path(tmp), broken)
            with self.assertRaises(obligations.ObligationError):
                obligations.load_registry(path)

    def test_float_weight_is_rejected(self) -> None:
        broken = copy.deepcopy(self.registry)
        obs = broken["dimensions"]["q1_doctrine_master_law"]["obligations"]
        obs[0]["weight"] = 700.0
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_registry(Path(tmp), broken)
            with self.assertRaises(obligations.ObligationError):
                obligations.load_registry(path)


if __name__ == "__main__":
    unittest.main()
