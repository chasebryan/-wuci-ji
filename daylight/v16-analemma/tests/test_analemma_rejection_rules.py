from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src import analemma
from tests import helpers


class AnalemmaRejectionRuleTests(unittest.TestCase):
    def test_manual_credit_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            evidence = helpers.write_json(root, "analemma-evidence.json", {"manual_credit": 1})
            with self.assertRaises(analemma.AnalemmaError):
                analemma.build_report(artifact, evidence_path=evidence)

    def test_claim_score_override_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            evidence = helpers.write_json(root, "analemma-evidence.json", {"claim_score_override_M": 1000000})
            with self.assertRaises(analemma.AnalemmaError):
                analemma.build_report(artifact, evidence_path=evidence)

    def test_float_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            evidence = helpers.write_json(root, "analemma-evidence.json", {"proof_mass_hint": 1.25})
            with self.assertRaises(analemma.AnalemmaError):
                analemma.build_report(artifact, evidence_path=evidence)

    def test_registry_credit_tamper_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = json.loads(Path(analemma.DEFAULT_REGISTRY).read_text(encoding="utf-8"))
            data["proof_units"][0]["base_credit"] += 1
            registry = helpers.write_json(root, "proof-units.tampered.json", data)
            with self.assertRaises(analemma.AnalemmaError):
                analemma.load_registry(registry)

    def test_security_bypass_regression_rejects_release_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = helpers.build_solstice_artifact(root)
            history = helpers.write_json(root, "analemma-history.json", {"security_bypass_regression": True})
            with self.assertRaises(analemma.AnalemmaError):
                analemma.build_report(artifact, history_path=history)


if __name__ == "__main__":
    unittest.main()
