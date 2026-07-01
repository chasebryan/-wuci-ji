from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE_STATE = ROOT / "examples" / "state.baseline.json"
FIXTURE_STATE = ROOT / "examples" / "state.declaration-fixture.json"


class CLITests(unittest.TestCase):
    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(
            [sys.executable, "-m", "src.cli", *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def test_score_command_writes_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.json"
            second = Path(tmp) / "second.json"
            self._run("score", "--state", str(BASELINE_STATE), "--out", str(first), "--format", "json")
            self._run("score", "--state", str(BASELINE_STATE), "--out", str(second), "--format", "json")
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_verify_scorecard_passes_for_generated_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scorecard.json"
            self._run("score", "--state", str(BASELINE_STATE), "--out", str(out))
            result = self._run("verify-scorecard", str(out), "--state", str(BASELINE_STATE))
            self.assertIn("scorecard verified", result.stdout)

    def test_verify_scorecard_fails_after_manual_edit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scorecard.json"
            self._run("score", "--state", str(BASELINE_STATE), "--out", str(out))
            data = json.loads(out.read_text(encoding="utf-8"))
            data["score_AM_plus"] += 1
            out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = self._run("verify-scorecard", str(out), "--state", str(BASELINE_STATE), check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_doctor_returns_zero(self) -> None:
        result = self._run("doctor")
        self.assertEqual(result.returncode, 0)
        self.assertIn("doctor pass", result.stdout)

    def test_fixture_demo_score_is_declared_but_not_claim_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fixture.json"
            self._run("fixture-demo", "--state", str(FIXTURE_STATE), "--out", str(out), "--format", "json")
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["score_AM_plus"], 999_999_999)
            self.assertTrue(data["declared"])
            self.assertTrue(data["fixture"])
            self.assertFalse(data["claim_usable"])
            self.assertEqual(data["boundary"]["production_allowed"], False)

    def test_declaration_gate_refuses_current_state(self) -> None:
        result = self._run("declaration-gate", "--format", "json")
        data = json.loads(result.stdout)
        self.assertEqual(data["decision"], "declaration_refused")
        self.assertTrue(data["fracture_suite"]["passed"])
        self.assertTrue(data["cross_verifier_agreement"]["passed"])


if __name__ == "__main__":
    unittest.main()
