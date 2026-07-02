from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CURRENT_STATE = ROOT / "examples" / "state.current.json"
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
            self._run("score", "--state", str(CURRENT_STATE), "--out", str(first), "--format", "json")
            self._run("score", "--state", str(CURRENT_STATE), "--out", str(second), "--format", "json")
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_verify_scorecard_passes_for_generated_current_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scorecard.json"
            self._run("score", "--state", str(CURRENT_STATE), "--out", str(out))
            result = self._run("verify-scorecard", str(out), "--state", str(CURRENT_STATE))
            self.assertIn("scorecard verified", result.stdout)

    def test_verify_scorecard_fails_after_manual_edit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scorecard.json"
            self._run("score", "--state", str(CURRENT_STATE), "--out", str(out))
            data = json.loads(out.read_text(encoding="utf-8"))
            data["score_AM_plus"] += 1
            out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result = self._run("verify-scorecard", str(out), "--state", str(CURRENT_STATE), check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_fracture_command_exits_zero_when_mutations_reject(self) -> None:
        result = self._run("fracture", "--state", str(CURRENT_STATE), "--format", "json")
        data = json.loads(result.stdout)
        self.assertTrue(data["passed"])

    def test_vector_command_emits_python_reference_vector(self) -> None:
        result = self._run("vector", "--state", str(CURRENT_STATE), "--format", "json")
        data = json.loads(result.stdout)
        self.assertEqual(data["implementation_family"], "python-reference")
        self.assertEqual(data["score_AM_plus"], 999_999_687)
        self.assertEqual(data["residue_AM_plus"], 313)

    def test_agreement_command_fails_without_three_vectors(self) -> None:
        result = self._run("agreement", "--state", str(CURRENT_STATE), "--format", "json", check=False)
        self.assertNotEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertFalse(data["passed"])
        self.assertEqual(data["agreement_status"], "partial_2_of_3")
        self.assertEqual(data["quorum"], "2/3")
        self.assertIn("at least three verifier vectors required", data["blockers"])
        self.assertIn("verifier quorum incomplete: 2/3", data["blockers"])

    def test_blockers_command_lists_current_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scorecard.json"
            self._run("score", "--state", str(CURRENT_STATE), "--out", str(out))
            result = self._run(
                "blockers",
                "--scorecard",
                str(out),
                "--state",
                str(CURRENT_STATE),
                "--format",
                "json",
            )
            data = json.loads(result.stdout)
            self.assertIn("omega_eff below declaration threshold", data["blockers"])
            self.assertIn("score_AM_plus below declaration target", data["blockers"])
            self.assertIn("cross_verifier_agreement_passed=false", data["blockers"])
            self.assertIn("verifier quorum incomplete: 2/3", data["blockers"])

    def test_declaration_gate_fails_for_current_without_cross_verifier_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scorecard.json"
            self._run("score", "--state", str(CURRENT_STATE), "--out", str(out))
            result = self._run(
                "declaration-gate",
                "--scorecard",
                str(out),
                "--state",
                str(CURRENT_STATE),
                "--format",
                "json",
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertEqual(data["decision"], "declaration_refused")
            self.assertFalse(data["cross_verifier_agreement_passed"])
            self.assertEqual(data["cross_verifier_agreement_status"], "partial_2_of_3")
            self.assertIn("omega_eff below declaration threshold", data["blockers"])
            self.assertIn("verifier quorum incomplete: 2/3", data["blockers"])

    def test_frontier_command_lists_open_atoms(self) -> None:
        result = self._run("frontier", "--state", str(CURRENT_STATE), "--format", "json")
        data = json.loads(result.stdout)
        self.assertEqual(data["score_AM_plus"], 999_999_687)
        self.assertTrue(data["weakest_fields"])
        self.assertTrue(data["open_proof_atoms"])
        self.assertEqual(data["weakest_fields"][0]["id"], "F2")

    def test_fixture_demo_produces_ceiling_score_but_not_claim_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fixture.json"
            self._run("fixture-demo", "--state", str(FIXTURE_STATE), "--out", str(out), "--format", "json")
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["score_AM_plus"], 999_999_999)
            self.assertTrue(data["fixture"])
            self.assertFalse(data["claim_usable"])
            self.assertFalse(data["declared"])

    def test_declaration_gate_fails_for_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fixture.json"
            self._run("fixture-demo", "--state", str(FIXTURE_STATE), "--out", str(out))
            result = self._run(
                "declaration-gate",
                "--scorecard",
                str(out),
                "--state",
                str(FIXTURE_STATE),
                "--format",
                "json",
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            data = json.loads(result.stdout)
            self.assertFalse(data["claim_usable"])
            self.assertTrue(data["fixture"])

    def test_doctor_exits_zero(self) -> None:
        result = self._run("doctor")
        self.assertEqual(result.returncode, 0)
        self.assertIn("doctor pass", result.stdout)


if __name__ == "__main__":
    unittest.main()
