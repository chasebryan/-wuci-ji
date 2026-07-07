from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import PACKAGE_ROOT

EXAMPLES = PACKAGE_ROOT / "examples"
SCORECARD = EXAMPLES / "expected-scorecard.v15-meridian.json"
LEDGER = EXAMPLES / "ledger.seed.jsonl"
CORPUS = EXAMPLES / "corpus.seed.jsonl"

COMMANDS = [
    "init-ledger",
    "append-entry",
    "freeze-corpus",
    "score",
    "verify-scorecard",
    "frontier",
    "attestation-template",
    "explain",
    "gate",
    "doctor",
    "artifact",
    "check-downgrade",
]


def run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(PACKAGE_ROOT))
    return subprocess.run(
        [sys.executable, "-m", "src.cli", *args],
        env=env,
        capture_output=True,
        text=True,
    )


class CliTests(unittest.TestCase):
    def test_every_command_has_help(self) -> None:
        for command in COMMANDS:
            proc = run_cli(command, "--help")
            self.assertEqual(proc.returncode, 0, f"{command} --help: {proc.stderr}")
            self.assertIn(command, proc.stdout)

    def test_version(self) -> None:
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("15.0.0", proc.stdout)

    def test_score_text_and_json(self) -> None:
        text = run_cli("score", "--format", "text")
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("998900", text.stdout)
        js = run_cli("score", "--format", "json")
        self.assertEqual(js.returncode, 0)
        self.assertEqual(json.loads(js.stdout)["final_score_M"], 998900)

    def test_score_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sc.json"
            receipt = Path(tmp) / "rc.json"
            proc = run_cli("score", "--out", str(out), "--receipt", str(receipt))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(out.read_text())["final_score_M"], 998900)
            self.assertTrue(receipt.is_file())

    def test_verify_passes_on_committed_scorecard(self) -> None:
        proc = run_cli("verify-scorecard", str(SCORECARD), "--ledger", str(LEDGER), "--corpus", str(CORPUS))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("evidence-bound", proc.stdout)

    def test_verify_strict_requires_evidence(self) -> None:
        proc = run_cli("verify-scorecard", str(SCORECARD), "--strict")
        self.assertEqual(proc.returncode, 1)

    def test_verify_fails_on_edited_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            edited = Path(tmp) / "edited.json"
            data = json.loads(SCORECARD.read_text())
            for pair in data["q_vector"]:
                if pair[0] == "q2_formalism_mathematical_density":
                    pair[1] = "1/1"
            edited.write_text(json.dumps(data), encoding="utf-8")
            proc = run_cli("verify-scorecard", str(edited))
            self.assertEqual(proc.returncode, 1)

    def test_verify_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dup = Path(tmp) / "duplicate-scorecard.json"
            dup.write_text('{"scorecard_version":"bad","scorecard_version":"ambiguous"}\n', encoding="utf-8")
            proc = run_cli("verify-scorecard", str(dup), "--ledger", str(LEDGER), "--corpus", str(CORPUS))
            self.assertEqual(proc.returncode, 1)
            self.assertIn("duplicate JSON key", proc.stderr)

    def test_gate_pass_and_fail(self) -> None:
        ok = run_cli(
            "gate", "--scorecard", str(SCORECARD), "--ledger", str(LEDGER), "--corpus", str(CORPUS),
            "--min-score", "998900", "--require-no-open-internal", "--allow-external-residue",
        )
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("PASS", ok.stdout)

        residue = run_cli("gate", "--scorecard", str(SCORECARD))
        self.assertEqual(residue.returncode, 1)
        self.assertIn("requires --ledger and --corpus", residue.stderr)

        too_high = run_cli(
            "gate", "--scorecard", str(SCORECARD), "--ledger", str(LEDGER), "--corpus", str(CORPUS),
            "--allow-external-residue", "--min-score", "1000000",
        )
        self.assertEqual(too_high.returncode, 1)

    def test_doctor_is_healthy(self) -> None:
        proc = run_cli("doctor")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("healthy", proc.stdout)

    def test_frontier_json(self) -> None:
        proc = run_cli("frontier", "--json")
        self.assertEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertEqual(report["internal_ceiling_M"], 998900)
        self.assertEqual(report["structural_external_residue_M"], 1100)

    def test_attestation_template_valid_and_rejects_harness_signer(self) -> None:
        ok = run_cli("attestation-template", "--obligation-id", "o.q7.external_red_team", "--signer-id", "ext:red-team")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["external_signer_id"], "ext:red-team")

        self_signed = run_cli(
            "attestation-template", "--obligation-id", "o.q7.external_red_team",
            "--signer-id", "daylight-meridian-harness-v0.1",
        )
        self.assertEqual(self_signed.returncode, 1)

        internal = run_cli("attestation-template", "--obligation-id", "o.q1.master_law_executable", "--signer-id", "ext:x")
        self.assertEqual(internal.returncode, 1)

    def test_explain_runs(self) -> None:
        proc = run_cli("explain", "--scorecard", str(SCORECARD), "--ledger", str(LEDGER))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("q11_external_falsification_readiness", proc.stdout)


if __name__ == "__main__":
    unittest.main()
