from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "daylight/ssv/v1/examples"


class CliTests(unittest.TestCase):
    def test_check_model_cli(self):
        proc = subprocess.run(
            [sys.executable, "-m", "daylight_ssv", "check-model"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("domain_weights_total: 100.0", proc.stdout)

    def test_validate_report_cli(self):
        proc = subprocess.run(
            [sys.executable, "-m", "daylight_ssv", "validate-report", str(EXAMPLES / "perfect.json")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_audit_json_cli_outputs_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, "-m", "daylight_ssv", "audit", "--json", "--repo-root", tmp],
                cwd=ROOT,
                text=True,
                capture_output=True,
                env=os.environ.copy(),
                check=False,
            )
        self.assertIn(proc.returncode, {0, 1})
        report = json.loads(proc.stdout)
        self.assertEqual(report["schema"], "daylight.ssv.v1.report")


if __name__ == "__main__":
    unittest.main()

