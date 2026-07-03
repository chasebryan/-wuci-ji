import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENV = {"PYTHONPATH": str(ROOT / "daylight/npt/v1")}
REGISTRY = "daylight/npt/v1/number-claims.registry.json"


class PositiveFixtureTests(unittest.TestCase):
    def test_positive_fixtures_pass(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "daylight_npt",
                "scan",
                "--registry",
                REGISTRY,
                "--json",
                "daylight/npt/v1/examples/positive",
            ],
            cwd=ROOT,
            env=ENV,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        report = json.loads(proc.stdout)
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["summary"]["errors"], 0)


if __name__ == "__main__":
    unittest.main()
