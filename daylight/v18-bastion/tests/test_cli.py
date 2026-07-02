from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BinaricCliTests(unittest.TestCase):
    def _run(self, cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(
            [sys.executable, "-m", "src.cli", *args],
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def test_cli_roundtrip_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subject = root / "subject.bin"
            vector = root / "subject.dbv.json"
            subject.write_bytes(b"cli subject")
            self._run(root, "measure", "--subject", "subject.bin", "--out", str(vector), "--format", "json")
            verified = self._run(root, "verify-vector", str(vector), "--format", "json")
            self.assertTrue(json.loads(verified.stdout)["verified"])
            inspected = self._run(root, "inspect-vector", str(vector), "--format", "json")
            self.assertEqual(json.loads(inspected.stdout)["subject_path_normalized"], "subject.bin")

    def test_verify_vector_fails_after_subject_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subject = root / "subject.bin"
            vector = root / "subject.dbv.json"
            subject.write_bytes(b"before")
            self._run(root, "measure", "--subject", "subject.bin", "--out", str(vector))
            subject.write_bytes(b"after")
            result = self._run(root, "verify-vector", str(vector), "--format", "json", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads(result.stdout)["verified"])

    def test_tamper_check_rejects_without_user_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subject = root / "subject.bin"
            before = root / "before.json"
            after = root / "after.json"
            subject.write_bytes(b"before")
            self._run(root, "measure", "--subject", "subject.bin", "--out", str(before))
            subject.write_bytes(b"after")
            self._run(root, "measure", "--subject", "subject.bin", "--out", str(after))
            result = self._run(root, "tamper-check", "--before", str(before), "--after", str(after), "--format", "json", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)["status"], "tamper_rejected")


if __name__ == "__main__":
    unittest.main()
