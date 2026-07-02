from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = "daylight-v18-fixture-passphrase"


class TransitionCliTests(unittest.TestCase):
    def _run(self, cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        env["DAYLIGHT_BASTION_PASSPHRASE"] = PASSPHRASE
        return subprocess.run(
            [sys.executable, "-m", "src.cli", *args],
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def _make_vectors(self, root: Path) -> tuple[Path, Path]:
        subject = root / "subject.bin"
        before = root / "before.json"
        after = root / "after.json"
        subject.write_bytes(b"before")
        self._run(root, "measure", "--subject", "subject.bin", "--out", str(before), "--format", "json")
        before_digest = json.loads(before.read_text(encoding="utf-8"))["vector_digest"]
        subject.write_bytes(b"after")
        self._run(
            root,
            "measure",
            "--subject",
            "subject.bin",
            "--out",
            str(after),
            "--previous-vector-digest",
            before_digest,
            "--format",
            "json",
        )
        return before, after

    def test_transition_cli_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before, after = self._make_vectors(root)
            unsigned = root / "transition.unsigned.json"
            signed = root / "transition.signed.json"
            ledger = root / "transition-ledger.jsonl"

            self._run(root, "transition-propose", "--before", str(before), "--after", str(after), "--reason", "user-approved update", "--out", str(unsigned), "--format", "json")
            unsigned_one = unsigned.read_text(encoding="utf-8")
            self._run(root, "transition-propose", "--before", str(before), "--after", str(after), "--reason", "user-approved update", "--out", str(unsigned), "--format", "json")
            self.assertEqual(unsigned_one, unsigned.read_text(encoding="utf-8"))

            self._run(root, "transition-sign", "--transition", str(unsigned), "--out", str(signed), "--format", "json")
            verify = self._run(root, "transition-verify", "--before", str(before), "--after", str(after), "--transition", str(signed), "--format", "json")
            self.assertTrue(json.loads(verify.stdout)["transition_valid"])

            edited = json.loads(signed.read_text(encoding="utf-8"))
            edited["reason"] = "manual edit"
            signed.write_text(json.dumps(edited, sort_keys=True), encoding="utf-8")
            verify_edited = self._run(root, "transition-verify", "--before", str(before), "--after", str(after), "--transition", str(signed), "--format", "json", check=False)
            self.assertNotEqual(verify_edited.returncode, 0)
            edited["reason"] = "user-approved update"
            signed.write_text(json.dumps(edited, sort_keys=True), encoding="utf-8")
            self._run(root, "transition-sign", "--transition", str(unsigned), "--out", str(signed), "--format", "json")

            self._run(root, "transition-ledger-init", "--out", str(ledger), "--format", "json")
            self._run(root, "transition-ledger-append", "--ledger", str(ledger), "--transition", str(signed), "--format", "json")
            ledger_verify = self._run(root, "transition-ledger-verify", "--ledger", str(ledger), "--format", "json")
            self.assertTrue(json.loads(ledger_verify.stdout)["ledger_valid"])

            no_transition = self._run(root, "tamper-check", "--before", str(before), "--after", str(after), "--format", "json", check=False)
            self.assertNotEqual(no_transition.returncode, 0)
            no_ledger = self._run(root, "tamper-check", "--before", str(before), "--after", str(after), "--transition", str(signed), "--format", "json", check=False)
            self.assertNotEqual(no_ledger.returncode, 0)
            accepted = self._run(
                root,
                "tamper-check",
                "--before",
                str(before),
                "--after",
                str(after),
                "--transition",
                str(signed),
                "--ledger",
                str(ledger),
                "--format",
                "json",
            )
            self.assertTrue(json.loads(accepted.stdout)["transition_allowed"])


if __name__ == "__main__":
    unittest.main()
