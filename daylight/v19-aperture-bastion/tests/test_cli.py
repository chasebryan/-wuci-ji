from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src import capsule as capsule_mod
from src.canonical_json import json_bytes, load_json_no_floats
from src.pathsafe import atomic_write_bytes

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]


class ApertureCliTests(unittest.TestCase):
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

    def _make_workspace(self, tmp: str) -> Path:
        base = Path(tmp)
        (base / "artifact.bin").write_bytes(b"cli test subject")
        return base

    def test_capsule_verify_public_artifact_firewall_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            self._run(
                base,
                "capsule",
                "--subject",
                "artifact.bin",
                "--fixture",
                "--out",
                "capsule.json",
            )
            verified = self._run(base, "verify-capsule", "capsule.json", "--format", "json")
            self.assertTrue(json.loads(verified.stdout)["verified"])
            self._run(
                base,
                "public-artifact",
                "--capsule",
                "capsule.json",
                "--out-dir",
                "public",
                "--format",
                "json",
            )
            fire = self._run(base, "firewall", "--root", "public", "--format", "json")
            self.assertTrue(json.loads(fire.stdout)["ok"])

    def test_verify_capsule_malformed_json_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            (base / "broken.json").write_text("{ this is not json", encoding="utf-8")
            result = self._run(base, "verify-capsule", "broken.json", check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_verify_capsule_float_payload_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            (base / "floaty.json").write_text('{"score": 1.5}', encoding="utf-8")
            result = self._run(base, "verify-capsule", "floaty.json", check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_unsupported_schema_version_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            built = capsule_mod.build_capsule(
                subjects=["artifact.bin"], base_dir=base, fixture=True
            )
            built["schema_version"] = "99.0.0"
            built["capsule_digest"] = capsule_mod.capsule_digest(built)
            atomic_write_bytes(base / "future.json", json_bytes(built))
            result = self._run(base, "verify-capsule", "future.json", "--format", "json", check=False)
            self.assertNotEqual(result.returncode, 0)
            report = json.loads(result.stdout)
            self.assertFalse(report["verified"])
            self.assertIn("schema_version", report["blockers"][0])

    def test_capsule_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            args = ("capsule", "--subject", "artifact.bin", "--fixture", "--out", "capsule.json")
            self._run(base, *args)
            result = self._run(base, *args, check=False)
            self.assertNotEqual(result.returncode, 0)
            self._run(base, *args, "--force")

    def test_firewall_cli_rejects_planted_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            self._run(base, "capsule", "--subject", "artifact.bin", "--fixture", "--out", "capsule.json")
            self._run(base, "public-artifact", "--capsule", "capsule.json", "--out-dir", "public")
            (base / "public" / "id_ed25519").write_bytes(b"planted")
            result = self._run(base, "firewall", "--root", "public", "--format", "json", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads(result.stdout)["ok"])

    def test_explain_reports_proofs_and_non_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = self._make_workspace(tmp)
            self._run(base, "capsule", "--subject", "artifact.bin", "--fixture", "--out", "capsule.json")
            result = self._run(base, "explain", "capsule.json")
            self.assertIn("proofs:", result.stdout)
            self.assertIn("non_claims:", result.stdout)
            self.assertIn("not production cryptography", result.stdout)
            as_json = self._run(base, "explain", "capsule.json", "--format", "json")
            payload = json.loads(as_json.stdout)
            self.assertTrue(payload["proofs"])
            self.assertTrue(payload["non_claims"])

    def test_doctor_runs_offline_against_repo_fixtures(self) -> None:
        result = self._run(REPO_ROOT, "doctor", "--format", "json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["network_access"], "none")
        check_names = {item["check"] for item in payload["checks"]}
        self.assertIn("example_capsule_verifies", check_names)
        self.assertIn("firewall_scan_rejects_planted_secret", check_names)

    def test_capsule_with_repo_evidence_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "capsule.json"
            self._run(
                REPO_ROOT,
                "capsule",
                "--subject",
                "daylight/v19-aperture-bastion/examples/example-subject.bin",
                "--binaric-vector",
                "daylight/v18-bastion/examples/transition.before.v18.json",
                "--binaric-vector",
                "daylight/v18-bastion/examples/transition.after.v18.json",
                "--transition-ledger",
                "daylight/v18-bastion/examples/transition-ledger.v18.json",
                "--meridian-scorecard",
                "daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json",
                "--event-horizon-scorecard",
                "daylight/v17-singularity/examples/expected-scorecard.current.v17.json",
                "--fixture",
                "--out",
                str(out),
            )
            capsule = load_json_no_floats(out)
            self.assertIsNotNone(capsule["optional_binaric_vector_digest"])
            self.assertIsNotNone(capsule["optional_transition_ledger_head"])
            self.assertIsNotNone(capsule["optional_meridian_scorecard_digest"])
            self.assertIsNotNone(capsule["optional_event_horizon_scorecard_digest"])
            verified = self._run(
                REPO_ROOT, "verify-capsule", str(out), "--require-evidence", "--format", "json"
            )
            self.assertTrue(json.loads(verified.stdout)["verified"])


if __name__ == "__main__":
    unittest.main()
