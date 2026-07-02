from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import capsule as capsule_mod
from src import public_artifact
from src.canonical_json import json_bytes
from src.pathsafe import atomic_write_bytes


class PublicArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = self.root / "repo"
        self.base.mkdir()
        (self.base / "artifact.bin").write_bytes(b"public artifact subject")
        (self.base / "evidence").mkdir()
        (self.base / "evidence" / "report.json").write_bytes(b'{"kind": "evidence-report"}\n')
        self.capsule_path = self.base / "capsule.json"
        self._write_capsule()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_capsule(self, **kwargs) -> dict:
        kwargs.setdefault("subjects", ["artifact.bin"])
        kwargs.setdefault("public_files", ["artifact.bin", "evidence/report.json"])
        kwargs.setdefault("base_dir", self.base)
        kwargs.setdefault("fixture", True)
        built = capsule_mod.build_capsule(**kwargs)
        atomic_write_bytes(self.capsule_path, json_bytes(built), force=True)
        return built

    def test_public_artifact_roundtrip(self) -> None:
        out = self.root / "public"
        report = public_artifact.build_public_artifact(self.capsule_path, out, base_dir=self.base)
        self.assertEqual(report["file_count"], 4)
        self.assertTrue((out / capsule_mod.CAPSULE_FILENAME).is_file())
        self.assertTrue((out / capsule_mod.SUMS_FILENAME).is_file())
        self.assertTrue((out / "evidence" / "report.json").is_file())

    def test_sha256sums_output_is_deterministic(self) -> None:
        first = self.root / "public-one"
        second = self.root / "public-two"
        public_artifact.build_public_artifact(self.capsule_path, first, base_dir=self.base)
        public_artifact.build_public_artifact(self.capsule_path, second, base_dir=self.base)
        self.assertEqual(
            (first / capsule_mod.SUMS_FILENAME).read_bytes(),
            (second / capsule_mod.SUMS_FILENAME).read_bytes(),
        )

    def test_missing_public_file_fails(self) -> None:
        (self.base / "evidence" / "report.json").unlink()
        out = self.root / "public"
        with self.assertRaises(public_artifact.PublicArtifactError):
            public_artifact.build_public_artifact(self.capsule_path, out, base_dir=self.base)
        self.assertFalse(out.exists())

    def test_source_drift_after_capsule_fails(self) -> None:
        (self.base / "evidence" / "report.json").write_bytes(b'{"kind": "drifted"}\n')
        out = self.root / "public"
        with self.assertRaises(public_artifact.PublicArtifactError):
            public_artifact.build_public_artifact(self.capsule_path, out, base_dir=self.base)
        self.assertFalse(out.exists())

    def test_refuses_nonempty_output_without_force(self) -> None:
        out = self.root / "public"
        public_artifact.build_public_artifact(self.capsule_path, out, base_dir=self.base)
        with self.assertRaises(public_artifact.PublicArtifactError):
            public_artifact.build_public_artifact(self.capsule_path, out, base_dir=self.base)
        report = public_artifact.build_public_artifact(
            self.capsule_path, out, base_dir=self.base, force=True
        )
        self.assertEqual(report["file_count"], 4)

    def test_tampered_capsule_file_fails(self) -> None:
        data = self.capsule_path.read_text(encoding="utf-8")
        self.capsule_path.write_text(data.replace('"fixture": true', '"fixture": false'), encoding="utf-8")
        out = self.root / "public"
        with self.assertRaises((public_artifact.PublicArtifactError, ValueError)):
            public_artifact.build_public_artifact(self.capsule_path, out, base_dir=self.base)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
