from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src import artifact as artifact_builder
from tests import helpers

REQUIRED_FILES = {
    "scorecard.v15-meridian.json",
    "reproducibility-receipt.v15-meridian.json",
    "frontier-report.v15-meridian.json",
    "frontier-report.v15-meridian.md",
    "ledger.with-scorecard.jsonl",
    "artifact-manifest.json",
    "SHA256SUMS",
}


class ArtifactTests(unittest.TestCase):
    def _build(self, root: Path, ledger: Path, corpus: Path) -> Path:
        out_dir = root / "artifact"
        artifact_builder.build_artifact(
            ledger_path=ledger,
            corpus_path=corpus,
            out_dir=out_dir,
            command_label="test",
        )
        return out_dir

    def test_artifact_contains_required_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, corpus = helpers.write_seed_inputs(root)
            out_dir = self._build(root, ledger, corpus)
            present = {p.name for p in out_dir.iterdir()}
        self.assertTrue(REQUIRED_FILES.issubset(present), present)

    def test_manifest_digests_match_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, corpus = helpers.write_seed_inputs(root)
            out_dir = self._build(root, ledger, corpus)
            manifest = json.loads((out_dir / "artifact-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["generated_date"], "2026-06-30")
            self.assertEqual(manifest["final_score_M"], 998900)
            self.assertEqual(manifest["external_residue_M"], 1100)
            for name, info in manifest["outputs"].items():
                actual = hashlib.sha256((out_dir / name).read_bytes()).hexdigest()
                self.assertEqual(actual, info["sha256"], name)
            for name, info in manifest["inputs"].items():
                self.assertTrue(info["path"])
                self.assertEqual(len(info["sha256"]), 64)
            self.assertIn("not production cryptography", manifest["boundary"])

    def test_sha256sums_are_correct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, corpus = helpers.write_seed_inputs(root)
            out_dir = self._build(root, ledger, corpus)
            sums = (out_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(sums), 6)
            for line in sums:
                digest, name = line.split("  ", 1)
                self.assertNotEqual(name, "SHA256SUMS")
                actual = hashlib.sha256((out_dir / name).read_bytes()).hexdigest()
                self.assertEqual(actual, digest, name)

    def test_artifact_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, corpus = helpers.write_seed_inputs(root)
            first = self._build(root / "a", ledger, corpus)
            second = self._build(root / "b", ledger, corpus)
            for name in REQUIRED_FILES:
                self.assertEqual(
                    (first / name).read_bytes(), (second / name).read_bytes(), f"non-deterministic: {name}"
                )

    def test_perfect_artifact_reaches_million(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger, corpus = helpers.write_perfect_inputs(root)
            out_dir = self._build(root, ledger, corpus)
            manifest = json.loads((out_dir / "artifact-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["final_score_M"], 1000000)
        self.assertEqual(manifest["residue_to_perfect_M"], 0)


if __name__ == "__main__":
    unittest.main()
