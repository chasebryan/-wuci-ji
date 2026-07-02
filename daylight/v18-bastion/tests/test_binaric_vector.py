from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from src import binaric_vector
from src.canonical_json import json_bytes, load_json_no_floats


class BinaricVectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.subject = self.root / "subject.bin"
        self.subject.write_bytes(b"binaric subject")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _vector(self) -> dict:
        return binaric_vector.measure_subject(subject_path="subject.bin", base_dir=self.root)

    def test_valid_vector_verifies(self) -> None:
        vector = self._vector()
        result = binaric_vector.verify_vector(vector, base_dir=self.root)
        self.assertTrue(result["verified"])

    def test_edited_file_digest_rejects(self) -> None:
        vector = self._vector()
        vector["file_sha256"] = "0" * 64
        vector["vector_digest"] = binaric_vector.vector_digest(vector)
        result = binaric_vector.verify_vector(vector, base_dir=self.root)
        self.assertFalse(result["verified"])
        self.assertIn("file_sha256 mismatch", result["blockers"])

    def test_edited_section_digest_rejects(self) -> None:
        vector = self._vector()
        vector["section_digests"][0]["sha256"] = "0" * 64
        vector["vector_digest"] = binaric_vector.vector_digest(vector)
        result = binaric_vector.verify_vector(vector, base_dir=self.root)
        self.assertFalse(result["verified"])
        self.assertIn("whole_file section sha256 mismatch", result["blockers"])

    def test_edited_policy_digest_rejects_shape_digest(self) -> None:
        vector = self._vector()
        vector["policy_digest"] = "0" * 64
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.validate_vector_shape(vector)

    def test_edited_scorecard_digest_rejects_shape_digest(self) -> None:
        vector = self._vector()
        vector["event_horizon_scorecard_digest"] = "0" * 64
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.validate_vector_shape(vector)

    def test_manual_vector_edit_rejects(self) -> None:
        vector = self._vector()
        vector["size_bytes"] += 1
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.validate_vector_shape(vector)

    def test_path_escape_rejected(self) -> None:
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.measure_subject(subject_path="../subject.bin", base_dir=self.root)

    def test_absolute_escape_rejected(self) -> None:
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.measure_subject(subject_path=self.subject, base_dir=self.root)

    def test_symlink_rejected(self) -> None:
        link = self.root / "link.bin"
        try:
            link.symlink_to(self.subject)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable")
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.measure_subject(subject_path="link.bin", base_dir=self.root)

    def test_float_rejected(self) -> None:
        path = self.root / "float.json"
        path.write_text('{"x": 0.5}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            load_json_no_floats(path)

    def test_unknown_critical_field_rejected(self) -> None:
        vector = self._vector()
        vector["new_critical"] = True
        vector["vector_digest"] = binaric_vector.vector_digest(vector)
        with self.assertRaises(binaric_vector.BinaricVectorError):
            binaric_vector.validate_vector_shape(vector)


if __name__ == "__main__":
    unittest.main()
