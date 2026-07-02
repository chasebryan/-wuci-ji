from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import capsule as capsule_mod
from src import claims
from src.canonical_json import json_bytes
from src.pathsafe import PathSafetyError, atomic_write_bytes

EXAMPLE_SUBJECT = "daylight/v19-aperture-bastion/examples/example-subject.bin"
EXAMPLE_CAPSULE = "daylight/v19-aperture-bastion/examples/expected-capsule.v19.json"


class CapsuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        (self.base / "artifact.bin").write_bytes(b"aperture capsule test subject")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _build(self, **kwargs) -> dict:
        kwargs.setdefault("subjects", ["artifact.bin"])
        kwargs.setdefault("base_dir", self.base)
        kwargs.setdefault("fixture", True)
        return capsule_mod.build_capsule(**kwargs)

    def _retamper(self, capsule: dict) -> dict:
        capsule["capsule_digest"] = capsule_mod.capsule_digest(capsule)
        return capsule

    def test_build_and_verify_roundtrip(self) -> None:
        built = self._build()
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertTrue(result["verified"], result)
        self.assertEqual(result["blockers"], [])

    def test_build_twice_is_byte_identical(self) -> None:
        first = json_bytes(self._build())
        second = json_bytes(self._build())
        self.assertEqual(first, second)

    def test_committed_example_capsule_is_reproducible(self) -> None:
        built = capsule_mod.build_capsule(
            subjects=[EXAMPLE_SUBJECT], base_dir=capsule_mod.REPO_ROOT, fixture=True
        )
        committed = (capsule_mod.REPO_ROOT / EXAMPLE_CAPSULE).read_bytes()
        self.assertEqual(json_bytes(built), committed)

    def test_edited_reference_digest_fails_verification(self) -> None:
        built = self._build()
        built["optional_meridian_scorecard_digest"] = "a" * 64
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_edited_claim_fails_even_with_recomputed_digest(self) -> None:
        for claim in claims.FORBIDDEN_AUTHORITY_CLAIMS:
            built = self._build()
            built["claim_boundary"][claim] = True
            self._retamper(built)
            result = capsule_mod.verify_capsule(built, base_dir=self.base)
            self.assertFalse(result["verified"], claim)
            self.assertIn(claim, result["blockers"][0])

    def test_removed_non_claim_fails_even_with_recomputed_digest(self) -> None:
        built = self._build()
        built["non_claims"] = [
            item for item in built["non_claims"] if item != "not production cryptography"
        ]
        self._retamper(built)
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_edited_subject_digest_fails_verification(self) -> None:
        built = self._build()
        built["subject_sha256"] = "b" * 64
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_subject_file_mutation_fails_verification(self) -> None:
        built = self._build()
        (self.base / "artifact.bin").write_bytes(b"tampered subject bytes")
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])
        self.assertTrue(any("digest mismatch" in blocker for blocker in result["blockers"]))

    def test_edited_public_manifest_fails_verification(self) -> None:
        built = self._build()
        built["public_manifest"][0]["sha256"] = "c" * 64
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_public_manifest_traversal_rejected(self) -> None:
        with self.assertRaises((capsule_mod.CapsuleError, PathSafetyError)):
            self._build(public_files=["../escape.txt"])
        built = self._build()
        built["public_manifest"] = [{"path": "../evil", "sha256": "a" * 64, "size_bytes": 1}]
        self._retamper(built)
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_public_manifest_absolute_path_rejected(self) -> None:
        with self.assertRaises((capsule_mod.CapsuleError, PathSafetyError)):
            self._build(public_files=["/etc/hostname"])
        built = self._build()
        built["public_manifest"] = [{"path": "/abs/evil", "sha256": "a" * 64, "size_bytes": 1}]
        self._retamper(built)
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_unsupported_schema_version_rejected(self) -> None:
        built = self._build()
        built["schema_version"] = "99.0.0"
        self._retamper(built)
        with self.assertRaises(capsule_mod.CapsuleError) as ctx:
            capsule_mod.validate_capsule_shape(built)
        self.assertIn("schema_version", str(ctx.exception))

    def test_failed_firewall_result_rejected(self) -> None:
        built = self._build()
        built["firewall_result"]["passed"] = False
        self._retamper(built)
        result = capsule_mod.verify_capsule(built, base_dir=self.base)
        self.assertFalse(result["verified"])

    def test_private_manifest_input_rejected_at_build(self) -> None:
        (self.base / "secret.txt").write_bytes(b"anything")
        with self.assertRaises(capsule_mod.CapsuleError):
            self._build(subjects=["artifact.bin"], public_files=["secret.txt"])

    def test_private_marker_content_rejected_at_build(self) -> None:
        (self.base / "notes.md").write_bytes(b"-----BEGIN RSA PRIVATE KEY-----")
        with self.assertRaises(capsule_mod.CapsuleError):
            self._build(public_files=["notes.md"])

    def test_symlink_subject_rejected(self) -> None:
        target = self.base / "artifact.bin"
        link = self.base / "linked.bin"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unsupported")
        with self.assertRaises(PathSafetyError):
            self._build(subjects=["linked.bin"])

    def test_reserved_public_names_rejected(self) -> None:
        (self.base / capsule_mod.CAPSULE_FILENAME).write_bytes(b"{}")
        with self.assertRaises(capsule_mod.CapsuleError):
            self._build(public_files=[capsule_mod.CAPSULE_FILENAME])

    def test_output_overwrite_requires_force(self) -> None:
        out = self.base / "capsule.json"
        atomic_write_bytes(out, json_bytes(self._build()))
        with self.assertRaises(PathSafetyError):
            atomic_write_bytes(out, b"{}")
        atomic_write_bytes(out, json_bytes(self._build()), force=True)


if __name__ == "__main__":
    unittest.main()
