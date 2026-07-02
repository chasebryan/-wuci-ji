from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from src import capsule as capsule_mod
from src import firewall
from src import public_artifact
from src.canonical_json import json_bytes
from src.pathsafe import atomic_write_bytes

FORBIDDEN_NAME_SAMPLES = (
    "vault.key",
    "release.key",
    "smoke-secret.txt",
    "secret.txt",
    "opened.txt",
    "artifact.opened",
    "private-transcript.md",
    "id_rsa",
    "id_ed25519",
    ".env",
)

FORBIDDEN_MARKER_SAMPLES = (
    b"-----BEGIN PRIVATE KEY----- material",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"DAYLIGHT-VAULT-KEY: aa",
    b"meridian vault demo: sealed by evidence, opened by proof.",
    b"DAYLIGHT_BASTION_PASSPHRASE=x",
    b"daylight-v18-fixture-passphrase",
    b"contains smoke-secret material",
    b"PLAINTEXT-ORACLE",
    b"WUCI_PRIVATE evidence",
    b"DAYLIGHT_PRIVATE evidence",
)


class FirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = self.root / "repo"
        self.base.mkdir()
        (self.base / "artifact.bin").write_bytes(b"firewall test subject")
        self.capsule_path = self.base / "capsule.json"
        self.out = self.root / "public"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _publish(self, **capsule_kwargs) -> Path:
        capsule_kwargs.setdefault("subjects", ["artifact.bin"])
        capsule_kwargs.setdefault("base_dir", self.base)
        capsule_kwargs.setdefault("fixture", True)
        built = capsule_mod.build_capsule(**capsule_kwargs)
        atomic_write_bytes(self.capsule_path, json_bytes(built), force=True)
        public_artifact.build_public_artifact(
            self.capsule_path, self.out, base_dir=self.base, force=True
        )
        return self.out

    def _scan(self) -> dict:
        return firewall.scan_public_root(self.out)

    def assert_violation(self, report: dict, reason_fragment: str) -> None:
        self.assertFalse(report["ok"], report)
        self.assertTrue(
            any(reason_fragment in item["reason"] for item in report["violations"]), report
        )

    def test_clean_public_root_passes_and_writes_report_outside(self) -> None:
        self._publish()
        report = firewall.run_firewall(self.out)
        self.assertTrue(report["ok"], report)
        report_path = Path(report["report_path"])
        self.assertEqual(report_path.parent, self.out.parent)
        self.assertTrue(report_path.is_file())

    def test_report_not_written_on_failure(self) -> None:
        self._publish()
        firewall.run_firewall(self.out)
        (self.out / "unexpected.md").write_bytes(b"drive-by file")
        report = firewall.run_firewall(self.out)
        self.assertFalse(report["ok"])
        self.assertFalse(firewall.default_report_path(self.out).exists())

    def test_report_inside_root_refused(self) -> None:
        self._publish()
        with self.assertRaises(firewall.FirewallScanError):
            firewall.run_firewall(self.out, report_path=self.out / "report.json")

    def test_forbidden_private_filenames_rejected(self) -> None:
        self._publish()
        for name in FORBIDDEN_NAME_SAMPLES:
            planted = self.out / name
            planted.write_bytes(b"benign bytes")
            try:
                report = self._scan()
                self.assertFalse(report["ok"], name)
                self.assertTrue(
                    any(item["path"] == name for item in report["violations"]), (name, report)
                )
            finally:
                planted.unlink()

    def test_private_directories_rejected(self) -> None:
        self._publish()
        for directory in ("vault-work", "smoke-vault", "private", "vault"):
            planted = self.out / directory
            planted.mkdir()
            (planted / "data.json").write_bytes(b"{}")
            try:
                self.assert_violation(self._scan(), "forbidden_private_directory")
            finally:
                (planted / "data.json").unlink()
                planted.rmdir()

    def test_forbidden_content_markers_rejected(self) -> None:
        self._publish()
        for index, marker in enumerate(FORBIDDEN_MARKER_SAMPLES):
            planted = self.out / f"note-{index}.md"
            planted.write_bytes(marker)
            try:
                self.assert_violation(self._scan(), "known_private_material_marker")
            finally:
                planted.unlink()

    def test_key_shaped_content_rejected(self) -> None:
        self._publish()
        planted = self.out / "checksum-note.md"
        planted.write_bytes(b"a1" * 32 + b"\n")
        self.assert_violation(self._scan(), "raw_key_shaped_material")

    def test_plaintext_oracle_json_rejected(self) -> None:
        self._publish()
        planted = self.out / "index-note.json"
        planted.write_bytes(b'{"plaintext_bytes": 5, "sha256": "' + b"a" * 64 + b'"}')
        self.assert_violation(self._scan(), "plaintext_sha256_oracle")

    def test_symlink_in_public_artifact_rejected(self) -> None:
        self._publish()
        private = self.root / "outside.txt"
        private.write_bytes(b"outside data")
        try:
            (self.out / "linked.txt").symlink_to(private)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unsupported")
        self.assert_violation(self._scan(), "symlink_in_public_artifact")

    def test_hardlink_to_private_file_rejected(self) -> None:
        self._publish()
        private = self.root / "private-data.txt"
        private.write_bytes(b"hardlink source")
        try:
            os.link(private, self.out / "linked-data.txt")
        except OSError:
            self.skipTest("hardlinks unsupported")
        self.assert_violation(self._scan(), "hardlink_in_public_artifact")

    def test_extra_public_file_rejected(self) -> None:
        self._publish()
        (self.out / "extra-note.md").write_bytes(b"not in the manifest")
        self.assert_violation(self._scan(), "unexpected_public_file")

    def test_allowed_extra_file_passes_when_listed(self) -> None:
        self._publish(allowed_extra_files=["release-note.md"])
        extra = self.out / "release-note.md"
        data = b"reviewed extra file\n"
        extra.write_bytes(data)
        sums = self.out / capsule_mod.SUMS_FILENAME
        sums.write_text(
            sums.read_text(encoding="utf-8")
            + f"{hashlib.sha256(data).hexdigest()}  release-note.md\n",
            encoding="utf-8",
        )
        report = self._scan()
        self.assertTrue(report["ok"], report)

    def test_allowed_extra_still_scanned_for_private_material(self) -> None:
        self._publish(allowed_extra_files=["release-note.md"])
        extra = self.out / "release-note.md"
        data = b"BEGIN RSA PRIVATE KEY"
        extra.write_bytes(data)
        sums = self.out / capsule_mod.SUMS_FILENAME
        sums.write_text(
            sums.read_text(encoding="utf-8")
            + f"{hashlib.sha256(data).hexdigest()}  release-note.md\n",
            encoding="utf-8",
        )
        self.assert_violation(self._scan(), "known_private_material_marker")

    def test_missing_manifest_file_rejected(self) -> None:
        self._publish()
        (self.out / "artifact.bin").unlink()
        report = self._scan()
        self.assertFalse(report["ok"])

    def test_sha256sums_tamper_rejected(self) -> None:
        self._publish()
        sums = self.out / capsule_mod.SUMS_FILENAME
        text = sums.read_text(encoding="utf-8")
        flipped = ("a" if text[0] != "a" else "b") + text[1:]
        sums.write_text(flipped, encoding="utf-8")
        report = self._scan()
        self.assertFalse(report["ok"])

    def test_capsule_missing_rejected(self) -> None:
        self._publish()
        (self.out / capsule_mod.CAPSULE_FILENAME).unlink()
        self.assert_violation(self._scan(), "capsule_missing_from_public_root")

    def test_capsule_tamper_rejected(self) -> None:
        self._publish()
        capsule_file = self.out / capsule_mod.CAPSULE_FILENAME
        text = capsule_file.read_text(encoding="utf-8")
        capsule_file.write_text(
            text.replace('"fixture": true', '"fixture": false'), encoding="utf-8"
        )
        report = self._scan()
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()
