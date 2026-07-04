from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import zipfile

from tools import wuci_backup_evidence


class WuciBackupEvidenceTests(unittest.TestCase):
    def test_emit_backup_evidence_restores_tracked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "WUCI_LOGGING.md").write_text("logging evidence\n", encoding="utf-8")
            (root / "README.md").write_text("readme\n", encoding="utf-8")
            out = root / "build" / "wuci-backup" / "backup-evidence.json"
            archive = root / "build" / "wuci-backup" / "wuci-ji-tracked-source.zip"

            report = wuci_backup_evidence.emit_backup_evidence(
                root,
                out,
                archive,
                tracked_files=["README.md", "docs/WUCI_LOGGING.md"],
            )

            self.assertEqual(report["schema"], wuci_backup_evidence.SCHEMA)
            self.assertEqual(report["result"], "pass")
            self.assertEqual(report["files_total"], 2)
            self.assertTrue(report["restore"]["checked"])
            self.assertEqual(report["restore"]["files_verified"], 2)
            self.assertTrue(out.is_file())
            self.assertTrue(archive.is_file())
            with zipfile.ZipFile(archive, "r") as zf:
                self.assertEqual(sorted(zf.namelist()), ["README.md", "docs/WUCI_LOGGING.md"])

    def test_emit_backup_evidence_rejects_symlink_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "target.txt").write_text("target\n", encoding="utf-8")
            (root / "link.txt").symlink_to("target.txt")
            with self.assertRaises(wuci_backup_evidence.BackupEvidenceError):
                wuci_backup_evidence.emit_backup_evidence(
                    root,
                    root / "build" / "wuci-backup" / "backup-evidence.json",
                    root / "build" / "wuci-backup" / "wuci-ji-tracked-source.zip",
                    tracked_files=["link.txt"],
                )


if __name__ == "__main__":
    unittest.main()
