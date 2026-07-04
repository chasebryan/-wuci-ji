from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from daylight_ssv.checks import build_checks
from daylight_ssv.collectors import collect_all
from tools import wuci_backup_evidence


def _check_by_id(checks, check_id):
    for check in checks:
        if check.id == check_id:
            return check
    raise AssertionError(f"missing check: {check_id}")


def _minimal_facts():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        facts = collect_all(root)
    return facts


class BackupLoggingEvidenceTests(unittest.TestCase):
    def test_backup_and_logging_evidence_are_credited_when_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs" / "WUCI_LOGGING.md").write_text("logging evidence\n", encoding="utf-8")
            wuci_backup_evidence.emit_backup_evidence(
                root,
                root / "build" / "wuci-backup" / "backup-evidence.json",
                root / "build" / "wuci-backup" / "wuci-ji-tracked-source.zip",
                tracked_files=["docs/WUCI_LOGGING.md"],
            )

            checks = build_checks(collect_all(root))

        self.assertEqual(_check_by_id(checks, "logging.logs_directory_presence").result, "pass")
        self.assertEqual(_check_by_id(checks, "backup.configuration_evidence").result, "pass")
        self.assertEqual(_check_by_id(checks, "backup.no_backup_evidence_unknown").result, "pass")

    def test_clean_marker_sweeps_are_strong_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            checks = build_checks(collect_all(root))

        for check_id in (
            "crypto.placeholder_crypto_wording_sweep",
            "config.debug_dev_mode_markers",
            "config.environment_file_exposure_markers",
            "supply.vendored_binary_warning",
        ):
            check = _check_by_id(checks, check_id)
            self.assertEqual(check.result, "pass")
            self.assertEqual(check.evidence_quality, "strong")

    def test_protected_rootless_sudoers_boundary_is_credited_without_content_claim(self):
        facts = _minimal_facts()
        facts["filesystem"]["paths"]["etc_sudoers"] = {
            "exists": True,
            "readable": False,
            "world_writable": False,
            "mode": "0o440",
        }
        facts["filesystem"]["sudoers_has_nopasswd"] = None

        check = _check_by_id(build_checks(facts), "identity.sudoers_nopasswd_marker")

        self.assertEqual(check.result, "pass")
        self.assertEqual(check.evidence_quality, "strong")
        self.assertIn("protected", check.evidence[0].value_summary)

    def test_bounded_suid_sgid_inventory_is_count_evidence(self):
        facts = _minimal_facts()
        facts["filesystem"]["suid_sgid_summary"] = {
            "dirs_checked": 2,
            "entries_checked": 10,
            "suid_count": 1,
            "sgid_count": 2,
            "errors": 0,
        }

        check = _check_by_id(build_checks(facts), "runtime.suid_sgid_inventory")

        self.assertEqual(check.result, "pass")
        self.assertEqual(check.evidence_quality, "strong")
        self.assertIn("suid_count=1", check.evidence[0].value_summary)


if __name__ == "__main__":
    unittest.main()
