import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "daylight/npt/v1"))

from daylight_npt.registry import load_registry
from daylight_npt.report import dumps_stable, scan


class ReportTests(unittest.TestCase):
    def test_report_is_stable_and_relative(self):
        registry_path = ROOT / "daylight/npt/v1/number-claims.registry.json"
        registry = load_registry(registry_path)
        inputs = ["daylight/npt/v1/examples/positive/valid-digest.md"]
        one = dumps_stable(scan(registry, registry_path, inputs, ROOT))
        two = dumps_stable(scan(registry, registry_path, inputs, ROOT))
        self.assertEqual(one, two)
        self.assertNotIn(str(ROOT), one)

    def test_report_is_byte_stable_on_fixture_set(self):
        registry_path = ROOT / "daylight/npt/v1/number-claims.registry.json"
        registry = load_registry(registry_path)
        inputs = [
            "daylight/npt/v1/examples/negative/certification-implication.md",
            "daylight/npt/v1/examples/negative/percent-mismatch.md",
            "daylight/npt/v1/examples/positive/recomputed-percent.md",
        ]
        one = dumps_stable(scan(registry, registry_path, inputs, ROOT))
        two = dumps_stable(scan(registry, registry_path, inputs, ROOT))
        self.assertEqual(one.encode("utf-8"), two.encode("utf-8"))
        report = scan(registry, registry_path, inputs, ROOT)
        ordered = sorted(
            report["findings"],
            key=lambda item: (item["path"], item["line"], item["column"], item["code"], item["value_raw"]),
        )
        self.assertEqual(report["findings"], ordered)
        forbidden = [str(ROOT), "/home/", "PRIVATE KEY", "BEGIN OPENSSH", "token"]
        for marker in forbidden:
            self.assertNotIn(marker, one)


if __name__ == "__main__":
    unittest.main()
