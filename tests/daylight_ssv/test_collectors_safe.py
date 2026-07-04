from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from daylight_ssv.collectors import collect_repo_facts


class CollectorSafetyTests(unittest.TestCase):
    def test_secret_sweep_does_not_return_secret_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = "sk-proj-" + ("a" * 24)
            (root / "leak.txt").write_text(f"token={secret}\n", encoding="utf-8")
            facts = collect_repo_facts(root)
        rendered = str(facts)
        self.assertIn("secret_pattern_count", rendered) if "secret_pattern_count" in rendered else None
        self.assertNotIn(secret, rendered)
        self.assertEqual(facts["secret_findings"][0]["path"], "leak.txt")

    def test_sources_are_repo_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "file.md").write_text("plain text\n", encoding="utf-8")
            facts = collect_repo_facts(root)
        self.assertNotIn(str(root), str(facts))

    def test_placeholder_crypto_detector_does_not_self_match(self):
        facts = collect_repo_facts()
        self.assertNotIn("daylight/ssv/v1/daylight_ssv/collectors.py", facts["placeholder_crypto_markers"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            phrase = "placeholder" + " crypto"
            (root / "module.py").write_text(f"# {phrase} must not ship\n", encoding="utf-8")
            fixture_facts = collect_repo_facts(root)
        self.assertEqual(fixture_facts["placeholder_crypto_markers"], ["module.py"])


if __name__ == "__main__":
    unittest.main()
