from __future__ import annotations

import os
import tempfile
from pathlib import Path
import unittest

from src import ledger
from tests.helpers import artifact, transcript, witness


class LedgerAppendTests(unittest.TestCase):
    def test_append_without_witness_is_rejected(self) -> None:
        with self.assertRaises(ledger.LedgerError):
            ledger.append_entry(
                [],
                entry_type="test",
                artifact_digest=artifact("no-witness"),
                witness=None,
                transcript_digest=transcript("no-witness"),
            )

    def test_append_without_transcript_is_rejected(self) -> None:
        with self.assertRaises(ledger.LedgerError):
            ledger.append_entry(
                [],
                entry_type="test",
                artifact_digest=artifact("no-transcript"),
                witness=witness("no-transcript"),
                transcript_digest=None,
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_write_jsonl_rejects_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.jsonl"
            target.write_text("existing\n", encoding="utf-8")
            link = root / "ledger.jsonl"
            link.symlink_to(target)
            with self.assertRaises(ledger.LedgerError):
                ledger.write_jsonl(link, [])
            self.assertEqual(target.read_text(encoding="utf-8"), "existing\n")


if __name__ == "__main__":
    unittest.main()
