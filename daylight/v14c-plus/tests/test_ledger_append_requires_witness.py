from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
