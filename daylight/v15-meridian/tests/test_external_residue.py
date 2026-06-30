from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import daylight_harness, ledger, obligations
from tests import helpers


class ExternalResidueTests(unittest.TestCase):
    """The 1,000,000M frontier is honest: reachable only with external attestations,
    and never self-issuable by the harness."""

    def setUp(self) -> None:
        self.registry = obligations.load_registry(helpers.OBLIGATIONS)

    def test_internal_evidence_cannot_reach_perfect_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = helpers.write_seed_inputs(Path(tmp))
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path, corpus_path=corpus_path, command="test"
            )
        self.assertEqual(scorecard["final_score_M"], 998900)
        self.assertEqual(scorecard["residue_to_perfect_M"], 1100)
        self.assertLess(scorecard["final_score_M"], scorecard["perfect_score_M"])
        open_scopes = {row["scope"] for row in scorecard["open_obligations"]}
        self.assertEqual(open_scopes, {"external"})
        self.assertEqual(len(scorecard["open_obligations"]), 9)

    def test_external_attestations_unlock_exactly_one_million(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_path, corpus_path = helpers.write_perfect_inputs(Path(tmp))
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path, corpus_path=corpus_path, command="test"
            )
            self.assertEqual(scorecard["final_score_M"], 1000000)
            self.assertEqual(scorecard["residue_to_perfect_M"], 0)
            self.assertEqual(scorecard["open_obligations"], [])
            daylight_harness.verify_scorecard(
                scorecard, ledger_path=ledger_path, corpus_path=corpus_path
            )

    def test_self_signed_external_attestation_is_refused(self) -> None:
        entries = helpers.seed_ledger_entries()
        entries, _ = ledger.append_entry(
            entries,
            entry_type="external_attestation",
            artifact_digest=helpers.artifact("self-signed"),
            witness=helpers.witness("external_attestation"),
            transcript_digest=helpers.transcript("self-signed"),
            closes_obligations=["o.q11.external_falsification_program"],
            external_signer_id=self.registry["harness_identity"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path = root / "self-signed.jsonl"
            corpus_path = root / "corpus.seed.jsonl"
            ledger.write_jsonl(ledger_path, entries)
            helpers.write_corpus(corpus_path, helpers.seed_corpus_entries())
            with self.assertRaises(obligations.ObligationError):
                daylight_harness.generate_scorecard(
                    ledger_path=ledger_path, corpus_path=corpus_path, command="test"
                )

    def test_unsigned_external_attestation_does_not_close_obligation(self) -> None:
        # An external_attestation with an empty signer names no external obligation,
        # so it is allowed onto the ledger but closes nothing.
        entries = helpers.seed_ledger_entries()
        entries, _ = ledger.append_entry(
            entries,
            entry_type="external_attestation",
            artifact_digest=helpers.artifact("unsigned-noop"),
            witness=helpers.witness("external_attestation"),
            transcript_digest=helpers.transcript("unsigned-noop"),
            closes_obligations=[],
            external_signer_id="",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ledger_path = root / "unsigned.jsonl"
            corpus_path = root / "corpus.seed.jsonl"
            ledger.write_jsonl(ledger_path, entries)
            helpers.write_corpus(corpus_path, helpers.seed_corpus_entries())
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=ledger_path, corpus_path=corpus_path, command="test"
            )
        self.assertEqual(scorecard["final_score_M"], 998900)


if __name__ == "__main__":
    unittest.main()
