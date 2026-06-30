from __future__ import annotations

import json
import unittest
from pathlib import Path

from src import schema_check
from tests.helpers import PACKAGE_ROOT

SCHEMA_DIR = PACKAGE_ROOT / "schema"
EXAMPLES = PACKAGE_ROOT / "examples"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class SchemaValidationTests(unittest.TestCase):
    def _schema(self, name: str) -> dict:
        return schema_check.load_schema(SCHEMA_DIR / name)

    def test_obligation_registry_matches_schema(self) -> None:
        registry = _load(PACKAGE_ROOT / "rules" / "obligations.v15.json")
        self.assertEqual(schema_check.validate(registry, self._schema("obligations.v15.schema.json")), [])

    def test_scorecards_match_schema(self) -> None:
        schema = self._schema("scorecard.v15.schema.json")
        for name in ("expected-scorecard.v15-meridian.json", "expected-scorecard.perfect.v15-meridian.json"):
            self.assertEqual(schema_check.validate(_load(EXAMPLES / name), schema), [], name)

    def test_receipt_matches_schema(self) -> None:
        schema = self._schema("reproducibility-receipt.v15.schema.json")
        receipt = _load(EXAMPLES / "reproducibility-receipt.v15-meridian.json")
        self.assertEqual(schema_check.validate(receipt, schema), [])

    def test_frontier_report_matches_schema(self) -> None:
        schema = self._schema("frontier-report.v15.schema.json")
        report = _load(EXAMPLES / "frontier.v15-meridian.json")
        self.assertEqual(schema_check.validate(report, schema), [])

    def test_ledger_entries_match_schema(self) -> None:
        schema = self._schema("ledger-entry.v15.schema.json")
        for name in ("ledger.seed.jsonl", "ledger.perfect.jsonl"):
            for entry in _load_jsonl(EXAMPLES / name):
                self.assertEqual(schema_check.validate(entry, schema), [], f"{name}:{entry.get('entry_id')}")

    def test_corpus_entries_match_schema(self) -> None:
        schema = self._schema("corpus-entry.v15.schema.json")
        for entry in _load_jsonl(EXAMPLES / "corpus.seed.jsonl"):
            self.assertEqual(schema_check.validate(entry, schema), [], entry.get("corpus_entry_id"))

    def test_validator_rejects_bad_instance(self) -> None:
        schema = self._schema("scorecard.v15.schema.json")
        bad = _load(EXAMPLES / "expected-scorecard.v15-meridian.json")
        bad["final_score_M"] = "not-an-integer"
        self.assertNotEqual(schema_check.validate(bad, schema), [])


if __name__ == "__main__":
    unittest.main()
