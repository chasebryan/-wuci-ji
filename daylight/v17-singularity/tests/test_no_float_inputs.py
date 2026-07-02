from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import registry, scorecard
from src.canonical_json import load_json_no_floats, reject_floats_recursive


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"


class NoFloatInputTests(unittest.TestCase):
    def test_json_input_with_float_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "float.json"
            path.write_text('{"x": 0.5}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json_no_floats(path)

    def test_nested_float_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested.json"
            path.write_text('{"x": {"y": [1, 0.5]}}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json_no_floats(path)

    def test_alpha_numeric_float_is_rejected(self) -> None:
        fields = copy.deepcopy(registry.load_fields_registry())
        fields["fields"][0]["alpha"] = 1.0
        with self.assertRaises(ValueError):
            registry.validate_fields_registry(fields)

    def test_threshold_numeric_float_is_rejected(self) -> None:
        fields = copy.deepcopy(registry.load_fields_registry())
        fields["fields"][0]["threshold"] = 0.9989
        with self.assertRaises(ValueError):
            registry.validate_fields_registry(fields)

    def test_scorecard_containing_float_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            reject_floats_recursive({"scorecard": {"score_AM_plus": 0.5}}, "scorecard")

    def test_state_file_float_is_rejected(self) -> None:
        state = scorecard.load_state(CURRENT_STATE)
        state["debt_uomega"] = 0.5
        with self.assertRaises(ValueError):
            scorecard.validate_state(state)


if __name__ == "__main__":
    unittest.main()
