from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from src import proof_atoms, registry, scorecard
from src.canonical_json import load_json_no_floats, reject_python_floats


class NoFloatInputTests(unittest.TestCase):
    def test_json_input_containing_float_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "float.json"
            path.write_text('{"x": 0.5}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json_no_floats(path)

    def test_nested_json_float_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "float.json"
            path.write_text('{"x": {"y": [1, 0.5]}}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_json_no_floats(path)

    def test_scorecard_with_python_float_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            reject_python_floats({"score": {"bad": 0.5}}, "scorecard")

    def test_proof_evidence_float_is_rejected_during_atom_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text('{"version":"daylight-v17.1-event-horizon-proof-evidence-v0.1","records":[{"atom_id":"x","bad":0.5}]}\n', encoding="utf-8")
            atoms = copy.deepcopy(proof_atoms.load_proof_atom_registry())
            atoms["proof_atoms"][0]["evidence_path"] = str(path)
            with self.assertRaises(ValueError):
                proof_atoms.verify_proof_atoms(atoms)

    def test_field_alpha_must_be_rational_string(self) -> None:
        fields = copy.deepcopy(registry.load_fields_registry())
        fields["fields"][0]["alpha"] = 1
        with self.assertRaises(registry.RegistryError):
            registry.validate_fields_registry(fields)


if __name__ == "__main__":
    unittest.main()
