from __future__ import annotations

import unittest

from src.canonical import CanonicalError, dumps, load_json


class CanonicalTests(unittest.TestCase):
    def test_canonical_sorting_is_stable(self) -> None:
        self.assertEqual(dumps({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_rejects_float(self) -> None:
        with self.assertRaises(CanonicalError):
            dumps({"score": 1.5})
        with self.assertRaises(CanonicalError):
            load_json('{"score": 1.5}')

    def test_rejects_duplicate_json_key(self) -> None:
        with self.assertRaises(CanonicalError):
            load_json('{"a": 1, "a": 2}')

    def test_rejects_non_finite_json_number(self) -> None:
        with self.assertRaises(CanonicalError):
            load_json('{"x": NaN}')


if __name__ == "__main__":
    unittest.main()
