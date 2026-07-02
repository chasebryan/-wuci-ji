from __future__ import annotations

import unittest

from src.canonical_json import (
    canonical_sha256,
    dumps_canonical,
    json_bytes,
    loads_json_no_floats,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_canonical_output_is_byte_stable(self) -> None:
        payload = {"b": [1, 2, {"z": "x", "a": True}], "a": None}
        first = dumps_canonical(payload)
        second = dumps_canonical({"a": None, "b": [1, 2, {"a": True, "z": "x"}]})
        self.assertEqual(first, second)
        self.assertEqual(first, b'{"a":null,"b":[1,2,{"a":true,"z":"x"}]}')

    def test_json_bytes_is_byte_stable(self) -> None:
        payload = {"k": 1, "a": ["x"]}
        self.assertEqual(json_bytes(payload), json_bytes({"a": ["x"], "k": 1}))

    def test_domain_separation_changes_digest(self) -> None:
        payload = {"a": 1}
        self.assertNotEqual(
            canonical_sha256(payload, "DOMAIN-ONE:"), canonical_sha256(payload, "DOMAIN-TWO:")
        )

    def test_floats_rejected_in_dumps(self) -> None:
        with self.assertRaises(ValueError):
            dumps_canonical({"score": 1.5})

    def test_floats_rejected_in_loads(self) -> None:
        with self.assertRaises(ValueError):
            loads_json_no_floats('{"score": 1.5}')

    def test_duplicate_keys_rejected(self) -> None:
        with self.assertRaises(ValueError):
            loads_json_no_floats('{"a": 1, "a": 2}')


if __name__ == "__main__":
    unittest.main()
