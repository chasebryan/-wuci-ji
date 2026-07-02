import unittest

from src import canonical


class CanonicalJsonTests(unittest.TestCase):
    def test_duplicate_keys_reject(self):
        with self.assertRaises(ValueError):
            canonical.loads_json_no_floats('{"a":1,"a":2}')

    def test_floats_reject_on_load_and_dump(self):
        with self.assertRaises(ValueError):
            canonical.loads_json_no_floats('{"a":1.5}')
        with self.assertRaises(ValueError):
            canonical.dumps_canonical({"a": 1.5})

    def test_canonical_bytes_are_stable_and_newline_terminated(self):
        payload = {"b": [2, 1], "a": 1}
        self.assertEqual(canonical.dumps_canonical(payload), b'{"a":1,"b":[2,1]}\n')


if __name__ == "__main__":
    unittest.main()
