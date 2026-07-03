from __future__ import annotations

import unittest

from .helpers import domain_checks, report_for


def _walk(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)
    else:
        yield value


class NoFloatPrecisionTests(unittest.TestCase):
    def test_report_contains_no_float_values(self):
        report = report_for(domain_checks())
        self.assertFalse(any(isinstance(value, float) for value in _walk(report)))

    def test_final_score_is_string_with_one_decimal(self):
        report = report_for(domain_checks())
        self.assertRegex(report["score"], r"^(?:100\.0|[0-9]?\d\.[0-9])$")


if __name__ == "__main__":
    unittest.main()

