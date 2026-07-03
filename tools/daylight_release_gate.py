#!/usr/bin/env python3
"""Focused wrapper for Daylight release-gate decisions."""

from daylight_conformance import main


if __name__ == "__main__":
    raise SystemExit(main(["gate", *(__import__("sys").argv[1:])]))
