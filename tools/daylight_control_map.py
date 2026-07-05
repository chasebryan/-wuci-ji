#!/usr/bin/env python3
"""Focused wrapper for Daylight control-map export."""

from daylight_conformance import main


if __name__ == "__main__":
    raise SystemExit(main(["control-map", *(__import__("sys").argv[1:])]))
