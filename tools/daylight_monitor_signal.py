#!/usr/bin/env python3
"""Focused wrapper for Daylight monitor-signal state updates."""

from daylight_conformance import main


if __name__ == "__main__":
    raise SystemExit(main(["monitor-signal", *(__import__("sys").argv[1:])]))
