#!/usr/bin/env python3
from __future__ import annotations

import runpy
from pathlib import Path


TEST = Path(__file__).resolve().with_name("wuci_witness_symlink_hardening.py")


if __name__ == "__main__":
    runpy.run_path(str(TEST), run_name="__main__")
