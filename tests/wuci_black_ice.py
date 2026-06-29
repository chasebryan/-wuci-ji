#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import wuci_noxframe

REPO = Path(__file__).resolve().parents[1]
BLACK_ICE = REPO / "tools" / "wuci-black-ice"


def main() -> None:
    wuci_noxframe.assert_launcher(BLACK_ICE)


if __name__ == "__main__":
    main()
