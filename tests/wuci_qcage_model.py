#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
QCAGE_TOOL = REPO_ROOT / "tools" / "wuci_qcage.py"
MODEL_DOC = REPO_ROOT / "docs" / "wuci_qcage_model.md"


def load_qcage_module():
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    spec = importlib.util.spec_from_file_location("wuci_qcage", QCAGE_TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-QCAGE model math.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    qcage = load_qcage_module()
    assert qcage.quantum_preimage_bits(256) == 128
    assert qcage.quantum_preimage_bits(384) == 192
    assert qcage.quantum_preimage_bits(512) == 256
    assert qcage.quantum_collision_bits(256) == 85
    assert qcage.quantum_collision_bits(384) == 128
    assert qcage.quantum_collision_bits(512) == 170
    assert qcage.quantum_migration_debt(3, 10, 10) == 3
    assert qcage.quantum_migration_debt(1, 2, 10) == 0

    text = MODEL_DOC.read_text(encoding="utf-8")
    assert "Accept_hybrid(A)" in text
    assert "AND" in text
    assert "Never implement hybrid acceptance as OR" in text
    assert "Verify_classic(...) OR Verify_pq(...)" in text

    if not args.quiet:
        print("wuci qcage model: PASS")


if __name__ == "__main__":
    main()
