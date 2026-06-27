#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daylight_m1 import run_vector_dir


def main():
    vectors_root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "vectors"
    results = []
    for manifest in sorted(vectors_root.rglob("manifest.json")):
        results.append(run_vector_dir(manifest.parent))
    failures = [r for r in results if not r["ok"]]
    print(json.dumps({"total": len(results), "passed": len(results) - len(failures), "failed": len(failures), "results": results}, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
