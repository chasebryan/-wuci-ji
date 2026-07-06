#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED_TEXT = {
    "docs/ZP1_WUCIJI_COUPLING.md": [
        "RUNTIME_GATE_31_ZP1_WUCIJI_COUPLING_PROOF_LANE",
        "ZP-1 does not replace WJSEAL",
        "ZP-1 does not replace WUCI-GATE",
        "InsecureTestProvider is not cryptographic",
        "No production provider is enabled",
        "not production cryptography",
        "not post-quantum security",
        "not external validation",
        "not a WuciOS score increase",
    ],
    "third_party/zp1/PROVIDERS.md": [
        "currently ships no production cryptographic provider",
        "deterministic provider is not cryptographic",
        "TESTS ONLY",
    ],
    "third_party/zp1/README.md": [
        "experimental, unaudited, and not production-ready",
        "default crate does not include production PQC providers",
        "deterministic provider is tests-only and not cryptographic",
    ],
}


def fail(message: str) -> None:
    print(f"ZP1/WuciJi coupling check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: str) -> str:
    file_path = ROOT / path
    if not file_path.is_file():
        fail(f"missing required file: {path}")
    return file_path.read_text(encoding="utf-8")


def main() -> None:
    for path, needles in REQUIRED_TEXT.items():
        text = read(path)
        for needle in needles:
            if needle not in text:
                fail(f"{path} missing required text: {needle}")

    record_path = ROOT / "docs/ZP1_WUCIJI_COUPLING.v1.json"
    record = json.loads(read("docs/ZP1_WUCIJI_COUPLING.v1.json"))

    required_false = [
        "production_provider_enabled",
        "replaces_wjseal",
        "replaces_wuci_gate",
        "replaces_daylight",
        "changes_wucios_score",
    ]
    for key in required_false:
        if record.get(key) is not False:
            fail(f"{record_path} must set {key}=false")

    if record.get("provider_mode") != "test_utils_only":
        fail("provider_mode must be test_utils_only")

    actual_zp1_commit = subprocess.check_output(
        ["git", "-C", str(ROOT / "third_party/zp1"), "rev-parse", "HEAD"],
        text=True,
    ).strip()

    if record.get("zp1_pinned_commit") != actual_zp1_commit:
        fail("zp1_pinned_commit does not match third_party/zp1 HEAD")

    print("ZP1/WuciJi coupling check passed")


if __name__ == "__main__":
    main()
