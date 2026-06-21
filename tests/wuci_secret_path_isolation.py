#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FROST = REPO_ROOT / "src" / "frost.s"
POINTS = REPO_ROOT / "src" / "secp256k1_point.s"

SECRET_PATH_LABELS = (
    "run_frost_secp256k1_nonce_generate",
    "run_frost_secp256k1_commit",
    "run_frost_secp256k1_signing_share",
    "run_frost_secp256k1_aggregate",
)

VARIABLE_TIME_SYMBOLS = (
    "secp256k1_public_point_mul_limbs",
    "secp256k1_point_mul_limbs",
)


def function_body(source: str, label: str) -> str:
    lines = source.splitlines(keepends=True)
    start_line = None
    for index, line in enumerate(lines):
        if line == f"{label}:\n":
            start_line = index
            break
    if start_line is None:
        raise AssertionError(f"missing label: {label}")

    end_line = len(lines)
    for index in range(start_line + 1, len(lines)):
        line = lines[index]
        if line.startswith("run_") and line.rstrip().endswith(":"):
            end_line = index
            break
    return "".join(lines[start_line:end_line])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    frost_source = FROST.read_text(encoding="ascii")
    point_source = POINTS.read_text(encoding="ascii")

    assert "secp256k1-basepoint-mul-variable-time-public-only" in (
        REPO_ROOT / "src" / "main.s"
    ).read_text(encoding="ascii")
    assert "secp256k1-basepoint-mul\"" not in (REPO_ROOT / "src" / "main.s").read_text(
        encoding="ascii"
    )
    assert "test dl, 1" in point_source

    offenders: list[str] = []
    for label in SECRET_PATH_LABELS:
        body = function_body(frost_source, label)
        for symbol in VARIABLE_TIME_SYMBOLS:
            if f"call {symbol}" in body or f"jmp {symbol}" in body:
                offenders.append(f"{label} calls {symbol}")

    if offenders:
        raise AssertionError("variable-time secret path use: " + "; ".join(offenders))

    if not args.quiet:
        print("wuci secret path isolation: PASS")


if __name__ == "__main__":
    main()
