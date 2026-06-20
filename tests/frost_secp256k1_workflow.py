#!/usr/bin/env python3
from __future__ import annotations

import argparse

import test_wuci_ji as wuci_tests


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the deterministic FROST(secp256k1,SHA-256) CLI workflow."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress signature field output",
    )
    args = parser.parse_args()

    signature = wuci_tests.assert_frost_end_to_end_cli_flow()
    if args.quiet:
        return

    for name in (
        "group_public_key",
        "group_commitment",
        "signature_commitment",
        "signature_scalar",
        "challenge",
    ):
        print(f"{name}: {signature[name]}")
    print("workflow: valid")


if __name__ == "__main__":
    main()
