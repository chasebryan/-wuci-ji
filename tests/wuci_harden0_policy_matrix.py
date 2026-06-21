#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "docs" / "wuci_harden0_policy.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-HARDEN-0 policy.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy["schema"] == "wuci-harden0-policy-v1"
    assert policy["status"] == "proof-chain-perimeter-hardening"
    assert policy["strict_mode"]["requires_trusted_verifier_sha256"] is True
    assert policy["strict_mode"]["rejects_unapproved_runner"] is True
    assert policy["assembly_enforced_actions_v1"] == ["open", "release"]
    assert policy["reserved_actions"] == ["trust", "publish"]
    fixture = policy["fixture_authority"]
    assert fixture["suite"] == "FROST-secp256k1-SHA256-v1"
    assert fixture["mode"] == "deterministic-2of2-fixture"
    assert fixture["trust_level"] == "test-only"
    assert fixture["production_allowed"] is False
    assert fixture["publish_allowed"] is False
    assert fixture["trust_allowed"] is False

    if not args.quiet:
        print("wuci harden0 policy matrix: PASS")


if __name__ == "__main__":
    main()
