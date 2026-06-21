#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = REPO_ROOT / "docs" / "wuci_threat_model.json"
HARDENING_POLICY = REPO_ROOT / "docs" / "wuci_hardening_policy.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-HARDEN policy documents.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    threat = json.loads(THREAT_MODEL.read_text(encoding="utf-8"))
    policy = json.loads(HARDENING_POLICY.read_text(encoding="utf-8"))

    assert threat["schema"] == "wuci-threat-model-v1"
    assert threat["status"] == "defensive-hardening-baseline"
    assert "fixture authority treated as production trust" in threat["must_prevent"]
    assert "fake verifier binary manufacturing proof outputs" in threat["must_prevent"]

    assert policy["schema"] == "wuci-hardening-policy-v1"
    assert policy["status"] == "proof-chain-hardening-v1"
    strict = policy["strict_mode"]
    assert strict["env"] == "WUCI_STRICT=1"
    assert strict["reject_unpinned_verifier"] is True
    assert strict["reject_unapproved_runner"] is True
    assert strict["reject_fixture_authority_for_publish_or_trust"] is True
    assert strict["reject_reserved_actions_by_default"] is True
    assert strict["reject_symlink_public_files"] is True
    assert strict["reject_hardlink_public_files"] is True
    assert strict["reject_runtime_sandbox_claims"] is True

    assert policy["reserved_actions"] == ["trust", "publish"]
    assert policy["assembly_enforced_actions_v1"] == ["open", "release"]
    assert policy["fixture_policy"]["fixture_authority_trust_level"] == "test-only"
    assert policy["fixture_policy"]["fixture_receipts_allowed_for_production"] is False
    assert policy["digest_policy"]["sha384_sha512_required_for_long_lived_public_evidence"] is True
    assert policy["digest_policy"]["quantum_safe_default"] is False

    if not args.quiet:
        print("wuci hardening policy matrix: PASS")


if __name__ == "__main__":
    main()
