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
    strict = policy["strict_mode"]
    assert strict["env"] == "WUCI_STRICT=1"
    assert strict["requires_trusted_verifier_sha256"] is True
    assert strict["rejects_unapproved_runner"] is True
    assert strict["rejects_fixture_publish_or_trust"] is True
    assert strict["rejects_hardlink_public_evidence"] is True
    assert strict["rejects_quantum_safe_claims"] is True
    assert strict["rejects_runtime_sandbox_claims"] is True
    assert strict["rejects_symlink_inputs"] is True
    assert strict["rejects_symlink_outputs"] is True
    assert strict["rejects_world_readable_keyfiles"] is True
    assert policy["assembly_enforced_actions_v1"] == ["open", "release"]
    assert policy["reserved_actions"] == ["trust", "publish"]

    safeio = policy["safeio"]
    assert safeio["new_outputs_must_be_exclusive"] is True
    assert safeio["python_writes_are_atomic_where_possible"] is True
    assert safeio["reject_devices"] is True
    assert safeio["reject_directories"] is True
    assert safeio["reject_fifos"] is True
    assert safeio["reject_sockets"] is True
    assert safeio["reject_symlinks"] is True
    assert safeio["require_regular_files"] is True

    ledger = policy["ledger"]
    assert ledger["append_only_claim_requires_verify_history"] is True
    assert ledger["detect_head_forks"] is True
    assert ledger["detect_missing_heads"] is True
    assert ledger["detect_rewritten_entries"] is True
    assert ledger["reject_unexpected_entry_files"] is True
    assert ledger["reject_unexpected_head_files"] is True

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
