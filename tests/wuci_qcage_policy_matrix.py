#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "docs" / "wuci_qcage_policy.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-QCAGE policy matrix.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    assert POLICY.exists()
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy["schema"] == "wuci-qcage-policy-v1"
    assert policy["status"] == "quantum-aware-artifact-airlock-v1"

    modes = policy["modes"]
    assert set(modes) == {"compat", "hybrid-required", "pq-required"}
    assert modes["compat"]["allow_quantum_safe_claim"] is False
    assert modes["hybrid-required"]["require_pq_signature"] is True
    assert modes["pq-required"]["require_pq_signature"] is True

    digest_policy = policy["digest_policy"]
    assert digest_policy["require_digest_vector"] == ["sha256", "sha384", "sha512"]
    assert digest_policy["minimum_quantum_collision_digest"] == "sha384"
    assert digest_policy["preferred_public_evidence_digest"] == "sha512"

    inventory = policy["algorithm_inventory"]
    vulnerable = set(inventory["classical_vulnerable_public_key"])
    assert "secp256k1" in vulnerable
    assert "x25519" in vulnerable
    targets = set(inventory["post_quantum_signature_targets"])
    targets.update(inventory["post_quantum_kem_targets"])
    for name in ("ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS"):
        assert name in targets

    rejections = set(policy["downgrade_rejections"])
    for name in (
        "quantum_safe_true_without_pq_verification",
        "hybrid_required_without_pq_signature",
        "pq_required_with_classic_only_signature",
        "sha256_only_public_evidence",
        "pq_stub_marked_as_real",
        "external_pq_verifier_unpinned",
    ):
        assert name in rejections

    runtime = policy["runtime_claims"]
    assert runtime["runtime_sandbox_enforced_v1"] is False
    assert runtime["network_sandbox_enforced_v1"] is False
    assert runtime["quantum_safe_default_v1"] is False

    if not args.quiet:
        print("wuci qcage policy matrix: PASS")


if __name__ == "__main__":
    main()
