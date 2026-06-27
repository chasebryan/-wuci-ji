#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE = REPO_ROOT / "docs" / "wuci_high_attestation_profile.json"
HARDENING_POLICY = REPO_ROOT / "docs" / "wuci_hardening_policy.json"
QCAGE_POLICY = REPO_ROOT / "docs" / "wuci_qcage_policy.json"
PRODUCTION_READINESS = REPO_ROOT / "docs" / "PRODUCTION_READINESS.md"
MAKEFILE = REPO_ROOT / "Makefile"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI high-attestation profile.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    harden = json.loads(HARDENING_POLICY.read_text(encoding="utf-8"))
    qcage = json.loads(QCAGE_POLICY.read_text(encoding="utf-8"))
    makefile = MAKEFILE.read_text(encoding="utf-8")
    readiness = PRODUCTION_READINESS.read_text(encoding="utf-8")

    assert profile["schema"] == "wuci-high-attestation-profile-v1"
    assert profile["status"] == "defensive-high-attestation-baseline-v1"
    assert profile["adoption_license"] == "Apache-2.0"

    authorities = {entry["authority"] for entry in profile["government_baseline"]}
    assert {"NIST", "OMB", "NSA", "CISA"}.issubset(authorities)
    for entry in profile["government_baseline"]:
        assert entry["source_url"].startswith("https://"), entry

    non_claims = set(profile["explicit_non_claims"])
    for claim in (
        "runtime sandbox enforcement",
        "network sandbox enforcement outside the CARROT kernel proof lane",
        "post-quantum security from classical-only evidence",
        "production trust from fixture authority",
        "absence of exploitable vulnerabilities",
    ):
        assert claim in non_claims

    threats = set(profile["critical_threats"])
    for threat in (
        "fake verifier binary manufacturing proof outputs",
        "fixture authority relabeled as production trust",
        "public witness bundle containing private material",
        "ledger rewrite or fork accepted as append-only history",
        "cryptographic downgrade or quantum-safe overclaim",
        "known-exploited-vulnerability debt in build and verification dependencies",
    ):
        assert threat in threats

    controls = profile["required_local_controls"]
    strict = harden["strict_mode"]
    assert controls["offline_deterministic_proofs"] is True
    assert controls["stdlib_only_policy_tests"] is True
    assert controls["pinned_qemu_cpu_for_x25519"] == "Haswell-v4"
    assert controls["kernel_no_network_sandbox_proof"] is True
    assert controls["assembly_no_network_probe"] is True
    assert controls["seccomp_network_syscall_deny_filter"] is True
    assert controls["rust_sandbox_wrapper_source"] is True
    assert controls["rust_sandbox_wrapper_build_gate"] is True
    assert controls["rust_sandbox_wrapper_selftest"] is True
    assert controls["fixture_authority_test_only"] is True
    assert controls["reserved_actions_denied_by_default"] == harden["reserved_actions"]
    assert controls["unapproved_runner_rejected_in_strict_mode"] is strict["reject_unapproved_runner"]
    assert controls["ledger_history_verification_required"] is harden["ledger_policy"]["verify_history_required"]
    assert controls["unsigned_install_manifest_rejected"] is True
    assert controls["machine_readable_cli_outputs"] is True
    assert controls["wjstar_formal_composition_model"] is True
    assert controls["deterministic_parser_corpus_replay"] is True
    assert controls["release_bundle_verifier"] is True
    assert controls["real_pq_verifier_pins_fail_closed"] is True
    assert controls["real_pq_external_verifier_protocol"] == "wuci-pq-external-verify-v1"
    assert controls["local_fips204_ml_dsa_verifier_proof"] is True
    assert controls["signed_production_authority_ceremony_required"] is True
    assert controls["signed_external_audit_evidence_required"] is True
    assert controls["external_audit_signature_namespace"] == "wuci-external-audit-v1"
    assert controls["multi_core_proof_execution_supported"] is True

    digest = profile["digest_policy"]
    assert digest["sha256_required_for_existing_assembly_compatibility"] is True
    assert digest["sha384_sha512_required_for_long_lived_public_evidence"] is True
    assert digest["preferred_public_evidence_digest"] == "sha512"
    assert digest["minimum_quantum_collision_digest"] == "sha384"
    assert digest["preferred_public_evidence_digest"] == qcage["digest_policy"]["preferred_public_evidence_digest"]
    assert digest["minimum_quantum_collision_digest"] == qcage["digest_policy"]["minimum_quantum_collision_digest"]

    pq = profile["post_quantum_policy"]
    assert pq["quantum_safe_default"] is False
    assert pq["reject_pq_stub_marked_as_real"] is True
    assert pq["external_verifier_protocol"] == "wuci-pq-external-verify-v1"
    assert pq["local_fips204_ml_dsa_verifier"] == "tools/wuci-pq-fips204-verify"
    assert pq["local_fips204_ml_dsa_verifier_target"] == "make pq-verifier-fips204-proof"
    assert pq["require_pinned_real_pq_verifier_before_quantum_safe_claim"] is True
    assert set(pq["classical_vulnerable_public_key"]) <= set(
        qcage["algorithm_inventory"]["classical_vulnerable_public_key"]
    )
    assert set(pq["real_pq_targets"]) <= (
        set(qcage["algorithm_inventory"]["post_quantum_kem_targets"])
        | set(qcage["algorithm_inventory"]["post_quantum_signature_targets"])
    )

    required_targets = profile["required_make_targets"]
    assert "high-attestation-proof" in makefile
    for target in required_targets:
        assert f"{target}:" in makefile or f" {target}" in makefile, target
        assert target in makefile, target

    assert "WUCI-JI is not production-ready today." in readiness
    assert "production-readiness evidence candidate" in readiness
    assert "Apache-2.0" in readiness

    if not args.quiet:
        print("wuci high-attestation profile: PASS")


if __name__ == "__main__":
    main()
