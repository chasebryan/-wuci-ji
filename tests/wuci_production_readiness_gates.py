#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROD_AUTHORITY = REPO_ROOT / "docs" / "wuci_production_authority_policy.json"
CRYPTO_AUDIT = REPO_ROOT / "docs" / "wuci_crypto_audit_policy.json"
PQ_CONTRACT = REPO_ROOT / "docs" / "wuci_pq_verifier_contract.json"
READINESS = REPO_ROOT / "docs" / "PRODUCTION_READINESS.md"
FIXTURE_ROOT = REPO_ROOT / "authority" / "wuci-root.fixture.txt"
PROD_AUTHORITY_TOOL = REPO_ROOT / "tools" / "wuci_production_authority.py"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI production-readiness gates.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    authority = load(PROD_AUTHORITY)
    audit = load(CRYPTO_AUDIT)
    pq = load(PQ_CONTRACT)
    readiness = READINESS.read_text(encoding="utf-8")
    fixture = FIXTURE_ROOT.read_text(encoding="ascii")

    assert authority["schema"] == "wuci-production-authority-policy-v1"
    assert authority["fixture_authority_allowed_for_production"] is False
    required = authority["required_for_production"]
    assert required["production"] is True
    assert required["fixture_path_rejected"] is True
    assert required["known_fixture_or_demo_group_key_rejected"] is True
    assert required["key_ceremony_document_required"] is True
    assert required["key_ceremony_signature_required"] is True
    assert required["key_ceremony_signature_namespace"] == "wuci-production-authority-v1"
    assert required["ceremony_threshold_minimum"] == 4
    assert required["ceremony_signer_count_minimum"] == 5
    assert required["publish_or_trust_requires_assembly_gate"] is True
    assert required["required_publish_trust_assembly_commands"] == [
        "publish-authorized-rooted",
        "trust-authorized-rooted",
    ]
    assert authority["golden_lock"]["schema"] == "wuci-golden-lock-v1"
    assert authority["golden_lock"]["normal_open_release_threshold"] == {"n": 5, "t": 3}
    assert authority["golden_lock"]["root_authority_audit_ceremony_threshold"] == {"n": 5, "t": 4}
    assert "production: false" in fixture
    fixture_check = subprocess.run(
        [
            sys.executable,
            str(PROD_AUTHORITY_TOOL),
            "verify",
            "--authority",
            str(FIXTURE_ROOT),
            "--quiet",
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert fixture_check.returncode != 0
    assert b"not production authority" in fixture_check.stderr

    assert audit["schema"] == "wuci-crypto-audit-policy-v1"
    assert audit["self_audit_allowed_as_evidence"] is True
    assert audit["self_audit_sufficient_for_production_ready"] is False
    assert audit["required_external_audit_evidence"]["schema"] == "wuci-external-audit-evidence-v1"
    assert audit["required_external_audit_evidence"]["verification_schema"] == "wuci-external-audit-verification-v1"
    assert audit["required_external_audit_evidence"]["report_digest_sha256"] is True
    assert audit["required_external_audit_evidence"]["report_digest_sha384"] is True
    assert audit["required_external_audit_evidence"]["report_digest_sha512"] is True
    assert audit["required_external_audit_evidence"]["signature_required"] is True
    assert audit["required_external_audit_evidence"]["signature_namespace"] == "wuci-external-audit-v1"
    assert audit["required_external_audit_evidence"]["required_finding_disposition"] == "all-production-blocking-findings-closed"
    for scope in ("crypto", "pq-verifier", "production-authority", "release-bundle", "runtime-sandbox"):
        assert scope in audit["required_external_audit_evidence"]["required_verification_scope"]
    assert "passing KATs is not an independent audit" in audit["non_claims"]
    assert "unsigned external-audit evidence is test-only" in audit["non_claims"]

    assert pq["schema"] == "wuci-pq-verifier-contract-v1"
    assert "ML-DSA" in pq["accepted_signature_algorithms"]
    assert "SLH-DSA" in pq["accepted_signature_algorithms"]
    assert pq["required_verifier_evidence"]["binary_sha256"] is True
    assert pq["required_verifier_evidence"]["schema"] == "wuci-real-pq-verifier-evidence-v2"
    assert pq["required_verifier_evidence"]["verifier_protocol"] == "wuci-pq-external-verify-v1"
    assert pq["required_verifier_evidence"]["known_answer_test"] is True
    assert pq["required_verifier_evidence"]["kat_public_key_sha256"] is True
    assert pq["required_verifier_evidence"]["kat_message_sha256"] is True
    assert pq["required_verifier_evidence"]["kat_signature_sha256"] is True
    assert pq["required_verifier_evidence"]["no_stub_mode"] is True
    assert pq["required_verifier_evidence"]["network_required"] is False
    assert "pq_stub_marked_as_real" in pq["rejections"]

    for blocker in (
        "Fixture authority is still test-only",
        "Custom assembly crypto has not been independently audited",
        "`publish-authorized-rooted`",
        "`trust-authorized-rooted`",
        "General runtime sandboxing, independent wrapper/seccomp review",
        "If claiming quantum safety, a real pinned PQ verifier lane",
        "Internal crypto self-audit evidence",
    ):
        assert blocker in readiness

    if not args.quiet:
        print("wuci production-readiness gates: PASS")


if __name__ == "__main__":
    main()
