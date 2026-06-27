#!/usr/bin/env python3
from __future__ import annotations

import argparse
from decimal import Decimal
import json
from math import comb
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL = REPO_ROOT / "docs" / "wuci_wjstar_model.json"
MODEL_DOC = REPO_ROOT / "docs" / "wuci_wjstar_model.md"
SECURITY_BOUNDARY = REPO_ROOT / "docs" / "SECURITY_BOUNDARY.md"
BUILD_TARGETS = REPO_ROOT / "docs" / "BUILD_TARGETS.md"
MAKEFILE = REPO_ROOT / "Makefile"


def threshold_probability(n: int, t: int, x: Decimal) -> Decimal:
    total = Decimal(0)
    for k in range(t, n + 1):
        total += Decimal(comb(n, k)) * (x**k) * ((Decimal(1) - x) ** (n - k))
    return total


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI WJ* formal composition model.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    doc = MODEL_DOC.read_text(encoding="utf-8")
    security_boundary = SECURITY_BOUNDARY.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert model["schema"] == "wuci-wjstar-model-v1"
    assert model["status"] == "formal-target-composition-not-production-claim"
    assert model["composition"] == "WJ* = GoldenLock_v1(AEAD + FROST_(3/5,4/5) + H-Merkle + G + R)"
    assert model["components"]["AEAD"]["role"] == "secrecy"
    assert model["components"]["FROST_Golden_Lock"]["role"] == "authority"
    assert model["components"]["FROST_Golden_Lock"]["normal_open_release"]["n"] == 5
    assert model["components"]["FROST_Golden_Lock"]["normal_open_release"]["t"] == 3
    assert model["components"]["FROST_Golden_Lock"]["ceremony_authority_audit"]["n"] == 5
    assert model["components"]["FROST_Golden_Lock"]["ceremony_authority_audit"]["t"] == 4
    assert model["components"]["H_Merkle"]["role"] == "evidence"
    assert model["components"]["G"]["role"] == "policy"
    assert model["components"]["R"]["role"] == "witness"
    assert model["components"]["PQ"]["role"] == "fail-closed post-quantum evidence"

    golden = model["golden_lock"]
    assert golden["schema"] == "wuci-golden-lock-v1"
    assert golden["digest_vector"] == ["SHA256", "SHA384", "SHA512"]
    assert golden["transcript"]["domain"] == "wuci/golden-lock/v1"
    assert golden["transcript"]["canonicalization"] == "C14N_G"
    assert golden["transcript"]["hash"] == 'm_G = H_DST("wuci/golden-lock/v1" || T_G)'
    for field in (
        "action = a",
        "artifact = Hvec(C)",
        "gate_contract = Hvec(Gamma)",
        "authority = Hvec(alpha)",
        "participants = P",
        "pq_mode = mu",
        "pressure = lambda",
    ):
        assert field in golden["transcript"]["fields"]
    assert golden["domain_quorum"]["name"] == "DomainQuorum_3/5(P,d)"
    assert golden["golden_rule"] == "No plaintext before Gate."
    thresholds = {entry["pressure"]: entry for entry in golden["dynamic_thresholds"]}
    assert thresholds[0]["n"] == 3 and thresholds[0]["t"] == 2
    assert thresholds[0]["pq_mode"] == "compat"
    assert thresholds[1]["n"] == 5 and thresholds[1]["t"] == 3
    assert thresholds[1]["pq_mode"] == "compat"
    assert thresholds[2]["n"] == 5 and thresholds[2]["t"] == 3
    assert thresholds[2]["pq_mode"] == "hybrid-evidence"
    assert thresholds[3]["n"] == 5 and thresholds[3]["t"] == 4
    assert thresholds[3]["pq_mode"] == "hybrid-evidence"

    accept_predicate = model["accept_predicate"]
    for required in (
        "a in {open, release}",
        "Parse_G(Omega_G)",
        "DomainQuorum_3/5(P,d)",
        "FROSTVerify_3/5(PK_F, m_G, sigma_F)",
        "GateOK(Gamma, a, M, alpha, m_G)",
        "RatchetOK(E, L, B, m_G)",
        "NoDowngrade(mu, lambda, T_G)",
        "PQModeOK_mu(epsilon_Q, m_G)",
        "ClaimOK_lambda(Omega_G)",
    ):
        assert required in accept_predicate

    open_predicate = model["open_predicate"]
    assert "GoldenLock_{lambda,mu}(a, Omega_G) = 1" in open_predicate
    assert "No plaintext before Gate" in open_predicate

    pq_modes = model["pq_modes"]
    assert pq_modes["compat"]["accepted"] is True
    assert pq_modes["hybrid-evidence"]["requires"] == [
        "MLDSA_Verify(PK_Q, m_G, sigma_Q)",
        "PinOK(verifier_Q)",
        "KAT_OK(verifier_Q)",
    ]
    assert pq_modes["pq-secure"]["accepted"] is False
    assert "false until signed production authority" in pq_modes["pq-secure"]["reason"]

    normal_auth = threshold_probability(5, 3, Decimal("0.95"))
    normal_break = threshold_probability(5, 3, Decimal("0.01"))
    ceremony_auth = threshold_probability(5, 4, Decimal("0.95"))
    ceremony_break = threshold_probability(5, 4, Decimal("0.01"))
    threshold = model["threshold_probability"]
    assert normal_auth == Decimal(threshold["normal_p_auth_at_0_95"])
    assert normal_break == Decimal(threshold["normal_p_break_at_0_01"])
    assert ceremony_auth == Decimal(threshold["ceremony_p_auth_at_0_95"])
    assert ceremony_break == Decimal(threshold["ceremony_p_break_at_0_01"])
    assert threshold["selected_thresholds"]["normal_open_release"]["n"] == 5
    assert threshold["selected_thresholds"]["normal_open_release"]["t"] == 3
    assert threshold["selected_thresholds"]["root_authority_audit_ceremony"]["n"] == 5
    assert threshold["selected_thresholds"]["root_authority_audit_ceremony"]["t"] == 4
    assert "10c^3" in threshold["normal_small_c_break"]
    assert "5c^4" in threshold["ceremony_small_c_break"]

    for phrase in (
        "WJ* = GoldenLock_v1(AEAD + FROST_(3/5,4/5) + H-Merkle + G + R)",
        "m_G = H_DST(\"wuci/golden-lock/v1\" || T_G)",
        "DomainQuorum_3/5(P,d)",
        "(n, t) = (5, 3)",
        "(n, t) = (5, 4)",
        "No plaintext before Gate.",
        "fixture FROST material remains test-only",
    ):
        assert phrase in doc

    for non_claim in (
        "this model does not make fixture FROST production authority",
        "this model does not implement production 5-party FROST authority",
        "this model does not claim post-quantum security",
        "this model does not claim runtime sandboxing",
        "this model does not replace independent cryptographic audit",
    ):
        assert non_claim in model["non_claims"]

    assert "WJ* composition boundary" in security_boundary
    assert "wjstar-model-test" in build_targets
    assert "wjstar-model-test:" in makefile

    if not args.quiet:
        print("wuci WJ* model: PASS")


if __name__ == "__main__":
    main()
