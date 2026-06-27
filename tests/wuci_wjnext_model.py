#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL = REPO_ROOT / "docs" / "wuci_wjnext_model.json"
MODEL_DOC = REPO_ROOT / "docs" / "wuci_wjnext_model.md"
BUILD_TARGETS = REPO_ROOT / "docs" / "BUILD_TARGETS.md"
MAKEFILE = REPO_ROOT / "Makefile"


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI WJ-next transcript model.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    doc = MODEL_DOC.read_text(encoding="utf-8")
    build_targets = BUILD_TARGETS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert model["schema"] == "wuci-wjnext-model-v1"
    assert model["status"] == "canonical-transcript-target-not-production-claim"
    assert model["composition"] == "WJ_next = Accept_v2_mu(a, Omega)"
    assert model["actions"] == ["open", "release"]
    assert model["digest_vector"] == ["SHA256", "SHA384", "SHA512"]
    assert model["transcript"]["domain"] == "wuci/transcript/v2"
    assert model["transcript"]["canonicalization"] == "C14N_v2"
    assert model["transcript"]["hash"] == 'm_v2 = H("wuci/transcript/v2" || T_v2)'

    fields = model["transcript"]["fields"]
    for field in (
        "a",
        "Hvec(C)",
        "Hvec(M)",
        "Hvec(Gamma)",
        "Hvec(alpha)",
        "Hvec(B)",
        "head(L)",
        "Hvec(rho)",
        "Hvec(iota)",
        "mu",
    ):
        assert field in fields

    predicate = model["accept_predicate"]
    for required in (
        "a in {open, release}",
        "Parse_v2(Omega)",
        "EnvOK(C, M)",
        "RootOK(alpha, a, PK_F)",
        "FROSTVerify_2_of_3(PK_F, m_v2, sigma_F)",
        "GateOK(Gamma, a, M, alpha, m_v2)",
        "WitnessOK(B, M, Gamma, alpha, m_v2)",
        "PrivateMaterial(B) = 0",
        "LedgerOK(L, Hvec(B))",
        "ProvenanceOK(rho, Hvec(C))",
        "InstallOK(iota, Hvec(C))",
        "PQModeOK_mu(epsilon_Q, m_v2)",
    ):
        assert required in predicate

    pq_modes = model["pq_modes"]
    assert pq_modes["compat"]["accepted"] is True
    assert pq_modes["hybrid-evidence"]["accepted"] is True
    assert pq_modes["hybrid-evidence"]["requires"] == ["MLDSA_Verify", "PinOK", "KAT_OK"]
    assert pq_modes["pq-secure"]["accepted"] is False
    assert pq_modes["pq-secure"]["reason"] == "false until earned"

    assert (
        model["typed_verifier_predicate"]
        == "canonical transcript -> one authorization hash -> typed verifier predicate"
    )
    for phrase in (
        "WJ_next = Accept_v2_mu(a, Omega)",
        'm_v2 = H("wuci/transcript/v2" || T_v2)',
        "mu = pq-secure       -> 0 until earned",
        "canonical transcript -> one authorization hash -> typed verifier predicate",
    ):
        assert phrase in doc
    for non_claim in (
        "compat mode does not claim post-quantum security",
        "pq-secure mode is false until independently earned",
        "this model does not claim runtime sandboxing",
    ):
        assert non_claim in model["non_claims"]

    assert "wjnext-model-test" in build_targets
    assert "wjnext-model-test:" in makefile

    if not args.quiet:
        print("wuci WJ-next model: PASS")


if __name__ == "__main__":
    main()
