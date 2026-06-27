#!/usr/bin/env python3
from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL = REPO_ROOT / "docs" / "wuci_wjstar_model.json"
MODEL_DOC = REPO_ROOT / "docs" / "wuci_wjstar_model.md"
SECURITY_BOUNDARY = REPO_ROOT / "docs" / "SECURITY_BOUNDARY.md"
BUILD_TARGETS = REPO_ROOT / "docs" / "BUILD_TARGETS.md"
MAKEFILE = REPO_ROOT / "Makefile"


def threshold_probability(x: Decimal) -> Decimal:
    return Decimal(3) * x * x - Decimal(2) * x * x * x


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
    assert model["composition"] == "WJ* = AEAD + FROST_(2/3) + H-Merkle + G + R"
    assert model["components"]["AEAD"]["role"] == "secrecy"
    assert model["components"]["FROST_2_of_3"]["role"] == "authority"
    assert model["components"]["FROST_2_of_3"]["n"] == 3
    assert model["components"]["FROST_2_of_3"]["t"] == 2
    assert model["components"]["H_Merkle"]["role"] == "evidence"
    assert model["components"]["G"]["role"] == "policy"
    assert model["components"]["R"]["role"] == "witness"

    open_predicate = model["open_predicate"]
    assert "AEAD.Dec_K(C; M || G) = A" in open_predicate
    assert "V_F(sigma_F, H(W), PK_F) = 1" in open_predicate
    assert "G(M) = 1" in open_predicate
    assert "MerkleVerify(H(W), R, path) = 1" in open_predicate

    p_auth = threshold_probability(Decimal("0.95"))
    p_break = threshold_probability(Decimal("0.01"))
    assert p_auth == Decimal(model["threshold_probability"]["p_auth_at_0_95"])
    assert p_break == Decimal(model["threshold_probability"]["p_break_at_0_01"])
    assert model["threshold_probability"]["selected_threshold"]["n"] == 3
    assert model["threshold_probability"]["selected_threshold"]["t"] == 2
    assert model["threshold_probability"]["one_of_one_break"] == "c"
    assert "3c^2" in model["threshold_probability"]["two_of_three_break_small_c"]

    for phrase in (
        "WJ* = AEAD + FROST_(2/3) + H-Merkle + G + R",
        "P_auth(p; 3, 2)",
        "P_break(c; 3, 2)",
        "(n, t) = (3, 2)",
        "fixture FROST material remains test-only",
    ):
        assert phrase in doc

    for non_claim in (
        "this model does not make fixture FROST production authority",
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
