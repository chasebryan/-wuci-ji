#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
MODEL = REPO / "daylight-equation" / "research" / "daylight-v06-m4-symbolic-model.v1.json"
PROOF = REPO / "daylight-equation" / "research" / "daylight-v06-m4-z3-proof.v1.json"
PROOF_DOC = REPO / "daylight-equation" / "research" / "daylight-v06-m4-z3-proof.md"
SMT2 = REPO / "daylight-equation" / "research" / "daylight-v06-m4-z3-proof.smt2"
SCORECARD = REPO / "daylight-equation" / "SCORECARD.md"
SCORECARD_JSON = REPO / "daylight-equation" / "SCORECARD.v1.json"
MAKEFILE = REPO / "Makefile"


def smt_symbol(name: str) -> str:
    if "." in name:
        return f"|{name}|"
    return name


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight v0.6 M4 Z3 proof evidence.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    model = json.loads(MODEL.read_text(encoding="utf-8"))
    proof = json.loads(PROOF.read_text(encoding="utf-8"))
    doc = PROOF_DOC.read_text(encoding="utf-8")
    smt2 = SMT2.read_text(encoding="utf-8")
    scorecard = SCORECARD.read_text(encoding="utf-8")
    machine = json.loads(SCORECARD_JSON.read_text(encoding="utf-8"))
    makefile = MAKEFILE.read_text(encoding="utf-8")

    assert proof["schema"] == "daylight-v06-m4-z3-proof-v1"
    assert proof["subject"] == "Daylight_v0.6"
    assert proof["status"] == "smt-backed-m4-predicate-proof-not-external-review"
    assert proof["model"] == "daylight-equation/research/daylight-v06-m4-symbolic-model.v1.json"
    assert proof["smt2"] == "daylight-equation/research/daylight-v06-m4-z3-proof.smt2"
    assert proof["solver"]["name"] == "z3"
    assert proof["solver"]["interface"] == "SMT-LIB2"
    assert proof["solver"]["logic"] == "QF_UF"
    assert proof["solver"]["expected_check_sat_result"] == "unsat"
    assert proof["solver"]["expected_unsat_checks"] == 38

    assert model["checked_properties"]["truth_table_states"] == 1048576
    for predicate in model["public_precheck_predicates"] + model["private_open_predicates"]:
        assert f"(declare-fun {smt_symbol(predicate)} () Bool)" in smt2
    for assumption in model["security_assumptions"]["confidentiality"]:
        assert f"(declare-fun {assumption} () Bool)" in smt2

    assert smt2.count("(check-sat)") == proof["solver"]["expected_unsat_checks"]
    assert "(define-fun OpenSuccess () Bool" in smt2
    assert "(define-fun PrivateOpsAllowed () Bool" in smt2
    assert "(define-fun ConfidentialReleaseAllowed () Bool" in smt2

    z3 = shutil.which("z3")
    assert z3 is not None, "z3 must be available on PATH for the M4 proof gate"
    proc = subprocess.run(
        [z3, "-smt2", str(SMT2)],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.strip() == ""
    results = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert results == ["unsat"] * proof["solver"]["expected_unsat_checks"]

    assert proof["proved_properties"] == {
        "open_iff_all_public_and_private_predicates": True,
        "public_precheck_blocks_private_operations": True,
        "open_requires_private_operations_allowed": True,
        "single_failure_fail_closed": True,
        "authorization_predicates_required": True,
        "downgrade_predicates_required": True,
        "confidentiality_assumptions_required_for_confidential_release": True,
    }

    for non_claim in proof["non_claims"]:
        assert non_claim in doc
    doc_flat = " ".join(doc.split())
    for phrase in (
        "38 unsatisfiable negated obligations",
        "`Open` succeeds if and only if all public and private predicates hold",
        "confidential release is conditional on all modeled confidentiality assumptions",
    ):
        assert phrase in doc_flat

    evidence = set(machine["evidence"])
    for required in (
        "daylight-equation/research/daylight-v06-m4-z3-proof.md",
        "daylight-equation/research/daylight-v06-m4-z3-proof.v1.json",
        "daylight-equation/research/daylight-v06-m4-z3-proof.smt2",
        "tests/daylight_v06_m4_z3_proof.py",
    ):
        assert required in evidence
        assert Path(required).name in scorecard
    hard_gates = {gate["name"]: gate["satisfied"] for gate in machine["hard_gates"]}
    assert hard_gates.get("m4_z3_proof") is True
    assert hard_gates.get("formal_model") is True
    assert "daylight-v06-m4-z3-proof-test" in scorecard
    assert "daylight-v06-m4-z3-proof-test:" in makefile
    assert "Daylight_v0.6_research_score = 975 / 1000" in scorecard

    if not args.quiet:
        print(f"Daylight v0.6 M4 Z3 proof: PASS ({len(results)} unsat checks)")


if __name__ == "__main__":
    main()
