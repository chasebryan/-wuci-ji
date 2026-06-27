#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_golden_lock_model.py"
MODEL = REPO_ROOT / "docs" / "wuci_golden_lock_model.json"


def load_module():
    spec = importlib.util.spec_from_file_location("wuci_golden_lock_model", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def participants(count: int, same_domain: bool = False) -> list[dict[str, str]]:
    domains = ["build", "release", "ledger", "build", "provenance"]
    if same_domain:
        domains = ["build"] * count
    return [
        {
            "id": f"signer-{index + 1}",
            "domain": domains[index],
            "role": "golden-lock-signer",
        }
        for index in range(count)
    ]


def valid_input(pressure: int, pq_mode: str | None = None) -> dict:
    expected = {
        0: (3, 2, "compat", "research/proof"),
        1: (5, 3, "compat", "release-candidate"),
        2: (5, 3, "hybrid-evidence", "defense-evidence profile"),
        3: (5, 4, "hybrid-evidence", "authority-root ceremony profile"),
    }[pressure]
    n_value, t_value, default_pq_mode, state = expected
    mode = pq_mode or default_pq_mode
    return {
        "schema": "wuci-golden-lock-evidence-fixture-v1",
        "action": "release",
        "pressure_level": pressure,
        "pq_mode": mode,
        "participants": participants(n_value),
        "signed_participant_count": t_value,
        "evidence": {
            "sealed_artifact": True,
            "manifest": True,
            "gate_contract": True,
            "authority_root": True,
            "witness_bundle": True,
            "ledger": True,
            "provenance": True,
            "install": True,
            "frost_quorum_receipt": True,
            "epoch_ratchet": True,
            "parse_ok": True,
            "env_ok": True,
            "root_ok": True,
            "gate_ok": True,
            "witness_ok": True,
            "ledger_ok": True,
            "ratchet_ok": True,
            "provenance_ok": True,
            "install_ok": True,
            "frost_verify_ok": True,
            "aead_ok": True,
            "no_overwrite": True,
            "final_output_exists": True,
            "plaintext_before_gate": False,
            "private_material_present": False,
            "private_material_count": 0,
        },
        "pq_evidence": {
            "mldsa_verify": mode == "hybrid-evidence",
            "pin_ok": mode == "hybrid-evidence",
            "kat_ok": mode == "hybrid-evidence",
        },
        "claims": {
            "state": state,
            "production_crypto_claim": False,
            "host_security_claim": False,
            "runtime_sandbox_claim": False,
            "pq_secure_system_claim": False,
            "independent_audit_claim": False,
            "production_authority_claim": False,
            "defense_grade_achieved_claim": False,
        },
    }


def assert_accept(golden, model: dict, value: dict, pressure: int, threshold: dict[str, int]) -> dict:
    result = golden.evaluate(model, value)
    assert result["accepted"] is True, result
    assert result["pressure_level"] == pressure
    assert result["pq_mode"] == value["pq_mode"]
    assert result["threshold_required"] == threshold
    assert result["participant_count"] == threshold["n"]
    assert result["distinct_domain_count"] >= 3
    assert "not production cryptography" in result["non_claims"]
    return result


def assert_reject(golden, model: dict, value: dict, needle: str) -> dict:
    result = golden.evaluate(model, value)
    assert result["accepted"] is False, result
    assert any(needle in blocker for blocker in result["blockers"]), result
    return result


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WJ-GOLD model validator.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    golden = load_module()
    model = golden.load_json(MODEL, "Golden Lock model")
    rules = golden.validate_model(model)
    assert rules[0]["n"] == 3
    assert rules[0]["t"] == 2
    assert rules[0]["mu"] == "compat"
    assert rules[1]["n"] == 5
    assert rules[1]["t"] == 3
    assert rules[1]["mu"] == "compat"
    assert rules[2]["n"] == 5
    assert rules[2]["t"] == 3
    assert rules[2]["mu"] == "hybrid-evidence"
    assert rules[3]["n"] == 5
    assert rules[3]["t"] == 4
    assert rules[3]["mu"] == "hybrid-evidence"
    assert model["pq_modes"]["pq-secure"]["accepted"] is False

    assert_accept(golden, model, valid_input(0), 0, {"n": 3, "t": 2})
    assert_accept(golden, model, valid_input(1), 1, {"n": 5, "t": 3})
    assert_accept(golden, model, valid_input(2), 2, {"n": 5, "t": 3})
    assert_accept(golden, model, valid_input(3), 3, {"n": 5, "t": 4})

    missing_pq = valid_input(2)
    missing_pq["pq_evidence"]["kat_ok"] = False
    assert_reject(golden, model, missing_pq, "KAT_OK")

    downgraded = valid_input(2, pq_mode="compat")
    assert_reject(golden, model, downgraded, "NoDowngrade")

    weak_ceremony = valid_input(3)
    weak_ceremony["participants"] = participants(3)
    assert_reject(golden, model, weak_ceremony, "participant count")

    same_domain = valid_input(0)
    same_domain["participants"] = participants(3, same_domain=True)
    assert_reject(golden, model, same_domain, "DomainQuorum_3_5")

    pq_secure = valid_input(2, pq_mode="pq-secure")
    assert_reject(golden, model, pq_secure, "pq-secure fails closed")

    private_material = valid_input(1)
    private_material["evidence"]["private_material_count"] = 1
    assert_reject(golden, model, private_material, "PrivateMaterial")

    missing_witness = valid_input(1)
    missing_witness["evidence"]["witness_bundle"] = False
    assert_reject(golden, model, missing_witness, "witness evidence missing")

    missing_ledger = valid_input(1)
    missing_ledger["evidence"]["ledger"] = False
    assert_reject(golden, model, missing_ledger, "ledger evidence missing")

    missing_provenance = valid_input(1)
    missing_provenance["evidence"]["provenance"] = False
    assert_reject(golden, model, missing_provenance, "provenance evidence missing")

    missing_install = valid_input(1)
    missing_install["evidence"]["install"] = False
    assert_reject(golden, model, missing_install, "install evidence missing")

    for claim, needle in (
        ("production_crypto_claim", "production_crypto_claim"),
        ("host_security_claim", "host_security_claim"),
        ("runtime_sandbox_claim", "runtime_sandbox_claim"),
        ("pq_secure_system_claim", "pq_secure_system_claim"),
        ("independent_audit_claim", "independent_audit_claim"),
    ):
        claimed = valid_input(1)
        claimed["claims"][claim] = True
        assert_reject(golden, model, claimed, needle)

    unsupported_state = valid_input(1)
    unsupported_state["claims"]["state"] = "defense-grade achieved security"
    assert_reject(golden, model, unsupported_state, "ClaimOK rejected state")

    for action in ("trust", "publish", "run"):
        bad_action = valid_input(1)
        bad_action["action"] = action
        assert_reject(golden, model, bad_action, "unsupported action")

    gate_leak = valid_input(1)
    gate_leak["evidence"]["gate_ok"] = False
    gate_leak["evidence"]["final_output_exists"] = True
    assert_reject(golden, model, gate_leak, "GateOK=0")

    aead_leak = valid_input(1)
    aead_leak["evidence"]["aead_ok"] = False
    aead_leak["evidence"]["final_output_exists"] = True
    assert_reject(golden, model, aead_leak, "AEAD tag fail")

    plaintext = valid_input(1)
    plaintext["evidence"]["plaintext_before_gate"] = True
    assert_reject(golden, model, plaintext, "No plaintext before Gate")

    assert_ok(
        run_cmd([sys.executable, str(TOOL), "check-model", "--model", str(MODEL), "--quiet"]),
        "check WJ-GOLD model CLI",
    )
    with tempfile.TemporaryDirectory(prefix="wuci-golden-lock-model-") as temp_dir:
        temp = Path(temp_dir)
        sample_path = temp / "valid.json"
        result_path = temp / "result.json"
        sample_path.write_text(json.dumps(valid_input(2), indent=2) + "\n", encoding="utf-8")
        assert_ok(
            run_cmd(
                [
                    sys.executable,
                    str(TOOL),
                    "validate",
                    "--model",
                    str(MODEL),
                    "--input",
                    str(sample_path),
                    "--out",
                    str(result_path),
                    "--quiet",
                ]
            ),
            "validate WJ-GOLD evidence CLI",
        )
        cli_result = json.loads(result_path.read_text(encoding="utf-8"))
        assert cli_result["accepted"] is True
        assert cli_result["pressure_level"] == 2
        assert cli_result["pq_mode"] == "hybrid-evidence"

    if not args.quiet:
        print("wuci WJ-GOLD model validator: PASS")


if __name__ == "__main__":
    main()
