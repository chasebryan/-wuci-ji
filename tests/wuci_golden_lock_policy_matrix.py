#!/usr/bin/env python3
from __future__ import annotations

import argparse
from copy import deepcopy
import importlib.util
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_golden_lock.py"
POLICY = REPO_ROOT / "docs" / "wuci_golden_lock_policy.json"
FIXTURE = REPO_ROOT / "docs" / "wuci_golden_lock_transcript_fixture.json"


def load_module():
    spec = importlib.util.spec_from_file_location("wuci_golden_lock", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def expect_fail(func, needle: str) -> None:
    try:
        func()
    except Exception as exc:
        assert needle in str(exc), str(exc)
        return
    raise AssertionError(f"expected failure containing {needle!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI Golden Lock policy matrix.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    golden = load_module()
    policy = golden.load_json(POLICY, "Golden Lock policy")
    fixture = golden.load_json(FIXTURE, "Golden Lock transcript fixture")

    rules = golden.validate_policy(policy)
    assert rules[0]["threshold"] == {"n": 3, "t": 2}
    assert rules[0]["pq_mode"] == "compat"
    assert rules[1]["threshold"] == {"n": 5, "t": 3}
    assert rules[1]["pq_mode"] == "compat"
    assert rules[2]["threshold"] == {"n": 5, "t": 3}
    assert rules[2]["pq_mode"] == "hybrid-evidence"
    assert rules[3]["threshold"] == {"n": 5, "t": 4}
    assert rules[3]["pq_mode"] == "hybrid-evidence"
    assert policy["pq_modes"]["pq-secure"]["accepted"] is False
    assert policy["golden_rule"] == "No plaintext before Gate."

    evidence = golden.validate_fixture(policy, fixture, require_expected=True)
    assert evidence["schema"] == "wuci-golden-lock-transcript-evidence-v1"
    assert evidence["domain"] == "wuci/golden-lock/v1"
    assert evidence["canonicalization"] == "C14N_G"
    assert evidence["fixture_hash_algorithm"] == "sha256(domain || T_G)"
    assert evidence["pressure"] == 2
    assert evidence["pq_mode"] == "hybrid-evidence"
    assert evidence["declared_threshold"] == {"n": 5, "t": 3}
    assert evidence["production_authority"] is False
    assert evidence["quantum_safe_claim"] is False
    assert evidence["runtime_sandbox_claim"] is False
    assert len(evidence["canonical_transcript_sha256"]) == 64
    assert len(evidence["m_g_sha256"]) == 64
    lines = evidence["canonical_transcript_lines"]
    assert lines[0] == "schema=wuci-golden-lock-transcript-v1"
    assert lines[1] == "domain=wuci/golden-lock/v1"
    assert lines[-2] == "pq_mode=hybrid-evidence"
    assert lines[-1] == "pressure=2"

    assert_ok(
        run_cmd([sys.executable, str(TOOL), "verify-policy", "--policy", str(POLICY), "--quiet"]),
        "verify Golden Lock policy CLI",
    )
    assert_ok(
        run_cmd(
            [
                sys.executable,
                str(TOOL),
                "verify-fixture",
                "--policy",
                str(POLICY),
                "--fixture",
                str(FIXTURE),
                "--quiet",
            ]
        ),
        "verify Golden Lock fixture CLI",
    )

    downgraded = deepcopy(fixture)
    downgraded["pq_mode"] = "compat"
    expect_fail(
        lambda: golden.validate_fixture(policy, downgraded, require_expected=True),
        "NoDowngrade",
    )

    ceremony_with_normal_threshold = deepcopy(fixture)
    ceremony_with_normal_threshold["pressure"] = 3
    ceremony_with_normal_threshold["claims"] = ["authority-root-audit-ceremony-evidence"]
    expect_fail(
        lambda: golden.validate_fixture(policy, ceremony_with_normal_threshold, require_expected=True),
        "declared threshold",
    )

    pq_secure = deepcopy(fixture)
    pq_secure["pq_mode"] = "pq-secure"
    expect_fail(
        lambda: golden.validate_fixture(policy, pq_secure, require_expected=True),
        "NoDowngrade",
    )

    weak_domains = deepcopy(fixture)
    for participant in weak_domains["participants"]:
        participant["domain"] = "build"
    expect_fail(
        lambda: golden.validate_fixture(policy, weak_domains, require_expected=True),
        "DomainQuorum_3/5",
    )

    plaintext = deepcopy(fixture)
    plaintext["plaintext_before_gate"] = True
    expect_fail(
        lambda: golden.validate_fixture(policy, plaintext, require_expected=True),
        "plaintext before Gate",
    )

    forbidden_claim = deepcopy(fixture)
    forbidden_claim["claims"] = ["quantum-safe"]
    expect_fail(
        lambda: golden.validate_fixture(policy, forbidden_claim, require_expected=True),
        "ClaimOK",
    )

    digest_drift = deepcopy(fixture)
    digest_drift["inputs"]["artifact"] = "tampered Golden Lock fixture artifact\n"
    expect_fail(
        lambda: golden.validate_fixture(policy, digest_drift, require_expected=True),
        "canonical transcript",
    )

    reordered = deepcopy(fixture)
    expected_lines = reordered["expected"]["canonical_transcript_lines"]
    expected_lines[3], expected_lines[4] = expected_lines[4], expected_lines[3]
    expect_fail(
        lambda: golden.validate_fixture(policy, reordered, require_expected=True),
        "canonical transcript",
    )

    missing_field = deepcopy(fixture)
    del missing_field["inputs"]["install"]
    expect_fail(
        lambda: golden.validate_fixture(policy, missing_field, require_expected=True),
        "missing inputs",
    )

    if not args.quiet:
        print("wuci Golden Lock policy matrix: PASS")


if __name__ == "__main__":
    main()
