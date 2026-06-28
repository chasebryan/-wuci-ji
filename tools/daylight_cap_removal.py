#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

import wuci_safeio


DEFAULT_PLAN = "daylight-equation/research/daylight-v06-cap-removal-plan.v1.json"
VERIFY_SCHEMA = "daylight-v06-cap-removal-verification-v1"
REQUIRED_CAPS = {
    "no_independent_external_reviews_tracked": 9000,
    "no_integrated_public_authority": 8500,
    "no_production_authority_publish_authority_or_trust_gate": 8250,
    "no_runtime_containment_enforcement": 8250,
    "no_whole_system_post_quantum_safety_claim": 8500,
}
COMMAND_CONTRACTS = {
    "publish-authorized-rooted": {
        "shape": "publish-authorized-rooted <authority> <artifact> <contract>",
        "required_action": "publish",
        "required_authority_field": "allow-publish",
        "current_status": "implemented-decision-only-fail-closed",
        "implemented": True,
    },
    "trust-authorized-rooted": {
        "shape": "trust-authorized-rooted <authority> <artifact> <contract>",
        "required_action": "trust",
        "required_authority_field": "allow-trust",
        "current_status": "implemented-decision-only-fail-closed",
        "implemented": True,
    },
}
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


class CapRemovalError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise CapRemovalError(message)


def read_bytes(path: Path, context: str, *, max_bytes: int | None = None) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(
            path,
            context,
            reject_symlink=True,
            reject_hardlink=True,
            max_bytes=max_bytes,
        )
    except wuci_safeio.SafeIOError as exc:
        raise CapRemovalError(str(exc)) from exc


def read_text(path: Path, context: str, *, max_bytes: int | None = None) -> str:
    try:
        return read_bytes(path, context, max_bytes=max_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CapRemovalError(f"{context} is not UTF-8") from exc


def read_json(path: Path, context: str) -> Any:
    try:
        return json.loads(read_text(path, context, max_bytes=512 * 1024))
    except json.JSONDecodeError as exc:
        raise CapRemovalError(f"{context} is not valid JSON: {exc.msg}") from exc


def parse_flat_fields(text: str, context: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        label, sep, value = line.partition(": ")
        if sep != ": ":
            fail(f"{context} contains malformed line")
        if label in fields:
            fail(f"{context} contains duplicate field: {label}")
        fields[label] = value
    return fields


def deterministic_group_key() -> str:
    for x in range(30001, 50000):
        rhs = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
        y = pow(rhs, (SECP256K1_P + 1) // 4, SECP256K1_P)
        if (y * y) % SECP256K1_P == rhs:
            prefix = "03" if y & 1 else "02"
            return prefix + f"{x:064x}"
    fail("could not find deterministic secp256k1 point")
    raise AssertionError("unreachable")


def require_proc_failure(proc: subprocess.CompletedProcess[bytes], needle: bytes, context: str) -> None:
    if proc.returncode == 0:
        fail(f"{context} unexpectedly succeeded")
    combined = proc.stderr + proc.stdout
    if needle not in combined:
        detail = combined.decode("utf-8", "replace")
        fail(f"{context} failed with unexpected output: {detail}")


def run_python(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def verify_fixture_rejections(repo: Path, plan: dict[str, Any]) -> list[str]:
    fixture = plan.get("fixture_authority_rejections")
    if not isinstance(fixture, dict):
        fail("fixture_authority_rejections must be an object")
    paths = fixture.get("paths")
    if paths != ["authority/wuci-root.fixture.txt", "authority/wuci-release-root.fixture.txt"]:
        fail("fixture rejection paths are not the two committed fixture roots")
    required_fields = fixture.get("required_fields")
    if required_fields != {
        "production": "false",
        "allow-trust": "false",
        "allow-publish": "false",
    }:
        fail("fixture rejection required fields changed")
    if fixture.get("production_verifier_must_reject") is not True:
        fail("fixture production verifier rejection is not required")
    if fixture.get("publish_trust_emit_must_fail_until_positive_authority_exists") is not True:
        fail("publish/trust emit fail-closed requirement is missing")

    verified_paths: list[str] = []
    for rel_path in paths:
        path = repo / rel_path
        fields = parse_flat_fields(read_text(path, rel_path, max_bytes=64 * 1024), rel_path)
        for key, expected in required_fields.items():
            if fields.get(key) != expected:
                fail(f"{rel_path} must keep {key}: {expected}")
        proc = run_python(
            repo,
            "tools/wuci_production_authority.py",
            "verify",
            "--authority",
            str(path),
            "--quiet",
        )
        require_proc_failure(proc, b"not production authority", f"production verifier fixture rejection for {rel_path}")
        verified_paths.append(rel_path)

    group_key = deterministic_group_key()
    with tempfile.TemporaryDirectory(prefix="daylight-cap-removal-") as tmp_name:
        tmp = Path(tmp_name)
        for flag in ("--allow-trust", "--allow-publish"):
            proc = run_python(
                repo,
                "tools/wuci_production_authority.py",
                "emit-root",
                "--group-public-key",
                group_key,
                "--allow-open",
                "--allow-release",
                flag,
                "--out",
                str(tmp / f"{flag[8:]}.txt"),
                "--quiet",
            )
            require_proc_failure(
                proc,
                b"trust/publish authority requires positive assembly Gate authority",
                f"production authority {flag} rejection",
            )

    return verified_paths


def verify_cap_blockers(plan: dict[str, Any]) -> list[str]:
    blockers = plan.get("active_cap_blockers")
    if not isinstance(blockers, list):
        fail("active_cap_blockers must be a list")
    observed = {item.get("name"): item for item in blockers if isinstance(item, dict)}
    if set(observed) != set(REQUIRED_CAPS):
        fail("active cap blocker names do not match required set")
    active_names: list[str] = []
    for name, cap in REQUIRED_CAPS.items():
        item = observed[name]
        if item.get("active") is not True:
            fail(f"required cap blocker is not active: {name}")
        if item.get("maximum_score") != cap:
            fail(f"required cap blocker has wrong maximum_score: {name}")
        if not item.get("clearance_requires"):
            fail(f"required cap blocker has no clearance requirements: {name}")
        active_names.append(name)
    return active_names


def verify_command_contracts(repo: Path, plan: dict[str, Any]) -> list[str]:
    contracts = plan.get("publish_trust_command_contracts")
    if not isinstance(contracts, list):
        fail("publish_trust_command_contracts must be a list")
    observed = {item.get("name"): item for item in contracts if isinstance(item, dict)}
    if set(observed) != set(COMMAND_CONTRACTS):
        fail("publish/trust command contract names do not match required set")

    gate = read_json(repo / "docs/wuci_gate_boundary.json", "Wuci Gate boundary")
    futures = {item.get("name"): item for item in gate.get("future_commands", []) if isinstance(item, dict)}
    assembly = {
        item.get("name"): item
        for item in gate.get("assembly_contract_commands", [])
        if isinstance(item, dict)
    }
    main_s = read_text(repo / "src/main.s", "assembly command dispatch", max_bytes=512 * 1024)
    policy = read_json(repo / "docs/wuci_production_authority_policy.json", "production authority policy")
    required_commands = policy.get("required_for_production", {}).get("required_publish_trust_assembly_commands")
    if required_commands != ["publish-authorized-rooted", "trust-authorized-rooted"]:
        fail("production authority policy does not require publish/trust assembly commands")

    verified: list[str] = []
    for name, expected in COMMAND_CONTRACTS.items():
        item = observed[name]
        if item.get("shape") != expected["shape"]:
            fail(f"{name} shape mismatch")
        if item.get("required_action") != expected["required_action"]:
            fail(f"{name} action mismatch")
        if item.get("authority_schema") != "wuci-authority-root-v1":
            fail(f"{name} authority schema mismatch")
        if item.get("required_authority_field") != expected["required_authority_field"]:
            fail(f"{name} required authority field mismatch")
        if item.get("current_status") != expected["current_status"]:
            fail(f"{name} current status mismatch")
        if item.get("implemented") is not expected["implemented"]:
            fail(f"{name} implemented state mismatch")
        for key in ("must_reject_now", "activation_requires"):
            if not isinstance(item.get(key), list) or not item[key]:
                fail(f"{name} missing {key}")

        if expected["implemented"]:
            command = assembly.get(name)
            if not isinstance(command, dict):
                fail(f"{name} is missing from Wuci Gate assembly commands")
            if command.get("implemented") is not True:
                fail(f"{name} assembly command must be marked implemented")
            if command.get("shape") != expected["shape"]:
                fail(f"{name} Wuci Gate assembly shape mismatch")
            if command.get("required_action") != expected["required_action"]:
                fail(f"{name} Wuci Gate assembly action mismatch")
            if command.get("contract_schema") != "wuci-gate-receipt-contract-v1":
                fail(f"{name} Wuci Gate assembly contract schema mismatch")
            if command.get("authority_schema") != "wuci-authority-root-v1":
                fail(f"{name} Wuci Gate assembly authority schema mismatch")
            if name in futures:
                fail(f"{name} must not remain in Wuci Gate future commands")
            if name not in main_s:
                fail(f"{name} is missing from assembly command dispatch")
        else:
            future = futures.get(name)
            if not isinstance(future, dict):
                fail(f"{name} is missing from Wuci Gate future commands")
            if future.get("implemented") is not False:
                fail(f"{name} future command must not be marked implemented")
            if future.get("shape") != expected["shape"]:
                fail(f"{name} Wuci Gate shape mismatch")
            if future.get("required_action") != expected["required_action"]:
                fail(f"{name} Wuci Gate action mismatch")
            if "assembly Gate enforcement" not in str(future.get("blocker", "")):
                fail(f"{name} Wuci Gate blocker must mention assembly Gate enforcement")
            if name in main_s:
                fail(f"{name} appears in assembly command dispatch before implementation")
        verified.append(name)
    return verified


def evaluate(repo: Path, plan_path: Path) -> dict[str, Any]:
    repo = repo.resolve()
    plan_path = plan_path if plan_path.is_absolute() else repo / plan_path
    plan = read_json(plan_path, "Daylight cap-removal plan")
    if plan.get("schema") != "daylight-v06-cap-removal-plan-v1":
        fail("unsupported Daylight cap-removal plan schema")
    if plan.get("subject") != "Daylight_v0.6":
        fail("Daylight cap-removal subject mismatch")
    if plan.get("status") != "cap-removal-planned-fail-closed":
        fail("Daylight cap-removal status mismatch")

    score = plan.get("score_state")
    if not isinstance(score, dict):
        fail("score_state must be an object")
    expected_score = {
        "peer_review_evaluation_score": 8250,
        "peer_review_evaluation_maximum": 10000,
        "daylight_research_score": 975,
        "daylight_research_maximum": 1000,
        "score_increase_authorized": False,
    }
    for key, expected in expected_score.items():
        if score.get(key) != expected:
            fail(f"score_state {key} mismatch")

    score_model = read_json(
        repo / "daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.v1.json",
        "Daylight peer-review score model",
    )
    if score_model.get("score", {}).get("value") != 8250:
        fail("peer-review score model is not at the expected 8250 cap")
    if score_model.get("score", {}).get("cap_ceiling") != 8250:
        fail("peer-review score model cap ceiling is not 8250")

    linked_files = plan.get("linked_policy_files")
    if not isinstance(linked_files, list) or not linked_files:
        fail("linked_policy_files must be a non-empty list")
    for rel_path in linked_files:
        if not isinstance(rel_path, str) or not (repo / rel_path).exists():
            fail(f"linked policy file missing: {rel_path}")

    active_names = verify_cap_blockers(plan)
    verified_commands = verify_command_contracts(repo, plan)
    verified_fixtures = verify_fixture_rejections(repo, plan)

    markdown_path = plan.get("markdown_path")
    if not isinstance(markdown_path, str):
        fail("markdown_path is missing")
    markdown = read_text(repo / markdown_path, "Daylight cap-removal Markdown", max_bytes=512 * 1024)
    makefile = read_text(repo / "Makefile", "Makefile", max_bytes=512 * 1024)
    for non_claim in plan.get("non_claims", []):
        if non_claim not in markdown:
            fail(f"non-claim missing from cap-removal Markdown: {non_claim}")
    for command in plan.get("required_local_commands", []):
        if not isinstance(command, str) or not command.startswith("make "):
            fail("required local commands must be make targets")
        target = command.removeprefix("make ")
        if f"{target}:" not in makefile:
            fail(f"required local command target missing from Makefile: {command}")
        if command not in markdown:
            fail(f"required local command missing from cap-removal Markdown: {command}")

    return {
        "schema": VERIFY_SCHEMA,
        "subject": "Daylight_v0.6",
        "status": "verified-fail-closed-cap-removal-plan",
        "score_increase_authorized": False,
        "peer_review_evaluation_score": 8250,
        "peer_review_evaluation_maximum": 10000,
        "active_cap_blockers": active_names,
        "verified_publish_trust_command_contracts": verified_commands,
        "verified_fixture_rejection_paths": verified_fixtures,
        "non_claims": plan["non_claims"],
    }


def run_verify(args: argparse.Namespace) -> int:
    result = evaluate(Path(args.repo), Path(args.plan))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        print("Daylight v0.6 cap-removal plan: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Daylight v0.6 cap-removal blockers.")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--plan", default=DEFAULT_PLAN)
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError, CapRemovalError) as exc:
        print(f"Daylight cap removal: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
