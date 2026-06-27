#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = REPO_ROOT / "docs" / "wuci_golden_lock_policy.json"
DEFAULT_FIXTURE = REPO_ROOT / "docs" / "wuci_golden_lock_transcript_fixture.json"

DOMAIN = "wuci/golden-lock/v1"
FIXTURE_HASH_ALGORITHM = "sha256(domain || T_G)"
HVEC_LABELS = (
    "artifact",
    "manifest",
    "gate_contract",
    "authority",
    "witness",
    "provenance",
    "install",
)


class GoldenLockError(RuntimeError):
    pass


def load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenLockError(f"could not read {context}: {path}") from exc
    if not isinstance(value, dict):
        raise GoldenLockError(f"{context} must be a JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def hash_hex(name: str, data: bytes) -> str:
    if name == "sha256":
        return hashlib.sha256(data).hexdigest()
    if name == "sha384":
        return hashlib.sha384(data).hexdigest()
    if name == "sha512":
        return hashlib.sha512(data).hexdigest()
    raise GoldenLockError(f"unsupported digest: {name}")


def hvec(text: str) -> dict[str, str]:
    data = text.encode("utf-8")
    return {
        "sha256": hash_hex("sha256", data),
        "sha384": hash_hex("sha384", data),
        "sha512": hash_hex("sha512", data),
    }


def is_hex(value: Any, chars: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == chars
        and value == value.lower()
        and all(ch in "0123456789abcdef" for ch in value)
    )


def pressure_rules(policy: dict[str, Any]) -> dict[int, dict[str, Any]]:
    levels = policy.get("pressure_levels")
    if not isinstance(levels, list):
        raise GoldenLockError("Golden Lock policy pressure_levels must be a list")
    rules: dict[int, dict[str, Any]] = {}
    for level in levels:
        if not isinstance(level, dict):
            raise GoldenLockError("Golden Lock pressure level must be an object")
        pressure = level.get("pressure")
        if not isinstance(pressure, int) or isinstance(pressure, bool):
            raise GoldenLockError("Golden Lock pressure must be an integer")
        if pressure in rules:
            raise GoldenLockError("Golden Lock pressure levels must be unique")
        threshold = level.get("threshold")
        if (
            not isinstance(threshold, dict)
            or not isinstance(threshold.get("n"), int)
            or not isinstance(threshold.get("t"), int)
            or threshold["n"] < threshold["t"]
            or threshold["t"] <= 0
        ):
            raise GoldenLockError("Golden Lock threshold must satisfy n >= t > 0")
        rules[pressure] = level
    return rules


def validate_policy(policy: dict[str, Any]) -> dict[int, dict[str, Any]]:
    if policy.get("schema") != "wuci-golden-lock-policy-v1":
        raise GoldenLockError("Golden Lock policy schema mismatch")
    if policy.get("status") != "target-policy-not-production-claim":
        raise GoldenLockError("Golden Lock policy status mismatch")
    transcript = policy.get("transcript")
    if not isinstance(transcript, dict):
        raise GoldenLockError("Golden Lock transcript policy must be an object")
    if transcript.get("domain") != DOMAIN:
        raise GoldenLockError("Golden Lock transcript domain mismatch")
    if transcript.get("canonicalization") != "C14N_G":
        raise GoldenLockError("Golden Lock transcript canonicalization mismatch")
    if transcript.get("fixture_hash_algorithm") != FIXTURE_HASH_ALGORITHM:
        raise GoldenLockError("Golden Lock fixture hash algorithm mismatch")
    if policy.get("golden_rule") != "No plaintext before Gate.":
        raise GoldenLockError("Golden Lock policy must preserve the Gate rule")
    if policy.get("plaintext_before_gate_allowed") is not False:
        raise GoldenLockError("Golden Lock policy must deny plaintext before Gate")
    if set(policy.get("actions", [])) != {"open", "release"}:
        raise GoldenLockError("Golden Lock policy actions must be open/release")
    pq_modes = policy.get("pq_modes")
    if not isinstance(pq_modes, dict):
        raise GoldenLockError("Golden Lock pq_modes must be an object")
    if pq_modes.get("pq-secure", {}).get("accepted") is not False:
        raise GoldenLockError("Golden Lock pq-secure must fail closed")
    quorum = policy.get("domain_quorum")
    if (
        not isinstance(quorum, dict)
        or quorum.get("min_participants") != 3
        or quorum.get("min_domains") != 3
    ):
        raise GoldenLockError("Golden Lock domain quorum must require 3 participants and 3 domains")
    rules = pressure_rules(policy)
    expected = {
        0: (3, 2, "compat"),
        1: (5, 3, "compat"),
        2: (5, 3, "hybrid-evidence"),
        3: (5, 4, "hybrid-evidence"),
    }
    for pressure, (n_value, t_value, pq_mode) in expected.items():
        rule = rules.get(pressure)
        if rule is None:
            raise GoldenLockError(f"Golden Lock missing pressure {pressure}")
        threshold = rule["threshold"]
        if threshold.get("n") != n_value or threshold.get("t") != t_value:
            raise GoldenLockError(f"Golden Lock pressure {pressure} threshold mismatch")
        if rule.get("pq_mode") != pq_mode:
            raise GoldenLockError(f"Golden Lock pressure {pressure} pq_mode mismatch")
    return rules


def canonical_transcript(policy: dict[str, Any], fixture: dict[str, Any]) -> str:
    inputs = fixture.get("inputs")
    if not isinstance(inputs, dict):
        raise GoldenLockError("Golden Lock fixture inputs must be an object")
    missing = [name for name in HVEC_LABELS if not isinstance(inputs.get(name), str)]
    if missing:
        raise GoldenLockError("Golden Lock fixture missing inputs: " + ", ".join(missing))

    ledger_head = fixture.get("ledger_head")
    if not isinstance(ledger_head, dict):
        raise GoldenLockError("Golden Lock fixture ledger_head must be an object")
    if not isinstance(ledger_head.get("tree_size"), int) or ledger_head["tree_size"] < 0:
        raise GoldenLockError("Golden Lock ledger tree_size must be nonnegative")
    if not is_hex(ledger_head.get("root_sha256"), 64):
        raise GoldenLockError("Golden Lock ledger root_sha256 must be lowercase sha256")
    if not is_hex(ledger_head.get("entry_sha256"), 64):
        raise GoldenLockError("Golden Lock ledger entry_sha256 must be lowercase sha256")

    epoch = fixture.get("epoch")
    if not isinstance(epoch, dict):
        raise GoldenLockError("Golden Lock fixture epoch must be an object")
    if not isinstance(epoch.get("number"), int) or epoch["number"] < 0:
        raise GoldenLockError("Golden Lock epoch number must be nonnegative")
    if not is_hex(epoch.get("previous_m_g_sha256"), 64):
        raise GoldenLockError("Golden Lock previous m_G must be lowercase sha256")

    lines = [
        "schema=wuci-golden-lock-transcript-v1",
        f"domain={DOMAIN}",
        f"action={fixture.get('action')}",
    ]
    for label in HVEC_LABELS:
        vector = hvec(inputs[label])
        lines.extend(
            [
                f"{label}.sha256={vector['sha256']}",
                f"{label}.sha384={vector['sha384']}",
                f"{label}.sha512={vector['sha512']}",
            ]
        )
    lines.extend(
        [
            f"ledger_head.tree_size={ledger_head['tree_size']}",
            f"ledger_head.root_sha256={ledger_head['root_sha256']}",
            f"ledger_head.entry_sha256={ledger_head['entry_sha256']}",
            f"epoch.number={epoch['number']}",
            f"epoch.previous_m_g_sha256={epoch['previous_m_g_sha256']}",
        ]
    )

    participants = fixture.get("participants")
    if not isinstance(participants, list):
        raise GoldenLockError("Golden Lock participants must be a list")
    lines.append(f"participants.count={len(participants)}")
    for index, participant in enumerate(participants):
        if not isinstance(participant, dict):
            raise GoldenLockError("Golden Lock participant must be an object")
        for key in ("id", "domain", "role"):
            if not isinstance(participant.get(key), str) or not participant[key].strip():
                raise GoldenLockError(f"Golden Lock participant {key} is required")
        lines.extend(
            [
                f"participants.{index}.id={participant['id']}",
                f"participants.{index}.domain={participant['domain']}",
                f"participants.{index}.role={participant['role']}",
            ]
        )
    lines.extend(
        [
            f"pq_mode={fixture.get('pq_mode')}",
            f"pressure={fixture.get('pressure')}",
        ]
    )
    return "\n".join(lines) + "\n"


def transcript_hashes(transcript: str) -> dict[str, str]:
    transcript_bytes = transcript.encode("ascii")
    return {
        "canonical_transcript_sha256": hash_hex("sha256", transcript_bytes),
        "m_g_sha256": hash_hex("sha256", DOMAIN.encode("ascii") + transcript_bytes),
    }


def validate_fixture(
    policy: dict[str, Any],
    fixture: dict[str, Any],
    *,
    require_expected: bool,
) -> dict[str, Any]:
    rules = validate_policy(policy)
    if fixture.get("schema") != "wuci-golden-lock-transcript-fixture-v1":
        raise GoldenLockError("Golden Lock fixture schema mismatch")
    if fixture.get("status") != "deterministic-fixture-not-production-authority":
        raise GoldenLockError("Golden Lock fixture status mismatch")
    if fixture.get("action") not in policy["actions"]:
        raise GoldenLockError("Golden Lock fixture action is unsupported")
    pressure = fixture.get("pressure")
    if not isinstance(pressure, int) or pressure not in rules:
        raise GoldenLockError("Golden Lock fixture pressure is unsupported")
    rule = rules[pressure]
    if fixture.get("pq_mode") != rule["pq_mode"]:
        raise GoldenLockError("Golden Lock NoDowngrade rejected pq_mode for pressure")
    if fixture.get("pq_mode") == "pq-secure":
        raise GoldenLockError("Golden Lock pq-secure is false until earned")
    if fixture.get("plaintext_before_gate") is not False:
        raise GoldenLockError("Golden Lock rejected plaintext before Gate")
    declared = fixture.get("declared_threshold")
    if not isinstance(declared, dict):
        raise GoldenLockError("Golden Lock fixture declared_threshold must be an object")
    threshold = rule["threshold"]
    if declared.get("n") != threshold["n"] or declared.get("t") != threshold["t"]:
        raise GoldenLockError("Golden Lock declared threshold does not match pressure")

    participants = fixture.get("participants")
    if not isinstance(participants, list):
        raise GoldenLockError("Golden Lock participants must be a list")
    if len(participants) != threshold["n"]:
        raise GoldenLockError("Golden Lock participant count must match threshold n")
    ids = [participant.get("id") for participant in participants if isinstance(participant, dict)]
    domains = [participant.get("domain") for participant in participants if isinstance(participant, dict)]
    if len(set(ids)) != len(participants):
        raise GoldenLockError("Golden Lock participant ids must be unique")
    quorum = policy["domain_quorum"]
    if len(participants) < quorum["min_participants"] or len(set(domains)) < quorum["min_domains"]:
        raise GoldenLockError("Golden Lock DomainQuorum_3/5 rejected participant domains")

    claims = fixture.get("claims")
    if not isinstance(claims, list) or not all(isinstance(claim, str) for claim in claims):
        raise GoldenLockError("Golden Lock claims must be a string list")
    forbidden = set(policy.get("forbidden_claims", []))
    if forbidden.intersection(claims):
        raise GoldenLockError("Golden Lock ClaimOK rejected forbidden claim")
    allowed = set(rule.get("allowed_claims", []))
    if not set(claims).issubset(allowed):
        raise GoldenLockError("Golden Lock ClaimOK rejected pressure claim")

    transcript = canonical_transcript(policy, fixture)
    hashes = transcript_hashes(transcript)
    expected = fixture.get("expected")
    if require_expected:
        if not isinstance(expected, dict):
            raise GoldenLockError("Golden Lock fixture expected evidence is required")
        transcript_lines = expected.get("canonical_transcript_lines")
        if isinstance(transcript_lines, list) and all(
            isinstance(line, str) for line in transcript_lines
        ):
            expected_transcript = "\n".join(transcript_lines) + "\n"
        else:
            expected_transcript = expected.get("canonical_transcript")
        if expected_transcript != transcript:
            raise GoldenLockError("Golden Lock canonical transcript mismatch")
        if expected.get("canonical_transcript_sha256") != hashes["canonical_transcript_sha256"]:
            raise GoldenLockError("Golden Lock canonical transcript digest mismatch")
        if expected.get("m_g_sha256") != hashes["m_g_sha256"]:
            raise GoldenLockError("Golden Lock m_G digest mismatch")
    return {
        "schema": "wuci-golden-lock-transcript-evidence-v1",
        "domain": DOMAIN,
        "canonicalization": "C14N_G",
        "fixture_hash_algorithm": FIXTURE_HASH_ALGORITHM,
        "pressure": pressure,
        "pq_mode": fixture["pq_mode"],
        "declared_threshold": declared,
        "canonical_transcript": transcript,
        "canonical_transcript_lines": transcript.rstrip("\n").split("\n"),
        **hashes,
        "production_authority": False,
        "quantum_safe_claim": False,
        "runtime_sandbox_claim": False,
    }


def run_verify_policy(args: argparse.Namespace) -> int:
    validate_policy(load_json(Path(args.policy), "Golden Lock policy"))
    if not args.quiet:
        print(f"valid Golden Lock policy: {args.policy}")
    return 0


def run_emit_fixture(args: argparse.Namespace) -> int:
    policy = load_json(Path(args.policy), "Golden Lock policy")
    fixture = load_json(Path(args.fixture), "Golden Lock transcript fixture")
    evidence = validate_fixture(policy, fixture, require_expected=False)
    if args.out:
        write_json(Path(args.out), evidence)
        if not args.quiet:
            print(f"wrote Golden Lock transcript evidence: {args.out}")
    else:
        print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


def run_verify_fixture(args: argparse.Namespace) -> int:
    policy = load_json(Path(args.policy), "Golden Lock policy")
    fixture = load_json(Path(args.fixture), "Golden Lock transcript fixture")
    validate_fixture(policy, fixture, require_expected=True)
    if not args.quiet:
        print(f"valid Golden Lock transcript fixture: {args.fixture}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="WUCI Golden Lock v1 policy and transcript checker.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser("verify-policy", help="verify Golden Lock policy")
    policy_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    policy_parser.add_argument("--quiet", action="store_true")
    policy_parser.set_defaults(func=run_verify_policy)

    emit_parser = subparsers.add_parser("emit-fixture", help="emit deterministic transcript evidence")
    emit_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    emit_parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    emit_parser.add_argument("--out")
    emit_parser.add_argument("--quiet", action="store_true")
    emit_parser.set_defaults(func=run_emit_fixture)

    fixture_parser = subparsers.add_parser("verify-fixture", help="verify deterministic transcript fixture")
    fixture_parser.add_argument("--policy", default=str(DEFAULT_POLICY))
    fixture_parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    fixture_parser.add_argument("--quiet", action="store_true")
    fixture_parser.set_defaults(func=run_verify_fixture)

    args = parser.parse_args()
    try:
        return args.func(args)
    except GoldenLockError as exc:
        print(f"wuci golden lock: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
