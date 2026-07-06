#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import wuci_safeio


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = REPO_ROOT / "docs" / "wuci_golden_lock_model.json"

VERSION = "wuci-golden-lock/v1"
SCHEMA = "wuci-golden-lock-model-v1"
TRANSCRIPT_DST = "wuci/golden-lock/v1"
ALLOWED_ACTIONS = {"open", "release"}
ALLOWED_PQ_MODES = {"compat", "hybrid-evidence", "pq-secure"}
REQUIRED_DIGEST_VECTOR = ["SHA256", "SHA384", "SHA512"]
EXPECTED_THRESHOLDS = {
    0: {"n": 3, "t": 2, "mu": "compat", "state": "research/proof"},
    1: {"n": 5, "t": 3, "mu": "compat", "state": "release-candidate"},
    2: {"n": 5, "t": 3, "mu": "hybrid-evidence", "state": "defense-evidence profile"},
    3: {"n": 5, "t": 4, "mu": "hybrid-evidence", "state": "authority-root ceremony profile"},
}
NON_CLAIMS = [
    "not production cryptography",
    "not host security",
    "not runtime sandboxing",
    "not post-quantum system security",
    "not independently audited",
    "not production authority",
]
REJECTED_CLAIMS = [
    "production_crypto_claim",
    "host_security_claim",
    "runtime_sandbox_claim",
    "pq_secure_system_claim",
    "independent_audit_claim",
    "production_authority_claim",
    "defense_grade_achieved_claim",
]
REQUIRED_EVIDENCE = [
    ("sealed_artifact", "sealed artifact evidence missing"),
    ("manifest", "manifest evidence missing"),
    ("gate_contract", "Gate contract evidence missing"),
    ("authority_root", "authority root evidence missing"),
    ("witness_bundle", "witness evidence missing"),
    ("ledger", "ledger evidence missing"),
    ("provenance", "provenance evidence missing"),
    ("install", "install evidence missing"),
    ("frost_quorum_receipt", "FROST quorum receipt evidence missing"),
    ("epoch_ratchet", "epoch/ratchet evidence missing"),
]
EXPLICIT_PREDICATE_FLAGS = [
    ("parse_ok", "Parse_G failed"),
    ("env_ok", "EnvOK failed"),
    ("root_ok", "RootOK failed"),
    ("gate_ok", "GateOK failed"),
    ("witness_ok", "WitnessOK failed"),
    ("ledger_ok", "LedgerOK failed"),
    ("ratchet_ok", "RatchetOK failed"),
    ("provenance_ok", "ProvenanceOK failed"),
    ("install_ok", "InstallOK failed"),
    ("frost_verify_ok", "FROSTVerify_3_5 failed"),
]
CLAIM_ALIASES = {
    "production_crypto_claim": {
        "production crypto",
        "production cryptography",
        "production-crypto",
        "production-cryptography",
        "production_crypto_claim",
    },
    "host_security_claim": {
        "host security",
        "host-secure",
        "host security claim",
        "host_security_claim",
    },
    "runtime_sandbox_claim": {
        "runtime sandbox",
        "runtime sandboxing",
        "complete sandbox",
        "runtime_sandbox_claim",
    },
    "pq_secure_system_claim": {
        "post-quantum secure",
        "post quantum secure",
        "post-quantum system security",
        "pq secure system",
        "pq_secure_system_claim",
        "quantum-safe",
    },
    "independent_audit_claim": {
        "independently audited",
        "independent audit",
        "audited",
        "independent_audit_claim",
    },
    "production_authority_claim": {
        "production authority",
        "production trust authority",
        "production_authority_claim",
    },
    "defense_grade_achieved_claim": {
        "defense-grade achieved",
        "defense-grade secure",
        "defense grade achieved",
        "defense_grade_achieved_claim",
    },
}


class GoldenLockModelError(RuntimeError):
    pass


def load_json(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            wuci_safeio.read_regular_bytes(path, context, reject_hardlink=True).decode("utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, wuci_safeio.SafeIOError) as exc:
        raise GoldenLockModelError(f"could not read {context}: {path}") from exc
    if not isinstance(value, dict):
        raise GoldenLockModelError(f"{context} must be a JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    try:
        wuci_safeio.atomic_replace_text(
            path,
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            "Golden Lock model output",
            mode=0o644,
        )
    except wuci_safeio.SafeIOError as exc:
        raise GoldenLockModelError(str(exc)) from exc


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _as_bool(value: Any) -> bool:
    return value is True


def _normalize_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().lower().replace("_", " ").split())


def _threshold_policy(model: dict[str, Any]) -> dict[int, dict[str, Any]]:
    policy = model.get("threshold_policy")
    if not isinstance(policy, dict):
        raise GoldenLockModelError("Golden Lock model threshold_policy must be an object")
    normalized: dict[int, dict[str, Any]] = {}
    for pressure, expected in EXPECTED_THRESHOLDS.items():
        entry = policy.get(str(pressure))
        if not isinstance(entry, dict):
            raise GoldenLockModelError(f"Golden Lock model missing threshold policy {pressure}")
        if entry.get("n") != expected["n"] or entry.get("t") != expected["t"]:
            raise GoldenLockModelError(f"Golden Lock threshold policy {pressure} mismatch")
        if entry.get("mu") != expected["mu"]:
            raise GoldenLockModelError(f"Golden Lock threshold policy {pressure} pq_mode mismatch")
        normalized[pressure] = {
            "n": expected["n"],
            "t": expected["t"],
            "mu": expected["mu"],
            "state": expected["state"],
        }
    return normalized


def _pressure_levels(model: dict[str, Any]) -> dict[int, dict[str, Any]]:
    levels = model.get("pressure_levels")
    if not isinstance(levels, list):
        raise GoldenLockModelError("Golden Lock model pressure_levels must be a list")
    normalized: dict[int, dict[str, Any]] = {}
    for entry in levels:
        if not isinstance(entry, dict):
            raise GoldenLockModelError("Golden Lock pressure level must be an object")
        pressure = entry.get("lambda")
        if not _is_int(pressure):
            raise GoldenLockModelError("Golden Lock pressure lambda must be an integer")
        if pressure in normalized:
            raise GoldenLockModelError("Golden Lock pressure levels must be unique")
        threshold = entry.get("threshold")
        if not isinstance(threshold, dict):
            raise GoldenLockModelError("Golden Lock pressure threshold must be an object")
        expected = EXPECTED_THRESHOLDS.get(pressure)
        if expected is None:
            raise GoldenLockModelError(f"unsupported Golden Lock pressure level {pressure}")
        if threshold.get("n") != expected["n"] or threshold.get("t") != expected["t"]:
            raise GoldenLockModelError(f"Golden Lock pressure {pressure} threshold mismatch")
        if entry.get("mu") != expected["mu"]:
            raise GoldenLockModelError(f"Golden Lock pressure {pressure} pq_mode mismatch")
        if entry.get("allowed_state") != expected["state"]:
            raise GoldenLockModelError(f"Golden Lock pressure {pressure} allowed_state mismatch")
        normalized[pressure] = {
            "name": entry.get("name"),
            "n": expected["n"],
            "t": expected["t"],
            "mu": expected["mu"],
            "state": expected["state"],
        }
    if set(normalized) != set(EXPECTED_THRESHOLDS):
        raise GoldenLockModelError("Golden Lock pressure levels must be exactly 0, 1, 2, 3")
    return normalized


def validate_model(model: dict[str, Any]) -> dict[int, dict[str, Any]]:
    if model.get("version") != VERSION:
        raise GoldenLockModelError("Golden Lock model version mismatch")
    if model.get("schema") != SCHEMA:
        raise GoldenLockModelError("Golden Lock model schema mismatch")
    if model.get("transcript_dst") != TRANSCRIPT_DST:
        raise GoldenLockModelError("Golden Lock transcript DST mismatch")
    if model.get("digest_vector") != REQUIRED_DIGEST_VECTOR:
        raise GoldenLockModelError("Golden Lock digest vector mismatch")
    if set(model.get("allowed_actions", [])) != ALLOWED_ACTIONS:
        raise GoldenLockModelError("Golden Lock allowed actions must be open/release")
    pq_modes = model.get("pq_modes")
    if not isinstance(pq_modes, dict) or set(pq_modes) != ALLOWED_PQ_MODES:
        raise GoldenLockModelError("Golden Lock pq_modes mismatch")
    if pq_modes.get("pq-secure", {}).get("accepted") is not False:
        raise GoldenLockModelError("Golden Lock pq-secure must fail closed")
    hybrid = pq_modes.get("hybrid-evidence", {})
    if hybrid.get("requires") != ["MLDSA_Verify", "PinOK", "KAT_OK"]:
        raise GoldenLockModelError("Golden Lock hybrid-evidence requirements mismatch")
    quorum = model.get("domain_quorum")
    if (
        not isinstance(quorum, dict)
        or quorum.get("min_participants") != 3
        or quorum.get("min_distinct_domains") != 3
    ):
        raise GoldenLockModelError("Golden Lock domain quorum must require 3 participants and 3 domains")
    required = set(model.get("required_predicates", []))
    for predicate in (
        "Parse_G",
        "EnvOK",
        "RootOK",
        "DomainQuorum_3_5",
        "FROSTVerify_3_5",
        "GateOK",
        "WitnessOK",
        "PrivateMaterial",
        "LedgerOK",
        "RatchetOK",
        "ProvenanceOK",
        "InstallOK",
        "NoDowngrade",
        "PQModeOK",
        "ClaimOK",
    ):
        if predicate not in required:
            raise GoldenLockModelError(f"Golden Lock model missing predicate {predicate}")
    _threshold_policy(model)
    return _pressure_levels(model)


def _participants(value: Any, blockers: list[str]) -> tuple[list[dict[str, Any]], int, int]:
    if not isinstance(value, list):
        blockers.append("participants must be a list")
        return [], 0, 0
    domains: set[str] = set()
    seen_ids: set[str] = set()
    for index, participant in enumerate(value):
        if not isinstance(participant, dict):
            blockers.append(f"participant {index} must be an object")
            continue
        pid = participant.get("id")
        if isinstance(pid, str) and pid.strip():
            if pid in seen_ids:
                blockers.append(f"participant id duplicated: {pid}")
            seen_ids.add(pid)
        domain = participant.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            blockers.append(f"participant {index} custody domain missing")
            continue
        domains.add(domain.strip().lower())
    return value, len(value), len(domains)


def _claim_enabled(claims: Any, name: str) -> bool:
    if isinstance(claims, dict):
        return claims.get(name) is True
    if isinstance(claims, list):
        normalized_claims = {_normalize_text(item) for item in claims}
        aliases = {_normalize_text(item) for item in CLAIM_ALIASES[name]}
        return bool(normalized_claims & aliases)
    return False


def _claim_state(claims: Any) -> str | None:
    if isinstance(claims, dict):
        state = claims.get("state")
        return state if isinstance(state, str) else None
    if isinstance(claims, list):
        allowed = {rule["state"] for rule in EXPECTED_THRESHOLDS.values()}
        normalized_allowed = {_normalize_text(state): state for state in allowed}
        for claim in claims:
            value = normalized_allowed.get(_normalize_text(claim))
            if value is not None:
                return value
    return None


def _pq_flag(pq_evidence: dict[str, Any], key: str) -> bool:
    aliases = {
        "MLDSA_Verify": ("MLDSA_Verify", "mldsa_verify", "ml_dsa_verify"),
        "PinOK": ("PinOK", "pin_ok", "pins_ok"),
        "KAT_OK": ("KAT_OK", "kat_ok", "kat"),
    }[key]
    return any(pq_evidence.get(alias) is True for alias in aliases)


def evaluate(model: dict[str, Any], evidence_input: dict[str, Any]) -> dict[str, Any]:
    rules = validate_model(model)
    blockers: list[str] = []
    warnings = ["model validation is not production cryptographic verification"]

    action = evidence_input.get("action")
    pressure_level = evidence_input.get("pressure_level", evidence_input.get("pressure"))
    pq_mode = evidence_input.get("pq_mode", evidence_input.get("mu"))

    rule = rules.get(pressure_level) if _is_int(pressure_level) else None
    threshold = {"n": rule["n"], "t": rule["t"]} if rule else {"n": None, "t": None}

    if action not in ALLOWED_ACTIONS:
        blockers.append(f"unsupported action: {action}")
    if rule is None:
        blockers.append(f"unsupported pressure level: {pressure_level}")
    if pq_mode not in ALLOWED_PQ_MODES:
        blockers.append(f"unsupported pq mode: {pq_mode}")
    if pq_mode == "pq-secure":
        blockers.append("pq-secure fails closed in WJ-GOLD v1")
    if rule is not None and pq_mode != rule["mu"]:
        blockers.append(f"NoDowngrade rejected pq_mode {pq_mode} for pressure {pressure_level}")
    if pressure_level in (2, 3) and pq_mode == "compat":
        blockers.append(f"NoDowngrade rejected compat for pressure {pressure_level}")

    participants, participant_count, distinct_domain_count = _participants(
        evidence_input.get("participants", evidence_input.get("P")),
        blockers,
    )
    if rule is not None and participant_count != rule["n"]:
        blockers.append(
            f"participant count must equal threshold n={rule['n']} for pressure {pressure_level}"
        )
    if participant_count < 3 or distinct_domain_count < 3:
        blockers.append("DomainQuorum_3_5 requires at least 3 participants in 3 custody domains")

    signed_count = evidence_input.get("signed_participant_count", threshold["t"])
    if not _is_int(signed_count):
        blockers.append("signed_participant_count must be an integer")
    elif rule is not None and signed_count < rule["t"]:
        blockers.append(f"signed participant count {signed_count} is below threshold t={rule['t']}")
    elif _is_int(signed_count) and signed_count > participant_count:
        blockers.append("signed participant count exceeds participant count")

    evidence = evidence_input.get("evidence")
    if not isinstance(evidence, dict):
        blockers.append("evidence must be an object")
        evidence = {}
    for key, message in REQUIRED_EVIDENCE:
        if not _as_bool(evidence.get(key)):
            blockers.append(message)
    for key, message in EXPLICIT_PREDICATE_FLAGS:
        if key in evidence and evidence.get(key) is not True:
            blockers.append(message)

    if evidence.get("private_material_present") is True:
        blockers.append("PrivateMaterial(B)=0 failed")
    private_count = evidence.get("private_material_count", 0)
    if _is_int(private_count) and private_count != 0:
        blockers.append("PrivateMaterial(B)=0 failed")
    elif "private_material_count" in evidence and not _is_int(private_count):
        blockers.append("private_material_count must be an integer")

    gate_ok = evidence.get("gate_ok")
    aead_ok = evidence.get("aead_ok")
    no_overwrite = evidence.get("no_overwrite")
    final_output_exists = evidence.get("final_output_exists")
    plaintext_before_gate = evidence.get("plaintext_before_gate")
    if plaintext_before_gate is True:
        blockers.append("No plaintext before Gate invariant failed")
    if gate_ok is False and final_output_exists is True:
        blockers.append("GateOK=0 implies no plaintext file exists")
    if aead_ok is False and final_output_exists is True:
        blockers.append("AEAD tag fail implies no plaintext file exists")
    if final_output_exists is True and not (gate_ok is True and aead_ok is True and no_overwrite is True):
        blockers.append("final output exists iff GateOK and AEADOK and NoOverwrite")

    if pq_mode == "hybrid-evidence":
        pq_evidence = evidence_input.get("pq_evidence")
        if not isinstance(pq_evidence, dict):
            pq_evidence = {}
        for required in ("MLDSA_Verify", "PinOK", "KAT_OK"):
            if not _pq_flag(pq_evidence, required):
                blockers.append(f"hybrid-evidence requires {required} evidence")

    claims = evidence_input.get("claims", {})
    if not isinstance(claims, (dict, list)):
        blockers.append("claims must be an object or string list")
        claims = {}
    expected_state = rule["state"] if rule is not None else None
    claim_state = _claim_state(claims)
    if expected_state is not None:
        if claim_state is None:
            blockers.append(f"ClaimOK requires bounded internal state {expected_state!r}")
        elif claim_state != expected_state:
            blockers.append(f"ClaimOK rejected state {claim_state!r} for pressure {pressure_level}")
    for claim in REJECTED_CLAIMS:
        if _claim_enabled(claims, claim):
            blockers.append(f"ClaimOK rejected {claim}")

    if participant_count and participant_count == distinct_domain_count:
        warnings.append("participant custody domains are distinct in this fixture")
    if participants and participant_count >= 3 and distinct_domain_count == 1:
        warnings.append("single custody domain cannot satisfy DomainQuorum_3_5")

    return {
        "accepted": not blockers,
        "action": action,
        "pressure_level": pressure_level,
        "pq_mode": pq_mode,
        "threshold_required": threshold,
        "participant_count": participant_count,
        "distinct_domain_count": distinct_domain_count,
        "blockers": blockers,
        "warnings": warnings,
        "non_claims": list(model.get("non_claims", NON_CLAIMS)),
    }


def cmd_check_model(args: argparse.Namespace) -> int:
    model = load_json(Path(args.model), "Golden Lock model")
    rules = validate_model(model)
    result = {
        "accepted": True,
        "version": model["version"],
        "schema": model["schema"],
        "pressure_levels": sorted(rules),
        "non_claims": list(model.get("non_claims", NON_CLAIMS)),
    }
    if args.out:
        write_json(Path(args.out), result)
    if not args.quiet:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    model = load_json(Path(args.model), "Golden Lock model")
    evidence = load_json(Path(args.input), "Golden Lock evidence input")
    result = evaluate(model, evidence)
    if args.out:
        write_json(Path(args.out), result)
    if not args.quiet:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["accepted"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WUCI WJ-GOLD model and evidence validator."
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    check = subparsers.add_parser("check-model", help="validate the WJ-GOLD model JSON")
    check.add_argument("--model", default=str(DEFAULT_MODEL), help="model JSON path")
    check.add_argument("--out", help="write machine-readable result JSON")
    check.add_argument("--quiet", action="store_true", help="suppress stdout")
    check.set_defaults(func=cmd_check_model)

    validate = subparsers.add_parser("validate", help="validate WJ-GOLD evidence input")
    validate.add_argument("--model", default=str(DEFAULT_MODEL), help="model JSON path")
    validate.add_argument("--input", required=True, help="evidence input JSON path")
    validate.add_argument("--out", help="write machine-readable result JSON")
    validate.add_argument("--quiet", action="store_true", help="suppress stdout")
    validate.set_defaults(func=cmd_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except GoldenLockModelError as exc:
        print(f"wuci golden lock model: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
