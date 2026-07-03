#!/usr/bin/env python3
"""Daylight conformance CLI skeleton for evidence-bound security claims."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from daylight_standard_validate import (
    ROOT,
    ValidationError,
    dump_json,
    load_json,
    policy_findings,
    unsupported_claims_in_text,
    validate_object,
)


EPOCH = "1970-01-01T00:00:00Z"
LEVEL_ORDER = {f"D{i}": i for i in range(10)}


def generated_at() -> str:
    return os.environ.get("SOURCE_DATE_EPOCH_ISO", EPOCH)


def as_list(data: Any, schema_tag: str | None = None) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if schema_tag and data.get("schema") == schema_tag:
            return [data]
        for key in ["claims", "evidence", "items"]:
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    raise SystemExit("expected JSON object or list")


def load_objects(path: Path, schema_tag: str | None = None) -> list[dict[str, Any]]:
    return as_list(load_json(path), schema_tag)


def validate_with_policy(path: Path) -> int:
    obj = load_json(path)
    try:
        validate_object(obj)
    except ValidationError as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 1
    findings = policy_findings(obj)
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 2
    print(f"{path}: valid")
    return 0


def field_scores_for_claim(claim: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> tuple[dict[str, int], list[str]]:
    blockers: list[str] = []
    refs = claim.get("evidence_refs", [])
    usable = [evidence_by_id.get(ref) for ref in refs]
    usable_ok = bool(refs) and all(item and item.get("claim_usable") is True for item in usable)
    if not usable_ok:
        blockers.append(f"NoEvidence({claim.get('claim_id')}) -> NoScore")

    provenance_ok = usable_ok and all(
        item.get("produced_by") and item.get("source_commit") and item.get("produced_at")
        for item in usable
        if item
    )
    if not provenance_ok:
        blockers.append(f"NoProvenance({claim.get('claim_id')}) -> NoAuthority")

    reproduction_ok = bool(claim.get("reproduction_refs"))
    if not reproduction_ok:
        blockers.append(f"NoReproduction({claim.get('claim_id')}) -> ProvisionalOnly")

    boundary_ok = bool(claim.get("allowed_boundary")) and bool(claim.get("forbidden_expansions"))
    if not boundary_ok:
        blockers.append(f"NoBoundary({claim.get('claim_id')}) -> NoScope")

    monitor_ok = bool(claim.get("monitoring_refs"))
    control_ok = bool(claim.get("control_refs"))
    vulnerability_ok = (ROOT / "docs" / "WUCI_VULNERABILITY_RESPONSE.md").exists()

    scores = {
        "Evidence": 100 if usable_ok else 0,
        "Provenance": 100 if provenance_ok else 0,
        "Reproducibility": 100 if reproduction_ok else 50,
        "BoundaryPrecision": 100 if boundary_ok else 0,
        "FalsificationCoverage": 100 if boundary_ok else 50,
        "MonitoringContinuity": 100 if monitor_ok else 50,
        "ControlMapping": 100 if control_ok else 50,
        "VulnerabilityResponse": 100 if vulnerability_ok else 50,
    }
    return scores, blockers


def level_from_score(score: int, blockers: list[str], unsupported: list[str]) -> str:
    if score <= 0 or unsupported:
        return "D0"
    if blockers:
        return "D1"
    if score < 75:
        return "D2"
    if score < 90:
        return "D3"
    return "D4"


def command_validate(args: argparse.Namespace) -> int:
    return validate_with_policy(Path(args.input))


def command_score(args: argparse.Namespace) -> int:
    claims = load_objects(Path(args.claims), "daylight-claim-v1")
    evidence = load_objects(Path(args.evidence), "daylight-evidence-v1")

    for claim in claims:
        validate_object(claim)
    for item in evidence:
        validate_object(item)

    evidence_by_id = {item["evidence_id"]: item for item in evidence}
    all_scores: list[int] = []
    blockers: list[str] = []
    unsupported: list[str] = []
    derived_from: list[str] = []
    weakest_field = "Evidence"

    for claim in claims:
        derived_from.append(claim["claim_id"])
        derived_from.extend(claim.get("evidence_refs", []))
        unsupported.extend(
            f"{claim['claim_id']}: {phrase}" for phrase in unsupported_claims_in_text(claim.get("claim_text", ""))
        )
        if claim.get("score_impact", {}).get("manual_score_allowed") is not False:
            blockers.append(f"ManualScore({claim.get('claim_id')}) -> Reject")
        scores, claim_blockers = field_scores_for_claim(claim, evidence_by_id)
        blockers.extend(claim_blockers)
        local_weakest = min(scores, key=lambda key: scores[key])
        if not all_scores or scores[local_weakest] < min(all_scores):
            weakest_field = local_weakest
        all_scores.append(min(scores.values()))

    score = min(all_scores) if all_scores else 0
    if unsupported:
        score = 0
        blockers.append("ClaimBeyondEvidence(x) -> Overclaim(x)")

    scorecard = {
        "schema": "daylight-scorecard-v1",
        "scorecard_id": "scorecard.daylight.conformance.local",
        "score_model": "daylight-equation-v1-min-authority",
        "score": score,
        "max_score": 100,
        "authority_level": level_from_score(score, blockers, unsupported),
        "blocker_vector": sorted(set(blockers)),
        "weakest_field": weakest_field,
        "derived_from": sorted(set(derived_from)),
        "manual_score_rejected": True,
        "unsupported_claims": sorted(set(unsupported)),
        "generated_at": generated_at()
    }
    validate_object(scorecard)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dump_json(scorecard), encoding="utf-8")
    print(f"wrote {out}")
    return 1 if unsupported else 0


def command_gate(args: argparse.Namespace) -> int:
    release = load_json(Path(args.release))
    scorecard = load_json(Path(args.scorecard))
    validate_object(release)
    validate_object(scorecard)

    reasons = list(release.get("reasons", []))
    blocked = list(release.get("blocked_actions", []))
    required = set(release.get("required_evidence", []))
    derived = set(scorecard.get("derived_from", []))
    missing = sorted(required - derived)
    passable = release.get("decision") == "pass" and scorecard.get("score", 0) > 0
    passable = passable and not scorecard.get("blocker_vector") and not scorecard.get("unsupported_claims") and not missing
    if missing:
        reasons.append(f"missing required evidence: {', '.join(missing)}")
        blocked.extend(["release", "publish"])
    if scorecard.get("unsupported_claims"):
        reasons.append("unsupported claims present")
        blocked.extend(["release", "publish", "claim-authority"])

    decision = {
        "release_id": release.get("release_id"),
        "decision": "pass" if passable else "fail",
        "reasons": sorted(set(reasons)),
        "allowed_actions": release.get("allowed_actions", []) if passable else ["explain"],
        "blocked_actions": sorted(set(blocked)),
        "scorecard": scorecard.get("scorecard_id"),
        "authority_level": scorecard.get("authority_level")
    }
    print(dump_json(decision), end="")
    return 0 if passable else 1


def command_explain(args: argparse.Namespace) -> int:
    scorecard = load_json(Path(args.scorecard))
    validate_object(scorecard)
    print(f"scorecard: {scorecard['scorecard_id']}")
    print(f"score: {scorecard['score']} / {scorecard['max_score']}")
    print(f"authority level: {scorecard['authority_level']}")
    print(f"weakest field: {scorecard['weakest_field']}")
    if scorecard["blocker_vector"]:
        print("blockers:")
        for blocker in scorecard["blocker_vector"]:
            print(f"- {blocker}")
    else:
        print("blockers: none")
    if scorecard["unsupported_claims"]:
        print("unsupported claims:")
        for claim in scorecard["unsupported_claims"]:
            print(f"- {claim}")
    return 0


def command_control_map(args: argparse.Namespace) -> int:
    claims = load_objects(Path(args.claims), "daylight-claim-v1")
    maps: list[dict[str, Any]] = []
    for claim in claims:
        validate_object(claim)
        refs = claim.get("control_refs") or ["UNMAPPED"]
        for control_id in refs:
            maps.append({
                "schema": "daylight-control-map-v1",
                "control_framework": "Daylight local",
                "control_family": "Claim Integrity",
                "control_id": control_id,
                "evidence_refs": claim.get("evidence_refs", []),
                "status": "mapped" if claim.get("evidence_refs") else "gap",
                "gap": "" if claim.get("evidence_refs") else "claim has no evidence references",
                "next_artifact": "external conformance report",
                "claim_allowed": f"{claim['claim_id']} maps to {control_id} as an evidence index.",
                "claim_forbidden": "Control mapping does not prove certification, compliance, or government authorization."
            })
            validate_object(maps[-1])
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(dump_json(maps), encoding="utf-8")
    print(f"wrote {out}")
    return 0


def git_commit(project: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(project), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "working-tree"


def command_status(args: argparse.Namespace) -> int:
    project = Path(args.project).resolve()
    required_docs = [
        "docs/DAYLIGHT_EQUATION_STANDARD.md",
        "docs/WUCI_SECURITY_PRODUCT_BOUNDARY.md",
        "docs/WUCI_CONFORMANCE_PROFILE.md",
        "docs/WUCI_ENTERPRISE_ADOPTION.md",
        "docs/WUCI_VULNERABILITY_RESPONSE.md",
    ]
    missing = [path for path in required_docs if not (project / path).exists()]
    schema_count = len(list((project / "specs/daylight-equation/v1").glob("daylight-*.schema.json")))
    example_count = len(list((project / "examples/daylight-standard").glob("*.json")))
    level = "D2" if not missing and schema_count >= 9 and example_count >= 8 else "D1"
    report = {
        "schema": "daylight-conformance-report-v1",
        "project": project.name,
        "commit": git_commit(project),
        "conformance_level": level,
        "evidence_summary": {
            "required_docs_present": len(required_docs) - len(missing),
            "schema_count": schema_count,
            "example_count": example_count
        },
        "blockers": [f"missing {path}" for path in missing],
        "forbidden_claims_found": [],
        "recommended_next_level": "D3" if level == "D2" else "D2",
        "claim_allowed": "Daylight-compatible standard candidate evidence exists.",
        "claim_forbidden": "Not certification, production authority, government approval, runtime sandboxing, or production cryptography."
    }
    validate_object(report)
    print(dump_json(report), end="")
    return 0 if not missing else 1


def command_reject_overclaims(args: argparse.Namespace) -> int:
    path = Path(args.path)
    text = path.read_text(encoding="utf-8")
    findings = unsupported_claims_in_text(text)
    if findings:
        for finding in findings:
            print(f"{path}: unsupported authority phrase: {finding}", file=sys.stderr)
        return 1
    print(f"{path}: no unsupported authority claims")
    return 0


def command_monitor_signal(args: argparse.Namespace) -> int:
    signal = load_json(Path(args.input))
    validate_object(signal)
    state_path = Path(args.state)
    if state_path.exists():
        state = load_json(state_path)
    else:
        state = {"schema": "daylight-monitor-state-v1", "claims": {}}
    claims = state.setdefault("claims", {})
    claims[signal["related_claim"]] = {
        "state": signal["state"],
        "last_signal": signal["signal_id"],
        "downgrade_rule": signal["downgrade_rule"],
        "action_required": signal["action_required"],
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(dump_json(state), encoding="utf-8")
    print(f"wrote {state_path}")
    return 0 if signal["state"] in {"ok", "watch"} else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--input", required=True)
    validate.set_defaults(func=command_validate)

    score = sub.add_parser("score")
    score.add_argument("--claims", required=True)
    score.add_argument("--evidence", required=True)
    score.add_argument("--out", required=True)
    score.set_defaults(func=command_score)

    gate = sub.add_parser("gate")
    gate.add_argument("--release", required=True)
    gate.add_argument("--scorecard", required=True)
    gate.set_defaults(func=command_gate)

    explain = sub.add_parser("explain")
    explain.add_argument("--scorecard", required=True)
    explain.set_defaults(func=command_explain)

    control = sub.add_parser("control-map")
    control.add_argument("--claims", required=True)
    control.add_argument("--out", required=True)
    control.set_defaults(func=command_control_map)

    status = sub.add_parser("status")
    status.add_argument("--project", required=True)
    status.set_defaults(func=command_status)

    reject = sub.add_parser("reject-overclaims")
    reject.add_argument("--path", required=True)
    reject.set_defaults(func=command_reject_overclaims)

    monitor = sub.add_parser("monitor-signal")
    monitor.add_argument("--input", required=True)
    monitor.add_argument("--state", required=True)
    monitor.set_defaults(func=command_monitor_signal)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
