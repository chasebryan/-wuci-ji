#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import daylight_authority
import daylight_external_review
import wuci_safeio


SCORECARD = "daylight-equation/SCORECARD.md"
SCORECARD_JSON = "daylight-equation/SCORECARD.v1.json"
PREFLIGHT = "daylight-equation/research/daylight-v06-1000-preflight.v1.json"
VERIFY_SCHEMA = "daylight-v06-1000-claim-gate-v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SCORE_RE = re.compile(r"^Daylight_v0\.6_research_score\s*=\s*(\d+)\s*/\s*1000$", re.MULTILINE)
REQUIRED_SCORECARD_GATES = ("integrated_public_authority", "external_review", "production_authority")


class Daylight1000GateError(RuntimeError):
    pass


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
        raise Daylight1000GateError(str(exc)) from exc


def read_text(path: Path, context: str, *, max_bytes: int | None = None) -> str:
    try:
        return read_bytes(path, context, max_bytes=max_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Daylight1000GateError(f"{context} is not UTF-8") from exc


def read_json(path: Path, context: str) -> Any:
    try:
        return json.loads(read_bytes(path, context, max_bytes=512 * 1024).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise Daylight1000GateError(f"{context} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise Daylight1000GateError(f"{context} is not valid JSON: {exc.msg}") from exc


def current_git_commit(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise Daylight1000GateError("could not read current git commit: " + (proc.stderr or proc.stdout).strip())
    commit = proc.stdout.strip()
    if COMMIT_RE.fullmatch(commit) is None:
        raise Daylight1000GateError("current git commit is not a full lowercase SHA-1")
    return commit


def score_from_text(text: str) -> int:
    match = SCORE_RE.search(text)
    if match is None:
        raise Daylight1000GateError("scorecard missing Daylight v0.6 score")
    return int(match.group(1))


def rel(repo: Path, path: str) -> Path:
    return repo / path


def verify_review_set_arg(repo: Path, path: str | None, ssh_keygen: str | None, blockers: list[str]) -> dict[str, Any]:
    if not path:
        blockers.append("external review set evidence missing")
        return {"provided": False, "verified": False}
    try:
        summary = daylight_external_review.verify_review_set(
            manifest_path=Path(path),
            repo=repo,
            ssh_keygen=ssh_keygen,
        )
    except daylight_external_review.DaylightReviewError as exc:
        blockers.append("external review set failed: " + str(exc))
        return {"provided": True, "verified": False}
    if summary.get("review_count") != 2 or summary.get("external_review_claim_ready") is not True:
        blockers.append("external review set is not claim-ready")
    if summary.get("reviewed_commit") != current_git_commit(repo):
        blockers.append("external review set reviewed_commit does not match current HEAD")
    return {"provided": True, "verified": summary.get("external_review_claim_ready") is True, **summary}


def verify_authority_arg(repo: Path, path: str | None, ssh_keygen: str | None, blockers: list[str]) -> dict[str, Any]:
    if not path:
        blockers.append("integrated Daylight authority evidence missing")
        return {"provided": False, "verified": False}
    try:
        summary = daylight_authority.verify_daylight_authority(
            evidence_path=Path(path),
            repo=repo,
            ssh_keygen=ssh_keygen,
            require_integrated=True,
        )
    except daylight_authority.DaylightAuthorityError as exc:
        blockers.append("Daylight authority evidence failed: " + str(exc))
        return {"provided": True, "verified": False}
    if summary.get("integrated_public_authority") is not True:
        blockers.append("Daylight authority evidence is not integrated public authority")
    if summary.get("production_authority_for_daylight") is not True:
        blockers.append("Daylight authority evidence is not production authority for Daylight")
    return {
        "provided": True,
        "verified": summary.get("integrated_public_authority") is True
        and summary.get("production_authority_for_daylight") is True,
        **summary,
    }


def evaluate_gate(
    *,
    repo: Path,
    review_set: str | None,
    authority_evidence: str | None,
    ssh_keygen: str | None,
) -> dict[str, Any]:
    repo = repo.resolve()
    markdown = read_text(rel(repo, SCORECARD), "Daylight scorecard", max_bytes=512 * 1024)
    machine = read_json(rel(repo, SCORECARD_JSON), "Daylight machine scorecard")
    preflight = read_json(rel(repo, PREFLIGHT), "Daylight 1000 preflight")
    score = score_from_text(markdown)
    blockers: list[str] = []

    if machine.get("score", {}).get("value") != score:
        blockers.append("machine scorecard score does not match Markdown scorecard")
    if machine.get("score", {}).get("maximum") != 1000:
        blockers.append("machine scorecard maximum is not 1000")
    if score != 1000:
        blockers.append(f"score is {score}/1000, not 1000/1000")
    if preflight.get("current_score") != score:
        blockers.append("1000 preflight current_score does not match scorecard")
    if "do not claim or push a 1000 checkpoint" not in str(preflight.get("claim_policy", "")):
        blockers.append("1000 preflight claim policy is missing push checkpoint discipline")

    components = {item["name"]: item for item in machine.get("components", []) if isinstance(item, dict)}
    external_review_component = components.get("external_review", {})
    if external_review_component.get("value") != external_review_component.get("maximum"):
        blockers.append("external review score component is not fully credited")

    hard_gates = {gate["name"]: gate for gate in machine.get("hard_gates", []) if isinstance(gate, dict)}
    scorecard_gate_results: dict[str, bool] = {}
    for name in REQUIRED_SCORECARD_GATES:
        satisfied = hard_gates.get(name, {}).get("satisfied") is True
        scorecard_gate_results[name] = satisfied
        if not satisfied:
            blockers.append(f"scorecard hard gate is open: {name}")

    review_summary = verify_review_set_arg(repo, review_set, ssh_keygen, blockers)
    authority_summary = verify_authority_arg(repo, authority_evidence, ssh_keygen, blockers)
    ready = not blockers
    return {
        "schema": VERIFY_SCHEMA,
        "subject": "Daylight_v0.6",
        "status": "ready-for-1000-checkpoint" if ready else "blocked",
        "ready": ready,
        "reviewed_commit": current_git_commit(repo),
        "score": score,
        "maximum_score": 1000,
        "scorecard_hard_gates": scorecard_gate_results,
        "external_review_set": review_summary,
        "daylight_authority": authority_summary,
        "blockers": blockers,
        "non_claims": [
            "this gate does not create external review evidence",
            "this gate does not create production authority",
            "this gate does not claim runtime containment",
            "this gate does not claim whole-system post-quantum safety",
        ],
    }


def run_verify(args: argparse.Namespace) -> int:
    result = evaluate_gate(
        repo=Path(args.repo),
        review_set=args.review_set,
        authority_evidence=args.authority_evidence,
        ssh_keygen=args.ssh_keygen,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        if result["ready"]:
            print("Daylight v0.6 1000 claim gate: READY")
        else:
            print("Daylight v0.6 1000 claim gate: BLOCKED")
            for blocker in result["blockers"]:
                print(f"- {blocker}")
    return 0 if result["ready"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Daylight v0.6 1000 claim gate.")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--review-set")
    verify.add_argument("--authority-evidence")
    verify.add_argument("--ssh-keygen")
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError, Daylight1000GateError) as exc:
        print(f"Daylight 1000 gate: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
