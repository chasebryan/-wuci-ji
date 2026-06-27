#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

import daylight_1000_gate
import wuci_safeio


CHECKPOINT_SCHEMA = "daylight-v06-1000-checkpoint-v1"


class Daylight1000CheckpointError(RuntimeError):
    pass


def write_json_new(path: Path, value: dict[str, Any], context: str) -> None:
    try:
        wuci_safeio.write_json_new(path, value, context, mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise Daylight1000CheckpointError(str(exc)) from exc


def checkpoint_value(
    *,
    repo: Path,
    review_set: str,
    authority_evidence: str,
    ssh_keygen: str | None,
) -> dict[str, Any]:
    gate = daylight_1000_gate.evaluate_gate(
        repo=repo,
        review_set=review_set,
        authority_evidence=authority_evidence,
        ssh_keygen=ssh_keygen,
    )
    if gate.get("ready") is not True:
        blockers = gate.get("blockers")
        if not isinstance(blockers, list):
            blockers = ["1000 claim gate is not ready"]
        blocker_text = "; ".join(str(item) for item in blockers)
        raise Daylight1000CheckpointError(f"Daylight 1000 checkpoint blocked: {blocker_text}")
    return {
        "schema": CHECKPOINT_SCHEMA,
        "subject": "Daylight_v0.6",
        "status": "ready-for-push",
        "reviewed_commit": gate["reviewed_commit"],
        "score": gate["score"],
        "maximum_score": gate["maximum_score"],
        "claim_gate_schema": gate["schema"],
        "claim_gate_ready": True,
        "review_set": review_set,
        "authority_evidence": authority_evidence,
        "external_review_set": gate["external_review_set"],
        "daylight_authority": gate["daylight_authority"],
        "non_claims": [
            "this checkpoint does not create external review evidence",
            "this checkpoint does not create production authority",
            "this checkpoint does not claim runtime containment",
            "this checkpoint does not claim whole-system post-quantum safety",
        ],
    }


def run_write(args: argparse.Namespace) -> int:
    if not args.review_set:
        raise Daylight1000CheckpointError("--review-set is required for a 1000 checkpoint")
    if not args.authority_evidence:
        raise Daylight1000CheckpointError("--authority-evidence is required for a 1000 checkpoint")
    value = checkpoint_value(
        repo=Path(args.repo).resolve(),
        review_set=args.review_set,
        authority_evidence=args.authority_evidence,
        ssh_keygen=args.ssh_keygen,
    )
    if args.json:
        print(json.dumps(value, indent=2, sort_keys=True))
    if not args.dry_run:
        write_json_new(Path(args.out), value, "Daylight 1000 checkpoint")
    if not args.quiet and not args.json:
        action = "validated Daylight 1000 checkpoint dry-run" if args.dry_run else "wrote Daylight 1000 checkpoint"
        print(f"{action}: {args.out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write a Daylight v0.6 1000 checkpoint only after the claim gate passes."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    write = sub.add_parser("write")
    write.add_argument("--repo", default=".")
    write.add_argument("--review-set", required=True)
    write.add_argument("--authority-evidence", required=True)
    write.add_argument("--ssh-keygen")
    write.add_argument("--out", required=True)
    write.add_argument("--dry-run", action="store_true")
    write.add_argument("--json", action="store_true")
    write.add_argument("--quiet", action="store_true")
    write.set_defaults(func=run_write)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError, Daylight1000CheckpointError) as exc:
        print(f"Daylight 1000 checkpoint: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
