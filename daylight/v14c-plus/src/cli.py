"""Command-line interface for the Daylight v14C+ execution package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import corpus as corpus_model
from . import daylight_harness
from . import downgrade
from . import ledger as ledger_model
from .canonical_json import canonical_sha256


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
DEFAULT_EVALUATORS = PACKAGE_ROOT / "rules" / "q-evaluators.json"


def _json_dump(obj: Any, path: Path | None) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    if path is None:
        print(text, end="")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def cmd_init_ledger(args: argparse.Namespace) -> int:
    ledger_model.write_jsonl(Path(args.out), [])
    print(ledger_model.GENESIS_HEAD)
    return 0


def cmd_append_entry(args: argparse.Namespace) -> int:
    path = Path(args.ledger)
    entries = ledger_model.load_jsonl(path)
    witness = json.loads(Path(args.witness).read_text(encoding="utf-8"))
    digest = canonical_sha256({"artifact": args.artifact}, "DAYLIGHT-v14C+-CLI-ARTIFACT:")
    entries, head = ledger_model.append_entry(
        entries,
        entry_type=args.type,
        artifact_digest=digest,
        witness=witness,
        transcript_digest=canonical_sha256({"type": args.type, "artifact": args.artifact}, "DAYLIGHT-v14C+-CLI-TRANSCRIPT:"),
    )
    ledger_model.write_jsonl(path, entries)
    print(head)
    return 0


def cmd_freeze_corpus(args: argparse.Namespace) -> int:
    snapshot = corpus_model.freeze_path(Path(args.corpus))
    _json_dump(snapshot, Path(args.out) if args.out else None)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    scorecard, receipt, scorecard_entries = daylight_harness.generate_scorecard(
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        weights_path=DEFAULT_WEIGHTS,
        evaluators_path=DEFAULT_EVALUATORS,
        command="score",
    )
    _json_dump(scorecard, Path(args.out) if args.out else None)
    if args.receipt:
        _json_dump(receipt, Path(args.receipt))
    if args.output_ledger:
        ledger_model.write_jsonl(Path(args.output_ledger), scorecard_entries)
    return 0


def cmd_verify_scorecard(args: argparse.Namespace) -> int:
    scorecard = json.loads(Path(args.scorecard).read_text(encoding="utf-8"))
    daylight_harness.verify_scorecard(scorecard)
    print("scorecard: pass")
    return 0


def cmd_check_downgrade(args: argparse.Namespace) -> int:
    claimed = json.loads(Path(args.claimed).read_text(encoding="utf-8"))
    current = json.loads(Path(args.current).read_text(encoding="utf-8"))
    result = downgrade.evaluate_downgrade(
        claimed_q=claimed["q_vector"],
        recomputed_q=current["q_vector"],
        claim_state=args.state,
        scorecard_digest_valid=not args.invalid_digest,
        ledger_trace_valid=not args.invalid_trace,
        unresolved_external_falsification=args.external_falsification,
    )
    _json_dump(result, None)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Daylight v14C+ execution package")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-ledger")
    init.add_argument("--out", default=str(PACKAGE_ROOT / "examples" / "ledger.seed.jsonl"))
    init.set_defaults(func=cmd_init_ledger)
    append = sub.add_parser("append-entry")
    append.add_argument("--ledger", required=True)
    append.add_argument("--type", required=True)
    append.add_argument("--artifact", required=True)
    append.add_argument("--witness", required=True)
    append.set_defaults(func=cmd_append_entry)
    freeze = sub.add_parser("freeze-corpus")
    freeze.add_argument("--corpus", default=str(PACKAGE_ROOT / "examples" / "corpus.seed.jsonl"))
    freeze.add_argument("--out")
    freeze.set_defaults(func=cmd_freeze_corpus)
    score = sub.add_parser("score")
    score.add_argument("--ledger", default=str(PACKAGE_ROOT / "examples" / "ledger.seed.jsonl"))
    score.add_argument("--corpus", default=str(PACKAGE_ROOT / "examples" / "corpus.seed.jsonl"))
    score.add_argument("--out")
    score.add_argument("--receipt")
    score.add_argument("--output-ledger")
    score.set_defaults(func=cmd_score)
    verify = sub.add_parser("verify-scorecard")
    verify.add_argument("scorecard")
    verify.set_defaults(func=cmd_verify_scorecard)
    check = sub.add_parser("check-downgrade")
    check.add_argument("--claimed", required=True)
    check.add_argument("--current", required=True)
    check.add_argument("--state", default="candidate")
    check.add_argument("--invalid-digest", action="store_true")
    check.add_argument("--invalid-trace", action="store_true")
    check.add_argument("--external-falsification", action="store_true")
    check.set_defaults(func=cmd_check_downgrade)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

