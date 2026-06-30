"""Command-line interface for the Daylight v15 Meridian execution package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import api
from . import artifact as artifact_builder
from . import corpus as corpus_model
from . import daylight_harness
from . import downgrade
from . import ledger as ledger_model
from . import obligations as obligation_model
from . import scoring
from .canonical_json import canonical_sha256


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
DEFAULT_OBLIGATIONS = PACKAGE_ROOT / "rules" / "obligations.v15.json"
DEFAULT_LEDGER = PACKAGE_ROOT / "examples" / "ledger.seed.jsonl"
DEFAULT_CORPUS = PACKAGE_ROOT / "examples" / "corpus.seed.jsonl"
DEFAULT_ARTIFACT_DIR = PACKAGE_ROOT.parents[1] / "build" / "daylight" / "v15-meridian"

CLI_ERRORS = (
    daylight_harness.HarnessError,
    obligation_model.ObligationError,
    scoring.ScoreError,
    ledger_model.LedgerError,
    corpus_model.CorpusError,
    FileNotFoundError,
)


class CommandError(Exception):
    """A clean, expected CLI failure (printed to stderr, exit code 1)."""


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
    digest = canonical_sha256({"artifact": args.artifact}, "DAYLIGHT-v15-MERIDIAN-CLI-ARTIFACT:")
    entries, head = ledger_model.append_entry(
        entries,
        entry_type=args.type,
        artifact_digest=digest,
        witness=witness,
        transcript_digest=canonical_sha256({"type": args.type, "artifact": args.artifact}, "DAYLIGHT-v15-MERIDIAN-CLI-TRANSCRIPT:"),
        closes_obligations=args.closes or [],
        external_signer_id=args.external_signer,
    )
    ledger_model.write_jsonl(path, entries)
    print(head)
    return 0


def cmd_freeze_corpus(args: argparse.Namespace) -> int:
    snapshot = corpus_model.freeze_path(Path(args.corpus))
    _json_dump(snapshot, Path(args.out) if args.out else None)
    return 0


def _score_text(scorecard: dict[str, Any]) -> str:
    closed = len(scorecard["closed_obligations"])
    open_total = len(scorecard["open_obligations"])
    open_external = sum(1 for row in scorecard["open_obligations"] if row["scope"] == "external")
    return (
        f"{scorecard['candidate']}\n"
        f"  final_score_M:   {scorecard['final_score_M']} / {scorecard['perfect_score_M']}\n"
        f"  unified:         {scorecard['unified_score_decimal']}\n"
        f"  status:          {scorecard['status']}\n"
        f"  closed:          {closed} obligations\n"
        f"  open:            {open_total} ({open_external} external)\n"
        f"  residue_to_perfect_M: {scorecard['residue_to_perfect_M']}"
    )


def cmd_score(args: argparse.Namespace) -> int:
    scorecard, receipt, scorecard_entries = daylight_harness.generate_scorecard(
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        weights_path=DEFAULT_WEIGHTS,
        obligations_path=DEFAULT_OBLIGATIONS,
        command="score",
    )
    if args.out:
        _json_dump(scorecard, Path(args.out))
    if args.receipt:
        _json_dump(receipt, Path(args.receipt))
    if args.output_ledger:
        ledger_model.write_jsonl(Path(args.output_ledger), scorecard_entries)
    if args.format == "text":
        print(_score_text(scorecard))
    elif not args.out:
        _json_dump(scorecard, None)
    return 0


def cmd_verify_scorecard(args: argparse.Namespace) -> int:
    scorecard = json.loads(Path(args.scorecard).read_text(encoding="utf-8"))
    if args.strict and not (args.ledger and args.corpus):
        raise CommandError("--strict requires --ledger and --corpus for an evidence-bound check")
    daylight_harness.verify_scorecard(
        scorecard,
        obligations_path=DEFAULT_OBLIGATIONS,
        ledger_path=Path(args.ledger) if args.ledger else None,
        corpus_path=Path(args.corpus) if args.corpus else None,
    )
    if args.ledger and args.corpus:
        print("scorecard: pass (evidence-bound)")
    else:
        print("scorecard: pass")
    return 0


def _frontier_text(report: dict[str, Any]) -> str:
    lines = [
        "Daylight v15 Meridian frontier",
        f"  internal_ceiling_M:           {report['internal_ceiling_M']} / {report['perfect_score_M']}",
        f"  structural_external_residue_M: {report['structural_external_residue_M']}",
        f"  open_internal_residue_M:       {report['open_internal_residue_M']}",
        f"  open_external_residue_M:       {report['open_external_residue_M']}",
        "  external obligations (independent attestation required):",
    ]
    for row in report["open_external_obligations"]:
        lines.append(
            f"    - {row['obligation_id']} [{row['q_id']}] weight={row['weight']}/1000 "
            f"contribution_M={row['contribution_M']} role={row['external_role']}"
        )
    if report["open_internal_obligations"]:
        lines.append("  open internal obligations (repository evidence required):")
        for row in report["open_internal_obligations"]:
            lines.append(
                f"    - {row['obligation_id']} [{row['q_id']}] weight={row['weight']}/1000 "
                f"contribution_M={row['contribution_M']}"
            )
    lines.append(f"  note: {report['note']}")
    return "\n".join(lines)


def cmd_frontier(args: argparse.Namespace) -> int:
    registry = obligation_model.load_registry(DEFAULT_OBLIGATIONS)
    report = api.frontier_status(registry, weights_path=DEFAULT_WEIGHTS)
    if args.out:
        _json_dump(report, Path(args.out))
    if args.markdown_out:
        md = api.frontier_markdown(report)
        Path(args.markdown_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown_out).write_text(md if md.endswith("\n") else md + "\n", encoding="utf-8")
    if args.json:
        _json_dump(report, None)
    elif not args.out:
        print(_frontier_text(report))
    return 0


def cmd_attestation_template(args: argparse.Namespace) -> int:
    registry = obligation_model.load_registry(DEFAULT_OBLIGATIONS)
    harness_identity = registry["harness_identity"]
    external = {
        ob["id"]: ob
        for _, ob in obligation_model.iter_obligations(registry)
        if ob["scope"] == "external"
    }
    if args.obligation_id not in external:
        raise CommandError(
            f"{args.obligation_id} is not an external obligation. External obligations: "
            + ", ".join(sorted(external))
        )
    if not args.signer_id or args.signer_id == harness_identity:
        raise CommandError(
            "external attestations require a non-harness signer id "
            f"(must not be empty and must not equal {harness_identity!r})"
        )
    ob = external[args.obligation_id]
    template = {
        "attestation_version": "daylight-v15-meridian-external-attestation-v0.1",
        "entry_type": "external_attestation",
        "obligation_id": args.obligation_id,
        "external_role": ob.get("external_role", ""),
        "external_signer_id": args.signer_id,
        "scope": "external",
        "closes_obligations": [args.obligation_id],
        "artifact_digest_target": "<sha256 of the artifact the external party attested>",
        "transcript_reference": "<reference to the external transcript / report>",
        "created_utc": "2026-06-30",
        "signature_status": "unsigned-template",
        "boundary": (
            "This is an unsigned template. A real deployment must bind a genuine "
            "external signature from a non-harness signer. The harness cannot "
            "self-issue this attestation."
        ),
    }
    _json_dump(template, Path(args.out) if args.out else None)
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    scorecard = json.loads(Path(args.scorecard).read_text(encoding="utf-8"))
    registry = obligation_model.load_registry(DEFAULT_OBLIGATIONS)
    label_map = obligation_model.labels(registry)
    closed_by_q: dict[str, list[dict[str, Any]]] = {}
    for record in scorecard["closed_obligations"]:
        closed_by_q.setdefault(record["q_id"], []).append(record)
    open_by_q: dict[str, list[dict[str, Any]]] = {}
    for row in scorecard["open_obligations"]:
        open_by_q.setdefault(row["q_id"], []).append(row)

    evidence_by_digest: dict[str, str] = {}
    if args.ledger:
        for entry in ledger_model.load_jsonl(Path(args.ledger)):
            evidence_by_digest[entry.get("artifact_digest", "")] = entry.get("entry_id", "")
    if args.corpus:
        snapshot = corpus_model.freeze_path(Path(args.corpus))
        for entry in snapshot.get("entries", []):
            evidence_by_digest[entry.get("input_digest", "")] = entry.get("corpus_entry_id", "")

    q_values = {name: value for name, value in scorecard["q_vector"]}
    selected = list(obligation_model.Q_IDS)
    if args.dimension:
        selected = [q for q in selected if q == args.dimension]
        if not selected:
            raise CommandError(f"unknown dimension: {args.dimension}")

    lines = [f"{scorecard['candidate']} — final_score_M {scorecard['final_score_M']}/{scorecard['perfect_score_M']}", ""]
    for q_id in selected:
        if args.obligation_id and not any(
            r["obligation_id"] == args.obligation_id for r in closed_by_q.get(q_id, []) + open_by_q.get(q_id, [])
        ):
            continue
        lines.append(f"{q_id} ({label_map[q_id]}): q = {q_values.get(q_id, '0/1')}")
        for record in sorted(closed_by_q.get(q_id, []), key=lambda r: r["obligation_id"]):
            if args.obligation_id and record["obligation_id"] != args.obligation_id:
                continue
            ev = evidence_by_digest.get(record.get("evidence_digest", ""), record.get("evidence_digest", "")[:16])
            lines.append(
                f"    closed  {record['obligation_id']} (+{record['weight']}/1000, {record['scope']}) "
                f"via {record['evidence_class']} evidence {ev}"
            )
        for row in sorted(open_by_q.get(q_id, []), key=lambda r: r["obligation_id"]):
            if args.obligation_id and row["obligation_id"] != args.obligation_id:
                continue
            lines.append(
                f"    open    {row['obligation_id']} (-{row['weight']}/1000, {row['scope']}) "
                f"needs {row['evidence_class']} evidence"
            )
        lines.append("")
    print("\n".join(lines).rstrip())
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    scorecard = json.loads(Path(args.scorecard).read_text(encoding="utf-8"))
    result = api.verify_scorecard(
        scorecard,
        obligations_path=DEFAULT_OBLIGATIONS,
        ledger_path=Path(args.ledger) if args.ledger else None,
        corpus_path=Path(args.corpus) if args.corpus else None,
    )
    failures: list[str] = []
    if not result.ok:
        failures.append(f"verification failed: {result.error}")
    final_score = int(scorecard.get("final_score_M", -1))
    if args.min_score is not None and final_score < args.min_score:
        failures.append(f"final_score_M {final_score} < --min-score {args.min_score}")
    open_internal = [r for r in scorecard.get("open_obligations", []) if r["scope"] == "internal"]
    open_external = [r for r in scorecard.get("open_obligations", []) if r["scope"] == "external"]
    if args.require_no_open_internal and open_internal:
        failures.append(f"{len(open_internal)} open internal obligation(s): " + ", ".join(r["obligation_id"] for r in open_internal))
    if open_external and not args.allow_external_residue:
        failures.append(
            f"{len(open_external)} open external obligation(s) and --allow-external-residue not set"
        )

    print(f"gate: final_score_M={final_score} open_internal={len(open_internal)} open_external={len(open_external)}")
    print("gate boundary: this is research-evidence scoring, not certification or release authority.")
    if failures:
        for failure in failures:
            print(f"gate: FAIL - {failure}", file=sys.stderr)
        return 1
    print("gate: PASS")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []

    py_ok = sys.version_info >= (3, 10)
    checks.append(("python >= 3.10", py_ok, f"{sys.version_info.major}.{sys.version_info.minor}"))

    try:
        registry = obligation_model.load_registry(DEFAULT_OBLIGATIONS)
        digest = obligation_model.registry_digest(registry)
        checks.append(("obligation registry loads", True, digest[:16]))
    except Exception as exc:  # noqa: BLE001 - doctor reports any failure
        registry = None
        checks.append(("obligation registry loads", False, str(exc)))

    for label, path in (("ledger fixture", DEFAULT_LEDGER), ("corpus fixture", DEFAULT_CORPUS), ("weights", DEFAULT_WEIGHTS)):
        checks.append((f"{label} present", path.is_file(), str(path.name)))

    score_ok = False
    detail = "skipped"
    if registry is not None and DEFAULT_LEDGER.is_file() and DEFAULT_CORPUS.is_file():
        try:
            scorecard, _, _ = daylight_harness.generate_scorecard(
                ledger_path=DEFAULT_LEDGER, corpus_path=DEFAULT_CORPUS, command="doctor"
            )
            score_ok = scorecard["final_score_M"] == 998900
            detail = f"final_score_M={scorecard['final_score_M']}"
        except Exception as exc:  # noqa: BLE001
            detail = str(exc)
    checks.append(("seed score == 998900M", score_ok, detail))

    all_ok = True
    for label, ok, detail in checks:
        mark = "ok " if ok else "FAIL"
        all_ok = all_ok and ok
        print(f"[{mark}] {label}: {detail}")
    print("doctor: " + ("healthy" if all_ok else "problems found"))
    return 0 if all_ok else 1


def cmd_artifact(args: argparse.Namespace) -> int:
    manifest = artifact_builder.build_artifact(
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        out_dir=Path(args.out_dir),
        command_label=args.command_label,
        weights_path=DEFAULT_WEIGHTS,
        obligations_path=DEFAULT_OBLIGATIONS,
    )
    print(f"artifact written to {args.out_dir}")
    print(f"  final_score_M: {manifest['final_score_M']} / {manifest['perfect_score_M']}")
    print(f"  external_residue_M: {manifest['external_residue_M']}")
    print(f"  scorecard_digest: {manifest['scorecard_digest']}")
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
        self_signed_external_attestation=args.self_signed_external,
    )
    _json_dump(result, None)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-meridian", description="Daylight v15 Meridian execution package")
    parser.add_argument("--version", action="version", version=f"daylight-meridian {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-ledger", help="write an empty ledger and print the genesis head")
    init.add_argument("--out", default=str(DEFAULT_LEDGER))
    init.set_defaults(func=cmd_init_ledger)

    append = sub.add_parser("append-entry", help="append a witnessed evidence entry to a ledger")
    append.add_argument("--ledger", required=True)
    append.add_argument("--type", required=True)
    append.add_argument("--artifact", required=True)
    append.add_argument("--witness", required=True)
    append.add_argument("--closes", nargs="*", default=[])
    append.add_argument("--external-signer", default=None)
    append.set_defaults(func=cmd_append_entry)

    freeze = sub.add_parser("freeze-corpus", help="freeze a negative-evidence corpus snapshot")
    freeze.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    freeze.add_argument("--out")
    freeze.set_defaults(func=cmd_freeze_corpus)

    score = sub.add_parser("score", help="derive the evidence-bound scorecard from frozen inputs")
    score.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    score.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    score.add_argument("--out")
    score.add_argument("--receipt")
    score.add_argument("--output-ledger")
    score.add_argument("--format", choices=["json", "text"], default="json")
    score.set_defaults(func=cmd_score)

    verify = sub.add_parser("verify-scorecard", help="verify a scorecard; re-derives q from obligations")
    verify.add_argument("scorecard")
    verify.add_argument("--ledger")
    verify.add_argument("--corpus")
    verify.add_argument("--strict", action="store_true", help="require an evidence-bound check (--ledger and --corpus)")
    verify.set_defaults(func=cmd_verify_scorecard)

    frontier = sub.add_parser("frontier", help="print internal ceiling, residue, and the external frontier")
    frontier.add_argument("--json", action="store_true", help="print the frontier report as JSON")
    frontier.add_argument("--out", help="write the frontier report JSON to a path")
    frontier.add_argument("--markdown-out", help="write the frontier report Markdown to a path")
    frontier.set_defaults(func=cmd_frontier)

    template = sub.add_parser("attestation-template", help="emit an unsigned external-attestation template")
    template.add_argument("--obligation-id", required=True)
    template.add_argument("--signer-id", required=True)
    template.add_argument("--out")
    template.set_defaults(func=cmd_attestation_template)

    explain = sub.add_parser("explain", help="explain why each q-value has its value")
    explain.add_argument("--scorecard", required=True)
    explain.add_argument("--obligation-id")
    explain.add_argument("--dimension")
    explain.add_argument("--ledger")
    explain.add_argument("--corpus")
    explain.set_defaults(func=cmd_explain)

    gate = sub.add_parser("gate", help="release/CI gate over a verified scorecard")
    gate.add_argument("--scorecard", required=True)
    gate.add_argument("--ledger")
    gate.add_argument("--corpus")
    gate.add_argument("--min-score", type=int)
    gate.add_argument("--require-no-open-internal", action="store_true")
    gate.add_argument("--allow-external-residue", action="store_true")
    gate.set_defaults(func=cmd_gate)

    doctor = sub.add_parser("doctor", help="self-check the installation and fixtures")
    doctor.set_defaults(func=cmd_doctor)

    artifact_cmd = sub.add_parser("artifact", help="build the deterministic release artifact directory")
    artifact_cmd.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    artifact_cmd.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    artifact_cmd.add_argument("--out-dir", default=str(DEFAULT_ARTIFACT_DIR))
    artifact_cmd.add_argument("--command-label", default="make daylight-meridian-artifact")
    artifact_cmd.set_defaults(func=cmd_artifact)

    check = sub.add_parser("check-downgrade", help="evaluate the downgrade machine")
    check.add_argument("--claimed", required=True)
    check.add_argument("--current", required=True)
    check.add_argument("--state", default="candidate")
    check.add_argument("--invalid-digest", action="store_true")
    check.add_argument("--invalid-trace", action="store_true")
    check.add_argument("--external-falsification", action="store_true")
    check.add_argument("--self-signed-external", action="store_true")
    check.set_defaults(func=cmd_check_downgrade)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CommandError as exc:
        print(f"daylight-meridian: {exc}", file=sys.stderr)
        return 1
    except CLI_ERRORS as exc:
        print(f"daylight-meridian: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
