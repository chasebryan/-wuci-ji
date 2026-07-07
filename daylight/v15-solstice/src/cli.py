"""Command-line interface for the Daylight v15+ Solstice execution package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from . import artifact_verify
from . import corpus as corpus_model
from . import external_attestation
from . import ledger as ledger_model
from . import obligations as obligation_model
from . import scoring
from . import semantic_evidence
from . import solstice_harness
from .canonical_json import CanonicalJSONError, canonical_sha256, load_json_file_no_duplicates


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
DEFAULT_OBLIGATIONS = PACKAGE_ROOT / "rules" / "obligations.v15.json"
DEFAULT_ROOTSET = PACKAGE_ROOT / "rules" / "external-rootset.solstice.json"
DEFAULT_LEDGER = PACKAGE_ROOT / "examples" / "ledger.seed.jsonl"
DEFAULT_CORPUS = PACKAGE_ROOT / "examples" / "corpus.seed.jsonl"
DEFAULT_ARTIFACT_DIR = PACKAGE_ROOT.parents[1] / "build" / "daylight" / "v15-solstice"

CLI_ERRORS = (
    artifact_verify.ArtifactError,
    corpus_model.CorpusError,
    external_attestation.ExternalAttestationError,
    ledger_model.LedgerError,
    obligation_model.ObligationError,
    scoring.ScoreError,
    semantic_evidence.SemanticEvidenceError,
    solstice_harness.SolsticeError,
    CanonicalJSONError,
    FileNotFoundError,
)


class CommandError(Exception):
    pass


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
    witness = load_json_file_no_duplicates(Path(args.witness), "Solstice witness")
    digest = canonical_sha256({"artifact": args.artifact}, "DAYLIGHT-v15-SOLSTICE-CLI-ARTIFACT:")
    entries, head = ledger_model.append_entry(
        entries,
        entry_type=args.type,
        artifact_digest=digest,
        witness=witness,
        transcript_digest=canonical_sha256(
            {"type": args.type, "artifact": args.artifact},
            "DAYLIGHT-v15-SOLSTICE-CLI-TRANSCRIPT:",
        ),
        closes_obligations=args.closes or [],
        external_signer_id=args.external_signer,
    )
    ledger_model.write_jsonl(path, entries)
    print(head)
    return 0


def cmd_freeze_corpus(args: argparse.Namespace) -> int:
    _json_dump(corpus_model.freeze_path(Path(args.corpus)), Path(args.out) if args.out else None)
    return 0


def _rootset_arg(value: str | None) -> Path | None:
    return Path(value) if value else None


def _score_text(scorecard: dict[str, Any]) -> str:
    body = scorecard["score_body"]
    closed = len(body["closed_obligations"])
    open_total = len(body["open_obligations"])
    open_external = sum(1 for row in body["open_obligations"] if row["scope"] == "external")
    return (
        f"{scorecard['candidate']}\n"
        f"  final_score_M:   {body['final_score_M']} / {body['perfect_score_M']}\n"
        f"  unified:         {body['unified_score_decimal']}\n"
        f"  status:          {scorecard['status']}\n"
        f"  closed:          {closed} obligations\n"
        f"  open:            {open_total} ({open_external} external)\n"
        f"  residue_to_perfect_M: {body['residue_to_perfect_M']}"
    )


def cmd_score(args: argparse.Namespace) -> int:
    scorecard, receipt, output_ledger = solstice_harness.generate_scorecard(
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        weights_path=DEFAULT_WEIGHTS,
        obligations_path=DEFAULT_OBLIGATIONS,
        rootset_path=_rootset_arg(args.rootset),
        command="score",
    )
    if args.out:
        _json_dump(scorecard, Path(args.out))
    if args.receipt:
        _json_dump(receipt, Path(args.receipt))
    if args.output_ledger:
        ledger_model.write_jsonl(Path(args.output_ledger), output_ledger)
    if args.format == "text":
        print(_score_text(scorecard))
    elif not args.out:
        _json_dump(scorecard, None)
    return 0


def cmd_verify_scorecard(args: argparse.Namespace) -> int:
    if not (args.ledger and args.corpus and args.output_ledger):
        raise CommandError("Solstice verification requires --ledger, --corpus, and --output-ledger")
    receipt = load_json_file_no_duplicates(Path(args.receipt), "Solstice receipt") if args.receipt else None
    solstice_harness.verify_scorecard(
        load_json_file_no_duplicates(Path(args.scorecard), "Solstice scorecard"),
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        output_ledger_path=Path(args.output_ledger),
        weights_path=DEFAULT_WEIGHTS,
        obligations_path=DEFAULT_OBLIGATIONS,
        rootset_path=_rootset_arg(args.rootset),
        receipt=receipt,
    )
    print("scorecard: pass (solstice hermetic)")
    return 0


def _frontier_text(report: dict[str, Any]) -> str:
    lines = [
        "Daylight v15+ Solstice frontier",
        f"  internal_ceiling_M:           {report['internal_ceiling_M']} / {report['perfect_score_M']}",
        f"  external_residue_M:            {report['external_residue_M']}",
        f"  open_internal_residue_M:       {report['open_internal_residue_M']}",
        f"  open_external_residue_M:       {report['open_external_residue_M']}",
        "  external obligations (independent attestation required):",
    ]
    for row in [r for r in report["open_obligations"] if r["scope"] == "external"]:
        lines.append(
            f"    - {row['obligation_id']} [{row['q_id']}] weight={row['weight']}/1000 "
            f"role={row.get('external_role', '')}"
        )
    open_internal = [r for r in report["open_obligations"] if r["scope"] == "internal"]
    if open_internal:
        lines.append("  open internal obligations (repository evidence required):")
        for row in open_internal:
            lines.append(f"    - {row['obligation_id']} [{row['q_id']}] weight={row['weight']}/1000")
    return "\n".join(lines)


def cmd_frontier(args: argparse.Namespace) -> int:
    scorecard, _, _ = solstice_harness.generate_scorecard(
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        weights_path=DEFAULT_WEIGHTS,
        obligations_path=DEFAULT_OBLIGATIONS,
        rootset_path=_rootset_arg(args.rootset),
        command="frontier",
    )
    report = artifact_verify._frontier_report(scorecard)
    if args.out:
        _json_dump(report, Path(args.out))
    if args.markdown_out:
        Path(args.markdown_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown_out).write_text("```text\n" + _frontier_text(report) + "\n```\n", encoding="utf-8")
    if args.json:
        _json_dump(report, None)
    elif not args.out:
        print(_frontier_text(report))
    return 0


def cmd_attestation_template(args: argparse.Namespace) -> int:
    registry = obligation_model.load_registry(DEFAULT_OBLIGATIONS)
    external = {
        ob["id"]: ob
        for _, ob in obligation_model.iter_obligations(registry)
        if ob["scope"] == "external"
    }
    if args.obligation_id not in external:
        raise CommandError("unknown external obligation: " + args.obligation_id)
    harness_identity = registry["harness_identity"]
    if not args.signer_id or args.signer_id == harness_identity:
        raise CommandError(f"external signer must be non-empty and not {harness_identity!r}")
    ob = external[args.obligation_id]
    template = {
        "attestation_version": external_attestation.ATTESTATION_VERSION,
        "obligation_id": args.obligation_id,
        "external_role": ob["external_role"],
        "external_signer_id": args.signer_id,
        "reviewer_identity": "<reviewer identity>",
        "root_key_digest": "<sha256 of external root key>",
        "reviewed_commit": external_attestation.ZERO_COMMIT,
        "report_digest": "<sha256 of report>",
        "artifact_digest_target": "<sha256 of reviewed artifact>",
        "transcript_reference": "<external report/transcript reference>",
        "signature_namespace": external_attestation.SIGNATURE_NAMESPACE,
        "signature": "<signature over canonical attestation payload>",
        "fixture_material_used": False,
        "network_required": False,
        "offensive_tooling_included": False,
        "non_claims": [
            "not production authority",
            "not runtime containment",
            "not whole-system post-quantum safety",
        ],
    }
    _json_dump(template, Path(args.out) if args.out else None)
    return 0


def cmd_artifact(args: argparse.Namespace) -> int:
    manifest = artifact_verify.build_artifact(
        ledger_path=Path(args.ledger),
        corpus_path=Path(args.corpus),
        out_dir=Path(args.out_dir),
        command_label=args.command_label,
        weights_path=DEFAULT_WEIGHTS,
        obligations_path=DEFAULT_OBLIGATIONS,
        rootset_path=_rootset_arg(args.rootset),
    )
    print(f"artifact written to {args.out_dir}")
    print(f"  final_score_M: {manifest['final_score_M']} / 1000000")
    print(f"  external_residue_M: {manifest['external_residue_M']}")
    print(f"  scorecard_digest: {manifest['scorecard_digest']}")
    return 0


def cmd_verify_artifact(args: argparse.Namespace) -> int:
    artifact_verify.verify_artifact_dir(Path(args.artifact_dir))
    print("artifact: pass")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-solstice", description="Daylight v15+ Solstice execution package")
    parser.add_argument("--version", action="version", version=f"daylight-solstice {__version__}")
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
    append.add_argument("--external-signer")
    append.set_defaults(func=cmd_append_entry)

    freeze = sub.add_parser("freeze-corpus", help="freeze a negative-evidence corpus snapshot")
    freeze.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    freeze.add_argument("--out")
    freeze.set_defaults(func=cmd_freeze_corpus)

    score = sub.add_parser("score", help="derive the Solstice scorecard from frozen inputs")
    score.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    score.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    score.add_argument("--rootset", default=str(DEFAULT_ROOTSET))
    score.add_argument("--out")
    score.add_argument("--receipt")
    score.add_argument("--output-ledger")
    score.add_argument("--format", choices=["json", "text"], default="json")
    score.set_defaults(func=cmd_score)

    verify = sub.add_parser("verify-scorecard", help="verify scorecard, receipt, evidence, and output-ledger transition")
    verify.add_argument("scorecard")
    verify.add_argument("--ledger", required=True)
    verify.add_argument("--corpus", required=True)
    verify.add_argument("--output-ledger", required=True)
    verify.add_argument("--receipt")
    verify.add_argument("--rootset", default=str(DEFAULT_ROOTSET))
    verify.set_defaults(func=cmd_verify_scorecard)

    frontier = sub.add_parser("frontier", help="print internal ceiling and external frontier")
    frontier.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    frontier.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    frontier.add_argument("--rootset", default=str(DEFAULT_ROOTSET))
    frontier.add_argument("--json", action="store_true")
    frontier.add_argument("--out")
    frontier.add_argument("--markdown-out")
    frontier.set_defaults(func=cmd_frontier)

    template = sub.add_parser("attestation-template", help="emit an unsigned external-attestation template")
    template.add_argument("--obligation-id", required=True)
    template.add_argument("--signer-id", required=True)
    template.add_argument("--out")
    template.set_defaults(func=cmd_attestation_template)

    artifact = sub.add_parser("artifact", help="build the deterministic Solstice artifact directory")
    artifact.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    artifact.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    artifact.add_argument("--rootset", default=str(DEFAULT_ROOTSET))
    artifact.add_argument("--out-dir", default=str(DEFAULT_ARTIFACT_DIR))
    artifact.add_argument("--command-label", default="make daylight-solstice-artifact")
    artifact.set_defaults(func=cmd_artifact)

    verify_artifact = sub.add_parser("verify-artifact", help="verify a Solstice artifact directory")
    verify_artifact.add_argument("artifact_dir")
    verify_artifact.set_defaults(func=cmd_verify_artifact)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CommandError as exc:
        print(f"daylight-solstice: {exc}", file=sys.stderr)
        return 1
    except CLI_ERRORS as exc:
        print(f"daylight-solstice: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
