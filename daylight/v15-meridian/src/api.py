"""Stable public library API for Daylight v15 Meridian.

This is the import surface third parties should use. It is a thin, documented
facade over the internal modules (:mod:`src.obligations`, :mod:`src.scoring`,
:mod:`src.ledger`, :mod:`src.corpus`, :mod:`src.daylight_harness`). All
score-critical arithmetic stays exact (``fractions.Fraction`` / integers); no
floating point is used on the scoring path.

Example
-------
    from src import api

    registry = api.load_registry(api.DEFAULT_OBLIGATIONS)
    ledger = api.load_ledger("examples/ledger.seed.jsonl")
    corpus = api.load_corpus("examples/corpus.seed.jsonl")
    closed = api.resolve_closed_obligations(registry, ledger, corpus)
    q_vector = api.derive_q_vector(registry, closed)
    score = api.score_q_vector(q_vector, api.load_weights(api.DEFAULT_WEIGHTS),
                               api.labels(registry))
    print(score["final_score_M"])  # 998900
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import __version__
from . import corpus as _corpus
from . import daylight_harness as _harness
from . import ledger as _ledger
from . import obligations as _obligations
from . import scoring as _scoring

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHTS = PACKAGE_ROOT / "rules" / "weights.v13.json"
DEFAULT_OBLIGATIONS = PACKAGE_ROOT / "rules" / "obligations.v15.json"
PERFECT_SCORE_M = _scoring.M_SCALE

# Type aliases (structural; the underlying values are plain dict/list/tuple).
ObligationRegistry = dict
EvidenceEntry = dict
CorpusEntry = dict
CorpusSnapshot = dict
ClosedObligationSet = dict
QVector = list
Score = dict
Scorecard = dict

__all__ = [
    "__version__",
    "DEFAULT_WEIGHTS",
    "DEFAULT_OBLIGATIONS",
    "PERFECT_SCORE_M",
    "VerificationResult",
    "load_registry",
    "registry_digest",
    "labels",
    "load_weights",
    "load_ledger",
    "ledger_head",
    "load_corpus",
    "freeze_corpus",
    "resolve_closed_obligations",
    "derive_q_vector",
    "score_q_vector",
    "generate_scorecard",
    "verify_scorecard",
    "frontier_status",
    "frontier_markdown",
]


class VerificationResult:
    """Outcome of :func:`verify_scorecard` (does not raise on a failed score)."""

    def __init__(self, ok: bool, error: str | None = None, evidence_bound: bool = False) -> None:
        self.ok = ok
        self.error = error
        self.evidence_bound = evidence_bound

    def __bool__(self) -> bool:
        return self.ok

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "error": self.error, "evidence_bound": self.evidence_bound}

    def __repr__(self) -> str:
        return f"VerificationResult(ok={self.ok!r}, error={self.error!r}, evidence_bound={self.evidence_bound!r})"


def load_registry(path: Path | str = DEFAULT_OBLIGATIONS) -> ObligationRegistry:
    return _obligations.load_registry(Path(path))


def registry_digest(registry: ObligationRegistry) -> str:
    return _obligations.registry_digest(registry)


def labels(registry: ObligationRegistry) -> dict[str, str]:
    return _obligations.labels(registry)


def load_weights(path: Path | str = DEFAULT_WEIGHTS) -> list[tuple[str, Fraction]]:
    return _scoring.load_weights(Path(path))


def load_ledger(path: Path | str) -> list[EvidenceEntry]:
    return _ledger.load_jsonl(Path(path))


def ledger_head(path: Path | str) -> tuple[list[EvidenceEntry], str]:
    return _ledger.frozen_head(Path(path))


def load_corpus(path: Path | str) -> list[CorpusEntry]:
    return _corpus.load_jsonl(Path(path))


def freeze_corpus(entries: Iterable[CorpusEntry]) -> CorpusSnapshot:
    return _corpus.freeze_corpus(entries)


def resolve_closed_obligations(
    registry: ObligationRegistry,
    ledger: list[EvidenceEntry],
    corpus: list[CorpusEntry] | CorpusSnapshot,
    harness_identity: str | None = None,
) -> ClosedObligationSet:
    """Resolve which obligations the evidence closes.

    ``corpus`` may be a raw entry list or an already-frozen snapshot. The
    ``harness_identity`` argument is accepted for explicitness; if given it must
    match the registry's identity (the self-signed-external rule is keyed off the
    registry, which is the single source of truth).
    """
    if harness_identity is not None and harness_identity != registry.get("harness_identity"):
        raise _obligations.ObligationError("harness_identity does not match the registry")
    snapshot = corpus if isinstance(corpus, dict) and corpus.get("frozen") else _corpus.freeze_corpus(corpus)
    return _obligations.resolve_closed_obligations(registry, ledger, snapshot)


def derive_q_vector(registry: ObligationRegistry, closed: ClosedObligationSet | Iterable[str]) -> QVector:
    closed_ids = closed.keys() if isinstance(closed, dict) else closed
    return _obligations.derive_q_vector(registry, closed_ids)


def score_q_vector(
    q_vector: QVector,
    weights: Iterable[tuple[str, Any]],
    labels_map: Mapping[str, str] | None = None,
) -> Score:
    return _scoring.compute_score(q_vector, weights, labels_map)


def generate_scorecard(
    *,
    ledger_path: Path | str,
    corpus_path: Path | str,
    weights_path: Path | str = DEFAULT_WEIGHTS,
    obligations_path: Path | str = DEFAULT_OBLIGATIONS,
    command: str = "api",
) -> tuple[Scorecard, dict[str, Any], list[EvidenceEntry]]:
    return _harness.generate_scorecard(
        ledger_path=Path(ledger_path),
        corpus_path=Path(corpus_path),
        weights_path=Path(weights_path),
        obligations_path=Path(obligations_path),
        command=command,
    )


def verify_scorecard(
    scorecard: Scorecard,
    *,
    obligations_path: Path | str = DEFAULT_OBLIGATIONS,
    ledger_path: Path | str | None = None,
    corpus_path: Path | str | None = None,
) -> VerificationResult:
    """Verify a scorecard and return a result instead of raising.

    When ``ledger_path`` and ``corpus_path`` are supplied the check is
    evidence-bound: the closed-obligation set must match what the evidence
    actually closes.
    """
    evidence_bound = ledger_path is not None and corpus_path is not None
    try:
        _harness.verify_scorecard(
            scorecard,
            obligations_path=Path(obligations_path),
            ledger_path=Path(ledger_path) if ledger_path is not None else None,
            corpus_path=Path(corpus_path) if corpus_path is not None else None,
        )
    except (_harness.HarnessError, _obligations.ObligationError, _scoring.ScoreError, _ledger.LedgerError, _corpus.CorpusError) as exc:
        return VerificationResult(ok=False, error=str(exc), evidence_bound=evidence_bound)
    return VerificationResult(ok=True, error=None, evidence_bound=evidence_bound)


def frontier_status(
    registry: ObligationRegistry,
    closed: ClosedObligationSet | Iterable[str] | None = None,
    *,
    weights_path: Path | str = DEFAULT_WEIGHTS,
) -> dict[str, Any]:
    """Report the internal ceiling, perfect score, and the external frontier.

    When ``closed`` is given, also report the residue still open relative to the
    current evidence; otherwise report the structural internal-ceiling frontier.
    """
    weights = _scoring.load_weights(Path(weights_path))
    label_map = _obligations.labels(registry)
    internal = _scoring.compute_score(_obligations.internal_ceiling_q_vector(registry), weights, label_map)
    perfect = _scoring.compute_score(_obligations.perfect_q_vector(registry), weights, label_map)
    weight_by_q = {name: value for name, value in weights}

    internal_open: list[dict[str, Any]] = []
    external_open: list[dict[str, Any]] = []
    if closed is not None:
        closed_ids = set(closed.keys() if isinstance(closed, dict) else closed)
    else:
        closed_ids = {ob["id"] for _, ob in _obligations.iter_obligations(registry) if ob["scope"] == "internal"}

    for q_id, ob in _obligations.iter_obligations(registry):
        if ob["id"] in closed_ids:
            continue
        contribution_M = int(weight_by_q[q_id] * _scoring.M_SCALE) * int(ob["weight"]) // _obligations.DIMENSION_THOUSANDTHS
        row = {
            "obligation_id": ob["id"],
            "q_id": q_id,
            "weight": int(ob["weight"]),
            "contribution_M": contribution_M,
            "external_role": ob.get("external_role", ""),
        }
        (external_open if ob["scope"] == "external" else internal_open).append(row)

    internal_open.sort(key=lambda r: r["obligation_id"])
    external_open.sort(key=lambda r: r["obligation_id"])
    open_external_residue_M = sum(r["contribution_M"] for r in external_open)
    open_internal_residue_M = sum(r["contribution_M"] for r in internal_open)

    return {
        "report_version": "daylight-v15-meridian-frontier-report-v0.1",
        "obligations_version": registry["version"],
        "obligations_digest": _obligations.registry_digest(registry),
        "internal_ceiling_M": internal["final_score_M"],
        "perfect_score_M": perfect["final_score_M"],
        "structural_external_residue_M": perfect["final_score_M"] - internal["final_score_M"],
        "open_internal_residue_M": open_internal_residue_M,
        "open_external_residue_M": open_external_residue_M,
        "open_internal_obligations": internal_open,
        "open_external_obligations": external_open,
        "note": (
            "Internal obligations are closeable by repository evidence. External "
            "obligations are closeable only by a genuine non-harness external "
            "attestation; the harness cannot self-certify them. A perfect "
            "1,000,000M requires every external obligation to be independently "
            "attested."
        ),
    }


def frontier_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Daylight v15 Meridian Frontier Report",
        "",
        f"- Obligations version: `{report['obligations_version']}`",
        f"- Obligations digest: `{report['obligations_digest']}`",
        f"- Internal ceiling: `{report['internal_ceiling_M']}M / {report['perfect_score_M']}M`",
        f"- Structural external residue: `{report['structural_external_residue_M']}M`",
        f"- Open internal residue (this evidence): `{report['open_internal_residue_M']}M`",
        f"- Open external residue (this evidence): `{report['open_external_residue_M']}M`",
        "",
        "## Open external obligations (independent attestation required)",
        "",
        "| Obligation | Dimension | Weight (‰) | Contribution (M) | External role |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["open_external_obligations"]:
        lines.append(
            f"| `{row['obligation_id']}` | {row['q_id']} | {row['weight']} | {row['contribution_M']} | {row['external_role']} |"
        )
    if report["open_internal_obligations"]:
        lines += [
            "",
            "## Open internal obligations (repository evidence required)",
            "",
            "| Obligation | Dimension | Weight (‰) | Contribution (M) |",
            "| --- | --- | --- | --- |",
        ]
        for row in report["open_internal_obligations"]:
            lines.append(
                f"| `{row['obligation_id']}` | {row['q_id']} | {row['weight']} | {row['contribution_M']} |"
            )
    lines += ["", "> " + report["note"], ""]
    return "\n".join(lines)
