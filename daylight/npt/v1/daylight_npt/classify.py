"""Classify extracted numeric tokens into DaylightNPT findings."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import re
from pathlib import Path
from typing import Any

from .evidence import digest_literal_valid, evaluate_claim
from .extract import NumberToken
from .registry import matching_claims

FINDING_EXPLANATIONS = {
    "NPT001_UNSUPPORTED_NUMERIC_CLAIM": "A numeric claim appears in claim context without registered evidence or a narrow exemption.",
    "NPT002_EVIDENCE_MISMATCH": "A registered numeric claim did not match its evidence check.",
    "NPT003_PERCENT_RATIO_MISMATCH": "A percentage does not recompute from the adjacent numerator and denominator.",
    "NPT004_SCORE_NOT_GENERATED": "A score-like value is asserted without generated machine-readable evidence.",
    "NPT005_QUORUM_MISMATCH": "A quorum value conflicts with the registered or stated contract.",
    "NPT006_VERSION_DRIFT": "A version claim does not match the bound path or context.",
    "NPT007_INVALID_DIGEST_LITERAL": "A digest literal is malformed for the declared digest algorithm.",
    "NPT008_FALSE_PRECISION": "A high-precision number is asserted without a method and evidence boundary.",
    "NPT009_MANUAL_SCORE_ASSERTION": "A score is manually asserted from prose rather than generated evidence.",
    "NPT010_VOLATILE_PUBLIC_COUNT": "A volatile public count lacks as-of evidence and source binding.",
    "NPT011_REGISTRY_ENTRY_STALE": "A registry entry is stale or no longer matches its evidence.",
    "NPT012_AMBIGUOUS_NUMERIC_CLAIM": "A numeric claim is ambiguous and should be narrowed or marked non-claim.",
    "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION": "Numeric claims are paired with unsupported certification, audit, endorsement, or universal-standard language.",
}

CLAIM_WORDS = re.compile(
    r"\b(scores?|percentage|percent|ratio|quorum|version|claims?|proves?|accurate|precision|precise|standard|best|perfect|rating|rank)\b",
    re.IGNORECASE,
)
SCORE_WORDS = re.compile(r"\b(score|scorecard|M scale|AM\+|perfect)\b", re.IGNORECASE)
EVIDENCE_WORDS = re.compile(r"\b(generated|evidence|scorecard|artifact|digest|registered|recomput|verified|bound|non-claim|nonclaim|candidate)\b", re.IGNORECASE)
SCORE_BOUNDARY_WORDS = re.compile(
    r"\b(generated|regenerates?|evidence|scorecard|artifact|digest|registered|recomput|verified|bound|candidate|satisfies|policy|reachable|required|requires|closing|external|ceiling|target|gap|rejects?|collapse|formula|checks?|fixture|maximum|declared|reserved|current truthful|internal ceiling)\b",
    re.IGNORECASE,
)
NO_EVIDENCE_WORDS = re.compile(r"\b(unsupported|manual|prose only|no generated evidence|no evidence|without\s+\w+\s+evidence|without evidence)\b", re.IGNORECASE)
NEGATION_WORDS = re.compile(r"\b(not|does not|must not|no |without|non-claim|nonclaim|refuses?|rejects?|blocked|incomplete)\b", re.IGNORECASE)
VOLATILE_WORDS = re.compile(r"\b(current|latest|live|today|now|public|github)\b.*\b(commits?|stars?|forks?|downloads?|issues?|pull requests?|PRs?)\b", re.IGNORECASE)
CERTIFICATION_WORDS = re.compile(
    r"\b(certif(?:y|ies|ied|ication)|audit(?:ed| status)?|production ready|production readiness|post-quantum secure|government|agency|agencies|endorsement|endorsed|approval|validated|official|universal|universally accurate|all AI number data|all numbers|standards? AI|standard for all AI|as precise as current technology allows)\b",
    re.IGNORECASE,
)
METHOD_WORDS = re.compile(r"\b(method|evidence source|source|recomputation path|recomput|limitation boundary|boundary)\b", re.IGNORECASE)
RATIO_PERCENT_RE = re.compile(
    r"(?P<num>\d[\d,]*(?:\.\d+)?)\s*/\s*(?P<den>\d[\d,]*(?:\.\d+)?)\s*(?:equals|=|is)?\s*(?P<pct>\d[\d,]*(?:\.\d+)?)%",
    re.IGNORECASE,
)
QUORUM_RE = re.compile(r"\b(?P<a>\d+)\s*(?:-of-| of )\s*(?P<b>\d+)\b")


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    path: str
    line: int
    column: int
    value_raw: str
    value_canonical: str
    claim_type: str
    context: str
    reason: str
    suggested_fix: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "value_raw": self.value_raw,
            "value_canonical": self.value_canonical,
            "claim_type": self.claim_type,
            "context": self.context,
            "reason": self.reason,
            "suggested_fix": self.suggested_fix,
        }


def _finding(token: NumberToken, code: str, claim_type: str, reason: str, fix: str, severity: str = "error") -> Finding:
    return Finding(
        code=code,
        severity=severity,
        path=token.path,
        line=token.line,
        column=token.column,
        value_raw=token.value_raw,
        value_canonical=token.value_canonical,
        claim_type=claim_type,
        context=token.context,
        reason=reason,
        suggested_fix=fix,
    )


def claim_type(token: NumberToken) -> str:
    if token.kind == "score":
        return "score"
    if token.kind == "percent":
        return "percent"
    if token.kind == "quorum":
        return "quorum"
    if token.kind == "version":
        return "version"
    if token.kind == "digest":
        return "digest"
    if token.kind == "date":
        return "date"
    if token.kind == "ratio":
        return "percent"
    if VOLATILE_WORDS.search(token.context):
        return "count"
    return "other"


def _decimal(text: str) -> Decimal:
    return Decimal(text.replace(",", "").strip())


def line_has_percent_mismatch(context: str) -> bool:
    for match in RATIO_PERCENT_RE.finditer(context):
        try:
            num = _decimal(match.group("num"))
            den = _decimal(match.group("den"))
            pct = _decimal(match.group("pct"))
        except (InvalidOperation, ZeroDivisionError):
            continue
        actual = num / den * Decimal("100")
        tolerance = Decimal("0.005")
        if abs(actual - pct) > tolerance:
            return True
    return False


def _safe_exempt(token: NumberToken) -> bool:
    line = token.context
    stripped = line.lstrip()
    if token.path.endswith(".json") and token.kind != "digest":
        return True
    if token.value_raw in {"256", "512"} and re.search(r"\b(?:SHA-256|SHA3-512|AES-256)\b", line):
        return True
    if re.match(r"^0\d+$", token.value_raw):
        return True
    if "`--" in line or "min_score_M" in line:
        return True
    if re.match(r"^\d+[.)]\s+", stripped) and token.column <= len(line) - len(stripped) + 3:
        return True
    if re.match(r"^#{1,6}\s+\d+(?:\.\d+)*\b", stripped):
        return True
    before = line[: max(0, token.column - 2)]
    after = line[token.column - 1 + len(token.value_raw) :]
    if (before.endswith("/") or before.endswith("-") or before.endswith("_")) and not CLAIM_WORDS.search(line):
        return True
    after_continues_path = after.startswith("/") or after.startswith("-") or (after.startswith(".") and len(after) > 1 and after[1].isalnum())
    if after_continues_path and token.kind in {"number", "version"} and not CLAIM_WORDS.search(line):
        return True
    if token.kind == "version" and not CERTIFICATION_WORDS.search(line) and not SCORE_WORDS.search(line):
        return True
    return False


def _has_full_precision_boundary(context: str) -> bool:
    lowered = context.lower()
    return (
        "method" in lowered
        and "evidence source" in lowered
        and "recomputation path" in lowered
        and "limitation boundary" in lowered
    )


def classify_token(token: NumberToken, registry: dict[str, Any], repo_root: Path) -> list[Finding]:
    ctype = claim_type(token)
    findings: list[Finding] = []
    matches = matching_claims(registry, token)
    if matches:
        for match in matches:
            ok, detail = evaluate_claim(match, repo_root)
            if ok:
                return []
            code = "NPT011_REGISTRY_ENTRY_STALE" if "stale" in match["id"].lower() else "NPT002_EVIDENCE_MISMATCH"
            findings.append(
                _finding(
                    token,
                    code,
                    ctype,
                    f"registry claim {match['id']} evidence check failed: {detail}",
                    "Regenerate the evidence artifact or update the claim to match the artifact.",
                )
            )
        return findings

    context = token.context
    if token.kind == "version" and (
        "version drift" in context.lower()
        or ("daylight/npt/v1" in context and token.value_raw not in {"v1.0.0"})
    ):
        return [
            _finding(
                token,
                "NPT006_VERSION_DRIFT",
                "version",
                "version text conflicts with the bound path or declared version context",
                "Update the version reference or bind it to the correct file/package/release path.",
            )
        ]

    if _safe_exempt(token):
        return []

    if token.kind == "digest":
        if not digest_literal_valid(token.value_raw):
            return [
                _finding(
                    token,
                    "NPT007_INVALID_DIGEST_LITERAL",
                    "digest",
                    "digest label is present but the literal has invalid length or non-hex bytes",
                    "Use a full SHA-256 64-hex or SHA3-512 128-hex digest, or remove the digest claim.",
                )
            ]
        return []

    if "as precise as current technology allows" in context.lower() and not _has_full_precision_boundary(context):
        findings.append(
            _finding(
                token,
                "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
                ctype,
                "precision-superlative wording lacks method, evidence source, recomputation path, and limitation boundary",
                "Replace the claim with evidence-bound precision language or add the required method, source, recomputation path, and limitation boundary.",
            )
        )

    precision_boundary_ok = "as precise as current technology allows" in context.lower() and _has_full_precision_boundary(context)
    if CERTIFICATION_WORDS.search(context) and CLAIM_WORDS.search(context) and not NEGATION_WORDS.search(context) and not precision_boundary_ok:
        findings.append(
            _finding(
                token,
                "NPT013_ENDORSEMENT_OR_CERTIFICATION_IMPLICATION",
                ctype,
                "numeric claim is paired with unsupported certification, audit, endorsement, approval, agency, or universal-standard language",
                "Remove certification/endorsement wording unless explicit external evidence is registered.",
            )
        )

    if token.kind in {"percent", "ratio"} and line_has_percent_mismatch(context):
        findings.append(
            _finding(
                token,
                "NPT003_PERCENT_RATIO_MISMATCH",
                "percent",
                "percentage does not recompute from the adjacent ratio",
                "Recompute the percentage from the exact numerator and denominator or register the evidence.",
            )
        )

    if token.kind == "quorum":
        match = QUORUM_RE.search(token.value_raw)
        if match and ("require" in context.lower() or "contract" in context.lower()) and match.group("a") != match.group("b"):
            findings.append(
                _finding(
                    token,
                    "NPT005_QUORUM_MISMATCH",
                    "quorum",
                    "quorum text conflicts with the exact contract requirement",
                    "Use the contract quorum or mark the text as a rejected/non-claim example.",
                )
            )

    if VOLATILE_WORDS.search(context) and not re.search(r"\bas[- ]of\b.*\b(evidence|source)\b", context, re.IGNORECASE):
        findings.append(
            _finding(
                token,
                "NPT010_VOLATILE_PUBLIC_COUNT",
                "count",
                "volatile public count lacks as-of evidence and source",
                "Add an as-of date plus source evidence, or remove the public count.",
            )
        )

    if token.kind == "number" and re.search(r"\b(about|around|roughly|approximately|approx\.?)\b", context, re.IGNORECASE) and CLAIM_WORDS.search(context):
        findings.append(
            _finding(
                token,
                "NPT012_AMBIGUOUS_NUMERIC_CLAIM",
                ctype,
                "ambiguous numeric claim uses approximate wording without a narrow non-claim exemption",
                "Replace the approximate number with evidence-bound precision or mark it as illustrative/non-claim.",
            )
        )

    score_like = token.kind == "score" or SCORE_WORDS.search(context)
    score_unsupported = bool(NO_EVIDENCE_WORDS.search(context)) or not SCORE_BOUNDARY_WORDS.search(context)
    if score_like and score_unsupported and not precision_boundary_ok:
        code = "NPT009_MANUAL_SCORE_ASSERTION" if re.search(r"\b(manual|prose only|perfect)\b", context, re.IGNORECASE) else "NPT004_SCORE_NOT_GENERATED"
        findings.append(
            _finding(
                token,
                code,
                "score",
                "score-like value is asserted without generated evidence language or registry evidence",
                "Bind the score to a generated artifact or mark it as a non-claim.",
            )
        )

    general_claim = re.search(r"\b(proves?|accurate|percentage|percent|ratio|quorum|rating|rank|probability|chance|standard)\b", context, re.IGNORECASE)
    if token.kind == "number" and not score_like and general_claim and (not EVIDENCE_WORDS.search(context) or NO_EVIDENCE_WORDS.search(context)) and (not NEGATION_WORDS.search(context) or NO_EVIDENCE_WORDS.search(context)):
        findings.append(
            _finding(
                token,
                "NPT001_UNSUPPORTED_NUMERIC_CLAIM",
                ctype,
                "number appears in claim context without evidence language or registry evidence",
                "Register evidence for this number or narrow it as a non-claim.",
            )
        )

    if token.kind == "number" and "." in token.value_raw and len(token.value_raw.rsplit(".", 1)[1]) > 4:
        if re.search(r"\b(probability|chance|confidence|rating|rank)\b", context, re.IGNORECASE) and (not METHOD_WORDS.search(context) or NO_EVIDENCE_WORDS.search(context) or "without" in context.lower()):
            findings.append(
                _finding(
                    token,
                    "NPT008_FALSE_PRECISION",
                    ctype,
                    "high-precision confidence number lacks method and evidence boundary",
                    "Round only to supported precision or register the method and evidence boundary.",
                )
            )

    unique: dict[tuple[str, int, int, str], Finding] = {}
    for finding in findings:
        unique[(finding.code, finding.line, finding.column, finding.value_raw)] = finding
    return list(unique.values())
