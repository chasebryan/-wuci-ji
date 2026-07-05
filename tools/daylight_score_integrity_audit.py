"""Daylight score-integrity audit report generator.

Recomputes or evidence-matches every distinct public Daylight / Wuci-Ji score
claim against committed repository evidence and writes four deterministic
reports under build/daylight/score-audit/. Uses only the Python standard
library, reads only git-tracked files, performs no network access, and embeds
no timestamps, hostnames, usernames, or absolute paths in its output.

This audit checks score integrity against repository evidence and original
claim boundaries. It does not certify security, production readiness, audit
status, post-quantum security, external endorsement, or mathematical finality.
"""

from __future__ import annotations

import json
import subprocess
import sys
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_UP, getcontext
from fractions import Fraction
from pathlib import Path

getcontext().prec = 100

SCHEMA_CLAIMS = "daylight.score_integrity.claims.v1"
SCHEMA_RATIO = "daylight.score_integrity.ratio_percent.v1"
SCHEMA_SURFACE = "daylight.score_integrity.public_surface.v1"
SCHEMA_REPORT = "daylight.score_integrity.report.v1"
OUT_DIR = Path("build/daylight/score-audit")

V14C_SCORECARD = "daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json"
V15_SCORECARD = "daylight/v15-meridian/examples/expected-scorecard.v15-meridian.json"
V17_CURRENT = "daylight/v17-singularity/examples/current-scorecard.v17.json"
V17_EXPECTED = "daylight/v17-singularity/examples/expected-scorecard.current.v17.json"
V20_CAPSULE = "daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json"
SITE_STATUS_V17 = "site/daylight-status.json"
SITE_STATUS_V20 = "site/daylight-v20-aperture-singularity-status.json"
SITE_CLAIM_EVIDENCE = "site/claim-evidence.json"
NPT_REPORT = "build/daylight/npt-v1/daylight-npt.report.json"
NPT_CLOSEOUT = "docs/DAYLIGHT_NPT_V1_CLOSEOUT.md"


def run_git(args: list[str]) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dumps_stable(data) -> str:
    return json.dumps(data, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def tracked_public_files() -> list[str]:
    names = run_git(["ls-files", "-z"]).split("\0")
    keep = []
    for name in names:
        if not name:
            continue
        if name.startswith("daylight/npt/v1/examples/"):
            continue
        if name.endswith((".md", ".json", ".html", ".txt")):
            keep.append(name)
    return sorted(keep)


def surface_bucket(path: str) -> str:
    if path == "README.md":
        return "readme"
    if path.startswith("site/"):
        return "site"
    if path.startswith("docs/"):
        return "docs"
    if path.startswith("daylight/"):
        return "family"
    return "other"


def find_locations(files: list[str], patterns: list[str]) -> list[dict]:
    out = []
    for name in files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if any(pattern in line for pattern in patterns):
                out.append({"path": name, "line": line_no, "surface": surface_bucket(name)})
                break
    return out


def score_from_omega(omega_text: str) -> int:
    omega = Decimal(omega_text)
    raw = Decimal(10**9) * (Decimal(1) - (-omega).exp())
    return int(raw.to_integral_value(rounding=ROUND_FLOOR))


def percent_of(numerator: str, denominator: str, places: int) -> str:
    value = Decimal(numerator) / Decimal(denominator) * Decimal(100)
    return str(value.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP))


RATIO_CASES = [
    {
        "id": "npt.fixture.recomputed_percent",
        "location": "daylight/npt/v1/examples/positive/recomputed-percent.md",
        "ratio_raw": "998,200 / 1,000,000",
        "numerator": "998200",
        "denominator": "1000000",
        "stated_percent": "99.82",
        "places": 2,
        "rounding_rule": "Decimal ROUND_HALF_UP at 2 places (documented in NPT json_ratio_percent)",
    },
    {
        "id": "v13.dominance_margin",
        "location": "docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
        "ratio_raw": "991300 / 962000 (margin over 1)",
        "numerator": "29300",
        "denominator": "962000",
        "stated_percent": "3.0457",
        "places": 4,
        "rounding_rule": "undocumented; matches Decimal ROUND_HALF_UP at 4 places",
    },
    {
        "id": "v13.gap_capture",
        "location": "docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
        "ratio_raw": "29300 / 38000",
        "numerator": "29300",
        "denominator": "38000",
        "stated_percent": "77.1053",
        "places": 4,
        "rounding_rule": "undocumented; matches Decimal ROUND_HALF_UP at 4 places",
    },
    {
        "id": "v16.analemma_proof_mass_growth",
        "location": "docs/WUCI_DAYLIGHT_V16_ANALEMMA.md",
        "ratio_raw": "120000 / 500000",
        "numerator": "120000",
        "denominator": "500000",
        "stated_percent": "24",
        "places": 0,
        "rounding_rule": "exact (no remainder)",
    },
]


def audit_ratios() -> list[dict]:
    out = []
    for case in RATIO_CASES:
        computed = percent_of(case["numerator"], case["denominator"], case["places"])
        stated = case["stated_percent"]
        out.append(
            {
                "id": case["id"],
                "location": case["location"],
                "ratio_raw": case["ratio_raw"],
                "numerator": case["numerator"],
                "denominator": case["denominator"],
                "computed_decimal": str(Decimal(case["numerator"]) / Decimal(case["denominator"])),
                "computed_percent": computed,
                "stated_percent": stated,
                "rounding_rule": case["rounding_rule"],
                "match": Decimal(computed) == Decimal(stated),
            }
        )
    return out


def check_v14c() -> tuple[str, dict]:
    sc = load_json(V14C_SCORECARD)
    contributions = sum(item["contribution_M"] for item in sc["term_contributions_M"])
    ok = (
        sc["final_score_M"] == 998200
        and contributions == sc["final_score_M"]
        and Fraction(sc["unified_score_rational"]) == Fraction(sc["final_score_M"], 1000000)
        and sc["manual_override"] is False
        and "CANDIDATE" in str(sc["candidate"])
    )
    return "PASS_RECOMPUTED" if ok else "FAIL_VALUE_MISMATCH", {
        "final_score_M": sc["final_score_M"],
        "sum_term_contributions_M": contributions,
        "unified_score_rational": sc["unified_score_rational"],
        "candidate_banner": sc["candidate"],
        "manual_override": sc["manual_override"],
    }


def check_v15() -> tuple[str, dict]:
    sc = load_json(V15_SCORECARD)
    contributions = sum(item["contribution_M"] for item in sc["term_contributions_M"])
    ok = (
        sc["final_score_M"] == 998900
        and contributions == sc["final_score_M"]
        and sc["perfect_score_M"] == 1000000
        and sc["residue_to_perfect_M"] == sc["perfect_score_M"] - sc["final_score_M"]
        and Fraction(sc["unified_score_rational"]) == Fraction(sc["final_score_M"], 1000000)
        and sc["manual_override"] is False
    )
    return "PASS_RECOMPUTED" if ok else "FAIL_VALUE_MISMATCH", {
        "final_score_M": sc["final_score_M"],
        "sum_term_contributions_M": contributions,
        "residue_to_perfect_M": sc["residue_to_perfect_M"],
        "closed_obligations": len(sc["closed_obligations"]),
        "open_obligations": len(sc["open_obligations"]),
    }


def check_v17() -> tuple[str, dict]:
    current = Path(V17_CURRENT).read_bytes()
    expected = Path(V17_EXPECTED).read_bytes()
    sc = json.loads(current)
    status = load_json(SITE_STATUS_V17)
    ok = (
        current == expected
        and sc["score_AM_plus"] == 999999687
        and status["score_AM_plus"] == sc["score_AM_plus"]
        and status.get("declared") is False
        and status.get("declaration_target_AM_plus") == 999999999
        and status.get("perfect_reserved_AM_plus") == 1000000000
        and status.get("scorecard_digest") == sc.get("scorecard_digest")
    )
    return "PASS_EVIDENCE_MATCH" if ok else "FAIL_VALUE_MISMATCH", {
        "score_AM_plus": sc["score_AM_plus"],
        "current_equals_expected_scorecard": current == expected,
        "site_status_score": status["score_AM_plus"],
        "declared": status.get("declared"),
        "scorecard_digest": sc.get("scorecard_digest"),
    }


def check_v20() -> tuple[str, dict]:
    capsule = load_json(V20_CAPSULE)
    status = load_json(SITE_STATUS_V20)
    recomputed = score_from_omega(capsule["omega_eff"])
    ok = (
        capsule["score_AM_plus"] == 999801305
        and recomputed == capsule["score_AM_plus"]
        and capsule["declaration_allowed"] is False
        and capsule["fixture"] is True
        and capsule["claim_usable"] is False
        and bool(capsule["blockers"])
        and status["score_AM_plus"] == capsule["score_AM_plus"]
        and status["capsule_digest"] == capsule["capsule_digest"]
        and status.get("declared") is False
        and status.get("repo_owned_ceiling_reached") is True
        and status.get("singularity_possible_without_external_validation") is False
        and status.get("highest_truthful_no_external_score_AM_plus") == capsule["score_AM_plus"]
        and status.get("repo_owned_code_gap_count") == 0
        and status.get("external_evidence_required_count") == 4
    )
    return "PASS_RECOMPUTED" if ok else "FAIL_VALUE_MISMATCH", {
        "score_AM_plus": capsule["score_AM_plus"],
        "recomputed_from_omega_eff": recomputed,
        "capsule_digest": capsule["capsule_digest"],
        "declaration_allowed": capsule["declaration_allowed"],
        "blocker_count": len(capsule["blockers"]),
        "site_status_matches_capsule": status["capsule_digest"] == capsule["capsule_digest"],
    }


def check_npt() -> tuple[str, dict]:
    if not Path(NPT_REPORT).is_file():
        return "UNRESOLVED_UNAVAILABLE_TARGET", {"reason": "run `make daylight-npt` before this audit"}
    report = load_json(NPT_REPORT)
    summary = report["summary"]
    closeout = Path(NPT_CLOSEOUT).read_text(encoding="utf-8")
    doc_ok = all(
        f"{key}: {summary[key]}" in closeout
        for key in ("claims_checked", "verified", "exempt", "warnings", "errors")
    )
    ok = report["result"] == "pass" and summary["errors"] == 0 and doc_ok
    return "PASS_EVIDENCE_MATCH" if ok else "FAIL_STALE_OR_DRIFTED_CLAIM", {
        "result": report["result"],
        "files_scanned": summary["files_scanned"],
        "numbers_seen": summary["numbers_seen"],
        "verified": summary["verified"],
        "exempt": summary["exempt"],
        "registry_sha256": report["registry_sha256"],
        "closeout_doc_matches_stable_fields": doc_ok,
        "note": "files_scanned/numbers_seen are tree-dependent; closeout records clean-checkout values",
    }


def check_quorum(files: list[str]) -> tuple[str, dict]:
    weakening = []
    probes = ("two of three", "majority of verifiers", "multiple verifiers", "some verifiers", "independent enough")
    for name in files:
        if "npt/v1/examples" in name or name.startswith("tests/"):
            continue
        try:
            text = Path(name).read_text(encoding="utf-8").lower()
        except (OSError, UnicodeDecodeError):
            continue
        for probe in probes:
            if probe in text:
                weakening.append({"path": name, "probe": probe})
    quorum_doc = Path("docs/DAYLIGHT_V20_VERIFIER_VECTOR_QUORUM.md").read_text(encoding="utf-8")
    exact_three = "exactly three distinct external verifier families are required" in quorum_doc
    more_rejected = "More than three is rejected" in quorum_doc
    closes_only = "independent_verifier_quorum.claim_usable_3_of_3" in quorum_doc
    no_declare = "does not certify, approve, audit, validate, raise the score, or declare" in quorum_doc
    ok = exact_three and more_rejected and closes_only and no_declare and not weakening
    return "PASS_EVIDENCE_MATCH" if ok else "FAIL_BOUNDARY_INFLATION", {
        "exactly_three_documented": exact_three,
        "more_than_three_rejected": more_rejected,
        "closes_only_verifier_vector_blocker": closes_only,
        "no_declaration_language": no_declare,
        "weakening_hits_outside_fixtures": weakening,
    }


CLAIMS = [
    {
        "id": "v14c.candidate_score",
        "claim_text": "expected generated candidate score 998,200M / 1,000,000M",
        "value_raw": "998,200M / 1,000,000M",
        "value_canonical": "998200/1000000",
        "numerator": 998200,
        "denominator": 1000000,
        "unit": "M",
        "stated_percent": None,
        "version_context": "Daylight v14C+",
        "score_family": "v14c-plus",
        "original_claim_source": V14C_SCORECARD,
        "original_claim_commit": "16631f7",
        "evidence_files": [V14C_SCORECARD],
        "commands_to_recompute": ["make daylight-cplus-test"],
        "expected_boundary": "generated candidate, not verified/external",
        "patterns": ["998,200M / 1,000,000M", "998200"],
        "check": check_v14c,
    },
    {
        "id": "v15.internal_ceiling",
        "claim_text": "Meridian honest internal ceiling 998,900M / 1,000,000M (candidate, generated)",
        "value_raw": "998,900M / 1,000,000M",
        "value_canonical": "998900/1000000",
        "numerator": 998900,
        "denominator": 1000000,
        "unit": "M",
        "stated_percent": None,
        "version_context": "Daylight v15 Meridian; held by v15 Solstice, v16 Analemma, v16 Zenith",
        "score_family": "v15-meridian",
        "original_claim_source": V15_SCORECARD,
        "original_claim_commit": "e09d5da",
        "evidence_files": [V15_SCORECARD],
        "commands_to_recompute": ["make daylight-meridian-ci", "make daylight-solstice-verify", "make daylight-zenith-verify", "make daylight-analemma-verify"],
        "expected_boundary": "honest internal ceiling; 1,000,000M reachable only via external attestations",
        "patterns": ["998,900M / 1,000,000M", "998900"],
        "check": check_v15,
    },
    {
        "id": "v17.event_horizon_score",
        "claim_text": "Daylight v17 Event Horizon current score 999,999,687 AM+, undeclared",
        "value_raw": "999,999,687 AM+",
        "value_canonical": "999999687",
        "numerator": 999999687,
        "denominator": 999999999,
        "unit": "AM+",
        "stated_percent": None,
        "version_context": "Daylight v17 Singularity / Event Horizon",
        "score_family": "v17-singularity",
        "original_claim_source": "daylight/v17-singularity (v17.1 kernel)",
        "original_claim_commit": "f4cf2db",
        "evidence_files": [V17_CURRENT, V17_EXPECTED, SITE_STATUS_V17],
        "commands_to_recompute": ["make daylight-v17-event-horizon-test", "make site-daylight-status-check", "make site-validate"],
        "expected_boundary": "below declaration target 999,999,999; gate refuses declaration; 1,000,000,000 reserved",
        "patterns": ["999,999,687", "999999687"],
        "check": check_v17,
    },
    {
        "id": "v20.repo_owned_ceiling",
        "claim_text": "Daylight v20 repo-owned no-external ceiling 999,801,305 AM+, declaration refused",
        "value_raw": "999,801,305 AM+",
        "value_canonical": "999801305",
        "numerator": 999801305,
        "denominator": 999999999,
        "unit": "AM+",
        "stated_percent": None,
        "version_context": "Daylight v20 Aperture Singularity",
        "score_family": "v20-aperture-singularity",
        "original_claim_source": "tag v20-aperture-singularity-score-999801305",
        "original_claim_commit": "d656951",
        "evidence_files": [V20_CAPSULE, SITE_STATUS_V20, SITE_CLAIM_EVIDENCE],
        "commands_to_recompute": ["make daylight-v20-aperture-singularity-ci", "make daylight-v20-score-ceiling-report", "make site-validate"],
        "expected_boundary": "fixture, not claim-usable, repo-owned ceiling, singularity impossible without external validation",
        "patterns": ["999,801,305", "999801305"],
        "check": check_v20,
    },
    {
        "id": "v20_3.verifier_quorum",
        "claim_text": "Daylight v20.3 external verifier-family quorum is exactly 3-of-3",
        "value_raw": "3-of-3",
        "value_canonical": "3/3",
        "numerator": 3,
        "denominator": 3,
        "unit": "quorum",
        "stated_percent": None,
        "version_context": "Daylight v20.3",
        "score_family": "v20.3",
        "original_claim_source": "docs/DAYLIGHT_V20_VERIFIER_VECTOR_QUORUM.md",
        "original_claim_commit": "cc3b5c7",
        "evidence_files": ["docs/DAYLIGHT_V20_VERIFIER_VECTOR_QUORUM.md", "docs/DAYLIGHT_V20_CANONICAL_VERIFIER_OUTPUT.md"],
        "commands_to_recompute": ["make daylight-v20-aperture-singularity-ci"],
        "expected_boundary": "closes only the verifier-vector blocker; no score raise; no declaration",
        "patterns": ["3-of-3"],
        "check": None,
    },
    {
        "id": "npt.clean_baseline",
        "claim_text": "DaylightNPT v1 clean-checkout report summary",
        "value_raw": "pass; verified 6; exempt 2; errors 0",
        "value_canonical": "npt-summary",
        "numerator": None,
        "denominator": None,
        "unit": "counts",
        "stated_percent": None,
        "version_context": "DaylightNPT v1",
        "score_family": "npt-v1",
        "original_claim_source": NPT_CLOSEOUT,
        "original_claim_commit": "014a117",
        "evidence_files": [NPT_REPORT, NPT_CLOSEOUT],
        "commands_to_recompute": ["make daylight-npt-ci"],
        "expected_boundary": "counts are tree-dependent; clean-checkout/CI values are the reference",
        "patterns": ["files_scanned"],
        "check": check_npt,
    },
    {
        "id": "v13.design_target",
        "claim_text": "Daylight v13 Sovereign design target 991,300M / 1,000,000M (specification target, never generated)",
        "value_raw": "991,300M / 1,000,000M",
        "value_canonical": "991300/1000000",
        "numerator": 991300,
        "denominator": 1000000,
        "unit": "M",
        "stated_percent": None,
        "version_context": "Daylight v13 Sovereign (historical spec)",
        "score_family": "v13-sovereign",
        "original_claim_source": "docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
        "original_claim_commit": "3e9d4e9",
        "evidence_files": ["docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md"],
        "commands_to_recompute": [],
        "expected_boundary": "design target in a historical specification; no generated scorecard asserts it",
        "patterns": ["991,300M", "991300"],
        "check": None,
    },
    {
        "id": "grok.quoted_third_party_scores",
        "claim_text": "Grok-attributed assessment numbers quoted on the audit page (955/1000, 973/1000, 984/1000, 941,000M)",
        "value_raw": "955/1000; 973/1000; 984/1000; 941,000M",
        "value_canonical": "quoted-third-party",
        "numerator": None,
        "denominator": None,
        "unit": "mixed",
        "stated_percent": None,
        "version_context": "docs/archive/site/daylight-grok-audit.html",
        "score_family": "external-quotation",
        "original_claim_source": "docs/archive/site/daylight-grok-audit.html",
        "original_claim_commit": "3718c24",
        "evidence_files": ["docs/archive/site/daylight-grok-audit.html"],
        "commands_to_recompute": ["make site-validate"],
        "expected_boundary": "Grok-attributed, not authenticated; quoted, never adopted as Daylight scores",
        "patterns": ["973/1000"],
        "check": None,
    },
]


def check_static_boundary(claim: dict, files: list[str]) -> tuple[str, dict]:
    if claim["id"] == "v20_3.verifier_quorum":
        return check_quorum(files)
    if claim["id"] == "v13.design_target":
        text = Path("docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md").read_text(encoding="utf-8")
        ok = "Target score" in text and "991,300M / 1,000,000M" in text
        return ("PASS_NON_CLAIM_BOUNDARY" if ok else "FAIL_BOUNDARY_INFLATION"), {"target_wording_present": ok}
    if claim["id"] == "grok.quoted_third_party_scores":
        text = Path("docs/archive/site/daylight-grok-audit.html").read_text(encoding="utf-8")
        ok = "Grok-attributed, not authenticated" in text and "973/1000" in text
        return ("PASS_NON_CLAIM_BOUNDARY" if ok else "FAIL_EXTERNALITY_MISSTATED"), {"attribution_boundary_present": ok}
    return "UNRESOLVED_NO_EVIDENCE", {}


def main() -> int:
    commit = run_git(["rev-parse", "HEAD"]).strip()
    dirty = bool(run_git(["status", "--porcelain"]).strip())
    files = tracked_public_files()

    claims_out = []
    findings = []
    counts = {"recomputed": 0, "evidence_matched": 0, "non_claim": 0, "failed": 0, "unresolved": 0}
    for claim in CLAIMS:
        checker = claim.pop("check")
        patterns = claim.pop("patterns")
        if checker is not None:
            status, observed = checker()
        else:
            status, observed = check_static_boundary(claim, files)
        locations = find_locations(files, patterns)
        record = dict(claim)
        record["current_locations"] = locations
        record["observed"] = observed
        record["audit_status"] = status
        record["generated_artifacts"] = claim["evidence_files"]
        record["percent_rounding_rule"] = None
        record["recomputed_percent"] = None
        claims_out.append(record)
        if status.startswith("PASS_RECOMPUTED"):
            counts["recomputed"] += 1
        elif status.startswith("PASS_EVIDENCE"):
            counts["evidence_matched"] += 1
        elif status.startswith("PASS_NON_CLAIM"):
            counts["non_claim"] += 1
        elif status.startswith("FAIL"):
            counts["failed"] += 1
            findings.append(
                {
                    "code": "SAI002_SCORE_VALUE_MISMATCH",
                    "severity": "error",
                    "path": claim["original_claim_source"],
                    "line": None,
                    "claim_id": claim["id"],
                    "value_raw": claim["value_raw"],
                    "expected_value": claim["value_canonical"],
                    "observed_value": observed,
                    "evidence_path": ";".join(claim["evidence_files"]),
                    "command": ";".join(claim["commands_to_recompute"]),
                    "reason": f"claim check returned {status}",
                    "suggested_fix": "Regenerate the evidence or narrow the public claim to match it.",
                }
            )
        else:
            counts["unresolved"] += 1

    ratios = audit_ratios()
    for ratio in ratios:
        if not ratio["match"]:
            counts["failed"] += 1
            findings.append(
                {
                    "code": "SAI003_PERCENT_MISMATCH",
                    "severity": "error",
                    "path": ratio["location"],
                    "line": None,
                    "claim_id": ratio["id"],
                    "value_raw": ratio["ratio_raw"],
                    "expected_value": ratio["computed_percent"],
                    "observed_value": ratio["stated_percent"],
                    "evidence_path": ratio["location"],
                    "command": "python3 tools/daylight_score_integrity_audit.py",
                    "reason": "stated percentage does not recompute from the exact ratio",
                    "suggested_fix": "Recompute the percentage from the exact numerator and denominator.",
                }
            )

    surface = []
    for record in claims_out:
        buckets = sorted({loc["surface"] for loc in record["current_locations"]})
        surface.append(
            {
                "claim_id": record["id"],
                "value_canonical": record["value_canonical"],
                "surfaces": buckets,
                "locations": record["current_locations"],
                "boundary": record["expected_boundary"],
                "consistent": not record["audit_status"].startswith("FAIL"),
            }
        )

    if counts["failed"]:
        result = "fail"
    elif counts["unresolved"]:
        result = "unresolved"
    else:
        result = "pass"

    report = {
        "schema": SCHEMA_REPORT,
        "commit": commit,
        "result": result,
        "summary": {
            "score_claims_seen": len(claims_out),
            "score_claims_recomputed": counts["recomputed"],
            "score_claims_evidence_matched": counts["evidence_matched"],
            "score_claims_non_claim": counts["non_claim"],
            "failures": counts["failed"],
            "unresolved": counts["unresolved"],
            "families_checked": sorted({claim["score_family"] for claim in claims_out}),
            "commands_run": sorted({cmd for claim in claims_out for cmd in claim["commands_to_recompute"]}),
        },
        "findings": findings,
        "non_claim_caveat": (
            "This audit checks score integrity against repository evidence and original claim boundaries. "
            "It does not certify security, production readiness, audit status, post-quantum security, "
            "external endorsement, or mathematical finality."
        ),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "daylight-score-claims.json").write_text(
        dumps_stable({"schema": SCHEMA_CLAIMS, "commit": commit, "clean_worktree": not dirty, "claims": claims_out}),
        encoding="utf-8",
    )
    (OUT_DIR / "ratio-percent-audit.json").write_text(
        dumps_stable({"schema": SCHEMA_RATIO, "commit": commit, "ratios": ratios}), encoding="utf-8"
    )
    (OUT_DIR / "public-surface-score-diff.json").write_text(
        dumps_stable({"schema": SCHEMA_SURFACE, "commit": commit, "claims": surface}), encoding="utf-8"
    )
    (OUT_DIR / "daylight-score-integrity.report.json").write_text(dumps_stable(report), encoding="utf-8")

    print(f"score-integrity: {result}")
    print(f"claims: {len(claims_out)} recomputed: {counts['recomputed']} evidence_matched: {counts['evidence_matched']} non_claim: {counts['non_claim']} failed: {counts['failed']} unresolved: {counts['unresolved']}")
    for finding in findings:
        print(f"finding: {finding['code']} {finding['claim_id']}")
    return 0 if result == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
