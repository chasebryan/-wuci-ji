"""Daylight v17 Singularity residue-collapse scoring."""

from __future__ import annotations

from decimal import Decimal, ROUND_FLOOR, getcontext
from pathlib import Path
from typing import Any

from . import __version__
from .canonical_json import canonical_sha256, json_bytes, load_json_path, reject_float, sha256_bytes
from . import v16_bridge


getcontext().prec = 90

NAME = "Daylight v17 Singularity"
VERSION = "daylight-v17-singularity-v0.1"
SCORECARD_VERSION = "daylight-v17-singularity-scorecard-v0.1"
RESOLUTION_VERSION = "daylight-v17-singularity-resolution-v0.1"
MANIFEST_VERSION = "daylight-v17-singularity-manifest-v0.1"
EVIDENCE_VERSION = "daylight-v17-singularity-evidence-v0.1"
GENERATED_DATE = "2026-07-01"

B = 1_000_000_000
S_DECLARED_TARGET = B - 1
S_PERFECT_RESERVED = B
CLOSURE_SCALE = 1_000_000_000_000
DEBT_SCALE = 1_000_000
LN_B = Decimal(B).ln()
DECIMAL_QUANT = Decimal("0.000000000000000000000000000000000000000000000001")

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REGISTRY = PACKAGE_ROOT / "rules" / "field-registry.v17.json"

D_REGISTRY = "DAYLIGHT-v17-SINGULARITY-REGISTRY:"
D_SCORECARD = "DAYLIGHT-v17-SINGULARITY-SCORECARD:"
D_RESOLUTION = "DAYLIGHT-v17-SINGULARITY-RESOLUTION:"
D_MANIFEST = "DAYLIGHT-v17-SINGULARITY-MANIFEST:"
D_VERIFIER = "DAYLIGHT-v17-SINGULARITY-VERIFIER:"
D_EVIDENCE = "DAYLIGHT-v17-SINGULARITY-EVIDENCE:"

HEX64 = set("0123456789abcdef")
FIELD_ORDER = [
    "claim",
    "self",
    "artifact",
    "replay",
    "implementation",
    "fuzz",
    "formal",
    "crypto",
    "falsification",
    "boundary",
]

FORBIDDEN_EVIDENCE_KEYS = {
    "manual_score",
    "manual_credit",
    "score_override",
    "score_AM_plus",
    "singularity_score",
    "declared_score",
    "omega",
    "residue",
    "field_closure",
    "closure_override",
    "credit_override",
}

BREAK_SEVERITY_MICRO = {
    "B0_documentation_ambiguity": 10_000,
    "B1_score_mismatch": 50_000,
    "B2_verifier_mismatch": 100_000,
    "B3_artifact_closure_bypass": 250_000,
    "B4_unsigned_external_credit": 500_000,
}

COLLAPSE_BREAKS = {
    "B5_forged_scorecard_accepted",
    "B6_opens_without_policy_evidence",
    "B7_production_or_pq_overclaim",
}

OVERCLAIM_PENALTY_MICRO = {
    "production_allowed": 5_000_000,
    "runtime_containment_claim": 3_000_000,
    "whole_system_post_quantum_safety_claim": 5_000_000,
    "external_certification_claim": 5_000_000,
    "new_primitive_security_claim": 5_000_000,
}


class SingularityError(ValueError):
    pass


def is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX64


def decimal_text(value: Decimal) -> str:
    quantized = value.quantize(DECIMAL_QUANT)
    text = format(quantized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def decimal_from_scaled(value: int, scale: int = CLOSURE_SCALE) -> Decimal:
    return Decimal(int(value)) / Decimal(scale)


def closure_from_credit(verified_credit: int, possible_credit: int) -> int:
    if not isinstance(verified_credit, int) or not isinstance(possible_credit, int):
        raise SingularityError("closure credit values must be integers")
    if possible_credit <= 0:
        raise SingularityError("possible credit must be positive")
    if verified_credit < 0 or verified_credit > possible_credit:
        raise SingularityError("verified credit outside possible range")
    scaled = verified_credit * CLOSURE_SCALE // possible_credit
    return min(scaled, CLOSURE_SCALE - 1)


def closure_scaled_from_decimal_text(value: str) -> int:
    dec = Decimal(value)
    if dec < 0 or dec >= 1:
        raise SingularityError("closure decimal must be in [0, 1)")
    return int((dec * Decimal(CLOSURE_SCALE)).to_integral_value(rounding=ROUND_FLOOR))


def self_progress_closure(proof_mass: int, baseline: int, *, beta_num: int = 1, beta_den: int = 1) -> int:
    if baseline <= 0:
        raise SingularityError("self-progress baseline must be positive")
    growth = Decimal(proof_mass) / Decimal(baseline) - Decimal(1)
    if growth <= 0:
        return 0
    beta = Decimal(beta_num) / Decimal(beta_den)
    closure = Decimal(1) - (-(beta * growth)).exp()
    scaled = int((closure * Decimal(CLOSURE_SCALE)).to_integral_value(rounding=ROUND_FLOOR))
    return min(max(scaled, 0), CLOSURE_SCALE - 1)


def field_omega_from_scaled(closure_scaled: int) -> Decimal:
    if not isinstance(closure_scaled, int) or closure_scaled < 0 or closure_scaled >= CLOSURE_SCALE:
        raise SingularityError("field closure must be an integer in [0, closure_scale)")
    residue = Decimal(1) - decimal_from_scaled(closure_scaled)
    return -residue.ln()


def score_from_omega(omega: Decimal) -> tuple[int, Decimal]:
    residue = (-omega).exp()
    raw = Decimal(B) * (Decimal(1) - residue)
    score = int(raw.to_integral_value(rounding=ROUND_FLOOR))
    return min(max(score, 0), S_DECLARED_TARGET), residue


def score_from_scaled_closures(closures: dict[str, int], weights_centi: dict[str, int], debt_micro: int = 0) -> dict[str, Any]:
    omega_raw = Decimal(0)
    for field_id in FIELD_ORDER:
        omega_raw += Decimal(weights_centi[field_id]) / Decimal(100) * field_omega_from_scaled(closures[field_id])
    omega = omega_raw - Decimal(debt_micro) / Decimal(DEBT_SCALE)
    score, residue = score_from_omega(omega)
    return {
        "omega_raw": omega_raw,
        "omega": omega,
        "residue": residue,
        "score_AM_plus": score,
        "declared": omega >= LN_B and score == S_DECLARED_TARGET,
    }


def load_registry(path: Path | str = DEFAULT_REGISTRY) -> dict[str, Any]:
    registry = load_json_path(path)
    reject_float(registry, "registry")
    if registry.get("version") != "daylight-v17-singularity-field-registry-v0.1":
        raise SingularityError("unsupported v17 field registry version")
    if registry.get("closure_scale") != CLOSURE_SCALE:
        raise SingularityError("unsupported v17 closure scale")
    fields = registry.get("fields")
    if not isinstance(fields, list) or [field.get("id") for field in fields] != FIELD_ORDER:
        raise SingularityError("v17 field registry must define the ten fields in canonical order")
    if sum(int(field["weight_centi"]) for field in fields) != 1350:
        raise SingularityError("v17 field weights must sum to 13.50")
    seen_units: set[str] = set()
    for field in fields:
        if int(field["weight_centi"]) <= 0:
            raise SingularityError(f"{field['id']}: weight must be positive")
        if field["mode"] == "unit_credit":
            units = field.get("units")
            if not isinstance(units, list) or not units:
                raise SingularityError(f"{field['id']}: unit_credit field requires units")
            for unit in units:
                uid = unit.get("id")
                if not isinstance(uid, str) or not uid:
                    raise SingularityError("unit id must be non-empty")
                if uid in seen_units:
                    raise SingularityError(f"duplicate v17 unit id: {uid}")
                seen_units.add(uid)
                if not isinstance(unit.get("credit"), int) or unit["credit"] <= 0:
                    raise SingularityError(f"{uid}: credit must be positive")
        elif field["mode"] not in {"claim_score", "self_progress"}:
            raise SingularityError(f"{field['id']}: unsupported field mode")
    return registry


def registry_digest(registry: dict[str, Any]) -> str:
    return canonical_sha256(registry, D_REGISTRY)


def _walk_forbidden_evidence_keys(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_EVIDENCE_KEYS:
                raise SingularityError(f"manual or generated score field rejected at {path}.{key}")
            _walk_forbidden_evidence_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_forbidden_evidence_keys(item, f"{path}[{index}]")


def load_evidence(path: Path | str | None) -> dict[str, Any]:
    if path is None:
        return {"version": EVIDENCE_VERSION}
    evidence = load_json_path(path)
    reject_float(evidence, "singularity_evidence")
    if not isinstance(evidence, dict):
        raise SingularityError("v17 evidence must be a JSON object")
    if evidence.get("version") != EVIDENCE_VERSION:
        raise SingularityError("unsupported v17 evidence version")
    _walk_forbidden_evidence_keys(evidence)
    return evidence


def evidence_digest(evidence: dict[str, Any]) -> str:
    return canonical_sha256(evidence, D_EVIDENCE)


def _list(evidence: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = evidence.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise SingularityError(f"{key} must be a list of objects")
    return value


def _record_has_digest(record: dict[str, Any]) -> bool:
    digest_keys = (
        "evidence_digest",
        "result_digest",
        "proof_digest",
        "transcript_digest",
        "coverage_report_digest",
        "scorecard_digest",
    )
    return any(is_hex_sha256(record.get(key)) for key in digest_keys)


def _valid_record(record: dict[str, Any]) -> bool:
    if record.get("fixture_material_used") is True:
        return False
    if record.get("offensive_tooling_included") not in (None, False):
        return False
    if not _record_has_digest(record):
        return False
    return any(record.get(flag) is True for flag in ("valid", "verified", "replayed", "checked"))


def _evidence_record_closed(evidence: dict[str, Any], unit: dict[str, Any]) -> bool:
    for record in _list(evidence, unit["collection"]):
        if record.get(unit["match_key"]) == unit["match_value"] and _valid_record(record):
            return True
    return False


def _zenith_obligation_closed(context: dict[str, Any], obligation: str) -> bool:
    zenith = context.get("zenith")
    return bool(zenith and obligation in zenith["closed_obligations"])


def _unit_closed(unit: dict[str, Any], context: dict[str, Any], evidence: dict[str, Any]) -> bool:
    verifier = unit["verifier"]
    solstice = context["solstice"]
    if verifier == "solstice_verified":
        return solstice["ok"] is True
    if verifier == "zenith_verified":
        return bool(context.get("zenith"))
    if verifier == "analemma_verified":
        return bool(context.get("analemma"))
    if verifier == "solstice_scorecard_digest":
        return is_hex_sha256(solstice.get("scorecard_digest"))
    if verifier == "solstice_receipt_digest":
        return is_hex_sha256(solstice.get("receipt_digest"))
    if verifier == "solstice_output_ledger":
        return is_hex_sha256(solstice.get("output_ledger_head"))
    if verifier == "solstice_manifest_closure":
        return is_hex_sha256(solstice.get("artifact_manifest_digest"))
    if verifier == "solstice_sha256sums_closure":
        return is_hex_sha256(solstice.get("sha256sums_digest"))
    if verifier == "zenith_report_manifest":
        return bool(context.get("zenith") and is_hex_sha256(context["zenith"].get("manifest_digest")))
    if verifier == "analemma_report_manifest":
        return bool(context.get("analemma") and is_hex_sha256(context["analemma"].get("manifest_digest")))
    if verifier == "v17_python_reference":
        return True
    if verifier == "zenith_obligation":
        return _zenith_obligation_closed(context, unit["obligation"])
    if verifier == "evidence_record":
        return _evidence_record_closed(evidence, unit)
    raise SingularityError(f"unknown v17 unit verifier: {verifier}")


def _field_from_units(field: dict[str, Any], context: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    closed_units: list[str] = []
    open_units: list[str] = []
    verified = 0
    possible = 0
    for unit in field["units"]:
        possible += int(unit["credit"])
        if _unit_closed(unit, context, evidence):
            verified += int(unit["credit"])
            closed_units.append(unit["id"])
        else:
            open_units.append(unit["id"])
    closure_scaled = closure_from_credit(verified, possible)
    return {
        "mode": "credit_ratio",
        "name": field["name"],
        "weight_centi": field["weight_centi"],
        "verified_credit": verified,
        "possible_credit": possible,
        "closure_pptrillion": closure_scaled,
        "closed_units": closed_units,
        "open_units": open_units,
    }


def _field_claim(field: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    solstice = context["solstice"]
    verified = int(solstice["final_score_M"])
    possible = int(solstice["perfect_score_M"])
    return {
        "mode": "claim_score",
        "name": field["name"],
        "weight_centi": field["weight_centi"],
        "verified_credit": verified,
        "possible_credit": possible,
        "closure_pptrillion": closure_from_credit(verified, possible),
        "closed_units": ["claim.solstice_score_regenerated"],
        "open_units": [] if verified == possible else ["claim.remaining_solstice_residue"],
    }


def _field_self(field: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    analemma = context.get("analemma")
    if analemma:
        proof_mass = int(analemma["report"]["proof_mass"])
        baseline = int(analemma["report"]["baseline_proof_mass"])
        closed_units = ["self.analemma_report_verified"]
        open_units: list[str] = []
    else:
        proof_mass = 0
        baseline = 1
        closed_units = []
        open_units = ["self.analemma_report_missing"]
    closure_scaled = self_progress_closure(
        proof_mass,
        baseline,
        beta_num=int(field.get("beta_num", 1)),
        beta_den=int(field.get("beta_den", 1)),
    )
    return {
        "mode": "self_progress",
        "name": field["name"],
        "weight_centi": field["weight_centi"],
        "proof_mass": proof_mass,
        "baseline_proof_mass": baseline,
        "beta_num": int(field.get("beta_num", 1)),
        "beta_den": int(field.get("beta_den", 1)),
        "closure_pptrillion": closure_scaled,
        "closed_units": closed_units,
        "open_units": open_units,
    }


def _build_fields(registry: dict[str, Any], context: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in registry["fields"]:
        mode = field["mode"]
        if mode == "claim_score":
            entry = _field_claim(field, context)
        elif mode == "self_progress":
            entry = _field_self(field, context)
        else:
            entry = _field_from_units(field, context, evidence)
        omega = field_omega_from_scaled(entry["closure_pptrillion"])
        entry["omega_i"] = decimal_text(omega)
        entry["weighted_omega_i"] = decimal_text(Decimal(entry["weight_centi"]) / Decimal(100) * omega)
        result[field["id"]] = entry
    return result


def _require_no_score_inflation(context: dict[str, Any]) -> None:
    zenith = context.get("zenith")
    analemma = context.get("analemma")
    if zenith and int(zenith.get("score_inflation_M", 0)) != 0:
        raise SingularityError("Zenith score inflation rejected")
    if analemma and int(analemma.get("score_inflation_M", 0)) != 0:
        raise SingularityError("Analemma score inflation rejected")


def _debt_from_events(evidence: dict[str, Any]) -> tuple[int, list[dict[str, Any]], list[str]]:
    total = 0
    events: list[dict[str, Any]] = []
    collapse: list[str] = []
    for record in _list(evidence, "break_ledger"):
        if record.get("resolved") is True:
            continue
        break_class = record.get("class")
        if break_class in COLLAPSE_BREAKS or record.get("collapse") is True:
            collapse.append(str(break_class or record.get("id", "critical_break")))
            continue
        severity = BREAK_SEVERITY_MICRO.get(str(break_class), None)
        if severity is None:
            raise SingularityError(f"unknown non-collapse break class: {break_class}")
        total += severity
        events.append({"id": record.get("id"), "class": break_class, "debt_micro": severity})
    for record in _list(evidence, "debt_events"):
        if record.get("resolved") is True:
            continue
        debt = record.get("debt_micro")
        if not isinstance(debt, int) or debt < 0:
            raise SingularityError("debt_events[].debt_micro must be a non-negative integer")
        total += debt
        events.append({"id": record.get("id"), "class": record.get("class", "custom"), "debt_micro": debt})
    return total, events, collapse


def _overclaim_debt(evidence: dict[str, Any], context: dict[str, Any]) -> tuple[int, list[dict[str, Any]], list[str]]:
    claims = evidence.get("declared_claims", {})
    if claims is None:
        claims = {}
    if not isinstance(claims, dict):
        raise SingularityError("declared_claims must be an object")
    release_facing = bool(evidence.get("release_facing", False))
    zenith_report = context.get("zenith", {}).get("report", {}) if context.get("zenith") else {}
    dz2 = zenith_report.get("dz2_production_eligible") is True
    zenith_level = zenith_report.get("zenith_level")
    proof_available = {
        "production_allowed": dz2,
        "runtime_containment_claim": dz2,
        "whole_system_post_quantum_safety_claim": dz2,
        "external_certification_claim": zenith_level in {"Z6_PUBLIC_EXTERNAL_STANDARD", "Z7_PRODUCTION_ELIGIBLE"},
        "new_primitive_security_claim": False,
    }
    total = 0
    events: list[dict[str, Any]] = []
    collapse: list[str] = []
    for key, penalty in OVERCLAIM_PENALTY_MICRO.items():
        if claims.get(key) is True and not proof_available[key]:
            if release_facing:
                collapse.append(key)
            else:
                total += penalty
                events.append({"claim": key, "debt_micro": penalty})
    return total, events, collapse


def _collapse_reasons(evidence: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for record in _list(evidence, "contradictions"):
        if record.get("resolved") is not True:
            reasons.append(str(record.get("id", "unresolved_contradiction")))
    for record in _list(evidence, "critical_breaks"):
        if record.get("resolved") is not True:
            reasons.append(str(record.get("id", "unresolved_critical_break")))
    return reasons


def _debt(context: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    regression = 0
    staleness = 0
    analemma = context.get("analemma")
    if analemma:
        baseline = int(analemma["report"]["baseline_proof_mass"])
        if baseline <= 0:
            raise SingularityError("Analemma baseline must be positive")
        regression = int(Decimal(int(analemma["report"]["regression_debt"])) * Decimal(DEBT_SCALE) / Decimal(baseline))
        staleness = int(Decimal(int(analemma["report"]["staleness_debt"])) * Decimal(DEBT_SCALE) / Decimal(baseline))
    event_debt, event_rows, break_collapse = _debt_from_events(evidence)
    overclaim, overclaim_rows, overclaim_collapse = _overclaim_debt(evidence, context)
    collapse = _collapse_reasons(evidence) + break_collapse + overclaim_collapse
    total = regression + staleness + event_debt + overclaim
    return {
        "regression_debt_micro": regression,
        "staleness_debt_micro": staleness,
        "break_and_custom_debt_micro": event_debt,
        "overclaim_debt_micro": overclaim,
        "total_debt_micro": total,
        "break_and_custom_events": event_rows,
        "overclaim_events": overclaim_rows,
        "collapse_reasons": collapse,
    }


def _context(
    *,
    solstice_artifact_dir: Path | str,
    zenith_report_dir: Path | str | None,
    analemma_report_dir: Path | str | None,
) -> dict[str, Any]:
    context = {
        "solstice": v16_bridge.verify_solstice_artifact(solstice_artifact_dir),
        "zenith": v16_bridge.verify_zenith_report_dir(zenith_report_dir),
        "analemma": v16_bridge.verify_analemma_report_dir(analemma_report_dir),
    }
    _require_no_score_inflation(context)
    return context


def verifier_digest(registry: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "name": NAME,
            "version": VERSION,
            "package_version": __version__,
            "registry_digest": registry_digest(registry),
            "math": "decimal-exp-ln-no-float-json",
        },
        D_VERIFIER,
    )


def _upstream_summary(context: dict[str, Any]) -> dict[str, Any]:
    solstice = context["solstice"]
    out = {
        "solstice_score_M": solstice["final_score_M"],
        "solstice_scorecard_digest": solstice["scorecard_digest"],
        "solstice_artifact_manifest_digest": solstice["artifact_manifest_digest"],
        "solstice_score_body_digest": solstice["score_body_digest"],
        "claim_boundary": solstice["claim_boundary"],
    }
    if context.get("zenith"):
        out.update({
            "zenith_report_digest": context["zenith"]["report_digest"],
            "zenith_resolution_digest": context["zenith"]["resolution_digest"],
            "zenith_level": context["zenith"]["report"].get("zenith_level"),
            "zenith_score_inflation_M": context["zenith"]["score_inflation_M"],
        })
    if context.get("analemma"):
        out.update({
            "analemma_report_digest": context["analemma"]["report_digest"],
            "analemma_resolution_digest": context["analemma"]["resolution_digest"],
            "analemma_score_A": context["analemma"]["report"].get("A_self_A"),
            "analemma_score_inflation_M": context["analemma"]["score_inflation_M"],
        })
    return out


def build_scorecard_from_context(registry: dict[str, Any], context: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fields = _build_fields(registry, context, evidence)
    weights = {field_id: int(fields[field_id]["weight_centi"]) for field_id in FIELD_ORDER}
    closures = {field_id: int(fields[field_id]["closure_pptrillion"]) for field_id in FIELD_ORDER}
    debt = _debt(context, evidence)
    collapse = bool(debt["collapse_reasons"])
    omega_raw = Decimal(0)
    for field_id in FIELD_ORDER:
        omega_raw += Decimal(fields[field_id]["weighted_omega_i"])
    omega_debt_adjusted = omega_raw - Decimal(debt["total_debt_micro"]) / Decimal(DEBT_SCALE)
    omega_effective = Decimal(0) if collapse else omega_debt_adjusted
    score, residue = (0, Decimal(1)) if collapse else score_from_omega(omega_effective)
    declared = (not collapse) and omega_effective >= LN_B and score == S_DECLARED_TARGET
    proof_registry_digest = registry_digest(registry)
    ev_digest = evidence_digest(evidence)
    scorecard = {
        "version": SCORECARD_VERSION,
        "name": NAME,
        "B": B,
        "unit": "AM+",
        "declared_target_AM_plus": S_DECLARED_TARGET,
        "perfect_reserved_AM_plus": S_PERFECT_RESERVED,
        "threshold_ln_B": decimal_text(LN_B),
        "omega_raw": decimal_text(omega_raw),
        "omega": decimal_text(omega_effective),
        "residue": decimal_text(residue),
        "score_AM_plus": score,
        "declared": declared,
        "fields": fields,
        "debt": debt,
        "collapse_state": {
            "collapsed": collapse,
            "reasons": debt["collapse_reasons"],
        },
        "score_inflation": {
            "score_inflation_M": 0,
            "score_inflation_AM_plus": 0,
        },
        "proof_registry_digest": proof_registry_digest,
        "evidence_digest": ev_digest,
        "verifier_digest": verifier_digest(registry),
        "upstream": _upstream_summary(context),
        "non_claims": [
            "Daylight v17 Singularity regenerates a residue-collapse score from evidence; it does not accept typed scores.",
            "999,999,999 AM+ is a declaration threshold, not a claim of perfect proof.",
            "1,000,000,000 AM+ remains reserved because zero future residue is not honestly assertable.",
            "This verifier does not grant production authority, runtime containment, whole-system PQ safety, external certification, or new primitive security.",
        ],
    }
    scorecard["singularity_digest"] = scorecard_digest(scorecard)
    resolution = {
        "version": RESOLUTION_VERSION,
        "field_order": FIELD_ORDER,
        "closed_units": {
            field_id: fields[field_id].get("closed_units", [])
            for field_id in FIELD_ORDER
        },
        "open_units": {
            field_id: fields[field_id].get("open_units", [])
            for field_id in FIELD_ORDER
        },
        "declared": declared,
        "collapse_state": scorecard["collapse_state"],
        "proof_registry_digest": proof_registry_digest,
        "evidence_digest": ev_digest,
        "singularity_digest": scorecard["singularity_digest"],
    }
    return scorecard, resolution


def build_scorecard(
    *,
    solstice_artifact_dir: Path | str,
    zenith_report_dir: Path | str | None = None,
    analemma_report_dir: Path | str | None = None,
    evidence_path: Path | str | None = None,
    registry_path: Path | str = DEFAULT_REGISTRY,
) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = load_registry(registry_path)
    evidence = load_evidence(evidence_path)
    context = _context(
        solstice_artifact_dir=solstice_artifact_dir,
        zenith_report_dir=zenith_report_dir,
        analemma_report_dir=analemma_report_dir,
    )
    return build_scorecard_from_context(registry, context, evidence)


def scorecard_digest(scorecard: dict[str, Any]) -> str:
    body = {key: value for key, value in scorecard.items() if key != "singularity_digest"}
    return canonical_sha256(body, D_SCORECARD)


def resolution_digest(resolution: dict[str, Any]) -> str:
    return canonical_sha256(resolution, D_RESOLUTION)


def manifest_digest(manifest: dict[str, Any]) -> str:
    body = {key: value for key, value in manifest.items() if key != "singularity_manifest_digest"}
    return canonical_sha256(body, D_MANIFEST)


def _repo_relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        return str(resolved)


def _resolve_input(path_text: str, report_dir: Path) -> Path:
    candidate = Path(path_text)
    if candidate.is_absolute():
        return candidate
    repo_candidate = REPO_ROOT / candidate
    if repo_candidate.exists():
        return repo_candidate
    return report_dir / candidate


def _input_file(path: Path) -> dict[str, str]:
    return {"path": _repo_relative(path), "sha256": sha256_bytes(path.read_bytes())}


def build_report_artifact(
    *,
    solstice_artifact_dir: Path | str,
    out_dir: Path | str,
    zenith_report_dir: Path | str | None = None,
    analemma_report_dir: Path | str | None = None,
    evidence_path: Path | str | None = None,
    registry_path: Path | str = DEFAULT_REGISTRY,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    scorecard, resolution = build_scorecard(
        solstice_artifact_dir=solstice_artifact_dir,
        zenith_report_dir=zenith_report_dir,
        analemma_report_dir=analemma_report_dir,
        evidence_path=evidence_path,
        registry_path=registry_path,
    )
    outputs = {
        "singularity-scorecard.json": json_bytes(scorecard),
        "singularity-resolution.json": json_bytes(resolution),
    }
    solstice_manifest = Path(solstice_artifact_dir) / "artifact-manifest.solstice.json"
    inputs = {
        "registry": _input_file(Path(registry_path)),
        "solstice_manifest": _input_file(solstice_manifest),
    }
    if zenith_report_dir is not None:
        inputs["zenith_manifest"] = _input_file(Path(zenith_report_dir) / "zenith-manifest.json")
    if analemma_report_dir is not None:
        inputs["analemma_manifest"] = _input_file(Path(analemma_report_dir) / "analemma-manifest.json")
    if evidence_path is not None:
        inputs["evidence"] = _input_file(Path(evidence_path))
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "artifact": NAME,
        "generated_date": GENERATED_DATE,
        "inputs": inputs,
        "outputs": {name: {"path": name, "sha256": sha256_bytes(data)} for name, data in sorted(outputs.items())},
        "singularity_digest": scorecard["singularity_digest"],
        "singularity_resolution_digest": resolution_digest(resolution),
        "score_AM_plus": scorecard["score_AM_plus"],
        "declared": scorecard["declared"],
        "collapse_state": scorecard["collapse_state"],
    }
    manifest["singularity_manifest_digest"] = manifest_digest(manifest)
    outputs["singularity-manifest.json"] = json_bytes(manifest)
    outputs["SHA256SUMS"] = "".join(
        f"{sha256_bytes(data)}  {name}\n" for name, data in sorted(outputs.items())
    ).encode("utf-8")
    for name, data in outputs.items():
        (out_dir / name).write_bytes(data)
    return manifest


def _verify_field_integrity(field_id: str, field: dict[str, Any]) -> None:
    mode = field.get("mode")
    if mode in {"claim_score", "credit_ratio"}:
        expected = closure_from_credit(int(field["verified_credit"]), int(field["possible_credit"]))
    elif mode == "self_progress":
        expected = self_progress_closure(
            int(field["proof_mass"]),
            int(field["baseline_proof_mass"]),
            beta_num=int(field["beta_num"]),
            beta_den=int(field["beta_den"]),
        )
    else:
        raise SingularityError(f"{field_id}: unsupported scorecard field mode")
    if expected != field.get("closure_pptrillion"):
        raise SingularityError(f"{field_id}: edited field closure rejected")
    omega = field_omega_from_scaled(expected)
    if decimal_text(omega) != field.get("omega_i"):
        raise SingularityError(f"{field_id}: edited field omega rejected")
    weighted = Decimal(int(field["weight_centi"])) / Decimal(100) * omega
    if decimal_text(weighted) != field.get("weighted_omega_i"):
        raise SingularityError(f"{field_id}: edited weighted omega rejected")


def verify_scorecard_integrity(scorecard: dict[str, Any]) -> None:
    reject_float(scorecard, "singularity_scorecard")
    if scorecard.get("version") != SCORECARD_VERSION:
        raise SingularityError("unsupported Singularity scorecard version")
    if scorecard.get("B") != B or scorecard.get("perfect_reserved_AM_plus") != S_PERFECT_RESERVED:
        raise SingularityError("Singularity scale mismatch")
    if scorecard_digest(scorecard) != scorecard.get("singularity_digest"):
        raise SingularityError("Singularity scorecard digest mismatch")
    fields = scorecard.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(FIELD_ORDER):
        raise SingularityError("Singularity fields are not canonical")
    omega_raw = Decimal(0)
    for field_id in FIELD_ORDER:
        field = fields[field_id]
        _verify_field_integrity(field_id, field)
        omega_raw += Decimal(field["weighted_omega_i"])
    debt = scorecard["debt"]
    total_debt = int(debt["total_debt_micro"])
    collapse_reasons = debt.get("collapse_reasons", [])
    collapsed = bool(collapse_reasons)
    omega_debt_adjusted = omega_raw - Decimal(total_debt) / Decimal(DEBT_SCALE)
    omega_effective = Decimal(0) if collapsed else omega_debt_adjusted
    score, residue = (0, Decimal(1)) if collapsed else score_from_omega(omega_effective)
    if decimal_text(omega_raw) != scorecard.get("omega_raw"):
        raise SingularityError("edited raw omega rejected")
    if decimal_text(omega_effective) != scorecard.get("omega"):
        raise SingularityError("edited omega rejected")
    if decimal_text(residue) != scorecard.get("residue"):
        raise SingularityError("edited residue rejected")
    if score != scorecard.get("score_AM_plus"):
        raise SingularityError("edited score rejected")
    declared = (not collapsed) and omega_effective >= LN_B and score == S_DECLARED_TARGET
    if declared != scorecard.get("declared"):
        raise SingularityError("edited declaration state rejected")
    if scorecard.get("collapse_state", {}).get("collapsed") != collapsed:
        raise SingularityError("edited collapse state rejected")
    inflation = scorecard.get("score_inflation", {})
    if inflation.get("score_inflation_M") != 0 or inflation.get("score_inflation_AM_plus") != 0:
        raise SingularityError("Singularity score inflation rejected")


def verify_report_dir(path: Path | str) -> None:
    path = Path(path)
    manifest = load_json_path(path / "singularity-manifest.json")
    reject_float(manifest, "singularity_manifest")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise SingularityError("unsupported Singularity manifest version")
    if manifest_digest(manifest) != manifest.get("singularity_manifest_digest"):
        raise SingularityError("Singularity manifest digest mismatch")
    for name, info in manifest.get("inputs", {}).items():
        actual = sha256_bytes(_resolve_input(info["path"], path).read_bytes())
        if actual != info["sha256"]:
            raise SingularityError(f"Singularity input hash mismatch: {name}")
    for name, info in manifest["outputs"].items():
        actual = sha256_bytes((path / info["path"]).read_bytes())
        if actual != info["sha256"]:
            raise SingularityError(f"Singularity output hash mismatch: {name}")
    scorecard = load_json_path(path / "singularity-scorecard.json")
    resolution = load_json_path(path / "singularity-resolution.json")
    verify_scorecard_integrity(scorecard)
    if scorecard.get("singularity_digest") != manifest.get("singularity_digest"):
        raise SingularityError("Singularity manifest/scorecard digest mismatch")
    if resolution_digest(resolution) != manifest.get("singularity_resolution_digest"):
        raise SingularityError("Singularity resolution digest mismatch")
    expected = "".join(
        f"{sha256_bytes((path / name).read_bytes())}  {name}\n"
        for name in sorted(list(manifest["outputs"]) + ["singularity-manifest.json"])
    )
    if (path / "SHA256SUMS").read_text(encoding="utf-8") != expected:
        raise SingularityError("Singularity SHA256SUMS mismatch")
