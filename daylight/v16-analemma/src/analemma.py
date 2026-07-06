"""Daylight v16 Analemma self-progress proof-mass scoring."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .canonical_json import canonical_bytes, canonical_sha256, sha256_bytes
from . import solstice_bridge


NAME = "Daylight v16 Analemma"
VERSION = "daylight-v16-analemma-v0.1"
REPORT_VERSION = "daylight-v16-analemma-report-v0.1"
MANIFEST_VERSION = "daylight-v16-analemma-manifest-v0.1"
GENERATED_DATE = "2026-07-01"
REGISTRY_DOMAIN = "DAYLIGHT-ANALEMMA-REGISTRY:"
REPORT_DOMAIN = "DAYLIGHT-ANALEMMA-REPORT:"
MANIFEST_DOMAIN = "DAYLIGHT-ANALEMMA-MANIFEST:"
EXTERNAL_REVIEW_NAMESPACE = "DAYLIGHT-v16-ANALEMMA-EXTERNAL-REVIEW"
M_SCALE = 1_000_000
A_BASELINE = 1_000_000
HEX64 = set("0123456789abcdef")
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REGISTRY = PACKAGE_ROOT / "rules" / "proof-units.v1.json"


class AnalemmaError(ValueError):
    pass


def reject_float(value: Any, path: str = "value") -> None:
    if isinstance(value, float):
        raise AnalemmaError(f"float rejected at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_float(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_float(item, f"{path}[{index}]")


def is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= HEX64


def load_json(path: Path | str | None) -> Any:
    if path is None:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    reject_float(data, str(path))
    return data


def registry_digest(registry: dict[str, Any]) -> str:
    return canonical_sha256(registry, REGISTRY_DOMAIN)


def _expected_credit(registry: dict[str, Any], unit: dict[str, Any]) -> int:
    impact = registry["impact_weights"][unit["impact"]]
    difficulty = registry["difficulty_weights"][unit["difficulty"]]
    layer = registry["layer_multipliers"][unit["layer"]]
    return int(impact) * int(difficulty) * int(layer)


def load_registry(path: Path | str = DEFAULT_REGISTRY) -> dict[str, Any]:
    registry = load_json(path)
    if registry.get("version") != "daylight-v16-analemma-proof-units-v0.1":
        raise AnalemmaError("unsupported Analemma proof-unit registry version")
    units = registry.get("proof_units")
    if not isinstance(units, list) or not units:
        raise AnalemmaError("Analemma registry requires proof_units")
    seen: set[str] = set()
    for unit in units:
        if not isinstance(unit, dict):
            raise AnalemmaError("proof unit must be an object")
        uid = unit.get("id")
        if not isinstance(uid, str) or not uid:
            raise AnalemmaError("proof unit id must be non-empty")
        if uid in seen:
            raise AnalemmaError(f"duplicate proof unit id: {uid}")
        seen.add(uid)
        for key in ("domain", "layer", "impact", "difficulty", "verifier", "claim_scope"):
            if not isinstance(unit.get(key), str) or not unit[key]:
                raise AnalemmaError(f"{uid}: missing {key}")
        expected = _expected_credit(registry, unit)
        if unit.get("base_credit") != expected:
            raise AnalemmaError(f"{uid}: base_credit {unit.get('base_credit')} != expected {expected}")
        if unit["verifier"] not in VERIFIERS:
            raise AnalemmaError(f"{uid}: unknown verifier {unit['verifier']}")
    baseline = registry.get("baseline_proof_mass")
    if not isinstance(baseline, int) or baseline <= 0:
        raise AnalemmaError("baseline_proof_mass must be a positive integer")
    return registry


def _root_key_digest(root_key: str) -> str:
    return hashlib.sha256(root_key.encode("utf-8")).hexdigest()


def _signature_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in {"signature", "root_key"}}


def hmac_signature(record: dict[str, Any], root_key: str, namespace: str = EXTERNAL_REVIEW_NAMESPACE) -> str:
    message = namespace.encode("utf-8") + b":" + canonical_bytes(_signature_payload(record))
    return hmac.new(root_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sign_external_review(record: dict[str, Any], root_key: str) -> dict[str, Any]:
    signed = dict(record)
    signed["root_key_digest"] = _root_key_digest(root_key)
    signed["signature_namespace"] = EXTERNAL_REVIEW_NAMESPACE
    signed["fixture_hmac_only"] = True
    signed["signature"] = hmac_signature(signed, root_key)
    return signed


def _valid_hmac(record: dict[str, Any], namespace: str = EXTERNAL_REVIEW_NAMESPACE) -> bool:
    # HMAC is symmetric: a record that supplies the key needed to verify itself
    # is self-authorizing, not external authority. Keep the helper for fixtures,
    # but never let HMAC evidence close public/external proof obligations.
    return False


def _list(evidence: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = evidence.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise AnalemmaError(f"{key} must be a list of objects")
    return value


def _solstice_closed_classes(solstice: dict[str, Any]) -> set[str]:
    return {str(row.get("evidence_class")) for row in solstice["closed_obligations"]}


def verify_solstice_scorecard_present(ctx: dict[str, Any]) -> bool:
    return is_hex_sha256(ctx["solstice"]["scorecard_digest"])


def verify_solstice_artifact_valid(ctx: dict[str, Any]) -> bool:
    return ctx["solstice"]["claim_score_M"] >= 0 and is_hex_sha256(ctx["solstice"]["artifact_manifest_digest"])


def verify_output_ledger_transition(ctx: dict[str, Any]) -> bool:
    return is_hex_sha256(ctx["solstice"]["output_ledger_head"])


def verify_manifest_closure(ctx: dict[str, Any]) -> bool:
    manifest = ctx["solstice"]["manifest"]
    return is_hex_sha256(manifest.get("artifact_manifest_digest")) and bool(manifest.get("outputs"))


def verify_weight_vector_pinned(ctx: dict[str, Any]) -> bool:
    return is_hex_sha256(ctx["solstice"]["weight_vector_digest"])


def verify_evidence_resolution_bound(ctx: dict[str, Any]) -> bool:
    return is_hex_sha256(ctx["solstice"]["evidence_resolution_digest"])


def verify_semantic_corpus_replay(ctx: dict[str, Any]) -> bool:
    return "adversarial_input" in _solstice_closed_classes(ctx["solstice"]) and "transcript_mismatch" in _solstice_closed_classes(ctx["solstice"])


def verify_claim_boundary_encoded(ctx: dict[str, Any]) -> bool:
    boundary = ctx["solstice"]["claim_boundary"]
    return set(boundary) >= {
        "production_allowed",
        "runtime_containment_claim",
        "whole_system_post_quantum_safety_claim",
        "external_certification_claim",
    }


def verify_manual_score_surface_closed(ctx: dict[str, Any]) -> bool:
    scorecard = ctx["solstice"]["scorecard"]
    return scorecard.get("manual_override") is False and scorecard.get("manual_edit_allowed") is False


def verify_no_claim_score_inflation(ctx: dict[str, Any]) -> bool:
    return ctx["D_claim_M"] == ctx["solstice"]["claim_score_M"]


def verify_zenith_report_valid(ctx: dict[str, Any]) -> bool:
    report = ctx["evidence"].get("zenith_report")
    if not isinstance(report, dict):
        return False
    path = report.get("path")
    digest = report.get("sha256")
    if not isinstance(path, str) or not is_hex_sha256(digest):
        return False
    file_path = Path(path)
    if not file_path.is_absolute():
        file_path = Path.cwd() / file_path
    if not file_path.is_file() or sha256_bytes(file_path.read_bytes()) != digest:
        return False
    data = json.loads(file_path.read_text(encoding="utf-8"))
    return data.get("score_inflation_M") == 0 and data.get("solstice_score_M") == ctx["D_claim_M"]


def verify_three_rebuilds(ctx: dict[str, Any]) -> bool:
    release_digest = ctx["solstice"]["artifact_manifest_digest"]
    valid = [
        row for row in _list(ctx["evidence"], "rebuilds")
        if row.get("output_artifact_digest") == release_digest
        and row.get("release_artifact_digest") == release_digest
        and is_hex_sha256(row.get("environment_digest"))
    ]
    return len(valid) >= 3 and len({row.get("builder_identity") for row in valid}) >= 3 and len({row.get("environment_digest") for row in valid}) >= 3


def verify_cross_impl_agreement(ctx: dict[str, Any]) -> bool:
    rows = _list(ctx["evidence"], "implementation_outputs")
    valid = [row for row in rows if row.get("scorecard_digest") == ctx["solstice"]["scorecard_digest"] and is_hex_sha256(row.get("output_vector_digest"))]
    families = {row.get("implementation_family") for row in valid}
    digests = {row.get("output_vector_digest") for row in valid}
    return len(families) >= 3 and len(digests) == 1 and "python" in families and "rust" in families


def _fuzz_clean(ctx: dict[str, Any], target: str) -> bool:
    for row in _list(ctx["evidence"], "fuzz_campaigns"):
        if row.get("target") != target:
            continue
        if int(row.get("crash_count", -1)) != int(row.get("triaged_crash_count", -2)):
            return False
        if is_hex_sha256(row.get("coverage_report_digest")):
            return True
    return False


def verify_parser_fuzz_clean(ctx: dict[str, Any]) -> bool:
    return _fuzz_clean(ctx, "parser")


def verify_artifact_fuzz_clean(ctx: dict[str, Any]) -> bool:
    return _fuzz_clean(ctx, "artifact")


def verify_formal_rejection_model(ctx: dict[str, Any]) -> bool:
    return any(row.get("model") == "rejection_rules" and is_hex_sha256(row.get("result_digest")) for row in _list(ctx["evidence"], "formal_models"))


def verify_provider_pq_vectors(ctx: dict[str, Any]) -> bool:
    return any(row.get("suite") == "pq_provider_vectors" and is_hex_sha256(row.get("result_digest")) for row in _list(ctx["evidence"], "provider_vectors"))


def verify_signed_external_review_set(ctx: dict[str, Any]) -> bool:
    reviews = []
    for row in _list(ctx["evidence"], "external_reviews"):
        if row.get("signature_namespace") != EXTERNAL_REVIEW_NAMESPACE:
            continue
        if row.get("fixture_material_used") is not False:
            continue
        if row.get("reviewed_artifact_digest") != ctx["solstice"]["artifact_manifest_digest"]:
            continue
        if is_hex_sha256(row.get("report_digest")) and _valid_hmac(row):
            reviews.append(row)
    return len(reviews) >= 2 and len({row.get("reviewer_identity") for row in reviews}) >= 2


def verify_production_authority(ctx: dict[str, Any]) -> bool:
    authority = ctx["evidence"].get("production_authority", {})
    if not isinstance(authority, dict):
        return False
    return False


VERIFIERS = {
    "verify_solstice_scorecard_present": verify_solstice_scorecard_present,
    "verify_solstice_artifact_valid": verify_solstice_artifact_valid,
    "verify_output_ledger_transition": verify_output_ledger_transition,
    "verify_manifest_closure": verify_manifest_closure,
    "verify_weight_vector_pinned": verify_weight_vector_pinned,
    "verify_evidence_resolution_bound": verify_evidence_resolution_bound,
    "verify_semantic_corpus_replay": verify_semantic_corpus_replay,
    "verify_claim_boundary_encoded": verify_claim_boundary_encoded,
    "verify_manual_score_surface_closed": verify_manual_score_surface_closed,
    "verify_no_claim_score_inflation": verify_no_claim_score_inflation,
    "verify_zenith_report_valid": verify_zenith_report_valid,
    "verify_three_rebuilds": verify_three_rebuilds,
    "verify_cross_impl_agreement": verify_cross_impl_agreement,
    "verify_parser_fuzz_clean": verify_parser_fuzz_clean,
    "verify_artifact_fuzz_clean": verify_artifact_fuzz_clean,
    "verify_formal_rejection_model": verify_formal_rejection_model,
    "verify_provider_pq_vectors": verify_provider_pq_vectors,
    "verify_signed_external_review_set": verify_signed_external_review_set,
    "verify_production_authority": verify_production_authority,
}


def _manual_credit_rejected(evidence: dict[str, Any]) -> None:
    text = json.dumps(evidence, sort_keys=True)
    forbidden = ("manual_credit", "base_credit_override", "claim_score_override_M")
    for item in forbidden:
        if item in text:
            raise AnalemmaError(f"manual scoring field rejected: {item}")


def _closed_units(registry: dict[str, Any], ctx: dict[str, Any]) -> set[str]:
    closed: set[str] = set()
    for unit in registry["proof_units"]:
        verifier = VERIFIERS[unit["verifier"]]
        if verifier(ctx):
            closed.add(unit["id"])
    return closed


def _credit_by_id(registry: dict[str, Any]) -> dict[str, int]:
    return {unit["id"]: int(unit["base_credit"]) for unit in registry["proof_units"]}


def _debt_units(history: dict[str, Any], closed: set[str], registry: dict[str, Any]) -> tuple[set[str], set[str]]:
    known = set(_credit_by_id(registry))
    previous = {uid for uid in history.get("previous_closed_units", []) if uid in known}
    explicit_reopened = {uid for uid in history.get("reopened_units", []) if uid in known}
    stale = {uid for uid in history.get("stale_units", []) if uid in known}
    reopened = (previous - closed) | explicit_reopened
    return reopened, stale


def analemma_score_A(proof_mass: int, baseline: int) -> int:
    if baseline <= 0:
        raise AnalemmaError("baseline proof mass must be positive")
    return max(0, proof_mass) * A_BASELINE // baseline


def proof_mass_growth_basis_points(proof_mass: int, baseline: int) -> int:
    if baseline <= 0:
        raise AnalemmaError("baseline proof mass must be positive")
    return (proof_mass - baseline) * 10_000 // baseline


def _external_trust_M(solstice: dict[str, Any]) -> int:
    possible = int(solstice["external_residue_M"])
    if possible <= 0:
        return M_SCALE
    signed = possible - int(solstice["open_external_residue_M"])
    return max(0, signed) * M_SCALE // possible


def _claim_level(solstice: dict[str, Any], evidence: dict[str, Any], external_trust_M: int) -> str:
    if solstice["open_internal_residue_M"] > 0:
        return "C0_internal_research"
    if external_trust_M == 0:
        return "C1_replayable_public_artifact"
    if external_trust_M < M_SCALE:
        return "C2_partially_attested"
    ctx = {"solstice": solstice, "evidence": evidence}
    if not verify_production_authority(ctx):
        return "C3_externally_reviewed"
    if not evidence.get("runtime_containment", {}).get("valid"):
        return "C4_production_authority_eligible"
    return "C5_production_allowed"


def build_report(
    artifact_dir: Path | str,
    *,
    registry_path: Path | str = DEFAULT_REGISTRY,
    evidence_path: Path | str | None = None,
    history_path: Path | str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = load_registry(registry_path)
    evidence = load_json(evidence_path) if evidence_path else {}
    history = load_json(history_path) if history_path else {}
    if not isinstance(evidence, dict) or not isinstance(history, dict):
        raise AnalemmaError("evidence and history must be JSON objects")
    _manual_credit_rejected(evidence)
    if evidence.get("claim_score_override_M") is not None:
        raise AnalemmaError("Analemma cannot override D_claim")
    if history.get("manual_score_regression") is True or history.get("security_bypass_regression") is True:
        raise AnalemmaError("release candidate rejected by regression policy")

    solstice = solstice_bridge.load_and_verify(artifact_dir)
    D_claim_M = solstice["claim_score_M"]
    ctx = {
        "registry": registry,
        "evidence": evidence,
        "history": history,
        "solstice": solstice,
        "D_claim_M": D_claim_M,
    }
    closed = _closed_units(registry, ctx)
    credits = _credit_by_id(registry)
    closed_credit = sum(credits[uid] for uid in closed)
    reopened, stale = _debt_units(history, closed, registry)
    regression_debt = sum(credits[uid] for uid in reopened) * int(registry["regression_multiplier"])
    staleness_debt = sum(credits[uid] for uid in stale) * int(registry["stale_penalty"])
    proof_mass = max(0, closed_credit - regression_debt - staleness_debt)
    baseline = int(registry["baseline_proof_mass"])
    A_self_A = analemma_score_A(proof_mass, baseline)
    previous_A = int(history.get("previous_analemma_score_A", A_self_A))
    best_A = int(history.get("best_analemma_score_A", A_self_A))
    external_trust_M = _external_trust_M(solstice)
    claim_level = _claim_level(solstice, evidence, external_trust_M)
    debt_A = analemma_score_A(regression_debt, baseline)
    stale_A = analemma_score_A(staleness_debt, baseline)
    all_units = {unit["id"] for unit in registry["proof_units"]}
    resolution = {
        "resolution_version": "daylight-v16-analemma-resolution-v0.1",
        "analemma_registry_digest": registry_digest(registry),
        "solstice_scorecard_digest": solstice["scorecard_digest"],
        "solstice_artifact_manifest_digest": solstice["artifact_manifest_digest"],
        "closed_units": sorted(closed),
        "open_units": sorted(all_units - closed),
        "reopened_units": sorted(reopened),
        "stale_units": sorted(stale),
        "closed_credit": closed_credit,
        "regression_debt": regression_debt,
        "staleness_debt": staleness_debt,
        "proof_mass": proof_mass,
    }
    report = {
        "report_version": REPORT_VERSION,
        "name": NAME,
        "version": VERSION,
        "D_claim_M": D_claim_M,
        "A_self_A": A_self_A,
        "E_trust_M": external_trust_M,
        "C_level": claim_level,
        "analemma_registry_digest": registry_digest(registry),
        "baseline_release": registry["baseline_release"],
        "baseline_proof_mass": baseline,
        "closed_credit": closed_credit,
        "proof_mass": proof_mass,
        "proof_mass_growth_basis_points": proof_mass_growth_basis_points(proof_mass, baseline),
        "regression_debt": regression_debt,
        "staleness_debt": staleness_debt,
        "regression_debt_A": debt_A,
        "staleness_debt_A": stale_A,
        "delta_since_baseline_A": A_self_A - A_BASELINE,
        "delta_since_previous_A": A_self_A - previous_A,
        "delta_since_best_A": A_self_A - best_A,
        "previous_analemma_score_A": previous_A,
        "best_analemma_score_A": best_A,
        "closed_units": resolution["closed_units"],
        "open_units": resolution["open_units"],
        "reopened_units": resolution["reopened_units"],
        "stale_units": resolution["stale_units"],
        "score_inflation_M": 0,
        "claim_boundary": solstice["claim_boundary"],
        "non_claims": [
            "Analemma self-progress does not modify D_claim",
            "Analemma is self-progress proof mass, not external certification",
            "External review upgrades claim level, not internal self-progress eligibility",
            "ProductionAllowed remains governed by separate authority gates"
        ]
    }
    if report["D_claim_M"] != solstice["claim_score_M"] or report["score_inflation_M"] != 0:
        raise AnalemmaError("Analemma score inflation invariant failed")
    return report, resolution


def report_digest(report: dict[str, Any]) -> str:
    return canonical_sha256(report, REPORT_DOMAIN)


def resolution_digest(resolution: dict[str, Any]) -> str:
    return canonical_sha256(resolution, "DAYLIGHT-ANALEMMA-RESOLUTION:")


def manifest_digest(manifest: dict[str, Any]) -> str:
    body = {key: value for key, value in manifest.items() if key != "analemma_manifest_digest"}
    return canonical_sha256(body, MANIFEST_DOMAIN)


def _repo_relative(path: Path) -> str:
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        return str(resolved)


def _resolve_manifest_input(path_text: str, report_dir: Path) -> Path:
    candidate = Path(path_text)
    if candidate.is_absolute():
        return candidate
    repo_candidate = REPO_ROOT / candidate
    if repo_candidate.exists():
        return repo_candidate
    return report_dir / candidate


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build_report_artifact(
    artifact_dir: Path | str,
    *,
    out_dir: Path | str,
    registry_path: Path | str = DEFAULT_REGISTRY,
    evidence_path: Path | str | None = None,
    history_path: Path | str | None = None,
) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry(registry_path)
    report, resolution = build_report(
        artifact_dir,
        registry_path=registry_path,
        evidence_path=evidence_path,
        history_path=history_path,
    )
    outputs = {
        "analemma-report.json": _json_bytes(report),
        "analemma-resolution.json": _json_bytes(resolution),
    }
    artifact_dir = Path(artifact_dir)
    inputs = {
        "registry": {"path": _repo_relative(Path(registry_path)), "sha256": sha256_bytes(Path(registry_path).read_bytes())},
    }
    solstice_files = {
        "solstice_scorecard": "scorecard.v15-solstice.json",
        "solstice_receipt": "reproducibility-receipt.v15-solstice.json",
        "solstice_output_ledger": "output-ledger.v15-solstice.jsonl",
        "solstice_frontier_report": "frontier-report.v15-solstice.json",
        "solstice_manifest": "artifact-manifest.solstice.json",
        "solstice_sha256sums": "SHA256SUMS",
    }
    for key, name in solstice_files.items():
        file_path = artifact_dir / name
        if file_path.is_file():
            inputs[key] = {"path": _repo_relative(file_path), "sha256": sha256_bytes(file_path.read_bytes())}
    if evidence_path is not None:
        inputs["evidence"] = {"path": _repo_relative(Path(evidence_path)), "sha256": sha256_bytes(Path(evidence_path).read_bytes())}
    if history_path is not None:
        inputs["history"] = {"path": _repo_relative(Path(history_path)), "sha256": sha256_bytes(Path(history_path).read_bytes())}
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "artifact": NAME,
        "generated_date": GENERATED_DATE,
        "inputs": inputs,
        "outputs": {name: {"path": name, "sha256": sha256_bytes(data)} for name, data in sorted(outputs.items())},
        "analemma_registry_digest": registry_digest(registry),
        "analemma_report_digest": report_digest(report),
        "analemma_resolution_digest": resolution_digest(resolution),
        "D_claim_M": report["D_claim_M"],
        "A_self_A": report["A_self_A"],
        "E_trust_M": report["E_trust_M"],
        "C_level": report["C_level"],
        "score_inflation_M": 0,
    }
    manifest["analemma_manifest_digest"] = manifest_digest(manifest)
    outputs["analemma-manifest.json"] = _json_bytes(manifest)
    outputs["SHA256SUMS"] = "".join(f"{sha256_bytes(data)}  {name}\n" for name, data in sorted(outputs.items())).encode("utf-8")
    for name, data in outputs.items():
        (out_dir / name).write_bytes(data)
    return manifest


def verify_report_dir(path: Path | str) -> None:
    path = Path(path)
    manifest = json.loads((path / "analemma-manifest.json").read_text(encoding="utf-8"))
    reject_float(manifest, "analemma_manifest")
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise AnalemmaError("unsupported Analemma manifest version")
    if manifest_digest(manifest) != manifest.get("analemma_manifest_digest"):
        raise AnalemmaError("Analemma manifest digest mismatch")
    for name, info in manifest.get("inputs", {}).items():
        actual = sha256_bytes(_resolve_manifest_input(info["path"], path).read_bytes())
        if actual != info["sha256"]:
            raise AnalemmaError(f"Analemma input hash mismatch: {name}")
    for name, info in manifest["outputs"].items():
        actual = sha256_bytes((path / info["path"]).read_bytes())
        if actual != info["sha256"]:
            raise AnalemmaError(f"Analemma output hash mismatch: {name}")
    report = json.loads((path / "analemma-report.json").read_text(encoding="utf-8"))
    resolution = json.loads((path / "analemma-resolution.json").read_text(encoding="utf-8"))
    reject_float(report, "analemma_report")
    reject_float(resolution, "analemma_resolution")
    if report_digest(report) != manifest.get("analemma_report_digest"):
        raise AnalemmaError("Analemma report digest mismatch")
    if resolution_digest(resolution) != manifest.get("analemma_resolution_digest"):
        raise AnalemmaError("Analemma resolution digest mismatch")
    for key in ("D_claim_M", "A_self_A", "E_trust_M", "C_level", "score_inflation_M"):
        if report.get(key) != manifest.get(key):
            raise AnalemmaError(f"Analemma manifest/report mismatch: {key}")
    expected = "".join(
        f"{sha256_bytes((path / name).read_bytes())}  {name}\n"
        for name in sorted(list(manifest["outputs"]) + ["analemma-manifest.json"])
    )
    if (path / "SHA256SUMS").read_text(encoding="utf-8") != expected:
        raise AnalemmaError("Analemma SHA256SUMS mismatch")
