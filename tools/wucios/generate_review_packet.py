#!/usr/bin/env python3
"""Generate the Tarski Review Appliance packet."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REVIEW_DIR = ROOT / "build/wucios/review"

PROFILE_DIR = ROOT / "wucios/profiles"
SUBSTRATE_DIR = ROOT / "wucios/substrates"
COMPONENT_REGISTER = ROOT / "wucios/components/component-register.json"
GODEL_DOC = ROOT / "docs/wucios/GODEL_BOUNDARY.md"

REQUIRED_OUTPUTS = [
    "review.md",
    "review.json",
    "euclid-trial-phase-1.md",
    "euclid-trial-phase-1.json",
    "euclid-trial-phase-2.md",
    "euclid-trial-phase-2.json",
    "euclid-trial-phase-2b.md",
    "euclid-trial-phase-2b.json",
    "euclid-trial-phase-3a.md",
    "euclid-trial-phase-3a.json",
    "euclid-trial-phase-3b-readiness.md",
    "euclid-trial-phase-3b-readiness.json",
    "substrate-matrix.md",
    "substrate-matrix.json",
    "surface-report.md",
    "surface-report.json",
    "package-manifest.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "hash-manifest.sha256",
    "godel-boundary.md",
    "daylight-wucios-score.json",
    "daylight-wucios-score.md",
]

OPTIONAL_OUTPUTS = [
    "euclid-trial-phase-3c-a.md",
    "euclid-trial-phase-3c-a.json",
    "euclid-trial-phase-3c-b.md",
    "euclid-trial-phase-3c-b.json",
    "euclid-trial-phase-3c-c.md",
    "euclid-trial-phase-3c-c.json",
]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_many(directory: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        items.append(load_json(path))
    return items


def ensure_prerequisites() -> list[str]:
    notes: list[str] = []
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    if not (REVIEW_DIR / "substrate-matrix.json").is_file():
        result = subprocess.run([sys.executable, str(ROOT / "tools/wucios/generate_substrate_matrix.py")], cwd=ROOT)
        notes.append(f"generated substrate matrix: exit {result.returncode}")
    if not (REVIEW_DIR / "euclid-trial-phase-1.json").is_file():
        result = subprocess.run([sys.executable, str(ROOT / "tools/wucios/run_euclid_trial.py")], cwd=ROOT)
        notes.append(f"generated Euclid Trial Phase 1 report: exit {result.returncode}")
    if not (REVIEW_DIR / "euclid-trial-phase-2.json").is_file():
        result = subprocess.run([sys.executable, str(ROOT / "tools/wucios/run_euclid_trial_phase_2.py")], cwd=ROOT)
        notes.append(f"generated Euclid Trial Phase 2 report: exit {result.returncode}")
    if not (REVIEW_DIR / "euclid-trial-phase-2b.json").is_file():
        result = subprocess.run([sys.executable, str(ROOT / "tools/wucios/run_euclid_trial_phase_2.py"), "--phase2b"], cwd=ROOT)
        notes.append(f"generated Euclid Trial Phase 2B report: exit {result.returncode}")
    if not (REVIEW_DIR / "daylight-wucios-score.json").is_file():
        result = subprocess.run([sys.executable, str(ROOT / "tools/wucios/score_wucios.py")], cwd=ROOT)
        notes.append(f"generated score material: exit {result.returncode}")
    if not (REVIEW_DIR / "surface-report.json").is_file():
        script = ROOT / "tools/wucios/surface_inventory.sh"
        if script.is_file():
            result = subprocess.run(["bash", str(script)], cwd=ROOT)
            notes.append(f"generated surface inventory: exit {result.returncode}")
        else:
            notes.append("surface inventory script missing")
    return notes


def read_text_or_not_measured(name: str) -> str:
    path = REVIEW_DIR / name
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return "NOT_MEASURED"


def measurement_summary() -> dict[str, str]:
    summary: dict[str, str] = {}
    for name in [
        "package-manifest.txt",
        "enabled-services.txt",
        "listening-ports.txt",
        "suid-sgid.txt",
        "kernel-modules.txt",
        "surface-report.json",
        "daylight-wucios-score.json",
        "substrate-matrix.json",
        "euclid-trial-phase-1.json",
        "euclid-trial-phase-2.json",
        "euclid-trial-phase-2b.json",
        "euclid-trial-phase-3a.json",
        "euclid-trial-phase-3b-readiness.json",
    ]:
        text = read_text_or_not_measured(name)
        if text == "NOT_MEASURED":
            summary[name] = "NOT_MEASURED"
        elif "NOT_MEASURED" in text or "PARTIAL" in text:
            summary[name] = "PARTIAL"
        else:
            summary[name] = "PRESENT"
    return summary


def load_generated_summary() -> dict[str, str]:
    substrate_selection = "NO_SUBSTRATE_SELECTED"
    euclid_phase_1_status = "TRIAL_DATA_PARTIAL"
    euclid_phase_2_status = "NOT_RUN"
    euclid_phase_2_execution = "NOT_RUN"
    euclid_phase_2_candidates = "NOT_RUN"
    euclid_phase_2_artifacts = "NOT_RUN"
    euclid_phase_2b_status = "NOT_RUN"
    euclid_phase_2b_execution = "NOT_RUN"
    euclid_phase_2b_candidate_count = "NOT_RUN"
    euclid_phase_2b_candidates = "NOT_RUN"
    euclid_phase_2b_artifacts = "NOT_RUN"
    euclid_phase_2b_blockers = "NOT_RUN"
    euclid_phase_2b_missing = "NOT_RUN"
    euclid_phase_3a_status = "NOT_RUN"
    euclid_phase_3a_execution = "NOT_RUN"
    euclid_phase_3a_candidate_count = "NOT_RUN"
    euclid_phase_3a_backend_summary = "NOT_RUN"
    euclid_phase_3a_definition_statuses = "NOT_RUN"
    euclid_phase_3a_attempt_readiness = "NOT_RUN"
    euclid_phase_3a_missing_inputs = "NOT_RUN"
    euclid_phase_3b_status = "NOT_RUN"
    euclid_phase_3b_execution = "NOT_RUN"
    euclid_phase_3b_backend_summary = "NOT_RUN"
    euclid_phase_3b_candidate_readiness = "NOT_RUN"
    euclid_phase_3b_future_authorization = "NOT_RUN"
    euclid_phase_3b_score_status = "NOT_RUN"
    euclid_phase_3b_boundaries = "NOT_RUN"
    euclid_phase_3c_a_status = "NOT_RUN"
    euclid_phase_3c_a_execution = "NOT_RUN"
    euclid_phase_3c_a_backend_summary = "NOT_RUN"
    euclid_phase_3c_a_l2_synthetic_smoke = "NOT_RUN"
    euclid_phase_3c_a_guardrails = "NOT_RUN"
    euclid_phase_3c_a_boundaries = "NOT_RUN"
    euclid_phase_3c_a_score_status = "NOT_RUN"
    euclid_phase_3c_b_status = "NOT_RUN"
    euclid_phase_3c_b_execution = "NOT_RUN"
    euclid_phase_3c_b_in_scope = "NOT_RUN"
    euclid_phase_3c_b_out_of_scope = "NOT_RUN"
    euclid_phase_3c_b_candidate_statuses = "NOT_RUN"
    euclid_phase_3c_b_l2_scaffold = "NOT_RUN"
    euclid_phase_3c_b_guardrails = "NOT_RUN"
    euclid_phase_3c_b_score_status = "NOT_RUN"
    euclid_phase_3c_b_boundaries = "NOT_RUN"
    euclid_phase_3c_c_status = "NOT_RUN"
    euclid_phase_3c_c_execution = "NOT_RUN"
    euclid_phase_3c_c_in_scope = "NOT_RUN"
    euclid_phase_3c_c_out_of_scope = "NOT_RUN"
    euclid_phase_3c_c_candidate_statuses = "NOT_RUN"
    euclid_phase_3c_c_l2_scaffold = "NOT_RUN"
    euclid_phase_3c_c_guardrails = "NOT_RUN"
    euclid_phase_3c_c_score_status = "NOT_RUN"
    euclid_phase_3c_c_boundaries = "NOT_RUN"
    euclid_phase_3c_d_status = "DEFERRED_LOCKED"
    euclid_phase_3c_e_status = "DEFERRED_LOCKED"
    score_status = "NO_ARTIFACT_SCORE"
    score_artifact_sha256 = "NOT_MEASURED"

    substrate_matrix = REVIEW_DIR / "substrate-matrix.json"
    if substrate_matrix.is_file():
        try:
            data = load_json(substrate_matrix)
            substrate_selection = str(data.get("selection_status", substrate_selection))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            substrate_selection = "NOT_MEASURED"

    euclid_phase_1 = REVIEW_DIR / "euclid-trial-phase-1.json"
    if euclid_phase_1.is_file():
        try:
            data = load_json(euclid_phase_1)
            euclid_phase_1_status = str(data.get("trial_status", euclid_phase_1_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_1_status = "NOT_MEASURED"

    euclid_phase_2 = REVIEW_DIR / "euclid-trial-phase-2.json"
    if euclid_phase_2.is_file():
        try:
            data = load_json(euclid_phase_2)
            euclid_phase_2_status = str(data.get("global_status", euclid_phase_2_status))
            euclid_phase_2_execution = str(data.get("execution_mode", euclid_phase_2_execution))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_2_candidates = ", ".join(
                f"{candidate.get('id', candidate.get('candidate', 'unknown'))}:{candidate.get('phase_status', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_2_artifacts = ", ".join(
                f"{candidate.get('id', candidate.get('candidate', 'unknown'))}:{str(candidate.get('artifact', {}).get('present', False)).lower()}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_2_status = "NOT_MEASURED"

    euclid_phase_2b = REVIEW_DIR / "euclid-trial-phase-2b.json"
    if euclid_phase_2b.is_file():
        try:
            data = load_json(euclid_phase_2b)
            euclid_phase_2b_status = str(data.get("global_status", euclid_phase_2b_status))
            euclid_phase_2b_execution = str(data.get("execution_mode", euclid_phase_2b_execution))
            euclid_phase_2b_candidate_count = str(data.get("candidate_count", euclid_phase_2b_candidate_count))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_2b_candidates = ", ".join(
                f"{candidate.get('id', candidate.get('candidate', 'unknown'))}:{candidate.get('phase_status', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_2b_artifacts = ", ".join(
                f"{candidate.get('id', candidate.get('candidate', 'unknown'))}:{str(candidate.get('artifact', {}).get('present', False)).lower()}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_2b_blockers = ", ".join(
                f"{candidate.get('id', candidate.get('candidate', 'unknown'))}:{'/'.join(candidate.get('blockers', [])) or 'NONE_DETECTED'}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_2b_missing = ", ".join(str(item) for item in data.get("missing_measurements", [])) or "NONE"
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_2b_status = "NOT_MEASURED"

    euclid_phase_3a = REVIEW_DIR / "euclid-trial-phase-3a.json"
    if euclid_phase_3a.is_file():
        try:
            data = load_json(euclid_phase_3a)
            euclid_phase_3a_status = str(data.get("global_status", euclid_phase_3a_status))
            euclid_phase_3a_execution = str(data.get("execution_mode", euclid_phase_3a_execution))
            euclid_phase_3a_candidate_count = str(data.get("candidate_count", euclid_phase_3a_candidate_count))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_3a_backend_summary = ", ".join(
                f"{key}:{value}" for key, value in sorted(data.get("backend_summary", {}).items())
            ) or "NOT_MEASURED"
            euclid_phase_3a_definition_statuses = ", ".join(
                f"{candidate.get('id', 'unknown')}:{candidate.get('definition_status', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_3a_attempt_readiness = ", ".join(
                f"{candidate.get('id', 'unknown')}:{candidate.get('attempt_readiness', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_3a_missing_inputs = ", ".join(
                f"{candidate.get('id', 'unknown')}:{'/'.join(candidate.get('missing_inputs', [])) or 'NONE_DETECTED'}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_3a_status = "NOT_MEASURED"

    euclid_phase_3b = REVIEW_DIR / "euclid-trial-phase-3b-readiness.json"
    if euclid_phase_3b.is_file():
        try:
            data = load_json(euclid_phase_3b)
            euclid_phase_3b_status = str(data.get("global_status", euclid_phase_3b_status))
            euclid_phase_3b_execution = str(data.get("execution_mode", euclid_phase_3b_execution))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_3b_backend_summary = ", ".join(
                f"{key}:{value}" for key, value in sorted(data.get("backend_summary", {}).items())
            ) or "NOT_MEASURED"
            euclid_phase_3b_candidate_readiness = ", ".join(
                f"{candidate.get('id', 'unknown')}:{candidate.get('readiness', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_3b_future_authorization = ", ".join(
                f"{candidate.get('id', 'unknown')}:{candidate.get('future_authorization_level_required', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            euclid_phase_3b_score_status = str(data.get("score_status", euclid_phase_3b_score_status))
            euclid_phase_3b_boundaries = ", ".join(
                f"{name}:{str(data.get(name, 'NOT_MEASURED')).lower()}"
                for name in [
                    "build_attempt_made",
                    "container_pull_attempted",
                    "container_build_attempted",
                    "container_run_attempted",
                    "vm_run_attempted",
                ]
            )
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_3b_status = "NOT_MEASURED"

    euclid_phase_3c_a = REVIEW_DIR / "euclid-trial-phase-3c-a.json"
    if euclid_phase_3c_a.is_file():
        try:
            data = load_json(euclid_phase_3c_a)
            euclid_phase_3c_a_status = str(data.get("global_status", euclid_phase_3c_a_status))
            euclid_phase_3c_a_execution = str(data.get("execution_mode", euclid_phase_3c_a_execution))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_3c_a_score_status = str(data.get("score_status", euclid_phase_3c_a_score_status))
            l1 = data.get("l1_backend_detection", {})
            l1_summary = l1.get("summary", {}) if isinstance(l1, dict) else {}
            euclid_phase_3c_a_backend_summary = ", ".join(
                f"{key}:{value}" for key, value in sorted(l1_summary.items())
            ) or "NOT_MEASURED"
            l2 = data.get("l2_synthetic_smoke", {})
            if isinstance(l2, dict):
                euclid_phase_3c_a_l2_synthetic_smoke = ", ".join(
                    f"{name}:{l2.get(name, {}).get('status', 'NOT_ATTEMPTED')}"
                    for name in ["podman", "buildah"]
                    if isinstance(l2.get(name, {}), dict)
                ) or "NOT_ATTEMPTED"
            guardrails = data.get("guardrails", [])
            if isinstance(guardrails, list):
                euclid_phase_3c_a_guardrails = ", ".join(
                    str(item.get("status", "UNKNOWN")) for item in guardrails if isinstance(item, dict)
                ) or "NO_GUARDRAIL_FAILURE_RECORDED"
            euclid_phase_3c_a_boundaries = ", ".join(
                f"{name}:{str(data.get(name, 'NOT_MEASURED')).lower()}"
                for name in [
                    "wucios_artifact_generated",
                    "substrate_artifact_attempt_made",
                    "runtime_inspection_attempted",
                    "container_pull_attempted",
                    "container_run_attempted",
                    "vm_run_attempted",
                    "network_used",
                ]
            )
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_3c_a_status = "NOT_MEASURED"

    euclid_phase_3c_b = REVIEW_DIR / "euclid-trial-phase-3c-b.json"
    if euclid_phase_3c_b.is_file():
        try:
            data = load_json(euclid_phase_3c_b)
            euclid_phase_3c_b_status = str(data.get("global_status", euclid_phase_3c_b_status))
            euclid_phase_3c_b_execution = str(data.get("execution_mode", euclid_phase_3c_b_execution))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_3c_b_score_status = str(data.get("score_status", euclid_phase_3c_b_score_status))
            euclid_phase_3c_b_in_scope = ", ".join(str(item) for item in data.get("in_scope_candidates", [])) or "NOT_MEASURED"
            out_of_scope = data.get("out_of_scope_preserved", {})
            if isinstance(out_of_scope, dict):
                euclid_phase_3c_b_out_of_scope = ", ".join(
                    f"{key}:{'/'.join(str(item) for item in value)}"
                    for key, value in sorted(out_of_scope.items())
                    if isinstance(value, list)
                ) or "NOT_MEASURED"
            euclid_phase_3c_b_candidate_statuses = ", ".join(
                f"{candidate.get('id', 'unknown')}:{candidate.get('preparation_status', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            l2 = data.get("l2_scaffold", {})
            if isinstance(l2, dict):
                euclid_phase_3c_b_l2_scaffold = ", ".join([
                    f"authorized:{str(l2.get('authorized', 'NOT_MEASURED')).lower()}",
                    f"attempted:{str(l2.get('attempted', 'NOT_MEASURED')).lower()}",
                ])
            guardrails = data.get("guardrails", [])
            if isinstance(guardrails, list):
                euclid_phase_3c_b_guardrails = ", ".join(
                    str(item.get("status", "UNKNOWN")) for item in guardrails if isinstance(item, dict)
                ) or "NO_GUARDRAIL_FAILURE_RECORDED"
            euclid_phase_3c_b_boundaries = ", ".join(
                f"{name}:{str(data.get(name, 'NOT_MEASURED')).lower()}"
                for name in [
                    "wucios_artifact_generated",
                    "substrate_artifact_attempt_made",
                    "rootfs_generation_attempted",
                    "runtime_inspection_attempted",
                    "container_build_attempted",
                    "container_run_attempted",
                    "image_pull_attempted",
                    "network_used",
                    "vm_run_attempted",
                ]
            )
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_3c_b_status = "NOT_MEASURED"

    euclid_phase_3c_c = REVIEW_DIR / "euclid-trial-phase-3c-c.json"
    if euclid_phase_3c_c.is_file():
        try:
            data = load_json(euclid_phase_3c_c)
            euclid_phase_3c_c_status = str(data.get("global_status", euclid_phase_3c_c_status))
            euclid_phase_3c_c_execution = str(data.get("execution_mode", euclid_phase_3c_c_execution))
            substrate_selection = str(data.get("substrate_selection", substrate_selection))
            euclid_phase_3c_c_score_status = str(data.get("score_status", euclid_phase_3c_c_score_status))
            euclid_phase_3c_c_in_scope = ", ".join(str(item) for item in data.get("in_scope_candidates", [])) or "NOT_MEASURED"
            out_of_scope = data.get("out_of_scope_preserved", {})
            if isinstance(out_of_scope, dict):
                euclid_phase_3c_c_out_of_scope = ", ".join(
                    f"{key}:{'/'.join(str(item) for item in value)}"
                    for key, value in sorted(out_of_scope.items())
                    if isinstance(value, list)
                ) or "NOT_MEASURED"
            euclid_phase_3c_c_candidate_statuses = ", ".join(
                f"{candidate.get('id', 'unknown')}:{candidate.get('preparation_status', 'NOT_MEASURED')}"
                for candidate in data.get("candidates", [])
                if isinstance(candidate, dict)
            ) or "NOT_MEASURED"
            l2 = data.get("l2_scaffold", {})
            if isinstance(l2, dict):
                euclid_phase_3c_c_l2_scaffold = ", ".join([
                    f"authorized:{str(l2.get('authorized', 'NOT_MEASURED')).lower()}",
                    f"attempted:{str(l2.get('attempted', 'NOT_MEASURED')).lower()}",
                ])
            guardrails = data.get("guardrails", [])
            if isinstance(guardrails, list):
                euclid_phase_3c_c_guardrails = ", ".join(
                    str(item.get("status", "UNKNOWN")) for item in guardrails if isinstance(item, dict)
                ) or "NO_GUARDRAIL_FAILURE_RECORDED"
            euclid_phase_3c_c_boundaries = ", ".join(
                f"{name}:{str(data.get(name, 'NOT_MEASURED')).lower()}"
                for name in [
                    "wucios_artifact_generated",
                    "artifact_hash_generated",
                    "substrate_artifact_attempt_made",
                    "rootfs_generation_attempted",
                    "store_realization_attempted",
                    "runtime_inspection_attempted",
                    "container_build_attempted",
                    "container_run_attempted",
                    "image_pull_attempted",
                    "network_used",
                    "vm_run_attempted",
                ]
            )
            score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            euclid_phase_3c_c_status = "NOT_MEASURED"

    score_json = REVIEW_DIR / "daylight-wucios-score.json"
    if score_json.is_file():
        try:
            data = load_json(score_json)
            score_artifact_sha256 = str(data.get("artifact", {}).get("sha256", "NOT_MEASURED"))
            if data.get("score_status") == "INVALID_WITHOUT_ARTIFACT":
                score_status = "NO_ARTIFACT_SCORE"
            else:
                score_status = str(data.get("score_status", score_status))
        except Exception:  # noqa: BLE001 - summary must degrade to explicit unknown.
            score_status = "NOT_MEASURED"

    return {
        "substrate_selection": substrate_selection,
        "euclid_phase_1_status": euclid_phase_1_status,
        "euclid_phase_2_status": euclid_phase_2_status,
        "euclid_phase_2_execution": euclid_phase_2_execution,
        "euclid_phase_2_candidates": euclid_phase_2_candidates,
        "euclid_phase_2_artifacts": euclid_phase_2_artifacts,
        "euclid_phase_2b_status": euclid_phase_2b_status,
        "euclid_phase_2b_execution": euclid_phase_2b_execution,
        "euclid_phase_2b_candidate_count": euclid_phase_2b_candidate_count,
        "euclid_phase_2b_candidates": euclid_phase_2b_candidates,
        "euclid_phase_2b_artifacts": euclid_phase_2b_artifacts,
        "euclid_phase_2b_blockers": euclid_phase_2b_blockers,
        "euclid_phase_2b_missing": euclid_phase_2b_missing,
        "euclid_phase_3a_status": euclid_phase_3a_status,
        "euclid_phase_3a_execution": euclid_phase_3a_execution,
        "euclid_phase_3a_candidate_count": euclid_phase_3a_candidate_count,
        "euclid_phase_3a_backend_summary": euclid_phase_3a_backend_summary,
        "euclid_phase_3a_definition_statuses": euclid_phase_3a_definition_statuses,
        "euclid_phase_3a_attempt_readiness": euclid_phase_3a_attempt_readiness,
        "euclid_phase_3a_missing_inputs": euclid_phase_3a_missing_inputs,
        "euclid_phase_3b_status": euclid_phase_3b_status,
        "euclid_phase_3b_execution": euclid_phase_3b_execution,
        "euclid_phase_3b_backend_summary": euclid_phase_3b_backend_summary,
        "euclid_phase_3b_candidate_readiness": euclid_phase_3b_candidate_readiness,
        "euclid_phase_3b_future_authorization": euclid_phase_3b_future_authorization,
        "euclid_phase_3b_score_status": euclid_phase_3b_score_status,
        "euclid_phase_3b_boundaries": euclid_phase_3b_boundaries,
        "euclid_phase_3c_a_status": euclid_phase_3c_a_status,
        "euclid_phase_3c_a_execution": euclid_phase_3c_a_execution,
        "euclid_phase_3c_a_backend_summary": euclid_phase_3c_a_backend_summary,
        "euclid_phase_3c_a_l2_synthetic_smoke": euclid_phase_3c_a_l2_synthetic_smoke,
        "euclid_phase_3c_a_guardrails": euclid_phase_3c_a_guardrails,
        "euclid_phase_3c_a_score_status": euclid_phase_3c_a_score_status,
        "euclid_phase_3c_a_boundaries": euclid_phase_3c_a_boundaries,
        "euclid_phase_3c_b_status": euclid_phase_3c_b_status,
        "euclid_phase_3c_b_execution": euclid_phase_3c_b_execution,
        "euclid_phase_3c_b_in_scope": euclid_phase_3c_b_in_scope,
        "euclid_phase_3c_b_out_of_scope": euclid_phase_3c_b_out_of_scope,
        "euclid_phase_3c_b_candidate_statuses": euclid_phase_3c_b_candidate_statuses,
        "euclid_phase_3c_b_l2_scaffold": euclid_phase_3c_b_l2_scaffold,
        "euclid_phase_3c_b_guardrails": euclid_phase_3c_b_guardrails,
        "euclid_phase_3c_b_score_status": euclid_phase_3c_b_score_status,
        "euclid_phase_3c_b_boundaries": euclid_phase_3c_b_boundaries,
        "euclid_phase_3c_c_status": euclid_phase_3c_c_status,
        "euclid_phase_3c_c_execution": euclid_phase_3c_c_execution,
        "euclid_phase_3c_c_in_scope": euclid_phase_3c_c_in_scope,
        "euclid_phase_3c_c_out_of_scope": euclid_phase_3c_c_out_of_scope,
        "euclid_phase_3c_c_candidate_statuses": euclid_phase_3c_c_candidate_statuses,
        "euclid_phase_3c_c_l2_scaffold": euclid_phase_3c_c_l2_scaffold,
        "euclid_phase_3c_c_guardrails": euclid_phase_3c_c_guardrails,
        "euclid_phase_3c_c_score_status": euclid_phase_3c_c_score_status,
        "euclid_phase_3c_c_boundaries": euclid_phase_3c_c_boundaries,
        "euclid_phase_3c_d_status": euclid_phase_3c_d_status,
        "euclid_phase_3c_e_status": euclid_phase_3c_e_status,
        "score_status": score_status,
        "score_artifact_sha256": score_artifact_sha256,
    }


def non_claims() -> list[str]:
    return [
        "WuciOS v2.4 is not externally certified.",
        "WuciOS v2.4 is not production authorized.",
        "WuciOS v2.4 is not government approved.",
        "WuciOS v2.4 is not seL4 equivalent.",
        "WuciOS v2.4 does not claim perfect security.",
        "Reduced size alone does not prove security.",
        "No substrate is selected until measured evidence exists.",
        "No score is release-authoritative without a current artifact hash.",
    ]


def compute_status(measurements: dict[str, str]) -> str:
    important_missing = [value for value in measurements.values() if value != "PRESENT"]
    if important_missing:
        return "REVIEW_PACKET_PARTIAL"
    return "REVIEW_PACKET_GENERATED"


def write_packet(prereq_notes: list[str]) -> dict[str, Any]:
    profiles = load_many(PROFILE_DIR)
    substrates = load_many(SUBSTRATE_DIR)
    components = load_json(COMPONENT_REGISTER)
    measurements = measurement_summary()
    generated_summary = load_generated_summary()
    status = compute_status(measurements)
    if GODEL_DOC.is_file():
        shutil.copyfile(GODEL_DOC, REVIEW_DIR / "godel-boundary.md")
    else:
        (REVIEW_DIR / "godel-boundary.md").write_text("NOT_MEASURED: GODEL_BOUNDARY.md missing\n", encoding="utf-8")

    outputs = {name: (REVIEW_DIR / name).is_file() for name in [*REQUIRED_OUTPUTS, *OPTIONAL_OUTPUTS]}
    packet = {
        "schema": "wucios.review_packet.v1",
        "review_status": status,
        "review_status_line": f"WuciOS v2.4 review status: {status}",
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "profiles": profiles,
        "substrates": substrates,
        "components": components,
        "summary": {
            "review_packet": status,
            **generated_summary,
        },
        "measurements": measurements,
        "non_claims": non_claims(),
        "outputs": outputs,
        "prerequisite_notes": prereq_notes,
    }
    (REVIEW_DIR / "review.json").write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# WuciOS v2.4 Review Packet",
        "",
        packet["review_status_line"],
        "",
        "## Summary",
        "",
        f"- Review packet: `{status}`",
        f"- Substrate selection: `{generated_summary['substrate_selection']}`",
        f"- Euclid Trial Phase 1: `{generated_summary['euclid_phase_1_status']}`",
        f"- Euclid Trial Phase 2: `{generated_summary['euclid_phase_2_status']}`",
        f"- Euclid Trial Phase 2 execution mode: `{generated_summary['euclid_phase_2_execution']}`",
        f"- Euclid Trial Phase 2 candidates: `{generated_summary['euclid_phase_2_candidates']}`",
        f"- Euclid Trial Phase 2 artifacts: `{generated_summary['euclid_phase_2_artifacts']}`",
        f"- Euclid Trial Phase 2B: `{generated_summary['euclid_phase_2b_status']}`",
        f"- Euclid Trial Phase 2B execution mode: `{generated_summary['euclid_phase_2b_execution']}`",
        f"- Euclid Trial Phase 2B candidate count: `{generated_summary['euclid_phase_2b_candidate_count']}`",
        f"- Euclid Trial Phase 2B candidates: `{generated_summary['euclid_phase_2b_candidates']}`",
        f"- Euclid Trial Phase 2B artifacts: `{generated_summary['euclid_phase_2b_artifacts']}`",
        f"- Euclid Trial Phase 2B blockers: `{generated_summary['euclid_phase_2b_blockers']}`",
        f"- Euclid Trial Phase 2B missing measurements: `{generated_summary['euclid_phase_2b_missing']}`",
        f"- Euclid Trial Phase 3A: `{generated_summary['euclid_phase_3a_status']}`",
        f"- Euclid Trial Phase 3A execution mode: `{generated_summary['euclid_phase_3a_execution']}`",
        f"- Euclid Trial Phase 3A candidate count: `{generated_summary['euclid_phase_3a_candidate_count']}`",
        f"- Euclid Trial Phase 3A backend summary: `{generated_summary['euclid_phase_3a_backend_summary']}`",
        f"- Euclid Trial Phase 3A definition statuses: `{generated_summary['euclid_phase_3a_definition_statuses']}`",
        f"- Euclid Trial Phase 3A attempt readiness: `{generated_summary['euclid_phase_3a_attempt_readiness']}`",
        f"- Euclid Trial Phase 3A missing inputs: `{generated_summary['euclid_phase_3a_missing_inputs']}`",
        f"- Euclid Trial Phase 3B Readiness: `{generated_summary['euclid_phase_3b_status']}`",
        f"- Euclid Trial Phase 3B Readiness execution mode: `{generated_summary['euclid_phase_3b_execution']}`",
        f"- Euclid Trial Phase 3B Readiness backend summary: `{generated_summary['euclid_phase_3b_backend_summary']}`",
        f"- Euclid Trial Phase 3B Readiness candidate readiness: `{generated_summary['euclid_phase_3b_candidate_readiness']}`",
        f"- Euclid Trial Phase 3B Readiness future authorization levels: `{generated_summary['euclid_phase_3b_future_authorization']}`",
        f"- Euclid Trial Phase 3B Readiness score status: `{generated_summary['euclid_phase_3b_score_status']}`",
        f"- Euclid Trial Phase 3B Readiness boundary booleans: `{generated_summary['euclid_phase_3b_boundaries']}`",
        f"- Euclid Trial Phase 3C-A: `{generated_summary['euclid_phase_3c_a_status']}`",
        f"- Euclid Trial Phase 3C-A execution mode: `{generated_summary['euclid_phase_3c_a_execution']}`",
        f"- Euclid Trial Phase 3C-A backend summary: `{generated_summary['euclid_phase_3c_a_backend_summary']}`",
        f"- Euclid Trial Phase 3C-A L2 synthetic smoke: `{generated_summary['euclid_phase_3c_a_l2_synthetic_smoke']}`",
        f"- Euclid Trial Phase 3C-A guardrails: `{generated_summary['euclid_phase_3c_a_guardrails']}`",
        f"- Euclid Trial Phase 3C-A score status: `{generated_summary['euclid_phase_3c_a_score_status']}`",
        f"- Euclid Trial Phase 3C-A boundary booleans: `{generated_summary['euclid_phase_3c_a_boundaries']}`",
        f"- Euclid Trial Phase 3C-B: `{generated_summary['euclid_phase_3c_b_status']}`",
        f"- Euclid Trial Phase 3C-B execution mode: `{generated_summary['euclid_phase_3c_b_execution']}`",
        f"- Euclid Trial Phase 3C-B in-scope candidates: `{generated_summary['euclid_phase_3c_b_in_scope']}`",
        f"- Euclid Trial Phase 3C-B out-of-scope preserved: `{generated_summary['euclid_phase_3c_b_out_of_scope']}`",
        f"- Euclid Trial Phase 3C-B candidate preparation statuses: `{generated_summary['euclid_phase_3c_b_candidate_statuses']}`",
        f"- Euclid Trial Phase 3C-B L2 scaffold: `{generated_summary['euclid_phase_3c_b_l2_scaffold']}`",
        f"- Euclid Trial Phase 3C-B guardrails: `{generated_summary['euclid_phase_3c_b_guardrails']}`",
        f"- Euclid Trial Phase 3C-B score status: `{generated_summary['euclid_phase_3c_b_score_status']}`",
        f"- Euclid Trial Phase 3C-B boundary booleans: `{generated_summary['euclid_phase_3c_b_boundaries']}`",
        f"- Euclid Trial Phase 3C-C: `{generated_summary['euclid_phase_3c_c_status']}`",
        f"- Euclid Trial Phase 3C-C execution mode: `{generated_summary['euclid_phase_3c_c_execution']}`",
        f"- Euclid Trial Phase 3C-C in-scope candidates: `{generated_summary['euclid_phase_3c_c_in_scope']}`",
        f"- Euclid Trial Phase 3C-C out-of-scope preserved: `{generated_summary['euclid_phase_3c_c_out_of_scope']}`",
        f"- Euclid Trial Phase 3C-C candidate preparation statuses: `{generated_summary['euclid_phase_3c_c_candidate_statuses']}`",
        f"- Euclid Trial Phase 3C-C L2 scaffold: `{generated_summary['euclid_phase_3c_c_l2_scaffold']}`",
        f"- Euclid Trial Phase 3C-C guardrails: `{generated_summary['euclid_phase_3c_c_guardrails']}`",
        f"- Euclid Trial Phase 3C-C score status: `{generated_summary['euclid_phase_3c_c_score_status']}`",
        f"- Euclid Trial Phase 3C-C boundary booleans: `{generated_summary['euclid_phase_3c_c_boundaries']}`",
        f"- Euclid Trial Phase 3C-D Yocto status: `{generated_summary['euclid_phase_3c_d_status']}`",
        f"- Euclid Trial Phase 3C-E OpenBSD reference status: `{generated_summary['euclid_phase_3c_e_status']}`",
        f"- Score status: `{generated_summary['score_status']}`",
        f"- Score artifact SHA-256: `{generated_summary['score_artifact_sha256']}`",
        "- Phase 3C-A note: No WuciOS artifact generated. No substrate artifact attempted. No numeric WuciOS score generated.",
        "- Phase 3C-B note: No WuciOS artifact generated. No substrate artifact attempted. No rootfs generated. No numeric WuciOS score generated.",
        "- Phase 3C-C note: No WuciOS artifact generated. No substrate artifact attempted. No store realization or rootfs generated. No numeric WuciOS score generated.",
        "",
        "## Profiles",
        "",
    ]
    for profile in profiles:
        lines.append(f"- `{profile['id']}`: {profile['display_name']} ({profile['status']})")
    lines.extend(["", "## Substrate Selection", "", "`NO_SUBSTRATE_SELECTED` unless a measured decision file exists.", "", "## Measurements", "", "| Output | Status |", "| --- | --- |"])
    for name, value in measurements.items():
        lines.append(f"| `{name}` | `{value}` |")
    lines.extend(["", "## Non-Claims", ""])
    lines.extend(f"- {item}" for item in packet["non_claims"])
    lines.extend(["", "## Outputs", "", "| File | Present |", "| --- | --- |"])
    for name, present in outputs.items():
        lines.append(f"| `{name}` | `{str(present).lower()}` |")
    if prereq_notes:
        lines.extend(["", "## Generation Notes", ""])
        lines.extend(f"- {note}" for note in prereq_notes)
    lines.append("")
    (REVIEW_DIR / "review.md").write_text("\n".join(lines), encoding="utf-8")
    return packet


def main() -> int:
    prereq_notes = ensure_prerequisites()
    try:
        packet = write_packet(prereq_notes)
    except Exception as exc:  # noqa: BLE001 - review packet should fail clearly.
        REVIEW_DIR.mkdir(parents=True, exist_ok=True)
        invalid = {
            "schema": "wucios.review_packet.v1",
            "review_status": "REVIEW_PACKET_INVALID",
            "error": str(exc),
        }
        (REVIEW_DIR / "review.json").write_text(json.dumps(invalid, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (REVIEW_DIR / "review.md").write_text(f"# WuciOS v2.4 Review Packet\n\nREVIEW_PACKET_INVALID: {exc}\n", encoding="utf-8")
        print(f"WuciOS review packet: REVIEW_PACKET_INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"WuciOS review packet: {packet['review_status']}")
    print(f"- output: {REVIEW_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
