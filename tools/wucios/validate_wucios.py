#!/usr/bin/env python3
"""Validate WuciOS v2.4 Reduction Gate structure."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

REQUIRED_DIRS = [
    "wucios/profiles",
    "wucios/substrates",
    "wucios/budgets",
    "wucios/sets",
    "wucios/components",
    "wucios/schemas",
    "wucios/trials",
    "wucios/buildrooms",
    "wucios/reports",
    "tools/wucios",
    "tools/wucios/trial_collectors",
    "docs/wucios",
    "docs/archive",
    "build/wucios",
]

REQUIRED_TOOLS = [
    "validate_wucios.py",
    "generate_substrate_matrix.py",
    "generate_review_packet.py",
    "scan_claims.py",
    "surface_inventory.sh",
    "score_wucios.py",
    "run_euclid_trial.py",
    "run_euclid_trial_phase_2.py",
    "run_euclid_buildrooms_phase_3a.py",
    "run_euclid_buildrooms_phase_3b_readiness.py",
    "run_euclid_buildrooms_phase_3c_a.py",
    "run_euclid_direct_rootfs_phase_3c_b.py",
    "run_euclid_store_root_phase_3c_c.py",
    "buildroom_common.py",
    "backend_readiness_common.py",
    "synthetic_smoke_common.py",
    "direct_rootfs_prep_common.py",
    "store_root_prep_common.py",
]

PROFILE_KEYS = {
    "schema",
    "id",
    "display_name",
    "status",
    "role",
    "default_profile",
    "authoritative_for_release",
    "allowed_component_classes",
    "forbidden_component_classes",
    "required_evidence_outputs",
    "invariants",
    "disqualifying_conditions",
    "notes",
}

SUBSTRATE_KEYS = {
    "schema",
    "id",
    "display_name",
    "status",
    "substrate_class",
    "linux_based",
    "package_manager",
    "init_or_supervision",
    "libc",
    "reason_to_test",
    "expected_strengths",
    "expected_risks",
    "required_trial_outputs",
    "disqualifying_conditions",
    "notes",
}

COMPONENT_KEYS = {
    "name",
    "display_name",
    "status",
    "profiles",
    "component_class",
    "default_in_noether_core",
    "reason",
    "network_surface",
    "privilege_surface",
    "language_surface",
    "dependency_notes",
    "risk_notes",
    "acceptance_gate",
    "evidence_hooks",
    "rejection_conditions",
}

REQUIRED_PROFILE_FILES = [
    "noether-core.json",
    "birkhoff-bastion.json",
    "tarski-review-appliance.json",
    "developer-desktop.json",
]

REQUIRED_SUBSTRATE_FILES = [
    "buildroot.json",
    "alpine.json",
    "debian-minimal.json",
    "void.json",
    "nixos.json",
    "guix.json",
    "yocto.json",
    "openbsd-reference.json",
]

REQUIRED_DOCS = [
    "WUCIOS_V24_REDUCTION_GATE.md",
    "MATHEMATICIAN_NAMING_SCHEME.md",
    "NOETHER_CORE.md",
    "BIRKHOFF_BASTION.md",
    "TARSKI_REVIEW_APPLIANCE.md",
    "EUCLID_SUBSTRATE_TRIAL.md",
    "EUCLID_SUBSTRATE_TRIAL_PLAN.md",
    "EUCLID_TRIAL_PHASE_1.md",
    "EUCLID_TRIAL_PHASE_2.md",
    "EUCLID_TRIAL_PHASE_2B.md",
    "EUCLID_TRIAL_PHASE_3A.md",
    "EUCLID_TRIAL_PHASE_3B_READINESS.md",
    "EUCLID_TRIAL_PHASE_3C_A.md",
    "EUCLID_TRIAL_PHASE_3C_B.md",
    "EUCLID_TRIAL_PHASE_3C_C.md",
    "KOLMOGOROV_BUDGET.md",
    "SHANNON_LEDGER.md",
    "GODEL_BOUNDARY.md",
    "BOOLE_GATE.md",
    "DEDEKIND_CUT.md",
    "CANTOR_SETS.md",
    "HOARE_CONTRACT.md",
    "COMPONENT_REGISTER.md",
    "FLUFF_EXTERMINATION_POLICY.md",
    "DAYLIGHT_WUCIOS_SCORE.md",
]

REQUIRED_COMPONENTS = {
    "kernel",
    "bootloader",
    "shell",
    "firewall-tooling",
    "daylight-validator",
    "wuci-prism-tooling",
    "ratpoison",
    "dwm",
    "xfce4",
    "browser",
}

FIRST_TRIAL_COHORT = [
    "buildroot",
    "alpine",
    "debian-minimal",
]

FULL_TRIAL_COHORT = [
    "buildroot",
    "alpine",
    "debian-minimal",
    "void",
    "nixos",
    "guix",
    "yocto",
    "openbsd-reference",
]

REQUIRED_TRIAL_FILES = [
    "trial-plan.json",
    "build-notes.md",
    "artifact-manifest.json",
    "package-manifest.txt",
    "package-count.txt",
    "image-size.txt",
    "enabled-services.txt",
    "listening-ports.txt",
    "suid-sgid.txt",
    "kernel-modules.txt",
    "dependency-tree.txt",
    "build-manifest.sha256",
    "substrate-report.json",
    "substrate-report.md",
    "failure-report.md",
]

REQUIRED_PHASE_2_CANDIDATE_FILES = [
    "build-probe.sh",
    "phase-2-plan.json",
    "README.md",
]

PHASE_2_PLAN_KEYS = {
    "schema",
    "phase_id",
    "phase_name",
    "status",
    "cohort",
    "default_execution_mode",
    "substrate_selection",
    "ranking_allowed",
    "emotional_testing_allowed",
    "network_default",
    "root_default",
    "sudo_allowed",
    "objectives",
    "candidate_status_values",
    "global_status_values",
}

PHASE_2B_PLAN_KEYS = {
    *PHASE_2_PLAN_KEYS,
    "measurement_values",
}

PHASE_3A_PLAN_KEYS = {
    "schema",
    "phase_id",
    "phase_name",
    "status",
    "default_execution_mode",
    "substrate_selection",
    "ranking_allowed",
    "emotional_testing_allowed",
    "build_attempts_allowed_by_default",
    "container_builds_allowed_by_default",
    "container_runs_allowed_by_default",
    "container_pulls_allowed_by_default",
    "vm_runs_allowed_by_default",
    "sudo_allowed",
    "host_package_install_allowed",
    "host_mutation_allowed",
    "cohort",
    "execution_classes",
    "objectives",
}

PHASE_3B_PLAN_KEYS = {
    "schema",
    "phase_id",
    "phase_name",
    "status",
    "default_execution_mode",
    "substrate_selection",
    "ranking_allowed",
    "emotional_testing_allowed",
    "build_attempts_allowed_by_default",
    "container_builds_allowed_by_default",
    "container_runs_allowed_by_default",
    "container_pulls_allowed_by_default",
    "vm_runs_allowed_by_default",
    "sudo_allowed",
    "host_package_install_allowed",
    "host_mutation_allowed",
    "network_default",
    "cohort",
    "objectives",
    "explicit_non_goals",
}

PHASE_3C_A_PLAN_KEYS = {
    "schema",
    "phase_id",
    "phase_name",
    "status",
    "default_execution_mode",
    "l1_authorized_by_default",
    "l2_synthetic_smoke_authorized_by_default",
    "l2_synthetic_smoke_authorization_env",
    "substrate_selection",
    "ranking_allowed",
    "emotional_testing_allowed",
    "network_default",
    "image_pulls_allowed",
    "substrate_artifact_attempts_allowed",
    "runtime_inspection_allowed",
    "container_runs_allowed",
    "vm_runs_allowed",
    "sudo_allowed",
    "host_package_install_allowed",
    "host_mutation_allowed",
    "allowed_l1_actions",
    "allowed_l2_actions",
    "forbidden_actions",
    "objectives",
}

SYNTHETIC_SMOKE_BUILDROOM_KEYS = {
    "schema",
    "id",
    "display_name",
    "phase_id",
    "purpose",
    "is_substrate",
    "is_wucios_artifact",
    "score_eligible",
    "allowed_backends",
    "forbidden_backends",
    "base_image",
    "base_image_pull_required",
    "network_required",
    "substrate_inputs_required",
    "container_run_required",
    "vm_required",
    "default_authorization",
    "evidence_outputs",
    "notes",
}

PHASE_3C_B_PLAN_KEYS = {
    "schema",
    "phase_id",
    "phase_name",
    "status",
    "default_execution_mode",
    "l1_authorized_by_default",
    "l2_scaffold_authorized_by_default",
    "l2_scaffold_authorization_env",
    "l3_substrate_artifact_attempts_allowed",
    "runtime_inspection_allowed",
    "substrate_selection",
    "ranking_allowed",
    "emotional_testing_allowed",
    "numeric_score_allowed",
    "network_default",
    "image_pulls_allowed",
    "container_runs_allowed",
    "vm_runs_allowed",
    "sudo_allowed",
    "host_package_install_allowed",
    "source_clone_allowed",
    "os_image_download_allowed",
    "in_scope_candidates",
    "out_of_scope_preserved",
    "objectives",
    "explicit_non_goals",
}

DIRECT_ROOTFS_CANDIDATES = ["buildroot", "alpine", "debian-minimal", "void"]

DIRECT_ROOTFS_CANDIDATE_POLICY_KEYS = {
    "schema",
    "phase_id",
    "candidate",
    "display_name",
    "status",
    "execution_class",
    "l3_artifact_attempt_allowed",
    "rootfs_generation_allowed",
    "required_future_inputs",
    "required_future_tools",
    "future_artifact_candidates",
    "phase_3c_b_allowed_outputs",
    "phase_3c_b_forbidden_actions",
    "future_evidence_requirements",
    "blocked_until",
}

PHASE_3C_C_PLAN_KEYS = {
    "schema",
    "phase_id",
    "phase_name",
    "status",
    "default_execution_mode",
    "l1_authorized_by_default",
    "l2_scaffold_authorized_by_default",
    "l2_scaffold_authorization_env",
    "l3_substrate_artifact_attempts_allowed",
    "runtime_inspection_allowed",
    "store_realization_allowed",
    "derivation_build_allowed",
    "package_build_allowed",
    "system_activation_allowed",
    "rootfs_generation_allowed",
    "substrate_selection",
    "ranking_allowed",
    "emotional_testing_allowed",
    "numeric_score_allowed",
    "network_default",
    "image_pulls_allowed",
    "container_builds_allowed",
    "container_runs_allowed",
    "vm_runs_allowed",
    "sudo_allowed",
    "host_package_install_allowed",
    "source_clone_allowed",
    "os_image_download_allowed",
    "in_scope_candidates",
    "out_of_scope_preserved",
    "direct_rootfs_assumptions_insufficient_because",
    "allowed_l1_actions",
    "allowed_l2_actions",
    "forbidden_actions",
    "objectives",
    "explicit_non_goals",
}

STORE_ROOT_CANDIDATES = ["nixos_store_root", "guix_store_root"]

STORE_ROOT_CANDIDATE_POLICY_KEYS = {
    "schema",
    "phase_id",
    "candidate_id",
    "candidate_name",
    "candidate_family",
    "phase",
    "preparation_level",
    "declarative_input_type",
    "required_inputs",
    "optional_inputs",
    "forbidden_commands",
    "l1_status",
    "l2_status",
    "artifact_status",
    "score_status",
    "authorization_status",
    "l3_artifact_attempt_allowed",
    "rootfs_generation_allowed",
    "store_realization_allowed",
    "phase_3c_c_allowed_outputs",
    "blocked_until",
    "notes",
}

BUILDROOM_KEYS = {
    "schema",
    "candidate",
    "display_name",
    "phase_id",
    "execution_class",
    "linux_based",
    "reference_path",
    "definition_status",
    "default_execution_mode",
    "build_attempt_default",
    "network_default",
    "sudo_allowed",
    "host_package_install_allowed",
    "host_mutation_allowed",
    "container_run_default",
    "container_pull_default",
    "vm_run_default",
    "allowed_backends",
    "blocked_backends",
    "required_host_tools",
    "required_local_inputs",
    "artifact_candidates",
    "evidence_outputs",
    "blocked_until",
    "notes",
}


def load_json(path: Path, failures: list[str]) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        failures.append(f"missing JSON file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON {path.relative_to(ROOT)}:{exc.lineno}:{exc.colno}: {exc.msg}")
    return None


def require_keys(path: Path, data: object, keys: set[str], failures: list[str]) -> None:
    if not isinstance(data, dict):
        failures.append(f"{path.relative_to(ROOT)} must be a JSON object")
        return
    missing = sorted(keys - set(data))
    if missing:
        failures.append(f"{path.relative_to(ROOT)} missing keys: {', '.join(missing)}")


def validate_profiles(failures: list[str]) -> dict[str, dict]:
    profiles: dict[str, dict] = {}
    profile_dir = ROOT / "wucios/profiles"
    for filename in REQUIRED_PROFILE_FILES:
        path = profile_dir / filename
        data = load_json(path, failures)
        if isinstance(data, dict):
            require_keys(path, data, PROFILE_KEYS, failures)
            profiles[data.get("id", filename)] = data
            if data.get("schema") != "wucios.profile.v1":
                failures.append(f"{path.relative_to(ROOT)} has wrong schema")
    return profiles


def validate_substrates(failures: list[str]) -> dict[str, dict]:
    substrates: dict[str, dict] = {}
    substrate_dir = ROOT / "wucios/substrates"
    for filename in REQUIRED_SUBSTRATE_FILES:
        path = substrate_dir / filename
        data = load_json(path, failures)
        if isinstance(data, dict):
            require_keys(path, data, SUBSTRATE_KEYS, failures)
            substrates[data.get("id", filename)] = data
            if data.get("schema") != "wucios.substrate.v1":
                failures.append(f"{path.relative_to(ROOT)} has wrong schema")
            if data.get("status") != "CANDIDATE_SUBSTRATE":
                failures.append(f"{path.relative_to(ROOT)} must remain CANDIDATE_SUBSTRATE")
    return substrates


def validate_components(failures: list[str]) -> dict[str, dict]:
    path = ROOT / "wucios/components/component-register.json"
    data = load_json(path, failures)
    components: dict[str, dict] = {}
    if not isinstance(data, dict):
        failures.append("component register must be a JSON object")
        return components
    if data.get("schema") != "wucios.component_register.v1":
        failures.append("component register schema mismatch")
    items = data.get("components")
    if not isinstance(items, list):
        failures.append("component register components must be a list")
        return components
    for index, component in enumerate(items):
        if not isinstance(component, dict):
            failures.append(f"component register item {index} must be an object")
            continue
        missing = sorted(COMPONENT_KEYS - set(component))
        if missing:
            failures.append(f"component {component.get('name', index)} missing keys: {', '.join(missing)}")
        name = str(component.get("name", f"index-{index}"))
        components[name] = component
    missing_components = sorted(REQUIRED_COMPONENTS - set(components))
    if missing_components:
        failures.append(f"component register missing required components: {', '.join(missing_components)}")
    return components


def validate_budgets(failures: list[str]) -> None:
    budget_dir = ROOT / "wucios/budgets"
    for path in sorted(budget_dir.glob("*.json")):
        data = load_json(path, failures)
        if isinstance(data, dict):
            required = {"schema", "id", "display_name", "profile", "status", "hard_limits", "measured_limits", "notes"}
            require_keys(path, data, required, failures)
            if data.get("schema") != "wucios.budget.v1":
                failures.append(f"{path.relative_to(ROOT)} has wrong schema")
            if not isinstance(data.get("hard_limits"), dict):
                failures.append(f"{path.relative_to(ROOT)} hard_limits must be an object")
            if not isinstance(data.get("measured_limits"), dict):
                failures.append(f"{path.relative_to(ROOT)} measured_limits must be an object")


def validate_json_files_parse(failures: list[str]) -> None:
    for base in ["wucios", "docs/wucios"]:
        for path in sorted((ROOT / base).rglob("*.json")):
            load_json(path, failures)


def validate_noether_policy(profiles: dict[str, dict], components: dict[str, dict], failures: list[str]) -> None:
    noether = profiles.get("noether-core")
    if not noether:
        failures.append("Noether Core profile missing")
        return
    forbidden = set(noether.get("forbidden_component_classes", []))
    for required in ["gui", "browser", "default-network-service", "desktop-environment"]:
        if required not in forbidden:
            failures.append(f"Noether Core must forbid {required}")
    for component_name in ["xfce4", "ratpoison", "dwm"]:
        component = components.get(component_name)
        if not component:
            continue
        profiles_for_component = set(component.get("profiles", []))
        if "noether-core" in profiles_for_component:
            failures.append(f"{component_name} must not be listed as Noether Core")
        if component.get("default_in_noether_core") is True:
            failures.append(f"{component_name} must not be default_in_noether_core")
    browser = components.get("browser")
    if browser and browser.get("default_in_noether_core") is True:
        failures.append("browser must not be default_in_noether_core")


def validate_euclid_trial_phase_1(failures: list[str]) -> None:
    plan = ROOT / "wucios/trials/euclid-substrate-trial-plan.json"
    if not plan.is_file():
        failures.append("missing Euclid substrate trial plan: wucios/trials/euclid-substrate-trial-plan.json")
    else:
        data = load_json(plan, failures)
        if isinstance(data, dict) and data.get("selection_status") != "NO_SUBSTRATE_SELECTED":
            failures.append("Euclid substrate trial plan must keep selection_status NO_SUBSTRATE_SELECTED")

    for candidate in FIRST_TRIAL_COHORT:
        directory = ROOT / "wucios/trials" / candidate
        if not directory.is_dir():
            failures.append(f"missing Euclid Phase 1 trial directory: wucios/trials/{candidate}")
            continue
        for filename in REQUIRED_TRIAL_FILES:
            path = directory / filename
            if not path.is_file():
                failures.append(f"missing Euclid Phase 1 file: {path.relative_to(ROOT)}")

        trial_plan = load_json(directory / "trial-plan.json", failures)
        if isinstance(trial_plan, dict):
            if trial_plan.get("selection_status") != "NO_SUBSTRATE_SELECTED":
                failures.append(f"{(directory / 'trial-plan.json').relative_to(ROOT)} must keep selection_status NO_SUBSTRATE_SELECTED")
            if trial_plan.get("candidate") != candidate:
                failures.append(f"{(directory / 'trial-plan.json').relative_to(ROOT)} candidate mismatch")

        artifact_manifest = load_json(directory / "artifact-manifest.json", failures)
        if isinstance(artifact_manifest, dict):
            artifact = artifact_manifest.get("artifact")
            if not isinstance(artifact, dict):
                failures.append(f"{(directory / 'artifact-manifest.json').relative_to(ROOT)} artifact must be an object")
            elif artifact.get("sha256") not in {"NOT_MEASURED"} and not isinstance(artifact.get("sha256"), str):
                failures.append(f"{(directory / 'artifact-manifest.json').relative_to(ROOT)} artifact sha256 must be a string or NOT_MEASURED")
            if artifact_manifest.get("build_status") not in {
                "BUILD_SUCCEEDED",
                "BUILD_NOT_ATTEMPTED",
                "BUILD_ATTEMPTED_FAILED",
                "MISSING_TOOLING",
                "NOT_MEASURED",
            }:
                failures.append(f"{(directory / 'artifact-manifest.json').relative_to(ROOT)} has invalid build_status")

        report = load_json(directory / "substrate-report.json", failures)
        if isinstance(report, dict):
            if report.get("selection_status") != "NO_SUBSTRATE_SELECTED":
                failures.append(f"{(directory / 'substrate-report.json').relative_to(ROOT)} must keep selection_status NO_SUBSTRATE_SELECTED")
            if report.get("candidate") != candidate:
                failures.append(f"{(directory / 'substrate-report.json').relative_to(ROOT)} candidate mismatch")


def validate_euclid_trial_phase_2(failures: list[str], warnings: list[str]) -> None:
    phase_plan_path = ROOT / "wucios/trials/euclid-substrate-trial-phase-2.json"
    phase_plan = load_json(phase_plan_path, failures)
    if isinstance(phase_plan, dict):
        require_keys(phase_plan_path, phase_plan, PHASE_2_PLAN_KEYS, failures)
        if phase_plan.get("phase_id") != "euclid-trial-phase-2":
            failures.append("Phase 2 plan must use phase_id euclid-trial-phase-2")
        if phase_plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 2 plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        if phase_plan.get("ranking_allowed") is not False:
            failures.append("Phase 2 plan must set ranking_allowed false")
        if phase_plan.get("emotional_testing_allowed") is not False:
            failures.append("Phase 2 plan must set emotional_testing_allowed false")
        if phase_plan.get("sudo_allowed") is not False:
            failures.append("Phase 2 plan must set sudo_allowed false")
        if phase_plan.get("default_execution_mode") != "SAFE_DETECT_ONLY":
            failures.append("Phase 2 plan must default to SAFE_DETECT_ONLY")
        if phase_plan.get("cohort") != FULL_TRIAL_COHORT:
            failures.append("Phase 2 plan cohort must match full trial cohort")

    schema_path = ROOT / "wucios/schemas/euclid-trial-phase-2.schema.json"
    if not schema_path.is_file():
        failures.append("missing Phase 2 schema: wucios/schemas/euclid-trial-phase-2.schema.json")
    else:
        load_json(schema_path, failures)

    helper_path = ROOT / "tools/wucios/trial_collectors/build_probe.py"
    if not helper_path.is_file():
        failures.append("missing Phase 2 helper: tools/wucios/trial_collectors/build_probe.py")

    phase_2b_doc = ROOT / "docs/wucios/EUCLID_TRIAL_PHASE_2B.md"
    if not phase_2b_doc.is_file():
        failures.append("missing Phase 2B doc: docs/wucios/EUCLID_TRIAL_PHASE_2B.md")

    phase_2b_plan_path = ROOT / "wucios/trials/euclid-substrate-trial-phase-2b.json"
    phase_2b_plan = load_json(phase_2b_plan_path, failures)
    if isinstance(phase_2b_plan, dict):
        require_keys(phase_2b_plan_path, phase_2b_plan, PHASE_2B_PLAN_KEYS, failures)
        if phase_2b_plan.get("phase_id") != "euclid-trial-phase-2b":
            failures.append("Phase 2B plan must use phase_id euclid-trial-phase-2b")
        if phase_2b_plan.get("cohort") != FULL_TRIAL_COHORT:
            failures.append("Phase 2B plan cohort must match full trial cohort")
        if phase_2b_plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 2B plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        if phase_2b_plan.get("ranking_allowed") is not False:
            failures.append("Phase 2B plan must set ranking_allowed false")
        if phase_2b_plan.get("emotional_testing_allowed") is not False:
            failures.append("Phase 2B plan must set emotional_testing_allowed false")
        if phase_2b_plan.get("sudo_allowed") is not False:
            failures.append("Phase 2B plan must set sudo_allowed false")

    phase_2b_schema = ROOT / "wucios/schemas/euclid-trial-phase-2b.schema.json"
    if not phase_2b_schema.is_file():
        failures.append("missing Phase 2B schema: wucios/schemas/euclid-trial-phase-2b.schema.json")
    else:
        load_json(phase_2b_schema, failures)

    for candidate in FULL_TRIAL_COHORT:
        directory = ROOT / "wucios/trials" / candidate
        if not directory.is_dir():
            failures.append(f"missing Phase 2 candidate directory: {directory.relative_to(ROOT)}")
            continue
        for filename in REQUIRED_PHASE_2_CANDIDATE_FILES:
            path = directory / filename
            if not path.is_file():
                failures.append(f"missing Phase 2 candidate file: {path.relative_to(ROOT)}")
        script = directory / "build-probe.sh"
        if script.is_file():
            if not script.stat().st_mode & 0o111:
                warnings.append(f"{script.relative_to(ROOT)} is readable but not executable")
            text = script.read_text(encoding="utf-8", errors="replace")
            if "sudo" in text:
                failures.append(f"{script.relative_to(ROOT)} must not call sudo")

        plan_path = directory / "phase-2-plan.json"
        plan = load_json(plan_path, failures)
        if isinstance(plan, dict):
            if plan.get("candidate") != candidate:
                failures.append(f"{plan_path.relative_to(ROOT)} candidate mismatch")
            if plan.get("phase_id") != "euclid-trial-phase-2":
                failures.append(f"{plan_path.relative_to(ROOT)} must use phase_id euclid-trial-phase-2")
            if plan.get("default_status") != "BUILD_NOT_ATTEMPTED":
                failures.append(f"{plan_path.relative_to(ROOT)} must default to BUILD_NOT_ATTEMPTED")
            if plan.get("substrate_selection") not in {None, "NO_SUBSTRATE_SELECTED"}:
                failures.append(f"{plan_path.relative_to(ROOT)} must not declare substrate selection")
            if plan.get("selected") is True:
                failures.append(f"{plan_path.relative_to(ROOT)} must not declare itself selected")
            if candidate == "openbsd-reference":
                if plan.get("linux_based") is not False and plan.get("reference_path") is not True:
                    failures.append(f"{plan_path.relative_to(ROOT)} must mark OpenBSD as non-Linux reference path")
            if candidate in {"nixos", "guix"}:
                never_do = "\n".join(str(item) for item in plan.get("never_do", []))
                attempt_requires = "\n".join(str(item) for item in plan.get("attempt_requires", []))
                if "future" not in attempt_requires or "host-store" not in attempt_requires:
                    failures.append(f"{plan_path.relative_to(ROOT)} must require future host-store or build-room policy")
                if "outside build/wucios" not in never_do:
                    failures.append(f"{plan_path.relative_to(ROOT)} must deny default writes outside build/wucios")


def validate_euclid_buildrooms_phase_3a(failures: list[str], warnings: list[str]) -> None:
    doc_path = ROOT / "docs/wucios/EUCLID_TRIAL_PHASE_3A.md"
    if not doc_path.is_file():
        failures.append("missing Phase 3A doc: docs/wucios/EUCLID_TRIAL_PHASE_3A.md")

    buildrooms_dir = ROOT / "wucios/buildrooms"
    required_paths = [
        buildrooms_dir / "euclid-buildrooms-phase-3a.json",
        buildrooms_dir / "backend-policy.json",
        buildrooms_dir / "README.md",
        ROOT / "wucios/schemas/euclid-buildroom.schema.json",
        ROOT / "wucios/schemas/euclid-buildrooms-phase-3a.schema.json",
        ROOT / "tools/wucios/run_euclid_buildrooms_phase_3a.py",
        ROOT / "tools/wucios/buildroom_common.py",
    ]
    for path in required_paths:
        if not path.is_file():
            failures.append(f"missing Phase 3A file: {path.relative_to(ROOT)}")

    plan_path = buildrooms_dir / "euclid-buildrooms-phase-3a.json"
    plan = load_json(plan_path, failures)
    if isinstance(plan, dict):
        require_keys(plan_path, plan, PHASE_3A_PLAN_KEYS, failures)
        if plan.get("phase_id") != "euclid-trial-phase-3a":
            failures.append("Phase 3A plan must use phase_id euclid-trial-phase-3a")
        if plan.get("cohort") != FULL_TRIAL_COHORT:
            failures.append("Phase 3A plan cohort must match full trial cohort")
        if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 3A plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        for key in [
            "ranking_allowed",
            "emotional_testing_allowed",
            "build_attempts_allowed_by_default",
            "container_builds_allowed_by_default",
            "container_runs_allowed_by_default",
            "container_pulls_allowed_by_default",
            "vm_runs_allowed_by_default",
            "sudo_allowed",
            "host_package_install_allowed",
            "host_mutation_allowed",
        ]:
            if plan.get(key) is not False:
                failures.append(f"Phase 3A plan must set {key} false")

    policy_path = buildrooms_dir / "backend-policy.json"
    policy = load_json(policy_path, failures)
    if isinstance(policy, dict):
        if policy.get("safe_detect_only") is not True:
            failures.append("Phase 3A backend policy must be safe_detect_only")
        forbidden = "\n".join(str(item) for item in policy.get("forbidden_default_actions", []))
        for phrase in ["docker pull", "docker build", "docker run", "podman run", "buildah bud", "nix build", "guix system", "VM launch", "sudo", "package installation"]:
            if phrase not in forbidden:
                failures.append(f"Phase 3A backend policy must forbid {phrase}")

    for candidate in FULL_TRIAL_COHORT:
        directory = buildrooms_dir / candidate
        if not directory.is_dir():
            failures.append(f"missing Phase 3A buildroom directory: {directory.relative_to(ROOT)}")
            continue
        buildroom_path = directory / "buildroom.json"
        readme_path = directory / "README.md"
        if not buildroom_path.is_file():
            failures.append(f"missing Phase 3A buildroom file: {buildroom_path.relative_to(ROOT)}")
            continue
        if not readme_path.is_file():
            failures.append(f"missing Phase 3A README: {readme_path.relative_to(ROOT)}")
        if candidate == "openbsd-reference":
            runtime_path = directory / "runtime-room.json"
            if not runtime_path.is_file():
                failures.append(f"missing OpenBSD runtime room: {runtime_path.relative_to(ROOT)}")
        else:
            template_path = directory / "Containerfile.template"
            if not template_path.is_file():
                failures.append(f"missing Phase 3A Containerfile template: {template_path.relative_to(ROOT)}")

        buildroom = load_json(buildroom_path, failures)
        if not isinstance(buildroom, dict):
            continue
        require_keys(buildroom_path, buildroom, BUILDROOM_KEYS, failures)
        if buildroom.get("schema") != "wucios.euclid.buildroom.v1":
            failures.append(f"{buildroom_path.relative_to(ROOT)} has wrong schema")
        if buildroom.get("candidate") != candidate:
            failures.append(f"{buildroom_path.relative_to(ROOT)} candidate mismatch")
        if buildroom.get("phase_id") != "euclid-trial-phase-3a":
            failures.append(f"{buildroom_path.relative_to(ROOT)} must use phase_id euclid-trial-phase-3a")
        if buildroom.get("definition_status") != "BUILDROOM_DEFINITION_PRESENT":
            failures.append(f"{buildroom_path.relative_to(ROOT)} must declare BUILDROOM_DEFINITION_PRESENT")
        if buildroom.get("default_execution_mode") != "SAFE_DETECT_ONLY":
            failures.append(f"{buildroom_path.relative_to(ROOT)} must default to SAFE_DETECT_ONLY")
        if buildroom.get("network_default") != "DISABLED":
            failures.append(f"{buildroom_path.relative_to(ROOT)} must disable network by default")
        for key in [
            "build_attempt_default",
            "sudo_allowed",
            "host_package_install_allowed",
            "host_mutation_allowed",
            "container_run_default",
            "container_pull_default",
            "vm_run_default",
        ]:
            if buildroom.get(key) is not False:
                failures.append(f"{buildroom_path.relative_to(ROOT)} must set {key} false")
        if buildroom.get("selected") is True or buildroom.get("substrate_selection") not in {None, "NO_SUBSTRATE_SELECTED"}:
            failures.append(f"{buildroom_path.relative_to(ROOT)} must not declare a selected substrate")
        if candidate in {"nixos", "guix"}:
            blockers = "\n".join(str(item) for item in buildroom.get("blocked_until", []))
            if "host-store" not in blockers and "isolated" not in blockers:
                failures.append(f"{buildroom_path.relative_to(ROOT)} must include host-store or isolated-store blockers")
        if candidate == "openbsd-reference":
            if buildroom.get("linux_based") is not False or buildroom.get("reference_path") is not True:
                failures.append(f"{buildroom_path.relative_to(ROOT)} must mark OpenBSD as non-Linux reference path")
        if "sudo" in "\n".join(str(item) for item in buildroom.get("notes", [])):
            warnings.append(f"{buildroom_path.relative_to(ROOT)} mentions sudo boundary")


def validate_euclid_buildrooms_phase_3b_readiness(failures: list[str], warnings: list[str]) -> None:
    doc_path = ROOT / "docs/wucios/EUCLID_TRIAL_PHASE_3B_READINESS.md"
    if not doc_path.is_file():
        failures.append("missing Phase 3B readiness doc: docs/wucios/EUCLID_TRIAL_PHASE_3B_READINESS.md")

    buildrooms_dir = ROOT / "wucios/buildrooms"
    required_paths = [
        buildrooms_dir / "euclid-buildrooms-phase-3b-readiness.json",
        buildrooms_dir / "backend-remediation-policy.json",
        buildrooms_dir / "test-authorization-matrix.json",
        ROOT / "wucios/schemas/euclid-buildrooms-phase-3b-readiness.schema.json",
        ROOT / "wucios/schemas/test-authorization-matrix.schema.json",
        ROOT / "tools/wucios/run_euclid_buildrooms_phase_3b_readiness.py",
        ROOT / "tools/wucios/backend_readiness_common.py",
    ]
    for path in required_paths:
        if not path.is_file():
            failures.append(f"missing Phase 3B readiness file: {path.relative_to(ROOT)}")

    plan_path = buildrooms_dir / "euclid-buildrooms-phase-3b-readiness.json"
    plan = load_json(plan_path, failures)
    if isinstance(plan, dict):
        require_keys(plan_path, plan, PHASE_3B_PLAN_KEYS, failures)
        if plan.get("phase_id") != "euclid-trial-phase-3b-readiness":
            failures.append("Phase 3B readiness plan must use phase_id euclid-trial-phase-3b-readiness")
        if plan.get("cohort") != FULL_TRIAL_COHORT:
            failures.append("Phase 3B readiness plan cohort must match full trial cohort")
        if plan.get("default_execution_mode") != "SAFE_READINESS_ONLY":
            failures.append("Phase 3B readiness plan must default to SAFE_READINESS_ONLY")
        if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 3B readiness plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        for key in [
            "ranking_allowed",
            "emotional_testing_allowed",
            "build_attempts_allowed_by_default",
            "container_builds_allowed_by_default",
            "container_runs_allowed_by_default",
            "container_pulls_allowed_by_default",
            "vm_runs_allowed_by_default",
            "sudo_allowed",
            "host_package_install_allowed",
            "host_mutation_allowed",
        ]:
            if plan.get(key) is not False:
                failures.append(f"Phase 3B readiness plan must set {key} false")

    matrix_path = buildrooms_dir / "test-authorization-matrix.json"
    matrix = load_json(matrix_path, failures)
    if isinstance(matrix, dict):
        if matrix.get("phase_id") != "euclid-trial-phase-3b-readiness":
            failures.append("test authorization matrix must use Phase 3B readiness phase_id")
        levels = matrix.get("test_levels", [])
        if not isinstance(levels, list):
            failures.append("test authorization matrix test_levels must be a list")
        else:
            by_id = {str(level.get("id")): level for level in levels if isinstance(level, dict)}
            if set(by_id) != {"L0", "L1", "L2", "L3", "L4"}:
                failures.append("test authorization matrix must define L0 through L4")
            if by_id.get("L0", {}).get("authorized_by_default") is not True:
                failures.append("test authorization matrix must authorize L0 by default")
            for level_id in ["L1", "L2", "L3", "L4"]:
                if by_id.get(level_id, {}).get("authorized_by_default") is not False:
                    failures.append(f"test authorization matrix must not authorize {level_id} by default")
                if by_id.get(level_id, {}).get("requires_future_explicit_authorization") is not True:
                    failures.append(f"test authorization matrix must require future explicit authorization for {level_id}")

    policy_path = buildrooms_dir / "backend-remediation-policy.json"
    policy = load_json(policy_path, failures)
    if isinstance(policy, dict):
        if policy.get("phase_id") != "euclid-trial-phase-3b-readiness":
            failures.append("backend remediation policy must use Phase 3B readiness phase_id")
        if policy.get("safe_readiness_only") is not True:
            failures.append("backend remediation policy must be safe_readiness_only")
        forbidden = "\n".join(str(item) for item in policy.get("forbidden_actions", []))
        for phrase in [
            "sudo",
            "package installation",
            "source tree cloning",
            "artifact download",
            "docker pull",
            "docker build",
            "docker run",
            "podman pull",
            "podman build",
            "podman run",
            "buildah bud",
            "VM launch",
        ]:
            if phrase not in forbidden:
                failures.append(f"backend remediation policy must forbid {phrase}")
        if "host configuration change" in "\n".join(str(item) for item in policy.get("notes", [])):
            warnings.append("Phase 3B readiness remediation policy records human approval boundary")


def validate_euclid_buildrooms_phase_3c_a(failures: list[str], warnings: list[str]) -> None:
    doc_path = ROOT / "docs/wucios/EUCLID_TRIAL_PHASE_3C_A.md"
    if not doc_path.is_file():
        failures.append("missing Phase 3C-A doc: docs/wucios/EUCLID_TRIAL_PHASE_3C_A.md")

    buildrooms_dir = ROOT / "wucios/buildrooms"
    required_paths = [
        buildrooms_dir / "euclid-buildrooms-phase-3c-a.json",
        buildrooms_dir / "synthetic-smoke/synthetic-smoke-buildroom.json",
        buildrooms_dir / "synthetic-smoke/Containerfile.template",
        buildrooms_dir / "synthetic-smoke/README.md",
        ROOT / "wucios/schemas/euclid-buildrooms-phase-3c-a.schema.json",
        ROOT / "wucios/schemas/synthetic-smoke-buildroom.schema.json",
        ROOT / "tools/wucios/run_euclid_buildrooms_phase_3c_a.py",
        ROOT / "tools/wucios/synthetic_smoke_common.py",
    ]
    for path in required_paths:
        if not path.is_file():
            failures.append(f"missing Phase 3C-A file: {path.relative_to(ROOT)}")

    plan_path = buildrooms_dir / "euclid-buildrooms-phase-3c-a.json"
    plan = load_json(plan_path, failures)
    if isinstance(plan, dict):
        require_keys(plan_path, plan, PHASE_3C_A_PLAN_KEYS, failures)
        if plan.get("phase_id") != "euclid-trial-phase-3c-a":
            failures.append("Phase 3C-A plan must use phase_id euclid-trial-phase-3c-a")
        if plan.get("default_execution_mode") != "L1_SAFE_BACKEND_DETECTION":
            failures.append("Phase 3C-A plan must default to L1_SAFE_BACKEND_DETECTION")
        if plan.get("l2_synthetic_smoke_authorized_by_default") is not False:
            failures.append("Phase 3C-A plan must disable L2 synthetic smoke by default")
        if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 3C-A plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        for key in [
            "ranking_allowed",
            "emotional_testing_allowed",
            "image_pulls_allowed",
            "substrate_artifact_attempts_allowed",
            "runtime_inspection_allowed",
            "container_runs_allowed",
            "vm_runs_allowed",
            "sudo_allowed",
            "host_package_install_allowed",
        ]:
            if plan.get(key) is not False:
                failures.append(f"Phase 3C-A plan must set {key} false")
        forbidden = "\n".join(str(item) for item in plan.get("forbidden_actions", []))
        for phrase in [
            "substrate artifact attempt",
            "runtime inspection",
            "image pull",
            "podman run",
            "buildah run",
            "docker run",
            "VM launch",
            "sudo",
            "package installation",
            "numeric WuciOS score",
        ]:
            if phrase not in forbidden:
                failures.append(f"Phase 3C-A plan must forbid {phrase}")

    buildroom_path = buildrooms_dir / "synthetic-smoke/synthetic-smoke-buildroom.json"
    buildroom = load_json(buildroom_path, failures)
    if isinstance(buildroom, dict):
        require_keys(buildroom_path, buildroom, SYNTHETIC_SMOKE_BUILDROOM_KEYS, failures)
        if buildroom.get("phase_id") != "euclid-trial-phase-3c-a":
            failures.append("synthetic smoke buildroom must use Phase 3C-A phase_id")
        for key in ["is_substrate", "is_wucios_artifact", "score_eligible"]:
            if buildroom.get(key) is not False:
                failures.append(f"synthetic smoke buildroom must set {key} false")
        if buildroom.get("base_image") != "scratch":
            failures.append("synthetic smoke buildroom must use scratch base")
        if "docker" not in buildroom.get("forbidden_backends", []):
            failures.append("synthetic smoke buildroom must forbid Docker")

    template_path = buildrooms_dir / "synthetic-smoke/Containerfile.template"
    if template_path.is_file():
        template = template_path.read_text(encoding="utf-8")
        instructions = [line.strip() for line in template.splitlines() if line.strip() and not line.strip().startswith("#")]
        if [line for line in instructions if line.upper().startswith("FROM ")] != ["FROM scratch"]:
            failures.append("synthetic smoke Containerfile.template must use FROM scratch")
        for line in instructions:
            if line.upper().startswith("RUN "):
                failures.append("synthetic smoke Containerfile.template must not contain RUN")
            if line.upper().startswith("ADD "):
                failures.append("synthetic smoke Containerfile.template must not contain ADD")
        if "http://" in template.lower() or "https://" in template.lower():
            failures.append("synthetic smoke Containerfile.template must not contain remote URLs")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    if "wucios-euclid-buildrooms-phase-3c-a-smoke:" not in makefile:
        failures.append("Makefile must contain Phase 3C-A guarded smoke target")
    if "WUCIOS_PHASE3CA_ALLOW_L2_SMOKE" not in makefile:
        failures.append("Makefile Phase 3C-A smoke target must check WUCIOS_PHASE3CA_ALLOW_L2_SMOKE")
    if "wucios-euclid-buildrooms-phase-3c-a-guardrails" not in makefile:
        failures.append("Makefile must contain Phase 3C-A guardrail target")


def validate_euclid_direct_rootfs_phase_3c_b(failures: list[str], warnings: list[str]) -> None:
    doc_path = ROOT / "docs/wucios/EUCLID_TRIAL_PHASE_3C_B.md"
    if not doc_path.is_file():
        failures.append("missing Phase 3C-B doc: docs/wucios/EUCLID_TRIAL_PHASE_3C_B.md")

    buildrooms_dir = ROOT / "wucios/buildrooms/direct-rootfs"
    required_paths = [
        buildrooms_dir / "euclid-direct-rootfs-phase-3c-b.json",
        buildrooms_dir / "direct-rootfs-policy.json",
        buildrooms_dir / "command-shapes.json",
        buildrooms_dir / "pull-pinning-cache-output-policy.json",
        buildrooms_dir / "evidence-requirements.json",
        buildrooms_dir / "guardrail-policy.json",
        buildrooms_dir / "README.md",
        ROOT / "wucios/schemas/euclid-direct-rootfs-phase-3c-b.schema.json",
        ROOT / "wucios/schemas/direct-rootfs-preparation-policy.schema.json",
        ROOT / "wucios/schemas/direct-rootfs-command-shapes.schema.json",
        ROOT / "wucios/schemas/direct-rootfs-evidence-requirements.schema.json",
        ROOT / "tools/wucios/run_euclid_direct_rootfs_phase_3c_b.py",
        ROOT / "tools/wucios/direct_rootfs_prep_common.py",
    ]
    for candidate in DIRECT_ROOTFS_CANDIDATES:
        required_paths.extend([
            buildrooms_dir / candidate / "preparation-policy.json",
            buildrooms_dir / candidate / "README.md",
        ])
    for path in required_paths:
        if not path.is_file():
            failures.append(f"missing Phase 3C-B file: {path.relative_to(ROOT)}")

    plan_path = buildrooms_dir / "euclid-direct-rootfs-phase-3c-b.json"
    plan = load_json(plan_path, failures)
    if isinstance(plan, dict):
        require_keys(plan_path, plan, PHASE_3C_B_PLAN_KEYS, failures)
        if plan.get("phase_id") != "euclid-trial-phase-3c-b":
            failures.append("Phase 3C-B plan must use phase_id euclid-trial-phase-3c-b")
        if plan.get("default_execution_mode") != "L1_POLICY_AND_PREPARATION_RULES":
            failures.append("Phase 3C-B plan must default to L1_POLICY_AND_PREPARATION_RULES")
        if plan.get("l2_scaffold_authorized_by_default") is not False:
            failures.append("Phase 3C-B plan must disable L2 scaffold by default")
        if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 3C-B plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        for key in [
            "ranking_allowed",
            "emotional_testing_allowed",
            "l3_substrate_artifact_attempts_allowed",
            "runtime_inspection_allowed",
            "numeric_score_allowed",
            "image_pulls_allowed",
            "container_runs_allowed",
            "vm_runs_allowed",
            "sudo_allowed",
            "host_package_install_allowed",
            "source_clone_allowed",
            "os_image_download_allowed",
        ]:
            if plan.get(key) is not False:
                failures.append(f"Phase 3C-B plan must set {key} false")
        if plan.get("network_default") != "DISABLED":
            failures.append("Phase 3C-B plan must disable network by default")
        if plan.get("in_scope_candidates") != DIRECT_ROOTFS_CANDIDATES:
            failures.append("Phase 3C-B plan must scope Buildroot, Alpine, Debian minimal, and Void only")
        out_of_scope = plan.get("out_of_scope_preserved", {})
        if not isinstance(out_of_scope, dict) or "phase_3c_c_store_aware" not in out_of_scope or "phase_3c_d_heavy_source" not in out_of_scope or "phase_3c_e_reference_runtime" not in out_of_scope:
            failures.append("Phase 3C-B plan must preserve later phases for NixOS/Guix, Yocto, and OpenBSD reference")

    direct_policy_path = buildrooms_dir / "direct-rootfs-policy.json"
    direct_policy = load_json(direct_policy_path, failures)
    if isinstance(direct_policy, dict):
        if direct_policy.get("phase_id") != "euclid-trial-phase-3c-b":
            failures.append("direct-rootfs policy must use Phase 3C-B phase_id")
        if direct_policy.get("applies_to") != DIRECT_ROOTFS_CANDIDATES:
            failures.append("direct-rootfs policy must apply only to direct-rootfs candidates")
        for key in [
            "l3_artifact_attempts_allowed",
            "rootfs_generation_allowed",
            "network_allowed",
            "container_runs_allowed",
            "image_pulls_allowed",
            "sudo_allowed",
            "host_package_install_allowed",
            "source_clone_allowed",
        ]:
            if direct_policy.get(key) is not False:
                failures.append(f"direct-rootfs policy must set {key} false")

    command_shapes_path = buildrooms_dir / "command-shapes.json"
    command_shapes = load_json(command_shapes_path, failures)
    if isinstance(command_shapes, dict):
        if command_shapes.get("status") != "POLICY_ONLY_NOT_EXECUTABLE":
            failures.append("command-shapes.json must be POLICY_ONLY_NOT_EXECUTABLE")
        if command_shapes.get("commands_execute_in_phase_3c_b") is not False:
            failures.append("command-shapes.json must not execute in Phase 3C-B")
        candidates = command_shapes.get("candidates", {})
        if not isinstance(candidates, dict):
            failures.append("command-shapes.json candidates must be an object")
        else:
            for candidate in DIRECT_ROOTFS_CANDIDATES:
                item = candidates.get(candidate, {})
                if not isinstance(item, dict):
                    failures.append(f"command-shapes.json missing {candidate}")
                    continue
                if item.get("future_level_required") != "L3":
                    failures.append(f"{candidate} command shapes must require L3")
                forbidden = "\n".join(str(entry) for entry in item.get("forbidden_in_phase_3c_b", []))
                for phrase in [
                    "execute command shape",
                    "generate substrate artifact",
                    "generate rootfs",
                    "run container",
                    "use network",
                    "select substrate",
                    "rank candidate",
                    "generate numeric score",
                ]:
                    if phrase not in forbidden:
                        failures.append(f"{candidate} command shapes must forbid {phrase}")

    evidence_path = buildrooms_dir / "evidence-requirements.json"
    evidence = load_json(evidence_path, failures)
    if isinstance(evidence, dict):
        if evidence.get("phase_3c_b_generates_substrate_evidence") is not False:
            failures.append("Phase 3C-B evidence requirements must not generate substrate evidence")
        required_outputs = evidence.get("future_l3_required_outputs", [])
        for name in ["artifact-manifest.json", "artifact.sha256", "build-log.txt", "substrate-report.json", "missing-measurements.txt"]:
            if name not in required_outputs:
                failures.append(f"Phase 3C-B evidence requirements must include {name}")

    guardrail_path = buildrooms_dir / "guardrail-policy.json"
    guardrail_policy = load_json(guardrail_path, failures)
    if isinstance(guardrail_policy, dict):
        refusal_text = "\n".join(str(item) for item in guardrail_policy.get("required_refusal_checks", []))
        for phrase in ["WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD", "WUCIOS_EUCLID_ALLOW_ATTEMPT", "WUCIOS_PHASE3CA_ALLOW_L2_SMOKE"]:
            if phrase not in refusal_text:
                failures.append(f"Phase 3C-B guardrail policy must include refusal check for {phrase}")
        forbidden_text = "\n".join(str(item) for item in guardrail_policy.get("phase_3c_b_must_not_execute", []))
        for phrase in ["podman build", "buildah bud", "podman run", "docker build", "docker run", "qemu-system", "sudo", "git clone"]:
            if phrase not in forbidden_text:
                failures.append(f"Phase 3C-B guardrail policy must forbid {phrase}")

    for candidate in DIRECT_ROOTFS_CANDIDATES:
        policy_path = buildrooms_dir / candidate / "preparation-policy.json"
        policy = load_json(policy_path, failures)
        if isinstance(policy, dict):
            require_keys(policy_path, policy, DIRECT_ROOTFS_CANDIDATE_POLICY_KEYS, failures)
            if policy.get("phase_id") != "euclid-trial-phase-3c-b":
                failures.append(f"{candidate} policy must use Phase 3C-B phase_id")
            if policy.get("candidate") != candidate:
                failures.append(f"{candidate} policy candidate id mismatch")
            if policy.get("l3_artifact_attempt_allowed") is not False:
                failures.append(f"{candidate} policy must forbid L3 artifact attempts")
            if policy.get("rootfs_generation_allowed") is not False:
                failures.append(f"{candidate} policy must forbid rootfs generation")
            forbidden = "\n".join(str(item) for item in policy.get("phase_3c_b_forbidden_actions", []))
            for phrase in ["rootfs generation", "substrate artifact attempt", "runtime inspection", "score generation", "selection", "ranking"]:
                if phrase not in forbidden:
                    failures.append(f"{candidate} policy must forbid {phrase}")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    if "wucios-euclid-direct-rootfs-phase-3c-b-scaffold:" not in makefile:
        failures.append("Makefile must contain Phase 3C-B guarded scaffold target")
    if "WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD" not in makefile:
        failures.append("Makefile Phase 3C-B scaffold target must check WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD")
    if "wucios-euclid-direct-rootfs-phase-3c-b-guardrails" not in makefile:
        failures.append("Makefile must contain Phase 3C-B guardrail target")


def validate_euclid_store_root_phase_3c_c(failures: list[str], warnings: list[str]) -> None:
    doc_path = ROOT / "docs/wucios/EUCLID_TRIAL_PHASE_3C_C.md"
    if not doc_path.is_file():
        failures.append("missing Phase 3C-C doc: docs/wucios/EUCLID_TRIAL_PHASE_3C_C.md")

    buildrooms_dir = ROOT / "wucios/buildrooms/store-root"
    required_paths = [
        buildrooms_dir / "euclid-store-root-phase-3c-c.json",
        buildrooms_dir / "store-root-policy.json",
        buildrooms_dir / "declarative-input-policy.json",
        buildrooms_dir / "evidence-requirements.json",
        buildrooms_dir / "guardrail-policy.json",
        buildrooms_dir / "README.md",
        ROOT / "wucios/schemas/euclid-store-root-phase-3c-c.schema.json",
        ROOT / "wucios/schemas/store-root-candidate-preparation.schema.json",
        ROOT / "wucios/schemas/store-root-declarative-input-policy.schema.json",
        ROOT / "tools/wucios/run_euclid_store_root_phase_3c_c.py",
        ROOT / "tools/wucios/store_root_prep_common.py",
    ]
    for candidate in STORE_ROOT_CANDIDATES:
        required_paths.extend([
            buildrooms_dir / candidate / "preparation-policy.json",
            buildrooms_dir / candidate / "README.md",
        ])
    for path in required_paths:
        if not path.is_file():
            failures.append(f"missing Phase 3C-C file: {path.relative_to(ROOT)}")

    plan_path = buildrooms_dir / "euclid-store-root-phase-3c-c.json"
    plan = load_json(plan_path, failures)
    if isinstance(plan, dict):
        require_keys(plan_path, plan, PHASE_3C_C_PLAN_KEYS, failures)
        if plan.get("phase_id") != "euclid-trial-phase-3c-c":
            failures.append("Phase 3C-C plan must use phase_id euclid-trial-phase-3c-c")
        if plan.get("default_execution_mode") != "L1_STORE_ROOT_POLICY_AND_DECLARATIVE_INPUTS":
            failures.append("Phase 3C-C plan must default to L1_STORE_ROOT_POLICY_AND_DECLARATIVE_INPUTS")
        if plan.get("l2_scaffold_authorized_by_default") is not False:
            failures.append("Phase 3C-C plan must disable L2 scaffold by default")
        if plan.get("l2_scaffold_authorization_env") != "WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1":
            failures.append("Phase 3C-C plan must require WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1")
        if plan.get("substrate_selection") != "NO_SUBSTRATE_SELECTED":
            failures.append("Phase 3C-C plan must keep substrate_selection NO_SUBSTRATE_SELECTED")
        for key in [
            "ranking_allowed",
            "emotional_testing_allowed",
            "l3_substrate_artifact_attempts_allowed",
            "runtime_inspection_allowed",
            "numeric_score_allowed",
            "image_pulls_allowed",
            "container_builds_allowed",
            "container_runs_allowed",
            "vm_runs_allowed",
            "sudo_allowed",
            "host_package_install_allowed",
            "source_clone_allowed",
            "os_image_download_allowed",
            "store_realization_allowed",
            "derivation_build_allowed",
            "package_build_allowed",
            "system_activation_allowed",
            "rootfs_generation_allowed",
        ]:
            if plan.get(key) is not False:
                failures.append(f"Phase 3C-C plan must set {key} false")
        if plan.get("network_default") != "DISABLED":
            failures.append("Phase 3C-C plan must disable network by default")
        if plan.get("in_scope_candidates") != STORE_ROOT_CANDIDATES:
            failures.append("Phase 3C-C plan must scope only NixOS and Guix store-root candidates")
        out_of_scope = plan.get("out_of_scope_preserved", {})
        if not isinstance(out_of_scope, dict) or "phase_3c_b_direct_rootfs" not in out_of_scope or "phase_3c_d_heavy_source" not in out_of_scope or "phase_3c_e_reference_runtime" not in out_of_scope:
            failures.append("Phase 3C-C plan must preserve Phase 3C-B, 3C-D, and 3C-E boundaries")
        forbidden = "\n".join(str(item) for item in plan.get("forbidden_actions", []))
        for phrase in [
            "nix-build",
            "nixos-rebuild",
            "nix develop",
            "nix shell",
            "nix flake check",
            "guix build",
            "guix system",
            "guix shell",
            "guix environment",
            "guix pull",
            "store realization",
            "network fetch",
            "OS image download",
            "rootfs generation",
            "VM launch",
            "sudo",
            "package installation",
            "source clone",
            "substrate selection",
            "candidate ranking",
            "numeric WuciOS score",
        ]:
            if phrase not in forbidden:
                failures.append(f"Phase 3C-C plan must forbid {phrase}")

    store_policy_path = buildrooms_dir / "store-root-policy.json"
    store_policy = load_json(store_policy_path, failures)
    if isinstance(store_policy, dict):
        if store_policy.get("phase_id") != "euclid-trial-phase-3c-c":
            failures.append("store-root policy must use Phase 3C-C phase_id")
        if store_policy.get("applies_to") != STORE_ROOT_CANDIDATES:
            failures.append("store-root policy must apply only to NixOS and Guix store-root candidates")
        for key in [
            "l3_artifact_attempts_allowed",
            "rootfs_generation_allowed",
            "store_realization_allowed",
            "derivation_build_allowed",
            "package_build_allowed",
            "system_activation_allowed",
            "network_allowed",
            "container_builds_allowed",
            "container_runs_allowed",
            "image_pulls_allowed",
            "sudo_allowed",
            "host_package_install_allowed",
            "source_clone_allowed",
            "os_image_download_allowed",
        ]:
            if store_policy.get(key) is not False:
                failures.append(f"store-root policy must set {key} false")

    declarative_path = buildrooms_dir / "declarative-input-policy.json"
    declarative_policy = load_json(declarative_path, failures)
    if isinstance(declarative_policy, dict):
        if declarative_policy.get("status") != "POLICY_ONLY_NOT_EXECUTABLE":
            failures.append("declarative-input-policy.json must be POLICY_ONLY_NOT_EXECUTABLE")
        for key in ["inputs_evaluated_in_phase_3c_c", "inputs_realized_in_phase_3c_c", "network_allowed_in_phase_3c_c"]:
            if declarative_policy.get(key) is not False:
                failures.append(f"declarative-input-policy.json must set {key} false")
        candidates = declarative_policy.get("candidates", {})
        if not isinstance(candidates, dict):
            failures.append("declarative-input-policy.json candidates must be an object")
        else:
            for candidate in STORE_ROOT_CANDIDATES:
                item = candidates.get(candidate, {})
                if not isinstance(item, dict):
                    failures.append(f"declarative-input-policy.json missing {candidate}")
                    continue
                if item.get("future_level_required") != "L3":
                    failures.append(f"{candidate} declarative input policy must require L3")
                forbidden = "\n".join(str(entry) for entry in item.get("forbidden_in_phase_3c_c", []))
                for phrase in ["evaluate declarative input", "realize store path", "use network", "generate rootfs", "select substrate", "rank candidate", "generate numeric score"]:
                    if phrase not in forbidden:
                        failures.append(f"{candidate} declarative input policy must forbid {phrase}")

    evidence_path = buildrooms_dir / "evidence-requirements.json"
    evidence = load_json(evidence_path, failures)
    if isinstance(evidence, dict):
        for key in ["phase_3c_c_generates_substrate_evidence", "phase_3c_c_generates_artifact_hashes", "phase_3c_c_generates_numeric_scores"]:
            if evidence.get(key) is not False:
                failures.append(f"Phase 3C-C evidence requirements must set {key} false")
        required_outputs = evidence.get("future_l3_required_outputs", [])
        for name in ["declarative-input-manifest.json", "store-policy.json", "store-realization-log.txt", "artifact-manifest.json", "artifact.sha256", "substrate-report.json", "missing-measurements.txt"]:
            if name not in required_outputs:
                failures.append(f"Phase 3C-C evidence requirements must include {name}")

    guardrail_path = buildrooms_dir / "guardrail-policy.json"
    guardrail_policy = load_json(guardrail_path, failures)
    if isinstance(guardrail_policy, dict):
        refusal_text = "\n".join(str(item) for item in guardrail_policy.get("required_refusal_checks", []))
        for phrase in ["WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD", "WUCIOS_EUCLID_ALLOW_ATTEMPT", "WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD"]:
            if phrase not in refusal_text:
                failures.append(f"Phase 3C-C guardrail policy must include refusal check for {phrase}")
        forbidden_text = "\n".join(str(item) for item in guardrail_policy.get("phase_3c_c_must_not_execute", []))
        for phrase in ["nix-build", "nixos-rebuild", "nix develop", "nix shell", "nix flake check", "guix build", "guix system", "guix shell", "guix environment", "guix pull", "docker", "podman run", "buildah", "qemu", "virt-install", "sudo", "apt", "apk", "xbps-install", "pacman", "git clone"]:
            if phrase not in forbidden_text:
                failures.append(f"Phase 3C-C guardrail policy must forbid {phrase}")

    for candidate in STORE_ROOT_CANDIDATES:
        policy_path = buildrooms_dir / candidate / "preparation-policy.json"
        policy = load_json(policy_path, failures)
        if isinstance(policy, dict):
            require_keys(policy_path, policy, STORE_ROOT_CANDIDATE_POLICY_KEYS, failures)
            if policy.get("phase_id") != "euclid-trial-phase-3c-c":
                failures.append(f"{candidate} policy must use Phase 3C-C phase_id")
            if policy.get("candidate_id") != candidate:
                failures.append(f"{candidate} policy candidate id mismatch")
            if policy.get("l1_status") != "PREP_DECLARATIVE_INPUTS_MISSING":
                failures.append(f"{candidate} policy must define PREP_DECLARATIVE_INPUTS_MISSING L1 status")
            if policy.get("l2_status") != "PREP_DECLARATIVE_SCAFFOLD_GENERATED":
                failures.append(f"{candidate} policy must define PREP_DECLARATIVE_SCAFFOLD_GENERATED L2 status")
            if policy.get("artifact_status") != "NO_WUCIOS_ARTIFACT":
                failures.append(f"{candidate} policy must keep NO_WUCIOS_ARTIFACT")
            if policy.get("score_status") != "NO_ARTIFACT_SCORE":
                failures.append(f"{candidate} policy must keep NO_ARTIFACT_SCORE")
            for key in ["l3_artifact_attempt_allowed", "rootfs_generation_allowed", "store_realization_allowed"]:
                if policy.get(key) is not False:
                    failures.append(f"{candidate} policy must set {key} false")
            forbidden = "\n".join(str(item) for item in policy.get("forbidden_commands", []))
            for phrase in ["nix-build", "nixos-rebuild", "nix develop", "nix shell", "nix flake check", "guix build", "guix system", "guix shell", "guix environment", "guix pull", "docker", "podman run", "podman build", "buildah", "qemu", "virt-install", "sudo", "apt", "apk", "xbps-install", "pacman", "curl", "wget", "git clone"]:
                if phrase not in forbidden:
                    failures.append(f"{candidate} policy must forbid {phrase}")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    if "wucios-euclid-store-root-phase-3c-c-scaffold:" not in makefile:
        failures.append("Makefile must contain Phase 3C-C guarded scaffold target")
    if "WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD" not in makefile:
        failures.append("Makefile Phase 3C-C scaffold target must check WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD")
    if "wucios-euclid-store-root-phase-3c-c-guardrails" not in makefile:
        failures.append("Makefile must contain Phase 3C-C guardrail target")


def main() -> int:
    failures: list[str] = []
    warnings: list[str] = []

    for directory in REQUIRED_DIRS:
        if not (ROOT / directory).is_dir():
            failures.append(f"missing required directory: {directory}")

    validate_json_files_parse(failures)
    profiles = validate_profiles(failures)
    substrates = validate_substrates(failures)
    components = validate_components(failures)
    validate_budgets(failures)
    validate_noether_policy(profiles, components, failures)
    validate_euclid_trial_phase_1(failures)
    validate_euclid_trial_phase_2(failures, warnings)
    validate_euclid_buildrooms_phase_3a(failures, warnings)
    validate_euclid_buildrooms_phase_3b_readiness(failures, warnings)
    validate_euclid_buildrooms_phase_3c_a(failures, warnings)
    validate_euclid_direct_rootfs_phase_3c_b(failures, warnings)
    validate_euclid_store_root_phase_3c_c(failures, warnings)

    for doc in REQUIRED_DOCS:
        if not (ROOT / "docs/wucios" / doc).is_file():
            failures.append(f"missing WuciOS doc: docs/wucios/{doc}")

    for tool in REQUIRED_TOOLS:
        if not (ROOT / "tools/wucios" / tool).is_file():
            failures.append(f"missing WuciOS tool: tools/wucios/{tool}")

    if not (ROOT / "wucios/sets/cantor-denied-claim-phrases.txt").is_file():
        failures.append("missing denied claim phrases file")

    if failures:
        print("WuciOS validation: FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("WuciOS validation: PASS")
    for warning in warnings:
        print(f"WARNING: {warning}")
    print(f"- profiles: {len(profiles)}")
    print(f"- substrates: {len(substrates)}")
    print(f"- components: {len(components)}")
    print(f"- Euclid Phase 1 candidates: {len(FIRST_TRIAL_COHORT)}")
    print(f"- Euclid Phase 2 candidates: {len(FULL_TRIAL_COHORT)}")
    print(f"- Euclid Phase 3A build rooms: {len(FULL_TRIAL_COHORT)}")
    print(f"- Euclid Phase 3B readiness candidates: {len(FULL_TRIAL_COHORT)}")
    print("- Euclid Phase 3C-A synthetic smoke buildroom: present")
    print(f"- Euclid Phase 3C-B direct rootfs preparation candidates: {len(DIRECT_ROOTFS_CANDIDATES)}")
    print(f"- Euclid Phase 3C-C store-root preparation candidates: {len(STORE_ROOT_CANDIDATES)}")
    print("- Noether Core forbids GUI, browser, desktop environment, and default network services")
    print("- Void remains a candidate substrate")
    print("- Xfce, ratpoison, and DWM are not in Noether Core")
    return 0


if __name__ == "__main__":
    sys.exit(main())
