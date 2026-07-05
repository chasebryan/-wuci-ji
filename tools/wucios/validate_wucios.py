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
    "buildroom_common.py",
    "backend_readiness_common.py",
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
    print("- Noether Core forbids GUI, browser, desktop environment, and default network services")
    print("- Void remains a candidate substrate")
    print("- Xfce, ratpoison, and DWM are not in Noether Core")
    return 0


if __name__ == "__main__":
    sys.exit(main())
