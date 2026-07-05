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
        if phase_plan.get("cohort") != FIRST_TRIAL_COHORT:
            failures.append("Phase 2 plan cohort must match first trial cohort")

    schema_path = ROOT / "wucios/schemas/euclid-trial-phase-2.schema.json"
    if not schema_path.is_file():
        failures.append("missing Phase 2 schema: wucios/schemas/euclid-trial-phase-2.schema.json")
    else:
        load_json(schema_path, failures)

    helper_path = ROOT / "tools/wucios/trial_collectors/build_probe.py"
    if not helper_path.is_file():
        failures.append("missing Phase 2 helper: tools/wucios/trial_collectors/build_probe.py")

    for candidate in FIRST_TRIAL_COHORT:
        directory = ROOT / "wucios/trials" / candidate
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
    print(f"- Euclid Phase 2 candidates: {len(FIRST_TRIAL_COHORT)}")
    print("- Noether Core forbids GUI, browser, desktop environment, and default network services")
    print("- Void remains a candidate substrate")
    print("- Xfce, ratpoison, and DWM are not in Noether Core")
    return 0


if __name__ == "__main__":
    sys.exit(main())
