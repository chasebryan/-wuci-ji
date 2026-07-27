#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import runpy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "wucios/profiles/lovelace-laboratory.json"
SCHEMA_PATH = ROOT / "wucios/schemas/lovelace-laboratory-profile.schema.json"
NOETHER_PATH = ROOT / "wucios/profiles/noether-core.json"
RELEASE_PATH = (
    ROOT / "wucios/releases/lovelace-laboratory-v0.1.0/release.json"
)
BUILDER_PATH = ROOT / "tools/wucios/lovelace_builder.py"
SUPERVISOR_PATH = ROOT / "tools/wuci_lab.py"
MAKEFILE_PATH = ROOT / "Makefile"
VALIDATOR_PATH = ROOT / "tools/wucios/validate_wucios.py"
PAYLOAD_FIXTURE_PATH = ROOT / "wucios/fixtures/lovelace/hostile-payload.txt"
PAYLOAD_VALIDATION_FIELD = "hostile_payload_ingress"
PAYLOAD_MEASURED_STATUS = (
    "locally-validated-kvm-fixed-benign-read-only-payload-ingress"
)
PAYLOAD_EVIDENCE_PATH = "evidence/hostile-payload-ingress.json"
PAYLOAD_EVIDENCE_SCHEMA = (
    "wucios.lovelace.hostile_payload_ingress_evidence.v1"
)
PAYLOAD_GATE_ID = "hostile-payload-ingress-fixed-fixture"
PAYLOAD_FIXTURE = {
    "path": "wucios/fixtures/lovelace/hostile-payload.txt",
    "size": 44,
    "sha256": (
        "cf7fe660be24036a09dfde459549fc0c"
        "b2fa57fd6551d6b207e450d1f9b320d5"
    ),
    "classification": "fixed-benign-acceptance-fixture",
}
HOSTILE_REQUIRED_LAYERS = [
    "usable-kvm-device",
    "unprivileged-qemu-process",
    "outer-bwrap-namespace",
    "qemu-sandbox-enabled",
    "resource-bounds-applied",
    "volatile-overlay-cleanup-observed",
    "observed-qemu-identity-disappearance",
    "network-device-absent",
    "host-shares-and-device-passthrough-absent",
]
PAYLOAD_REQUIRED_LAYERS = HOSTILE_REQUIRED_LAYERS + [
    "fixed-benign-payload-fixture-bound",
    "supervisor-payload-sha256-bound",
    "exact-trusted-debugfs-semantic-readback",
    "guest-payload-and-manifest-bytes-verified",
    "guest-read-only-mount-and-write-rejection",
    "payload-media-cleanup-observed",
]
PAYLOAD_GATE = {
    "id": PAYLOAD_GATE_ID,
    "required_evidence_path": PAYLOAD_EVIDENCE_PATH,
    "manifest_status_source": (
        "manifest.validation.hostile_payload_ingress"
    ),
    "manifest_evidence_source": (
        "manifest.validation_evidence.hostile_payload_ingress"
    ),
    "missing_status": "NOT_MEASURED",
    "measured_status": PAYLOAD_MEASURED_STATUS,
    "claim_allowed_when": {
        "manifest_status_equals_measured_status": True,
        "exact_artifact_binding_validated": True,
        "evidence_status_pass": True,
        "all_required_layers_validated": True,
        "fixed_benign_fixture_identity_validated": True,
        "payload_sha256_bound_at_supervisor_launch": True,
        "supervisor_semantic_readback_validated": True,
        "guest_payload_exact_bytes_validated": True,
        "guest_manifest_exact_bytes_validated": True,
        "guest_read_only_mount_validated": True,
        "guest_root_write_rejected_and_probe_absent": True,
        "post_dispatch_challenge_results_validated": True,
        "forbidden_guest_runtime_diagnostics_absent": True,
        "console_ready_within_bounded_deadline": True,
        "hostile_console_byte_allowlist_enforced": True,
        "hostile_stdin_one_way_pipe_validated": True,
        "hostile_normal_unwind_cleanup_validated": True,
    },
    "required_layers": PAYLOAD_REQUIRED_LAYERS,
}

CANONICAL_OUTPUTS = [
    {
        "path": "manifest.json",
        "producer_command": "build",
        "claim_scope": "artifact-binding-and-static-runtime-surface",
        "validation_fields": [],
        "isolation_claim": False,
    },
    {
        "path": "evidence/reproducibility.json",
        "producer_command": "reproducibility-test",
        "claim_scope": "offline-two-build-byte-for-byte-reproducibility",
        "validation_fields": ["reproducible_build"],
        "isolation_claim": False,
    },
    {
        "path": "evidence/boot-test.json",
        "producer_command": "boot-test",
        "claim_scope": "volatile-offline-tcg-language-matrix",
        "validation_fields": ["boot", "language_matrix"],
        "isolation_claim": False,
    },
    {
        "path": "evidence/ghidra-headless.json",
        "producer_command": "ghidra-test",
        "claim_scope": "volatile-offline-tcg-ghidra-headless",
        "validation_fields": ["ghidra_headless"],
        "isolation_claim": False,
    },
    {
        "path": "evidence/noxframe-guest.json",
        "producer_command": "noxframe-test",
        "claim_scope": (
            "volatile-offline-tcg-noxframe-programming-and-ghidra-broker"
        ),
        "validation_fields": ["noxframe_guest_broker"],
        "isolation_claim": False,
    },
    {
        "path": "evidence/persistent-round-trip.json",
        "producer_command": "persistent-test",
        "claim_scope": "offline-tcg-two-boot-persistent-round-trip",
        "validation_fields": ["persistent_round_trip"],
        "isolation_claim": False,
    },
    {
        "path": "evidence/network-internet.json",
        "producer_command": "network-test",
        "claim_scope": "explicit-internet-nat-tcg-https-reachability",
        "validation_fields": ["network_internet"],
        "isolation_claim": False,
    },
    {
        "path": "evidence/hostile-kvm-cell.json",
        "producer_command": "hostile-test",
        "claim_scope": "local-kvm-bwrap-layered-control-presence",
        "validation_fields": ["hostile_kvm_cell"],
        "isolation_claim": True,
        "claim_gate": "hostile-kvm-bwrap-cell",
    },
    {
        "path": PAYLOAD_EVIDENCE_PATH,
        "producer_command": "hostile-payload-test",
        "claim_scope": (
            "local-kvm-bwrap-fixed-benign-read-only-payload-ingress"
        ),
        "validation_fields": [PAYLOAD_VALIDATION_FIELD],
        "isolation_claim": False,
        "claim_gate": PAYLOAD_GATE_ID,
    },
]

EVIDENCE_FUNCTION_COMMANDS = {
    "_reproducibility_test_unlocked": "reproducibility-test",
    "_boot_test_unlocked": "boot-test",
    "_ghidra_test_unlocked": "ghidra-test",
    "_noxframe_test_unlocked": "noxframe-test",
    "_persistent_round_trip_test_unlocked": "persistent-test",
    "network_test": "network-test",
    "hostile_test": "hostile-test",
    "hostile_payload_test": "hostile-payload-test",
}


class SchemaError(ValueError):
    pass


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    if "const" in schema and instance != schema["const"]:
        raise SchemaError(f"{path}: value does not match const")

    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(instance, dict),
        "array": isinstance(instance, list),
        "string": isinstance(instance, str),
        "boolean": isinstance(instance, bool),
    }
    if expected_type in type_matches and not type_matches[expected_type]:
        raise SchemaError(f"{path}: expected {expected_type}")

    if isinstance(instance, str) and len(instance) < schema.get("minLength", 0):
        raise SchemaError(f"{path}: string is too short")

    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            raise SchemaError(f"{path}: array is too short")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in instance]
            if len(encoded) != len(set(encoded)):
                raise SchemaError(f"{path}: array items are not unique")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                validate(item, item_schema, f"{path}[{index}]")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        missing = set(schema.get("required", [])) - set(instance)
        if missing:
            raise SchemaError(f"{path}: missing {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(properties)
            if extra:
                raise SchemaError(f"{path}: unexpected {sorted(extra)}")
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], f"{path}.{key}")


def assert_rejected(profile: dict[str, Any], schema: dict[str, Any]) -> None:
    try:
        validate(profile, schema)
    except SchemaError:
        return
    raise AssertionError("mutated profile unexpectedly passed its schema")


def builder_contract() -> tuple[set[str], dict[str, dict[str, Any]]]:
    tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"))
    commands: set[str] = set()
    evidence: dict[str, dict[str, Any]] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_parser"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            commands.add(node.args[0].value)

    for function in (
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    ):
        for call in ast.walk(function):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "_update_validation_unlocked"
                and function.name != "update_validation"
                and len(call.args) >= 4
            ):
                continue
            updates, evidence_name = call.args[1], call.args[2]
            if not (
                isinstance(updates, ast.Dict)
                and isinstance(evidence_name, ast.Constant)
                and isinstance(evidence_name.value, str)
            ):
                raise AssertionError(
                    f"{function.name}: evidence mapping must be literal"
                )
            fields: list[str] = []
            for key in updates.keys:
                if not (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                ):
                    raise AssertionError(
                        f"{function.name}: validation field must be literal"
                    )
                fields.append(key.value)
            path = f"evidence/{evidence_name.value}"
            if path in evidence:
                raise AssertionError(f"duplicate builder evidence path: {path}")
            evidence[path] = {
                "function": function.name,
                "validation_fields": fields,
            }
    return commands, evidence


def assignment_node(tree: ast.Module, name: str) -> ast.expr:
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id == name:
                return statement.value
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == name
            and statement.value is not None
        ):
            return statement.value
    raise AssertionError(f"missing supervisor assignment: {name}")


def function_source(tree: ast.Module, source: str, name: str) -> str:
    for statement in tree.body:
        if isinstance(statement, ast.FunctionDef) and statement.name == name:
            value = ast.get_source_segment(source, statement)
            if value is None:
                break
            return value
    raise AssertionError(f"missing supervisor function: {name}")


def test_profile_matches_strict_schema() -> None:
    profile = load_json(PROFILE_PATH)
    schema = load_json(SCHEMA_PATH)

    validate(profile, schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(profile)


def test_wucios_validator_applies_strict_profile_schema() -> None:
    validator = runpy.run_path(str(VALIDATOR_PATH))[
        "validate_lovelace_profile_schema"
    ]
    profile = load_json(PROFILE_PATH)
    failures: list[str] = []
    validator(profile, failures)
    assert failures == []

    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["qemu_configuration"][
        "network_device"
    ] = "present"
    failures = []
    validator(changed, failures)
    assert len(failures) == 1
    assert "Lovelace strict profile schema rejected profile" in failures[0]
    assert "network_device" in failures[0]

    for field_path, invalid in (
        (("default_profile",), 0),
        (("network", "modes", "internet", "explicit_selection_required"), 1),
    ):
        changed = copy.deepcopy(profile)
        target = changed
        for key in field_path[:-1]:
            target = target[key]
        target[field_path[-1]] = invalid
        failures = []
        validator(changed, failures)
        assert len(failures) == 1
        assert "value does not match const" in failures[0]


def test_profile_is_separate_and_non_authoritative() -> None:
    profile = load_json(PROFILE_PATH)
    noether = load_json(NOETHER_PATH)

    assert profile["id"] != noether["id"]
    assert profile["default_profile"] is False
    assert profile["authoritative_for_release"] is False
    assert profile["profile_separation"] == {
        "noether_core_dependency": False,
        "noether_core_package_lock_reused": False,
        "noether_core_release_evidence_accepted": False,
        "release_score_allowed": False,
    }
    assert noether["default_profile"] is True
    assert noether["authoritative_for_release"] is True
    assert "runtime-compiler" in noether["forbidden_component_classes"]


def test_evidence_contract_matches_builder_outputs_and_claim_gate() -> None:
    profile = load_json(PROFILE_PATH)
    release = load_json(RELEASE_PATH)
    contract = profile["evidence_contract"]
    commands, builder_evidence = builder_contract()

    assert release["output_files"]["manifest"] == "manifest.json"
    assert contract["canonical_outputs"] == CANONICAL_OUTPUTS
    canonical_paths = [item["path"] for item in CANONICAL_OUTPUTS]
    assert profile["required_evidence_outputs"] == canonical_paths
    assert set(builder_evidence) == set(canonical_paths) - {"manifest.json"}

    for output in CANONICAL_OUTPUTS:
        assert output["producer_command"] in commands
        if output["path"] == "evidence/hostile-kvm-cell.json":
            assert output["isolation_claim"] is True
            assert output["claim_gate"] == "hostile-kvm-bwrap-cell"
        else:
            assert output["isolation_claim"] is False
        if output["path"] == "manifest.json":
            continue
        emitted = builder_evidence[output["path"]]
        assert (
            EVIDENCE_FUNCTION_COMMANDS[emitted["function"]]
            == output["producer_command"]
        )
        assert emitted["validation_fields"] == output["validation_fields"]

    assert contract["missing_evidence_status"] == "NOT_MEASURED"
    claim_gates = contract["claim_gates"]
    assert claim_gates == [
        {
            "id": "hostile-kvm-bwrap-cell",
            "required_evidence_path": "evidence/hostile-kvm-cell.json",
            "manifest_status_source": (
                "manifest.validation.hostile_kvm_cell"
            ),
            "manifest_evidence_source": (
                "manifest.validation_evidence.hostile_kvm_cell"
            ),
            "missing_status": "NOT_MEASURED",
            "measured_status": (
                "locally-validated-kvm-layered-control-presence"
            ),
            "claim_allowed_when": {
                "manifest_status_equals_measured_status": True,
                "exact_artifact_binding_validated": True,
                "evidence_status_pass": True,
                "all_required_layers_validated": True,
                "forbidden_guest_runtime_diagnostics_absent": True,
                "console_ready_within_bounded_deadline": True,
                "hostile_console_byte_allowlist_enforced": True,
                "hostile_stdin_one_way_pipe_validated": True,
                "hostile_normal_unwind_cleanup_validated": True,
            },
            "required_layers": HOSTILE_REQUIRED_LAYERS,
        },
        PAYLOAD_GATE,
    ]
    ordinary_gate = claim_gates[0]
    payload_gate = claim_gates[1]
    for gate in claim_gates:
        assert "status" not in gate
        assert "claim_allowed" not in gate
    assert ordinary_gate["id"] != payload_gate["id"]
    assert ordinary_gate["required_evidence_path"] != (
        payload_gate["required_evidence_path"]
    )
    assert ordinary_gate["manifest_status_source"] != (
        payload_gate["manifest_status_source"]
    )

    builder_tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"))
    validation_contract = ast.literal_eval(
        assignment_node(builder_tree, "VALIDATION_CONTRACT")
    )
    assert validation_contract["hostile_kvm_cell"] == {
        "measured_status": ordinary_gate["measured_status"],
        "evidence_path": ordinary_gate["required_evidence_path"],
        "evidence_schema": (
            "wucios.lovelace.hostile_kvm_cell_evidence.v1"
        ),
    }
    assert validation_contract[PAYLOAD_VALIDATION_FIELD] == {
        "measured_status": payload_gate["measured_status"],
        "evidence_path": payload_gate["required_evidence_path"],
        "evidence_schema": PAYLOAD_EVIDENCE_SCHEMA,
    }


def test_capability_claims_map_to_exact_functional_evidence() -> None:
    profile = load_json(PROFILE_PATH)
    by_scope = {
        item["claim_scope"]: item
        for item in profile["evidence_contract"]["canonical_outputs"]
    }

    assert profile["programming"]["language_targets"] == [
        "python3",
        "c",
        "c++",
        "assembly",
        "rust",
        "go",
    ]
    assert by_scope["volatile-offline-tcg-language-matrix"][
        "validation_fields"
    ] == ["boot", "language_matrix"]
    assert by_scope[
        "volatile-offline-tcg-noxframe-programming-and-ghidra-broker"
    ][
        "validation_fields"
    ] == ["noxframe_guest_broker"]
    assert by_scope["volatile-offline-tcg-ghidra-headless"][
        "validation_fields"
    ] == ["ghidra_headless"]
    assert by_scope["offline-tcg-two-boot-persistent-round-trip"][
        "validation_fields"
    ] == ["persistent_round_trip"]
    assert by_scope["explicit-internet-nat-tcg-https-reachability"][
        "validation_fields"
    ] == ["network_internet"]
    functional_scopes = set(by_scope) - {
        "local-kvm-bwrap-layered-control-presence"
    }
    assert all(
        by_scope[scope]["isolation_claim"] is False
        for scope in functional_scopes
    )
    hostile_output = by_scope[
        "local-kvm-bwrap-layered-control-presence"
    ]
    assert hostile_output["validation_fields"] == ["hostile_kvm_cell"]
    assert hostile_output["isolation_claim"] is True
    assert hostile_output["claim_gate"] == "hostile-kvm-bwrap-cell"
    payload_output = by_scope[
        "local-kvm-bwrap-fixed-benign-read-only-payload-ingress"
    ]
    assert payload_output["validation_fields"] == [
        PAYLOAD_VALIDATION_FIELD
    ]
    assert payload_output["isolation_claim"] is False
    assert payload_output["claim_gate"] == PAYLOAD_GATE_ID


def test_hostile_profile_layers_match_supervisor_controls() -> None:
    profile = load_json(PROFILE_PATH)
    source = SUPERVISOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    builder_source = BUILDER_PATH.read_text(encoding="utf-8")
    builder_tree = ast.parse(builder_source)
    cell = profile["virtualization"]["defensive_cell"]

    assert list(ast.literal_eval(assignment_node(tree, "KERNEL_ARGUMENTS"))) == (
        cell["kernel_arguments"]
    )
    assert ast.literal_eval(
        assignment_node(tree, "HOSTILE_CONSOLE_RENDERING")
    ) == cell["qemu_configuration"]["console_rendering"]
    assert ast.unparse(
        assignment_node(tree, "MAX_HOSTILE_CONSOLE_BYTES")
    ) == "32 * 1024 * 1024"
    assert cell["qemu_configuration"]["console_byte_limit"] == 33554432
    assert ast.literal_eval(
        assignment_node(
            tree,
            "HOSTILE_CONSOLE_DESCENDANT_DRAIN_TIMEOUT_SECONDS",
        )
    ) == cell["qemu_configuration"]["descendant_drain_timeout_seconds"]
    assert ast.literal_eval(
        assignment_node(
            tree,
            "HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS",
        )
    ) == cell["qemu_configuration"][
        "leader_exit_confirm_timeout_seconds"
    ]
    assert ast.literal_eval(
        assignment_node(
            builder_tree, "HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS"
        )
    ) == cell["console_ready_timeout_seconds"]
    assert list(
        ast.literal_eval(
            assignment_node(
                builder_tree,
                "FORBIDDEN_GUEST_RUNTIME_DIAGNOSTICS",
            )
        )
    ) == cell["forbidden_guest_runtime_diagnostics"]
    assert ast.literal_eval(assignment_node(tree, "QEMU_SANDBOX")) == (
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,"
        "resourcecontrol=deny"
    )
    assert ast.literal_eval(assignment_node(tree, "HOSTILE_BWRAP_FLAGS")) == (
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-net",
    )
    trusted_bwrap = assignment_node(tree, "TRUSTED_BWRAP")
    assert (
        isinstance(trusted_bwrap, ast.Call)
        and isinstance(trusted_bwrap.func, ast.Name)
        and trusted_bwrap.func.id == "Path"
        and len(trusted_bwrap.args) == 1
        and isinstance(trusted_bwrap.args[0], ast.Constant)
        and trusted_bwrap.args[0].value == "/usr/bin/bwrap"
    )

    blockers = function_source(tree, source, "_hostile_blockers")
    for capability in (
        "qemu_available",
        "q35_supported",
        "qemu_sandbox_supported",
        "kvm_accel_supported",
        "kvm_device",
        "non_root_user",
        "bubblewrap",
    ):
        assert capability in blockers

    acceleration = function_source(tree, source, "select_acceleration")
    assert 'if profile == "hostile"' in acceleration
    assert 'requested == "tcg"' in acceleration
    assert '"selected": "kvm"' in acceleration
    outer = function_source(tree, source, "_build_hostile_bwrap_argv")
    for boundary_token in (
        "HOSTILE_BWRAP_FLAGS",
        '"--dev-bind"',
        '"/dev/kvm"',
        '"--remount-ro"',
        "DEFERRED_VOLATILE_ROOT",
    ):
        assert boundary_token in outer
    launch = function_source(tree, source, "launch_plan")
    assert 'profile == "hostile" and network != "none"' in launch
    assert 'profile == "hostile" and storage != "volatile"' in launch
    assert "_build_hostile_bwrap_argv(" in launch
    relay = function_source(tree, source, "_run_hostile_console_relay")
    relay_cleanup = function_source(
        tree, source, "_cleanup_hostile_console_relay"
    )
    relay_restore = function_source(
        tree, source, "_restore_stdin_termios"
    )
    for relay_token in (
        "stdout=subprocess.PIPE",
        "stdin=subprocess.PIPE",
        "stderr=subprocess.STDOUT",
        "start_new_session=True",
        "MAX_HOSTILE_CONSOLE_BYTES",
        "MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES",
    ):
        assert relay_token in relay
    for cleanup_token in (
        "_restore_stdin_termios",
        "_hostile_console_process_group_exists",
    ):
        assert cleanup_token in relay_cleanup
    assert "termios.TCSAFLUSH" in relay_restore
    assert "termios.TCSANOW" not in relay_restore
    assert relay_cleanup.index(
        "_terminate_hostile_console_process"
    ) < relay_cleanup.index("_restore_stdin_termios")

    assert set(cell["required_host_gates"]) == {
        "usable-kvm-device",
        "unprivileged-qemu-process",
        "outer-bwrap-namespace",
        "qemu-sandbox-enabled",
        "resource-bounds-applied",
    }
    assert (
        cell["manifest_status_source"]
        == "manifest.validation.hostile_kvm_cell"
    )
    assert cell["claim_condition"] == (
        "local layered-control presence may be claimed only when exact "
        "artifact-bound hostile evidence validates every required layer"
    )
    assert "claim_status" not in cell
    assert "claim_allowed" not in cell


def test_storage_and_network_fail_closed_by_default() -> None:
    profile = load_json(PROFILE_PATH)
    storage = profile["storage"]
    network = profile["network"]

    assert storage["default_mode"] == "volatile"
    assert storage["modes"]["volatile"] == {
        "explicit_selection_required": False,
        "base_image_read_only": True,
        "discard_on_clean_exit": True,
        "discard_on_handled_failed_launch": True,
        "cleanup_after_sigkill_or_host_crash_claimed": False,
    }
    persistent = storage["modes"]["persistent"]
    for gate in (
        "explicit_selection_required",
        "named_store_required",
        "exclusive_lock_required",
        "owner_only_permissions_required",
        "base_digest_binding_required",
    ):
        assert persistent[gate] is True
    assert persistent["prohibited_execution_classes"] == [
        "defensive-untrusted-system-code"
    ]
    assert persistent["destructive_lifecycle"] == {
        "explicit_confirmation_required": True,
        "confirmation_binding": "action:name:base-sha256",
        "remove_action": "remove",
        "reset_action": "reset",
        "exact_image_and_manifest_only": True,
        "symlinks_allowed": False,
        "hardlinks_allowed": False,
        "per_name_lock_held": True,
        "inode_recheck_before_unlink": True,
        "recursive_deletion_allowed": False,
        "reset_removal_committed_before_recreation": True,
    }

    assert network["default_mode"] == "none"
    assert network["modes"]["none"]["guest_network_device_attached"] is False
    internet = network["modes"]["internet"]
    assert internet["explicit_selection_required"] is True
    assert internet["host_port_forwarding_allowed"] is False
    assert internet["host_filesystem_shares_allowed"] is False
    assert internet["isolation_claim"] is False
    assert internet["prohibited_execution_classes"] == [
        "defensive-untrusted-system-code"
    ]


def test_hostile_cell_is_kvm_only_and_has_no_ambient_bridges() -> None:
    profile = load_json(PROFILE_PATH)
    hostile = profile["execution_classes"]["defensive_untrusted_system_code"]
    cell = profile["virtualization"]["defensive_cell"]
    functional = profile["virtualization"]["functional"]

    assert hostile == {
        "hardware_accelerator": "kvm",
        "kvm_required": True,
        "fail_closed_without_kvm": True,
        "software_emulation_fallback": False,
        "network_mode": "none",
        "storage_mode": "volatile",
        "guest_privilege_assumption": "attacker-controlled-root",
        "persistent_storage_allowed": False,
        "host_shares_allowed": False,
        "host_device_passthrough_allowed": False,
        "bounded_read_only_payload_ingress_allowed": True,
        "payload_ingress_enabled_by_default": False,
    }
    assert cell["accelerator"] == "kvm"
    assert cell["fail_closed"] is True
    assert cell["guest_privilege_assumption"] == "attacker-controlled-root"
    assert set(cell["required_host_gates"]) == {
        "usable-kvm-device",
        "unprivileged-qemu-process",
        "outer-bwrap-namespace",
        "qemu-sandbox-enabled",
        "resource-bounds-applied",
    }
    assert (
        cell["manifest_status_source"]
        == "manifest.validation.hostile_kvm_cell"
    )
    assert cell["claim_condition"] == (
        "local layered-control presence may be claimed only when exact "
        "artifact-bound hostile evidence validates every required layer"
    )
    assert cell["required_evidence_path"] == "evidence/hostile-kvm-cell.json"
    release = load_json(RELEASE_PATH)
    expected_kernel_arguments = release["boot"]["kernel_arguments"]
    assert expected_kernel_arguments == [
        "root=/dev/vda",
        "rw",
        "rootfstype=ext4",
        "console=ttyS0,115200",
        "panic=10",
    ]
    assert cell["kernel_arguments"] == expected_kernel_arguments
    assert cell["console_ready_timeout_seconds"] == 180
    assert cell["forbidden_guest_runtime_diagnostics"] == [
        "Kernel panic - not syncing:",
        "watchdog: BUG: soft lockup",
        "BUG: unable to handle",
        "Oops:",
        "general protection fault",
        "EXT4-fs error",
        "Buffer I/O error",
        "Mounting root: failed.",
        "Launching initramfs emergency recovery shell.",
        "mount: mounting /dev/vda on /sysroot failed",
        "VFS: Cannot open root device",
        "VFS: Unable to mount root fs",
        "No filesystem could mount root",
        "No working init found.",
        "Failed to execute /init",
        "Attempted to kill init!",
    ]
    assert cell["qemu_configuration"] == {
        "nodefaults": True,
        "no_user_config": True,
        "monitor": "disabled",
        "qmp": "disabled",
        "exact_boot_line": (
            "LOVELACE_LABORATORY_BOOT profile=lovelace-laboratory "
            "storage=host-selected network=none"
        ),
        "console_rendering": "escaped-ascii",
        "console_forwarded_byte_allowlist": [
            "tab-0x09",
            "line-feed-0x0a",
            "printable-ascii-0x20-0x7e",
        ],
        "non_allowlisted_console_bytes_forwarded": False,
        "console_stderr_merged": True,
        "console_byte_limit": 33554432,
        "console_input_buffer_byte_limit": 1048576,
        "stdin_transport": "one-way-pipe",
        "tty_restoration_on_handled_exit": True,
        "tty_input_flushed_before_handoff": True,
        "process_group_absence_checked": True,
        "handled_signals": [
            "SIGHUP",
            "SIGINT",
            "SIGQUIT",
            "SIGTERM",
            "SIGTSTP",
        ],
        "descendant_drain_timeout_seconds": 5,
        "leader_exit_confirm_timeout_seconds": 0.1,
        "network_device": "absent",
        "persistent_disk": "absent",
        "host_filesystem_share": "absent",
        "clipboard_integration": "absent",
        "usb_passthrough": "absent",
        "host_device_passthrough": "absent",
    }
    assert functional["accelerator"] == "tcg"
    assert functional["cpu_model"] == (
        "Broadwell-v4,pcid=off,x2apic=off,tsc-deadline=off,"
        "invpcid=off,spec-ctrl=off"
    )
    assert functional["kernel_argument_policy"] == {
        "tcg_only_extra_arguments": ["nosoftlockup"],
        "canonical_builder_arguments": [
            "root=/dev/vda",
            "rw",
            "rootfstype=ext4",
            "console=ttyS0,115200",
            "panic=10",
            "nosoftlockup",
        ],
        "interactive_supervisor_arguments": [
            "root=/dev/vda",
            "rw",
            "rootfstype=ext4",
            "console=ttyS0,115200",
            "panic=10",
            "nosoftlockup",
        ],
        "soft_lockup_detector_enabled": False,
        "hard_lockup_detector_disabled_by_policy": False,
        "liveness_gates": [
            "bounded-host-wall-clock-timeout",
            "exact-ordered-guest-markers",
            "zero-qemu-exit-status",
        ],
    }
    assert functional["isolation_claim"] is False
    assert functional["hostile_code_allowed"] is False


def test_payload_ingress_contract_is_bounded_and_artifact_gated() -> None:
    profile = load_json(PROFILE_PATH)
    cell = profile["virtualization"]["defensive_cell"]
    payload = cell["payload_ingress"]

    assert payload == {
        "implementation_status": "implemented-source-tested",
        "artifact_bound_runtime_evidence_status_source": (
            "manifest.validation.hostile_payload_ingress"
        ),
        "artifact_bound_runtime_evidence_source": (
            "manifest.validation_evidence.hostile_payload_ingress"
        ),
        "required_evidence_path": PAYLOAD_EVIDENCE_PATH,
        "missing_status": "NOT_MEASURED",
        "measured_status": PAYLOAD_MEASURED_STATUS,
        "claim_gate": PAYLOAD_GATE_ID,
        "runtime_capability_claimed_without_valid_gate": False,
        "canonical_runtime_test": {
            "producer_command": "hostile-payload-test",
            "make_target": "wucios-lovelace-hostile-payload-smoke",
            "fixture": PAYLOAD_FIXTURE,
        },
        "enabled_by_default": False,
        "required_controls": [
            "explicit-source-and-sha256",
            "bounded-single-link-regular-source",
            "private-nofollow-snapshot",
            "exact-trusted-mke2fs",
            "exact-trusted-debugfs-semantic-readback",
            "read-only-secondary-media",
            "no-host-source-share-or-execution",
            "offline-volatile-kvm-hostile-only",
            "exact-supervisor-unwind-cleanup",
        ],
        "explicit_source_and_sha256_required": True,
        "source_type": "single-link-regular-file",
        "maximum_source_bytes": 67108864,
        "private_snapshot_required": True,
        "host_source_shared": False,
        "host_source_executed": False,
        "media_builder_path": "/usr/sbin/mke2fs",
        "media_builder_version": "1.47.0",
        "media_readback_path": "/usr/sbin/debugfs",
        "media_readback_version": "1.47.0",
        "semantic_readback_required": True,
        "payload_readback_path": "/payload.bin",
        "payload_exact_bytes_readback_required": True,
        "manifest_readback_path": "/manifest.json",
        "manifest_exact_bytes_readback_required": True,
        "media_format": "raw-ext4",
        "maximum_media_bytes": 100663296,
        "host_media_mode": "0400",
        "guest_device": "/dev/vdb",
        "guest_attachment": "read-only-secondary-virtio-block",
        "guest_mount_policy": "read-only",
        "network_device_added": False,
        "persistent_storage_added": False,
        "host_share_added": False,
        "cleanup_on_supervisor_unwind": True,
        "cleanup_after_sigkill_or_host_crash_claimed": False,
        "containment_or_malware_safety_claimed": False,
    }
    assert "artifact_bound_runtime_evidence_status" not in payload
    assert "runtime_capability_claimed" not in payload
    ordinary_gate, payload_gate = profile["evidence_contract"]["claim_gates"]
    assert all(
        "payload" not in layer for layer in ordinary_gate["required_layers"]
    )
    assert payload_gate == PAYLOAD_GATE
    assert (
        ordinary_gate["required_layers"]
        == payload_gate["required_layers"][: len(HOSTILE_REQUIRED_LAYERS)]
        == HOSTILE_REQUIRED_LAYERS
    )
    assert payload_gate["required_layers"] == PAYLOAD_REQUIRED_LAYERS
    assert (
        payload["artifact_bound_runtime_evidence_status_source"]
        == payload_gate["manifest_status_source"]
    )
    assert (
        payload["artifact_bound_runtime_evidence_source"]
        == payload_gate["manifest_evidence_source"]
    )
    assert payload["required_evidence_path"] == (
        payload_gate["required_evidence_path"]
    )
    assert payload["missing_status"] == payload_gate["missing_status"]
    assert payload["measured_status"] == payload_gate["measured_status"]
    assert payload["claim_gate"] == payload_gate["id"]
    assert PAYLOAD_FIXTURE_PATH.read_bytes() == (
        b"Lovelace hostile payload ingress fixture v1\n"
    )
    assert PAYLOAD_FIXTURE_PATH.stat().st_size == PAYLOAD_FIXTURE["size"]
    assert hashlib.sha256(PAYLOAD_FIXTURE_PATH.read_bytes()).hexdigest() == (
        PAYLOAD_FIXTURE["sha256"]
    )
    assert (
        "The ordinary hostile-kvm-cell evidence does not exercise payload "
        "ingress and cannot promote manifest.validation.hostile_payload_ingress; "
        "payload-ingress evidence cannot promote "
        "manifest.validation.hostile_kvm_cell."
        in profile["notes"]
    )
    assert (
        "payload-ingress runtime validation is claimed without "
        "manifest.validation.hostile_payload_ingress and its exact "
        "artifact-bound evidence gate"
        in profile["disqualifying_conditions"]
    )

    source = SUPERVISOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert ast.unparse(
        assignment_node(tree, "MAX_HOSTILE_PAYLOAD_BYTES")
    ) == "64 * 1024 * 1024"
    assert ast.unparse(
        assignment_node(tree, "MAX_HOSTILE_PAYLOAD_MEDIA_BYTES")
    ) == "96 * 1024 * 1024"
    assert ast.literal_eval(
        assignment_node(tree, "TRUSTED_MKE2FS_VERSION")
    ) == payload["media_builder_version"]
    assert payload["media_readback_version"] == payload["media_builder_version"]

    for assignment, expected in (
        ("TRUSTED_MKE2FS", payload["media_builder_path"]),
        ("TRUSTED_DEBUGFS", payload["media_readback_path"]),
        ("HOSTILE_PAYLOAD_GUEST_MEDIA", "/run/wuci-payload.ext4"),
    ):
        node = assignment_node(tree, assignment)
        assert (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Path"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == expected
        )

    launch = function_source(tree, source, "launch_plan")
    assert (
        "--hostile-payload and --hostile-payload-sha256 are required together"
        in launch
    )
    assert 'payload ingress is restricted to the hostile profile' in launch
    qemu = function_source(tree, source, "_build_qemu_argv")
    assert "readonly=on" in qemu
    assert "offline, volatile" in qemu
    media = function_source(tree, source, "private_hostile_payload_media")
    for token in (
        "_copy_bound_payload",
        "_verify_hostile_payload_media_contents",
        "_remove_payload_operation_exact",
    ):
        assert token in media
    manifest = function_source(tree, source, "_hostile_payload_manifest")
    for token in (
        '"host_execution": False',
        '"host_source_shared": False',
        '"guest_media_read_only": True',
        '"network_enabled": False',
        '"persistent_storage_enabled": False',
    ):
        assert token in manifest
    readback = function_source(
        tree, source, "_verify_hostile_payload_media_contents"
    )
    for token in (
        "_debugfs_dump_digest",
        payload["payload_readback_path"],
        payload["manifest_readback_path"],
        "canonical_json(manifest)",
        '"exact_guest_file_bytes_verified": True',
    ):
        assert token in readback


def test_make_targets_bind_overlay_lifecycle_and_payload_parameters() -> None:
    source = MAKEFILE_PATH.read_text(encoding="utf-8")
    for variable in (
        "LOVELACE_OVERLAY_REMOVE_CONFIRM ?=",
        "LOVELACE_OVERLAY_RESET_CONFIRM ?=",
        "LOVELACE_HOSTILE_PAYLOAD ?=",
        "LOVELACE_HOSTILE_PAYLOAD_SHA256 ?=",
    ):
        assert variable in source
    for target in (
        "wucios-lovelace-overlay-remove",
        "wucios-lovelace-overlay-reset",
        "wucios-lovelace-hostile-payload-launch-plan",
        "wucios-lovelace-hostile-payload-launch",
    ):
        assert f"\n{target}: wucios-lovelace-structural-verify\n" in source
    assert (
        "\nwucios-lovelace-hostile-payload-smoke: "
        "wucios-lovelace-source-test\n"
    ) in source
    assert 'confirmation=os.environ["LOVELACE_OVERLAY_REMOVE_CONFIRM"]' in source
    assert 'confirmation=os.environ["LOVELACE_OVERLAY_RESET_CONFIRM"]' in source
    assert '"--hostile-payload", os.environ["LOVELACE_HOSTILE_PAYLOAD"]' in source
    assert (
        '"--hostile-payload-sha256", '
        'os.environ["LOVELACE_HOSTILE_PAYLOAD_SHA256"]' in source
    )
    assert source.count('"--profile", "hostile", "--storage", "volatile"') == 2
    assert source.count('"--network", "none", "--accel", "kvm"') == 2


def test_wucios_validator_enforces_payload_artifact_gate_contract() -> None:
    validator = runpy.run_path(str(VALIDATOR_PATH))[
        "validate_lovelace_laboratory"
    ]
    profile = load_json(PROFILE_PATH)
    payload_failure = (
        "Lovelace defensive-cell payload ingress contract is invalid"
    )
    output_failure = (
        "Lovelace hostile payload canonical evidence output is invalid"
    )
    gate_failure = "Lovelace hostile payload evidence gate is invalid"
    separation_failure = (
        "Lovelace hostile and payload evidence gates are not separate"
    )
    broker_resource_failure = (
        "Lovelace NOXFRAME Ghidra/output/resource contract is invalid"
    )

    failures: list[str] = []
    validator({"lovelace-laboratory": profile}, failures)
    for failure in (
        payload_failure,
        output_failure,
        gate_failure,
        separation_failure,
        "Lovelace hostile payload fixed benign fixture is invalid",
        "Lovelace hostile payload builder validation contract is invalid",
        broker_resource_failure,
    ):
        assert failure not in failures, failures

    mutations: list[dict[str, Any]] = []
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "semantic_readback_required"
    ] = False
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    del changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "media_readback_path"
    ]
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "unexpected_readback_override"
    ] = True
    mutations.append(changed)

    for field, invalid in (
        (
            "artifact_bound_runtime_evidence_status_source",
            "manifest.validation.hostile_kvm_cell",
        ),
        (
            "artifact_bound_runtime_evidence_source",
            "manifest.validation_evidence.hostile_kvm_cell",
        ),
        ("required_evidence_path", "evidence/hostile-kvm-cell.json"),
        ("missing_status", "PASS"),
        ("measured_status", "locally-validated"),
        ("claim_gate", "hostile-kvm-bwrap-cell"),
        ("runtime_capability_claimed_without_valid_gate", True),
    ):
        changed = copy.deepcopy(profile)
        changed["virtualization"]["defensive_cell"]["payload_ingress"][
            field
        ] = invalid
        mutations.append(changed)

    for field, invalid in (
        ("producer_command", "hostile-test"),
        ("make_target", "wucios-lovelace-hostile-smoke"),
    ):
        changed = copy.deepcopy(profile)
        changed["virtualization"]["defensive_cell"]["payload_ingress"][
            "canonical_runtime_test"
        ][field] = invalid
        mutations.append(changed)

    for field, invalid in (
        ("path", "wucios/fixtures/lovelace/other.txt"),
        ("size", 43),
        ("sha256", "0" * 64),
        ("classification", "arbitrary-malware-fixture"),
    ):
        changed = copy.deepcopy(profile)
        changed["virtualization"]["defensive_cell"]["payload_ingress"][
            "canonical_runtime_test"
        ]["fixture"][field] = invalid
        mutations.append(changed)

    for changed in mutations:
        failures = []
        validator({"lovelace-laboratory": changed}, failures)
        assert payload_failure in failures

    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["canonical_outputs"][-1][
        "isolation_claim"
    ] = True
    failures = []
    validator({"lovelace-laboratory": changed}, failures)
    assert output_failure in failures

    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][-1][
        "measured_status"
    ] = "locally-validated"
    failures = []
    validator({"lovelace-laboratory": changed}, failures)
    assert gate_failure in failures

    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][-1][
        "required_layers"
    ].remove("qemu-sandbox-enabled")
    failures = []
    validator({"lovelace-laboratory": changed}, failures)
    assert gate_failure in failures

    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"].reverse()
    failures = []
    validator({"lovelace-laboratory": changed}, failures)
    assert separation_failure in failures

    changed = copy.deepcopy(profile)
    changed["noxframe"]["guest_broker"]["resource_limits"]["open_files"][
        "ghidra_headless_route"
    ] = 128
    failures = []
    validator({"lovelace-laboratory": changed}, failures)
    assert broker_resource_failure in failures


def test_noxframe_and_ghidra_do_not_acquire_containment_authority() -> None:
    profile = load_json(PROFILE_PATH)
    noxframe = profile["noxframe"]
    broker = noxframe["guest_broker"]
    ghidra = profile["ghidra"]

    assert noxframe["default_behavior"] == "metadata-only"
    assert noxframe["containment_boundary"] is False
    assert noxframe["ambient_host_execution_allowed"] is False
    assert broker == {
        "default_enabled": False,
        "explicit_enable_required": True,
        "execution_target": "selected-guest-domain",
        "host_passthrough_allowed": False,
        "argument_vector_boundary_required": True,
        "programming_languages": [
            "python3",
            "c",
            "c++",
            "assembly",
            "rust",
            "go",
        ],
        "analysis_tools": ["ghidra-headless"],
        "analysis_input_executed": False,
        "resource_limits": {
            "open_files": {
                "programming_routes": 128,
                "ghidra_headless_route": 1024,
                "inherited_by_child": True,
            },
            "ghidra_headless_route": {
                "maximum_heap_mib": 2048,
                "inner_wall_timeout_seconds": 600,
                "inner_termination_grace_seconds": 30,
                "outer_broker_timeout_seconds": 660,
                "online_vcpu_range": [1, 8],
                "cpu_seconds_per_online_vcpu": 670,
                "cpu_limit_inherited_by_child": True,
            },
        },
        "ghidra_success_contract": {
            "zero_exit_status_required": True,
            "zero_exit_status_sufficient": False,
            "semantic_marker": "LOVELACE_NOXFRAME_GHIDRA_SEMANTIC_PASS",
            "semantic_marker_required_exactly_once": True,
            "completion_marker": "noxframe-ghidra-headless:ok",
            "semantic_marker_precedes_completion_marker": True,
        },
        "output_policy": {
            "maximum_combined_output_bytes": 65536,
            "forwarded_byte_classes": [
                "tab-0x09",
                "line-feed-0x0a",
                "printable-ascii-0x20-0x7e",
            ],
            "other_bytes_rendered_as_lowercase_hex_escape": True,
            "terminal_control_sequences_forwarded": False,
            "printable_text_authenticated": False,
            "printable_prompt_spoofing_prevented": False,
        },
    }
    assert ghidra == {
        "acceptance_target": "headless",
        "entry_point": "analyzeHeadless",
        "runtime": "openjdk21",
        "default_network_mode": "none",
        "graphical_operation_claimed": False,
        "containment_boundary": False,
    }
    assert profile["non_claims"] == [
        "No production readiness",
        "No release authority",
        "No certification or independent security evaluation",
        "No perfect isolation or escape-proof execution",
        "No guarantee that malicious code is safe to execute",
        "No hostile-code isolation from TCG",
        (
            "No hostile-cell isolation claim while KVM and outer-bwrap "
            "runtime evidence is NOT_MEASURED"
        ),
        "No outer-bwrap namespace claim from package presence alone",
        (
            "No containment or arbitrary-malware safety from read-only "
            "payload ingress"
        ),
        "No containment from NOXFRAME metadata or Ghidra",
        (
            "No confidentiality guarantee against side channels or "
            "virtualization defects"
        ),
    ]


def test_schema_rejects_security_boundary_regressions() -> None:
    profile = load_json(PROFILE_PATH)
    schema = load_json(SCHEMA_PATH)
    mutations: list[dict[str, Any]] = []

    changed = copy.deepcopy(profile)
    changed["default_profile"] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["authoritative_for_release"] = True
    mutations.append(changed)
    for field, invalid in (
        ("role", "Certified production malware sandbox"),
        ("allowed_component_classes", ["release-authority"]),
        ("forbidden_component_classes", ["none"]),
        ("invariants", ["Arbitrary malware is safe to execute"]),
        ("disqualifying_conditions", ["none"]),
        ("notes", ["Production ready"]),
    ):
        changed = copy.deepcopy(profile)
        changed[field] = invalid
        mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["storage"]["default_mode"] = "persistent"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["storage"]["modes"]["persistent"]["destructive_lifecycle"][
        "recursive_deletion_allowed"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["network"]["default_mode"] = "internet"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["execution_classes"]["defensive_untrusted_system_code"][
        "software_emulation_fallback"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["execution_classes"]["defensive_untrusted_system_code"][
        "network_mode"
    ] = "internet"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["execution_classes"]["defensive_untrusted_system_code"][
        "guest_privilege_assumption"
    ] = "trusted-unprivileged-user"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["functional"]["hostile_code_allowed"] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["functional"]["cpu_model"] = "max"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["required_host_gates"].remove(
        "outer-bwrap-namespace"
    )
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"][
        "manifest_status_source"
    ] = "manifest.status"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"][
        "guest_privilege_assumption"
    ] = "trusted-unprivileged-user"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["claim_condition"] = (
        "always allowed"
    )
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "artifact_bound_runtime_evidence_status_source"
    ] = "manifest.validation.hostile_kvm_cell"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "artifact_bound_runtime_evidence_source"
    ] = "manifest.validation_evidence.hostile_kvm_cell"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "runtime_capability_claimed_without_valid_gate"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "canonical_runtime_test"
    ]["make_target"] = "wucios-lovelace-hostile-smoke"
    mutations.append(changed)
    for field, invalid in (
        ("path", "wucios/fixtures/lovelace/unbound.txt"),
        ("size", 45),
        ("sha256", "0" * 64),
        ("classification", "unbounded-hostile-sample"),
    ):
        changed = copy.deepcopy(profile)
        changed["virtualization"]["defensive_cell"]["payload_ingress"][
            "canonical_runtime_test"
        ]["fixture"][field] = invalid
        mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "host_source_executed"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "guest_attachment"
    ] = "writable-host-share"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "required_controls"
    ].remove("exact-trusted-debugfs-semantic-readback")
    mutations.append(changed)
    for field, invalid in (
        ("media_readback_path", "/usr/bin/debugfs"),
        ("media_readback_version", "1.47.1"),
        ("semantic_readback_required", False),
        ("payload_readback_path", "/wrong-payload.bin"),
        ("payload_exact_bytes_readback_required", False),
        ("manifest_readback_path", "/wrong-manifest.json"),
        ("manifest_exact_bytes_readback_required", False),
    ):
        changed = copy.deepcopy(profile)
        changed["virtualization"]["defensive_cell"]["payload_ingress"][
            field
        ] = invalid
        mutations.append(changed)
    changed = copy.deepcopy(profile)
    del changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "semantic_readback_required"
    ]
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["payload_ingress"][
        "unexpected_readback_override"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["canonical_outputs"][1][
        "isolation_claim"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["canonical_outputs"][-1][
        "isolation_claim"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][0][
        "missing_status"
    ] = "PASS"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][0][
        "measured_status"
    ] = "locally-validated"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][0][
        "claim_allowed_when"
    ]["exact_artifact_binding_validated"] = False
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][-1][
        "measured_status"
    ] = "locally-validated"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][-1][
        "claim_allowed_when"
    ]["fixed_benign_fixture_identity_validated"] = False
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][-1][
        "required_layers"
    ].remove("guest-read-only-mount-and-write-rejection")
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["evidence_contract"]["claim_gates"][-1][
        "required_layers"
    ].remove("qemu-sandbox-enabled")
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["virtualization"]["defensive_cell"]["qemu_configuration"][
        "host_filesystem_share"
    ] = "present"
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["noxframe"]["ambient_host_execution_allowed"] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["noxframe"]["guest_broker"]["analysis_input_executed"] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["noxframe"]["guest_broker"]["resource_limits"]["open_files"][
        "ghidra_headless_route"
    ] = 128
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["noxframe"]["guest_broker"]["resource_limits"][
        "ghidra_headless_route"
    ]["cpu_seconds_per_online_vcpu"] = 620
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["noxframe"]["guest_broker"]["ghidra_success_contract"][
        "zero_exit_status_sufficient"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["noxframe"]["guest_broker"]["output_policy"][
        "printable_prompt_spoofing_prevented"
    ] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["ghidra"]["containment_boundary"] = True
    mutations.append(changed)
    changed = copy.deepcopy(profile)
    changed["non_claims"].remove(
        "No guarantee that malicious code is safe to execute"
    )
    mutations.append(changed)

    for changed in mutations:
        assert_rejected(changed, schema)


TESTS = [
    test_profile_matches_strict_schema,
    test_profile_is_separate_and_non_authoritative,
    test_evidence_contract_matches_builder_outputs_and_claim_gate,
    test_capability_claims_map_to_exact_functional_evidence,
    test_hostile_profile_layers_match_supervisor_controls,
    test_storage_and_network_fail_closed_by_default,
    test_hostile_cell_is_kvm_only_and_has_no_ambient_bridges,
    test_payload_ingress_contract_is_bounded_and_artifact_gated,
    test_make_targets_bind_overlay_lifecycle_and_payload_parameters,
    test_wucios_validator_enforces_payload_artifact_gate_contract,
    test_noxframe_and_ghidra_do_not_acquire_containment_authority,
    test_schema_rejects_security_boundary_regressions,
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    for test in TESTS:
        test()
        if not args.quiet:
            print(f"PASS {test.__name__}")
    if not args.quiet:
        print(f"PASS {len(TESTS)} Lovelace profile tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
