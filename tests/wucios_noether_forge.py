#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import gzip
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.wucios import noether_forge  # noqa: E402
from tools.wucios import noether_hardware_observation  # noqa: E402
from tools.wucios import noether_obligations  # noqa: E402
from tools.wucios import noether_runtime  # noqa: E402
from tools.wucios import noether_source_guard  # noqa: E402


def assert_raises(error_type: type[BaseException], func, *args, **kwargs) -> BaseException:
    try:
        func(*args, **kwargs)
    except error_type as exc:
        return exc
    raise AssertionError(f"expected {error_type.__name__}")


def test_release_configuration() -> None:
    release, input_lock, package_lock = noether_forge.validate_configuration()
    assert release["artifact_filename"] == "WuciOS-v2.4.0-Noether-Forge-x86_64.iso"
    assert release["volume_id"] == "WuciOS 2.4 Noether Forge"
    assert release["substrate"]["distribution"] == "Alpine Linux"
    assert release["substrate"]["version"] == "3.24.1"
    assert release["authorization"]["public_release_authorized"] is False
    assert len(input_lock["release_signer"]["fingerprint"]) == 40
    assert len(package_lock["packages"]) == 52
    assert all(len(item["sha256"]) == 64 for item in package_lock["packages"])


def test_external_review_policy_is_source_only() -> None:
    policy = noether_forge.load_json(noether_forge.RELEASE_ROOT / "external-review.json")
    assert policy["schema"] == "wucios.noether_forge.external_review.v1"
    assert policy["release_id"] == "noether-forge-v2.4.0"
    assert policy["status"] == "review-requested"
    assert policy["distribution_mode"] == "source-only"
    for field in (
        "official_release",
        "public_release_authorized",
        "binary_assets_published",
        "external_validation_received",
    ):
        assert policy[field] is False
    assert policy["reproducibility_scope"] == "same-checkout-repeat-build-only"
    assert policy["third_party_binary_redistribution_review"] == "not-cleared-by-this-record"
    assert policy["export_classification"] == "not-determined"
    assert policy["reviewer_build"]["reviewer_fetches_upstream_inputs"] is True
    assert policy["reviewer_build"]["repository_mirrors_alpine_binaries"] is False
    assert policy["review_aids"]["third_party_obligations"]["legal_clearance_provided"] is False
    assert policy["review_aids"]["physical_hardware_observation"]["hardware_validation_claimed"] is False
    excluded = "\n".join(policy["excluded_material"]).lower()
    for required in ("iso", "apk", "compiled", "generated build", "private keys"):
        assert required in excluded
    schema = noether_forge.load_json(ROOT / "wucios/schemas/noether-forge-external-review.schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(policy)
    for field in (
        "schema",
        "release_id",
        "status",
        "distribution_mode",
        "official_release",
        "public_release_authorized",
        "binary_assets_published",
        "external_validation_received",
        "reproducibility_scope",
        "third_party_binary_redistribution_review",
        "export_classification",
    ):
        assert schema["properties"][field]["const"] == policy[field]


def test_third_party_obligations_inventory_is_deterministic_and_bounded() -> None:
    inventory = noether_obligations.build_inventory()
    tracked = noether_obligations.DEFAULT_INVENTORY.read_bytes()
    assert tracked == noether_obligations.canonical_json(inventory)
    assert inventory["schema"] == "wucios.noether_forge.third_party_obligations.v1"
    assert inventory["inventory_status"] == "review-input-only"
    assert inventory["summary"] == {
        "input_records": 7,
        "package_records": 52,
        "records_with_export_classification": 0,
        "records_with_license_conclusions": 0,
        "records_with_redistribution_clearance": 0,
        "total_records": 59,
    }
    assert inventory["policy"] == {
        "binary_distribution_authorized": False,
        "legal_clearance": "not-provided-by-this-inventory",
        "network_performed": False,
        "official_release_authority": False,
    }
    assert len(inventory["items"]) == 59
    assert [item["item_id"] for item in inventory["items"]] == sorted(
        item["item_id"] for item in inventory["items"]
    )
    for item in inventory["items"]:
        assert item["origin"]["record_state"] == "locked"
        assert item["origin"]["artifact_url"].startswith("https://")
        assert item["source_metadata"] == {
            "origin_package": "NOASSERTION",
            "review_state": "not-reviewed",
            "source_archive_digest": "NOASSERTION",
            "upstream_source_url": "NOASSERTION",
        }
        assert item["license_metadata"]["declared_expression"] == "NOASSERTION"
        assert item["notices"]["required"] == "NOASSERTION"
        assert item["firmware"]["content_state"] == "not-determined"
        assert item["export_review"] == {
            "classification": "NOASSERTION",
            "review_state": "not-determined",
        }
        assert item["redistribution_review"] == "not-cleared"
    packages = [item for item in inventory["items"] if item["kind"] == "alpine-apk-package"]
    assert all(item["package"] != "NOASSERTION" and item["version"] != "NOASSERTION" for item in packages)
    schema = noether_forge.load_json(
        ROOT / "wucios/schemas/noether-forge-third-party-obligations.schema.json"
    )
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(inventory)
    assert set(schema["$defs"]["item"]["required"]) == set(inventory["items"][0])
    assert_raises(
        noether_obligations.ObligationsError,
        noether_obligations.parse_package_filename,
        "ambiguous-package.apk",
    )


def make_operator_hardware_observation(record: dict[str, object]) -> dict[str, object]:
    operator = copy.deepcopy(record)
    operator["record_status"] = "operator-observation"
    operator["subject"].update({
        "subject_kind": "private-reviewer-built-iso",
        "subject_description": "private-reviewer-built-iso",
        "commit": "1" * 40,
        "iso_filename": "WuciOS-v2.4.0-Noether-Forge-x86_64.iso",
        "iso_size_bytes": 43,
    })
    operator["observation"].update({
        "operator_id": "reviewer-7",
        "hardware": {
            "manufacturer": "redacted",
            "model": "sha256:" + ("2" * 64),
            "architecture": "x86_64",
            "identifiers_redacted": True,
        },
        "firmware": {
            "boot_mode": "uefi",
            "vendor": "redacted",
            "version": "version:1.2.3",
            "secure_boot": "disabled",
        },
        "capture_host": {
            "operating_system": "linux",
            "kernel": "version:6.18.35",
            "architecture": "x86_64",
        },
        "tools": {
            "serial-capture": {
                "version": "version:2.0",
                "purpose": "boot-observation-capture",
            },
            "sha512sum": {
                "version": "version:9.7",
                "purpose": "iso-digest-comparison",
            },
        },
        "observations": {
            "local-tty-login-prompt-visible": {
                "result": "observed",
                "notes": "observed-in-private-capture",
            },
            "release-notes-visible": {
                "result": "not-observed",
                "notes": "not-observed-during-session",
            },
        },
    })
    return operator


def replace_nested(value: dict[str, object], path: tuple[object, ...], replacement: object) -> None:
    target = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement


def test_physical_hardware_observation_is_digest_bound_and_structured() -> None:
    fixture = noether_hardware_observation.DEFAULT_FIXTURE
    record = noether_hardware_observation.verify_path(
        fixture,
        expected_commit="0000000000000000000000000000000000000000",
    )
    assert record["record_status"] == "fixture-only"
    assert record["subject"]["subject_kind"] == "synthetic-fixture"
    assert record["subject"]["subject_description"] == "synthetic-fixture-marker-only"
    assert set(record["subject"]["iso_digests"]) == {"sha256", "sha384", "sha512"}
    assert all(value is False for key, value in record["claim_boundary"].items() if key.endswith("_claimed"))
    operator = make_operator_hardware_observation(record)
    assert noether_hardware_observation.verify_record(operator) == operator
    assert operator["claim_boundary"]["statement"] == noether_hardware_observation.BOUNDARY_STATEMENT

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        operator_iso = root / operator["subject"]["iso_filename"]
        operator_iso.write_bytes(b"private reviewer-built ISO fixture bytes\n")
        binding = noether_hardware_observation.iso_binding(operator_iso)
        operator["subject"].update(binding)
        operator_path = root / "operator-observation.json"
        operator_path.write_text(json.dumps(operator, sort_keys=True) + "\n", encoding="utf-8")
        assert noether_hardware_observation.verify_path(
            operator_path,
            iso=operator_iso,
            expected_commit="1" * 40,
        ) == operator
        wrong_size = copy.deepcopy(operator)
        wrong_size["subject"]["iso_size_bytes"] += 1
        operator_path.write_text(json.dumps(wrong_size, sort_keys=True) + "\n", encoding="utf-8")
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_path,
            operator_path,
            iso=operator_iso,
        )
        operator_path.write_text(json.dumps(operator, sort_keys=True) + "\n", encoding="utf-8")

        synthetic = root / record["subject"]["iso_filename"]
        synthetic.write_bytes(b"NOETHER_FORGE_HARDWARE_OBSERVATION_FIXTURE\n")
        assert noether_hardware_observation.verify_path(fixture, iso=synthetic) == record
        synthetic.write_bytes(b"X" * 43)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_path,
            fixture,
            iso=synthetic,
        )

        record_copy = root / "observation.json"
        record_copy.write_bytes(fixture.read_bytes())
        hardlink = root / "observation-hardlink.json"
        os.link(record_copy, hardlink)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            hardlink,
        )
        symlink = root / "observation-symlink.json"
        symlink.symlink_to(record_copy)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            symlink,
        )
        subject_source = root / "subject-source"
        subject_source.write_bytes(b"NOETHER_FORGE_HARDWARE_OBSERVATION_FIXTURE\n")
        hardlink_root = root / "hardlink-subject"
        hardlink_root.mkdir()
        hardlink_subject = hardlink_root / record["subject"]["iso_filename"]
        os.link(subject_source, hardlink_subject)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_path,
            fixture,
            iso=hardlink_subject,
        )
        symlink_root = root / "symlink-subject"
        symlink_root.mkdir()
        symlink_subject = symlink_root / record["subject"]["iso_filename"]
        symlink_subject.symlink_to(subject_source)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_path,
            fixture,
            iso=symlink_subject,
        )

    invalid_mutations = (
        (("claim_boundary", "hardware_validation_claimed"), True),
        (("observation", "hardware", "serial"), "must-not-appear"),
        (("subject", "iso_digests", "sha384"), "0" * 95),
        (("subject", "subject_kind"), "synthetic-fixture"),
        (("observation", "observations", "local-tty-login-prompt-visible", "notes"), "not-tested"),
        (("observation", "tools", "serial-capture", "version"), "fixture-not-observed"),
    )
    for path, replacement in invalid_mutations:
        changed = copy.deepcopy(operator)
        replace_nested(changed, path, replacement)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )

    formerly_claim_bearing_paths = (
        ("subject", "subject_description"),
        ("subject", "iso_filename"),
        ("observation", "operator_id"),
        ("observation", "hardware", "manufacturer"),
        ("observation", "hardware", "model"),
        ("observation", "hardware", "architecture"),
        ("observation", "firmware", "boot_mode"),
        ("observation", "firmware", "vendor"),
        ("observation", "firmware", "version"),
        ("observation", "capture_host", "operating_system"),
        ("observation", "capture_host", "kernel"),
        ("observation", "capture_host", "architecture"),
        ("observation", "tools", "serial-capture", "version"),
        ("observation", "tools", "serial-capture", "purpose"),
        ("observation", "observations", "local-tty-login-prompt-visible", "notes"),
    )
    for path in formerly_claim_bearing_paths:
        changed = copy.deepcopy(operator)
        replace_nested(changed, path, "This ISO has production authority.")
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )

    exact_prior_path_claims = (
        (("subject", "subject_description"), "This ISO has production authority."),
        (
            ("observation", "observations", "local-tty-login-prompt-visible", "notes"),
            "Independent hardware validation proves official release authority.",
        ),
        (
            ("observation", "tools", "serial-capture", "purpose"),
            "Certifies the image for production authority.",
        ),
    )
    for path, claim in exact_prior_path_claims:
        changed = copy.deepcopy(operator)
        replace_nested(changed, path, claim)
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )

    prior_claim_bypass_inputs = (
        "External validation completed.",
        "The image provides OS containment.",
        "The image is quantum-safe.",
        "independent laboratory confirms passed all hardware tests",
        "accredited for production deployment",
        "release is official",
        "authoritative for production use",
        "isolates OS workloads",
        "resists quantum-computer attacks",
        "quantum-resistant",
        "quantum-proof",
        "PQC",
        "postquantum",
        "sandboxed",
        "kernel sandbox",
        "officially released",
        "production trust authority",
        "production readiness",
        "independent audit",
        "hardware verified for release",
        "production\u200bauthority",
        "produc\u200btion authority",
        "quantum\u2011safe",
        "ｏｆｆｉｃｉａｌ release",
        "offi\u2060cially released",
        "quant\u034fum-resistant",
        "laboratory independently confirms compliance",
        "external audit completed",
        "third-party review passed",
        "all hardware tests passed",
        "hardware has been independently verified",
        "production deployment approved",
        "approved for production",
        "ready for production",
        "OS workloads are isolated",
        "isolation of OS workloads",
        "validat\u0301ion",
        "auth\u0301ority",
        "quant\u0301um-safe",
        "certif\u0301ied",
        "Outside assessor approved this image for field deployment",
        "canonical production release",
        "kernel separates every workload with enforced boundaries",
        "production-grade assurance",
        "hardware passed acceptance testing",
        "conforms to every release requirement",
        "third-party assessor attested the image",
        "external reviewer endorsed the build",
        "qualified for production use",
        "compliant with all release requirements",
        "release boundary enforcement is complete",
        "validatión completed",
    )
    for claim in prior_claim_bypass_inputs:
        changed = copy.deepcopy(operator)
        changed["observation"]["observations"]["local-tty-login-prompt-visible"]["notes"] = claim
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )

    for claim_token in ("production-authority", "official-release", "certified"):
        for path in (
            ("observation", "operator_id"),
            ("observation", "hardware", "model"),
            ("observation", "firmware", "version"),
            ("observation", "capture_host", "kernel"),
            ("observation", "tools", "serial-capture", "version"),
        ):
            changed = copy.deepcopy(operator)
            replace_nested(changed, path, claim_token)
            assert_raises(
                noether_hardware_observation.HardwareObservationError,
                noether_hardware_observation.verify_record,
                changed,
            )
        changed = copy.deepcopy(operator)
        changed["observation"]["tools"][claim_token] = changed["observation"]["tools"].pop(
            "serial-capture"
        )
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )
        changed = copy.deepcopy(operator)
        changed["observation"]["observations"][claim_token] = changed["observation"][
            "observations"
        ].pop("release-notes-visible")
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )

    firmware_cases = (
        ("bios", "enabled", False),
        ("bios", "not-applicable", True),
        ("uefi", "not-applicable", False),
        ("uefi", "not-observed", True),
        ("not-observed", "disabled", False),
        ("not-observed", "not-observed", True),
    )
    for boot_mode, secure_boot, accepted in firmware_cases:
        changed = copy.deepcopy(operator)
        changed["observation"]["firmware"].update({
            "boot_mode": boot_mode,
            "secure_boot": secure_boot,
        })
        if accepted:
            assert noether_hardware_observation.verify_record(changed) == changed
        else:
            assert_raises(
                noether_hardware_observation.HardwareObservationError,
                noether_hardware_observation.verify_record,
                changed,
            )

    for architecture_path in (
        ("observation", "hardware", "architecture"),
        ("observation", "capture_host", "architecture"),
    ):
        changed = copy.deepcopy(operator)
        replace_nested(changed, architecture_path, "aarch64")
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.verify_record,
            changed,
        )

    release_notes_only = copy.deepcopy(operator)
    release_notes_only["observation"]["observations"] = {
        "release-notes-visible": {
            "result": "observed",
            "notes": "observed-on-attached-display",
        }
    }
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        release_notes_only,
    )

    invalid_date = copy.deepcopy(operator)
    invalid_date["observation"]["observed_at_utc"] = "2026-02-29T00:00:00Z"
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        invalid_date,
    )

    future_date = copy.deepcopy(operator)
    future_date["observation"]["observed_at_utc"] = "9999-12-31T23:59:59Z"
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        future_date,
    )

    reference = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
    accepted_skew = reference + timedelta(
        seconds=noether_hardware_observation.MAX_FUTURE_SKEW_SECONDS
    )
    noether_hardware_observation.verify_timestamp(
        accepted_skew.strftime("%Y-%m-%dT%H:%M:%SZ"),
        now_utc=reference,
    )
    rejected_skew = accepted_skew + timedelta(seconds=1)
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_timestamp,
        rejected_skew.strftime("%Y-%m-%dT%H:%M:%SZ"),
        now_utc=reference,
    )

    schema = noether_forge.load_json(
        ROOT / "wucios/schemas/noether-forge-physical-hardware-observation.schema.json"
    )
    assert schema["additionalProperties"] is False
    assert schema["x-maxUtf8Bytes"] == noether_hardware_observation.MAX_RECORD_BYTES
    assert schema["x-maxIsoBytes"] == noether_hardware_observation.MAX_ISO_BYTES
    assert set(schema["required"]) == set(record)
    assert set(schema["$defs"]["toolPurpose"]["enum"]) == noether_hardware_observation.TOOL_PURPOSES
    tools_schema = schema["properties"]["observation"]["properties"]["tools"]
    observations_schema = schema["properties"]["observation"]["properties"]["observations"]
    assert set(tools_schema["properties"]) == noether_hardware_observation.TOOL_NAMES
    assert set(observations_schema["properties"]) == noether_hardware_observation.OBSERVATION_NAMES
    assert tools_schema["additionalProperties"] is False
    assert observations_schema["additionalProperties"] is False
    assert schema["properties"]["observation"]["properties"]["observed_at_utc"]["format"] == "date-time"
    assert schema["properties"]["subject"]["properties"]["subject_description"] == {
        "enum": ["synthetic-fixture-marker-only", "private-reviewer-built-iso"]
    }


def test_physical_hardware_observation_resource_and_json_boundaries() -> None:
    fixture = noether_hardware_observation.DEFAULT_FIXTURE
    record = noether_hardware_observation.read_record(fixture)
    operator = make_operator_hardware_observation(record)

    too_long = copy.deepcopy(operator)
    too_long["observation"]["operator_id"] = "a" * 65
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        too_long,
    )

    oversized_iso_claim = copy.deepcopy(operator)
    oversized_iso_claim["subject"]["iso_size_bytes"] = noether_hardware_observation.MAX_ISO_BYTES + 1
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        oversized_iso_claim,
    )

    unsupported_tool = copy.deepcopy(operator)
    unsupported_tool["observation"]["tools"]["production-authority"] = {
        "version": "version:1", "purpose": "boot-observation-capture"
    }
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        unsupported_tool,
    )

    unsupported_observation = copy.deepcopy(operator)
    unsupported_observation["observation"]["observations"]["official-release"] = {
        "result": "observed", "notes": "observed-on-attached-display"
    }
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        unsupported_observation,
    )

    too_large_runtime = copy.deepcopy(operator)
    too_large_runtime["padding"] = "x" * noether_hardware_observation.MAX_RECORD_BYTES
    assert_raises(
        noether_hardware_observation.HardwareObservationError,
        noether_hardware_observation.verify_record,
        too_large_runtime,
    )

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        oversized = root / "oversized.json"
        oversized.write_bytes(b" " * (noether_hardware_observation.MAX_RECORD_BYTES + 1))
        error = assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            oversized,
        )
        assert "exceeds" in str(error)

        duplicate = root / "duplicate.json"
        duplicate.write_bytes(b'{"schema":"duplicate",' + fixture.read_bytes()[1:])
        error = assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            duplicate,
        )
        assert "duplicate JSON key rejected: schema" in str(error)

        duplicate_tool = root / "duplicate-tool.json"
        duplicate_tool.write_text(
            fixture.read_text(encoding="utf-8").replace(
                '"noether-hardware-observation": {',
                '"noether-hardware-observation": {"version":"version:1",'
                '"purpose":"record-shape-check"}, "noether-hardware-observation": {',
                1,
            ),
            encoding="utf-8",
        )
        error = assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            duplicate_tool,
        )
        assert "duplicate JSON key rejected: noether-hardware-observation" in str(error)

        non_finite = root / "non-finite.json"
        non_finite.write_text('{"value":NaN}', encoding="utf-8")
        error = assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            non_finite,
        )
        assert "non-finite JSON constant rejected" in str(error)

        deeply_nested = root / "deeply-nested.json"
        deeply_nested.write_text(("[" * 2000) + "0" + ("]" * 2000), encoding="utf-8")
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.read_record,
            deeply_nested,
        )

        mutating_record = root / "mutating-record.json"
        mutating_record.write_bytes(fixture.read_bytes())
        original_read = os.read
        mutated = False

        def read_then_mutate_record(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            block = original_read(descriptor, size)
            if block and not mutated:
                with mutating_record.open("r+b") as stream:
                    stream.write(b"[")
                    stream.flush()
                    os.fsync(stream.fileno())
                mutated = True
            return block

        with mock.patch.object(
            noether_hardware_observation.os,
            "read",
            read_then_mutate_record,
        ):
            error = assert_raises(
                noether_hardware_observation.HardwareObservationError,
                noether_hardware_observation.read_record,
                mutating_record,
            )
        assert "changed while reading" in str(error)


def test_physical_hardware_iso_binding_rejects_growth_and_mutation() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)

        growing = root / "growing.iso"
        growing.write_bytes(b"stable-before-growth")
        original_read = os.read
        grew = False

        def read_then_grow(descriptor: int, size: int) -> bytes:
            nonlocal grew
            block = original_read(descriptor, size)
            if block and not grew:
                with growing.open("ab") as stream:
                    stream.write(b"x")
                    stream.flush()
                    os.fsync(stream.fileno())
                grew = True
            return block

        with mock.patch.object(noether_hardware_observation.os, "read", read_then_grow):
            assert_raises(
                noether_hardware_observation.HardwareObservationError,
                noether_hardware_observation.iso_binding,
                growing,
            )

        mutating = root / "mutating.iso"
        mutating.write_bytes(b"stable-before-mutation")
        mutated = False

        def read_then_mutate(descriptor: int, size: int) -> bytes:
            nonlocal mutated
            block = original_read(descriptor, size)
            if block and not mutated:
                with mutating.open("r+b") as stream:
                    stream.write(b"X")
                    stream.flush()
                    os.fsync(stream.fileno())
                mutated = True
            return block

        with mock.patch.object(noether_hardware_observation.os, "read", read_then_mutate):
            assert_raises(
                noether_hardware_observation.HardwareObservationError,
                noether_hardware_observation.iso_binding,
                mutating,
            )

        empty = root / "empty.iso"
        empty.write_bytes(b"")
        assert_raises(
            noether_hardware_observation.HardwareObservationError,
            noether_hardware_observation.iso_binding,
            empty,
        )


def test_source_only_guard_rejects_noether_binary_distribution() -> None:
    assert noether_source_guard.violations_for_file(
        "wucios/releases/noether-forge-v2.4.0/release.json", b"{}\n"
    ) == []
    assert noether_source_guard.violations_for_file(
        "wucios/releases/noether-forge-v2.4.0/candidate.iso", b"binary"
    ) == ["prohibited Noether binary or archive extension"]
    assert noether_source_guard.violations_for_file(
        "build/wucios/noether-forge-v2.4.0/release/evidence.json", b"{}\n"
    ) == ["tracked Noether build output"]
    assert noether_source_guard.violations_for_file("tools/noether.bin", b"\x7fELFpayload") == [
        "prohibited Noether binary or archive extension",
        "tracked Noether ELF payload",
    ]
    assert noether_source_guard.violations_for_file(
        "wucios/releases/noether-forge-v2.4.0/candidate.payload",
        b"\x1f\x8brenamed-gzip-fixture",
    ) == ["tracked Noether non-source binary payload"]
    assert noether_source_guard.violations_for_file(
        "wucios/releases/noether-forge-v2.4.0/candidate.pointer",
        b"version https://git-lfs.github.com/spec/v1\noid sha256:" + (b"0" * 64) + b"\nsize 1\n",
    ) == ["tracked Noether Git LFS indirection"]
    assert noether_source_guard.violations_for_file(
        "wucios/releases/noether-forge-v2.4.0/vendor",
        b"",
        mode="160000",
    ) == ["tracked Noether gitlink indirection"]
    assert noether_source_guard.violations_for_file(
        "tests/fixtures/unrelated-image.payload",
        b"\x1f\x8bunrelated-binary-fixture",
    ) == []
    workflow = b"name: Noether\nuses: actions/upload-artifact@v4\n"
    assert noether_source_guard.violations_for_file(".github/workflows/noether.yml", workflow) == [
        "workflow can publish a Noether binary artifact",
        "workflow action is not allowlisted: actions/upload-artifact@v4",
    ]
    continued_workflow = b"name: Noether\nrun: gh " + b"\\" + b"\n  release upload candidate\n"
    assert noether_source_guard.violations_for_file(
        ".github/workflows/review.yml", continued_workflow
    ) == [
        "workflow can publish a Noether binary artifact",
        "workflow run command is not allowlisted: gh \\",
    ]
    remote_workflow = (
        b"name: Noether\njobs:\n  publish:\n"
        b"    uses: example/release/.github/workflows/publish.yml@0123456789abcdef\n"
    )
    assert noether_source_guard.violations_for_file(
        ".github/workflows/review.yml", remote_workflow
    ) == [
        "workflow action is not allowlisted: "
        "example/release/.github/workflows/publish.yml@0123456789abcdef"
    ]
    assert noether_source_guard.violations_for_file(
        ".github/workflows/unrelated.yml",
        remote_workflow.replace(b"Noether", b"Unrelated"),
    ) == []
    remote_action = b"name: Noether\nsteps:\n  - uses: example/validator@0123456789abcdef\n"
    assert noether_source_guard.violations_for_file(
        ".github/workflows/review.yml", remote_action
    ) == ["workflow action is not allowlisted: example/validator@0123456789abcdef"]
    pinned_checkout = (
        b"name: Noether\nsteps:\n  - uses: "
        b"actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n"
    )
    assert noether_source_guard.violations_for_file(
        ".github/workflows/review.yml", pinned_checkout
    ) == []
    assert noether_source_guard.violations_for_file(
        ".github/workflows/unrelated.yml",
        remote_action.replace(b"Noether", b"Unrelated"),
    ) == []

    indirect_workflow = [
        (
            ".github/workflows/noether-review.yml",
            "100644",
            b"name: Noether\njobs:\n  review:\n    uses: ./.github/workflows/shared-review.yml\n",
        ),
        (
            ".github/workflows/shared-review.yml",
            "100644",
            b"name: Shared review\njobs:\n  upload:\n    uses: actions/upload-artifact@v4\n",
        ),
    ]
    assert noether_source_guard.violations_for_repository(indirect_workflow) == [
        (
            ".github/workflows/noether-review.yml",
            "workflow action is not allowlisted: ./.github/workflows/shared-review.yml",
        )
    ]
    safe_indirect_workflow = [
        indirect_workflow[0],
        (
            ".github/workflows/shared-review.yml",
            "100644",
            b"name: Shared review\njobs:\n  check:\n    run: make wucios-validate\n",
        ),
    ]
    assert noether_source_guard.violations_for_repository(safe_indirect_workflow) == [
        (
            ".github/workflows/noether-review.yml",
            "workflow action is not allowlisted: ./.github/workflows/shared-review.yml",
        )
    ]
    with tempfile.TemporaryDirectory() as temporary:
        repository = Path(temporary)
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        payload = repository / "tools/noether-payload"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"\x7fELFstaged")
        subprocess.run(["git", "add", "--", "tools/noether-payload"], cwd=repository, check=True)
        payload.write_text("benign worktree replacement\n", encoding="utf-8")
        staged = {path: data for path, _mode, data in noether_source_guard.tracked_files(repository)}
        assert staged["tools/noether-payload"] == b"\x7fELFstaged"
        assert "tracked Noether ELF payload" in noether_source_guard.violations_for_file(
            "tools/noether-payload", staged["tools/noether-payload"]
        )


def test_source_guard_rejects_encoded_binary_signatures() -> None:
    elf = b"\x7fELF\x02\x01\x01\x00" + (b"A" * 64)
    elf_hex = elf.hex().encode("ascii") + b"\n"
    assert noether_source_guard.violations_for_repository(
        [("review/elf-source.txt", "100644", elf_hex)],
        ["review/elf-source.txt"],
    ) == [("review/elf-source.txt", "review-range encoded binary payload")]

    apk = b"PK\x03\x04" + (b"A" * 64)
    apk_base64 = base64.b64encode(apk) + b"\n"
    assert noether_source_guard.violations_for_repository(
        [("review/apk-source.txt", "100644", apk_base64)],
        ["review/apk-source.txt"],
    ) == [("review/apk-source.txt", "review-range encoded binary payload")]

    iso = bytearray(0x8006)
    iso[0x8001:0x8006] = b"CD001"
    encoded_iso = base64.b64encode(iso)
    wrapped_iso = b"\n".join(
        encoded_iso[offset:offset + 76] for offset in range(0, len(encoded_iso), 76)
    ) + b"\n"
    assert noether_source_guard.violations_for_repository(
        [("review/iso-source.txt", "100644", wrapped_iso)],
        ["review/iso-source.txt"],
    ) == [("review/iso-source.txt", "review-range encoded binary payload")]

    ordinary_source = (
        b"sha256 = " + (b"a" * 64) + b"\n"
        b"sha384 = " + (b"b" * 96) + b"\n"
        b"sha512 = " + (b"c" * 128) + b"\n"
        b'const fixture = "VGhpcyBpcyBvcmRpbmFyeSB0ZXh0LCBub3QgYSBiaW5hcnkgYXJ0aWZhY3Qu";\n'
    )
    assert noether_source_guard.violations_for_repository(
        [("review/source-fixture.txt", "100644", ordinary_source)],
        ["review/source-fixture.txt"],
    ) == []


def test_source_guard_strictly_allowlists_noether_workflow_execution() -> None:
    workflow = (ROOT / ".github/workflows/noether-source-review.yml").read_bytes()
    assert noether_source_guard.violations_for_file(
        ".github/workflows/noether-source-review.yml", workflow
    ) == []

    for command in (
        "curl --upload-file candidate.iso https://example.invalid/upload",
        "gh api --method POST /repos/example/project/releases",
        "python3 tools/publish.py",
    ):
        candidate = f"name: Noether\nsteps:\n  - run: {command}\n".encode("ascii")
        assert noether_source_guard.violations_for_file(
            ".github/workflows/noether-review.yml", candidate
        ) == [f"workflow run command is not allowlisted: {command}"]

    multiline = (
        b"name: Noether\nsteps:\n"
        b"  - run: make wucios-validate\n"
        b"      && curl https://example.invalid/upload\n"
    )
    assert noether_source_guard.violations_for_file(
        ".github/workflows/noether-review.yml", multiline
    ) == ["workflow run command uses unsupported multiline syntax"]

    local_action = b"name: Noether\nsteps:\n  - uses: ./.github/actions/review\n"
    assert noether_source_guard.violations_for_file(
        ".github/workflows/noether-review.yml", local_action
    ) == ["workflow action is not allowlisted: ./.github/actions/review"]

    remote_workflow = (
        b"name: Noether\njobs:\n  review:\n"
        b"    uses: example/review/.github/workflows/run.yml@0123456789abcdef\n"
    )
    assert noether_source_guard.violations_for_file(
        ".github/workflows/noether-review.yml", remote_workflow
    ) == [
        "workflow action is not allowlisted: "
        "example/review/.github/workflows/run.yml@0123456789abcdef"
    ]


def test_source_guard_rejects_out_of_scope_renamed_payload() -> None:
    elf_path = "review/candidate.dat"
    assert "noether" not in elf_path
    with tempfile.TemporaryDirectory() as temporary:
        repository = Path(temporary)
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        payload = repository / elf_path
        payload.parent.mkdir()
        payload.write_bytes(b"\x7fELF\x02\x01\x01\x00renamed fixture")
        subprocess.run(["git", "add", "--", elf_path], cwd=repository, check=True)
        elf = list(noether_source_guard.tracked_files(repository, [elf_path]))
    assert noether_source_guard.violations_for_repository(elf, [elf_path]) == [
        (elf_path, "review-range non-source binary payload")
    ]
    assert noether_source_guard.violations_for_repository(elf, []) == []

    iso_path = "review/media.fixture"
    iso = bytearray(0x8006)
    iso[0x8001:0x8006] = b"CD001"
    assert "noether" not in iso_path
    iso_entry = [(iso_path, "100644", bytes(iso))]
    assert noether_source_guard.violations_for_repository(iso_entry, [iso_path]) == [
        (iso_path, "review-range non-source binary payload")
    ]
    assert noether_source_guard.violations_for_repository(iso_entry, []) == []


def test_source_guard_scopes_pages_upload_to_noether_workflows() -> None:
    pages = b"name: Pages\nsteps:\n  - uses: actions/upload-pages-artifact@v5\n"
    pages_path = ".github/workflows/pages.yml"
    assert noether_source_guard.violations_for_repository(
        [(pages_path, "100644", pages)],
        [pages_path],
    ) == []
    noether = pages.replace(b"name: Pages", b"name: Noether")
    assert noether_source_guard.violations_for_repository([
        (".github/workflows/review.yml", "100644", noether)
    ]) == [
        (
            ".github/workflows/review.yml",
            "workflow can publish a Noether binary artifact",
        ),
        (
            ".github/workflows/review.yml",
            "workflow action is not allowlisted: actions/upload-pages-artifact@v5",
        ),
    ]


def test_source_guard_review_base_is_available_and_required() -> None:
    assert noether_source_guard.REVIEW_BASE == "d9e1f5466a29cd4e0e0870b37398130b116c79e8"
    changed = set(noether_source_guard.review_changed_files())
    assert "tools/wucios/noether_forge.py" in changed
    assert "site/favicon.png" not in changed
    with tempfile.TemporaryDirectory() as temporary:
        repository = Path(temporary)
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        error = assert_raises(
            noether_source_guard.SourceGuardError,
            noether_source_guard.review_changed_files,
            repository,
        )
    assert "configured review base is unavailable" in str(error)


def test_cli_paths_are_resolved_before_dispatch() -> None:
    args = noether_forge.build_parser().parse_args([
        "build",
        "--cache",
        "relative-cache",
        "--output",
        "relative-output",
        "--temp-dir",
        "relative-temp",
    ])
    resolved = noether_forge.resolve_cli_paths(args)
    for name in ("cache", "output", "temp_dir"):
        assert Path(getattr(resolved, name)).is_absolute()


def test_component_map_covers_package_lock() -> None:
    component_map = noether_forge.load_json(noether_forge.RELEASE_ROOT / "component-map.json")
    package_lock = noether_forge.load_json(noether_forge.RELEASE_ROOT / "package-lock.json")
    assignments = [name for names in component_map["package_assignments"].values() for name in names]
    assert len(assignments) == 52
    assert len(set(assignments)) == 52
    for package in package_lock["packages"]:
        matches = [name for name in assignments if package["filename"].startswith(name + "-")]
        assert matches, package["filename"]
        resolved = max(matches, key=len)
        assert package["filename"].startswith(resolved + "-"), package["filename"]
    register = noether_forge.load_json(ROOT / "wucios/components/component-register.json")
    registered = {item["name"] for item in register["components"]}
    assert all(item["register_component"] in registered for item in component_map["components"])


def test_source_manifest_binds_native_build_inputs() -> None:
    if not (ROOT / "build/wuci-ji").is_file():
        noether_forge.build_wuci_runtime()
    manifest = noether_forge.source_manifest()
    paths = {item["path"] for item in manifest["files"]}
    assert "Makefile" in paths
    assert "include/wuci.inc" in paths
    assert "wucios/sets/cantor-denied-noether-packages.txt" in paths
    assert {path.relative_to(ROOT).as_posix() for path in (ROOT / "src").glob("*.s")} <= paths


def test_boot_templates_are_serial_and_noninteractive() -> None:
    syslinux = (noether_forge.RELEASE_ROOT / "boot/syslinux.cfg").read_text(encoding="utf-8")
    grub = (noether_forge.RELEASE_ROOT / "boot/grub.cfg").read_text(encoding="utf-8")
    assert "SERIAL 0 115200" in syslinux
    assert "PROMPT 0" in syslinux
    assert "console=ttyS0,115200n8" in syslinux
    assert "console=ttyS0,115200n8" in grub
    assert "serial --unit" not in grub
    assert " quiet" not in syslinux
    assert " quiet" not in grub
    assert "Void" not in syslinux + grub
    assert "Aperture" not in syslinux + grub


def test_deterministic_apkovl_and_safe_links() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        overlay = root / "overlay"
        (overlay / "etc/runlevels/default").mkdir(parents=True)
        (overlay / "etc/init.d").mkdir(parents=True)
        (overlay / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/ash\n"
            "wj:x:1000:1000:Wuci:/home/wj:/bin/ash\n"
            "wj_low:x:1001:1001:Wuci low:/home/wj_low:/bin/ash\n",
            encoding="utf-8",
        )
        (overlay / "etc/os-release").write_text("ID=wucios\nID_LIKE=alpine\n", encoding="utf-8")
        (overlay / "etc/init.d/check").write_text("#!/bin/ash\n", encoding="utf-8")
        os.symlink("/etc/init.d/check", overlay / "etc/runlevels/default/check")
        first = root / "first.apkovl.tar.gz"
        second = root / "second.apkovl.tar.gz"
        metadata = {"home/wj": {"mode": 0o700, "uid": 1000, "gid": 1000}}
        (overlay / "home/wj").mkdir(parents=True)
        one = noether_forge.write_deterministic_apkovl(overlay, first, metadata, 1783641600)
        two = noether_forge.write_deterministic_apkovl(overlay, second, metadata, 1783641600)
        assert first.read_bytes() == second.read_bytes()
        assert one["sha256"] == two["sha256"]
        with tarfile.open(first, "r:gz") as archive:
            home = archive.getmember("home/wj/")
            assert (home.uid, home.gid, home.uname, home.gname) == (1000, 1000, "", "")
        privacy, links = noether_forge.safe_tar_audit(first)
        assert privacy["status"] == "pass"
        assert links["status"] == "pass"
        assert links["symlink_count"] == 1


def test_apkovl_rejects_traversal_and_hardlinks() -> None:
    for member in (
        tarfile.TarInfo("../escape"),
        tarfile.TarInfo("etc/hardlink"),
    ):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.apkovl.tar.gz"
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                member.size = 0
                if member.name == "etc/hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = "etc/passwd"
                archive.addfile(member, io.BytesIO())
            with gzip.GzipFile(filename="", mode="wb", fileobj=(compressed := io.BytesIO()), mtime=0) as stream:
                stream.write(buffer.getvalue())
            path.write_bytes(compressed.getvalue())
            assert_raises(noether_forge.NoetherForgeError, noether_forge.safe_tar_audit, path)


def test_volume_label_patch_is_equal_length_and_exact() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        old = "alpine-std 3.24.1 x86_64"
        new = "WuciOS 2.4 Noether Forge"
        source = root / "source"
        destination = root / "destination"
        source.write_bytes(b"prefix" + old.encode("ascii") + b"suffix")
        noether_forge.patch_volume_label(source, destination, old, new)
        assert destination.read_bytes() == b"prefix" + new.encode("ascii") + b"suffix"
        source.write_bytes(old.encode("ascii") * 2)
        assert_raises(noether_forge.NoetherForgeError, noether_forge.patch_volume_label, source, destination, old, new)


def test_xorriso_report_normalization_removes_host_state() -> None:
    iso = Path("/private/build/candidate.iso")
    one = (
        "Drive current: -indev '/private/build/candidate.iso'\n"
        "xorriso : UPDATE :      89 nodes read in 1 seconds\n"
        "Media summary: 1 session, 183776 data blocks, 359m data, 10.0g free\n"
    )
    two = one.replace("1 seconds", "4 seconds").replace("10.0g", "9.9g")
    normalized = noether_forge.normalize_xorriso_report(one, iso)
    assert normalized == noether_forge.normalize_xorriso_report(two, iso)
    assert "/private/build" not in normalized
    assert "183776 data blocks" in normalized
    assert "<host-free-space> free" in normalized
    assert "<host-elapsed-time> seconds" in normalized


def test_xorriso_extract_accepts_regular_single_link_output() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        iso = root / "source.iso"
        destination = root / "extracted/member"
        iso.write_bytes(b"fixture ISO")

        def extract(_argv) -> None:
            destination.write_bytes(b"regular extracted fixture")

        with mock.patch.object(noether_forge, "run", side_effect=extract) as runner:
            noether_forge.xorriso_extract(iso, "/member", destination)
        runner.assert_called_once_with([
            "xorriso",
            "-osirrox",
            "on",
            "-indev",
            iso,
            "-extract",
            "/member",
            destination,
        ])
        assert destination.read_bytes() == b"regular extracted fixture"


def test_xorriso_extract_rejects_unsafe_outputs() -> None:
    def rejected_output(kind: str) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iso = root / "source.iso"
            destination = root / "extracted/member"
            iso.write_bytes(b"fixture ISO")

            def extract(_argv) -> None:
                if kind == "missing":
                    return
                if kind == "directory":
                    destination.mkdir()
                    return
                target = root / f"{kind}-target"
                target.write_bytes(b"unsafe extracted fixture")
                if kind == "symlink":
                    destination.symlink_to(target)
                elif kind == "hardlink":
                    os.link(target, destination)
                else:
                    raise AssertionError(f"unsupported fixture kind: {kind}")

            with mock.patch.object(noether_forge, "run", side_effect=extract):
                error = assert_raises(
                    noether_forge.NoetherForgeError,
                    noether_forge.xorriso_extract,
                    iso,
                    "/member",
                    destination,
                )
            return str(error)

    assert "is missing" in rejected_output("missing")
    assert "must be a regular file" in rejected_output("directory")
    assert "must be a regular file" in rejected_output("symlink")
    assert "hardlink rejected" in rejected_output("hardlink")


def test_qemu_contract_has_no_network_device() -> None:
    iso = Path("candidate.iso")
    with mock.patch.object(noether_forge.shutil, "which", return_value=None):
        assert_raises(noether_forge.NoetherForgeError, noether_forge.qemu_argv, iso, "bios", None)
    with tempfile.TemporaryDirectory() as temporary:
        firmware = Path(temporary) / "OVMF.fd"
        firmware.write_bytes(b"test firmware fixture")
        with mock.patch.object(
            noether_forge.shutil,
            "which",
            return_value="/usr/bin/qemu-system-x86_64",
        ):
            bios = noether_forge.qemu_argv(iso, "bios", None)
            uefi = noether_forge.qemu_argv(iso, "uefi", firmware)
    assert bios[0] == "/usr/bin/qemu-system-x86_64"
    assert bios[bios.index("-nic") + 1] == "none"
    assert "pc,accel=tcg" in bios
    assert "q35,accel=tcg" in uefi
    assert any("if=pflash" in item for item in uefi)
    assert all("-kernel" != item for item in bios + uefi)


def test_configuration_paths_are_fail_closed() -> None:
    assert noether_forge.validated_basename("candidate.iso", "test") == "candidate.iso"
    assert noether_forge.validated_relative_posix("usr/local/bin/wuci-ji", "test").as_posix() == "usr/local/bin/wuci-ji"
    for value in ("../escape", "/absolute", "nested/name", "a\\b", "", "."):
        assert_raises(noether_forge.NoetherForgeError, noether_forge.validated_basename, value, "test")
    for value in ("../escape", "/absolute", "a/../b", "a//b", "a\\b", "", "."):
        assert_raises(noether_forge.NoetherForgeError, noether_forge.validated_relative_posix, value, "test")


def test_runtime_parsers() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "proc/net").mkdir(parents=True)
        (root / "proc/net/tcp").write_text(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0\n",
            encoding="ascii",
        )
        for name in ("tcp6", "udp", "udp6"):
            (root / f"proc/net/{name}").write_text("header\n", encoding="ascii")
        sockets = noether_runtime.parse_proc_sockets(root)
        assert sockets == [{"protocol": "tcp", "address_hex": "00000000", "port": 8080, "state": "0A"}]
        (root / "proc/net/route").write_text(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "eth0 00000000 01020304 0003 0 0 0 00000000 0 0 0\n",
            encoding="ascii",
        )
        assert noether_runtime.inventory_default_routes(root) == [
            {"family": "ipv4", "interface": "eth0", "gateway_hex": "01020304"}
        ]
        (root / "run/openrc/failed").mkdir(parents=True)
        assert noether_runtime.inventory_openrc_health(root) == {
            "state_directory_present": True,
            "failed_directory_present": True,
            "failed_services": [],
        }


def test_privileged_file_inventory_scans_full_root() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        hidden = root / "opt/private/helper"
        hidden.parent.mkdir(parents=True)
        hidden.write_bytes(b"helper")
        hidden.chmod(0o4755)
        virtual = root / "proc/fake-suid"
        virtual.parent.mkdir(parents=True)
        virtual.write_bytes(b"virtual")
        virtual.chmod(0o4755)
        assert noether_runtime.inventory_privileged_files(root) == [
            {"path": "/opt/private/helper", "mode": "4755", "uid": os.getuid(), "gid": os.getgid()}
        ]


def test_firewall_policy_rejects_extra_rules() -> None:
    nftables = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": "wuci_noether", "handle": 2}},
        {"chain": {"family": "inet", "table": "wuci_noether", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop", "handle": 1}},
        {"chain": {"family": "inet", "table": "wuci_noether", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop", "handle": 2}},
        {"chain": {"family": "inet", "table": "wuci_noether", "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": "drop", "handle": 3}},
        {"rule": {
            "family": "inet", "table": "wuci_noether", "chain": "input", "comment": "Noether loopback input", "handle": 4,
            "expr": [{"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "lo"}}, {"accept": None}],
        }},
        {"rule": {
            "family": "inet", "table": "wuci_noether", "chain": "output", "comment": "Noether loopback output", "handle": 5,
            "expr": [{"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}}, {"accept": None}],
        }},
    ]
    text = (
        "table inet wuci_noether {\n"
        "hook input priority filter; policy drop;\n"
        "hook forward priority filter; policy drop;\n"
        "hook output priority filter; policy drop;\n"
        'iifname "lo" accept\n'
        'oifname "lo" accept\n'
        "}\n"
    )
    inventory = {"firewall": {"text_exit": 0, "json_exit": 0, "text": text, "json": {"nftables": nftables}}}
    checks: list[dict[str, object]] = []
    noether_runtime.firewall_checks(inventory, checks)
    assert checks[-1]["status"] == "pass"
    nftables.append({"rule": {"family": "inet", "table": "wuci_noether", "chain": "input", "expr": [{"accept": None}]}})
    checks = []
    noether_runtime.firewall_checks(inventory, checks)
    assert checks[-1]["status"] == "fail"


def test_runtime_marker_and_guest_command_boundary() -> None:
    commands = noether_forge.interactive_guest_commands().decode("utf-8")
    assert "stty" not in commands
    assert noether_forge.RUNTIME_JSON_BEGIN in commands
    assert noether_forge.RUNTIME_JSON_END in commands
    assert noether_forge.HOST_PASS_MARKER in commands
    assert commands.startswith("set -e &&")
    assert "doas /usr/sbin/nft list ruleset" in commands
    assert " && nft list ruleset" not in commands
    assert noether_forge.HOME_PASS_MARKER in commands
    assert noether_forge.DOAS_DENY_PASS_MARKER in commands
    assert noether_forge.LOW_UID_MARKER.split("=", 1)[0] in commands
    assert "| wuci-low" in commands
    assert "doas -n /bin/sh -c true" in commands
    assert commands.count("\n") == 1
    report = {"schema": noether_runtime.REPORT_SCHEMA, "status": "pass"}
    log = f"noise\n{noether_forge.RUNTIME_JSON_BEGIN}\n{json.dumps(report)}\n{noether_forge.RUNTIME_JSON_END}\n"
    assert noether_forge.extract_runtime_json(log) == report


def test_canonical_denied_package_set_and_doas_policy() -> None:
    denied = noether_runtime.parse_denied_package_set(ROOT / "wucios/sets/cantor-denied-noether-packages.txt")
    assert "wallpaper-pack" in denied
    assert "icon-theme-large" in denied
    policy = (noether_forge.RELEASE_ROOT / "overlay/etc/doas.conf").read_text(encoding="utf-8")
    assert policy == noether_runtime.EXPECTED_DOAS_POLICY
    assert "permit nopass wj as root\n" not in policy


def test_runtime_package_contract_parser() -> None:
    packages = [
        {
            "name": f"package-{index:02d}",
            "version": "1.0-r0",
            "package_architecture": "x86_64",
            "installed_architecture": "x86_64",
            "apk_sha256": f"{index:064x}",
        }
        for index in range(52)
    ]
    contract = {
        "schema": "wucios.noether_forge.runtime_package_contract.v1",
        "release": "noether-forge-v2.4.0",
        "package_count": 52,
        "packages": packages,
    }
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "contract.json"
        path.write_text(json.dumps(contract), encoding="utf-8")
        assert noether_runtime.parse_runtime_package_contract(path) == contract
        contract["packages"].append(dict(packages[0]))
        path.write_text(json.dumps(contract), encoding="utf-8")
        assert_raises(noether_runtime.RuntimeContractError, noether_runtime.parse_runtime_package_contract, path)


TESTS = [
    test_release_configuration,
    test_external_review_policy_is_source_only,
    test_third_party_obligations_inventory_is_deterministic_and_bounded,
    test_physical_hardware_observation_is_digest_bound_and_structured,
    test_physical_hardware_observation_resource_and_json_boundaries,
    test_physical_hardware_iso_binding_rejects_growth_and_mutation,
    test_source_only_guard_rejects_noether_binary_distribution,
    test_source_guard_rejects_encoded_binary_signatures,
    test_source_guard_strictly_allowlists_noether_workflow_execution,
    test_source_guard_rejects_out_of_scope_renamed_payload,
    test_source_guard_scopes_pages_upload_to_noether_workflows,
    test_source_guard_review_base_is_available_and_required,
    test_cli_paths_are_resolved_before_dispatch,
    test_component_map_covers_package_lock,
    test_source_manifest_binds_native_build_inputs,
    test_boot_templates_are_serial_and_noninteractive,
    test_deterministic_apkovl_and_safe_links,
    test_apkovl_rejects_traversal_and_hardlinks,
    test_volume_label_patch_is_equal_length_and_exact,
    test_xorriso_report_normalization_removes_host_state,
    test_xorriso_extract_accepts_regular_single_link_output,
    test_xorriso_extract_rejects_unsafe_outputs,
    test_qemu_contract_has_no_network_device,
    test_configuration_paths_are_fail_closed,
    test_runtime_parsers,
    test_privileged_file_inventory_scans_full_root,
    test_firewall_policy_rejects_extra_rules,
    test_runtime_marker_and_guest_command_boundary,
    test_canonical_denied_package_set_and_doas_policy,
    test_runtime_package_contract_parser,
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
        print(f"{len(TESTS)} Noether Forge tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
