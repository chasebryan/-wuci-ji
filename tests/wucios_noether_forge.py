#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import gzip
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import stat
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


def newc_entry(
    name: str,
    data: bytes = b"",
    *,
    mode: int = stat.S_IFREG | 0o644,
    uid: int = 0,
    gid: int = 0,
    nlink: int = 1,
) -> bytes:
    encoded_name = name.encode("utf-8") + b"\0"
    fields = [1, mode, uid, gid, nlink, 0, len(data), 0, 0, 0, 0, len(encoded_name), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    name_part = header + encoded_name
    name_part += b"\0" * ((-len(name_part)) % 4)
    data_part = data + (b"\0" * ((-(len(name_part) + len(data))) % 4))
    return name_part + data_part


def newc_archive(*entries: bytes) -> bytes:
    trailer_fields = [0] * 13
    trailer_fields[11] = 11
    trailer = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in trailer_fields)
    trailer += b"TRAILER!!!\0"
    trailer += b"\0" * ((-len(trailer)) % 4)
    return b"".join(entries) + trailer


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
    assert input_lock["schema"] == "wucios.noether_forge.alpine_input_lock.v2"
    assert package_lock["schema"] == "wucios.noether_forge.package_lock.v2"
    assert len(noether_forge.cache_records(input_lock)) == 12
    cache_names = [item["filename"] for item in noether_forge.cache_records(input_lock)]
    assert "APKINDEX.tar.gz" not in cache_names
    assert sum(name.endswith(".apk") for name in cache_names) == 3
    assert package_lock["post_release_overlay"] == [item["filename"] for item in input_lock["post_release_overlay"]]
    patch_spec = noether_forge.load_initramfs_patch_spec(input_lock)
    assert patch_spec["license"] == "GPL-2.0-only"
    assert patch_spec["upstream"]["version"] == "3.14.0-r0"
    assert patch_spec["upstream"]["source_archive"]["instantiation"] == {
        "token": "@VERSION@",
        "value": "3.14.0-r0",
        "result_size": input_lock["bootstrap"]["patch"]["source_member_size"],
        "result_sha256": input_lock["bootstrap"]["patch"]["source_member_sha256"],
    }
    assert list(noether_forge.initramfs_replacements(patch_spec)) == [
        span["label"] for span in input_lock["bootstrap"]["patch"]["source_spans"]
    ]


def test_generated_spdx_package_purposes_use_official_json_enum() -> None:
    package_lock = {
        "packages": [{"filename": "fixture-1.0-r0.apk", "sha256": "1" * 64}],
        "repository_path": "apks/x86_64",
        "source_media": "fixture-source.iso",
    }
    source = {
        "files": [{"path": "Makefile", "sha256": "2" * 64}],
        "source_payload_sha256": "3" * 64,
    }
    package_info = {
        "pkgname": "fixture",
        "pkgver": "1.0-r0",
        "arch": "x86_64",
        "license": "MIT",
    }
    with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
        noether_forge,
        "apk_pkginfo",
        return_value=package_info,
    ):
        package_source = Path(temporary)
        first = noether_forge.generate_sbom(package_source, package_lock, source)
        second = noether_forge.generate_sbom(package_source, package_lock, source)

    assert noether_forge.canonical_json(first) == noether_forge.canonical_json(second)
    purposes = {
        package["primaryPackagePurpose"]
        for package in first["packages"]
        if "primaryPackagePurpose" in package
    }
    assert purposes == {"OPERATING_SYSTEM"}
    assert b"OPERATING-SYSTEM" not in noether_forge.canonical_json(first)

    for invalid_purpose in ("OPERATING-SYSTEM", "DEVICE-DRIVER"):
        invalid = copy.deepcopy(first)
        next(
            package for package in invalid["packages"] if "primaryPackagePurpose" in package
        )["primaryPackagePurpose"] = invalid_purpose
        assert_raises(
            noether_forge.NoetherForgeError,
            noether_forge.validate_spdx_sbom,
            invalid,
            package_lock,
            source,
        )


def test_exact_trust_locks_reject_substitution_and_expat_downgrade() -> None:
    input_lock = noether_forge.load_json(noether_forge.RELEASE_ROOT / "alpine-input-lock.json")
    package_lock = noether_forge.load_json(noether_forge.RELEASE_ROOT / "package-lock.json")
    noether_forge.validate_trust_locks(input_lock, package_lock)

    mutations = []
    changed = copy.deepcopy(input_lock)
    changed["release_signer"]["key_url"] = "file:///tmp/ncopa.asc"
    mutations.append(changed)
    changed = copy.deepcopy(input_lock)
    changed["boot_media"]["iso"]["url"] = "https://attacker.invalid/alpine.iso"
    mutations.append(changed)
    changed = copy.deepcopy(input_lock)
    changed["package_source_media"]["iso"]["url"] += "?mirror=attacker"
    mutations.append(changed)
    changed = copy.deepcopy(input_lock)
    changed["boot_media"], changed["package_source_media"] = changed["package_source_media"], changed["boot_media"]
    mutations.append(changed)
    changed = copy.deepcopy(input_lock)
    changed["boot_media"]["sidecars"][1] = copy.deepcopy(changed["boot_media"]["sidecars"][0])
    mutations.append(changed)
    changed = copy.deepcopy(input_lock)
    changed["post_release_overlay"][0], changed["post_release_overlay"][1] = changed["post_release_overlay"][1], changed["post_release_overlay"][0]
    mutations.append(changed)
    changed = copy.deepcopy(input_lock)
    changed["bootstrap"]["members"][0]["sha256"] = "0" * 64
    mutations.append(changed)
    for changed in mutations:
        assert_raises(
            noether_forge.NoetherForgeError,
            noether_forge.validate_trust_locks,
            changed,
            package_lock,
        )

    downgraded = copy.deepcopy(package_lock)
    expat = next(item for item in downgraded["packages"] if item["filename"].startswith("libexpat-"))
    expat["filename"] = "libexpat-2.8.1-r0.apk"
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.validate_trust_locks,
        input_lock,
        downgraded,
    )


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
        "input_records": 10,
        "package_records": 52,
        "provenance_records": 1,
        "network_records": 13,
        "container_member_records": 50,
        "records_with_declared_license_metadata": 1,
        "records_with_source_provenance": 1,
        "records_with_notice_files": 1,
        "records_with_export_classification": 0,
        "records_with_license_conclusions": 0,
        "records_with_redistribution_clearance": 0,
        "total_records": 63,
    }
    assert inventory["policy"] == {
        "binary_distribution_authorized": False,
        "legal_clearance": "not-provided-by-this-inventory",
        "network_performed": False,
        "official_release_authority": False,
    }
    assert len(inventory["generated_from"]) == 3
    assert [(item["path"], item["schema"]) for item in inventory["generated_from"]] == [
        (
            "wucios/releases/noether-forge-v2.4.0/alpine-input-lock.json",
            "wucios.noether_forge.alpine_input_lock.v2",
        ),
        (
            "wucios/releases/noether-forge-v2.4.0/package-lock.json",
            "wucios.noether_forge.package_lock.v2",
        ),
        (
            "wucios/releases/noether-forge-v2.4.0/initramfs-patch-spec.json",
            "wucios.noether_forge.initramfs_patch_spec.v1",
        ),
    ]
    assert len(inventory["items"]) == 63
    assert [item["item_id"] for item in inventory["items"]] == sorted(
        item["item_id"] for item in inventory["items"]
    )
    for item in inventory["items"]:
        assert item["origin"]["record_state"] == "locked"
        assert item["origin"]["acquisition"] in {"network", "container-member"}
        if item["origin"]["acquisition"] == "network":
            assert item["origin"]["artifact_url"].startswith("https://")
        else:
            assert item["origin"]["artifact_url"] == "NOASSERTION"
            assert item["origin"]["container_url"].startswith("https://")
        if item["kind"] == "alpine-mkinitfs-source-provenance":
            assert item["package"] == "mkinitfs"
            assert item["version"] == "3.14.0-r0"
            assert item["license_metadata"] == {
                "declared_expression": "GPL-2.0-only",
                "evidence": "initramfs-patch-spec.json and authenticated Alpine package-index metadata",
                "review_state": "declared-metadata-recorded",
            }
            assert item["notices"] == {
                "provided": "PATCH-NOTICE.md and LICENSES/GPL-2.0-only.txt",
                "required": "NOASSERTION",
                "review_state": "provided-files-recorded",
            }
            assert item["source_metadata"]["origin_package"] == "mkinitfs"
            assert item["source_metadata"]["review_state"] == "exact-source-provenance-recorded"
            assert item["source_metadata"]["upstream_source_url"].startswith("https://")
            assert item["source_metadata"]["source_archive_digest"].startswith("sha256:")
        else:
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
    packages = [item for item in inventory["items"] if item["kind"].startswith("alpine-apk-") and item["package"] != "NOASSERTION"]
    assert len(packages) == 52
    assert sum(item["kind"] == "alpine-apk-post-release-overlay" for item in packages) == 3
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


def test_newc_bootstrap_parser_is_exact_and_bounded() -> None:
    data = b"locked bootstrap"
    spec = {
        "path": "usr/bin/tool",
        "type": "regular",
        "mode": "0755",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    archive = newc_archive(newc_entry("usr/bin/tool", data, mode=stat.S_IFREG | 0o755))
    parsed = noether_forge.parse_newc_bootstrap(archive, [spec], expected_entry_count=1)
    assert parsed["usr/bin/tool"]["data"] == data

    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.parse_newc_bootstrap,
        archive[:-1],
        [spec],
        expected_entry_count=1,
    )
    malformed_hex = bytearray(archive)
    malformed_hex[6] = ord("g")
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, bytes(malformed_hex), [spec], expected_entry_count=1)
    malformed_nul = bytearray(archive)
    malformed_nul[110 + len("usr/bin/tool")] = ord("x")
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, bytes(malformed_nul), [spec], expected_entry_count=1)

    padding_archive = bytearray(newc_archive(newc_entry("ab", b"x")))
    padding_archive[113] = 1
    padding_spec = {"path": "ab", "type": "regular", "mode": "0644", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, bytes(padding_archive), [padding_spec], expected_entry_count=1)
    traversal = newc_archive(newc_entry("../escape", b"x"))
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, traversal, [spec], expected_entry_count=1)
    duplicate = newc_archive(
        newc_entry("usr/bin/tool", data, mode=stat.S_IFREG | 0o755),
        newc_entry("usr/bin/tool", data, mode=stat.S_IFREG | 0o755),
    )
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, duplicate, [spec], expected_entry_count=2)
    directory = newc_archive(newc_entry("usr/bin/tool", b"", mode=stat.S_IFDIR | 0o755))
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, directory, [spec], expected_entry_count=1)

    link_spec = {"path": "usr/lib/libx.so", "type": "symlink", "mode": "0777", "target": "libx.so.1"}
    wrong_link = newc_archive(newc_entry("usr/lib/libx.so", b"wrong.so", mode=stat.S_IFLNK | 0o777))
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, wrong_link, [link_spec], expected_entry_count=1)
    missing_spec = dict(spec, path="usr/bin/missing")
    assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, archive, [missing_spec], expected_entry_count=1)
    with mock.patch.object(noether_forge, "NEWC_MAX_ENTRY_SIZE", 1):
        assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, archive, [spec], expected_entry_count=1)
    with mock.patch.object(noether_forge, "NEWC_MAX_ARCHIVE_SIZE", len(archive) - 1):
        assert_raises(noether_forge.NoetherForgeError, noether_forge.parse_newc_bootstrap, archive, [spec], expected_entry_count=1)


def synthetic_initramfs_patch_fixture() -> tuple[bytes, bytes, dict[str, object], dict[str, object]]:
    replacement_records = [
        {"label": "synthetic-alpha", "encoding": "utf-8", "content": "replacement-alpha-0"},
        {"label": "synthetic-bravo", "encoding": "utf-8", "content": "replacement-bravo-1"},
        {"label": "synthetic-charlie", "encoding": "utf-8", "content": "replacement-charlie-2"},
        {"label": "synthetic-delta", "encoding": "utf-8", "content": "replacement-delta-3"},
    ]
    patch_spec: dict[str, object] = {"replacements": replacement_records}
    member_parts = [b"synthetic-prefix|"]
    output_parts = [b"synthetic-prefix|"]
    source_spans: list[dict[str, object]] = []
    offset = len(member_parts[0])
    for index, record in enumerate(replacement_records):
        replacement = record["content"].encode("utf-8")
        source_slice = bytes([ord("A") + index]) * len(replacement)
        source_spans.append({
            "label": record["label"],
            "offset": offset,
            "length": len(source_slice),
            "sha256": hashlib.sha256(source_slice).hexdigest(),
            "replacement_length": len(replacement),
            "replacement_sha256": hashlib.sha256(replacement).hexdigest(),
        })
        member_parts.append(source_slice)
        output_parts.append(replacement)
        offset += len(source_slice)
        gap = f"|synthetic-gap-{index}|".encode("ascii")
        member_parts.append(gap)
        output_parts.append(gap)
        offset += len(gap)
    member = b"".join(member_parts)
    output_member = b"".join(output_parts)
    archive = newc_archive(newc_entry("init", member, mode=stat.S_IFREG | 0o755))
    expected = newc_archive(newc_entry("init", output_member, mode=stat.S_IFREG | 0o755))
    patch_lock = {
        "member": "init",
        "source_member_size": len(member),
        "source_member_sha256": hashlib.sha256(member).hexdigest(),
        "source_spans": source_spans,
        "output_member_size": len(output_member),
        "output_member_sha256": hashlib.sha256(output_member).hexdigest(),
        "output_uncompressed_size": len(expected),
        "output_uncompressed_sha256": hashlib.sha256(expected).hexdigest(),
    }
    return archive, expected, patch_lock, patch_spec


def test_initramfs_patch_changes_only_locked_init_member() -> None:
    archive, expected, patch_lock, patch_spec = synthetic_initramfs_patch_fixture()
    patched = noether_forge.patch_initramfs_payload(
        archive,
        patch_lock,
        patch_spec,
        expected_entry_count=1,
    )
    assert patched == expected
    assert len(patched) == len(archive)
    start, end = noether_forge.locate_newc_regular_member(archive, "init", expected_entry_count=1)
    assert patched[:start] == archive[:start]
    assert patched[end:] == archive[end:]
    replacements = noether_forge.initramfs_replacements(patch_spec)
    for replacement in replacements.values():
        assert patched.count(replacement) == 1
    evidence = noether_forge.verify_patched_initramfs_payload(
        patched,
        patch_lock,
        patch_spec,
        expected_entry_count=1,
    )
    assert evidence["marker_counts"] == {label: 1 for label in replacements}

    member_start, member_end = noether_forge.locate_newc_regular_member(archive, "init", expected_entry_count=1)
    member = archive[member_start:member_end]
    outside_marker = next(iter(replacements.values()))
    injected = newc_archive(
        newc_entry("init", member, mode=stat.S_IFREG | 0o755),
        newc_entry("outside", outside_marker),
    )
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.patch_initramfs_payload,
        injected,
        patch_lock,
        patch_spec,
        expected_entry_count=2,
    )


def test_initramfs_patch_rejects_span_and_accounting_drift() -> None:
    archive, _expected, patch_lock, patch_spec = synthetic_initramfs_patch_fixture()
    member_size = patch_lock["source_member_size"]

    out_of_range = copy.deepcopy(patch_lock)
    out_of_range["source_spans"][0]["offset"] = member_size
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.patch_initramfs_payload,
        archive,
        out_of_range,
        patch_spec,
        expected_entry_count=1,
    )

    overlap = copy.deepcopy(patch_lock)
    first = overlap["source_spans"][0]
    overlap["source_spans"][1]["offset"] = first["offset"] + first["length"] - 1
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.patch_initramfs_payload,
        archive,
        overlap,
        patch_spec,
        expected_entry_count=1,
    )

    slice_drift = copy.deepcopy(patch_lock)
    slice_drift["source_spans"][0]["sha256"] = "0" * 64
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.patch_initramfs_payload,
        archive,
        slice_drift,
        patch_spec,
        expected_entry_count=1,
    )

    output_drift = copy.deepcopy(patch_lock)
    output_drift["output_member_sha256"] = "0" * 64
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.patch_initramfs_payload,
        archive,
        output_drift,
        patch_spec,
        expected_entry_count=1,
    )

    length_drift_spec = copy.deepcopy(patch_spec)
    length_drift_spec["replacements"][0]["content"] += "x"
    replacement = length_drift_spec["replacements"][0]["content"].encode("utf-8")
    length_drift_lock = copy.deepcopy(patch_lock)
    length_drift_lock["source_spans"][0]["replacement_length"] = len(replacement)
    length_drift_lock["source_spans"][0]["replacement_sha256"] = hashlib.sha256(replacement).hexdigest()
    assert_raises(
        noether_forge.NoetherForgeError,
        noether_forge.patch_initramfs_payload,
        archive,
        length_drift_lock,
        length_drift_spec,
        expected_entry_count=1,
    )


def test_initramfs_patch_rejects_duplicate_replacement_markers() -> None:
    _archive, _expected, _patch_lock, patch_spec = synthetic_initramfs_patch_fixture()
    duplicate_label = copy.deepcopy(patch_spec)
    duplicate_label["replacements"][1]["label"] = duplicate_label["replacements"][0]["label"]
    assert_raises(noether_forge.NoetherForgeError, noether_forge.initramfs_replacements, duplicate_label)

    duplicate_content = copy.deepcopy(patch_spec)
    duplicate_content["replacements"][1]["content"] = duplicate_content["replacements"][0]["content"]
    assert_raises(noether_forge.NoetherForgeError, noether_forge.initramfs_replacements, duplicate_content)


def test_source_guard_detects_digest_only_copied_source_window() -> None:
    marker = b"synthetic-upstream\nwindow"
    fingerprint = (
        "synthetic-window",
        len(marker),
        sum(marker),
        sum((index + 1) * value for index, value in enumerate(marker)),
        hashlib.sha256(marker).hexdigest(),
    )
    data = b"prefix|" + marker + b"|suffix"
    assert noether_source_guard.locked_upstream_source_window_labels(data, (fingerprint,)) == ("synthetic-window",)
    assert noether_source_guard.locked_upstream_source_window_labels(data.replace(b"window", b"changed"), (fingerprint,)) == ()

    escaped_python = b'payload = b"synthetic-upstream\\nwindow"\n'
    assert noether_source_guard.locked_upstream_source_window_labels(escaped_python, (fingerprint,)) == ()
    python_literals = noether_source_guard.decoded_text_literals("fixture.py", escaped_python)
    assert any(
        noether_source_guard.locked_upstream_source_window_labels(literal, (fingerprint,))
        == ("synthetic-window",)
        for literal in python_literals
    )

    escaped_json = json.dumps({"payload": "synthetic-upstream\nwindow"}).encode("utf-8")
    assert noether_source_guard.locked_upstream_source_window_labels(escaped_json, (fingerprint,)) == ()
    json_literals = noether_source_guard.decoded_text_literals("fixture.json", escaped_json)
    assert any(
        noether_source_guard.locked_upstream_source_window_labels(literal, (fingerprint,))
        == ("synthetic-window",)
        for literal in json_literals
    )


def test_download_locked_enforces_stream_size_cap() -> None:
    record = {
        "filename": "locked.bin",
        "url": "https://example.invalid/locked.bin",
        "size": 4,
        "sha256": hashlib.sha256(b"four").hexdigest(),
        "kind": "test-input",
    }
    with tempfile.TemporaryDirectory() as temporary:
        cache = Path(temporary)
        with mock.patch.object(noether_forge.urllib.request, "urlopen", return_value=io.BytesIO(b"five!")):
            assert_raises(noether_forge.NoetherForgeError, noether_forge.download_locked, record, cache)
        with mock.patch.object(noether_forge.urllib.request, "urlopen", return_value=io.BytesIO(b"two")):
            assert_raises(noether_forge.NoetherForgeError, noether_forge.download_locked, record, cache)
        with mock.patch.object(noether_forge.urllib.request, "urlopen", return_value=io.BytesIO(b"four")):
            noether_forge.download_locked(record, cache)
        assert (cache / "locked.bin").read_bytes() == b"four"


def write_overlay_apk(path: Path, *, signer: str, origin: str) -> None:
    pkginfo = (
        "pkgname = libexpat\n"
        "pkgver = 2.8.2-r0\n"
        "arch = x86_64\n"
        f"origin = {origin}\n"
    ).encode("utf-8")
    with tarfile.open(path, "w:gz") as archive:
        for name, data in ((signer, b"signature"), (".PKGINFO", pkginfo)):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def test_post_release_overlay_metadata_is_exact() -> None:
    record = {
        "package": "libexpat",
        "version": "2.8.2-r0",
        "architecture": "x86_64",
        "origin": "expat",
    }
    signer = ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "overlay.apk"
        write_overlay_apk(path, signer=signer, origin="expat")
        assert noether_forge.verify_post_release_overlay_metadata(path, record)["origin"] == "expat"
        write_overlay_apk(path, signer=".SIGN.RSA.attacker.rsa.pub", origin="expat")
        assert_raises(noether_forge.NoetherForgeError, noether_forge.verify_post_release_overlay_metadata, path, record)
        write_overlay_apk(path, signer=signer, origin="attacker")
        assert_raises(noether_forge.NoetherForgeError, noether_forge.verify_post_release_overlay_metadata, path, record)


def prepare_wrapper_fixture(root: Path) -> tuple[Path, Path, Path]:
    sysroot = root / "sysroot"
    media = root / "media/cdrom"
    packages = media / "apks/x86_64"
    manifest = sysroot / "usr/share/wucios/locked-apk-manifest.sha256"
    packages.mkdir(parents=True)
    manifest.parent.mkdir(parents=True)
    lines = []
    for index in range(52):
        name = f"package-{index:02d}-1.0-r0.apk"
        data = f"package-{index}\n".encode("ascii")
        (packages / name).write_bytes(data)
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    manifest.write_text("\n".join(lines) + "\n", encoding="ascii")
    ovl = media / "wucios-noether-forge.apkovl.tar.gz"
    ovl.write_bytes(b"fixture")
    return sysroot, ovl, packages


def run_wrapper(
    wrapper: Path,
    sysroot: Path,
    ovl: Path,
    *,
    mode: str = "plain",
    stdin_text: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/sh", str(wrapper), str(sysroot), str(ovl), mode],
        input=stdin_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def test_locked_apk_wrapper_rejects_tampering_and_propagates_apk_failure() -> None:
    wrapper = noether_forge.RELEASE_ROOT / "overlay/usr/local/sbin/wuci-install-locked-apks"
    assert subprocess.run(["/bin/sh", "-n", wrapper], check=False).returncode == 0
    text = wrapper.read_text(encoding="utf-8")
    for required in (
        "set -eu",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        "NOETHER_FORGE_APK_SHA256_PASS",
        "--no-network --force-non-repository",
        "--repositories-file",
        "--arch x86_64",
        "env -i",
        ".wuci-apk-install",
        "trap cleanup 0",
        "trap - 0 1 2 15",
        "cleanup || exit 79",
    ):
        assert required in text
    assert "exec env -i" not in text

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        sysroot, ovl, packages = prepare_wrapper_fixture(root)
        (packages / ".hidden").write_bytes(b"extra")
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 73
        (packages / ".hidden").unlink()
        (packages / ".hidden-link").symlink_to("missing")
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 73
        (packages / ".hidden-link").unlink()

        first = sorted(packages.iterdir())[0]
        original = first.read_bytes()
        first.write_bytes(b"tampered")
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 76
        first.write_bytes(original)

        manifest = sysroot / "usr/share/wucios/locked-apk-manifest.sha256"
        original_manifest = manifest.read_text(encoding="ascii")
        lines = original_manifest.splitlines()
        manifest.write_text("\n".join([lines[0], lines[0], *lines[2:]]) + "\n", encoding="ascii")
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 70
        manifest.write_text(original_manifest.replace("package-00-1.0-r0.apk", "../escape.apk", 1), encoding="ascii")
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 70
        manifest.write_text(original_manifest, encoding="ascii")

        state_dir = sysroot / ".wuci-apk-install"
        state_dir.mkdir()
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 77
        state_dir.rmdir()
        state_dir.write_bytes(b"preexisting state")
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 77
        state_dir.unlink()
        outside = root / "outside-state-target"
        outside.mkdir()
        state_dir.symlink_to(outside, target_is_directory=True)
        assert run_wrapper(wrapper, sysroot, ovl).returncode == 77
        assert list(outside.iterdir()) == []
        state_dir.unlink()
        assert not (sysroot / "tmp").exists()

        fakebin = root / "fakebin"
        fakebin.mkdir()
        fake_apk = fakebin / "apk"
        argv_capture = fakebin / "argv"
        env_capture = fakebin / "env"
        stdin_capture = fakebin / "stdin"

        def write_fake_apk(exit_status: int) -> None:
            fake_apk.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$@\" > {shlex.quote(str(argv_capture))}\n"
                f"env | sort > {shlex.quote(str(env_capture))}\n"
                f"cat > {shlex.quote(str(stdin_capture))}\n"
                f"exit {exit_status}\n",
                encoding="ascii",
            )
            fake_apk.chmod(0o755)

        write_fake_apk(42)
        test_wrapper = root / "wrapper"
        test_wrapper.write_text(
            text.replace(
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                f"PATH={fakebin}:/usr/bin:/bin:/usr/sbin:/sbin",
            ).replace(
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                f"PATH={fakebin}:/usr/sbin:/usr/bin:/sbin:/bin",
            ),
            encoding="utf-8",
        )
        test_wrapper.chmod(0o755)
        result = run_wrapper(test_wrapper, sysroot, ovl)
        assert result.returncode == 42, (result.returncode, result.stdout, result.stderr)
        assert "NOETHER_FORGE_APK_SHA256_PASS" in result.stdout
        assert not state_dir.exists() and not state_dir.is_symlink()
        assert not (sysroot / "tmp").exists()
        expected_argv = [
            "add",
            "--root", str(sysroot),
            "--initramfs-diskless-boot", "--progress",
            "--no-cache", "--no-network", "--force-non-repository",
            "--repositories-file", str(state_dir / "repositories"),
            "--arch", "x86_64", "--clean-protected",
            *(str(path) for path in sorted(packages.iterdir())),
        ]
        assert argv_capture.read_text(encoding="utf-8").splitlines() == expected_argv
        environment = set(env_capture.read_text(encoding="utf-8").splitlines())
        assert {"HOME=/root", "LC_ALL=C", f"PATH={fakebin}:/usr/sbin:/usr/bin:/sbin:/bin"} <= environment
        assert not any(line.startswith(("USER=", "LOGNAME=", "SSH_", "XDG_")) for line in environment)

        write_fake_apk(0)
        result = run_wrapper(test_wrapper, sysroot, ovl)
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        assert not state_dir.exists() and not state_dir.is_symlink()
        assert argv_capture.read_text(encoding="utf-8").splitlines() == expected_argv

        overlay_stdin = "etc/apk/world\netc/network/interfaces\n"
        result = run_wrapper(
            test_wrapper,
            sysroot,
            ovl,
            mode="overlay",
            stdin_text=overlay_stdin,
        )
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        assert not state_dir.exists() and not state_dir.is_symlink()
        assert stdin_capture.read_text(encoding="utf-8") == overlay_stdin
        expected_overlay_argv = [*expected_argv[:13], "--overlay-from-stdin", *expected_argv[13:]]
        assert argv_capture.read_text(encoding="utf-8").splitlines() == expected_overlay_argv
        assert set(env_capture.read_text(encoding="utf-8").splitlines()) == environment


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


def test_safe_reset_removes_read_only_generated_tree() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        generated = root / "generated"
        readonly = generated / "readonly"
        readonly.mkdir(parents=True)
        (readonly / "member").write_bytes(b"generated")
        readonly.chmod(0o555)
        noether_forge.safe_reset_directory(generated, root)
        assert generated.is_dir()
        assert list(generated.iterdir()) == []


def test_safe_reset_rejects_escape_and_non_directory_leaves_without_side_effects() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        allowed = base / "allowed"
        allowed.mkdir()

        sibling = base / "sibling"
        sibling.mkdir()
        sibling_marker = sibling / "marker"
        sibling_marker.write_bytes(b"preserve sibling")

        base_marker = base / "base-marker"
        base_marker.write_bytes(b"preserve base")
        leaf_parent_escape = allowed / ".."
        assert_raises(
            noether_forge.NoetherForgeError,
            noether_forge.safe_reset_directory,
            leaf_parent_escape,
            allowed,
        )
        assert base_marker.read_bytes() == b"preserve base"
        assert allowed.is_dir()

        lexical_escape = allowed / ".." / "sibling"
        assert_raises(
            noether_forge.NoetherForgeError,
            noether_forge.safe_reset_directory,
            lexical_escape,
            allowed,
        )
        assert sibling_marker.read_bytes() == b"preserve sibling"

        outside = base / "outside"
        outside.mkdir()
        outside_generated = outside / "generated"
        outside_generated.mkdir()
        outside_marker = outside_generated / "marker"
        outside_marker.write_bytes(b"preserve outside")
        parent_link = allowed / "parent-link"
        parent_link.symlink_to(outside, target_is_directory=True)
        assert_raises(
            noether_forge.NoetherForgeError,
            noether_forge.safe_reset_directory,
            parent_link / "generated",
            allowed,
        )
        assert outside_marker.read_bytes() == b"preserve outside"

        regular = allowed / "regular"
        regular.write_bytes(b"regular leaf")
        regular.chmod(0o440)
        regular_mode = stat.S_IMODE(regular.stat().st_mode)
        assert_raises(noether_forge.NoetherForgeError, noether_forge.safe_reset_directory, regular, allowed)
        assert regular.read_bytes() == b"regular leaf"
        assert stat.S_IMODE(regular.stat().st_mode) == regular_mode

        peer = base / "hardlink-peer"
        peer.write_bytes(b"hardlink leaf")
        peer.chmod(0o440)
        hardlink = allowed / "hardlink"
        os.link(peer, hardlink)
        peer_mode = stat.S_IMODE(peer.stat().st_mode)
        assert_raises(noether_forge.NoetherForgeError, noether_forge.safe_reset_directory, hardlink, allowed)
        assert peer.read_bytes() == b"hardlink leaf"
        assert stat.S_IMODE(peer.stat().st_mode) == peer_mode
        assert hardlink.exists()

        target = base / "symlink-target"
        target.mkdir()
        target_marker = target / "marker"
        target_marker.write_bytes(b"preserve symlink target")
        leaf_link = allowed / "leaf-link"
        leaf_link.symlink_to(target, target_is_directory=True)
        assert_raises(noether_forge.NoetherForgeError, noether_forge.safe_reset_directory, leaf_link, allowed)
        assert leaf_link.is_symlink()
        assert target_marker.read_bytes() == b"preserve symlink target"


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
    assert noether_forge.APK_SHA256_PASS_MARKER == "NOETHER_FORGE_APK_SHA256_PASS"
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


def test_runtime_package_contract_preserves_noarch_installed_identity() -> None:
    package_lock = {
        "packages": [
            {"filename": f"fixture-{index:02d}.apk", "sha256": f"{index:064x}"}
            for index in range(52)
        ],
    }
    package_info = {
        item["filename"]: {
            "pkgname": f"package-{index:02d}",
            "pkgver": "1.0-r0",
            "arch": "noarch" if index % 2 == 0 else "x86_64",
        }
        for index, item in enumerate(package_lock["packages"])
    }
    with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
        noether_forge,
        "verify_locked_file",
    ), mock.patch.object(
        noether_forge,
        "apk_pkginfo",
        side_effect=lambda path: package_info[path.name],
    ):
        contract = noether_forge.generate_runtime_package_contract(Path(temporary), package_lock)

        by_name = {item["name"]: item for item in contract["packages"]}
        assert by_name["package-00"]["package_architecture"] == "noarch"
        assert by_name["package-00"]["installed_architecture"] == "noarch"
        assert by_name["package-01"]["package_architecture"] == "x86_64"
        assert by_name["package-01"]["installed_architecture"] == "x86_64"
        expected_identities = [
            (item["name"], item["version"], item["installed_architecture"])
            for item in contract["packages"]
        ]
        assert expected_identities == sorted(expected_identities)
        assert len(expected_identities) == len(set(expected_identities)) == 52

        installed = Path(temporary) / "installed"
        installed.write_text(
            "\n\n".join(
                f"P:{name}\nV:{version}\nA:{architecture}"
                for name, version, architecture in reversed(expected_identities)
            )
            + "\n",
            encoding="utf-8",
        )
        assert noether_forge.installed_apk_identities(installed) == expected_identities

        duplicate_info = copy.deepcopy(package_info)
        duplicate_info["fixture-51.apk"] = dict(duplicate_info["fixture-00.apk"])
        with mock.patch.object(
            noether_forge,
            "apk_pkginfo",
            side_effect=lambda path: duplicate_info[path.name],
        ):
            assert_raises(
                noether_forge.NoetherForgeError,
                noether_forge.generate_runtime_package_contract,
                Path(temporary),
                package_lock,
            )


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
    test_generated_spdx_package_purposes_use_official_json_enum,
    test_exact_trust_locks_reject_substitution_and_expat_downgrade,
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
    test_newc_bootstrap_parser_is_exact_and_bounded,
    test_initramfs_patch_changes_only_locked_init_member,
    test_initramfs_patch_rejects_span_and_accounting_drift,
    test_initramfs_patch_rejects_duplicate_replacement_markers,
    test_source_guard_detects_digest_only_copied_source_window,
    test_download_locked_enforces_stream_size_cap,
    test_post_release_overlay_metadata_is_exact,
    test_locked_apk_wrapper_rejects_tampering_and_propagates_apk_failure,
    test_xorriso_report_normalization_removes_host_state,
    test_xorriso_extract_accepts_regular_single_link_output,
    test_xorriso_extract_rejects_unsafe_outputs,
    test_qemu_contract_has_no_network_device,
    test_configuration_paths_are_fail_closed,
    test_safe_reset_removes_read_only_generated_tree,
    test_safe_reset_rejects_escape_and_non_directory_leaves_without_side_effects,
    test_runtime_parsers,
    test_privileged_file_inventory_scans_full_root,
    test_firewall_policy_rejects_extra_rules,
    test_runtime_marker_and_guest_command_boundary,
    test_canonical_denied_package_set_and_doas_policy,
    test_runtime_package_contract_preserves_noarch_installed_identity,
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
