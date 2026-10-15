#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import copy
import hashlib
import inspect
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import warnings
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any
from unittest import mock


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools/wucios"))
sys.path.insert(0, str(REPO / "tools"))
import lovelace_builder  # noqa: E402
import wuci_black_ice  # noqa: E402
import wuci_lab  # noqa: E402


def expect_lovelace_error(
    callback: Callable[[], object], contains: str | None = None
) -> None:
    try:
        callback()
    except lovelace_builder.LovelaceError as exc:
        if contains is not None:
            assert contains in str(exc), str(exc)
        return
    raise AssertionError("invalid Lovelace builder input was accepted")


@contextlib.contextmanager
def patched(**changes: object) -> Iterator[None]:
    originals = {name: getattr(lovelace_builder, name) for name in changes}
    try:
        for name, value in changes.items():
            setattr(lovelace_builder, name, value)
        yield
    finally:
        for name, value in originals.items():
            setattr(lovelace_builder, name, value)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(lovelace_builder.canonical_json(value))


def assert_configuration_contract(tmp: Path) -> None:
    release, seeds, ghidra = lovelace_builder.configuration()
    assert release["profile"] == "lovelace-laboratory"
    assert release["status"] == "NON_AUTHORITATIVE_RESEARCH_DEVELOPMENT_ARTIFACT"
    assert seeds["repositories"] == sorted(
        seeds["repositories"], key=lambda item: item["name"]
    ) or {item["name"] for item in seeds["repositories"]} == {"main", "community"}
    assert ghidra["published_detached_signature"] is False

    expect_lovelace_error(
        lambda: lovelace_builder.require_exact_keys(
            {"schema": "x", "extra": False}, {"schema"}, "fixture"
        ),
        "extra=['extra']",
    )
    expect_lovelace_error(
        lambda: lovelace_builder.require_exact_keys({}, {"schema"}, "fixture"),
        "missing=['schema']",
    )
    duplicate_json = tmp / "duplicate.json"
    duplicate_json.write_text(
        '{"schema":"first","schema":"second"}\n', encoding="utf-8"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.load_object(duplicate_json),
        "duplicate JSON key rejected",
    )

    config_root = tmp / "configuration"
    profile_path = config_root / "profile.json"
    original_profile = lovelace_builder.load_object(lovelace_builder.PROFILE_PATH)
    assert (
        original_profile["virtualization"]["functional"]["cpu_model"]
        == lovelace_builder.TCG_CPU_MODEL
    )

    def reset(
        release_value: dict[str, Any] | None = None,
        seeds_value: dict[str, Any] | None = None,
        ghidra_value: dict[str, Any] | None = None,
        profile_value: dict[str, Any] | None = None,
    ) -> None:
        write_json(config_root / "release.json", release_value or release)
        write_json(config_root / "package-seeds.json", seeds_value or seeds)
        write_json(config_root / "ghidra-lock.json", ghidra_value or ghidra)
        write_json(profile_path, profile_value or original_profile)

    reset()
    with patched(RELEASE_ROOT=config_root, PROFILE_PATH=profile_path):
        observed_release, observed_seeds, observed_ghidra = (
            lovelace_builder.configuration()
        )
        assert observed_release == release
        assert observed_seeds == seeds
        assert observed_ghidra == ghidra
        assert tuple(release["claims"]) == (
            lovelace_builder.EXPECTED_RELEASE_CLAIMS
        )
        assert tuple(release["non_claims"]) == (
            lovelace_builder.EXPECTED_RELEASE_NON_CLAIMS
        )
        assert release["release_id"] == lovelace_builder.EXPECTED_RELEASE_ID
        assert release["display_name"] == (
            lovelace_builder.EXPECTED_RELEASE_DISPLAY_NAME
        )
        assert release["substrate"] == (
            lovelace_builder.EXPECTED_RELEASE_SUBSTRATE
        )
        assert release["shared_alpine_input"]["use"] == (
            lovelace_builder.EXPECTED_SHARED_ALPINE_INPUT_USE
        )
        assert tuple(ghidra["limitations"]) == (
            lovelace_builder.EXPECTED_GHIDRA_LIMITATIONS
        )
        assert hashlib.sha256(
            lovelace_builder.canonical_json(original_profile)
        ).hexdigest() == lovelace_builder.EXPECTED_PROFILE_CANONICAL_SHA256

        extra_release = copy.deepcopy(release)
        extra_release["unexpected"] = False
        reset(release_value=extra_release)
        expect_lovelace_error(lovelace_builder.configuration, "keys differ")

        missing_release = copy.deepcopy(release)
        del missing_release["non_claims"]
        reset(release_value=missing_release)
        expect_lovelace_error(lovelace_builder.configuration, "keys differ")

        misleading_claims = copy.deepcopy(release)
        misleading_claims["claims"] = ["Safe for arbitrary malware"]
        reset(release_value=misleading_claims)
        expect_lovelace_error(
            lovelace_builder.configuration, "release claim boundary"
        )

        misleading_non_claims = copy.deepcopy(release)
        misleading_non_claims["non_claims"] = [
            "Certified production release"
        ]
        reset(release_value=misleading_non_claims)
        expect_lovelace_error(
            lovelace_builder.configuration, "release claim boundary"
        )

        wrong_type_non_claims = copy.deepcopy(release)
        wrong_type_non_claims["non_claims"] = {
            "safe_for_arbitrary_malware": True
        }
        reset(release_value=wrong_type_non_claims)
        expect_lovelace_error(
            lovelace_builder.configuration, "release claim boundary"
        )

        for field, invalid in (
            ("release_id", "lovelace-production-v1"),
            ("display_name", "Certified WuciOS Malware Sandbox"),
            ("substrate", "noether-core-production"),
        ):
            changed_identity = copy.deepcopy(release)
            changed_identity[field] = invalid
            reset(release_value=changed_identity)
            expect_lovelace_error(
                lovelace_builder.configuration, "release identity"
            )

        misleading_shared_use = copy.deepcopy(release)
        misleading_shared_use["shared_alpine_input"]["use"] = (
            "Noether release authority is inherited; production use approved."
        )
        reset(release_value=misleading_shared_use)
        expect_lovelace_error(
            lovelace_builder.configuration, "shared Alpine input contract"
        )

        extra_seeds = copy.deepcopy(seeds)
        extra_seeds["unexpected"] = False
        reset(seeds_value=extra_seeds)
        expect_lovelace_error(lovelace_builder.configuration, "keys differ")

        extra_ghidra = copy.deepcopy(ghidra)
        extra_ghidra["unexpected"] = False
        reset(ghidra_value=extra_ghidra)
        expect_lovelace_error(lovelace_builder.configuration, "keys differ")

        extra_filesystem = copy.deepcopy(release)
        extra_filesystem["filesystem"]["unexpected"] = 0
        reset(release_value=extra_filesystem)
        expect_lovelace_error(lovelace_builder.configuration, "filesystem keys differ")

        invalid_repository = copy.deepcopy(seeds)
        invalid_repository["repositories"][0]["mirror"] = True
        reset(seeds_value=invalid_repository)
        expect_lovelace_error(lovelace_builder.configuration, "repository seed")

        duplicate_seed = copy.deepcopy(seeds)
        duplicate_seed["packages"].append(duplicate_seed["packages"][0])
        reset(seeds_value=duplicate_seed)
        expect_lovelace_error(lovelace_builder.configuration, "package seed contract")

        authoritative_profile = copy.deepcopy(original_profile)
        authoritative_profile["authoritative_for_release"] = True
        reset(profile_value=authoritative_profile)
        expect_lovelace_error(lovelace_builder.configuration, "profile contract")

        misleading_profile = copy.deepcopy(original_profile)
        misleading_profile["role"] = (
            "Production-authoritative escape-proof malware sandbox."
        )
        misleading_profile["non_claims"] = [
            "Certified safe for arbitrary malicious code"
        ]
        reset(profile_value=misleading_profile)
        expect_lovelace_error(
            lovelace_builder.configuration, "profile contract"
        )

        invalid_ghidra = copy.deepcopy(ghidra)
        invalid_ghidra["published_detached_signature"] = True
        reset(ghidra_value=invalid_ghidra)
        expect_lovelace_error(lovelace_builder.configuration, "Ghidra lock")

        misleading_ghidra = copy.deepcopy(ghidra)
        misleading_ghidra["limitations"] = [
            "Ghidra safely contains attacker-controlled formats."
        ]
        reset(ghidra_value=misleading_ghidra)
        expect_lovelace_error(lovelace_builder.configuration, "Ghidra lock")

    lock = lovelace_builder.load_object(lovelace_builder.PACKAGE_LOCK_PATH)
    lovelace_builder.validate_package_lock(lock, seeds)
    extra_lock = copy.deepcopy(lock)
    extra_lock["unexpected"] = False
    expect_lovelace_error(
        lambda: lovelace_builder.validate_package_lock(extra_lock, seeds),
        "keys differ",
    )
    duplicate_lock = copy.deepcopy(lock)
    duplicate_lock["packages"][1] = copy.deepcopy(duplicate_lock["packages"][0])
    expect_lovelace_error(
        lambda: lovelace_builder.validate_package_lock(duplicate_lock, seeds),
        "invalid or duplicate",
    )
    extra_package_field = copy.deepcopy(lock)
    extra_package_field["packages"][0]["unexpected"] = False
    expect_lovelace_error(
        lambda: lovelace_builder.validate_package_lock(
            extra_package_field, seeds
        ),
        "incomplete",
    )


def zip_member(name: str, data: bytes, mode: int = 0o644) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info, data


def write_zip(path: Path, members: list[tuple[zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for info, data in members:
            archive.writestr(info, data)


def assert_ghidra_archive_guards(tmp: Path) -> None:
    valid_archive = tmp / "ghidra-valid.zip"
    write_zip(
        valid_archive,
        [
            zip_member(
                "ghidra_12.1.2_PUBLIC/support/analyzeHeadless",
                b"#!/bin/sh\nexit 0\n",
                0o755,
            )
        ],
    )
    destination = tmp / "ghidra-valid"
    result = lovelace_builder.safe_extract_ghidra(valid_archive, destination)
    entry_point = destination / result["top_level"] / "support/analyzeHeadless"
    assert result == {
        "entry_count": 1,
        "expanded_size": len(b"#!/bin/sh\nexit 0\n"),
        "top_level": "ghidra_12.1.2_PUBLIC",
    }
    assert entry_point.read_bytes() == b"#!/bin/sh\nexit 0\n"
    assert stat.S_IMODE(entry_point.stat().st_mode) == 0o755

    _release, _seeds, ghidra_lock = lovelace_builder.configuration()
    for creation_umask in (0o002, 0o077):
        install_root = tmp / f"ghidra-install-{creation_umask:o}"
        install_work = tmp / f"ghidra-work-{creation_umask:o}"
        install_work.mkdir(mode=0o700)
        previous_umask = os.umask(creation_umask)
        try:
            lovelace_builder.install_ghidra(
                install_root,
                valid_archive,
                ghidra_lock,
                install_work,
            )
        finally:
            os.umask(previous_umask)
        for relative in (
            "opt",
            "opt/wucios",
            "opt/wucios/ghidra",
            "opt/wucios/ghidra/support",
        ):
            assert stat.S_IMODE(
                (install_root / relative).lstat().st_mode
            ) == 0o755

    traversal_archive = tmp / "ghidra-traversal.zip"
    write_zip(
        traversal_archive,
        [zip_member("ghidra_12.1.2_PUBLIC/../escape", b"escape")],
    )
    expect_lovelace_error(
        lambda: lovelace_builder.safe_extract_ghidra(
            traversal_archive, tmp / "ghidra-traversal"
        ),
        "path is unsafe",
    )
    assert not (tmp / "escape").exists()

    symlink_archive = tmp / "ghidra-symlink.zip"
    symlink_info = zipfile.ZipInfo(
        "ghidra_12.1.2_PUBLIC/support/analyzeHeadless"
    )
    symlink_info.create_system = 3
    symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
    write_zip(symlink_archive, [(symlink_info, b"../../outside")])
    expect_lovelace_error(
        lambda: lovelace_builder.safe_extract_ghidra(
            symlink_archive, tmp / "ghidra-symlink"
        ),
        "non-regular",
    )

    duplicate_archive = tmp / "ghidra-duplicate.zip"
    duplicate_name = "ghidra_12.1.2_PUBLIC/support/analyzeHeadless"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        write_zip(
            duplicate_archive,
            [
                zip_member(duplicate_name, b"first", 0o755),
                zip_member(duplicate_name, b"second", 0o755),
            ],
        )
    expect_lovelace_error(
        lambda: lovelace_builder.safe_extract_ghidra(
            duplicate_archive, tmp / "ghidra-duplicate"
        ),
        "duplicate Ghidra archive member",
    )

    oversized_archive = tmp / "ghidra-oversized.zip"
    write_zip(
        oversized_archive,
        [zip_member(duplicate_name, b"12345", 0o755)],
    )
    with patched(MAX_GHIDRA_ENTRY_SIZE=4, MAX_GHIDRA_EXPANDED_SIZE=8):
        expect_lovelace_error(
            lambda: lovelace_builder.safe_extract_ghidra(
                oversized_archive, tmp / "ghidra-oversized"
            ),
            "expanded-size limits",
        )

    for unsafe in ("", "/absolute", "../escape", "a/../escape", "a\\b"):
        expect_lovelace_error(
            lambda unsafe=unsafe: lovelace_builder.validated_relative_path(
                unsafe, "fixture"
            ),
            "path is unsafe",
        )


def write_apk_index(path: Path, payload: bytes) -> None:
    with tarfile.open(path, "w:gz") as archive:
        signature = b"fixture-signature"
        signature_info = tarfile.TarInfo(".SIGN.RSA.fixture.rsa.pub")
        signature_info.size = len(signature)
        archive.addfile(signature_info, io.BytesIO(signature))
        index_info = tarfile.TarInfo("APKINDEX")
        index_info.size = len(payload)
        archive.addfile(index_info, io.BytesIO(payload))


def assert_apk_index_duplicate_rejection(tmp: Path) -> None:
    index = tmp / "duplicate-index.tar.gz"
    write_apk_index(
        index,
        (
            b"P:duplicate\nV:1.0-r0\nA:x86_64\n\n"
            b"P:duplicate\nV:1.0-r0\nA:x86_64\n"
        ),
    )
    expect_lovelace_error(
        lambda: lovelace_builder.parse_apk_index(index, "fixture"),
        "duplicate APK index identity",
    )


def assert_overlay_and_runtime_contracts(tmp: Path) -> None:
    root = tmp / "overlay-root"
    records = lovelace_builder.copy_overlay(root)
    overlay = lovelace_builder.RELEASE_ROOT / "overlay"
    source_files = sorted(
        path.relative_to(overlay).as_posix()
        for path in overlay.rglob("*")
        if path.is_file()
    )
    assert [record["path"] for record in records] == source_files
    assert len({record["path"] for record in records}) == len(records)
    assert lovelace_builder.overlay_source_manifest() == {
        "file_count": len(records),
        "files": records,
    }
    for record in records:
        relative = Path(record["path"])
        destination = root / relative
        expected_mode = (
            0o755
            if relative.parts[:3]
            in {("usr", "local", "bin"), ("usr", "local", "sbin")}
            else 0o600
            if relative.as_posix() == "etc/shadow"
            else 0o644
        )
        assert record["mode"] == f"{expected_mode:04o}"
        assert stat.S_IMODE(destination.stat().st_mode) == expected_mode
        assert record["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()

    _release, seeds, _ghidra = lovelace_builder.configuration()
    assert [item["name"] for item in seeds["repositories"]] == [
        "main",
        "community",
    ]
    expected_repositories = b"".join(
        item["url"].encode("ascii") + b"\n"
        for item in seeds["repositories"]
    )
    assert (root / "etc/apk/repositories").read_bytes() == (
        expected_repositories
    )

    wrapper = root / "usr/local/bin/noxframe"
    wrapper_text = wrapper.read_text(encoding="utf-8")
    assert stat.S_IMODE(wrapper.stat().st_mode) == 0o755
    assert 'state=/work/.noxframe' in wrapper_text
    assert "umask 077" in wrapper_text
    assert "mkdir -p \"$state\"" in wrapper_text
    assert "exec /opt/wuci-ji/tools/wuci-noxframe" in wrapper_text
    for argument, suffix in (
        ("--report", "launch-report.md"),
        ("--seal", "self-seal.json"),
        ("--clock", "clock.json"),
        ("--substrate-state", "substrate-state.json"),
        ("--substrate-seal", "substrate-seal.json"),
        ("--daylight-wrap-out", "daylight-wrap"),
    ):
        assert f'{argument} "$state/{suffix}"' in wrapper_text
    assert "--bin /usr/local/bin/wuci-ji" in wrapper_text

    runner_text = (root / "usr/local/bin/wuci-lab-run").read_text(
        encoding="utf-8"
    )
    for expected in (
        "python3) ulimit -t 25;",
        "c) ulimit -t 90;",
        "c++) ulimit -t 150;",
        "assembly) ulimit -t 90;",
        "rust) ulimit -t 480;",
        "go) ulimit -t 480;",
    ):
        assert expected in runner_text
    assert "ulimit -f 131072" in runner_text
    assert "ghidra) nofile_limit=1024 ;;" in runner_text
    assert "*) nofile_limit=128 ;;" in runner_text
    assert 'ulimit -n "$nofile_limit"' in runner_text
    assert "ulimit -n 128" not in runner_text
    assert "ulimit -u 128" in runner_text
    assert 'online_vcpus=$(getconf _NPROCESSORS_ONLN)' in runner_text
    assert 'ghidra_cpu_seconds=$((670 * online_vcpus))' in runner_text
    assert 'ulimit -t "$ghidra_cpu_seconds"' in runner_text
    assert "ulimit -t 620" not in runner_text
    assert "GHIDRA_HEADLESS_MAXMEM=2G" in runner_text

    noxframe_smoke_text = (
        root / "usr/local/bin/wuci-noxframe-smoke"
    ).read_text(encoding="utf-8")
    for output in ("c", "cpp", "assembly", "rust", "go"):
        assert f"/work/.wuci-lab-{output}" in noxframe_smoke_text

    lab_smoke_text = (root / "usr/local/bin/wuci-lab-smoke").read_text(
        encoding="utf-8"
    )
    assert 'wuci-ji selftest | grep -Fx "wuci-ji selftest: PASS"' in (
        lab_smoke_text
    )
    assert lovelace_builder.WUCIJI_MARKER in lab_smoke_text

    console = root / "usr/local/sbin/wuci-lab-console"
    console_text = console.read_text(encoding="utf-8")
    assert lovelace_builder.CONSOLE_MARKER in console_text
    assert "exec /sbin/runuser -u lab -- /bin/bash -l" in console_text
    assert stat.S_IMODE(console.stat().st_mode) == 0o755

    early_text = (root / "usr/local/sbin/wuci-lab-early").read_text(
        encoding="utf-8"
    )
    assert "udhcpc" not in early_text
    assert "network_mode=unavailable" in early_text
    assert "ip -4 address replace 10.0.2.15/24 dev eth0" in early_text
    assert (
        "ip -4 route replace default via 10.0.2.2 dev eth0"
        in early_text
    )
    assert "'nameserver 10.0.2.3'" in early_text
    assert "network_mode=internet" in early_text
    assert "network=$network_mode" in early_text
    assert (
        lovelace_builder.HOSTILE_BOOT_LINE.replace(
            "network=none", "network=$network_mode"
        )
        in early_text
    )

    busybox_root = tmp / "busybox-root"
    (busybox_root / "bin").mkdir(parents=True)
    (busybox_root / "bin/busybox").write_bytes(b"busybox fixture\n")
    installed = lovelace_builder.install_busybox_runtime_links(busybox_root)
    assert installed == [
        path for path, _target in lovelace_builder.BUSYBOX_RUNTIME_LINKS
    ]
    assert (busybox_root / "bin/ash").is_symlink()
    assert os.readlink(busybox_root / "bin/ash") == "busybox"
    assert (busybox_root / "bin/ash").resolve() == (
        busybox_root / "bin/busybox"
    ).resolve()
    assert lovelace_builder.install_busybox_runtime_links(busybox_root) == (
        installed
    )

    tracked = {
        path.relative_to(REPO).as_posix()
        for path in lovelace_builder.tracked_runtime_sources()
    }
    expected_anchors = set(wuci_black_ice.ANCHOR_PATHS)
    assert expected_anchors <= tracked
    assert {
        "tools/wuci-noxframe",
        "tools/wuci_black_ice.py",
        "tools/wuci_kaiju.py",
        "docs/noxframe/README.md",
    } <= tracked
    assert set(lovelace_builder.HOST_ONLY_RUNTIME_SOURCE_PATHS).isdisjoint(
        tracked
    )
    for path in lovelace_builder.HOST_ONLY_RUNTIME_SOURCE_PATHS:
        assert lovelace_builder.runtime_source_path_selected(path) is False
    assert lovelace_builder.runtime_source_path_selected(
        "tools/wuci-noxframe"
    ) is True
    assert all(not path.startswith("build/") for path in tracked)

    bad_overlay = tmp / "bad-overlay-release"
    (bad_overlay / "overlay").mkdir(parents=True)
    if hasattr(os, "symlink"):
        (bad_overlay / "target").write_text("target\n", encoding="utf-8")
        (bad_overlay / "overlay/link").symlink_to(bad_overlay / "target")
        with patched(RELEASE_ROOT=bad_overlay):
            expect_lovelace_error(
                lambda: lovelace_builder.copy_overlay(tmp / "bad-overlay-root"),
                "regular files only",
            )

    artifact_output = tmp / "relative-artifact-output"
    artifact_release = artifact_output / "release"
    artifact_release.mkdir(parents=True)
    lovelace_builder.write_json(artifact_release / "manifest.json", {})
    relative_output = Path(os.path.relpath(artifact_output, REPO))
    _manifest, artifact_path_records = lovelace_builder.artifact_paths(
        relative_output
    )
    assert all(path.is_absolute() for path in artifact_path_records.values())

    symlink_output = tmp / "symlink-artifact-output"
    symlink_output.mkdir()
    external_release = tmp / "external-artifact-release"
    external_release.mkdir()
    lovelace_builder.write_json(external_release / "manifest.json", {})
    (symlink_output / "release").symlink_to(
        external_release, target_is_directory=True
    )
    expect_lovelace_error(
        lambda: lovelace_builder.artifact_paths(symlink_output),
        "release root must be a real directory",
    )

    manifest_symlink_output = tmp / "manifest-symlink-output"
    (manifest_symlink_output / "release").mkdir(parents=True)
    external_manifest = tmp / "external-manifest.json"
    lovelace_builder.write_json(external_manifest, {})
    (manifest_symlink_output / "release/manifest.json").symlink_to(
        external_manifest
    )
    expect_lovelace_error(
        lambda: lovelace_builder.artifact_paths(manifest_symlink_output),
        "build manifest must be a regular file",
    )

    oversized_output = tmp / "oversized-manifest-output"
    (oversized_output / "release").mkdir(parents=True)
    (oversized_output / "release/manifest.json").write_bytes(
        b"{" + b"x" * lovelace_builder.MAX_BUILD_MANIFEST_BYTES
    )
    expect_lovelace_error(
        lambda: lovelace_builder.artifact_paths(oversized_output),
        "changed or is too large",
    )


def assert_static_build_record_validation() -> None:
    manifest = {
        "overlay": lovelace_builder.overlay_source_manifest(),
        "native_wuci_ji": {
            "path": "/usr/local/bin/wuci-ji",
            "size": 1,
            "sha256": "a" * 64,
            "source": (
                "isolated direct GNU as/ld build from the working source tree"
            ),
            "sources": lovelace_builder.native_source_records(),
            "host_tools": lovelace_builder.native_host_tool_records(),
        },
        "java_home": lovelace_builder.EXPECTED_JAVA_HOME,
        "busybox_runtime_links": [
            path
            for path, _target in lovelace_builder.BUSYBOX_RUNTIME_LINKS
        ],
        "privileged_files": {
            "suid_sgid_removed": [],
            "single_justified_suid": lovelace_builder.DOAS_PATH,
            "final_setid_inventory": [
                {
                    "path": lovelace_builder.DOAS_PATH,
                    "mode": lovelace_builder.DOAS_MODE,
                }
            ],
            "justification": lovelace_builder.DOAS_JUSTIFICATION,
        },
    }
    lovelace_builder.validate_static_build_records(manifest)

    mutations: list[tuple[Callable[[dict[str, Any]], None], str]] = [
        (
            lambda value: value["overlay"]["files"][0].__setitem__(
                "sha256", "0" * 64
            ),
            "overlay record differs",
        ),
        (
            lambda value: value["overlay"]["files"][0].__setitem__(
                "path", "../escape"
            ),
            "overlay record differs",
        ),
        (
            lambda value: value["native_wuci_ji"].__setitem__(
                "unexpected", True
            ),
            "keys differ",
        ),
        (
            lambda value: value["native_wuci_ji"].__setitem__(
                "path", "/tmp/wuci-ji"
            ),
            "native Wuci-Ji build record differs",
        ),
        (
            lambda value: value.__setitem__("java_home", "/tmp/java"),
            "Java home differs",
        ),
        (
            lambda value: value["busybox_runtime_links"].reverse(),
            "BusyBox links differ",
        ),
        (
            lambda value: value["privileged_files"].__setitem__(
                "justification", "decorative"
            ),
            "privileged-file record differs",
        ),
        (
            lambda value: value["privileged_files"][
                "final_setid_inventory"
            ].append({"path": "/usr/bin/other", "mode": "04755"}),
            "privileged-file record differs",
        ),
    ]
    for mutate, message in mutations:
        candidate = copy.deepcopy(manifest)
        mutate(candidate)
        expect_lovelace_error(
            lambda candidate=candidate: (
                lovelace_builder.validate_static_build_records(candidate)
            ),
            message,
        )


def assert_embedded_runtime_source_inventory_contract() -> None:
    manifest = {
        "source_tree": {
            "files": [
                {
                    "path": "src/main.s",
                    "type": "regular",
                    "mode": "0644",
                    "size": 1,
                    "sha256": "a" * 64,
                },
                {
                    "path": "tools/current",
                    "type": "symlink",
                    "target": "current.py",
                },
            ]
        }
    }

    def record(
        path: str,
        inode: int,
        entry_type: str,
        *,
        uid: int = 0,
        gid: int = 0,
        mode: str | None = None,
        size: int | None = None,
    ) -> dict[str, Any]:
        default_mode = {
            "directory": "040755",
            "regular": "100644",
            "symlink": "120777",
        }[entry_type]
        return {
            "path": path,
            "inode": inode,
            "mode": mode or default_mode,
            "type": entry_type,
            "uid": uid,
            "gid": gid,
            "size": None if entry_type == "directory" else size or 1,
        }

    inventory = {
        item["path"]: item
        for item in (
            record("/opt/wuci-ji", 10, "directory"),
            record("/opt/wuci-ji/src", 11, "directory"),
            record("/opt/wuci-ji/src/main.s", 12, "regular"),
            record("/opt/wuci-ji/tools", 13, "directory"),
            record("/opt/wuci-ji/tools/current", 14, "symlink"),
            record("/opt/wuci-ji/build", 15, "directory"),
            record(
                "/opt/wuci-ji/build/wuci-ji",
                16,
                "regular",
                mode="100755",
            ),
        )
    }
    assert lovelace_builder.validate_embedded_runtime_source_inventory(
        manifest, inventory
    ) == (PurePosixPath("/opt/wuci-ji"), "/opt/wuci-ji/build/wuci-ji")

    missing = copy.deepcopy(inventory)
    del missing["/opt/wuci-ji/src/main.s"]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_embedded_runtime_source_inventory(
            manifest, missing
        ),
        "subtree path set differs",
    )
    extra = copy.deepcopy(inventory)
    extra["/opt/wuci-ji/untracked"] = record(
        "/opt/wuci-ji/untracked", 17, "regular"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_embedded_runtime_source_inventory(
            manifest, extra
        ),
        "subtree path set differs",
    )
    external_alias = copy.deepcopy(inventory)
    external_alias["/tmp/source-alias"] = record(
        "/tmp/source-alias", 12, "regular"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_embedded_runtime_source_inventory(
            manifest, external_alias
        ),
        "subtree entry differs",
    )
    for mutation in (
        lambda value: value["/opt/wuci-ji/src"].__setitem__("uid", 1000),
        lambda value: value["/opt/wuci-ji/src"].__setitem__(
            "mode", "040700"
        ),
        lambda value: value["/opt/wuci-ji/src"].__setitem__(
            "type", "regular"
        ),
        lambda value: value["/opt/wuci-ji/src/main.s"].__setitem__(
            "inode", 16
        ),
    ):
        changed = copy.deepcopy(inventory)
        mutation(changed)
        expect_lovelace_error(
            lambda changed=changed: (
                lovelace_builder.validate_embedded_runtime_source_inventory(
                    manifest, changed
                )
            ),
            "subtree entry differs",
        )

    at_limit = {
        "regular": lovelace_builder.MAX_ROOT_TREE_ENTRIES,
        "directory": 1,
        "symlink": 0,
        "owner_read_added": 0,
    }
    assert (
        lovelace_builder.validated_root_tree_entry_count(at_limit)
        == lovelace_builder.MAX_ROOT_TREE_ENTRIES
    )
    over_limit = dict(at_limit)
    over_limit["symlink"] = 1
    expect_lovelace_error(
        lambda: lovelace_builder.validated_root_tree_entry_count(over_limit),
        "exceed the entry ceiling",
    )


def assert_embedded_contract_binding_contract() -> None:
    records = lovelace_builder.embedded_contract_bindings()
    assert [record["path"] for record in records] == [
        "/usr/share/wucios/ghidra-lock.json",
        "/usr/share/wucios/lovelace-runtime.json",
        "/usr/share/wucios/package-lock.json",
        "/usr/share/wucios/profile.json",
        "/usr/share/wucios/release.json",
    ]
    assert all(record["mode"] == 0o644 for record in records)
    assert all(record["size"] > 0 for record in records)
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
        for record in records
    )
    observed: list[dict[str, Any]] = []

    def capture_binding(
        _image: object,
        _debugfs: Path,
        _inventory: dict[str, dict[str, Any]],
        guest_path: str,
        *,
        expected_mode: int,
        expected_size: int,
        expected_sha256: str,
        label: str,
        deadline: float | int | None = None,
    ) -> None:
        observed.append(
            {
                "path": guest_path,
                "mode": expected_mode,
                "size": expected_size,
                "sha256": expected_sha256,
                "label": label,
                "deadline": deadline,
            }
        )

    with patched(validate_ext4_regular_binding=capture_binding):
        lovelace_builder.validate_embedded_contract_bindings(
            object(), Path("/usr/sbin/debugfs"), {}
        )
    assert [
        {
            key: value
            for key, value in item.items()
            if key not in {"label", "deadline"}
        }
        for item in observed
    ] == records
    assert all(item["deadline"] is None for item in observed)


def assert_embedded_debugfs_deadline_contract() -> None:
    java_path = f"{lovelace_builder.EXPECTED_JAVA_HOME}/bin/java"
    inventory = {
        java_path: {
            "path": java_path,
            "inode": 20,
            "mode": "100755",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "size": 1,
        }
    }
    manifest = {
        "overlay": {"files": []},
        "source_tree": {"files": []},
        "native_wuci_ji": {
            "path": "/usr/local/bin/wuci-ji",
            "size": 1,
            "sha256": "a" * 64,
        },
        "ghidra_fixture": {
            "source": "/opt/wucios/fixture.s",
            "source_size": 1,
            "source_sha256": "b" * 64,
            "binary": "/opt/wucios/fixture",
            "binary_size": 1,
            "binary_sha256": "c" * 64,
        },
        "privileged_files": {"final_setid_inventory": []},
    }
    observed_deadlines: list[float | int | None] = []

    def capture_regular(
        _image: object,
        _debugfs: Path,
        _inventory: dict[str, dict[str, Any]],
        _guest_path: str,
        *,
        expected_mode: int,
        expected_size: int,
        expected_sha256: str,
        label: str,
        deadline: float | int | None = None,
    ) -> None:
        del expected_mode, expected_size, expected_sha256, label
        observed_deadlines.append(deadline)

    def capture_symlink(
        _image: object,
        _debugfs: Path,
        _inventory: dict[str, dict[str, Any]],
        _guest_path: str,
        *,
        expected_target: str,
        label: str,
        deadline: float | int | None = None,
    ) -> None:
        del expected_target, label
        observed_deadlines.append(deadline)

    started = 100.0
    with patched(
        ext4_inventory_by_path=lambda _records: inventory,
        validate_embedded_runtime_source_inventory=(
            lambda _manifest, _inventory: (
                PurePosixPath("/opt/wuci-ji"),
                "/opt/wuci-ji/build/wuci-ji",
            )
        ),
        validate_ext4_regular_binding=capture_regular,
        validate_ext4_symlink_binding=capture_symlink,
        validate_final_setid_inventory=lambda _records: [],
    ):
        with mock.patch.object(
            lovelace_builder.time,
            "monotonic",
            side_effect=(started, started + 1),
        ):
            lovelace_builder.validate_embedded_build_records(
                manifest,
                object(),
                Path("/usr/sbin/debugfs"),
                [],
            )
    expected_deadline = (
        started + lovelace_builder.MAX_EMBEDDED_DEBUGFS_VERIFICATION_SECONDS
    )
    assert len(observed_deadlines) > 10
    assert all(deadline == expected_deadline for deadline in observed_deadlines)

    with mock.patch.object(
        lovelace_builder.time, "monotonic", return_value=started
    ):
        assert lovelace_builder.remaining_embedded_debugfs_timeout(
            started + 601, 600
        ) == 600
        assert lovelace_builder.remaining_embedded_debugfs_timeout(
            started + 59.9, 600
        ) == 59
        expect_lovelace_error(
            lambda: lovelace_builder.remaining_embedded_debugfs_timeout(
                started + 0.9, 600
            ),
            "aggregate time budget",
        )

    regular_inventory = {
        "/fixture": {
            "path": "/fixture",
            "inode": 21,
            "mode": "100644",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "size": 1,
        }
    }
    symlink_record = {
        "path": "/link",
        "inode": 22,
        "mode": "120777",
        "type": "symlink",
        "uid": 0,
        "gid": 0,
        "size": 6,
    }

    def reject_subprocess(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("expired aggregate budget launched debugfs")

    with patched(run_bounded=reject_subprocess):
        with mock.patch.object(
            lovelace_builder.time, "monotonic", return_value=started
        ):
            expect_lovelace_error(
                lambda: lovelace_builder.validate_ext4_regular_binding(
                    object(),
                    Path("/usr/sbin/debugfs"),
                    regular_inventory,
                    "/fixture",
                    expected_mode=0o644,
                    expected_size=1,
                    expected_sha256="d" * 64,
                    label="expired regular binding",
                    deadline=started,
                ),
                "aggregate time budget",
            )
            expect_lovelace_error(
                lambda: lovelace_builder.read_ext4_symlink_target(
                    object(),
                    Path("/usr/sbin/debugfs"),
                    symlink_record,
                    label="expired symlink binding",
                    deadline=started,
                ),
                "aggregate time budget",
            )


def assert_required_runtime_path_resolution_contract() -> None:
    def record(
        path: str,
        inode: int,
        entry_type: str,
        *,
        mode: str | None = None,
        uid: int = 0,
        gid: int = 0,
        size: int | None = None,
    ) -> dict[str, Any]:
        default_mode = {
            "directory": "040755",
            "regular": "100755",
            "symlink": "120777",
        }[entry_type]
        return {
            "path": path,
            "inode": inode,
            "mode": mode or default_mode,
            "type": entry_type,
            "uid": uid,
            "gid": gid,
            "size": None if entry_type == "directory" else size or 1,
        }

    records = (
        record("/", 2, "directory"),
        record("/usr", 3, "directory"),
        record("/usr/bin", 4, "directory"),
        record("/usr/libexec", 5, "directory"),
        record("/usr/bin/cc", 6, "symlink", size=len("../libexec/cc")),
        record("/usr/libexec/cc", 7, "regular", size=4096),
        record("/usr/bin/python3", 8, "symlink", size=len("/opt/python/bin/python3")),
        record("/opt", 9, "directory"),
        record("/opt/python", 10, "directory"),
        record("/opt/python/bin", 11, "directory"),
        record("/opt/python/bin/python3", 12, "regular", size=8192),
    )
    inventory = {item["path"]: item for item in records}
    targets = {6: "../libexec/cc", 8: "/opt/python/bin/python3"}

    def target(
        _image: object,
        _debugfs: Path,
        link: dict[str, Any],
        *,
        label: str,
    ) -> str:
        del label
        return targets[link["inode"]]

    def checked_target(
        _image: object,
        _debugfs: Path,
        link: dict[str, Any],
        *,
        label: str,
    ) -> str:
        if link["uid"] != 0:
            raise lovelace_builder.LovelaceError(
                f"{label} is not a safe root-owned ext4 symlink"
            )
        return targets[link["inode"]]

    with patched(read_ext4_symlink_target=target):
        assert lovelace_builder.resolve_ext4_guest_path(
            object(), Path("/usr/sbin/debugfs"), inventory, "/usr/bin/cc", label="cc"
        )[0] == "/usr/libexec/cc"
        assert lovelace_builder.resolve_ext4_guest_path(
            object(),
            Path("/usr/sbin/debugfs"),
            inventory,
            "/usr/bin/python3",
            label="python",
        )[0] == "/opt/python/bin/python3"
        lovelace_builder.validate_required_runtime_executable_paths(
            object(),
            Path("/usr/sbin/debugfs"),
            inventory,
            ("/usr/bin/cc", "/usr/bin/python3"),
        )

        writable = copy.deepcopy(inventory)
        writable["/usr/libexec/cc"]["mode"] = "100775"
        expect_lovelace_error(
            lambda: lovelace_builder.validate_required_runtime_executable_paths(
                object(),
                Path("/usr/sbin/debugfs"),
                writable,
                ("/usr/bin/cc",),
            ),
            "non-writable executable regular file",
        )

        for field, value in (
            ("mode", "040777"),
            ("uid", 1000),
            ("gid", 1000),
            ("type", "regular"),
        ):
            unsafe_ancestor = copy.deepcopy(inventory)
            unsafe_ancestor["/usr/bin"][field] = value
            if field == "type":
                unsafe_ancestor["/usr/bin"]["mode"] = "100755"
                unsafe_ancestor["/usr/bin"]["size"] = 1
            expect_lovelace_error(
                lambda unsafe_ancestor=unsafe_ancestor: (
                    lovelace_builder.validate_required_runtime_executable_paths(
                        object(),
                        Path("/usr/sbin/debugfs"),
                        unsafe_ancestor,
                        ("/usr/bin/cc",),
                    )
                ),
                "unsafe directory ancestor",
            )

        non_root_link = copy.deepcopy(inventory)
        non_root_link["/usr/bin/cc"]["uid"] = 1000
        with patched(read_ext4_symlink_target=checked_target):
            expect_lovelace_error(
                lambda: lovelace_builder.resolve_ext4_guest_path(
                    object(),
                    Path("/usr/sbin/debugfs"),
                    non_root_link,
                    "/usr/bin/cc",
                    label="non-root link",
                ),
                "not a safe root-owned ext4 symlink",
            )

    for inode, prefix in enumerate(
        ("/dev", "/proc", "/sys", "/run", "/tmp", "/etc", "/home", "/work"),
        start=30,
    ):
        overmounted = copy.deepcopy(inventory)
        target_path = f"{prefix}/python3"
        overmounted[prefix] = record(prefix, inode, "directory")
        overmounted[target_path] = record(
            target_path, inode + 100, "regular", size=4096
        )
        overmounted["/usr/bin/python3"]["size"] = len(target_path)
        with patched(
            read_ext4_symlink_target=(
                lambda _image, _debugfs, _link, *, label, target_path=target_path: (
                    target_path
                )
            )
        ):
            expect_lovelace_error(
                lambda overmounted=overmounted: (
                    lovelace_builder.validate_required_runtime_executable_paths(
                        object(),
                        Path("/usr/sbin/debugfs"),
                        overmounted,
                        ("/usr/bin/python3",),
                    )
                ),
                "outside immutable guest prefixes",
            )

    loop_inventory = copy.deepcopy(inventory)
    loop_inventory["/usr/bin/a"] = record(
        "/usr/bin/a", 20, "symlink", size=1
    )
    loop_inventory["/usr/bin/b"] = record(
        "/usr/bin/b", 21, "symlink", size=1
    )
    escape_inventory = copy.deepcopy(loop_inventory)
    escape_inventory["/usr/bin/escape"] = record(
        "/usr/bin/escape", 22, "symlink", size=len("../../../host")
    )
    extended_targets = {
        **targets,
        20: "b",
        21: "a",
        22: "../../../host",
    }
    with patched(
        read_ext4_symlink_target=(
            lambda _image, _debugfs, link, *, label: extended_targets[
                link["inode"]
            ]
        )
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.resolve_ext4_guest_path(
                object(),
                Path("/usr/sbin/debugfs"),
                loop_inventory,
                "/usr/bin/a",
                label="loop",
            ),
            "symlink-resolution ceiling",
        )
        expect_lovelace_error(
            lambda: lovelace_builder.resolve_ext4_guest_path(
                object(),
                Path("/usr/sbin/debugfs"),
                escape_inventory,
                "/usr/bin/escape",
                label="escape",
            ),
            "escapes guest root",
        )


def assert_source_input_tracking(tmp: Path) -> None:
    manifest = lovelace_builder.source_inputs_manifest()
    assert manifest["schema"] == "wucios.lovelace.source_inputs.v1"
    assert manifest["builder"] == lovelace_builder.BUILDER_VERSION
    files = manifest["files"]
    paths = [record["path"] for record in files]
    assert paths == sorted(set(paths))
    expected = {
        "tools/wucios/lovelace_builder.py",
        "tools/wuci_lab.py",
        "wucios/profiles/lovelace-laboratory.json",
        "wucios/releases/lovelace-laboratory-v0.1.0/release.json",
        "wucios/releases/lovelace-laboratory-v0.1.0/package-seeds.json",
        "wucios/releases/lovelace-laboratory-v0.1.0/package-lock.json",
        "wucios/releases/lovelace-laboratory-v0.1.0/ghidra-lock.json",
        "wucios/releases/lovelace-laboratory-v0.1.0/mke2fs.conf",
        "wucios/schemas/lovelace-laboratory-profile.schema.json",
        "wucios/fixtures/lovelace/ghidra-smoke.s",
        "wucios/fixtures/lovelace/hostile-payload.txt",
    }
    overlay_prefix = "wucios/releases/lovelace-laboratory-v0.1.0/overlay/"
    expected.update(
        path.relative_to(REPO).as_posix()
        for path in (lovelace_builder.RELEASE_ROOT / "overlay").rglob("*")
        if path.is_file()
    )
    assert expected == set(paths)
    assert any(path.startswith(overlay_prefix) for path in paths)
    assert lovelace_builder.validated_runtime_symlink_target(
        "src/main.s", "fixture"
    ) == "src/main.s"
    assert lovelace_builder.validated_runtime_symlink_target(
        "x" * lovelace_builder.MAX_EXT4_FAST_SYMLINK_TARGET_BYTES,
        "fixture",
    ) == "x" * lovelace_builder.MAX_EXT4_FAST_SYMLINK_TARGET_BYTES
    for target in (
        "/absolute",
        "nested//target",
        "target/",
        "./target",
        "..",
        "../target",
        "nested/../target",
        "nested/..",
        "x" * (lovelace_builder.MAX_EXT4_FAST_SYMLINK_TARGET_BYTES + 1),
    ):
        expect_lovelace_error(
            lambda target=target: (
                lovelace_builder.validated_runtime_symlink_target(
                    target, "fixture"
                )
            ),
            "tracked symlink rejected",
        )
    for record in files:
        source = REPO / record["path"]
        assert source.is_file()
        assert record["size"] == source.stat().st_size
        assert record["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()

    runtime_root = tmp / "runtime-source-copy"
    launcher = runtime_root / "usr/local/bin/noxframe"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    previous_umask = os.umask(0o077)
    try:
        copied = lovelace_builder.copy_runtime_sources(runtime_root)
    finally:
        os.umask(previous_umask)
    assert copied == lovelace_builder.runtime_source_manifest()
    source_root = runtime_root / "opt/wuci-ji"
    assert stat.S_IMODE(source_root.lstat().st_mode) == 0o755
    for candidate in source_root.rglob("*"):
        if stat.S_ISDIR(candidate.lstat().st_mode):
            assert stat.S_IMODE(candidate.lstat().st_mode) == 0o755


def assert_serialized_ext4_staged_tree_counts() -> None:
    root = {
        "path": "/",
        "inode": 2,
        "mode": "040755",
        "type": "directory",
        "uid": 0,
        "gid": 0,
        "size": None,
    }
    lost_found = {
        "path": "/lost+found",
        "inode": 11,
        "mode": "040700",
        "type": "directory",
        "uid": 0,
        "gid": 0,
        "size": None,
    }
    inventory = [
        root,
        lost_found,
        {
            "path": "/etc",
            "inode": 12,
            "mode": "040755",
            "type": "directory",
            "uid": 0,
            "gid": 0,
            "size": None,
        },
        {
            "path": "/etc/fixture",
            "inode": 13,
            "mode": "100644",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "size": 9,
        },
        {
            "path": "/fixture-link",
            "inode": 14,
            "mode": "120777",
            "type": "symlink",
            "uid": 0,
            "gid": 0,
            "size": 11,
        },
    ]
    root_counts = {
        "regular": 1,
        "directory": 2,
        "symlink": 1,
        "owner_read_added": 0,
    }
    lovelace_builder.validate_serialized_ext4_staged_tree_counts(
        inventory, root_counts, 3
    )

    expect_lovelace_error(
        lambda: lovelace_builder.validate_serialized_ext4_staged_tree_counts(
            [record for record in inventory if record is not lost_found],
            root_counts,
            3,
        ),
        "exactly one canonical /lost+found",
    )
    wrong_lost_found = [dict(record) for record in inventory]
    wrong_lost_found[1]["mode"] = "040755"
    expect_lovelace_error(
        lambda: lovelace_builder.validate_serialized_ext4_staged_tree_counts(
            wrong_lost_found, root_counts, 3
        ),
        "/lost+found metadata differs",
    )
    duplicate_lost_found = [*inventory, dict(lost_found)]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_serialized_ext4_staged_tree_counts(
            duplicate_lost_found, root_counts, 3
        ),
        "exactly one canonical /lost+found",
    )
    populated_lost_found = [
        *inventory,
        {
            "path": "/lost+found/recovered",
            "inode": 15,
            "mode": "100600",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "size": 1,
        },
    ]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_serialized_ext4_staged_tree_counts(
            populated_lost_found, root_counts, 3
        ),
        "/lost+found directory is not empty",
    )
    unexpected_staged_path = [
        *inventory,
        {
            "path": "/unexpected",
            "inode": 15,
            "mode": "100600",
            "type": "regular",
            "uid": 0,
            "gid": 0,
            "size": 1,
        },
    ]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_serialized_ext4_staged_tree_counts(
            unexpected_staged_path, root_counts, 3
        ),
        "path counts differ from the staged root tree",
    )


def assert_ext4_metadata_normalization(tmp: Path) -> None:
    root = tmp / "ext4-root"
    (root / "etc").mkdir(parents=True)
    (root / "home/lab").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True)
    (root / "etc/fixture").write_text("lovelace\n", encoding="ascii")
    os.chmod(root / "etc/fixture", 0o644)
    (root / "home/lab/link").symlink_to("../../etc/fixture")
    (root / "usr/bin/doas").write_bytes(b"fixture doas\n")
    os.chmod(root / "usr/bin/doas", 0o4755)
    epoch = 1_700_000_000
    filesystem_uuid = "49a0ece5-da24-4a3d-91a2-91791dd7c2ac"
    mke2fs = lovelace_builder.trusted_host_tool("mke2fs")
    debugfs = lovelace_builder.trusted_host_tool("debugfs")
    e2fsck = lovelace_builder.trusted_host_tool("e2fsck")
    environment = {
        "E2FSPROGS_FAKE_TIME": str(epoch),
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "MKE2FS_CONFIG": str(lovelace_builder.MKE2FS_CONFIG_PATH),
        "MKE2FS_DEVICE_SECTSIZE": "512",
        "MKE2FS_DEVICE_PHYS_SECTSIZE": "4096",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    images: list[Path] = []
    for index in range(2):
        root_tree_counts = lovelace_builder.normalize_root_tree(root, epoch)
        staged_entry_count = lovelace_builder.validate_root_tree_paths(root)
        image = tmp / f"normalized-{index}.ext4"
        with image.open("xb") as stream:
            stream.truncate(64 * 1024 * 1024)
        lovelace_builder.run(
            [
                mke2fs,
                "-q",
                "-F",
                "-t",
                "ext4",
                "-T",
                "default",
                "-b",
                "4096",
                "-I",
                "256",
                "-N",
                "8192",
                "-G",
                "16",
                "-g",
                "32768",
                "-m",
                "0",
                "-o",
                "linux",
                "-e",
                "continue",
                "-L",
                "WUCI_TEST",
                "-U",
                filesystem_uuid,
                "-M",
                "/",
                "-O",
                (
                    "has_journal,ext_attr,resize_inode,dir_index,filetype,"
                    "extent,64bit,flex_bg,sparse_super,large_file,huge_file,"
                    "dir_nlink,extra_isize,metadata_csum"
                ),
                "-J",
                "size=4",
                "-E",
                (
                    "lazy_itable_init=0,lazy_journal_init=0,"
                    "root_owner=0:0,nodiscard,"
                    f"hash_seed={filesystem_uuid}"
                ),
                "-d",
                root,
                image,
                "16384",
            ],
            env=environment,
            timeout=120,
        )
        for guest_path in (
            "/etc/fixture",
            "/home/lab/link",
            "/usr/bin/doas",
        ):
            for field in ("uid", "gid"):
                ownership = lovelace_builder.run(
                    [
                        debugfs,
                        "-w",
                        "-R",
                        f"set_inode_field {guest_path} {field} 0",
                        image,
                    ],
                    check=False,
                    timeout=120,
                )
                lovelace_builder.require_clean_debugfs_stderr(
                    ownership,
                    f"fixture {guest_path} {field} normalization",
                )
        inventory = lovelace_builder.ext4_inode_inventory(image, debugfs)
        assert 2 in inventory
        path_inventory = lovelace_builder.ext4_path_inventory(image, debugfs)
        by_path = lovelace_builder.ext4_inventory_by_path(path_inventory)
        lovelace_builder.validate_ext4_root_inventory_record(by_path["/"])
        lovelace_builder.validate_serialized_ext4_staged_tree_counts(
            path_inventory,
            root_tree_counts,
            staged_entry_count,
        )
        for field, value in (
            ("mode", "040777"),
            ("uid", 1000),
            ("gid", 1000),
        ):
            changed_root = dict(by_path["/"])
            changed_root[field] = value
            expect_lovelace_error(
                lambda changed_root=changed_root: (
                    lovelace_builder.validate_ext4_root_inventory_record(
                        changed_root
                    )
                ),
                "root inode metadata differs",
            )
        assert by_path["/etc/fixture"]["type"] == "regular"
        assert by_path["/etc/fixture"]["uid"] == 0
        assert by_path["/etc/fixture"]["gid"] == 0
        assert by_path["/etc/fixture"]["size"] == len(b"lovelace\n")
        assert by_path["/home/lab/link"]["type"] == "symlink"
        assert by_path["/home/lab/link"]["size"] == len(
            b"../../etc/fixture"
        )
        assert lovelace_builder.validate_final_setid_inventory(
            path_inventory
        ) == [
            {
                "path": lovelace_builder.DOAS_PATH,
                "mode": lovelace_builder.DOAS_MODE,
            }
        ]
        lovelace_builder.validate_ext4_regular_binding(
            image,
            debugfs,
            by_path,
            "/etc/fixture",
            expected_mode=0o644,
            expected_size=len(b"lovelace\n"),
            expected_sha256=hashlib.sha256(b"lovelace\n").hexdigest(),
            label="ext4 fixture",
        )
        lovelace_builder.validate_ext4_symlink_binding(
            image,
            debugfs,
            by_path,
            "/home/lab/link",
            expected_target="../../etc/fixture",
            label="ext4 fixture symlink",
        )
        for mutation, message in (
            (
                {"expected_mode": 0o600},
                "type, ownership, mode, or size differs",
            ),
            (
                {"expected_size": 1},
                "type, ownership, mode, or size differs",
            ),
            ({"expected_sha256": "0" * 64}, "SHA-256 differs"),
        ):
            parameters = {
                "expected_mode": 0o644,
                "expected_size": len(b"lovelace\n"),
                "expected_sha256": hashlib.sha256(
                    b"lovelace\n"
                ).hexdigest(),
            }
            parameters.update(mutation)
            expect_lovelace_error(
                lambda parameters=parameters: (
                    lovelace_builder.validate_ext4_regular_binding(
                        image,
                        debugfs,
                        by_path,
                        "/etc/fixture",
                        label="mutated ext4 fixture",
                        **parameters,
                    )
                ),
                message,
            )
        expect_lovelace_error(
            lambda: lovelace_builder.validate_ext4_symlink_binding(
                image,
                debugfs,
                by_path,
                "/home/lab/link",
                expected_target="../../etc/fixturE",
                label="mutated ext4 fixture symlink",
            ),
            "target differs",
        )
        oversized_inventory = {
            path: dict(record) for path, record in by_path.items()
        }
        oversized_inventory["/etc/fixture"]["size"] = 4 * 1024**3
        expect_lovelace_error(
            lambda: lovelace_builder.validate_ext4_regular_binding(
                image,
                debugfs,
                oversized_inventory,
                "/etc/fixture",
                expected_mode=0o644,
                expected_size=len(b"lovelace\n"),
                expected_sha256=hashlib.sha256(b"lovelace\n").hexdigest(),
                label="oversized ext4 fixture",
            ),
            "type, ownership, mode, or size differs",
        )
        normalization = lovelace_builder.normalize_ext4_metadata(
            image,
            epoch=epoch,
            filesystem_uuid=filesystem_uuid,
            debugfs=debugfs,
            work=tmp,
        )
        expected_normalized_inodes = sorted(
            set(inventory) | set(range(1, 11))
        )
        assert (
            normalization["normalized_inode_count"]
            == len(expected_normalized_inodes)
        )
        assert normalization["reachable_inode_count"] == len(inventory)
        assert normalization["reserved_inode_count"] == 10
        assert normalization["timestamp_epoch"] == epoch
        assert normalization["superblock_readback"] == {
            "filesystem_uuid": filesystem_uuid,
            "directory_hash_seed": filesystem_uuid,
            "mtime": 0,
            "wtime": epoch,
            "lastcheck": epoch,
            "mkfs_time": epoch,
            "timestamp_high_bytes_zero": True,
            "allocated_inode_count": len(expected_normalized_inodes),
        }
        timestamp_readback = normalization["inode_timestamp_readback"]
        assert timestamp_readback["inode_count"] == len(
            expected_normalized_inodes
        )
        assert timestamp_readback["first_nonreserved_inode"] == 11
        assert timestamp_readback["inode_size"] == 256
        assert timestamp_readback["block_size"] == 4096
        assert timestamp_readback["blocks_count"] == 16384
        assert timestamp_readback["group_count"] == 1
        assert timestamp_readback["descriptor_size"] == 64
        assert timestamp_readback["feature_compat"] == 0x3C
        assert timestamp_readback["feature_incompat"] == 0x2C2
        assert timestamp_readback["feature_ro_compat"] == 0x46B
        assert timestamp_readback["timestamp_epoch"] == epoch
        assert timestamp_readback["allocated_inode_count"] == len(
            expected_normalized_inodes
        )
        assert re.fullmatch(
            r"[0-9a-f]{64}",
            timestamp_readback["allocated_inode_bitmap_sha256"],
        )
        assert (
            timestamp_readback["inodes_with_extra_timestamp_fields"]
            + timestamp_readback["inodes_without_extra_timestamp_fields"]
            == len(expected_normalized_inodes)
        )
        assert (
            timestamp_readback[
                "base_atime_ctime_mtime_equal_epoch"
            ]
            is True
        )
        assert timestamp_readback["deletion_time_zero"] is True
        assert timestamp_readback["crtime_equal_epoch_where_present"] is True
        assert (
            timestamp_readback[
                "extra_timestamp_bits_zero_where_present"
            ]
            is True
        )
        assert re.fullmatch(
            r"[0-9a-f]{64}",
            timestamp_readback["raw_timestamp_fields_sha256"],
        )
        expect_lovelace_error(
            lambda: lovelace_builder.ext4_inode_timestamp_readback(
                image,
                expected_normalized_inodes,
                expected_epoch=epoch + 1,
            ),
            "base timestamp",
        )
        lovelace_builder.require_ext4_path_absent(
            image, debugfs, "/var/log/apk.log"
        )
        expect_lovelace_error(
            lambda: lovelace_builder.require_ext4_path_absent(
                image, debugfs, "/etc/fixture"
            ),
            "present or ambiguous",
        )
        check = lovelace_builder.run(
            [e2fsck, "-fn", image], check=False, timeout=120
        )
        assert check.returncode in {0, 1}, check.stderr
        images.append(image)
    assert images[0].read_bytes() == images[1].read_bytes()

    unexpected_setid = tmp / "unexpected-setid.ext4"
    shutil.copyfile(images[0], unexpected_setid)
    setid_result = lovelace_builder.run(
        [
            debugfs,
            "-w",
            "-R",
            "set_inode_field /etc/fixture mode 0104755",
            unexpected_setid,
        ],
        check=False,
        timeout=120,
    )
    lovelace_builder.require_clean_debugfs_stderr(
        setid_result, "unexpected set-ID fixture mutation"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_final_setid_inventory(
            lovelace_builder.ext4_path_inventory(
                unexpected_setid, debugfs
            )
        ),
        "set-ID inventory differs",
    )
    for field, value in (("uid", 1000), ("gid", 1000)):
        non_root_doas = [dict(record) for record in path_inventory]
        next(
            record
            for record in non_root_doas
            if record["path"] == lovelace_builder.DOAS_PATH
        )[field] = value
        expect_lovelace_error(
            lambda non_root_doas=non_root_doas: (
                lovelace_builder.validate_final_setid_inventory(
                    non_root_doas
                )
            ),
            "not a root-owned regular file",
        )

    def overwrite(image: Path, offset: int, value: bytes) -> bytes:
        with image.open("r+b", buffering=0) as stream:
            stream.seek(offset)
            previous = stream.read(len(value))
            assert len(previous) == len(value)
            stream.seek(offset)
            stream.write(value)
            os.fsync(stream.fileno())
        return previous

    mutated = images[1]
    with mutated.open("rb") as stream:
        stream.seek(4096)
        descriptor = stream.read(64)
    inode_table_block = int.from_bytes(
        descriptor[0x08:0x0C], "little"
    )
    inode_table_block |= int.from_bytes(
        descriptor[0x28:0x2C], "little"
    ) << 32
    inode_two_mtime = inode_table_block * 4096 + 256 + 0x10
    previous = overwrite(
        mutated, inode_two_mtime, (epoch + 1).to_bytes(4, "little")
    )
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_inode_timestamp_readback(
            mutated,
            expected_normalized_inodes,
            expected_epoch=epoch,
        ),
        "base timestamp",
    )
    overwrite(mutated, inode_two_mtime, previous)

    superblock_high_time = 1024 + 0x274
    previous = overwrite(mutated, superblock_high_time, b"\x01")
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_metadata_readback(mutated),
        "high timestamp bytes",
    )
    overwrite(mutated, superblock_high_time, previous)

    log_block_size = 1024 + 0x18
    previous = overwrite(
        mutated, log_block_size, (0xFFFFFFFF).to_bytes(4, "little")
    )
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_inode_timestamp_readback(
            mutated,
            expected_normalized_inodes,
            expected_epoch=epoch,
        ),
        "geometry",
    )
    overwrite(mutated, log_block_size, previous)

    inode_bitmap_block = int.from_bytes(
        descriptor[0x04:0x08], "little"
    )
    inode_bitmap_block |= int.from_bytes(
        descriptor[0x24:0x28], "little"
    ) << 32
    bitmap_offset = inode_bitmap_block * 4096
    with mutated.open("rb") as stream:
        stream.seek(bitmap_offset)
        first_bitmap_byte = stream.read(1)
    previous = overwrite(
        mutated,
        bitmap_offset,
        bytes([first_bitmap_byte[0] ^ 0x01]),
    )
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_inode_timestamp_readback(
            mutated,
            expected_normalized_inodes,
            expected_epoch=epoch,
        ),
        "free-inode counter",
    )
    overwrite(mutated, bitmap_offset, previous)

    inode_table_pointer = 4096 + 0x08
    previous = overwrite(
        mutated, inode_table_pointer, (16384).to_bytes(4, "little")
    )
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_inode_timestamp_readback(
            mutated,
            expected_normalized_inodes,
            expected_epoch=epoch,
        ),
        "allocation descriptor",
    )
    overwrite(mutated, inode_table_pointer, previous)

    hardlink = tmp / "normalized-hardlink.ext4"
    os.link(mutated, hardlink)
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_metadata_readback(mutated),
        "hardlink rejected",
    )
    hardlink.unlink()
    symlink = tmp / "normalized-symlink.ext4"
    symlink.symlink_to(mutated)
    expect_lovelace_error(
        lambda: lovelace_builder.ext4_metadata_readback(symlink),
        "must be a regular file",
    )


def assert_transient_build_path_scan(tmp: Path) -> None:
    root = tmp / "transient-scan-root"
    root.mkdir()
    (root / "stable").write_bytes(b"stable guest content\n")
    (root / "link").symlink_to("stable")
    first_work = tmp / "private-build-a"
    second_work = tmp / "private-build-b"
    first_work.mkdir(mode=0o700)
    second_work.mkdir(mode=0o700)
    first = lovelace_builder.reject_transient_build_path_leaks(
        root, first_work
    )
    second = lovelace_builder.reject_transient_build_path_leaks(
        root, second_work
    )
    assert first == second == {
        "schema": "wucios.lovelace.transient_path_scan.v2",
        "status": "pass",
        "coverage": [
            "regular-file-bytes",
            "symlink-target-bytes",
            "xattr-name-bytes",
            "xattr-value-bytes",
        ],
        "regular_files_scanned": 1,
        "directories_scanned": 1,
        "symlinks_scanned": 1,
        "xattrs_scanned": 0,
        "bytes_scanned": len(b"stable guest content\n") + len(b"stable"),
        "exact_plain_work_path_bytes_found": False,
    }

    (root / "link").unlink()
    (root / "link").symlink_to(first_work)
    expect_lovelace_error(
        lambda: lovelace_builder.reject_transient_build_path_leaks(
            root, first_work
        ),
        "symlink target",
    )
    (root / "link").unlink()
    (root / "link").symlink_to("stable")

    os.setxattr(root / "stable", "user.lovelace", os.fsencode(first_work))
    expect_lovelace_error(
        lambda: lovelace_builder.reject_transient_build_path_leaks(
            root, first_work
        ),
        "xattr",
    )
    os.removexattr(root / "stable", "user.lovelace")
    xattr_name = "user." + os.fspath(first_work)
    os.setxattr(root / "stable", xattr_name, b"stable")
    expect_lovelace_error(
        lambda: lovelace_builder.reject_transient_build_path_leaks(
            root, first_work
        ),
        "xattr name",
    )
    os.removexattr(root / "stable", xattr_name)

    leak = root / "leak"
    prefix_size = 1024 * 1024 - max(1, len(os.fsencode(first_work)) // 2)
    leak.write_bytes(
        b"x" * prefix_size + os.fsencode(first_work) + b"\n"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.reject_transient_build_path_leaks(
            root, first_work
        ),
        "embeds its transient build path",
    )
    leak.unlink()
    with patched(MAX_TRANSIENT_PATH_SCAN_BYTES=1):
        expect_lovelace_error(
            lambda: lovelace_builder.reject_transient_build_path_leaks(
                root, first_work
            ),
            "scan byte ceiling",
        )
    expect_lovelace_error(
        lambda: lovelace_builder.reject_transient_build_path_leaks(
            tmp / "missing-transient-root", first_work
        ),
        "is missing",
    )
    root_alias = tmp / "transient-root-alias"
    root_alias.symlink_to(root, target_is_directory=True)
    expect_lovelace_error(
        lambda: lovelace_builder.reject_transient_build_path_leaks(
            root_alias, first_work
        ),
        "must be a real directory",
    )

    serialized = tmp / "serialized-path-scan"
    serialized.write_bytes(b"stable serialized artifact\n")
    record = lovelace_builder.digest_file_rejecting_exact_bytes(
        serialized, os.fsencode(first_work)
    )
    assert record == {
        "schema": "wucios.lovelace.serialized_exact_path_scan.v1",
        "bytes_scanned": len(b"stable serialized artifact\n"),
        "sha256": hashlib.sha256(
            b"stable serialized artifact\n"
        ).hexdigest(),
        "exact_plain_work_path_bytes_found": False,
    }
    prefix_size = 1024 * 1024 - max(
        1, len(os.fsencode(first_work)) // 2
    )
    serialized.write_bytes(
        b"x" * prefix_size + os.fsencode(first_work) + b"\n"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.digest_file_rejecting_exact_bytes(
            serialized, os.fsencode(first_work)
        ),
        "embeds exact transient",
    )


def assert_reproducible_file_comparison(tmp: Path) -> None:
    first = tmp / "first-artifact"
    second = tmp / "second-artifact"
    first.write_bytes(b"exact Lovelace artifact\n")
    second.write_bytes(first.read_bytes())
    record = lovelace_builder.compare_reproducible_files(
        first, second, "fixture"
    )
    assert record == {
        "size": len(b"exact Lovelace artifact\n"),
        "sha256": hashlib.sha256(
            b"exact Lovelace artifact\n"
        ).hexdigest(),
        "byte_for_byte_equal": True,
    }
    second.write_bytes(b"different Lovelace artifact\n")
    expect_lovelace_error(
        lambda: lovelace_builder.compare_reproducible_files(
            first, second, "fixture"
        ),
        "sizes differ",
    )


def assert_bounded_subprocess_contract() -> None:
    result = lovelace_builder.run_bounded(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('out'); sys.stderr.write('err')",
        ],
        timeout=10,
        max_stdout_bytes=3,
        max_stderr_bytes=3,
    )
    assert result.returncode == 0
    assert result.stdout == "out"
    assert result.stderr == "err"

    for stream, program in (
        ("stdout", "import sys; sys.stdout.write('x' * 65536)"),
        ("stderr", "import sys; sys.stderr.write('x' * 65536)"),
    ):
        expect_lovelace_error(
            lambda program=program: lovelace_builder.run_bounded(
                [sys.executable, "-c", program],
                timeout=10,
                max_stdout_bytes=32,
                max_stderr_bytes=32,
            ),
            f"bounded subprocess {stream} exceeds 32 bytes",
        )

    expect_lovelace_error(
        lambda: lovelace_builder.run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=1,
            max_stdout_bytes=0,
            max_stderr_bytes=0,
        ),
        "bounded subprocess timed out",
    )

    class UnreapableProcess:
        pid = 424242

        @staticmethod
        def wait(timeout: float) -> int:
            raise subprocess.TimeoutExpired("unreapable-fixture", timeout)

    with mock.patch.object(lovelace_builder.os, "killpg") as killpg:
        expect_lovelace_error(
            lambda: lovelace_builder._terminate_and_reap_bounded_process(
                UnreapableProcess(),  # type: ignore[arg-type]
                context="fixture timeout",
            ),
            "bounded subprocess cleanup failed to reap process group 424242",
        )
        killpg.assert_called_once_with(424242, lovelace_builder.signal.SIGKILL)

    class ReapedProcess:
        pid = 434343

        @staticmethod
        def wait(timeout: float) -> int:
            assert timeout == (
                lovelace_builder.BOUNDED_SUBPROCESS_REAP_TIMEOUT_SECONDS
            )
            return -lovelace_builder.signal.SIGKILL

    signal_failure = PermissionError("fixture signal rejection")
    with mock.patch.object(
        lovelace_builder.os, "killpg", side_effect=signal_failure
    ):
        expect_lovelace_error(
            lambda: lovelace_builder._terminate_and_reap_bounded_process(
                ReapedProcess(),  # type: ignore[arg-type]
                context="fixture signal",
            ),
            "bounded subprocess cleanup failed to signal process group 434343",
        )

    with (
        mock.patch.object(
            lovelace_builder.os,
            "killpg",
            side_effect=[None, None],
        ) as killpg,
        mock.patch.object(
            lovelace_builder.time,
            "monotonic",
            side_effect=[100.0, 106.0],
        ),
        mock.patch.object(lovelace_builder.time, "sleep") as sleep,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder._terminate_and_reap_bounded_process(
                ReapedProcess(),  # type: ignore[arg-type]
                context="fixture descendant",
            ),
            "bounded subprocess cleanup left process group 434343 present",
        )
        assert killpg.call_args_list == [
            mock.call(434343, lovelace_builder.signal.SIGKILL),
            mock.call(434343, 0),
        ]
        sleep.assert_not_called()

    with mock.patch.object(lovelace_builder.subprocess, "Popen") as popen:
        expect_lovelace_error(
            lambda: lovelace_builder.run_bounded(
                [sys.executable, "-c", "raise SystemExit(0)"],
                timeout=(
                    lovelace_builder.MAX_BOUNDED_SUBPROCESS_TIMEOUT_SECONDS
                    + 1
                ),
                max_stdout_bytes=0,
                max_stderr_bytes=0,
            ),
            "bounded subprocess contract is invalid",
        )
        popen.assert_not_called()


def assert_ext4_inventory_aggregate_budgets(tmp: Path) -> None:
    prefix = (
        "debugfs: ls -p -l <2>\n"
        "/2/040755/0/0/.//\n"
        "/2/040755/0/0/..//\n"
    )
    inode_zero = "/0/000000/0/0//0/\n"

    def inventory() -> list[dict[str, Any]]:
        return lovelace_builder._ext4_path_inventory_pinned(
            "fixture.ext4",
            Path("/usr/sbin/debugfs"),
            pass_fds=(),
            scratch_directory=tmp,
        )

    with patched(
        run_bounded=lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            prefix + inode_zero * 2,
            "debugfs 1.47.0 (fixture)\n",
        ),
        MAX_DEBUGFS_INVENTORY_INODE_ZERO_ENTRIES=1,
    ):
        expect_lovelace_error(
            inventory,
            "inode-zero entry ceiling",
        )

    with patched(
        run_bounded=lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, prefix, "debugfs 1.47.0 (fixture)\n"
        ),
        MAX_DEBUGFS_INVENTORY_TOTAL_OUTPUT_BYTES=1,
    ):
        expect_lovelace_error(
            inventory,
            "aggregate output ceiling",
        )

    with patched(MAX_DEBUGFS_INVENTORY_SECONDS=0):
        expect_lovelace_error(
            inventory,
            "time budget",
        )


def assert_pinned_ext4_identity(tmp: Path) -> None:
    original = b"pinned ext4 fixture bytes\n"
    image = tmp / "pinned.ext4"
    image.write_bytes(original)
    image.chmod(0o444)
    record = {
        "filename": image.name,
        "size": len(original),
        "sha256": hashlib.sha256(original).hexdigest(),
        "mode": "0444",
        "format": "ext4",
    }

    def replace_path_during_session() -> None:
        replacement = tmp / "replacement.ext4"
        replacement.write_bytes(original)
        replacement.chmod(0o444)
        with lovelace_builder.pinned_ext4_image(image, record) as pinned:
            os.replace(replacement, image)
            assert pinned.pread(len(original), 0) == original

    expect_lovelace_error(
        replace_path_during_session,
        "ext4 image changed during verification",
    )

    def mutate_and_restore_bytes() -> None:
        with lovelace_builder.pinned_ext4_image(image, record) as pinned:
            opened_mtime_ns = pinned.opened.st_mtime_ns
            image.chmod(0o644)
            with image.open("r+b", buffering=0) as stream:
                stream.write(b"X" * len(original))
                stream.seek(0)
                stream.write(original)
                os.fsync(stream.fileno())
            image.chmod(0o444)
            os.utime(
                image,
                ns=(pinned.opened.st_atime_ns, opened_mtime_ns + 1),
            )
            assert pinned.pread(len(original), 0) == original

    expect_lovelace_error(
        mutate_and_restore_bytes,
        "ext4 image changed during verification",
    )

    descriptors_before = set(os.listdir("/proc/self/fd"))
    original_fstat = lovelace_builder.os.fstat

    def fail_fstat(_descriptor: int) -> os.stat_result:
        raise OSError("forced fstat failure")

    try:
        with mock.patch.object(
            lovelace_builder.os, "fstat", side_effect=fail_fstat
        ):
            with lovelace_builder.pinned_ext4_image(image, record):
                raise AssertionError("pinned image yielded after fstat failure")
    except OSError as exc:
        assert "forced fstat failure" in str(exc)
    finally:
        assert lovelace_builder.os.fstat is original_fstat
    assert set(os.listdir("/proc/self/fd")) == descriptors_before


def assert_locked_file_identity(tmp: Path) -> None:
    payload = b"locked kernel fixture\n"
    path = tmp / "locked-kernel"
    path.write_bytes(payload)
    record = {
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "sha512": hashlib.sha512(payload).hexdigest(),
    }
    lovelace_builder.verify_locked_file(path, record, "locked fixture")

    hardlink = tmp / "locked-kernel-hardlink"
    os.link(path, hardlink)
    expect_lovelace_error(
        lambda: lovelace_builder.verify_locked_file(
            path, record, "hardlinked fixture"
        ),
        "hardlink rejected",
    )
    hardlink.unlink()

    alternate = tmp / "locked-kernel-alternate"
    alternate.write_bytes(payload)
    original_ensure_regular = lovelace_builder.ensure_regular
    swapped = False

    def swap_to_symlink(
        candidate: Path,
        label: str,
        *,
        size: int | None = None,
        single_link: bool = True,
    ) -> os.stat_result:
        nonlocal swapped
        info = original_ensure_regular(
            candidate,
            label,
            size=size,
            single_link=single_link,
        )
        if candidate == path and not swapped:
            swapped = True
            candidate.unlink()
            candidate.symlink_to(alternate)
        return info

    with patched(ensure_regular=swap_to_symlink):
        expect_lovelace_error(
            lambda: lovelace_builder.verify_locked_file(
                path, record, "swapped fixture"
            ),
            "cannot safely open",
        )
    path.unlink()
    path.write_bytes(payload)

    original_digest_vector = lovelace_builder._digest_descriptor_vector
    replaced = False

    def replace_after_digest(
        descriptor: int,
        size: int,
        algorithms: tuple[str, ...],
    ) -> dict[str, str]:
        nonlocal replaced
        result = original_digest_vector(descriptor, size, algorithms)
        if not replaced:
            replaced = True
            replacement = tmp / "locked-kernel-replacement"
            replacement.write_bytes(payload)
            os.replace(replacement, path)
        return result

    with patched(_digest_descriptor_vector=replace_after_digest):
        expect_lovelace_error(
            lambda: lovelace_builder.verify_locked_file(
                path, record, "replaced fixture"
            ),
            "changed during verification",
        )


def evidence_fixture_manifest() -> dict[str, Any]:
    ghidra_lock = lovelace_builder.load_object(
        lovelace_builder.RELEASE_ROOT / "ghidra-lock.json"
    )
    ghidra_fixture_source = (
        lovelace_builder.REPO
        / "wucios/fixtures/lovelace/ghidra-smoke.s"
    )
    semantic_script_source = (
        lovelace_builder.RELEASE_ROOT
        / "overlay"
        / lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_PATH.lstrip("/")
        / lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_NAME
    )
    return {
        "schema": "wucios.lovelace.build_manifest.v1",
        "status": "locally-built-non-authoritative",
        "builder": lovelace_builder.BUILDER_VERSION,
        "release_id": "lovelace-fixture-v1",
        "profile": "lovelace-laboratory",
        "authoritative_for_release": False,
        "artifacts": {
            "base_image": {
                "filename": "fixture.ext4",
                "size": 4096,
                "sha256": "a" * 64,
                "mode": "0444",
                "format": "ext4",
            },
            "kernel": {
                "filename": "fixture-kernel",
                "size": 1024,
                "sha256": "b" * 64,
            },
            "initramfs": {
                "filename": "fixture-initramfs",
                "size": 2048,
                "sha256": "c" * 64,
            },
        },
        "package_install": {
            "package_count": 1,
            "installed_identities_exact": True,
            "network_used": False,
            "package_scripts_executed": False,
            "apk_build_log_embedded": False,
            "stdout_tail": "",
        },
        "package_lock_sha256": "d" * 64,
        "source_inputs": {
            "schema": "wucios.lovelace.source_inputs.v1",
            "builder": lovelace_builder.BUILDER_VERSION,
            "files": [],
        },
        "source_tree": {"file_count": 0, "files": [], "scope": []},
        "overlay": {"file_count": 0, "files": []},
        "native_wuci_ji": {
            "path": "/usr/local/bin/wuci-ji",
            "size": 1,
            "sha256": "e" * 64,
            "source": "fixture",
            "sources": [],
            "host_tools": {},
        },
        "java_home": lovelace_builder.EXPECTED_JAVA_HOME,
        "busybox_runtime_links": [
            path
            for path, _target in lovelace_builder.BUSYBOX_RUNTIME_LINKS
        ],
        "privileged_files": {
            "suid_sgid_removed": [],
            "single_justified_suid": lovelace_builder.DOAS_PATH,
            "final_setid_inventory": [
                {
                    "path": lovelace_builder.DOAS_PATH,
                    "mode": lovelace_builder.DOAS_MODE,
                }
            ],
            "justification": lovelace_builder.DOAS_JUSTIFICATION,
        },
        "input_snapshot": {"package_count": 1},
        "ghidra_fixture": {
            "source": "/usr/share/wucios/fixtures/ghidra/ghidra-smoke.s",
            "source_size": ghidra_fixture_source.stat().st_size,
            "source_sha256": lovelace_builder.digest_file(
                ghidra_fixture_source
            ),
            "binary": "/usr/share/wucios/fixtures/ghidra/ghidra-smoke",
            "binary_size": 1,
            "binary_sha256": lovelace_builder.GHIDRA_FIXTURE_SHA256,
            "binary_md5_identity": lovelace_builder.GHIDRA_FIXTURE_MD5,
            "semantic_script": (
                f"{lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_PATH}/"
                f"{lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_NAME}"
            ),
            "semantic_script_sha256": lovelace_builder.digest_file(
                semantic_script_source
            ),
            "semantic_marker": lovelace_builder.GHIDRA_SEMANTIC_MARKER,
        },
        "ghidra": {
            "name": ghidra_lock["name"],
            "version": ghidra_lock["version"],
            "archive_sha256": ghidra_lock["sha256"],
            "install_path": ghidra_lock["install_path"],
            "entry_point": ghidra_lock["entry_point"],
            "expanded_size": 1,
            "entry_count": 1,
            "published_detached_signature": False,
            "runtime_validation": "pending guest boot test",
        },
        "root_tree_counts": {
            "regular": 1,
            "directory": 1,
            "symlink": 0,
            "owner_read_added": 0,
        },
        "filesystem": {
            "format": "ext4",
            "staged_entry_count": 1,
        },
        "defaults": {
            "storage": "volatile",
            "network": "none",
            "noxframe": "metadata-only",
        },
        "hostile_cell": {
            "requires_kvm": True,
            "software_emulation_fallback": False,
            "network": "none",
            "storage": "volatile",
            "persistent_storage": False,
            "host_shares": False,
        },
        "non_claims": ["fixture evidence is non-authoritative"],
        "validation": {
            field: "NOT_MEASURED"
            for field in lovelace_builder.VALIDATION_CONTRACT
        },
        "validation_evidence": {
            field: None
            for field in lovelace_builder.VALIDATION_CONTRACT
        },
    }


def assert_ghidra_semantic_fixture_contract(tmp: Path) -> None:
    script_source = (
        lovelace_builder.RELEASE_ROOT
        / "overlay"
        / lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_PATH.lstrip("/")
        / lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_NAME
    )
    script_text = script_source.read_text(encoding="ascii")
    assert (
        f'private static final String EXPECTED_MD5 =\n'
        f'        "{lovelace_builder.GHIDRA_FIXTURE_MD5}";'
        in script_text
    )
    assert (
        f'private static final String EXPECTED_SHA256 =\n'
        f'        "{lovelace_builder.GHIDRA_FIXTURE_SHA256}";'
        in script_text
    )
    assert (
        f'        "{lovelace_builder.GHIDRA_SEMANTIC_MARKER}";'
        in script_text
    )
    for semantic_check in (
        "extends HeadlessScript",
        "isHeadlessAnalysisEnabled()",
        "analysisTimeoutOccurred()",
        "GhidraProgramUtilities.isAnalyzed(currentProgram)",
        "currentProgram.getExecutableSHA256()",
        "System.out.flush()",
        'EXPECTED_FORMAT.equals(currentProgram.getExecutableFormat())',
        "currentProgram.getLanguageID().toString()",
        "currentProgram.getFunctionManager().getFunctionCount() > 0",
        "currentProgram.getListing().getNumInstructions() >= 8",
        '"lovelace-ghidra-smoke\\n"',
    ):
        assert semantic_check in script_text

    root = tmp / "ghidra-semantic-root"
    installed_script = (
        root
        / lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_PATH.lstrip("/")
        / lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_NAME
    )
    installed_script.parent.mkdir(parents=True)
    shutil.copyfile(script_source, installed_script)
    work = tmp / "ghidra-semantic-work"
    work.mkdir()
    fixture = lovelace_builder.build_ghidra_fixture(root, work)
    source_fixture = REPO / "wucios/fixtures/lovelace/ghidra-smoke.s"
    assert fixture["source_size"] == source_fixture.stat().st_size
    assert fixture["source_sha256"] == hashlib.sha256(
        source_fixture.read_bytes()
    ).hexdigest()
    assert fixture["binary_md5_identity"] == (
        lovelace_builder.GHIDRA_FIXTURE_MD5
    )
    assert fixture["binary_sha256"] == (
        lovelace_builder.GHIDRA_FIXTURE_SHA256
    )
    assert fixture["semantic_script"] == (
        f"{lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_PATH}/"
        f"{lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_NAME}"
    )
    assert fixture["semantic_script_sha256"] == (
        lovelace_builder.digest_file(installed_script)
    )
    assert fixture["semantic_marker"] == (
        lovelace_builder.GHIDRA_SEMANTIC_MARKER
    )
    manifest = evidence_fixture_manifest()
    ghidra_lock = lovelace_builder.load_object(
        lovelace_builder.RELEASE_ROOT / "ghidra-lock.json"
    )
    lovelace_builder.validate_ghidra_manifest_records(
        manifest, ghidra_lock
    )
    manifest["ghidra_fixture"]["semantic_script_sha256"] = "0" * 64
    expect_lovelace_error(
        lambda: lovelace_builder.validate_ghidra_manifest_records(
            manifest, ghidra_lock
        ),
        "Ghidra fixture record is invalid",
    )


def evidence_input_verification(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    return {
        "schema": "wucios.lovelace.build_verification.v1",
        "status": "pass",
        "release_id": vector["release_id"],
        "artifacts": vector["artifacts"],
        "package_count": manifest["input_snapshot"]["package_count"],
        "offline_package_install": True,
        "base_image_read_only": True,
        "ext4_check": "pass",
        "runtime_marker": lovelace_builder.runtime_marker(),
        "required_runtime_paths": "pass",
        "boot": "NOT_MEASURED",
        "ghidra_headless": "NOT_MEASURED",
        "validation_evidence": {},
        "authoritative_for_release": False,
        "non_claims": manifest["non_claims"],
    }


def bind_functional_console_transcript(
    runtime: dict[str, Any],
    transcript: bytes,
    *,
    dispatch_offset: int | None = None,
) -> None:
    ready = (lovelace_builder.CONSOLE_MARKER + "\n").encode("ascii")
    ready_start = transcript.find(ready)
    assert ready_start >= 0
    ready_line_end_offset = ready_start + len(ready)
    if dispatch_offset is None:
        dispatch_offset = ready_line_end_offset
    runtime.update(
        {
            "console_bytes": len(transcript),
            "console_transcript_base64": base64.b64encode(transcript).decode(
                "ascii"
            ),
            "console_ready_line_end_offset": ready_line_end_offset,
            "command_dispatch_offset": dispatch_offset,
            "console_sha256": hashlib.sha256(transcript).hexdigest(),
            "console_tail": transcript.decode(
                "utf-8", errors="replace"
            )[-12000:],
        }
    )


def evidence_runtime(markers: list[str]) -> dict[str, Any]:
    transcript = ("\n".join(markers) + "\n").encode("ascii")
    runtime = {
        "status": "pass",
        "qemu_exit": 0,
        "markers": markers,
        "console_eof_observed": True,
        "console_drain_timeout_seconds": (
            lovelace_builder.FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS
        ),
        "functional_accelerator": "tcg",
        "functional_cpu_model": lovelace_builder.TCG_CPU_MODEL,
        "functional_kernel_arguments": (
            lovelace_builder.expected_functional_kernel_arguments()
        ),
        "forbidden_diagnostics_absent": True,
        "isolation_claim": False,
    }
    bind_functional_console_transcript(runtime, transcript)
    return runtime


def boot_evidence_fixture(manifest: dict[str, Any]) -> dict[str, Any]:
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    base_sha256 = vector["artifacts"]["base_image"]["sha256"]
    return {
        "schema": "wucios.lovelace.boot_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": base_sha256,
        "base_image_sha256_before": base_sha256,
        "base_image_sha256_after": base_sha256,
        "base_image_unchanged": True,
        "storage": "volatile",
        "network": "none",
        "functional_accelerator": "tcg",
        "isolation_claim": False,
        "input_verification": evidence_input_verification(manifest),
        "runtime": evidence_runtime(
            [
                lovelace_builder.OFFLINE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                lovelace_builder.LANGUAGE_MARKER,
                lovelace_builder.WUCIJI_MARKER,
                lovelace_builder.NOXFRAME_MARKER,
                lovelace_builder.GHIDRA_PRESENT_MARKER,
            ]
        ),
    }


def hostile_materialized_plan_fixture(
    vector: dict[str, Any],
    executables: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    sandbox = (
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,"
        "resourcecontrol=deny"
    )
    state_root = REPO / "build/wuci-lab"
    volatile = state_root / "volatile"
    root_disk = volatile / ".wuci-volatile.fixture.qcow2"
    release = Path("/tmp/lovelace-hostile-fixture/release")
    paths = {
        name: release / vector["artifacts"][name]["filename"]
        for name in ("base_image", "kernel", "initramfs")
    }
    inputs = {
        "kernel": {
            "path": str(paths["kernel"]),
            "sha256": vector["artifacts"]["kernel"]["sha256"],
            "size": vector["artifacts"]["kernel"]["size"],
            "mode": "0644",
        },
        "initrd": {
            "path": str(paths["initramfs"]),
            "sha256": vector["artifacts"]["initramfs"]["sha256"],
            "size": vector["artifacts"]["initramfs"]["size"],
            "mode": "0644",
        },
        "base_image": {
            "path": str(paths["base_image"]),
            "sha256": vector["artifacts"]["base_image"]["sha256"],
            "size": vector["artifacts"]["base_image"]["size"],
            "mode": "0444",
        },
    }
    binding_triples = [
        (
            "/usr/bin/qemu-system-x86_64",
            "/usr/bin/qemu-system-x86_64",
            "file",
        ),
        (
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "directory",
        ),
        ("/usr/share/qemu", "/usr/share/qemu", "directory"),
        ("/usr/share/seabios", "/usr/share/seabios", "directory"),
        (
            "/usr/lib/x86_64-linux-gnu",
            "/lib/x86_64-linux-gnu",
            "directory",
        ),
        (
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/lib64/ld-linux-x86-64.so.2",
            "file",
        ),
        ("/etc/ld.so.cache", "/etc/ld.so.cache", "file"),
        (str(paths["kernel"]), str(paths["kernel"]), "file"),
        (str(paths["initramfs"]), str(paths["initramfs"]), "file"),
        (str(paths["base_image"]), str(paths["base_image"]), "file"),
    ]
    read_only_bindings: list[dict[str, Any]] = []
    for index, (source, destination, kind) in enumerate(binding_triples):
        if index == 0:
            qemu = executables["qemu"]
            metadata = {
                field: qemu[field]
                for field in (
                    "device",
                    "inode",
                    "links",
                    "size",
                    "mtime_ns",
                    "ctime_ns",
                    "mode",
                )
            }
        elif index >= 7:
            input_name = ("kernel", "initrd", "base_image")[index - 7]
            metadata = {
                "device": 8,
                "inode": 300 + index,
                "links": 1,
                "size": inputs[input_name]["size"],
                "mtime_ns": 1,
                "ctime_ns": 1,
                "mode": inputs[input_name]["mode"],
            }
        else:
            metadata = {
                "device": 8,
                "inode": 300 + index,
                "links": 1,
                "size": 4096,
                "mtime_ns": 1,
                "ctime_ns": 1,
                "mode": (
                    "0755"
                    if kind == "directory" or index == 5
                    else "0644"
                ),
            }
        read_only_bindings.append(
            {
                "source": source,
                "destination": destination,
                "kind": kind,
                **metadata,
            }
        )

    directories = {
        Path("/dev"),
        Path("/proc"),
        Path("/run"),
        Path("/sys"),
        Path("/tmp"),
        Path("/var"),
        Path("/var/tmp"),
        volatile,
    }
    for _source, destination_value, kind in binding_triples:
        destination = Path(destination_value)
        current = destination if kind == "directory" else destination.parent
        while current != Path("/"):
            directories.add(current)
            current = current.parent
    current = volatile
    while current != Path("/"):
        directories.add(current)
        current = current.parent
    directory_skeleton = [
        str(path)
        for path in sorted(
            directories, key=lambda item: (len(item.parts), str(item))
        )
    ]

    qemu_argv = [
        "/usr/bin/qemu-system-x86_64",
        "-nodefaults",
        "-no-user-config",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        str(lovelace_builder.HOSTILE_MEMORY_MIB),
        "-smp",
        str(lovelace_builder.HOSTILE_CPUS),
        "-name",
        "wuci-lab-hostile,debug-threads=on",
        "-sandbox",
        sandbox,
        "-monitor",
        "none",
        "-nographic",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-kernel",
        str(paths["kernel"]),
        "-initrd",
        str(paths["initramfs"]),
        "-append",
        " ".join(lovelace_builder.expected_release_kernel_arguments()),
        "-drive",
        (
            f"file={root_disk},if=none,id=wuci-root,format=qcow2,"
            "cache=writeback,aio=threads"
        ),
        "-device",
        "virtio-blk-pci,drive=wuci-root,bootindex=1",
        "-nic",
        "none",
    ]
    outer_environment = {
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin",
        "XDG_CONFIG_HOME": "/tmp",
    }
    outer_argv = [
        "/usr/bin/bwrap",
        *lovelace_builder.HOSTILE_BWRAP_FLAGS,
        "--cap-drop",
        "ALL",
        "--hostname",
        "wuci-hostile",
        "--clearenv",
        "--perms",
        "0700",
        "--tmpfs",
        "/",
    ]
    for directory in directory_skeleton:
        outer_argv.extend(["--dir", directory])
    outer_argv.extend(
        [
            "--dev",
            "/dev",
            "--dev-bind",
            "/dev/kvm",
            "/dev/kvm",
            "--proc",
            "/proc",
        ]
    )
    for destination in ("/tmp", "/run", "/var/tmp"):
        outer_argv.extend(["--perms", "0700", "--tmpfs", destination])
    for record in read_only_bindings:
        outer_argv.extend(
            ["--ro-bind", record["source"], record["destination"]]
        )
    outer_argv.extend(
        [
            "--bind",
            str(root_disk),
            str(root_disk),
            "--remount-ro",
            "/",
            "--chdir",
            "/tmp",
        ]
    )
    for key, value in outer_environment.items():
        outer_argv.extend(["--setenv", key, value])
    outer_argv.extend(["--", *qemu_argv])

    limits = lovelace_builder.hostile_resource_limits(vector)
    materialized_plan = {
        "schema": "wuci.lab.launch-plan.v1",
        "decision": "launch-plan-valid",
        "argv_materialized": True,
        "profile": "hostile",
        "supervisor": {
            "state_root": str(state_root),
            "qemu_path": "/usr/bin/qemu-system-x86_64",
            "qemu_img_path": "/usr/bin/qemu-img",
            "mke2fs_path": None,
            "mke2fs_version": None,
            "debugfs_path": None,
            "debugfs_version": None,
            "bubblewrap_path": "/usr/bin/bwrap",
        },
        "inputs": inputs,
        "payload_ingress": None,
        "storage": {
            "mode": "volatile",
            "root_disk": str(root_disk),
            "deferred_root_disk_token": None,
            "root_format": "qcow2",
            "base_image_mutated": False,
            "qemu_temporary_snapshot": False,
            "explicit_private_volatile_overlay": True,
            "volatile_overlay_deferred_until_real_launch": False,
            "volatile_overlay_cleanup_on_supervisor_unwind": True,
            "volatile_overlay_cleanup_after_sigkill_or_host_crash": False,
            "guest_writes_persist": False,
            "overlay": {
                "path": str(root_disk),
                "format": "qcow2",
                "allocated_file_size": 196616,
                "virtual_size": vector["artifacts"]["base_image"]["size"],
                "base_path": str(paths["base_image"]),
                "base_sha256": vector["artifacts"]["base_image"]["sha256"],
                "single_link_regular_file": True,
                "private_permissions": True,
                "cleanup_on_supervisor_unwind": True,
                "cleanup_after_sigkill_or_host_crash_claimed": False,
            },
        },
        "network": {
            "mode": "none",
            "guest_internet_enabled": False,
            "inbound_host_forwarding": False,
            "host_shares": False,
        },
        "acceleration": {
            "selected": "kvm",
            "tcg_fallback": False,
            "label": "KVM REQUIRED (hostile fail-closed profile)",
        },
        "resources": {
            "memory_mib": lovelace_builder.HOSTILE_MEMORY_MIB,
            "cpus": lovelace_builder.HOSTILE_CPUS,
            "limits": {
                "memory_mib": [512, 16384],
                "cpus": [1, 8],
            },
        },
        "controls": {
            "direct_kernel_boot": True,
            "q35_machine": True,
            "nodefaults": True,
            "no_user_config": True,
            "monitor_disabled": True,
            "serial_stdio": True,
            "hostile_console_rendering": "escaped-ascii",
            "hostile_console_forwarded_byte_allowlist": list(
                lovelace_builder.HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST
            ),
            "hostile_non_allowlisted_console_bytes_forwarded": False,
            "hostile_console_stderr_merged": True,
            "hostile_console_byte_limit": (
                lovelace_builder.MAX_HOSTILE_CONSOLE_BYTES
            ),
            "hostile_console_input_buffer_byte_limit": (
                lovelace_builder.MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES
            ),
            "hostile_stdin_one_way_pipe": True,
            "hostile_tty_restoration_on_handled_exit": True,
            "hostile_tty_input_flushed_before_handoff": True,
            "hostile_process_group_absence_checked": True,
            "hostile_handled_signals": [
                "SIGHUP",
                "SIGINT",
                "SIGQUIT",
                "SIGTERM",
                "SIGTSTP",
            ],
            "hostile_console_descendant_drain_timeout_seconds": 5,
            "hostile_console_leader_exit_confirm_timeout_seconds": (
                lovelace_builder.HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS
            ),
            "qemu_sandbox": sandbox,
            "host_shares": False,
            "shell": False,
            "sanitized_environment": True,
            "hostile_requires_kvm": True,
            "hostile_requires_non_root": True,
            "hostile_outer_bubblewrap": True,
            "empty_private_host_root": True,
            "host_network_namespace_unshared": True,
            "exact_read_only_host_bindings": True,
            "volatile_overlay_only_read_write_binding": True,
            "exact_kvm_device_binding": True,
            "hostile_payload_read_only_secondary_media": False,
            "hostile_payload_host_source_shared": False,
            "hostile_payload_host_execution": False,
            "explicit_host_resource_limits": True,
            "implicit_qemu_snapshot": False,
            "explicit_private_volatile_overlay": True,
        },
        "outer_boundary": {
            "supervisor": "bubblewrap",
            "path": "/usr/bin/bwrap",
            "empty_private_root": True,
            "root_read_only_after_setup": True,
            "namespace_flags": list(
                lovelace_builder.HOSTILE_BWRAP_FLAGS
            ),
            "private_tmpfs": ["/tmp", "/run", "/var/tmp"],
            "read_only_bindings": read_only_bindings,
            "read_write_bindings": [
                {
                    "source": str(root_disk),
                    "destination": str(root_disk),
                    "purpose": "private volatile qcow2 overlay only",
                    "materialized": True,
                }
            ],
            "device_bindings": [
                {"source": "/dev/kvm", "destination": "/dev/kvm"}
            ],
            "directory_skeleton": directory_skeleton,
            "environment": outer_environment,
            "host_network_namespace_unshared": True,
            "host_resource_limits": {
                "applied_before_bubblewrap_exec": True,
                "inherited_by_qemu": True,
                "limits": limits,
            },
        },
        "host_resource_limits": limits,
        "qemu_argv": qemu_argv,
        "argv": outer_argv,
        "environment": {
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "XDG_CONFIG_HOME": "/nonexistent",
        },
        "claims": {
            "production_ready_claimed": False,
            "runtime_sandbox_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
            "hypervisor_escape_impossible_claimed": False,
        },
        "nonclaims": list(
            lovelace_builder.HOSTILE_SUPERVISOR_NONCLAIMS
        ),
    }
    summary, _root_disk = lovelace_builder.hostile_plan_summary(
        materialized_plan,
        paths,
        vector,
        state_root,
        inspect_artifacts=False,
    )
    return materialized_plan, summary


def hostile_evidence_fixture(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    base_sha256 = vector["artifacts"]["base_image"]["sha256"]
    empty_snapshot = hashlib.sha256(
        lovelace_builder.canonical_json([])
    ).hexdigest()
    executables = {
        name: {
            "path": path,
            "size": 4096,
            "sha256": digest_character * 64,
            "mode": "0755",
            "uid": 0,
            "gid": 0,
            "device": 8,
            "inode": 100 + index,
            "links": 1,
            "mtime_ns": 1,
            "ctime_ns": 1,
            "setuid": False,
            "setgid": False,
            "executable": True,
            "version": f"{name} fixture version",
        }
        for index, (name, path, digest_character) in enumerate((
            ("qemu", "/usr/bin/qemu-system-x86_64", "1"),
            ("qemu_img", "/usr/bin/qemu-img", "2"),
            ("bubblewrap", "/usr/bin/bwrap", "3"),
        ))
    }
    materialized_plan, plan_summary = hostile_materialized_plan_fixture(
        vector, executables
    )
    qemu_argv = materialized_plan["qemu_argv"]
    challenge = "9" * 64
    result_markers = [
        lovelace_builder.HOSTILE_NETWORK_MARKER,
        lovelace_builder.HOSTILE_WUCIJI_MARKER,
        lovelace_builder.HOSTILE_NOXFRAME_RESULT_MARKER,
        lovelace_builder.GHIDRA_SEMANTIC_MARKER,
        lovelace_builder.HOSTILE_GHIDRA_MARKER,
        lovelace_builder.HOSTILE_CELL_MARKER,
    ]
    command_results = [
        f"{marker} {challenge}" for marker in result_markers
    ]
    predispatch_transcript = (
        lovelace_builder.canonical_json(materialized_plan).decode("ascii")
        + lovelace_builder.HOSTILE_BOOT_LINE
        + "\n"
        + lovelace_builder.CONSOLE_MARKER
        + "\n"
    )
    dispatch_offset = len(predispatch_transcript.encode("ascii"))
    runtime_lines = [
        *command_results[:4],
        lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER,
        *command_results[4:],
    ]
    console_transcript = predispatch_transcript + "\n".join(
        runtime_lines
    ) + "\n"
    console_bytes = console_transcript.encode("ascii")
    return {
        "schema": "wucios.lovelace.hostile_kvm_cell_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": base_sha256,
        "base_image_sha256_before": base_sha256,
        "base_image_sha256_after": base_sha256,
        "base_image_unchanged": True,
        "profile": "hostile",
        "execution_class": "defensive-untrusted-system-code",
        "storage": "volatile",
        "network": "none",
        "functional_accelerator": "kvm",
        "isolation_claim": True,
        "claim_scope": "local-kvm-bwrap-layered-control-presence",
        "required_layers": list(lovelace_builder.HOSTILE_REQUIRED_LAYERS),
        "layers": {
            layer: True
            for layer in lovelace_builder.HOSTILE_REQUIRED_LAYERS
        },
        "input_verification": evidence_input_verification(manifest),
        "host": {
            "effective_uid": 1000,
            "kvm_device": {
                "path": "/dev/kvm",
                "character_device": True,
                "root_owned": True,
                "device_major": 10,
                "device_minor": 232,
                "mode": "0660",
                "world_readable": False,
                "world_writable": False,
                "readable": True,
                "writable": True,
            },
            "executables": executables,
            "executables_stable_before_after": True,
        },
        "launch_plan": plan_summary,
        "cleanup": {
            "materialized_overlay_absent": True,
            "volatile_directory_unchanged": True,
            "entries_before_sha256": empty_snapshot,
            "entries_after_sha256": empty_snapshot,
            "normal_supervisor_unwind": True,
            "cleanup_after_sigkill_or_host_crash_claimed": False,
        },
        "runtime": {
            "status": "pass",
            "supervisor_exit": 0,
            "markers": [
                lovelace_builder.BOOT_MARKER,
                lovelace_builder.CONSOLE_MARKER,
            ],
            "challenge": challenge,
            "command_results": command_results,
            "command_results_after_dispatch": True,
            "command_dispatch_offset": dispatch_offset,
            "challenge_generated_after_predispatch_validation": True,
            "challenge_absent_before_dispatch": True,
            "exact_boot_line_validated": True,
            "complete_result_lines_validated": True,
            "console_sha256": hashlib.sha256(console_bytes).hexdigest(),
            "console_transcript": console_transcript,
            "console_transcript_bytes": len(console_bytes),
            "console_transcript_complete": True,
            "console_tail": console_transcript[-12000:],
            "forbidden_diagnostics_absent": True,
            "console_ready_timeout_seconds": (
                lovelace_builder.HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS
            ),
            "console_rendering": "escaped-ascii",
            "console_forwarded_byte_allowlist": list(
                lovelace_builder.HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST
            ),
            "non_allowlisted_console_bytes_forwarded": False,
            "console_sha256_scope": (
                "escaped-ascii-supervisor-transcript"
            ),
            "plan_emitted_before_guest_console": True,
            "plan_validated_before_guest_command_dispatch": True,
            "qemu_process_absent_after_supervisor_exit": True,
            "qemu_process": {
                "observed": True,
                "executable": "/usr/bin/qemu-system-x86_64",
                "host_pid": 1234,
                "process_group_id": 1233,
                "session_id": 1232,
                "start_time_ticks": 123456,
                "executable_device": executables["qemu"]["device"],
                "executable_inode": executables["qemu"]["inode"],
                "cmdline_sha256": hashlib.sha256(
                    lovelace_builder.canonical_json(qemu_argv)
                ).hexdigest(),
                "host_uids": [1000, 1000, 1000, 1000],
                "all_host_uids_equal_nonzero": True,
                "effective_capabilities_hex": "0000000000000000",
                "capabilities_empty": True,
                "no_new_privileges": True,
                "seccomp_mode": 2,
                "seccomp_filters": 1,
                "namespaces": {
                    name: {
                        "producer": f"{name}:[100]",
                        "qemu": f"{name}:[200]",
                        "different": True,
                    }
                    for name in (
                        "mnt",
                        "user",
                        "pid",
                        "ipc",
                        "uts",
                        "cgroup",
                        "net",
                    )
                },
            },
        },
        "claims": {
            "authoritative_for_release": False,
            "production_ready_claimed": False,
            "perfect_isolation_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
            "hypervisor_escape_impossible_claimed": False,
            "side_channel_confidentiality_claimed": False,
        },
        "non_claims": list(
            lovelace_builder.HOSTILE_EVIDENCE_NONCLAIMS
        ),
    }


def hostile_payload_tool_fixture() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "path": path,
            "size": 4096,
            "sha256": digest_character * 64,
            "mode": "0755",
            "uid": 0,
            "gid": 0,
            "device": 8,
            "inode": 500 + index,
            "links": 1,
            "mtime_ns": 1,
            "ctime_ns": 1,
            "setuid": False,
            "setgid": False,
            "executable": True,
            "version": (
                f"{name} {lovelace_builder.EXPECTED_E2FSPROGS_VERSION} "
                "(5-Feb-2023)"
            ),
        }
        for index, (name, path, digest_character) in enumerate(
            (
                ("mke2fs", "/usr/sbin/mke2fs", "4"),
                ("debugfs", "/usr/sbin/debugfs", "5"),
            )
        )
    }


def hostile_payload_evidence_fixture(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    ordinary = hostile_evidence_fixture(manifest)
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    materialized = copy.deepcopy(
        ordinary["launch_plan"]["materialized_plan"]
    )
    payload_tools = hostile_payload_tool_fixture()
    source = lovelace_builder.hostile_payload_fixture_record()
    state_root = REPO / "build/wuci-lab"
    media_path = (
        state_root
        / "payloads/.wuci-payload.fixture99/payload.ext4"
    )
    media = {
        "path": str(media_path),
        "sha256": "6" * 64,
        "size": lovelace_builder.hostile_payload_media_size(),
        "mode": "0400",
        "format": "raw-ext4",
        "filesystem_uuid": (
            lovelace_builder.hostile_payload_filesystem_uuid()
        ),
        "guest_device": lovelace_builder.HOSTILE_PAYLOAD_GUEST_DEVICE,
        "qemu_read_only": True,
        "host_mode": "0400",
    }
    report = {
        "schema": lovelace_builder.HOSTILE_PAYLOAD_SCHEMA,
        "source": source,
        "manifest": lovelace_builder.hostile_payload_manifest(source),
        "semantic_readback": (
            lovelace_builder.hostile_payload_semantic_readback(
                source, Path(payload_tools["debugfs"]["path"])
            )
        ),
        "media": media,
        "cleanup_on_supervisor_unwind": True,
        "cleanup_after_sigkill_or_host_crash_claimed": False,
    }
    materialized["supervisor"].update(
        {
            "mke2fs_path": "/usr/sbin/mke2fs",
            "mke2fs_version": (
                lovelace_builder.EXPECTED_E2FSPROGS_VERSION
            ),
            "debugfs_path": "/usr/sbin/debugfs",
            "debugfs_version": (
                lovelace_builder.EXPECTED_E2FSPROGS_VERSION
            ),
        }
    )
    materialized["payload_ingress"] = {
        "schema": lovelace_builder.HOSTILE_PAYLOAD_SCHEMA,
        "source": source,
        "media": report,
        "deferred_media_token": None,
        "guest_device": lovelace_builder.HOSTILE_PAYLOAD_GUEST_DEVICE,
        "guest_media_path": lovelace_builder.HOSTILE_PAYLOAD_GUEST_MEDIA,
        "guest_read_only": True,
        "host_source_shared": False,
        "host_execution": False,
        "bounded_source_bytes": (
            lovelace_builder.MAX_HOSTILE_PAYLOAD_BYTES
        ),
        "cleanup_on_supervisor_unwind": True,
        "cleanup_after_sigkill_or_host_crash_claimed": False,
    }
    materialized["controls"][
        "hostile_payload_read_only_secondary_media"
    ] = True
    payload_binding = {
        "source": str(media_path),
        "destination": lovelace_builder.HOSTILE_PAYLOAD_GUEST_MEDIA,
        "kind": "file",
        "device": 8,
        "inode": 700,
        "links": 1,
        "size": media["size"],
        "mtime_ns": 1,
        "ctime_ns": 1,
        "mode": "0400",
        "purpose": "guest-read-only hostile payload media",
        "materialized": True,
    }
    materialized["outer_boundary"]["read_only_bindings"].append(
        payload_binding
    )
    qemu_argv = materialized["qemu_argv"]
    network_offset = qemu_argv.index("-nic")
    qemu_argv[network_offset:network_offset] = [
        "-drive",
        (
            f"file={lovelace_builder.HOSTILE_PAYLOAD_GUEST_MEDIA},"
            "if=none,id=wuci-payload,format=raw,readonly=on,"
            "cache=writeback,aio=threads"
        ),
        "-device",
        "virtio-blk-pci,drive=wuci-payload",
    ]
    outer_argv = materialized["argv"]
    separator = outer_argv.index("--")
    outer_prefix = outer_argv[:separator]
    writable_offset = outer_prefix.index("--bind")
    outer_prefix[writable_offset:writable_offset] = [
        "--ro-bind",
        str(media_path),
        lovelace_builder.HOSTILE_PAYLOAD_GUEST_MEDIA,
    ]
    materialized["argv"] = [*outer_prefix, "--", *qemu_argv]
    plan_summary, _root_disk, _media_path = (
        lovelace_builder.hostile_payload_plan_summary(
            materialized,
            {
                "kernel": Path(materialized["inputs"]["kernel"]["path"]),
                "initramfs": Path(
                    materialized["inputs"]["initrd"]["path"]
                ),
                "base_image": Path(
                    materialized["inputs"]["base_image"]["path"]
                ),
            },
            vector,
            state_root,
            payload_tools,
            payload_uid=1000,
            payload_gid=1000,
            inspect_artifacts=False,
        )
    )
    challenge = "8" * 64
    command_results = [
        f"{marker} {challenge}"
        for marker in (
            lovelace_builder.HOSTILE_PAYLOAD_BYTES_MARKER,
            lovelace_builder.HOSTILE_PAYLOAD_MANIFEST_MARKER,
            lovelace_builder.HOSTILE_PAYLOAD_MARKER,
        )
    ]
    predispatch = (
        lovelace_builder.canonical_json(materialized).decode("ascii")
        + lovelace_builder.HOSTILE_BOOT_LINE
        + "\n"
        + lovelace_builder.CONSOLE_MARKER
        + "\n"
    )
    transcript = predispatch + "\n".join(command_results) + "\n"
    transcript_bytes = transcript.encode("ascii")
    runtime = copy.deepcopy(ordinary["runtime"])
    runtime.update(
        {
            "challenge": challenge,
            "command_results": command_results,
            "command_dispatch_offset": len(predispatch.encode("ascii")),
            "console_sha256": hashlib.sha256(transcript_bytes).hexdigest(),
            "console_transcript": transcript,
            "console_transcript_bytes": len(transcript_bytes),
            "console_tail": transcript[-12000:],
        }
    )
    runtime["qemu_process"]["cmdline_sha256"] = plan_summary[
        "qemu_argv_sha256"
    ]
    empty_snapshot = hashlib.sha256(
        lovelace_builder.canonical_json([])
    ).hexdigest()
    evidence = copy.deepcopy(ordinary)
    evidence.update(
        {
            "schema": (
                "wucios.lovelace.hostile_payload_ingress_evidence.v1"
            ),
            "execution_class": "fixed-benign-hostile-payload-ingress",
            "isolation_claim": False,
            "claim_scope": (
                "local-kvm-bwrap-fixed-benign-read-only-payload-ingress"
            ),
            "required_layers": list(
                lovelace_builder.HOSTILE_PAYLOAD_REQUIRED_LAYERS
            ),
            "layers": {
                layer: True
                for layer in lovelace_builder.HOSTILE_PAYLOAD_REQUIRED_LAYERS
            },
            "host": {
                **ordinary["host"],
                "effective_gid": 1000,
                "payload_tools": payload_tools,
            },
            "launch_plan": plan_summary,
            "guest_command_contract": (
                lovelace_builder.hostile_payload_guest_command_contract(
                    challenge
                )
            ),
            "cleanup": {
                "materialized_overlay_absent": True,
                "payload_media_absent": True,
                "volatile_directory_unchanged": True,
                "payload_directory_unchanged": True,
                "volatile_entries_before_sha256": empty_snapshot,
                "volatile_entries_after_sha256": empty_snapshot,
                "payload_entries_before_sha256": empty_snapshot,
                "payload_entries_after_sha256": empty_snapshot,
                "normal_supervisor_unwind": True,
                "cleanup_after_sigkill_or_host_crash_claimed": False,
            },
            "runtime": runtime,
        }
    )
    return evidence


def assert_hostile_payload_lane_contract(tmp: Path) -> None:
    contract = lovelace_builder.VALIDATION_CONTRACT[
        "hostile_payload_ingress"
    ]
    assert contract == {
        "measured_status": (
            "locally-validated-kvm-fixed-benign-read-only-payload-ingress"
        ),
        "evidence_path": "evidence/hostile-payload-ingress.json",
        "evidence_schema": (
            "wucios.lovelace.hostile_payload_ingress_evidence.v1"
        ),
    }
    assert list(lovelace_builder.HOSTILE_PAYLOAD_REQUIRED_LAYERS) == [
        *lovelace_builder.HOSTILE_REQUIRED_LAYERS,
        "fixed-benign-payload-fixture-bound",
        "supervisor-payload-sha256-bound",
        "exact-trusted-debugfs-semantic-readback",
        "guest-payload-and-manifest-bytes-verified",
        "guest-read-only-mount-and-write-rejection",
        "payload-media-cleanup-observed",
    ]
    source = lovelace_builder.hostile_payload_fixture_record()
    manifest_bytes = lovelace_builder.canonical_json(
        lovelace_builder.hostile_payload_manifest(source)
    )
    assert len(manifest_bytes) == 527
    assert hashlib.sha256(manifest_bytes).hexdigest() == (
        "4cf11e8d73cfa687af0f8f546071ecfdd759d63b587cf6a6f3e548b24e13b01b"
    )

    challenge = "7" * 64
    commands, results = lovelace_builder.hostile_payload_guest_commands(
        challenge
    )
    assert len(commands) == 4
    assert results == [
        f"{lovelace_builder.HOSTILE_PAYLOAD_BYTES_MARKER} {challenge}",
        f"{lovelace_builder.HOSTILE_PAYLOAD_MANIFEST_MARKER} {challenge}",
        f"{lovelace_builder.HOSTILE_PAYLOAD_MARKER} {challenge}",
    ]
    for command in commands:
        parsed = subprocess.run(
            ["/bin/sh", "-n", "-c", command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
            timeout=10,
        )
        assert parsed.returncode == 0, parsed.stderr
    assert "mount -t ext4 -o ro,nodev,nosuid,noexec" in commands[0]
    assert "test ! -e \"$probe\"" in commands[2]
    assert commands[2].count("sha256sum") == 1
    assert "if printf x" in commands[2]
    assert "if touch \"$probe\" 2>/dev/null; then exit 1; fi" in commands[2]
    assert "if : 2>/dev/null > \"$probe\"" not in commands[2]
    write_rejection_probe = (
        "set -eu; probe=/dev/null/wuci-lovelace-read-only-probe; "
        "if touch \"$probe\" 2>/dev/null; then exit 1; fi; "
        "test ! -e \"$probe\"; printf probe-survived"
    )
    shell_paths = [["/bin/sh", "-c", write_rejection_probe]]
    busybox = shutil.which("busybox")
    if busybox is not None:
        shell_paths.append([busybox, "ash", "-c", write_rejection_probe])
    for shell_argv in shell_paths:
        rejected_write = subprocess.run(
            shell_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
            timeout=10,
        )
        assert rejected_write.returncode == 0, rejected_write.stderr
        assert rejected_write.stdout == "probe-survived"
    command_contract = (
        lovelace_builder.hostile_payload_guest_command_contract(challenge)
    )
    assert command_contract[
        "guest_root_write_rejected_and_probe_absent"
    ] is True
    assert command_contract[
        "payload_reverified_after_write_rejection"
    ] is True

    manifest = evidence_fixture_manifest()
    evidence = hostile_payload_evidence_fixture(manifest)
    lovelace_builder.validate_evidence_document(
        evidence, evidence["schema"], manifest, "hostile payload fixture"
    )
    assert evidence["isolation_claim"] is False
    assert evidence["claims"]["safe_for_arbitrary_malware_claimed"] is False

    unsafe_claim = copy.deepcopy(evidence)
    unsafe_claim["claims"]["safe_for_arbitrary_malware_claimed"] = True
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            unsafe_claim,
            unsafe_claim["schema"],
            manifest,
            "unsafe hostile payload claim",
        ),
        "claim boundary differs",
    )
    missing_probe = copy.deepcopy(evidence)
    del missing_probe["guest_command_contract"][
        "guest_root_write_rejected_and_probe_absent"
    ]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            missing_probe,
            missing_probe["schema"],
            manifest,
            "hostile payload missing probe proof",
        ),
        "guest-command contract differs",
    )
    duplicate_result = copy.deepcopy(evidence)
    duplicate_line = duplicate_result["runtime"]["command_results"][0]
    duplicate_transcript = (
        duplicate_result["runtime"]["console_transcript"]
        + duplicate_line
        + "\n"
    )
    encoded = duplicate_transcript.encode("ascii")
    duplicate_result["runtime"].update(
        {
            "console_transcript": duplicate_transcript,
            "console_transcript_bytes": len(encoded),
            "console_sha256": hashlib.sha256(encoded).hexdigest(),
            "console_tail": duplicate_transcript[-12000:],
        }
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            duplicate_result,
            duplicate_result["schema"],
            manifest,
            "hostile payload duplicate result",
        ),
        "complete result-line binding differs",
    )

    materialized = evidence["launch_plan"]["materialized_plan"]
    ordinary_rejection_plan = copy.deepcopy(materialized)
    ordinary_rejection_plan["supervisor"].update(
        {
            "mke2fs_path": None,
            "mke2fs_version": None,
            "debugfs_path": None,
            "debugfs_version": None,
        }
    )
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    expect_lovelace_error(
        lambda: lovelace_builder.hostile_plan_summary(
            ordinary_rejection_plan,
            {
                "kernel": Path(materialized["inputs"]["kernel"]["path"]),
                "initramfs": Path(
                    materialized["inputs"]["initrd"]["path"]
                ),
                "base_image": Path(
                    materialized["inputs"]["base_image"]["path"]
                ),
            },
            vector,
            REPO / "build/wuci-lab",
            inspect_artifacts=False,
        ),
        "does not accept a payload",
    )

    media_build = tmp / "hostile-payload-media/build"
    media_build.mkdir(parents=True, mode=0o700)
    state_root = media_build / "state"
    bound_source = wuci_lab.validate_bound_file(
        lovelace_builder.HOSTILE_PAYLOAD_FIXTURE_PATH,
        lovelace_builder.HOSTILE_PAYLOAD_FIXTURE_SHA256,
        "fixed hostile payload fixture",
        max_bytes=lovelace_builder.MAX_HOSTILE_PAYLOAD_BYTES,
    )
    original_build_root = wuci_lab.BUILD_ROOT
    try:
        wuci_lab.BUILD_ROOT = media_build
        with wuci_lab.private_hostile_payload_media(
            state_root=state_root,
            source=bound_source,
            mke2fs_path=Path("/usr/sbin/mke2fs"),
            debugfs_path=Path("/usr/sbin/debugfs"),
        ) as report:
            validated = (
                lovelace_builder.validate_hostile_payload_media_report(
                    report,
                    source=source,
                    state_root=state_root,
                    debugfs_path=Path("/usr/sbin/debugfs"),
                    payload_uid=os.geteuid(),
                    payload_gid=os.getegid(),
                    inspect_media=True,
                )
            )
            assert validated["semantic_readback"]["manifest"] == {
                "guest_path": "/manifest.json",
                "size": 527,
                "sha256": (
                    "4cf11e8d73cfa687af0f8f546071ecfdd759d63b587cf6a6f"
                    "3e548b24e13b01b"
                ),
            }
            altered = copy.deepcopy(report)
            altered["semantic_readback"]["payload"]["sha256"] = "0" * 64
            expect_lovelace_error(
                lambda: (
                    lovelace_builder.validate_hostile_payload_media_report(
                        altered,
                        source=source,
                        state_root=state_root,
                        debugfs_path=Path("/usr/sbin/debugfs"),
                        payload_uid=os.geteuid(),
                        payload_gid=os.getegid(),
                        inspect_media=False,
                    )
                ),
                "media contract differs",
            )
    finally:
        wuci_lab.BUILD_ROOT = original_build_root
    assert list((state_root / "payloads").iterdir()) == []


def refresh_hostile_plan_digests(evidence: dict[str, Any]) -> None:
    summary = evidence["launch_plan"]
    materialized = summary["materialized_plan"]
    bindings = materialized["outer_boundary"]["read_only_bindings"]
    summary["source_plan_sha256"] = hashlib.sha256(
        lovelace_builder.canonical_json(materialized)
    ).hexdigest()
    summary["read_only_bindings_sha256"] = hashlib.sha256(
        lovelace_builder.canonical_json(bindings)
    ).hexdigest()
    summary["qemu_argv_sha256"] = hashlib.sha256(
        lovelace_builder.canonical_json(materialized["qemu_argv"])
    ).hexdigest()
    summary["outer_argv_sha256"] = hashlib.sha256(
        lovelace_builder.canonical_json(materialized["argv"])
    ).hexdigest()
    evidence["runtime"]["qemu_process"]["cmdline_sha256"] = summary[
        "qemu_argv_sha256"
    ]


def evidence_binding(
    evidence_path: Path,
    schema: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    return {
        "path": f"evidence/{evidence_path.name}",
        "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        "schema": schema,
        "base_image_sha256": vector["artifacts"]["base_image"]["sha256"],
        "artifact_vector_sha256": (
            lovelace_builder.canonical_object_sha256(vector)
        ),
    }


def assert_validation_evidence_binding(tmp: Path) -> None:
    release = tmp / "evidence-contract/release"
    evidence_directory = release / "evidence"
    release.mkdir(parents=True)
    manifest = evidence_fixture_manifest()
    paths = {
        "manifest": release / "manifest.json",
        "evidence": evidence_directory,
    }
    assert lovelace_builder.verify_validation_evidence(manifest, paths) == {}

    manifest["validation"]["boot"] = (
        "locally-validated-tcg-functional-only"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "promoted together",
    )
    manifest["validation"]["language_matrix"] = "locally-validated"
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "lacks evidence binding",
    )
    underspecified = {
        "schema": "wucios.lovelace.boot_evidence.v1",
        "status": "pass",
        "artifact_vector": (
            lovelace_builder.canonical_artifact_vector(manifest)
        ),
        "base_image_sha256": "a" * 64,
    }
    evidence_directory.mkdir()
    evidence_path = evidence_directory / "boot-test.json"
    write_json(evidence_path, underspecified)
    binding = evidence_binding(
        evidence_path,
        "wucios.lovelace.boot_evidence.v1",
        manifest,
    )
    manifest["validation_evidence"]["boot"] = dict(binding)
    manifest["validation_evidence"]["language_matrix"] = dict(binding)
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "keys differ",
    )

    evidence = boot_evidence_fixture(manifest)
    write_json(evidence_path, evidence)
    binding = evidence_binding(
        evidence_path,
        "wucios.lovelace.boot_evidence.v1",
        manifest,
    )
    manifest["validation_evidence"]["boot"] = dict(binding)
    manifest["validation_evidence"]["language_matrix"] = dict(binding)
    verified = lovelace_builder.verify_validation_evidence(manifest, paths)
    assert verified == {
        "boot": binding,
        "language_matrix": binding,
    }

    unbacked_nested = copy.deepcopy(evidence)
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    unbacked_nested["input_verification"]["validation_evidence"] = {
        "hostile_kvm_cell": {
            "path": "evidence/hostile-kvm-cell.json",
            "sha256": "3" * 64,
            "schema": "wucios.lovelace.hostile_kvm_cell_evidence.v1",
            "base_image_sha256": vector["artifacts"]["base_image"][
                "sha256"
            ],
            "artifact_vector_sha256": (
                lovelace_builder.canonical_object_sha256(vector)
            ),
        }
    }
    write_json(evidence_path, unbacked_nested)
    unbacked_binding = evidence_binding(
        evidence_path,
        "wucios.lovelace.boot_evidence.v1",
        manifest,
    )
    manifest["validation_evidence"]["boot"] = dict(unbacked_binding)
    manifest["validation_evidence"]["language_matrix"] = dict(
        unbacked_binding
    )
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "must exclude nested runtime validation evidence",
    )
    write_json(evidence_path, evidence)
    binding = evidence_binding(
        evidence_path,
        "wucios.lovelace.boot_evidence.v1",
        manifest,
    )
    manifest["validation_evidence"]["boot"] = dict(binding)
    manifest["validation_evidence"]["language_matrix"] = dict(binding)

    original = evidence_path.read_bytes()
    evidence_schema = "wucios.lovelace.boot_evidence.v1"
    original_limit = (
        lovelace_builder.MAX_VALIDATION_EVIDENCE_BYTES_BY_SCHEMA[
            evidence_schema
        ]
    )
    try:
        lovelace_builder.MAX_VALIDATION_EVIDENCE_BYTES_BY_SCHEMA[
            evidence_schema
        ] = len(original) - 1
        expect_lovelace_error(
            lambda: lovelace_builder.verify_validation_evidence(
                manifest, paths
            ),
            "too large",
        )
    finally:
        lovelace_builder.MAX_VALIDATION_EVIDENCE_BYTES_BY_SCHEMA[
            evidence_schema
        ] = original_limit

    evidence_path.write_bytes(original + b" ")
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "digest differs",
    )
    evidence_path.write_bytes(original)

    for artifact in ("kernel", "initramfs"):
        stale_manifest = copy.deepcopy(manifest)
        stale_manifest["artifacts"][artifact]["sha256"] = "9" * 64
        stale_vector_sha256 = lovelace_builder.canonical_object_sha256(
            lovelace_builder.canonical_artifact_vector(stale_manifest)
        )
        for field in ("boot", "language_matrix"):
            stale_manifest["validation_evidence"][field][
                "artifact_vector_sha256"
            ] = stale_vector_sha256
        expect_lovelace_error(
            lambda stale_manifest=stale_manifest: (
                lovelace_builder.verify_validation_evidence(
                    stale_manifest, paths
                )
            ),
            "artifact vector differs",
        )

    extra = evidence_directory / "stale.json"
    extra.write_text("{}\n", encoding="ascii")
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "file set differs",
    )

    extra.unlink()
    evidence_path.unlink()
    expect_lovelace_error(
        lambda: lovelace_builder.verify_validation_evidence(manifest, paths),
        "file set differs",
    )

    hostile_release = tmp / "hostile-evidence-contract/release"
    hostile_directory = hostile_release / "evidence"
    hostile_directory.mkdir(parents=True)
    hostile_manifest = evidence_fixture_manifest()
    hostile_evidence = hostile_evidence_fixture(hostile_manifest)
    hostile_path = hostile_directory / "hostile-kvm-cell.json"
    write_json(hostile_path, hostile_evidence)
    hostile_binding = evidence_binding(
        hostile_path,
        "wucios.lovelace.hostile_kvm_cell_evidence.v1",
        hostile_manifest,
    )
    hostile_manifest["validation"]["hostile_kvm_cell"] = (
        "locally-validated-kvm-layered-control-presence"
    )
    hostile_manifest["validation_evidence"]["hostile_kvm_cell"] = (
        hostile_binding
    )
    assert lovelace_builder.verify_validation_evidence(
        hostile_manifest,
        {
            "manifest": hostile_release / "manifest.json",
            "evidence": hostile_directory,
        },
    ) == {"hostile_kvm_cell": hostile_binding}


def assert_manifest_artifact_locks() -> None:
    release, _seeds, _ghidra = lovelace_builder.configuration()
    manifest = evidence_fixture_manifest()
    manifest["release_id"] = release["release_id"]
    manifest["artifacts"] = {
        "base_image": {
            "filename": release["output_files"]["base_image"],
            "size": release["filesystem"]["size_mib"] * 1024 * 1024,
            "sha256": "a" * 64,
            "mode": "0444",
            "format": "ext4",
        },
        "kernel": {
            "filename": release["output_files"]["kernel"],
            "size": release["boot"]["kernel_size"],
            "sha256": release["boot"]["kernel_sha256"],
        },
        "initramfs": {
            "filename": release["output_files"]["initramfs"],
            "size": release["boot"]["initramfs_size"],
            "sha256": release["boot"]["initramfs_sha256"],
        },
    }
    lovelace_builder.validate_manifest_artifact_locks(manifest, release)
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    assert vector["schema"] == "wucios.lovelace.artifact_vector.v2"
    assert re.fullmatch(
        r"[0-9a-f]{64}", vector["immutable_build_manifest_sha256"]
    )
    for field, mutation in (
        ("root_tree_counts", lambda value: value.__setitem__("regular", 2)),
        ("input_snapshot", lambda value: value.__setitem__("package_count", 2)),
        (
            "filesystem",
            lambda value: value.__setitem__("staged_entry_count", 2),
        ),
    ):
        altered_immutable = copy.deepcopy(manifest)
        mutation(altered_immutable[field])
        altered_immutable_vector = (
            lovelace_builder.canonical_artifact_vector(
                altered_immutable
            )
        )
        assert altered_immutable_vector[
            "immutable_build_manifest_sha256"
        ] != vector["immutable_build_manifest_sha256"]

    validation_only = copy.deepcopy(manifest)
    validation_only["validation"]["boot"] = (
        "locally-validated-tcg-functional-only"
    )
    validation_only["validation_evidence"]["boot"] = {
        "fixture": "validation-only mutation"
    }
    assert (
        lovelace_builder.canonical_artifact_vector(validation_only)
        == vector
    )
    altered_embedded = copy.deepcopy(manifest)
    altered_embedded["java_home"] = "/different-java"
    altered_vector = lovelace_builder.canonical_artifact_vector(
        altered_embedded
    )
    assert altered_vector["embedded_build_records_sha256"] != (
        vector["embedded_build_records_sha256"]
    )
    missing_embedded = copy.deepcopy(manifest)
    del missing_embedded["privileged_files"]
    expect_lovelace_error(
        lambda: lovelace_builder.canonical_artifact_vector(
            missing_embedded
        ),
        "artifact-vector build manifest keys differ",
    )
    for artifact, field in (
        ("kernel", "sha256"),
        ("initramfs", "size"),
        ("kernel", "filename"),
    ):
        stale = copy.deepcopy(manifest)
        stale["artifacts"][artifact][field] = (
            "9" * 64
            if field == "sha256"
            else 1
            if field == "size"
            else "stale-kernel"
        )
        expect_lovelace_error(
            lambda stale=stale: (
                lovelace_builder.validate_manifest_artifact_locks(
                    stale, release
                )
            ),
            "differs from the release boot lock",
        )


def runtime_evidence_fixture(
    manifest: dict[str, Any], schema: str
) -> dict[str, Any]:
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    base_sha256 = vector["artifacts"]["base_image"]["sha256"]
    return {
        "schema": schema,
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": base_sha256,
        "base_image_sha256_before": base_sha256,
        "base_image_sha256_after": base_sha256,
        "base_image_unchanged": True,
        "functional_accelerator": "tcg",
        "isolation_claim": False,
        "input_verification": evidence_input_verification(manifest),
    }


def assert_evidence_lane_contracts() -> None:
    assert tuple(wuci_lab.NONCLAIMS) == (
        lovelace_builder.HOSTILE_SUPERVISOR_NONCLAIMS
    )
    for unsafe_path in (
        "/tmp/overlay,cache=unsafe",
        "/tmp/../overlay",
        "/tmp\\overlay",
        "/tmp/overlay\n",
    ):
        expect_lovelace_error(
            lambda unsafe_path=unsafe_path: (
                lovelace_builder._hostile_serialized_absolute_path(
                    unsafe_path, "hostile fixture path"
                )
            )
        )

    manifest = evidence_fixture_manifest()
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    base_sha256 = vector["artifacts"]["base_image"]["sha256"]
    boot = boot_evidence_fixture(manifest)
    measured_input = evidence_input_verification(manifest)
    measured_input["boot"] = "locally-validated-tcg-functional-only"
    measured_input["ghidra_headless"] = "locally-validated"
    measured_input["validation_evidence"] = {
        "boot": {"fixture": "must not survive"}
    }
    input_snapshot = (
        lovelace_builder.evidence_input_verification_snapshot(
            measured_input
        )
    )
    assert input_snapshot["boot"] == "NOT_MEASURED"
    assert input_snapshot["ghidra_headless"] == "NOT_MEASURED"
    assert input_snapshot["validation_evidence"] == {}
    assert measured_input["validation_evidence"] != {}

    ghidra = runtime_evidence_fixture(
        manifest, "wucios.lovelace.ghidra_headless_evidence.v1"
    )
    ghidra.update(
        {
            "storage": "volatile",
            "network": "none",
            "fixture": manifest["ghidra_fixture"],
            "ghidra": manifest["ghidra"],
            "runtime": evidence_runtime(
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    lovelace_builder.GHIDRA_SEMANTIC_MARKER,
                    lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER,
                    lovelace_builder.GHIDRA_PASS_MARKER,
                ]
            ),
        }
    )
    noxframe = runtime_evidence_fixture(
        manifest, "wucios.lovelace.noxframe_guest_evidence.v1"
    )
    noxframe.update(
        {
            "storage": "volatile",
            "network": "none",
            "languages": [
                "python3",
                "c",
                "cpp",
                "assembly",
                "rust",
                "go",
            ],
            "analysis_tools": ["ghidra-headless"],
            "runtime": evidence_runtime(
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    lovelace_builder.NOXFRAME_GHIDRA_SEMANTIC_MARKER,
                    lovelace_builder.NOXFRAME_GHIDRA_MARKER,
                    lovelace_builder.HOSTILE_NOXFRAME_MARKER,
                ]
            ),
        }
    )
    persistent = runtime_evidence_fixture(
        manifest, "wucios.lovelace.persistence_evidence.v1"
    )
    token = hashlib.sha256(
        (
            "wucios-lovelace-persistent-round-trip-v1:" + base_sha256
        ).encode("ascii")
    ).hexdigest()
    persistent.update(
        {
            "storage": "temporary-qcow2-round-trip-overlay",
            "network": "none",
            "proof_token_sha256": hashlib.sha256(
                token.encode("ascii")
            ).hexdigest(),
            "first_boot": evidence_runtime(
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    "LOVELACE_PERSISTENT_WRITE_PASS",
                ]
            ),
            "second_boot": evidence_runtime(
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    "LOVELACE_PERSISTENT_ROUND_TRIP_PASS",
                ]
            ),
        }
    )
    release, _seeds, _ghidra = lovelace_builder.configuration()
    alpine_lock = lovelace_builder.shared_alpine_lock(release)
    iso = alpine_lock["boot_media"]["iso"]
    sha256_sidecars = [
        record
        for record in alpine_lock["boot_media"]["sidecars"]
        if record["role"] == "sha256-digest"
    ]
    assert len(sha256_sidecars) == 1
    sidecar = sha256_sidecars[0]
    expected_exact_line = f"{iso['sha256']}  {iso['filename']}"
    expected_response = (expected_exact_line + "\n").encode("ascii")
    assert sidecar["url"] == iso["url"] + sidecar["suffix"]
    assert sidecar["size"] == len(expected_response)
    assert sidecar["sha256"] == hashlib.sha256(expected_response).hexdigest()
    resolv_conf = b"nameserver 10.0.2.3\noptions timeout:2 attempts:3\n"
    network = runtime_evidence_fixture(
        manifest, "wucios.lovelace.network_evidence.v1"
    )
    network.update(
        {
            "storage": "volatile",
            "network": "explicit-qemu-user-nat",
            "inbound_host_forwarding": False,
            "guest_listening_sockets": {
                "command": "ss -H -lntup",
                "command_succeeded": True,
                "observed": [],
                "scope": (
                    "TCP/UDP listening sockets visible to the guest lab user"
                ),
            },
            "guest_topology": {
                "qemu_netdev": lovelace_builder.QEMU_USER_NETDEV,
                "ipv4_cidr": "10.0.2.15/24",
                "gateway_ipv4": "10.0.2.2",
                "dns_proxy_ipv4": "10.0.2.3",
                "resolv_conf_bytes": len(resolv_conf),
                "resolv_conf_sha256": hashlib.sha256(
                    resolv_conf
                ).hexdigest(),
            },
            "launch_contract": {
                "machine": "q35,accel=tcg",
                "accelerator": "tcg",
                "netdev": lovelace_builder.QEMU_USER_NETDEV,
                "network_device": (
                    lovelace_builder.QEMU_USER_NETWORK_DEVICE
                ),
                "host_forwarding": False,
                "root_disk_format": "qcow2",
                "temporary_overlay": True,
                "base_image_directly_writable": False,
                "qemu_snapshot_flag": False,
            },
            "https_probe": {
                "url": sidecar["url"],
                "expected_exact_line": expected_exact_line,
                "expected_response_bytes": sidecar["size"],
                "expected_response_sha256": sidecar["sha256"],
                "maximum_response_bytes": sidecar["size"],
                "connect_timeout_seconds": (
                    lovelace_builder.NETWORK_CONNECT_TIMEOUT_SECONDS
                ),
                "transfer_timeout_seconds": (
                    lovelace_builder.NETWORK_TRANSFER_TIMEOUT_SECONDS
                ),
            },
            "timeouts": {
                "connect_seconds": (
                    lovelace_builder.NETWORK_CONNECT_TIMEOUT_SECONDS
                ),
                "transfer_seconds": (
                    lovelace_builder.NETWORK_TRANSFER_TIMEOUT_SECONDS
                ),
                "vm_seconds": lovelace_builder.NETWORK_VM_TIMEOUT_SECONDS,
            },
            "runtime": evidence_runtime(
                [
                    lovelace_builder.INTERNET_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    "LOVELACE_EXPLICIT_INTERNET_PASS",
                ]
            ),
        }
    )
    comparisons = {
        name: {
            "size": record["size"],
            "sha256": record["sha256"],
            "byte_for_byte_equal": True,
        }
        for name, record in vector["artifacts"].items()
    }
    comparisons["manifest"] = {
        "size": 512,
        "sha256": "2" * 64,
        "byte_for_byte_equal": True,
    }
    reproducibility = {
        "schema": "wucios.lovelace.reproducibility_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "release_id": vector["release_id"],
        "independent_build_roots": 2,
        "network_used": False,
        "source_inputs_unchanged_during_test": True,
        "byte_for_byte_equal": True,
        "base_image_sha256": base_sha256,
        "isolation_claim": False,
        "artifacts": comparisons,
        "first_verification": evidence_input_verification(manifest),
        "second_verification": evidence_input_verification(manifest),
        "authoritative_for_release": False,
        "non_claims": manifest["non_claims"],
    }
    hostile = hostile_evidence_fixture(manifest)

    def set_hostile_transcript(
        document: dict[str, Any], transcript: str
    ) -> None:
        encoded = transcript.encode("utf-8")
        runtime = document["runtime"]
        runtime["console_transcript"] = transcript
        runtime["console_transcript_bytes"] = len(encoded)
        runtime["console_sha256"] = hashlib.sha256(encoded).hexdigest()
        runtime["console_tail"] = transcript[-12000:]

    evidence_documents = [
        boot,
        ghidra,
        noxframe,
        persistent,
        network,
        reproducibility,
        hostile,
    ]
    for evidence in evidence_documents:
        schema = evidence["schema"]
        lovelace_builder.validate_evidence_document(
            evidence, schema, manifest, schema
        )
        underspecified = copy.deepcopy(evidence)
        del underspecified[
            "network_used" if schema.endswith("reproducibility_evidence.v1")
            else "isolation_claim"
        ]
        expect_lovelace_error(
            lambda underspecified=underspecified, schema=schema: (
                lovelace_builder.validate_evidence_document(
                    underspecified, schema, manifest, schema
                )
            ),
            "keys differ",
        )

    for evidence in (boot, ghidra, noxframe, network):
        invalid_marker = copy.deepcopy(evidence)
        invalid_marker["runtime"]["markers"] = []
        expect_lovelace_error(
            lambda invalid_marker=invalid_marker: (
                lovelace_builder.validate_evidence_document(
                    invalid_marker,
                    invalid_marker["schema"],
                    manifest,
                    invalid_marker["schema"],
                )
            ),
            "runtime invariants differ",
        )

    missing_ghidra_semantics = copy.deepcopy(ghidra)
    missing_semantic_runtime = missing_ghidra_semantics["runtime"]
    missing_semantic_transcript = base64.b64decode(
        missing_semantic_runtime["console_transcript_base64"],
        validate=True,
    ).replace(
        (lovelace_builder.GHIDRA_SEMANTIC_MARKER + "\n").encode(
            "ascii"
        ),
        b"",
        1,
    )
    bind_functional_console_transcript(
        missing_semantic_runtime, missing_semantic_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            missing_ghidra_semantics,
            missing_ghidra_semantics["schema"],
            manifest,
            "Ghidra exit zero without semantic analysis marker",
        ),
        "does not contain each exact marker once",
    )

    conflicting_ghidra_status = copy.deepcopy(ghidra)
    conflicting_status_runtime = conflicting_ghidra_status["runtime"]
    conflicting_status_transcript = base64.b64decode(
        conflicting_status_runtime["console_transcript_base64"],
        validate=True,
    ) + b"LOVELACE_GHIDRA_HEADLESS_EXIT status=124\n"
    bind_functional_console_transcript(
        conflicting_status_runtime, conflicting_status_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            conflicting_ghidra_status,
            conflicting_ghidra_status["schema"],
            manifest,
            "conflicting Ghidra process status",
        ),
        "missing or conflicting LOVELACE_GHIDRA_HEADLESS_EXIT status=",
    )

    conflicting_ghidra_semantics = copy.deepcopy(ghidra)
    conflicting_semantic_runtime = conflicting_ghidra_semantics["runtime"]
    conflicting_semantic_transcript = base64.b64decode(
        conflicting_semantic_runtime["console_transcript_base64"],
        validate=True,
    ) + (
        lovelace_builder.GHIDRA_SEMANTIC_MARKER + " conflicting\n"
    ).encode("ascii")
    bind_functional_console_transcript(
        conflicting_semantic_runtime, conflicting_semantic_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            conflicting_ghidra_semantics,
            conflicting_ghidra_semantics["schema"],
            manifest,
            "conflicting Ghidra semantic result",
        ),
        "missing or conflicting LOVELACE_GHIDRA_SEMANTIC_PASS line",
    )

    for field, replacement in (
        ("console_eof_observed", False),
        (
            "console_drain_timeout_seconds",
            lovelace_builder.FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS + 1,
        ),
    ):
        invalid_runtime = copy.deepcopy(boot)
        invalid_runtime["runtime"][field] = replacement
        expect_lovelace_error(
            lambda invalid_runtime=invalid_runtime: (
                lovelace_builder.validate_evidence_document(
                    invalid_runtime,
                    invalid_runtime["schema"],
                    manifest,
                    f"invalid functional runtime {field}",
                )
            ),
            "runtime invariants differ",
        )

    transcript_tamper = copy.deepcopy(boot)
    transcript_bytes = base64.b64decode(
        transcript_tamper["runtime"]["console_transcript_base64"],
        validate=True,
    )
    transcript_tamper["runtime"]["console_transcript_base64"] = (
        base64.b64encode(transcript_bytes[:-2] + b"X\n").decode("ascii")
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            transcript_tamper,
            transcript_tamper["schema"],
            manifest,
            "functional transcript changed without digest update",
        )
    )

    digest_tamper = copy.deepcopy(boot)
    digest_tamper["runtime"]["console_sha256"] = "0" * 64
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            digest_tamper,
            digest_tamper["schema"],
            manifest,
            "functional console digest tamper",
        )
    )

    tail_tamper = copy.deepcopy(boot)
    tail_tamper["runtime"]["console_tail"] = "unbound fixture tail"
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            tail_tamper,
            tail_tamper["schema"],
            manifest,
            "functional console tail tamper",
        )
    )

    wrong_boot_line = copy.deepcopy(boot)
    wrong_boot_transcript = base64.b64decode(
        wrong_boot_line["runtime"]["console_transcript_base64"],
        validate=True,
    ).replace(
        lovelace_builder.OFFLINE_BOOT_LINE.encode("ascii"),
        lovelace_builder.INTERNET_BOOT_LINE.encode("ascii"),
        1,
    )
    bind_functional_console_transcript(
        wrong_boot_line["runtime"], wrong_boot_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            wrong_boot_line,
            wrong_boot_line["schema"],
            manifest,
            "wrong functional boot line",
        )
    )

    conflicting_boot_line = copy.deepcopy(boot)
    conflicting_boot_runtime = conflicting_boot_line["runtime"]
    conflicting_boot_transcript = base64.b64decode(
        conflicting_boot_runtime["console_transcript_base64"],
        validate=True,
    ) + (
        lovelace_builder.BOOT_MARKER
        + " profile=conflicting storage=volatile network=internet\n"
    ).encode("ascii")
    bind_functional_console_transcript(
        conflicting_boot_runtime, conflicting_boot_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            conflicting_boot_line,
            conflicting_boot_line["schema"],
            manifest,
            "additional conflicting functional boot line",
        ),
        "missing, duplicate, or conflicting boot line",
    )

    early_result = copy.deepcopy(boot)
    early_runtime = early_result["runtime"]
    early_transcript = base64.b64decode(
        early_runtime["console_transcript_base64"], validate=True
    )
    first_result_offset = early_transcript.index(
        (early_runtime["markers"][2] + "\n").encode("ascii")
    )
    early_runtime["command_dispatch_offset"] = first_result_offset + 1
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            early_result,
            early_result["schema"],
            manifest,
            "functional result before dispatch",
        )
    )

    duplicate_result = copy.deepcopy(boot)
    duplicate_runtime = duplicate_result["runtime"]
    duplicate_transcript = base64.b64decode(
        duplicate_runtime["console_transcript_base64"], validate=True
    ) + (duplicate_runtime["markers"][2] + "\n").encode("ascii")
    bind_functional_console_transcript(
        duplicate_runtime, duplicate_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            duplicate_result,
            duplicate_result["schema"],
            manifest,
            "duplicate functional result line",
        )
    )

    reordered_results = copy.deepcopy(boot)
    reordered_runtime = reordered_results["runtime"]
    reordered_markers = reordered_runtime["markers"]
    reordered_transcript = (
        "\n".join(
            [
                reordered_markers[0],
                reordered_markers[1],
                reordered_markers[3],
                reordered_markers[2],
                *reordered_markers[4:],
            ]
        )
        + "\n"
    ).encode("ascii")
    bind_functional_console_transcript(
        reordered_runtime, reordered_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            reordered_results,
            reordered_results["schema"],
            manifest,
            "reordered functional result lines",
        ),
        "exact markers are out of order",
    )

    unterminated_result = copy.deepcopy(boot)
    unterminated_runtime = unterminated_result["runtime"]
    unterminated_transcript = base64.b64decode(
        unterminated_runtime["console_transcript_base64"], validate=True
    ).removesuffix(b"\n")
    bind_functional_console_transcript(
        unterminated_runtime, unterminated_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            unterminated_result,
            unterminated_result["schema"],
            manifest,
            "unterminated functional result line",
        ),
        "does not contain each exact marker once",
    )

    diagnostic_outside_tail = copy.deepcopy(boot)
    diagnostic_runtime = diagnostic_outside_tail["runtime"]
    diagnostic_transcript = base64.b64decode(
        diagnostic_runtime["console_transcript_base64"], validate=True
    )
    diagnostic_ready_end = diagnostic_runtime[
        "console_ready_line_end_offset"
    ]
    diagnostic_transcript = (
        diagnostic_transcript[:diagnostic_ready_end]
        + b"Kernel panic - not syncing: fixture outside tail\n"
        + b"x" * 13000
        + b"\n"
        + diagnostic_transcript[diagnostic_ready_end:]
    )
    bind_functional_console_transcript(
        diagnostic_runtime, diagnostic_transcript
    )
    assert "Kernel panic" not in diagnostic_runtime["console_tail"]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            diagnostic_outside_tail,
            diagnostic_outside_tail["schema"],
            manifest,
            "functional diagnostic outside retained tail",
        ),
        "forbidden kernel or storage diagnostic",
    )

    wrong_network_boot = copy.deepcopy(network)
    wrong_network_transcript = base64.b64decode(
        wrong_network_boot["runtime"]["console_transcript_base64"],
        validate=True,
    ).replace(
        lovelace_builder.INTERNET_BOOT_LINE.encode("ascii"),
        lovelace_builder.OFFLINE_BOOT_LINE.encode("ascii"),
        1,
    )
    bind_functional_console_transcript(
        wrong_network_boot["runtime"], wrong_network_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            wrong_network_boot,
            wrong_network_boot["schema"],
            manifest,
            "network evidence with offline boot line",
        )
    )

    for topology_field, replacement in (
        ("qemu_netdev", "user,id=wrong"),
        ("ipv4_cidr", "10.0.2.16/24"),
        ("gateway_ipv4", "10.0.2.1"),
        ("dns_proxy_ipv4", "10.0.2.4"),
        ("resolv_conf_bytes", 1),
        ("resolv_conf_sha256", "0" * 64),
    ):
        wrong_topology = copy.deepcopy(network)
        wrong_topology["guest_topology"][topology_field] = replacement
        expect_lovelace_error(
            lambda wrong_topology=wrong_topology: (
                lovelace_builder.validate_evidence_document(
                    wrong_topology,
                    wrong_topology["schema"],
                    manifest,
                    f"wrong network topology {topology_field}",
                )
            )
        )

    wrong_response_size = copy.deepcopy(network)
    wrong_response_size["https_probe"]["expected_response_bytes"] += 1
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            wrong_response_size,
            wrong_response_size["schema"],
            manifest,
            "wrong HTTPS response size binding",
        )
    )
    wrong_response_digest = copy.deepcopy(network)
    wrong_response_digest["https_probe"][
        "expected_response_sha256"
    ] = "0" * 64
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            wrong_response_digest,
            wrong_response_digest["schema"],
            manifest,
            "wrong HTTPS response digest binding",
        )
    )
    failed_listener_observation = copy.deepcopy(network)
    failed_listener_observation["guest_listening_sockets"][
        "command_succeeded"
    ] = False
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            failed_listener_observation,
            failed_listener_observation["schema"],
            manifest,
            "failed guest listener observation",
        )
    )
    unsafe_launch_contract = copy.deepcopy(network)
    unsafe_launch_contract["launch_contract"]["host_forwarding"] = True
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            unsafe_launch_contract,
            unsafe_launch_contract["schema"],
            manifest,
            "unsafe network launch contract",
        )
    )

    wrong_cpu_model = copy.deepcopy(boot)
    wrong_cpu_model["runtime"]["functional_cpu_model"] = "max"
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            wrong_cpu_model,
            wrong_cpu_model["schema"],
            manifest,
            "wrong functional CPU model",
        ),
        "runtime invariants differ",
    )
    missing_cpu_model = copy.deepcopy(boot)
    del missing_cpu_model["runtime"]["functional_cpu_model"]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            missing_cpu_model,
            missing_cpu_model["schema"],
            manifest,
            "missing functional CPU model",
        ),
        "keys differ",
    )
    wrong_kernel_arguments = copy.deepcopy(boot)
    wrong_kernel_arguments["runtime"]["functional_kernel_arguments"] = [
        "root=/dev/vda"
    ]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            wrong_kernel_arguments,
            wrong_kernel_arguments["schema"],
            manifest,
            "wrong functional kernel arguments",
        ),
        "runtime invariants differ",
    )
    missing_kernel_arguments = copy.deepcopy(boot)
    del missing_kernel_arguments["runtime"]["functional_kernel_arguments"]
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            missing_kernel_arguments,
            missing_kernel_arguments["schema"],
            manifest,
            "missing functional kernel arguments",
        ),
        "keys differ",
    )
    diagnostics_claim = copy.deepcopy(boot)
    diagnostics_claim["runtime"]["forbidden_diagnostics_absent"] = False
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            diagnostics_claim,
            diagnostics_claim["schema"],
            manifest,
            "functional diagnostics claim",
        ),
        "runtime invariants differ",
    )
    diagnostic_tail = copy.deepcopy(boot)
    diagnostic_runtime = diagnostic_tail["runtime"]
    diagnostic_transcript = base64.b64decode(
        diagnostic_runtime["console_transcript_base64"], validate=True
    ) + b"watchdog: BUG: soft lockup - fixture\n"
    bind_functional_console_transcript(
        diagnostic_runtime, diagnostic_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            diagnostic_tail,
            diagnostic_tail["schema"],
            manifest,
            "functional diagnostic tail",
        ),
        "forbidden kernel or storage diagnostic",
    )

    hostile_diagnostics_claim = copy.deepcopy(hostile)
    hostile_diagnostics_claim["runtime"][
        "forbidden_diagnostics_absent"
    ] = False
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_diagnostics_claim,
            hostile_diagnostics_claim["schema"],
            manifest,
            "hostile diagnostics claim",
        ),
        "hostile runtime observation differs",
    )
    hostile_raw_terminal_tail = copy.deepcopy(hostile)
    set_hostile_transcript(
        hostile_raw_terminal_tail,
        hostile_raw_terminal_tail["runtime"]["console_transcript"]
        + "fixture\x1b]52;clipboard\x07",
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_raw_terminal_tail,
            hostile_raw_terminal_tail["schema"],
            manifest,
            "hostile raw terminal tail",
        ),
        "raw terminal-control or non-ASCII characters",
    )
    hostile_terminal_forwarding = copy.deepcopy(hostile)
    hostile_terminal_forwarding["runtime"][
        "non_allowlisted_console_bytes_forwarded"
    ] = True
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_terminal_forwarding,
            hostile_terminal_forwarding["schema"],
            manifest,
            "hostile terminal forwarding",
        ),
        "hostile runtime observation differs",
    )
    hostile_diagnostic_tail = copy.deepcopy(hostile)
    set_hostile_transcript(
        hostile_diagnostic_tail,
        hostile_diagnostic_tail["runtime"]["console_transcript"]
        + "Kernel panic - not syncing: fixture\n",
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_diagnostic_tail,
            hostile_diagnostic_tail["schema"],
            manifest,
            "hostile diagnostic tail",
        ),
        "forbidden kernel or storage diagnostic",
    )
    hostile_console_timeout = copy.deepcopy(hostile)
    hostile_console_timeout["runtime"]["console_ready_timeout_seconds"] = 179
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_console_timeout,
            hostile_console_timeout["schema"],
            manifest,
            "hostile console timeout",
        ),
        "hostile runtime observation differs",
    )
    hostile_conflicting_status = copy.deepcopy(hostile)
    set_hostile_transcript(
        hostile_conflicting_status,
        hostile_conflicting_status["runtime"]["console_transcript"]
        + "LOVELACE_GHIDRA_HEADLESS_EXIT status=124\n",
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_conflicting_status,
            hostile_conflicting_status["schema"],
            manifest,
            "hostile conflicting Ghidra status",
        ),
        "hostile Ghidra status or semantic line conflicts",
    )
    hostile_conflicting_semantic = copy.deepcopy(hostile)
    set_hostile_transcript(
        hostile_conflicting_semantic,
        hostile_conflicting_semantic["runtime"]["console_transcript"]
        + lovelace_builder.GHIDRA_SEMANTIC_MARKER
        + " "
        + "8" * 64
        + "\n",
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_conflicting_semantic,
            hostile_conflicting_semantic["schema"],
            manifest,
            "hostile conflicting Ghidra semantics",
        ),
        "hostile Ghidra status or semantic line conflicts",
    )
    hostile_bare_semantic = copy.deepcopy(hostile)
    set_hostile_transcript(
        hostile_bare_semantic,
        hostile_bare_semantic["runtime"]["console_transcript"]
        + lovelace_builder.GHIDRA_SEMANTIC_MARKER
        + "\n",
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_bare_semantic,
            hostile_bare_semantic["schema"],
            manifest,
            "hostile bare Ghidra semantic conflict",
        ),
        "hostile Ghidra status or semantic line conflicts",
    )
    hostile_reordered_ghidra = copy.deepcopy(hostile)
    hostile_challenge = hostile_reordered_ghidra["runtime"]["challenge"]
    hostile_semantic_line = (
        f"{lovelace_builder.GHIDRA_SEMANTIC_MARKER} "
        f"{hostile_challenge}\n"
    )
    original_ghidra_sequence = (
        hostile_semantic_line
        + lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER
        + "\n"
    )
    reordered_ghidra_sequence = (
        lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER
        + "\n"
        + hostile_semantic_line
    )
    reordered_transcript = hostile_reordered_ghidra["runtime"][
        "console_transcript"
    ].replace(
        original_ghidra_sequence,
        reordered_ghidra_sequence,
        1,
    )
    assert reordered_transcript != hostile_reordered_ghidra["runtime"][
        "console_transcript"
    ]
    set_hostile_transcript(
        hostile_reordered_ghidra, reordered_transcript
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_reordered_ghidra,
            hostile_reordered_ghidra["schema"],
            manifest,
            "hostile reordered Ghidra status",
        ),
        "hostile complete result-line binding differs",
    )
    hostile_early_dispatch = copy.deepcopy(hostile)
    hostile_early_dispatch["runtime"]["command_dispatch_offset"] = len(
        lovelace_builder.canonical_json(
            hostile_early_dispatch["launch_plan"]["materialized_plan"]
        )
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_early_dispatch,
            hostile_early_dispatch["schema"],
            manifest,
            "hostile early dispatch",
        ),
        "complete result-line binding differs",
    )

    boot_binding = {
        "path": "evidence/boot-test.json",
        "sha256": "3" * 64,
        "schema": "wucios.lovelace.boot_evidence.v1",
        "base_image_sha256": base_sha256,
        "artifact_vector_sha256": (
            lovelace_builder.canonical_object_sha256(vector)
        ),
    }
    inconsistent = copy.deepcopy(boot)
    inconsistent["input_verification"]["validation_evidence"] = {
        "language_matrix": boot_binding
    }
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            inconsistent, inconsistent["schema"], manifest, "inconsistent"
        ),
        "boot/language evidence group is incomplete",
    )
    hostile_nested = copy.deepcopy(boot)
    hostile_nested["input_verification"]["validation_evidence"] = {
        "hostile_kvm_cell": {}
    }
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            hostile_nested,
            hostile_nested["schema"],
            manifest,
            "hostile nested",
        ),
        "keys differ",
    )
    unbacked_hostile_nested = copy.deepcopy(boot)
    unbacked_hostile_nested["input_verification"][
        "validation_evidence"
    ] = {
        "hostile_kvm_cell": {
            "path": "evidence/hostile-kvm-cell.json",
            "sha256": "3" * 64,
            "schema": "wucios.lovelace.hostile_kvm_cell_evidence.v1",
            "base_image_sha256": base_sha256,
            "artifact_vector_sha256": (
                lovelace_builder.canonical_object_sha256(vector)
            ),
        }
    }
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            unbacked_hostile_nested,
            unbacked_hostile_nested["schema"],
            manifest,
            "unbacked hostile nested",
        ),
        "must exclude nested runtime validation evidence",
    )
    measured_without_binding = copy.deepcopy(boot)
    measured_without_binding["input_verification"]["boot"] = (
        "locally-validated-tcg-functional-only"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            measured_without_binding,
            measured_without_binding["schema"],
            manifest,
            "measured without binding",
        ),
        "boot evidence status is inconsistent",
    )
    rewritten_ghidra_manifest = copy.deepcopy(manifest)
    del rewritten_ghidra_manifest["ghidra"]["version"]
    rewritten_ghidra = copy.deepcopy(ghidra)
    rewritten_ghidra["artifact_vector"] = (
        lovelace_builder.canonical_artifact_vector(
            rewritten_ghidra_manifest
        )
    )
    rewritten_ghidra["ghidra"] = rewritten_ghidra_manifest["ghidra"]
    rewritten_ghidra["input_verification"] = (
        evidence_input_verification(rewritten_ghidra_manifest)
    )
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            rewritten_ghidra,
            rewritten_ghidra["schema"],
            rewritten_ghidra_manifest,
            "rewritten Ghidra",
        ),
        "installed Ghidra record keys differ",
    )

    qemu_tamper = copy.deepcopy(hostile)
    materialized = qemu_tamper["launch_plan"]["materialized_plan"]
    original_qemu = list(materialized["qemu_argv"])
    separator = len(materialized["argv"]) - len(original_qemu) - 1
    assert materialized["argv"][separator] == "--"
    materialized["qemu_argv"].extend(
        ["-netdev", "user,id=unexpected-hostile-network"]
    )
    materialized["argv"][separator + 1 :] = materialized["qemu_argv"]
    refresh_hostile_plan_digests(qemu_tamper)
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            qemu_tamper,
            qemu_tamper["schema"],
            manifest,
            "self-consistent hostile QEMU tamper",
        ),
        "hostile executed argument vector differs",
    )

    binding_tamper = copy.deepcopy(hostile)
    materialized = binding_tamper["launch_plan"]["materialized_plan"]
    binding = materialized["outer_boundary"]["read_only_bindings"][1]
    old_source = binding["source"]
    old_destination = binding["destination"]
    binding.update(
        {
            "source": "/etc/passwd",
            "destination": "/etc/passwd",
            "kind": "file",
            "mode": "0644",
        }
    )
    outer_argv = materialized["argv"]
    replacements = 0
    for index in range(len(outer_argv) - 2):
        if outer_argv[index : index + 3] == [
            "--ro-bind",
            old_source,
            old_destination,
        ]:
            outer_argv[index + 1 : index + 3] = [
                binding["source"],
                binding["destination"],
            ]
            replacements += 1
    assert replacements == 1
    refresh_hostile_plan_digests(binding_tamper)
    expect_lovelace_error(
        lambda: lovelace_builder.validate_evidence_document(
            binding_tamper,
            binding_tamper["schema"],
            manifest,
            "self-consistent hostile binding tamper",
        ),
        "hostile outer-boundary policy differs",
    )

    for mutation, message in (
        (
            lambda value: value["layers"].__setitem__(
                "usable-kvm-device", False
            ),
            "does not validate every required hostile layer",
        ),
        (
            lambda value: value.__setitem__(
                "functional_accelerator", "tcg"
            ),
            "hostile execution identity differs",
        ),
        (
            lambda value: value["runtime"]["qemu_process"].__setitem__(
                "host_uids", [0, 0, 0, 0]
            ),
            "hostile runtime observation differs",
        ),
        (
            lambda value: value["host"]["executables"]["bubblewrap"].__setitem__(
                "setuid", True
            ),
            "trust record is invalid",
        ),
        (
            lambda value: value["claims"].__setitem__(
                "safe_for_arbitrary_malware_claimed", True
            ),
            "claim boundary differs",
        ),
        (
            lambda value: value["launch_plan"].__setitem__(
                "source_plan_sha256", "0" * 64
            ),
            "materialized plan does not match its summary",
        ),
        (
            lambda value: value["launch_plan"].__setitem__(
                "qemu_argv_sha256", "0" * 64
            ),
            "materialized plan does not match its summary",
        ),
        (
            lambda value: value["launch_plan"].__setitem__(
                "read_only_bindings_sha256", "0" * 64
            ),
            "materialized plan does not match its summary",
        ),
        (
            lambda value: value["launch_plan"].__setitem__(
                "outer_argv_sha256", "0" * 64
            ),
            "materialized plan does not match its summary",
        ),
        (
            lambda value: value["runtime"].__setitem__(
                "supervisor_exit", False
            ),
            "hostile runtime observation differs",
        ),
        (
            lambda value: value["runtime"].__setitem__(
                "qemu_process_absent_after_supervisor_exit", False
            ),
            "hostile runtime observation differs",
        ),
        (
            lambda value: value["runtime"].__setitem__(
                "plan_validated_before_guest_command_dispatch", False
            ),
            "hostile runtime observation differs",
        ),
        (
            lambda value: value["runtime"]["qemu_process"]["namespaces"][
                "net"
            ].__setitem__("different", False),
            "namespace was not separated",
        ),
    ):
        invalid = copy.deepcopy(hostile)
        mutation(invalid)
        expect_lovelace_error(
            lambda invalid=invalid: (
                lovelace_builder.validate_evidence_document(
                    invalid,
                    invalid["schema"],
                    manifest,
                    "invalid hostile evidence",
                )
            ),
            message,
        )


def assert_locked_input_snapshot(tmp: Path) -> None:
    source = tmp / "locked-input"
    source.write_bytes(b"locked input bytes\n")
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    destination = tmp / "snapshot/input"
    lovelace_builder.snapshot_locked_regular(
        source,
        destination,
        size=source.stat().st_size,
        sha256=expected,
        label="fixture input",
    )
    assert destination.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400

    wrong_destination = tmp / "snapshot/wrong"
    expect_lovelace_error(
        lambda: lovelace_builder.snapshot_locked_regular(
            source,
            wrong_destination,
            size=source.stat().st_size,
            sha256="0" * 64,
            label="fixture input",
        ),
        "failed its digest",
    )
    assert not wrong_destination.exists()

    hardlink = tmp / "locked-input-hardlink"
    os.link(source, hardlink)
    expect_lovelace_error(
        lambda: lovelace_builder.snapshot_locked_regular(
            source,
            tmp / "snapshot/hardlinked",
            size=source.stat().st_size,
            sha256=expected,
            label="fixture input",
        ),
        "hardlink rejected",
    )


def assert_transactional_release_publication(tmp: Path) -> None:
    output = tmp / "transactional-output"
    old_release = output / "release"
    old_evidence = old_release / "evidence"
    old_evidence.mkdir(parents=True)
    old_manifest = {
        "artifacts": {"base_image": {"sha256": "1" * 64}}
    }
    write_json(old_release / "manifest.json", old_manifest)
    (old_release / "old-image").write_bytes(b"old image\n")
    (old_evidence / "boot-test.json").write_text(
        '{"old":true}\n', encoding="ascii"
    )

    staged_release = tmp / "staged-release"
    staged_release.mkdir()
    write_json(
        staged_release / "manifest.json",
        {"artifacts": {"base_image": {"sha256": "2" * 64}}},
    )
    (staged_release / "new-image").write_bytes(b"new image\n")
    lovelace_builder.publish_staged_release(
        staged_release,
        output,
        replacement_base_sha256="2" * 64,
    )
    assert not staged_release.exists()
    assert (output / "release/new-image").read_bytes() == b"new image\n"
    assert not (output / "release/old-image").exists()
    archives = list((output / "superseded-validation").iterdir())
    assert len(archives) == 1
    archive = archives[0]
    assert lovelace_builder.load_object(archive / "manifest.json") == (
        old_manifest
    )
    assert (archive / "evidence/boot-test.json").read_text(
        encoding="ascii"
    ) == '{"old":true}\n'
    superseded = lovelace_builder.load_object(
        archive / "superseded.json"
    )
    assert superseded["old_base_image_sha256"] == "1" * 64
    assert superseded["replacement_base_image_sha256"] == "2" * 64
    assert not any(
        path.name == "old-image"
        for path in (output / "superseded-validation").rglob("*")
    )


def assert_isolated_native_build(tmp: Path) -> None:
    sources = lovelace_builder.native_asm_sources()
    assert sources
    assert [path.relative_to(REPO).as_posix() for path in sources] == [
        "src/main.s",
        "src/wuci-ji.s",
        "src/gate_contract.s",
        "src/ledger.s",
        "src/regression.s",
        "src/sandbox.s",
        "src/sys.s",
        "src/encoding.s",
        "src/frost.s",
        "src/hmac_hkdf.s",
        "src/secp256k1_field.s",
        "src/secp256k1_point.s",
        "src/secp256k1_scalar.s",
        "src/sha256.s",
        "src/x25519.s",
    ]
    root = tmp / "native-root"
    work = tmp / "native-work"
    work.mkdir()
    previous_umask = os.umask(0o077)
    try:
        result = lovelace_builder.build_native_wuciji(root, work)
    finally:
        os.umask(previous_umask)
    installed = root / result["path"].lstrip("/")
    embedded = root / "opt/wuci-ji/build/wuci-ji"
    assert stat.S_IMODE(embedded.parent.lstat().st_mode) == 0o755
    assert installed.read_bytes() == embedded.read_bytes()
    assert result["sha256"] == hashlib.sha256(installed.read_bytes()).hexdigest()
    assert result["size"] == installed.stat().st_size
    assert len(result["sources"]) == len(sources)
    assert set(result["host_tools"]) == {"assembler", "linker"}
    selftest = subprocess.run(
        [installed, "selftest"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert selftest.returncode == 0, selftest.stderr
    assert selftest.stdout == b"wuci-ji selftest: PASS\n"
    source_text = inspect.getsource(lovelace_builder.build_native_wuciji)
    assert 'run(["make"' not in source_text
    assert 'REPO / "build/wuci-ji"' not in source_text


def function_calls(function: Callable[..., object]) -> set[str]:
    tree = ast.parse(inspect.getsource(function))
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            calls.add(ast.unparse(node.func))
    return calls


def assert_evidence_commit_boundary() -> None:
    update_source = inspect.getsource(
        lovelace_builder._update_validation_unlocked
    )
    commit_source = inspect.getsource(
        lovelace_builder._commit_validation_transaction
    )
    assert update_source.count("_verify_build_locked(output)") == 1
    assert "_commit_validation_transaction" in update_source
    assert commit_source.count("_verify_build_locked(output)") == 1
    assert commit_source.index("write_json(evidence_path, evidence)") < (
        commit_source.index("write_json(manifest_path, manifest)")
    ) < commit_source.index("_verify_build_locked(output)")
    for producer in (
        lovelace_builder._reproducibility_test_unlocked,
        lovelace_builder._boot_test_unlocked,
        lovelace_builder._ghidra_test_unlocked,
        lovelace_builder._noxframe_test_unlocked,
        lovelace_builder._persistent_round_trip_test_unlocked,
        lovelace_builder.network_test,
        lovelace_builder.hostile_test,
        lovelace_builder.hostile_payload_test,
    ):
        calls = function_calls(producer)
        assert "canonical_artifact_vector" in calls, producer.__name__
        assert "_verify_build_locked" in calls, producer.__name__
        assert "_update_validation_unlocked" in calls, producer.__name__


def assert_ghidra_vm_memory_contract(tmp: Path) -> None:
    manifest = evidence_fixture_manifest()
    vector = lovelace_builder.canonical_artifact_vector(manifest)
    base_image = tmp / "ghidra-vm-memory-base.ext4"
    base_image.write_bytes(b"fixture base image\n")
    paths = {
        "base_image": base_image,
        "kernel": tmp / "vmlinuz-lts",
        "initramfs": tmp / "initramfs-lts",
        "evidence": tmp / "evidence",
        "manifest": tmp / "manifest.json",
    }
    captured_memory: list[int | None] = []

    def capture_qemu_argv(
        *_args: object, **kwargs: object
    ) -> list[str]:
        value = kwargs.get("memory_mib")
        captured_memory.append(value if isinstance(value, int) else None)
        return ["fixture-qemu"]

    verification = evidence_input_verification(manifest)
    with patched(
        _verify_build_locked=lambda _output: verification,
        artifact_paths=lambda _output: (manifest, paths),
        canonical_artifact_vector=lambda _manifest: vector,
        digest_file=lambda _path: vector["artifacts"]["base_image"][
            "sha256"
        ],
        create_temporary_overlay=lambda _base, directory: (
            directory / "overlay.qcow2"
        ),
        qemu_argv=capture_qemu_argv,
        run_qemu_commands=lambda *_args, **_kwargs: {},
        _update_validation_unlocked=lambda *_args, **_kwargs: None,
    ):
        lovelace_builder._ghidra_test_unlocked(tmp)
        lovelace_builder._noxframe_test_unlocked(tmp)
    assert lovelace_builder.GHIDRA_VM_MEMORY_MIB == 6144
    assert captured_memory == [
        lovelace_builder.GHIDRA_VM_MEMORY_MIB,
        lovelace_builder.GHIDRA_VM_MEMORY_MIB,
    ]


def assert_validation_transaction_rollback(tmp: Path) -> None:
    release = tmp / "validation-transaction/release"
    evidence_directory = release / "evidence"
    evidence_directory.mkdir(parents=True)
    manifest_path = release / "manifest.json"
    evidence_path = evidence_directory / "boot-test.json"
    old_manifest = {"schema": "fixture.old.manifest", "generation": 1}
    old_evidence = {"schema": "fixture.old.evidence", "generation": 1}
    write_json(manifest_path, old_manifest)
    write_json(evidence_path, old_evidence)
    old_manifest_bytes = manifest_path.read_bytes()
    old_evidence_bytes = evidence_path.read_bytes()
    old_manifest_mode = stat.S_IMODE(manifest_path.stat().st_mode)
    old_evidence_mode = stat.S_IMODE(evidence_path.stat().st_mode)
    new_manifest = {"schema": "fixture.new.manifest", "generation": 2}
    new_evidence = {
        "schema": "wucios.lovelace.boot_evidence.v1",
        "generation": 2,
    }
    paths = {"manifest": manifest_path, "evidence": evidence_directory}
    original_write_json = lovelace_builder.write_json
    failures = 1

    def fail_manifest_once(path: Path, value: object) -> None:
        nonlocal failures
        if path == manifest_path and failures:
            failures -= 1
            raise lovelace_builder.LovelaceError(
                "forced manifest write failure"
            )
        original_write_json(path, value)

    with patched(
        write_json=fail_manifest_once,
        _verify_build_locked=lambda _output: {"status": "pass"},
    ):
        expect_lovelace_error(
            lambda: lovelace_builder._commit_validation_transaction(
                tmp,
                paths,
                new_manifest,
                evidence_path,
                new_evidence,
            ),
            "forced manifest write failure",
        )
    assert manifest_path.read_bytes() == old_manifest_bytes
    assert evidence_path.read_bytes() == old_evidence_bytes
    assert stat.S_IMODE(manifest_path.stat().st_mode) == old_manifest_mode
    assert stat.S_IMODE(evidence_path.stat().st_mode) == old_evidence_mode

    with patched(_verify_build_locked=lambda _output: {"status": "pass"}):
        lovelace_builder._commit_validation_transaction(
            tmp,
            paths,
            new_manifest,
            evidence_path,
            new_evidence,
        )
    assert manifest_path.read_bytes() == lovelace_builder.canonical_json(
        new_manifest
    )
    assert evidence_path.read_bytes() == lovelace_builder.canonical_json(
        new_evidence
    )

    introduced = evidence_directory / "new-evidence.json"
    final_manifest = {"schema": "fixture.final.manifest", "generation": 3}
    failures = 1
    with patched(
        write_json=fail_manifest_once,
        _verify_build_locked=lambda _output: {"status": "pass"},
    ):
        expect_lovelace_error(
            lambda: lovelace_builder._commit_validation_transaction(
                tmp,
                paths,
                final_manifest,
                introduced,
                {
                    "schema": "wucios.lovelace.boot_evidence.v1",
                    "generation": 3,
                },
            ),
            "forced manifest write failure",
        )
    assert not introduced.exists()
    assert manifest_path.read_bytes() == lovelace_builder.canonical_json(
        new_manifest
    )

    hostile_path = evidence_directory / "hostile-kvm-cell.json"
    old_hostile = {"schema": "fixture.old.hostile", "generation": 1}
    new_hostile = {
        "schema": "wucios.lovelace.hostile_kvm_cell_evidence.v1",
        "generation": 2,
    }
    write_json(hostile_path, old_hostile)
    old_hostile_bytes = hostile_path.read_bytes()
    original_snapshot = lovelace_builder._transaction_file_snapshot
    snapshot_limits: list[tuple[str, int]] = []

    def observed_snapshot(
        path: Path,
        label: str,
        *,
        max_bytes: int = lovelace_builder.MAX_INDEX_SIZE,
    ) -> dict[str, Any]:
        snapshot_limits.append((label, max_bytes))
        return original_snapshot(path, label, max_bytes=max_bytes)

    failures = 1
    with patched(
        _transaction_file_snapshot=observed_snapshot,
        write_json=fail_manifest_once,
        _verify_build_locked=lambda _output: {"status": "pass"},
    ):
        expect_lovelace_error(
            lambda: lovelace_builder._commit_validation_transaction(
                tmp,
                paths,
                new_manifest,
                hostile_path,
                new_hostile,
            ),
            "forced manifest write failure",
        )
    assert hostile_path.read_bytes() == old_hostile_bytes
    hostile_snapshot_labels = {
        label
        for label, _limit in snapshot_limits
        if "validation evidence" in label
    }
    assert hostile_snapshot_labels == {
        "prior validation evidence",
        "committed validation evidence",
        "current validation evidence",
        "restored validation evidence",
    }
    assert all(
        limit == lovelace_builder.MAX_HOSTILE_VALIDATION_EVIDENCE_BYTES
        for label, limit in snapshot_limits
        if "validation evidence" in label
    )


def assert_offline_install_command(tmp: Path) -> None:
    cache = tmp / "offline-cache"
    packages = lovelace_builder.cache_paths(cache)["packages"]
    packages.mkdir(parents=True)
    package = packages / "fixture-1.0-r0.apk"
    package.write_bytes(b"signed APK fixture placeholder\n")
    work = tmp / "offline-work"
    work.mkdir()
    bootstrap = tmp / "apk-bootstrap"
    (bootstrap / "etc/apk/keys").mkdir(parents=True)
    root = tmp / "offline-root"
    lock = {
        "packages": [
            {
                "name": "fixture",
                "version": "1.0-r0",
                "architecture": "x86_64",
                "filename": package.name,
            }
        ],
        "world": ["fixture=1.0-r0"],
    }
    commands: list[list[str]] = []

    def fake_run(
        argv: list[object], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append([os.fspath(item) for item in argv])
        installed = root / "lib/apk/db/installed"
        installed.parent.mkdir(parents=True)
        installed.write_text("fixture database\n", encoding="utf-8")
        if "--no-logfile" not in commands[-1]:
            apk_log = root / "var/log/apk.log"
            apk_log.parent.mkdir(parents=True)
            apk_log.write_text(
                f"Running from transient work root {work}\n",
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(commands[-1], 0, "offline\n", "")

    def network_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline builder lane attempted a network helper")

    with patched(
        apk_command=lambda _bootstrap: ["fixture-apk"],
        apk_environment=lambda _work: {"PATH": "/usr/bin"},
        run=fake_run,
        installed_apk_identities=lambda _path: [
            ("fixture", "1.0-r0", "x86_64")
        ],
        safe_download_snapshot=network_forbidden,
        fetch_locked_file=network_forbidden,
    ):
        result = lovelace_builder.install_offline_root(
            root, lock, cache, bootstrap, work
        )
    assert result["network_used"] is False
    assert result["package_scripts_executed"] is False
    assert result["apk_build_log_embedded"] is False
    assert not (root / "var/log/apk.log").exists()
    assert len(commands) == 1
    command = commands[0]
    for required in (
        "--no-network",
        "--no-cache",
        "--no-logfile",
        "--no-scripts",
        "--force-non-repository",
    ):
        assert required in command
    repositories_path = Path(command[command.index("--repositories-file") + 1])
    assert repositories_path.read_bytes() == b""
    assert str(package) in command
    assert "fixture=1.0-r0" in command
    assert all("http://" not in item and "https://" not in item for item in command)


def assert_network_lane_separation(tmp: Path) -> None:
    network_calls = {
        "safe_download_snapshot",
        "fetch_locked_file",
        "fetch_package_closure",
    }
    assert "urllib.request.urlopen" in function_calls(
        lovelace_builder.safe_download_snapshot
    )
    assert "safe_download_snapshot" in function_calls(
        lovelace_builder.fetch_package_closure
    )
    assert {
        "fetch_locked_file",
        "fetch_package_closure",
    } <= function_calls(lovelace_builder.fetch_inputs)
    for function in (
        lovelace_builder.verify_inputs,
        lovelace_builder.install_offline_root,
        lovelace_builder.build,
        lovelace_builder.verify_build,
    ):
        assert not (function_calls(function) & network_calls), function.__name__

    with mock.patch.dict(os.environ, {}, clear=True):
        parsed_build = lovelace_builder.parser().parse_args(["build"])
        parsed_verify = lovelace_builder.parser().parse_args(["verify"])
        parsed_verify_inputs = lovelace_builder.parser().parse_args(
            ["verify-inputs"]
        )
        parsed_reproducibility = lovelace_builder.parser().parse_args(
            ["reproducibility-test"]
        )
        parsed_hostile = lovelace_builder.parser().parse_args(["hostile-test"])
        parsed_hostile_payload = lovelace_builder.parser().parse_args(
            ["hostile-payload-test"]
        )
        parsed_launch = lovelace_builder.parser().parse_args(["launch"])
    assert parsed_build.command == "build"
    assert parsed_verify.command == "verify"
    assert parsed_verify_inputs.command == "verify-inputs"
    assert parsed_reproducibility.command == "reproducibility-test"
    assert parsed_hostile.command == "hostile-test"
    assert parsed_hostile_payload.command == "hostile-payload-test"
    assert parsed_launch.storage == "volatile"
    assert parsed_launch.network == "none"
    assert parsed_launch.accel == "auto"

    fetch_root = tmp / "fetch-lane"
    output = fetch_root / "output"
    output.parent.mkdir(parents=True)
    package_lock = fetch_root / "package-lock.json"
    fetches: list[tuple[str, Path]] = []
    closure_calls: list[Path] = []
    writes: list[tuple[Path, object]] = []
    release = {"release_id": "fixture-release"}
    seeds = {"architecture": "x86_64"}
    ghidra = {
        "filename": "ghidra.zip",
        "size": 7,
        "sha256": "0" * 64,
    }

    def fake_fetch(record: dict[str, Any], destination: Path) -> None:
        fetches.append((str(record["filename"]), destination))

    def fake_closure(
        _seeds: dict[str, Any],
        _cache: Path,
        _bootstrap: Path,
        _keys: Path,
        work: Path,
    ) -> dict[str, Any]:
        closure_calls.append(work)
        return {"package_count": 1}

    with patched(
        REPO=fetch_root,
        DEFAULT_OUTPUT=output,
        PACKAGE_LOCK_PATH=package_lock,
        configuration=lambda: (release, seeds, ghidra),
        shared_alpine_lock=lambda _release: {},
        boot_cache_records=lambda _lock: [{"filename": "alpine.iso"}],
        fetch_locked_file=fake_fetch,
        verify_boot_media=lambda *_args: (
            fetch_root / "alpine.iso",
            fetch_root / "kernel",
            fetch_root / "initramfs",
        ),
        materialize_apk_bootstrap=lambda *_args: (
            fetch_root / "bootstrap",
            fetch_root / "keys",
        ),
        fetch_package_closure=fake_closure,
        validate_package_lock=lambda *_args: None,
        write_json=lambda path, value: writes.append((path, value)),
    ):
        fetch_result = lovelace_builder.fetch_inputs(fetch_root / "cache")
    assert [name for name, _destination in fetches] == [
        "alpine.iso",
        "ghidra.zip",
    ]
    assert len(closure_calls) == 1
    assert writes == [(package_lock, {"package_count": 1})]
    assert fetch_result["network_boundary"] == (
        "Only this explicit fetch command used the network."
    )

    verify_root = tmp / "verify-lane"
    verify_root.mkdir()
    verify_lock = verify_root / "package-lock.json"
    write_json(verify_lock, {"repositories": [], "packages": []})
    verify_ghidra = {"filename": "ghidra.zip"}

    def network_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("verify-inputs attempted a network helper")

    with patched(
        PACKAGE_LOCK_PATH=verify_lock,
        configuration=lambda: ({}, {}, verify_ghidra),
        validate_package_lock=lambda *_args: None,
        shared_alpine_lock=lambda _release: {},
        verify_boot_media=lambda *_args: (
            verify_root / "alpine.iso",
            verify_root / "kernel",
            verify_root / "initramfs",
        ),
        materialize_apk_bootstrap=lambda *_args: (
            verify_root / "bootstrap",
            verify_root / "keys",
        ),
        apk_command=lambda _bootstrap: ["fixture-apk"],
        apk_environment=lambda _work: {},
        verify_locked_file=lambda *_args: None,
        safe_download_snapshot=network_forbidden,
        fetch_locked_file=network_forbidden,
        fetch_package_closure=network_forbidden,
    ):
        verified = lovelace_builder.verify_inputs(
            verify_root / "cache", verify_root / "work"
        )
    assert verified[4] == verify_root / "kernel"
    assert verified[5] == verify_root / "initramfs"

    expected_probe_line = f"{'a' * 64}  alpine.iso"
    probe = lovelace_builder.explicit_network_probe_command(
        "https://example.invalid/alpine.iso.sha256",
        expected_probe_line,
    )
    assert lovelace_builder.QEMU_USER_NETDEV == wuci_lab.QEMU_USER_NETDEV
    assert lovelace_builder.QEMU_USER_NETDEV == (
        "user,id=wuci-net,restrict=off,ipv6=off,"
        "net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,"
        "dhcpstart=10.0.2.15"
    )
    assert "hostfwd" not in lovelace_builder.QEMU_USER_NETDEV
    assert lovelace_builder.TCG_CPU_MODEL == wuci_lab.TCG_CPU_MODEL
    assert lovelace_builder.TCG_CPU_MODEL == (
        "Broadwell-v4,pcid=off,x2apic=off,tsc-deadline=off,"
        "invpcid=off,spec-ctrl=off"
    )
    with mock.patch.object(
        lovelace_builder,
        "trusted_host_tool",
        return_value=Path("/fixture/qemu-system-x86_64"),
    ):
        builder_argv = lovelace_builder.qemu_argv(
            {
                "kernel": Path("/fixture/kernel"),
                "initramfs": Path("/fixture/initramfs"),
                "base_image": Path("/fixture/base.img"),
            },
            {},
        )
    assert (
        builder_argv[builder_argv.index("-cpu") + 1]
        == lovelace_builder.TCG_CPU_MODEL
    )
    assert (
        lovelace_builder.functional_qemu_cpu_model(builder_argv)
        == lovelace_builder.TCG_CPU_MODEL
    )
    expected_kernel_arguments = (
        lovelace_builder.expected_functional_kernel_arguments()
    )
    expected_release_kernel_arguments = (
        lovelace_builder.expected_release_kernel_arguments()
    )
    assert list(wuci_lab.KERNEL_ARGUMENTS) == expected_release_kernel_arguments
    assert wuci_lab.KERNEL_APPEND.split() == expected_release_kernel_arguments
    assert expected_kernel_arguments[-1] == "nosoftlockup"
    assert expected_kernel_arguments.count("nosoftlockup") == 1
    profile = lovelace_builder.load_object(
        lovelace_builder.PROFILE_PATH
    )
    kernel_policy = profile["virtualization"]["functional"][
        "kernel_argument_policy"
    ]
    assert (
        kernel_policy["canonical_builder_arguments"]
        == expected_kernel_arguments
    )
    assert (
        kernel_policy["interactive_supervisor_arguments"]
        == wuci_lab._kernel_append_for_acceleration("tcg").split()
    )
    assert kernel_policy["tcg_only_extra_arguments"] == [
        *lovelace_builder.FUNCTIONAL_TCG_EXTRA_KERNEL_ARGUMENTS
    ]
    assert kernel_policy["tcg_only_extra_arguments"] == [
        *wuci_lab.FUNCTIONAL_TCG_EXTRA_KERNEL_ARGUMENTS
    ]
    assert (
        lovelace_builder.functional_qemu_kernel_arguments(builder_argv)
        == expected_kernel_arguments
    )
    assert "nosoftlockup" not in wuci_lab._kernel_append_for_acceleration(
        "kvm"
    ).split()
    assert wuci_lab._kernel_append_for_acceleration("kvm").split() == (
        expected_release_kernel_arguments
    )
    assert "max" not in builder_argv
    stale_argv = list(builder_argv)
    stale_argv[stale_argv.index("-cpu") + 1] = "max"
    expect_lovelace_error(
        lambda: lovelace_builder.functional_qemu_cpu_model(stale_argv),
        "does not bind the pinned TCG CPU model",
    )
    lovelace_builder.reject_forbidden_tcg_diagnostics(
        "benign QEMU console"
    )
    expect_lovelace_error(
        lambda: lovelace_builder.reject_forbidden_tcg_diagnostics(
            "qemu-system-x86_64: warning: "
            "TCG doesn't support requested feature: "
            "CPUID.01H:ECX.pcid [bit 17]"
        ),
        "filtered the pinned functional TCG CPU model",
    )
    try:
        lovelace_builder.reject_forbidden_guest_runtime_diagnostics(
            "\x1b]52;fixture\x07Kernel panic - not syncing: fixture",
            "hostile guest console",
        )
    except lovelace_builder.LovelaceError as exc:
        assert "\x1b" not in str(exc)
        assert "\\x1b" in str(exc)
    else:
        raise AssertionError("terminal-control diagnostic was accepted")
    split_diagnostic_output = bytearray()
    lovelace_builder._append_hostile_console_block(
        split_diagnostic_output, b"Kernel panic - not syn"
    )
    expect_lovelace_error(
        lambda: lovelace_builder._append_hostile_console_block(
            split_diagnostic_output, b"cing: split fixture"
        ),
        "hostile guest console emitted a forbidden kernel or storage "
        "diagnostic",
    )
    expect_lovelace_error(
        lambda: lovelace_builder._append_hostile_console_block(
            bytearray(), b"fixture\x1b]52;clipboard\x07"
        ),
        "raw terminal-control or non-ASCII bytes",
    )
    stale_kernel_argv = list(builder_argv)
    append_index = stale_kernel_argv.index("-append")
    stale_kernel_argv[append_index + 1] = " ".join(
        expected_kernel_arguments[:-1]
    )
    expect_lovelace_error(
        lambda: lovelace_builder.functional_qemu_kernel_arguments(
            stale_kernel_argv
        ),
        "does not bind the exact kernel arguments",
    )
    assert "LOVELACE_EXPLICIT_INTERNET_PASS" not in probe
    assert "|" not in probe
    assert probe.startswith("(set -efu;")
    expected_probe_response = (expected_probe_line + "\n").encode("ascii")
    assert str(len(expected_probe_response)) in probe
    assert hashlib.sha256(expected_probe_response).hexdigest() in probe
    failed_probe = probe.replace(
        "test -d /sys/class/net/eth0", "false", 1
    )
    failed = subprocess.run(
        ["/bin/sh", "-c", failed_probe],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=10,
    )
    assert failed.returncode != 0
    assert "LOVELACE_EXPLICIT_INTERNET_PASS" not in failed.stdout
    expect_lovelace_error(
        lambda: lovelace_builder.explicit_network_probe_command(
            "https://example.invalid/'bad", "fixture"
        ),
        "invalid explicit-network probe binding",
    )
    assert "console_tail=" in inspect.getsource(
        lovelace_builder.run_qemu_commands
    )
    assert "reject_forbidden_tcg_diagnostics" in inspect.getsource(
        lovelace_builder.run_qemu_commands
    )


def assert_explicit_network_probe_execution(tmp: Path) -> None:
    expected_line = f"{'a' * 64}  alpine.iso"
    expected_response = (expected_line + "\n").encode("ascii")
    probe = lovelace_builder.explicit_network_probe_command(
        "https://example.invalid/alpine.iso.sha256", expected_line
    )
    assert probe.startswith("(set -efu;")
    assert probe.endswith(")")
    assert "|" not in probe
    assert "LOVELACE_EXPLICIT_INTERNET_PASS" not in probe

    root = tmp / "network-probe-execution"
    fake_bin = root / "bin"
    fake_eth0 = root / "sys/class/net/eth0"
    fake_bin.mkdir(parents=True)
    fake_eth0.mkdir(parents=True)
    resolv_conf = root / "resolv.conf"

    fake_ip = fake_bin / "ip"
    fake_ip.write_text(
        "#!/bin/sh\n"
        "case \" $* \" in\n"
        "  *\" address \"*|*\" addr \"*)\n"
        "    printf '%s\\n' \"2: eth0    inet "
        "${FAKE_IPV4_CIDR:-10.0.2.15/24} scope global eth0\" ;;\n"
        "  *\" route \"*)\n"
        "    printf '%s\\n' \"default via "
        "${FAKE_GATEWAY_IPV4:-10.0.2.2} dev eth0"
        "${FAKE_ROUTE_SUFFIX-}\" ;;\n"
        "  *\" link \"*) exit 0 ;;\n"
        "  *) exit 19 ;;\n"
        "esac\n",
        encoding="ascii",
    )
    fake_ss = fake_bin / "ss"
    fake_ss.write_text(
        "#!/bin/sh\n"
        "printf '%s' \"${FAKE_SS_OUTPUT-}\"\n"
        "exit \"${FAKE_SS_STATUS:-0}\"\n",
        encoding="ascii",
    )
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        "#!/bin/sh\n"
        "output=\n"
        "while test \"$#\" -gt 0; do\n"
        "  case \"$1\" in\n"
        "    --output|-o) shift; test \"$#\" -gt 0 || exit 91; "
        "output=$1 ;;\n"
        "  esac\n"
        "  shift\n"
        "done\n"
        "test -n \"$output\" || exit 92\n"
        "printf '%s' \"${FAKE_CURL_BODY-}\" > \"$output\" || exit 93\n"
        "exit \"${FAKE_CURL_STATUS:-0}\"\n",
        encoding="ascii",
    )
    for executable in (fake_ip, fake_ss, fake_curl):
        executable.chmod(0o755)

    executable_probe = probe.replace(
        "/sys/class/net/eth0", str(fake_eth0)
    ).replace("/etc/resolv.conf", str(resolv_conf))
    marker = "LOVELACE_EXPLICIT_INTERNET_PASS"

    def execute_probe(
        *,
        response: bytes = expected_response,
        curl_status: int = 0,
        ss_status: int = 0,
        ss_output: str = "",
        ipv4_cidr: str = "10.0.2.15/24",
        gateway_ipv4: str = "10.0.2.2",
        route_suffix: str = "",
        resolver: bytes = (
            b"nameserver 10.0.2.3\noptions timeout:2 attempts:3\n"
        ),
        terminal_prefix: bool = False,
        following_command: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        resolv_conf.write_bytes(resolver)
        environment = {
            "HOME": str(root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "TMPDIR": str(root),
            "FAKE_CURL_BODY": response.decode("ascii"),
            "FAKE_CURL_STATUS": str(curl_status),
            "FAKE_SS_STATUS": str(ss_status),
            "FAKE_SS_OUTPUT": ss_output,
            "FAKE_IPV4_CIDR": ipv4_cidr,
            "FAKE_GATEWAY_IPV4": gateway_ipv4,
            "FAKE_ROUTE_SUFFIX": route_suffix,
            "POWER_OFF_SENTINEL": str(root / "poweroff-equivalent"),
        }
        command = executable_probe
        if terminal_prefix:
            command = "printf '\\033[?2004l\\r'; " + command
        if following_command is not None:
            command += "; " + following_command
        return subprocess.run(
            ["/bin/sh", "-c", command],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            timeout=10,
        )

    success = execute_probe()
    assert success.returncode == 0, success.stderr
    assert success.stdout == ("\n" + marker + "\n").encode("ascii")

    interactive_framing = execute_probe(terminal_prefix=True)
    assert interactive_framing.returncode == 0
    interactive_lines = [
        line
        for _start, _end, line in (
            lovelace_builder._complete_console_line_spans(
                interactive_framing.stdout
            )
        )
    ]
    assert interactive_lines.count(marker.encode("ascii")) == 1

    alpine_trailing_space = execute_probe(route_suffix=" ")
    assert alpine_trailing_space.returncode == 0
    assert alpine_trailing_space.stdout == (
        "\n" + marker + "\n"
    ).encode("ascii")

    extra_route_token = execute_probe(route_suffix=" metric")
    assert extra_route_token.returncode != 0
    assert marker.encode("ascii") not in extra_route_token.stdout

    curl_nonzero = execute_probe(curl_status=23)
    assert curl_nonzero.returncode != 0
    assert marker.encode("ascii") not in curl_nonzero.stdout

    sentinel = root / "poweroff-equivalent"
    failed_then_poweroff = execute_probe(
        curl_status=23,
        following_command=(
            "printf '%s\\n' poweroff-equivalent > "
            '"$POWER_OFF_SENTINEL"'
        ),
    )
    assert failed_then_poweroff.returncode == 0
    assert marker.encode("ascii") not in failed_then_poweroff.stdout
    assert sentinel.read_bytes() == b"poweroff-equivalent\n"

    extra_response = execute_probe(response=expected_response + b"extra\n")
    assert extra_response.returncode != 0
    assert marker.encode("ascii") not in extra_response.stdout

    altered_response = execute_probe(
        response=b"b" + expected_response[1:]
    )
    assert altered_response.returncode != 0
    assert marker.encode("ascii") not in altered_response.stdout

    ss_nonzero = execute_probe(ss_status=7)
    assert ss_nonzero.returncode != 0
    assert marker.encode("ascii") not in ss_nonzero.stdout

    listening_socket = execute_probe(
        ss_output="LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    )
    assert listening_socket.returncode != 0
    assert marker.encode("ascii") not in listening_socket.stdout

    for wrong_topology in (
        {"ipv4_cidr": "10.0.2.16/24"},
        {"gateway_ipv4": "10.0.2.1"},
        {"resolver": b"nameserver 10.0.2.4\n"},
    ):
        rejected = execute_probe(**wrong_topology)
        assert rejected.returncode != 0
        assert marker.encode("ascii") not in rejected.stdout


def assert_network_binding_and_launch_contracts(tmp: Path) -> None:
    release, _seeds, _ghidra = lovelace_builder.configuration()
    alpine_lock = lovelace_builder.shared_alpine_lock(release)
    binding = lovelace_builder.network_probe_binding(release)
    assert binding["expected_response_bytes"] == binding[
        "maximum_response_bytes"
    ]
    assert binding["expected_response_sha256"] == hashlib.sha256(
        (binding["expected_exact_line"] + "\n").encode("ascii")
    ).hexdigest()
    assert binding["connect_timeout_seconds"] == (
        lovelace_builder.NETWORK_CONNECT_TIMEOUT_SECONDS
    )
    assert binding["transfer_timeout_seconds"] == (
        lovelace_builder.NETWORK_TRANSFER_TIMEOUT_SECONDS
    )

    def reject_lock(
        lock: dict[str, Any], contains: str | None = None
    ) -> None:
        with patched(shared_alpine_lock=lambda _release: lock):
            expect_lovelace_error(
                lambda: lovelace_builder.network_probe_binding(release),
                contains,
            )

    missing_role = copy.deepcopy(alpine_lock)
    missing_role["boot_media"]["sidecars"] = [
        record
        for record in missing_role["boot_media"]["sidecars"]
        if record["role"] != "sha256-digest"
    ]
    reject_lock(missing_role, "exactly one sha256-digest sidecar")

    duplicate_role = copy.deepcopy(alpine_lock)
    sha256_sidecar = next(
        record
        for record in duplicate_role["boot_media"]["sidecars"]
        if record["role"] == "sha256-digest"
    )
    duplicate_role["boot_media"]["sidecars"].append(
        copy.deepcopy(sha256_sidecar)
    )
    reject_lock(duplicate_role, "exactly one sha256-digest sidecar")

    for field, value in (
        ("suffix", ".digest"),
        ("url", "https://example.invalid/wrong.sha256"),
        ("size", sha256_sidecar["size"] + 1),
        ("sha256", "0" * 64),
    ):
        malformed = copy.deepcopy(alpine_lock)
        record = next(
            candidate
            for candidate in malformed["boot_media"]["sidecars"]
            if candidate["role"] == "sha256-digest"
        )
        record[field] = value
        reject_lock(
            malformed,
            "authenticated Alpine SHA-256 sidecar binding is invalid",
        )

    stale_release = copy.deepcopy(release)
    stale_release["shared_alpine_input"]["canonical_sha256"] = "0" * 64
    expect_lovelace_error(
        lambda: lovelace_builder.network_probe_binding(stale_release),
        "shared authenticated Alpine input lock drift",
    )

    calls = function_calls(lovelace_builder.network_test)
    assert {"configuration", "network_probe_binding"} <= calls
    assert "shared_alpine_lock" in function_calls(
        lovelace_builder.network_probe_binding
    )
    assert {"configuration", "network_probe_binding"} <= function_calls(
        lovelace_builder.validate_evidence_document
    )

    launch_root = tmp / "network-launch-contract"
    launch_root.mkdir()
    base = launch_root / "base.ext4"
    overlay = launch_root / "volatile.qcow2"
    kernel = launch_root / "kernel"
    initramfs = launch_root / "initramfs"
    for path in (base, overlay, kernel, initramfs):
        path.write_bytes(b"fixture\n")
    launch_paths = {
        "kernel": kernel,
        "initramfs": initramfs,
        "base_image": base,
    }
    with patched(
        trusted_host_tool=lambda name: Path(
            f"/usr/bin/{name}"
        )
    ):
        argv = lovelace_builder.qemu_argv(
            launch_paths,
            {},
            disk=overlay,
            disk_format="qcow2",
            snapshot=False,
            network="internet",
        )
    expected = {
        "machine": "q35,accel=tcg",
        "accelerator": "tcg",
        "netdev": lovelace_builder.QEMU_USER_NETDEV,
        "network_device": lovelace_builder.QEMU_USER_NETWORK_DEVICE,
        "host_forwarding": False,
        "root_disk_format": "qcow2",
        "temporary_overlay": True,
        "base_image_directly_writable": False,
        "qemu_snapshot_flag": False,
    }
    def launch_contract(values: list[str]) -> dict[str, Any]:
        with patched(
            trusted_host_tool=lambda name: Path(f"/usr/bin/{name}")
        ):
            return lovelace_builder.network_qemu_launch_contract(
                values, launch_paths, overlay
            )

    assert launch_contract(argv) == expected

    def replace_option_value(
        values: list[str], option: str, replacement: str
    ) -> list[str]:
        changed = list(values)
        index = changed.index(option)
        changed[index + 1] = replacement
        return changed

    host_forward = replace_option_value(
        argv,
        "-netdev",
        lovelace_builder.QEMU_USER_NETDEV
        + ",hostfwd=tcp::2222-:22",
    )
    different_netdev = replace_option_value(
        argv, "-netdev", "user,id=unexpected"
    )
    missing_nic = list(argv)
    nic_index = next(
        index
        for index, value in enumerate(missing_nic)
        if value == lovelace_builder.QEMU_USER_NETWORK_DEVICE
    )
    del missing_nic[nic_index - 1 : nic_index + 1]
    drive_index = argv.index("-drive") + 1
    raw_disk = list(argv)
    raw_disk[drive_index] = raw_disk[drive_index].replace(
        "format=qcow2", "format=raw"
    )
    direct_base = list(argv)
    direct_base[drive_index] = direct_base[drive_index].replace(
        f"file={overlay.resolve()}", f"file={base.resolve()}"
    )
    snapshot_disk = [*argv, "-snapshot"]
    legacy_net = [*argv, "-net", "user"]
    readconfig = [*argv, "-readconfig", "/tmp/fixture-qemu.cfg"]
    extra_option = [*argv, "-name", "unexpected"]
    for malformed_argv in (
        host_forward,
        different_netdev,
        missing_nic,
        raw_disk,
        direct_base,
        snapshot_disk,
        legacy_net,
        readconfig,
        extra_option,
    ):
        expect_lovelace_error(
            lambda malformed_argv=malformed_argv: launch_contract(
                malformed_argv
            ),
            "volatile user-NAT contract",
        )


def assert_output_lock_timeout(tmp: Path) -> None:
    output = tmp / "bounded-output-lock"
    output.mkdir()
    lock_path = output / ".build.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    sentinel = output / "sentinel"
    sentinel.write_bytes(b"unchanged\n")
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,os,sys; "
                "fd=os.open(sys.argv[1],os.O_RDWR); "
                "fcntl.flock(fd,fcntl.LOCK_EX); "
                "sys.stdout.write('locked\\n'); sys.stdout.flush(); "
                "sys.stdin.buffer.read(1); os.close(fd)"
            ),
            str(lock_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline() == b"locked\n"
        entered = False

        def contend() -> None:
            nonlocal entered
            with lovelace_builder.output_lock(output):
                entered = True

        started = time.monotonic()
        with patched(
            OUTPUT_LOCK_TIMEOUT_SECONDS=0.1,
            OUTPUT_LOCK_RETRY_SECONDS=0.01,
        ):
            expect_lovelace_error(
                contend, "timed out waiting for the Lovelace output lock"
            )
        elapsed = time.monotonic() - started
        assert 0.08 <= elapsed < 1.0, elapsed
        assert entered is False
        assert sentinel.read_bytes() == b"unchanged\n"
    finally:
        if holder.stdin is not None:
            holder.stdin.write(b"x")
            holder.stdin.flush()
            holder.stdin.close()
        holder.wait(timeout=10)
    assert holder.returncode == 0, (
        holder.stderr.read() if holder.stderr is not None else b""
    )
    with patched(
        OUTPUT_LOCK_TIMEOUT_SECONDS=0.1,
        OUTPUT_LOCK_RETRY_SECONDS=0.01,
    ):
        with lovelace_builder.output_lock(output):
            pass


def assert_evidence_producer_locking(tmp: Path) -> None:
    update_source = inspect.getsource(lovelace_builder.update_validation)
    assert "with output_lock(output)" in update_source
    assert "_lock_held" not in update_source
    assert "_lock_held" not in inspect.signature(
        lovelace_builder.update_validation
    ).parameters
    wrapper_pairs = (
        (lovelace_builder.boot_test, lovelace_builder._boot_test_unlocked),
        (
            lovelace_builder.ghidra_test,
            lovelace_builder._ghidra_test_unlocked,
        ),
        (
            lovelace_builder.noxframe_test,
            lovelace_builder._noxframe_test_unlocked,
        ),
        (
            lovelace_builder.persistent_round_trip_test,
            lovelace_builder._persistent_round_trip_test_unlocked,
        ),
        (
            lovelace_builder.reproducibility_test,
            lovelace_builder._reproducibility_test_unlocked,
        ),
    )
    for public, unlocked in wrapper_pairs:
        assert "with output_lock(output)" in inspect.getsource(public)
        assert "_update_validation_unlocked(" in inspect.getsource(unlocked)
    for inline_locked in (
        lovelace_builder.network_test,
        lovelace_builder.hostile_test,
        lovelace_builder.hostile_payload_test,
    ):
        source = inspect.getsource(inline_locked)
        assert "with output_lock(output)" in source
        assert "_update_validation_unlocked(" in source

    output = tmp / "producer-lock-integration"
    output.mkdir()
    lock_path = output / ".build.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import fcntl,os,sys; "
                "fd=os.open(sys.argv[1],os.O_RDWR); "
                "fcntl.flock(fd,fcntl.LOCK_EX); "
                "sys.stdout.write('locked\\n'); sys.stdout.flush(); "
                "sys.stdin.buffer.read(1); os.close(fd)"
            ),
            str(lock_path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    body_calls = {
        name: 0
        for name in (
            "boot",
            "ghidra",
            "noxframe",
            "persistent",
            "reproducibility",
            "update",
        )
    }

    def body(name: str) -> Callable[..., str]:
        def reached(*_args: object, **_kwargs: object) -> str:
            body_calls[name] += 1
            return name

        return reached

    try:
        assert holder.stdout is not None
        assert holder.stdout.readline() == b"locked\n"
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    lovelace_builder,
                    "_boot_test_unlocked",
                    side_effect=body("boot"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    lovelace_builder,
                    "_ghidra_test_unlocked",
                    side_effect=body("ghidra"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    lovelace_builder,
                    "_noxframe_test_unlocked",
                    side_effect=body("noxframe"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    lovelace_builder,
                    "_persistent_round_trip_test_unlocked",
                    side_effect=body("persistent"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    lovelace_builder,
                    "_reproducibility_test_unlocked",
                    side_effect=body("reproducibility"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    lovelace_builder,
                    "_update_validation_unlocked",
                    side_effect=body("update"),
                )
            )
            invocations: tuple[Callable[[], object], ...] = (
                lambda: lovelace_builder.boot_test(output),
                lambda: lovelace_builder.ghidra_test(output),
                lambda: lovelace_builder.noxframe_test(output),
                lambda: lovelace_builder.persistent_round_trip_test(output),
                lambda: lovelace_builder.reproducibility_test(
                    tmp / "unused-cache", output
                ),
                lambda: lovelace_builder.update_validation(
                    output, {}, "unused.json", {}
                ),
            )
            with patched(
                OUTPUT_LOCK_TIMEOUT_SECONDS=0.05,
                OUTPUT_LOCK_RETRY_SECONDS=0.005,
            ):
                for invoke in invocations:
                    expect_lovelace_error(
                        invoke,
                        "timed out waiting for the Lovelace output lock",
                    )
            assert set(body_calls.values()) == {0}
    finally:
        if holder.stdin is not None:
            holder.stdin.write(b"x")
            holder.stdin.flush()
            holder.stdin.close()
        holder.wait(timeout=10)
    assert holder.returncode == 0, (
        holder.stderr.read() if holder.stderr is not None else b""
    )
    released_invocations = (
        (
            "_boot_test_unlocked",
            body("boot"),
            lambda: lovelace_builder.boot_test(output),
            "boot",
        ),
        (
            "_ghidra_test_unlocked",
            body("ghidra"),
            lambda: lovelace_builder.ghidra_test(output),
            "ghidra",
        ),
        (
            "_noxframe_test_unlocked",
            body("noxframe"),
            lambda: lovelace_builder.noxframe_test(output),
            "noxframe",
        ),
        (
            "_persistent_round_trip_test_unlocked",
            body("persistent"),
            lambda: lovelace_builder.persistent_round_trip_test(output),
            "persistent",
        ),
        (
            "_reproducibility_test_unlocked",
            body("reproducibility"),
            lambda: lovelace_builder.reproducibility_test(
                tmp / "unused-cache", output
            ),
            "reproducibility",
        ),
        (
            "_update_validation_unlocked",
            body("update"),
            lambda: lovelace_builder.update_validation(
                output, {}, "unused.json", {}
            ),
            None,
        ),
    )
    for private_name, private_body, invoke, expected in released_invocations:
        with mock.patch.object(
            lovelace_builder, private_name, side_effect=private_body
        ):
            assert invoke() == expected
    assert set(body_calls.values()) == {1}


def assert_explicit_xorriso_contract(tmp: Path) -> None:
    tool = tmp / "xorriso fixture"
    tool.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'GNU xorriso 1.5.8.pl02 fixture'\n",
        encoding="ascii",
    )
    tool.chmod(0o755)
    previous = os.environ.get("LOVELACE_XORRISO")
    try:
        os.environ["LOVELACE_XORRISO"] = str(tool)
        assert lovelace_builder.trusted_xorriso() == tool.resolve()

        tool.chmod(0o775)
        expect_lovelace_error(
            lovelace_builder.trusted_xorriso,
            "not group/world writable",
        )
        tool.chmod(0o755)

        os.environ["LOVELACE_XORRISO"] = "relative/xorriso"
        expect_lovelace_error(
            lovelace_builder.trusted_xorriso,
            "must be an absolute path",
        )

        wrong = tmp / "wrong-xorriso"
        wrong.write_text(
            "#!/bin/sh\nprintf '%s\\n' 'GNU xorriso 1.5.7'\n",
            encoding="ascii",
        )
        wrong.chmod(0o755)
        os.environ["LOVELACE_XORRISO"] = str(wrong)
        expect_lovelace_error(
            lovelace_builder.trusted_xorriso,
            "exact supported version",
        )
    finally:
        if previous is None:
            os.environ.pop("LOVELACE_XORRISO", None)
        else:
            os.environ["LOVELACE_XORRISO"] = previous


def assert_ghidra_smoke_command(tmp: Path) -> None:
    prefix = f"wuci-ghidra-fixture-{os.getpid()}"
    command = lovelace_builder.ghidra_smoke_command(
        project_name="fixture-project",
        temporary_prefix=prefix,
        timeout_seconds=2,
        success_marker=lovelace_builder.GHIDRA_PASS_MARKER,
    )
    assert "-analysisTimeoutPerFile" not in command
    assert "</dev/null" in command
    assert "JAVA_TOOL_OPTIONS=" in command
    assert lovelace_builder.GHIDRA_JAVA_COMPILER_OPTION in command
    assert (
        f"GHIDRA_HEADLESS_MAXMEM={lovelace_builder.GHIDRA_HEADLESS_MAXMEM}"
        in command
    )
    assert "-Xint" not in command
    assert (
        f"-scriptPath {lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_PATH}"
        in command
    )
    assert (
        f"-postScript {lovelace_builder.GHIDRA_SEMANTIC_SCRIPT_NAME}"
        in command
    )
    assert lovelace_builder.GHIDRA_SEMANTIC_MARKER not in command
    assert lovelace_builder.GHIDRA_PASS_MARKER not in command
    assert lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER not in command
    assert not list(Path("/tmp").glob(prefix + ".*"))

    fake_bin = tmp / "ghidra-command-bin"
    fake_bin.mkdir()
    system_timeout = shutil.which("timeout")
    system_find = shutil.which("find")
    system_mktemp = shutil.which("mktemp")
    assert system_timeout and system_find and system_mktemp

    (fake_bin / "ghidra-headless").write_text(
        "#!/bin/sh\n"
        "if IFS= read -r consumed; then exit 86; fi\n"
        "work=${1%/projects}\n"
        f"case \"$work\" in /tmp/{prefix}.*) ;; *) exit 89 ;; esac\n"
        "test \"$1\" = \"$work/projects\" || exit 90\n"
        "test \"$(stat -c %a \"$work\")\" = 700 || exit 91\n"
        "test \"$HOME\" = \"$work/home\" || exit 92\n"
        "test \"$XDG_CONFIG_HOME\" = \"$work/config\" || exit 93\n"
        "test \"$XDG_CACHE_HOME\" = \"$work/cache\" || exit 94\n"
        "test \"$TMPDIR\" = \"$work/tmp\" || exit 95\n"
        "test \"$GHIDRA_HEADLESS_MAXMEM\" = \"2G\" || exit 99\n"
        "test \"$JAVA_TOOL_OPTIONS\" = \""
        f"{lovelace_builder.GHIDRA_JAVA_COMPILER_OPTION} "
        "-Duser.home=$work/home "
        "-Djava.io.tmpdir=$work/tmp\" || exit 96\n"
        "for state in \"$HOME\" \"$XDG_CONFIG_HOME\" "
        "\"$XDG_CACHE_HOME\" \"$TMPDIR\"; do\n"
        "  test -d \"$state\" || exit 97\n"
        "  : > \"$state/fixture-private-state\" || exit 98\n"
        "done\n"
        "case \"${FAKE_GHIDRA_MODE:-success}\" in\n"
        "  success) printf '%s\\n' "
        "'LOVELACE_GHIDRA_SEMANTIC_PASS'; exit 0 ;;\n"
        "  nonnewline) printf '%s\\n' "
        "'LOVELACE_GHIDRA_SEMANTIC_PASS'; "
        "printf '%s' 'fixture-no-newline'; exit 0 ;;\n"
        "  importfail) printf '%s\\n' 'fixture import failed'; exit 0 ;;\n"
        "  exit1) exit 1 ;;\n"
        "  residue) printf '%s\\n' "
        "'LOVELACE_GHIDRA_SEMANTIC_PASS'; "
        ": > \"$1/residue\"; exit 0 ;;\n"
        "  *) exit 87 ;;\n"
        "esac\n",
        encoding="ascii",
    )
    (fake_bin / "timeout").write_text(
        "#!/bin/sh\n"
        "case \"${FAKE_TIMEOUT_STATUS:-}\" in\n"
        "  124|137) exit \"$FAKE_TIMEOUT_STATUS\" ;;\n"
        f"  '') exec {system_timeout} \"$@\" ;;\n"
        "  *) exit 88 ;;\n"
        "esac\n",
        encoding="ascii",
    )
    (fake_bin / "find").write_text(
        "#!/bin/sh\n"
        "test \"${FAKE_FIND_FAILURE:-0}\" = 0 || exit 75\n"
        f"exec {system_find} \"$@\"\n",
        encoding="ascii",
    )
    (fake_bin / "mktemp").write_text(
        "#!/bin/sh\n"
        "test \"${FAKE_MKTEMP_FAILURE:-0}\" = 0 || exit 71\n"
        f"exec {system_mktemp} \"$@\"\n",
        encoding="ascii",
    )
    for executable in fake_bin.iterdir():
        executable.chmod(0o755)

    def execute(**overrides: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(overrides)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        result = subprocess.run(
            [
                "/bin/sh",
                "-c",
                command
                + "; status=$?; printf '%s\\n' "
                "'LOVELACE_POWER_OFF_SENTINEL'; exit \"$status\"",
            ],
            env=environment,
            input="queued-poweroff-must-not-reach-ghidra\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
            timeout=10,
        )
        assert result.stdout.count("LOVELACE_POWER_OFF_SENTINEL") == 1
        assert not list(Path("/tmp").glob(prefix + ".*"))
        return result

    success = execute()
    assert success.returncode == 0, success.stderr
    assert success.stdout.count(
        lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER
    ) == 1
    assert success.stdout.count(
        lovelace_builder.GHIDRA_SEMANTIC_MARKER
    ) == 1
    assert success.stdout.count(lovelace_builder.GHIDRA_PASS_MARKER) == 1

    nonnewline = execute(FAKE_GHIDRA_MODE="nonnewline")
    assert nonnewline.returncode == 0, nonnewline.stderr
    assert nonnewline.stdout.count(
        "\n" + lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER + "\n"
    ) == 1
    assert nonnewline.stdout.count(lovelace_builder.GHIDRA_PASS_MARKER) == 1

    import_failure = execute(FAKE_GHIDRA_MODE="importfail")
    assert import_failure.returncode == 0
    assert lovelace_builder.GHIDRA_SEMANTIC_MARKER not in (
        import_failure.stdout
    )
    assert import_failure.stdout.count(
        lovelace_builder.GHIDRA_EXIT_SUCCESS_MARKER
    ) == 1

    for overrides, status_marker in (
        ({"FAKE_GHIDRA_MODE": "exit1"}, "status=1"),
        ({"FAKE_TIMEOUT_STATUS": "124"}, "status=124"),
        ({"FAKE_TIMEOUT_STATUS": "137"}, "status=137"),
        ({"FAKE_GHIDRA_MODE": "residue"}, "status=0"),
        ({"FAKE_FIND_FAILURE": "1"}, "status=0"),
        ({"FAKE_MKTEMP_FAILURE": "1"}, None),
    ):
        failed = execute(**overrides)
        assert failed.returncode != 0
        assert lovelace_builder.GHIDRA_PASS_MARKER not in failed.stdout
        if status_marker is not None:
            assert (
                f"LOVELACE_GHIDRA_HEADLESS_EXIT {status_marker}"
                in failed.stdout
            )

    challenge = "a" * 64
    hostile = lovelace_builder.ghidra_smoke_command(
        project_name="fixture-hostile",
        temporary_prefix=prefix,
        timeout_seconds=2,
        success_marker=lovelace_builder.HOSTILE_GHIDRA_MARKER,
        challenge=challenge,
    )
    assert (
        f"{lovelace_builder.HOSTILE_GHIDRA_MARKER} {challenge}"
        not in hostile
    )
    for invalid in (
        {"project_name": "bad;project"},
        {"temporary_prefix": "../bad"},
        {"timeout_seconds": 0},
        {"success_marker": "bad marker"},
        {"challenge": "b" * 63},
    ):
        values: dict[str, object] = {
            "project_name": "fixture-project",
            "temporary_prefix": prefix,
            "timeout_seconds": 2,
            "success_marker": lovelace_builder.GHIDRA_PASS_MARKER,
            "challenge": None,
        }
        values.update(invalid)
        expect_lovelace_error(
            lambda values=values: lovelace_builder.ghidra_smoke_command(
                **values  # type: ignore[arg-type]
            ),
            "invalid Ghidra smoke command binding",
        )


def assert_functional_qemu_runtime_contract(tmp: Path) -> None:
    clean = tmp / "fake-qemu-clean"
    clean.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
        "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
        "IFS= read -r command\n"
        "test \"$command\" = fixture-command || exit 9\n"
        "printf '%s\\n' 'LOVELACE_FAKE_QEMU_PASS'\n",
        encoding="ascii",
    )
    clean.chmod(0o755)
    argv = [
        str(clean),
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        lovelace_builder.TCG_CPU_MODEL,
        "-append",
        " ".join(lovelace_builder.expected_functional_kernel_arguments()),
    ]
    result = lovelace_builder.run_qemu_commands(
        argv,
        ["fixture-command"],
        [
            lovelace_builder.OFFLINE_BOOT_LINE,
            lovelace_builder.CONSOLE_MARKER,
            "LOVELACE_FAKE_QEMU_PASS",
        ],
        timeout_seconds=10,
    )
    assert result["functional_cpu_model"] == lovelace_builder.TCG_CPU_MODEL
    assert result["functional_kernel_arguments"] == (
        lovelace_builder.expected_functional_kernel_arguments()
    )
    assert result["forbidden_diagnostics_absent"] is True
    assert result["console_eof_observed"] is True
    assert result["console_drain_timeout_seconds"] == (
        lovelace_builder.FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS
    )
    encoded_transcript = result["console_transcript_base64"]
    console = base64.b64decode(encoded_transcript, validate=True)
    assert base64.b64encode(console).decode("ascii") == encoded_transcript
    assert result["console_bytes"] == len(console)
    assert result["console_sha256"] == hashlib.sha256(console).hexdigest()
    assert result["console_tail"] == console.decode(
        "utf-8", errors="replace"
    )[-12000:]
    complete_records = lovelace_builder._hostile_complete_console_line_records(
        console
    )
    ready_offsets = [
        offset
        for offset, line in complete_records
        if line == lovelace_builder.CONSOLE_MARKER.encode("ascii")
    ]
    result_offsets = [
        offset
        for offset, line in complete_records
        if line == b"LOVELACE_FAKE_QEMU_PASS"
    ]
    assert len(ready_offsets) == len(result_offsets) == 1
    assert result["console_ready_line_end_offset"] == (
        ready_offsets[0] + len(lovelace_builder.CONSOLE_MARKER) + 1
    )
    assert (
        result["console_ready_line_end_offset"]
        <= result["command_dispatch_offset"]
        <= result_offsets[0]
    )

    missing = tmp / "fake-qemu-missing-marker"
    missing.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
        "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
        "IFS= read -r command\n"
        "test \"$command\" = fixture-command || exit 9\n"
        "printf '%s\\n' "
        "'LOVELACE_GHIDRA_HEADLESS_EXIT status=124'\n",
        encoding="ascii",
    )
    missing.chmod(0o755)
    missing_argv = list(argv)
    missing_argv[0] = str(missing)
    try:
        lovelace_builder.run_qemu_commands(
            missing_argv,
            ["fixture-command"],
            [
                lovelace_builder.OFFLINE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                "LOVELACE_FAKE_QEMU_PASS",
            ],
            timeout_seconds=10,
        )
    except lovelace_builder.LovelaceError as exc:
        message = str(exc)
        assert "does not contain each exact marker once" in message
        assert "console_tail=" in message
        assert "LOVELACE_GHIDRA_HEADLESS_EXIT status=124" in message
    else:
        raise AssertionError("missing functional marker was accepted")

    long_tail = tmp / "fake-qemu-long-tail"
    long_tail.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
        "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
        "IFS= read -r command\n"
        "test \"$command\" = fixture-command || exit 9\n"
        f"printf '%s\\n' '{'X' * 13050}'\n",
        encoding="ascii",
    )
    long_tail.chmod(0o755)
    long_tail_argv = list(argv)
    long_tail_argv[0] = str(long_tail)
    try:
        lovelace_builder.run_qemu_commands(
            long_tail_argv,
            ["fixture-command"],
            [
                lovelace_builder.OFFLINE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                "LOVELACE_FAKE_QEMU_PASS",
            ],
            timeout_seconds=10,
        )
    except lovelace_builder.LovelaceError as exc:
        message = str(exc)
        assert "does not contain each exact marker once" in message
        tail = message.split("; console_tail=", 1)[1]
        assert lovelace_builder.BOOT_MARKER not in tail
        assert tail.count("X") == 11999
        assert tail.endswith("\\n'")
    else:
        raise AssertionError("oversized functional console tail was accepted")

    def post_exit_console_fake(name: str, trailing_line: str) -> Path:
        fake = tmp / name
        fake.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
            "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
            "IFS= read -r command\n"
            "test \"$command\" = fixture-command || exit 9\n"
            "parent=$$\n"
            "(trap '' HUP\n"
            " while kill -0 \"$parent\" 2>/dev/null; do sleep 0.01; done\n"
            f" printf '%s\\n' '{trailing_line}') &\n"
            "printf '%s\\n' 'LOVELACE_FAKE_QEMU_PASS'\n"
            "exit 0\n",
            encoding="ascii",
        )
        fake.chmod(0o755)
        return fake

    for name, trailing_line, rejection in (
        (
            "fake-qemu-post-exit-duplicate",
            "LOVELACE_FAKE_QEMU_PASS",
            "does not contain each exact marker once",
        ),
        (
            "fake-qemu-post-exit-diagnostic",
            "Kernel panic - not syncing: buffered trailing fixture",
            "forbidden kernel or storage diagnostic",
        ),
    ):
        trailing_argv = list(argv)
        trailing_argv[0] = str(
            post_exit_console_fake(name, trailing_line)
        )
        expect_lovelace_error(
            lambda trailing_argv=trailing_argv: (
                lovelace_builder.run_qemu_commands(
                    trailing_argv,
                    ["fixture-command"],
                    [
                        lovelace_builder.OFFLINE_BOOT_LINE,
                        lovelace_builder.CONSOLE_MARKER,
                        "LOVELACE_FAKE_QEMU_PASS",
                    ],
                    timeout_seconds=10,
                )
            ),
            rejection,
        )

    with mock.patch.object(
        lovelace_builder.subprocess,
        "Popen",
        side_effect=OSError("fixture functional launch failure"),
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_qemu_commands(
                argv,
                ["fixture-command"],
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    "LOVELACE_FAKE_QEMU_PASS",
                ],
                timeout_seconds=10,
            ),
            "QEMU process launch failed: 'fixture functional launch failure'; "
            "console_tail=''",
        )

    captured_processes: list[subprocess.Popen[bytes]] = []
    real_popen = lovelace_builder.subprocess.Popen

    def captured_popen(
        *args: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        captured_processes.append(process)
        return process

    with (
        mock.patch.object(
            lovelace_builder.subprocess,
            "Popen",
            side_effect=captured_popen,
        ),
        mock.patch.object(
            lovelace_builder.selectors,
            "DefaultSelector",
            side_effect=OSError("fixture functional selector failure"),
        ),
    ):
        try:
            lovelace_builder.run_qemu_commands(
                argv,
                ["fixture-command"],
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    "LOVELACE_FAKE_QEMU_PASS",
                ],
                timeout_seconds=10,
            )
        except lovelace_builder.LovelaceError as exc:
            message = str(exc)
            assert "fixture functional selector failure" in message
            assert "console_tail=''" in message
        else:
            raise AssertionError("functional selector failure was accepted")
    assert len(captured_processes) == 1
    assert captured_processes[0].poll() is not None

    real_selector_factory = lovelace_builder.selectors.DefaultSelector

    class FailingSelector:
        def __init__(self, operation: str) -> None:
            self.operation = operation
            self.real = real_selector_factory()

        def register(self, fileobj: object, events: int) -> object:
            if self.operation == "register":
                raise OSError("fixture functional register failure")
            return self.real.register(fileobj, events)

        def select(self, timeout: float | None = None) -> object:
            if self.operation == "select":
                raise OSError("fixture functional select failure")
            return self.real.select(timeout)

        def close(self) -> None:
            self.real.close()

    for operation in ("register", "select"):
        operation_processes: list[subprocess.Popen[bytes]] = []

        def operation_popen(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            operation_processes.append(process)
            return process

        with (
            mock.patch.object(
                lovelace_builder.subprocess,
                "Popen",
                side_effect=operation_popen,
            ),
            mock.patch.object(
                lovelace_builder.selectors,
                "DefaultSelector",
                side_effect=lambda operation=operation: FailingSelector(
                    operation
                ),
            ),
        ):
            expect_lovelace_error(
                lambda: lovelace_builder.run_qemu_commands(
                    argv,
                    ["fixture-command"],
                    [
                        lovelace_builder.OFFLINE_BOOT_LINE,
                        lovelace_builder.CONSOLE_MARKER,
                        "LOVELACE_FAKE_QEMU_PASS",
                    ],
                    timeout_seconds=10,
                ),
                f"fixture functional {operation} failure",
            )
        assert len(operation_processes) == 1
        assert operation_processes[0].poll() is not None

    def start_fake_process() -> subprocess.Popen[bytes]:
        return real_popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            cwd=lovelace_builder.REPO,
            close_fds=True,
        )

    read_process = start_fake_process()
    synthetic_console = (
        lovelace_builder.OFFLINE_BOOT_LINE
        + "\n"
        + lovelace_builder.CONSOLE_MARKER
        + "\n"
    ).encode("ascii")
    read_calls = 0

    def failing_read(_descriptor: int, _size: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        if read_calls == 1:
            return synthetic_console
        raise OSError("fixture functional read failure")

    with (
        mock.patch.object(
            lovelace_builder.subprocess,
            "Popen",
            return_value=read_process,
        ),
        mock.patch.object(
            lovelace_builder.os, "read", side_effect=failing_read
        ),
    ):
        try:
            lovelace_builder.run_qemu_commands(
                argv,
                ["fixture-command"],
                [
                    lovelace_builder.OFFLINE_BOOT_LINE,
                    lovelace_builder.CONSOLE_MARKER,
                    "LOVELACE_FAKE_QEMU_PASS",
                ],
                timeout_seconds=10,
            )
        except lovelace_builder.LovelaceError as exc:
            message = str(exc)
            assert "fixture functional read failure" in message
            assert lovelace_builder.OFFLINE_BOOT_LINE in message
            assert "console_tail=" in message
        else:
            raise AssertionError("functional read failure was accepted")
    assert read_calls >= 2
    assert read_process.poll() is not None

    class FailingStdin:
        def __init__(self, operation: str) -> None:
            self.operation = operation

        def write(self, payload: bytes) -> int:
            if self.operation == "write":
                raise BrokenPipeError("fixture functional stdin write failure")
            return len(payload)

        def flush(self) -> None:
            raise BrokenPipeError("fixture functional stdin flush failure")

    for operation in ("write", "flush"):
        stdin_process = start_fake_process()
        original_stdin = stdin_process.stdin
        assert original_stdin is not None
        stdin_process.stdin = FailingStdin(operation)  # type: ignore[assignment]
        with mock.patch.object(
            lovelace_builder.subprocess,
            "Popen",
            return_value=stdin_process,
        ):
            try:
                lovelace_builder.run_qemu_commands(
                    argv,
                    ["fixture-command"],
                    [
                        lovelace_builder.OFFLINE_BOOT_LINE,
                        lovelace_builder.CONSOLE_MARKER,
                        "LOVELACE_FAKE_QEMU_PASS",
                    ],
                    timeout_seconds=10,
                )
            except lovelace_builder.LovelaceError as exc:
                message = str(exc)
                assert f"fixture functional stdin {operation} failure" in message
                assert lovelace_builder.OFFLINE_BOOT_LINE in message
                assert "console_tail=" in message
            else:
                raise AssertionError(
                    f"functional stdin {operation} failure was accepted"
                )
        original_stdin.close()
        assert stdin_process.poll() is not None

    warning = tmp / "fake-qemu-warning"
    warning.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"TCG doesn't support requested feature: fixture\" "
        ">&2\n"
        f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
        "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
        "IFS= read -r command\n"
        "test \"$command\" = fixture-command || exit 9\n"
        "printf '%s\\n' 'LOVELACE_FAKE_QEMU_PASS'\n",
        encoding="ascii",
    )
    warning.chmod(0o755)
    warning_argv = list(argv)
    warning_argv[0] = str(warning)
    expect_lovelace_error(
        lambda: lovelace_builder.run_qemu_commands(
            warning_argv,
            ["fixture-command"],
            [
                lovelace_builder.OFFLINE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                "LOVELACE_FAKE_QEMU_PASS",
            ],
            timeout_seconds=10,
        ),
        "filtered the pinned functional TCG CPU model",
    )

    guest_warning = tmp / "fake-qemu-guest-warning"
    guest_warning.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'watchdog: BUG: soft lockup - fixture' >&2\n"
        f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
        "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
        "IFS= read -r command\n"
        "test \"$command\" = fixture-command || exit 9\n"
        "printf '%s\\n' 'LOVELACE_FAKE_QEMU_PASS'\n",
        encoding="ascii",
    )
    guest_warning.chmod(0o755)
    guest_warning_argv = list(argv)
    guest_warning_argv[0] = str(guest_warning)
    expect_lovelace_error(
        lambda: lovelace_builder.run_qemu_commands(
            guest_warning_argv,
            ["fixture-command"],
            [
                lovelace_builder.OFFLINE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                "LOVELACE_FAKE_QEMU_PASS",
            ],
            timeout_seconds=10,
        ),
        "forbidden kernel or storage diagnostic",
    )

    early_result = tmp / "fake-qemu-early-functional-result"
    early_result.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' '{lovelace_builder.OFFLINE_BOOT_LINE}'\n"
        "printf '%s\\n' 'LOVELACE_LABORATORY_CONSOLE_READY'\n"
        "printf '%s\\n' 'LOVELACE_FAKE_QEMU_PASS'\n"
        "IFS= read -r command\n"
        "test \"$command\" = fixture-command || exit 9\n",
        encoding="ascii",
    )
    early_result.chmod(0o755)
    early_argv = list(argv)
    early_argv[0] = str(early_result)
    expect_lovelace_error(
        lambda: lovelace_builder.run_qemu_commands(
            early_argv,
            ["fixture-command"],
            [
                lovelace_builder.OFFLINE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                "LOVELACE_FAKE_QEMU_PASS",
            ],
            timeout_seconds=10,
        )
    )


def assert_standalone_guest_result_command() -> None:
    marker = "LOVELACE_PERSISTENT_WRITE_PASS"
    command = lovelace_builder._standalone_guest_result_command(marker)
    assert marker not in command
    assert command.startswith("printf '\\n%s%s\\n' ")
    result = subprocess.run(
        [
            "/bin/sh",
            "-c",
            "printf '\\033[?2004l\\r'; " + command,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    lines = [
        line
        for _start, _end, line in (
            lovelace_builder._complete_console_line_spans(result.stdout)
        )
    ]
    assert lines.count(marker.encode("ascii")) == 1
    expect_lovelace_error(
        lambda: lovelace_builder._standalone_guest_result_command(
            "bad marker"
        ),
        "invalid standalone guest result marker",
    )


def assert_hostile_runtime_fail_closed(tmp: Path) -> None:
    assert lovelace_builder._namespace_inode("mnt", "mnt:[4026531840]") == (
        4026531840
    )
    for malformed in (
        r"mnt:\[4026531840\]",
        "mnt:[4026531840]suffix",
        "net:[4026531840]",
        "mnt:[04026531840]",
        "mnt:[0]",
    ):
        assert lovelace_builder._namespace_inode("mnt", malformed) is None

    def proc_stat(
        *,
        process_group: int = 120,
        session: int = 110,
        start_time: int = 987654,
        user_ticks: int = 1,
    ) -> bytes:
        fields = [b"S", b"100", str(process_group).encode("ascii")]
        fields.append(str(session).encode("ascii"))
        fields.extend([b"0"] * 16)
        fields[11] = str(user_ticks).encode("ascii")
        fields[19] = str(start_time).encode("ascii")
        return b"123 (qemu worker) " + b" ".join(fields) + b"\n"

    first_identity = lovelace_builder._proc_stat_identity(proc_stat())
    assert first_identity == (120, 110, 987654)
    assert lovelace_builder._proc_stat_identity(
        proc_stat(user_ticks=9999)
    ) == first_identity
    assert lovelace_builder._proc_stat_identity(
        proc_stat(process_group=121)
    ) != first_identity
    assert lovelace_builder._proc_stat_identity(
        proc_stat(session=111)
    ) != first_identity
    assert lovelace_builder._proc_stat_identity(
        proc_stat(start_time=987655)
    ) != first_identity
    assert lovelace_builder._proc_stat_identity(b"malformed") is None

    challenge = "a" * 64
    marker = lovelace_builder.HOSTILE_NETWORK_MARKER
    result_line = f"{marker} {challenge}"
    result_command = lovelace_builder._challenge_result_command(
        marker, challenge
    )
    assert result_line not in result_command
    emitted = subprocess.run(
        ["/bin/sh", "-c", result_command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=10,
    )
    assert emitted.returncode == 0
    assert emitted.stdout == "\n" + result_line + "\n"
    bracketed_paste_prefix = b"\\x1b[?2004l\\x0d"
    prefixed_records = (
        lovelace_builder._hostile_complete_console_line_records(
            bracketed_paste_prefix + emitted.stdout.encode("ascii")
        )
    )
    assert [
        line
        for _offset, line in prefixed_records
        if line == result_line.encode("ascii")
    ] == [result_line.encode("ascii")]
    materialized_commands, materialized_results = (
        lovelace_builder._materialize_hostile_challenge_commands(
            lambda generated: (
                [
                    lovelace_builder._challenge_result_command(
                        marker, generated
                    )
                ],
                [f"{marker} {generated}"],
            ),
            challenge,
        )
    )
    assert materialized_commands == [result_command]
    assert materialized_results == [result_line]
    expect_lovelace_error(
        lambda: lovelace_builder._materialize_hostile_challenge_commands(
            lambda generated: (
                [f"printf '%s\\n' '{generated}'"],
                [f"{marker} {generated}"],
            ),
            challenge,
        ),
        "payload discloses a complete challenge",
    )
    expect_lovelace_error(
        lambda: lovelace_builder._materialize_hostile_challenge_commands(
            lambda _generated: (["true"], ["not-a-result"]),
            challenge,
        ),
        "invalid challenge results",
    )

    def fixture_command_factory(
        commands: list[str],
    ) -> Callable[[str], tuple[list[str], list[str]]]:
        def materialize(
            generated_challenge: str,
        ) -> tuple[list[str], list[str]]:
            return list(commands), [
                f"{marker} {generated_challenge}"
            ]

        return materialize

    child_pid_path = tmp / "surviving-child.pid"
    parent_code = (
        "import pathlib,subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c',"
        "'import time; time.sleep(60)']); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(p.pid));"
    )
    leader = subprocess.Popen(
        [sys.executable, "-c", parent_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    leader.wait(timeout=10)
    deadline = time.monotonic() + 5
    while not child_pid_path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert child_pid_path.exists()
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    assert Path(f"/proc/{child_pid}").exists()
    lovelace_builder._terminate_hostile_process_group(leader)
    assert not lovelace_builder._hostile_process_group_exists(leader)

    captured_processes: list[subprocess.Popen[bytes]] = []
    real_popen = lovelace_builder.subprocess.Popen

    def captured_popen(
        *args: object,
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        captured_processes.append(process)
        return process

    with (
        mock.patch.object(
            lovelace_builder.subprocess,
            "Popen",
            side_effect=captured_popen,
        ),
        mock.patch.object(
            lovelace_builder.selectors,
            "DefaultSelector",
            side_effect=OSError("fixture selector setup failure"),
        ),
    ):
        try:
            lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(["true"]),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            )
        except OSError as exc:
            assert "fixture selector setup failure" in str(exc)
        else:
            raise AssertionError("selector setup failure was accepted")
    assert len(captured_processes) == 1
    assert captured_processes[0].poll() is not None
    assert not lovelace_builder._hostile_process_group_exists(
        captured_processes[0]
    )

    rejected_identity = {
        "host_pid": 1234,
        "start_time_ticks": 123456,
        "executable": "/usr/bin/qemu-system-x86_64",
        "executable_device": 1,
        "executable_inode": 1,
    }
    teardown_observations: list[dict[str, Any]] = []

    def reject_observation(
        _root_pid: int,
        _expected_qemu: dict[str, Any],
    ) -> None:
        raise lovelace_builder._HostileProcessObservationError(
            "fixture hostile QEMU rejection",
            rejected_identity,
        )

    def accept_teardown(observation: dict[str, Any]) -> bool:
        teardown_observations.append(dict(observation))
        return True

    with patched(
        _qemu_process_observation=reject_observation,
        _wait_for_observed_qemu_absence=accept_teardown,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(["true"]),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "fixture hostile QEMU rejection",
        )
    assert teardown_observations == [rejected_identity]

    early_failure = (
        "import sys; "
        "sys.stderr.write("
        "'wuci-lab: hostile bound base image exceeds the "
        "1073741824-byte limit\\n'); "
        "sys.stderr.flush(); "
        "raise SystemExit(23)"
    )
    try:
        lovelace_builder.run_hostile_supervisor_commands(
            [sys.executable, "-c", early_failure],
            [
                lovelace_builder.BOOT_MARKER,
                lovelace_builder.CONSOLE_MARKER,
            ],
            {
                "path": "/usr/bin/qemu-system-x86_64",
                "device": 1,
                "inode": 1,
            },
            command_factory=fixture_command_factory(["true"]),
            validate_plan=lambda _plan: None,
            timeout_seconds=10,
        )
    except lovelace_builder.LovelaceError as exc:
        failure_text = str(exc)
        assert "supervisor_exit=23" in failure_text
        assert "exceeds the 1073741824-byte limit" in failure_text
        assert "console_ready=false" in failure_text
        assert "qemu_observed=false" in failure_text
    else:
        raise AssertionError("early hostile supervisor failure was accepted")

    raw_terminal_script = (
        "import sys; "
        "sys.stdout.buffer.write(b'fixture\\x1b]52;clipboard\\x07'); "
        "sys.stdout.buffer.flush()"
    )
    try:
        lovelace_builder.run_hostile_supervisor_commands(
            [sys.executable, "-c", raw_terminal_script],
            [
                lovelace_builder.BOOT_MARKER,
                lovelace_builder.CONSOLE_MARKER,
            ],
            {
                "path": "/usr/bin/qemu-system-x86_64",
                "device": 1,
                "inode": 1,
            },
            command_factory=fixture_command_factory(["true"]),
            validate_plan=lambda _plan: None,
            timeout_seconds=10,
        )
    except lovelace_builder.LovelaceError as exc:
        failure_text = str(exc)
        assert "raw terminal-control or non-ASCII bytes" in failure_text
        assert "\x1b" not in failure_text
        assert "\x07" not in failure_text
    else:
        raise AssertionError("raw hostile terminal bytes were accepted")

    panic_dispatch_path = tmp / "hostile-panic-command-dispatched"
    panic_script = (
        "import pathlib,sys; "
        "sys.stdout.write('Kernel panic - not syncing: fixture panic\\n'); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(panic_dispatch_path)!r}).write_text(line) "
        "if line else None"
    )
    with patched(
        _qemu_process_observation=lambda _pid, _expected: None,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", panic_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "hostile guest console emitted a forbidden kernel or storage "
            "diagnostic",
        )
    assert not panic_dispatch_path.exists()

    prelaunch_exit_script = (
        "import sys; "
        "sys.stdout.write('fixture pre-qemu verification output\\n'); "
        "sys.stdout.flush(); "
        "raise SystemExit(23)"
    )
    with patched(
        HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS=0,
        _qemu_process_observation=lambda _pid, _expected: None,
    ):
        try:
            lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", prelaunch_exit_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            )
        except lovelace_builder.LovelaceError as exc:
            failure_text = str(exc)
            assert "supervisor_exit=23" in failure_text
            assert "qemu_observed=false" in failure_text
            assert "did not reach its console-ready marker" not in failure_text
        else:
            raise AssertionError(
                "pre-QEMU supervisor exit was accepted as a guest timeout"
            )

    timeout_dispatch_path = tmp / "hostile-timeout-command-dispatched"
    timeout_script = (
        "import pathlib,sys; "
        "sys.stdout.write('fixture pre-console output\\n'); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(timeout_dispatch_path)!r}).write_text(line) "
        "if line else None"
    )
    with patched(
        HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS=0,
        _qemu_process_observation=lambda _pid, _expected: {
            "observed": True,
            "executable": "/usr/bin/qemu-system-x86_64",
            "host_pid": 1234,
            "start_time_ticks": 123456,
            "executable_device": 1,
            "executable_inode": 1,
            "_cmdline": [],
        },
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", timeout_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "did not reach its console-ready marker within 0 seconds",
        )
    assert not timeout_dispatch_path.exists()

    spoof_dispatch_path = tmp / "hostile-spoof-command-dispatched"
    spoof_script = (
        "import pathlib,sys; "
        f"result={marker!r}+' '+('a'*64); "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': []})!r}.decode()"
        f"+{(lovelace_builder.HOSTILE_BOOT_LINE + chr(10))!r}"
        f"+{(lovelace_builder.CONSOLE_MARKER + chr(10))!r}"
        "+result+chr(10)); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(spoof_dispatch_path)!r}).write_text(line) "
        "if line else None"
    )
    fake_observation = {
        "observed": True,
        "executable": "/usr/bin/qemu-system-x86_64",
        "host_pid": 1234,
        "start_time_ticks": 123456,
        "executable_device": 1,
        "executable_inode": 1,
        "_cmdline": [],
    }
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            fake_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ), mock.patch.object(
        lovelace_builder.secrets, "token_hex", return_value=challenge
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", spoof_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(["true"]),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "challenge was disclosed before dispatch",
        )
    assert not spoof_dispatch_path.exists()

    dispatch_path = tmp / "hostile-mismatched-cmdline-dispatched"
    candidate_qemu_argv = ["fixture-qemu", "-nic", "none"]
    plan_script = (
        "import pathlib,sys; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{(lovelace_builder.HOSTILE_BOOT_LINE + chr(10))!r}"
        f"+{(lovelace_builder.CONSOLE_MARKER + chr(10))!r}); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(dispatch_path)!r}).write_text(line) if line else None"
    )
    mismatched_observation = {
        **fake_observation,
        "_cmdline": ["different-qemu", "-nic", "none"],
    }
    plan_validations: list[dict[str, Any]] = []
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            mismatched_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", plan_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda plan: plan_validations.append(plan),
                timeout_seconds=10,
            ),
            "differs from the materialized canonical plan before "
            "guest-command dispatch",
        )
    assert plan_validations == []
    assert not dispatch_path.exists()

    matching_observation = {
        **fake_observation,
        "_cmdline": candidate_qemu_argv,
    }
    substring_dispatch_path = tmp / "hostile-substring-marker-dispatched"
    substring_marker_script = (
        "import pathlib,sys; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{(lovelace_builder.HOSTILE_BOOT_LINE + chr(10))!r}"
        f"+{('prefix' + lovelace_builder.CONSOLE_MARKER + 'suffix' + chr(10))!r}); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(substring_dispatch_path)!r}).write_text(line) "
        "if line else None"
    )
    with patched(
        HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS=0,
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", substring_marker_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "did not reach its console-ready marker within 0 seconds",
        )
    assert not substring_dispatch_path.exists()

    substring_boot_dispatch_path = (
        tmp / "hostile-substring-boot-dispatched"
    )
    substring_boot_script = (
        "import pathlib,sys; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{('prefix' + lovelace_builder.HOSTILE_BOOT_LINE + 'suffix' + chr(10))!r}"
        f"+{(lovelace_builder.CONSOLE_MARKER + chr(10))!r}); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(substring_boot_dispatch_path)!r}).write_text(line) "
        "if line else None"
    )
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", substring_boot_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "materialized plan was not emitted before guest output",
        )
    assert not substring_boot_dispatch_path.exists()

    wrong_boot_dispatch_path = tmp / "hostile-wrong-boot-dispatched"
    wrong_boot_script = (
        "import pathlib,sys; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{(lovelace_builder.BOOT_MARKER + ' profile=fixture' + chr(10))!r}"
        f"+{(lovelace_builder.CONSOLE_MARKER + chr(10))!r}); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(wrong_boot_dispatch_path)!r}).write_text(line) "
        "if line else None"
    )
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", wrong_boot_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "materialized plan was not emitted before guest output",
        )
    assert not wrong_boot_dispatch_path.exists()

    for name, transcript_lines in (
        (
            "duplicate-boot",
            [
                lovelace_builder.HOSTILE_BOOT_LINE,
                lovelace_builder.HOSTILE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
            ],
        ),
        (
            "duplicate-console",
            [
                lovelace_builder.HOSTILE_BOOT_LINE,
                lovelace_builder.CONSOLE_MARKER,
                lovelace_builder.CONSOLE_MARKER,
            ],
        ),
        (
            "out-of-order",
            [
                lovelace_builder.CONSOLE_MARKER,
                lovelace_builder.HOSTILE_BOOT_LINE,
            ],
        ),
    ):
        dispatch_guard = tmp / f"hostile-{name}-dispatched"
        transcript = "".join(
            line + chr(10) for line in transcript_lines
        )
        script = (
            "import pathlib,sys; "
            f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
            f"+{transcript!r}); "
            "sys.stdout.flush(); "
            "line=sys.stdin.readline(); "
            f"pathlib.Path({str(dispatch_guard)!r}).write_text(line) "
            "if line else None"
        )
        with patched(
            _qemu_process_observation=lambda _pid, _expected: dict(
                matching_observation
            ),
            _wait_for_observed_qemu_absence=lambda _observation: True,
        ):
            expect_lovelace_error(
                lambda: lovelace_builder.run_hostile_supervisor_commands(
                    [sys.executable, "-c", script],
                    [
                        lovelace_builder.BOOT_MARKER,
                        lovelace_builder.CONSOLE_MARKER,
                    ],
                    {
                        "path": "/usr/bin/qemu-system-x86_64",
                        "device": 1,
                        "inode": 1,
                    },
                    command_factory=fixture_command_factory(
                        ["fixture-command"]
                    ),
                    validate_plan=lambda _plan: None,
                    timeout_seconds=10,
                ),
                "materialized plan was not emitted before guest output",
            )
        assert not dispatch_guard.exists()

    def shell_result_factory(
        generated_challenge: str,
    ) -> tuple[list[str], list[str]]:
        return [
            lovelace_builder._challenge_result_command(
                marker, generated_challenge
            )
        ], [f"{marker} {generated_challenge}"]

    split_at = len(lovelace_builder.CONSOLE_MARKER) // 2
    positive_script = (
        "import subprocess,sys,time; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{(lovelace_builder.HOSTILE_BOOT_LINE + chr(10))!r}"
        f"+{lovelace_builder.CONSOLE_MARKER[:split_at]!r}); "
        "sys.stdout.flush(); time.sleep(0.02); "
        f"sys.stdout.write({(lovelace_builder.CONSOLE_MARKER[split_at:] + chr(10))!r}); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        "subprocess.run(['/bin/sh','-c',line],check=True)"
    )
    accepted_plans: list[dict[str, Any]] = []
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        accepted_plan, accepted_runtime = (
            lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", positive_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=shell_result_factory,
                validate_plan=lambda plan: accepted_plans.append(plan),
                timeout_seconds=10,
            )
        )
    assert accepted_plan == {"qemu_argv": candidate_qemu_argv}
    assert accepted_plans == [accepted_plan]
    assert accepted_runtime["status"] == "pass"
    assert accepted_runtime["command_results_after_dispatch"] is True
    assert accepted_runtime["command_results"] == [
        f"{marker} {accepted_runtime['challenge']}"
    ]

    prefixed_result_dispatch = tmp / "hostile-prefixed-result-dispatched"
    prefixed_result_script = (
        "import pathlib,subprocess,sys; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{(lovelace_builder.HOSTILE_BOOT_LINE + chr(10))!r}"
        f"+{(lovelace_builder.CONSOLE_MARKER + chr(10))!r}"
        "+'attacker-prefix'); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(prefixed_result_dispatch)!r}).write_text(line); "
        "result=subprocess.run(['/bin/sh','-c',line],check=True,"
        "stdout=subprocess.PIPE).stdout; "
        "sys.stdout.buffer.write(result[1:]); "
        "sys.stdout.buffer.flush()"
    )
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", prefixed_result_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=shell_result_factory,
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "exactly once after dispatch",
        )
    assert prefixed_result_dispatch.read_text(encoding="utf-8")

    unterminated_result_dispatch = (
        tmp / "hostile-unterminated-result-dispatched"
    )
    unterminated_result_script = (
        "import pathlib,subprocess,sys; "
        f"sys.stdout.write({lovelace_builder.canonical_json({'qemu_argv': candidate_qemu_argv})!r}.decode()"
        f"+{(lovelace_builder.HOSTILE_BOOT_LINE + chr(10))!r}"
        f"+{(lovelace_builder.CONSOLE_MARKER + chr(10))!r}); "
        "sys.stdout.flush(); "
        "line=sys.stdin.readline(); "
        f"pathlib.Path({str(unterminated_result_dispatch)!r}).write_text(line); "
        "result=subprocess.run(['/bin/sh','-c',line],check=True,"
        "stdout=subprocess.PIPE).stdout; "
        "sys.stdout.buffer.write(result.rstrip(b'\\n')); "
        "sys.stdout.buffer.flush()"
    )
    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", unterminated_result_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=shell_result_factory,
                validate_plan=lambda _plan: None,
                timeout_seconds=10,
            ),
            "exactly once after dispatch",
        )
    assert unterminated_result_dispatch.read_text(encoding="utf-8")

    with patched(
        _qemu_process_observation=lambda _pid, _expected: dict(
            matching_observation
        ),
        _wait_for_observed_qemu_absence=lambda _observation: True,
    ):
        expect_lovelace_error(
            lambda: lovelace_builder.run_hostile_supervisor_commands(
                [sys.executable, "-c", plan_script],
                [
                    lovelace_builder.BOOT_MARKER,
                    lovelace_builder.CONSOLE_MARKER,
                ],
                {
                    "path": "/usr/bin/qemu-system-x86_64",
                    "device": 1,
                    "inode": 1,
                },
                command_factory=fixture_command_factory(
                    ["fixture-command"]
                ),
                validate_plan=lambda _plan: (_ for _ in ()).throw(
                    lovelace_builder.LovelaceError(
                        "fixture pre-dispatch plan rejection"
                    )
                ),
                timeout_seconds=10,
            ),
            "fixture pre-dispatch plan rejection",
        )
    assert not dispatch_path.exists()


def assert_make_variables_are_not_shell_interpolated() -> None:
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    assert "LOVELACE_OVERLAY_ARG" not in makefile
    lovelace_variables = (
        "LOVELACE_CACHE",
        "LOVELACE_OUTPUT",
        "LOVELACE_XORRISO",
        "LOVELACE_PROFILE",
        "LOVELACE_STORAGE",
        "LOVELACE_NETWORK",
        "LOVELACE_ACCEL",
        "LOVELACE_OVERLAY",
        "LOVELACE_OVERLAY_REMOVE_CONFIRM",
        "LOVELACE_OVERLAY_RESET_CONFIRM",
        "LOVELACE_HOSTILE_PAYLOAD",
        "LOVELACE_HOSTILE_PAYLOAD_SHA256",
        "LOVELACE_MEMORY_MIB",
        "LOVELACE_CPUS",
    )
    for variable in lovelace_variables:
        assert (
            f"override export {variable} := $(value {variable})" in makefile
        ), variable
    for target in (
        "wucios-lovelace-boot-smoke",
        "wucios-lovelace-ghidra-headless",
        "wucios-lovelace-noxframe-smoke",
        "wucios-lovelace-persistent-round-trip",
        "wucios-lovelace-hostile-smoke",
        "wucios-lovelace-network-smoke",
    ):
        declaration = re.search(
            rf"^{re.escape(target)}:\s+([^\n]+)$",
            makefile,
            flags=re.MULTILINE,
        )
        assert declaration is not None, target
        assert declaration.group(1).split() == [
            "wucios-lovelace-source-test"
        ], target
    for unsafe in (
        '--cache "$(LOVELACE_CACHE)"',
        '--output "$(LOVELACE_OUTPUT)"',
        '--xorriso "$(LOVELACE_XORRISO)"',
        '--profile "$(LOVELACE_PROFILE)"',
        '--storage "$(LOVELACE_STORAGE)"',
        '--network "$(LOVELACE_NETWORK)"',
        '--accel "$(LOVELACE_ACCEL)"',
        '--overlay "$(LOVELACE_OVERLAY)"',
        '--memory-mib "$(LOVELACE_MEMORY_MIB)"',
        '--cpus "$(LOVELACE_CPUS)"',
    ):
        assert unsafe not in makefile
    result = subprocess.run(
        [
            "make",
            "-n",
            "wucios-lovelace-launch",
            'LOVELACE_OVERLAY=x"; id; #',
            'LOVELACE_OUTPUT=x"; uname; #',
        ],
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert 'x"; id; #' not in result.stdout
    assert 'x"; uname; #' not in result.stdout

    make_markers = {
        variable: f"WUCI_LITERAL_{variable}_MUST_NOT_EXPAND"
        for variable in lovelace_variables
    }
    literal_make_values = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "help",
            *(
                f"{variable}=$(info {marker})/literal"
                for variable, marker in make_markers.items()
            ),
        ],
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    assert literal_make_values.returncode == 0, literal_make_values.stderr
    make_output = literal_make_values.stdout + literal_make_values.stderr
    for marker in make_markers.values():
        assert marker not in make_output, marker

    environment = dict(os.environ)
    environment.update(
        {
            "LOVELACE_CACHE": "/tmp/lovelace cache;literal",
            "LOVELACE_OUTPUT": "/tmp/lovelace output;literal",
            "LOVELACE_PROFILE": "analysis",
            "LOVELACE_STORAGE": "persistent",
            "LOVELACE_OVERLAY": "workbench",
            "LOVELACE_NETWORK": "internet",
            "LOVELACE_ACCEL": "tcg",
            "LOVELACE_MEMORY_MIB": "6144",
            "LOVELACE_CPUS": "4",
            "PYTHONPATH": str(REPO / "tools/wucios"),
        }
    )
    parsed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, lovelace_builder as b; "
                "a=b.parser().parse_args(['launch']); "
                "print(json.dumps({'cache':str(a.cache),'output':str(a.output),"
                "'profile':a.profile,'storage':a.storage,'overlay':a.overlay,"
                "'network':a.network,'accel':a.accel,"
                "'memory_mib':a.memory_mib,'cpus':a.cpus},sort_keys=True))"
            ),
        ],
        cwd=REPO,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    assert parsed.returncode == 0, parsed.stderr
    assert json.loads(parsed.stdout) == {
        "cache": "/tmp/lovelace cache;literal",
        "output": "/tmp/lovelace output;literal",
        "profile": "analysis",
        "storage": "persistent",
        "overlay": "workbench",
        "network": "internet",
        "accel": "tcg",
        "memory_mib": 6144,
        "cpus": 4,
    }

    invalid_environment = dict(environment)
    invalid_environment.update(
        {
            "LOVELACE_PROFILE": "evil",
            "LOVELACE_STORAGE": "bad",
            "LOVELACE_NETWORK": "oops",
            "LOVELACE_ACCEL": "nope",
        }
    )
    rejected = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import lovelace_builder as b; "
                "b.parser().parse_args(['launch'])"
            ),
        ],
        cwd=REPO,
        env=invalid_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    assert rejected.returncode == 2
    assert "invalid launch profile default" in rejected.stderr
    assert "Traceback" not in rejected.stderr

    explicit_override = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import lovelace_builder as b; "
                "a=b.parser().parse_args(['launch','--profile','developer',"
                "'--storage','volatile','--network','none','--accel','tcg',"
                "'--memory-mib','8192','--cpus','6']); "
                "assert (a.profile,a.storage,a.network,a.accel,"
                "a.memory_mib,a.cpus)=="
                "('developer','volatile','none','tcg',8192,6)"
            ),
        ],
        cwd=REPO,
        env=invalid_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=30,
    )
    assert explicit_override.returncode == 0, explicit_override.stderr


def run_suite() -> None:
    with tempfile.TemporaryDirectory(
        prefix="wucios-lovelace-builder-test-", dir="/tmp"
    ) as temporary:
        tmp = Path(temporary)
        assert_configuration_contract(tmp)
        assert_ghidra_archive_guards(tmp)
        assert_apk_index_duplicate_rejection(tmp)
        assert_overlay_and_runtime_contracts(tmp)
        assert_static_build_record_validation()
        assert_embedded_runtime_source_inventory_contract()
        assert_embedded_contract_binding_contract()
        assert_embedded_debugfs_deadline_contract()
        assert_required_runtime_path_resolution_contract()
        assert_source_input_tracking(tmp)
        assert_serialized_ext4_staged_tree_counts()
        assert_ext4_metadata_normalization(tmp)
        assert_ext4_inventory_aggregate_budgets(tmp)
        assert_transient_build_path_scan(tmp)
        assert_reproducible_file_comparison(tmp)
        assert_bounded_subprocess_contract()
        assert_pinned_ext4_identity(tmp)
        assert_locked_file_identity(tmp)
        assert_validation_evidence_binding(tmp)
        assert_manifest_artifact_locks()
        assert_evidence_lane_contracts()
        assert_hostile_payload_lane_contract(tmp)
        assert_locked_input_snapshot(tmp)
        assert_transactional_release_publication(tmp)
        assert_isolated_native_build(tmp)
        assert_evidence_commit_boundary()
        assert_ghidra_vm_memory_contract(tmp)
        assert_validation_transaction_rollback(tmp)
        assert_offline_install_command(tmp)
        assert_network_lane_separation(tmp)
        assert_explicit_network_probe_execution(tmp)
        assert_network_binding_and_launch_contracts(tmp)
        assert_output_lock_timeout(tmp)
        assert_evidence_producer_locking(tmp)
        assert_explicit_xorriso_contract(tmp)
        assert_ghidra_semantic_fixture_contract(tmp)
        assert_ghidra_smoke_command(tmp)
        assert_functional_qemu_runtime_contract(tmp)
        assert_standalone_guest_result_command()
        assert_hostile_runtime_fail_closed(tmp)
        assert_make_variables_are_not_shell_interpolated()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Focused WuciOS Lovelace builder contract tests"
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    run_suite()
    if not args.quiet:
        print("wucios lovelace builder: PASS")


if __name__ == "__main__":
    main()
