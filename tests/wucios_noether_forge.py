#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.wucios import noether_forge  # noqa: E402
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
    workflow = b"name: Noether\nuses: actions/upload-artifact@v4\n"
    assert noether_source_guard.violations_for_file(".github/workflows/noether.yml", workflow) == [
        "workflow can publish a Noether binary artifact"
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
    test_source_only_guard_rejects_noether_binary_distribution,
    test_cli_paths_are_resolved_before_dispatch,
    test_component_map_covers_package_lock,
    test_source_manifest_binds_native_build_inputs,
    test_boot_templates_are_serial_and_noninteractive,
    test_deterministic_apkovl_and_safe_links,
    test_apkovl_rejects_traversal_and_hardlinks,
    test_volume_label_patch_is_equal_length_and_exact,
    test_xorriso_report_normalization_removes_host_state,
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
