#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_kaiju  # noqa: E402


def assert_rejects(description: str, func: Callable[[], object]) -> None:
    try:
        func()
    except wuci_kaiju.KaijuError:
        return
    raise AssertionError(f"expected rejection: {description}")


def assert_manifest_validation() -> None:
    manifest = wuci_kaiju.load_manifest(wuci_kaiju.default_manifest_path(REPO))
    problems = wuci_kaiju.validate_manifest(manifest)
    assert not problems, problems
    result = wuci_kaiju.verify_manifest(wuci_kaiju.default_manifest_path(REPO))
    assert result["status"] == "pass"
    assert result["purpose_count"] == len(wuci_kaiju.REQUIRED_PURPOSES)
    assert result["selected_tool_count"] >= len(wuci_kaiju.REQUIRED_PURPOSES)
    assert "no offensive scanning" in manifest["global_denials"]
    assert manifest["boundary"]["host_execution"] == "unavailable"
    assert manifest["boundary"]["network_access"] == "unavailable"
    assert manifest["boot_bridge"]["graphics"] == "none"
    assert manifest["boot_bridge"]["default_network"] == "none"
    assert manifest["boot_bridge"]["host_execution"] == "explicit --allow-kaiju-boot only"

    purpose_ids = {purpose["id"] for purpose in manifest["purposes"]}
    assert set(wuci_kaiju.REQUIRED_PURPOSES) == purpose_ids
    for purpose in manifest["purposes"]:
        for tool in purpose["selected_tools"]:
            assert tool["host_execution"] == "unavailable"
            assert "command" not in tool
            assert "argv" not in tool


def assert_public_manifest_rejections(tmp: Path) -> None:
    source = tmp / "manifest.json"
    source.write_text(
        json.dumps(
            {
                "schema": wuci_kaiju.SCHEMA,
                "name": "WUCI-KAIJU",
                "boundary": {
                    "host_execution": "unavailable",
                    "network_access": "unavailable",
                    "shell": "unavailable",
                    "runtime_sandbox_claim": "none",
                },
                "global_denials": ["no offensive scanning"],
                "purposes": [],
            }
        ),
        encoding="utf-8",
    )

    if hasattr(os, "symlink"):
        symlink = tmp / "manifest-link.json"
        symlink.symlink_to(source)
        assert_rejects("symlink manifest", lambda: wuci_kaiju.load_manifest(symlink))

    if hasattr(os, "link"):
        hardlink = tmp / "manifest-hardlink.json"
        try:
            os.link(source, hardlink)
        except OSError:
            pass
        else:
            assert_rejects("hardlinked manifest", lambda: wuci_kaiju.load_manifest(hardlink))

    duplicate = tmp / "manifest-duplicate.json"
    duplicate.write_text('{"schema":"one","schema":"two"}\n', encoding="utf-8")
    assert_rejects("duplicate JSON manifest", lambda: wuci_kaiju.load_manifest(duplicate))

    oversized = tmp / "manifest-oversized.json"
    oversized.write_bytes(b'{"schema":"' + (b"A" * (wuci_kaiju.MAX_PUBLIC_JSON_BYTES + 1)) + b'"}\n')
    assert_rejects("oversized JSON manifest", lambda: wuci_kaiju.load_manifest(oversized))


def _dirent(ino: int, name: str, rec_len: int, file_type: int) -> bytes:
    raw = name.encode("utf-8")
    return struct.pack("<IHBb", ino, rec_len, len(raw), file_type) + raw + b"\0" * (rec_len - 8 - len(raw))


def _dir_block(entries: list[tuple[int, str, int]]) -> bytes:
    block_size = 1024
    out = bytearray()
    for idx, (ino, name, file_type) in enumerate(entries):
        raw_len = 8 + len(name.encode("utf-8"))
        rec_len = (raw_len + 3) & ~3
        if idx == len(entries) - 1:
            rec_len = block_size - len(out)
        out.extend(_dirent(ino, name, rec_len, file_type))
    return bytes(out)


def _newc_record(name: str, payload: bytes = b"") -> bytes:
    name_bytes = name.encode("utf-8") + b"\0"
    fields = [
        1,
        0o100644,
        0,
        0,
        1,
        0,
        len(payload),
        0,
        0,
        0,
        0,
        len(name_bytes),
        0,
    ]
    header = b"070701" + "".join(f"{value:08x}" for value in fields).encode("ascii")
    out = bytearray(header + name_bytes)
    while len(out) % 4:
        out.append(0)
    out.extend(payload)
    while len(out) % 4:
        out.append(0)
    return bytes(out)


def _minimal_initrd() -> bytes:
    return _newc_record("TRAILER!!!")


def _inode(mode: int, size: int, block: int) -> bytes:
    raw = bytearray(128)
    struct.pack_into("<H", raw, 0, mode)
    struct.pack_into("<I", raw, 4, size)
    struct.pack_into("<I", raw, 32, 0)
    struct.pack_into("<I", raw, 40, block)
    return bytes(raw)


def _write_inode(table: bytearray, ino: int, raw: bytes) -> None:
    start = (ino - 1) * 128
    table[start : start + 128] = raw


def _write_block(image: bytearray, ext_offset: int, block: int, data: bytes) -> None:
    start = ext_offset + block * 1024
    image[start : start + len(data)] = data


def _write_minimal_installed_disk(path: Path) -> tuple[bytes, bytes]:
    disk_bytes = 4 * 1024 * 1024
    ext_offset = 2048 * 512
    image = bytearray(disk_bytes)
    partition_sectors = (disk_bytes - ext_offset) // 512
    image[446] = 0x80
    image[450] = 0x83
    struct.pack_into("<I", image, 454, 2048)
    struct.pack_into("<I", image, 458, partition_sectors)
    image[510:512] = b"\x55\xaa"

    superblock = bytearray(1024)
    struct.pack_into("<I", superblock, 0, 16)
    struct.pack_into("<I", superblock, 4, (disk_bytes - ext_offset) // 1024)
    struct.pack_into("<I", superblock, 20, 1)
    struct.pack_into("<I", superblock, 24, 0)
    struct.pack_into("<I", superblock, 32, (disk_bytes - ext_offset) // 1024)
    struct.pack_into("<I", superblock, 40, 16)
    struct.pack_into("<H", superblock, 56, 0xEF53)
    struct.pack_into("<H", superblock, 88, 128)
    image[ext_offset + 1024 : ext_offset + 2048] = superblock

    group = bytearray(32)
    struct.pack_into("<I", group, 8, 5)
    _write_block(image, ext_offset, 2, group)

    kernel = b"test kernel bytes\n"
    initrd = _minimal_initrd()
    table = bytearray(16 * 128)
    _write_inode(table, 2, _inode(0x41ED, 1024, 10))
    _write_inode(table, 12, _inode(0x41ED, 1024, 11))
    _write_inode(table, 13, _inode(0x81A4, len(kernel), 12))
    _write_inode(table, 14, _inode(0x81A4, len(initrd), 13))
    _write_block(image, ext_offset, 5, table[:1024])
    _write_block(image, ext_offset, 6, table[1024:2048])
    _write_block(image, ext_offset, 10, _dir_block([(2, ".", 2), (2, "..", 2), (12, "boot", 2)]))
    _write_block(
        image,
        ext_offset,
        11,
        _dir_block([(12, ".", 2), (2, "..", 2), (13, "vmlinuz-1", 1), (14, "initrd.img-1", 1)]),
    )
    _write_block(image, ext_offset, 12, kernel)
    _write_block(image, ext_offset, 13, initrd)
    path.write_bytes(image)
    return kernel, initrd


def assert_installed_boot_direct_path(tmp: Path) -> None:
    disk_root = tmp / "installed-disk"
    disk_root.mkdir()
    disk_path = disk_root / "kali.raw"
    kernel, initrd = _write_minimal_installed_disk(disk_path)
    wuci_kaiju.write_json_atomic(
        disk_root / wuci_kaiju.DISK_MANIFEST_NAME,
        {
            "schema": wuci_kaiju.DISK_SCHEMA,
            "created_utc": "2026-06-29T00:00:00Z",
            "disk_path": str(disk_path),
            "format": "raw",
            "size_mib": disk_path.stat().st_size // (1024 * 1024),
            "mutable": True,
        },
    )

    probe = wuci_kaiju._probe_installed_boot(disk_path)
    assert probe["status"] == "pass", probe
    assert probe["root_device"] == "/dev/vda1"
    assert probe["kernel_path"] == "/boot/vmlinuz-1"
    assert probe["initrd_path"] == "/boot/initrd.img-1"
    assert wuci_kaiju._select_installed_boot_pair(
        [
            "vmlinuz-6.9-amd64",
            "initrd.img-6.9-amd64",
            "vmlinuz-6.18-amd64",
            "initrd.img-6.18-amd64",
        ]
    ) == ("vmlinuz-6.18-amd64", "initrd.img-6.18-amd64")
    extent_node = (
        struct.pack("<HHHHI", wuci_kaiju.EXTENT_HEADER_MAGIC, 1, 4, 0, 0)
        + struct.pack("<IHHI", 0, 0x8000, 0, 7)
    )
    assert wuci_kaiju._ExtReader._extents_from_node(object(), extent_node) == [(0, 7, 32768)]
    wuci_kaiju._validate_installed_initrd(initrd)

    plan = wuci_kaiju.boot_plan(
        disk_root=disk_root,
        qemu_bin="/bin/true",
        memory_mib=512,
        cpus=1,
        network=True,
        boot_disk=True,
    )
    assert plan["launch_mode"] == "direct-installed-kernel+serial"
    assert plan["installed_boot"]["status"] == "pass"
    assert "-kernel" in plan["argv"]
    assert "-initrd" in plan["argv"]
    assert any("root=/dev/vda1" in item for item in plan["argv"])
    assert "user,model=virtio-net-pci" in plan["argv"]

    blocked_share = wuci_kaiju.boot_plan(
        disk_root=disk_root,
        qemu_bin="/bin/true",
        memory_mib=512,
        cpus=1,
        network=True,
        boot_disk=True,
        share_repo=tmp,
    )
    assert blocked_share["status"] == "blocked"
    assert blocked_share["argv"] == []
    assert blocked_share["share_status"] == "unsupported"
    assert "virtio-9p-pci" in blocked_share["share_problem"]

    argv = wuci_kaiju.build_live_boot_argv(plan)
    work = disk_root / wuci_kaiju.INSTALLED_BOOT_ROOT
    assert (work / "vmlinuz").read_bytes() == kernel
    assert (work / "initrd.img").read_bytes() == initrd
    assert "-boot" not in argv
    wuci_kaiju._cleanup_installed_boot_artifacts(disk_root)
    assert not work.exists()


def assert_iso_disk_boot(tmp: Path) -> None:
    source = tmp / "kali-test.iso"
    source.write_bytes(b"KAIJU ISO FIXTURE\n" * 16)
    iso_root = tmp / "iso"
    disk_root = tmp / "disk"

    manifest = wuci_kaiju.install_iso(
        source,
        iso_root=iso_root,
        name="kali-test.iso",
    )
    assert manifest["schema"] == wuci_kaiju.ISO_SCHEMA
    assert manifest["image_bytes"] == source.stat().st_size
    assert manifest["boot_profile"]["graphics"] == "none"
    assert manifest["boot_profile"]["default_network"] == "none"

    iso_result = wuci_kaiju.verify_iso_install(iso_root)
    assert iso_result["status"] == "pass", iso_result
    assert "boot: non-graphical QEMU plan available" in wuci_kaiju.iso_status_text(iso_root)

    if hasattr(os, "symlink"):
        symlink = tmp / "kali-link.iso"
        symlink.symlink_to(source)
        assert_rejects("symlink ISO source", lambda: wuci_kaiju.install_iso(symlink, iso_root=tmp / "link-iso"))
        iso_root_target = tmp / "iso-root-target"
        iso_root_target.mkdir()
        iso_root_link = tmp / "iso-root-link"
        iso_root_link.symlink_to(iso_root_target, target_is_directory=True)
        assert_rejects(
            "symlink ISO workspace root",
            lambda: wuci_kaiju.install_iso(source, iso_root=iso_root_link, name="kali-test.iso"),
        )
        bad_iso_root = tmp / "bad-iso-root"
        bad_iso_root.mkdir()
        (bad_iso_root / "kali-test.iso").symlink_to(tmp / "missing.iso")
        assert_rejects(
            "symlink ISO destination",
            lambda: wuci_kaiju.install_iso(
                source,
                iso_root=bad_iso_root,
                name="kali-test.iso",
                force=True,
            ),
        )

    if hasattr(os, "link"):
        hardlink = tmp / "kali-hard.iso"
        try:
            os.link(source, hardlink)
        except OSError:
            pass
        else:
            assert_rejects("hardlinked ISO source", lambda: wuci_kaiju.install_iso(hardlink, iso_root=tmp / "hard-iso"))

    disk = wuci_kaiju.create_disk(disk_root=disk_root, size_mib=1)
    assert disk["schema"] == wuci_kaiju.DISK_SCHEMA
    disk_result = wuci_kaiju.verify_disk(disk_root)
    assert disk_result["status"] == "pass", disk_result
    if hasattr(os, "symlink"):
        disk_root_target = tmp / "disk-root-target"
        disk_root_target.mkdir()
        disk_root_link = tmp / "disk-root-link"
        disk_root_link.symlink_to(disk_root_target, target_is_directory=True)
        assert_rejects(
            "symlink disk workspace root",
            lambda: wuci_kaiju.create_disk(disk_root=disk_root_link, size_mib=1),
        )
        bad_disk_root = tmp / "bad-disk-root"
        bad_disk_root.mkdir()
        (bad_disk_root / "kali.raw").symlink_to(tmp / "missing.raw")
        assert_rejects(
            "symlink disk destination",
            lambda: wuci_kaiju.create_disk(disk_root=bad_disk_root, size_mib=1, force=True),
        )

    plan = wuci_kaiju.boot_plan(
        iso_root=iso_root,
        disk_root=disk_root,
        qemu_bin="/bin/true",
        memory_mib=512,
        cpus=1,
    )
    argv = plan["argv"]
    assert plan["schema"] == wuci_kaiju.BOOT_SCHEMA
    assert plan["graphics"] == "none"
    assert plan["network"] == "none"
    assert "-nographic" in argv
    assert "-net" in argv
    assert "none" in argv
    assert any(str(disk_result["disk_path"]) in item for item in argv)
    assert wuci_kaiju.discover_qemu("/bin/true") == "/bin/true"
    assert wuci_kaiju.discover_qemu(str(tmp / "missing-qemu")) is None
    assert plan["qemu_candidates"] == ["/bin/true"]


def assert_cli() -> None:
    verify = subprocess.run(
        [str(REPO / "tools" / "wuci-kaiju"), "verify", "--json"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr + verify.stdout
    payload = json.loads(verify.stdout)
    assert payload["schema"] == "wuci-kaiju-verification-v1"
    assert payload["status"] == "pass"

    purpose = subprocess.run(
        [str(REPO / "tools" / "wuci-kaiju"), "list", "--purpose", "exploitation-frameworks"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert purpose.returncode == 0, purpose.stderr + purpose.stdout
    assert "schema: wuci-kaiju-purpose-list-v1" in purpose.stdout
    assert "metasploit-framework" in purpose.stdout
    assert "host_execution=unavailable" in purpose.stdout

    with tempfile.TemporaryDirectory(prefix="wuci-kaiju-cli-") as tmp_name:
        tmp = Path(tmp_name)
        source = tmp / "kali-cli.iso"
        source.write_bytes(b"KAIJU CLI ISO\n")
        iso_root = tmp / "iso"
        disk_root = tmp / "disk"
        iso_install = subprocess.run(
            [
                str(REPO / "tools" / "wuci-kaiju"),
                "iso",
                "--iso-root",
                str(iso_root),
                "install",
                str(source),
                "--name",
                "kali-cli.iso",
                "--json",
            ],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert iso_install.returncode == 0, iso_install.stderr + iso_install.stdout
        assert json.loads(iso_install.stdout)["schema"] == wuci_kaiju.ISO_SCHEMA

        disk_create = subprocess.run(
            [
                str(REPO / "tools" / "wuci-kaiju"),
                "disk",
                "--disk-root",
                str(disk_root),
                "create",
                "--size-mib",
                "1",
                "--json",
            ],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert disk_create.returncode == 0, disk_create.stderr + disk_create.stdout
        assert json.loads(disk_create.stdout)["schema"] == wuci_kaiju.DISK_SCHEMA

        boot = subprocess.run(
            [
                str(REPO / "tools" / "wuci-kaiju"),
                "boot",
                "--iso-root",
                str(iso_root),
                "--disk-root",
                str(disk_root),
                "--qemu-bin",
                "/bin/true",
                "--memory-mib",
                "512",
                "--cpus",
                "1",
                "--json",
            ],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert boot.returncode == 0, boot.stderr + boot.stdout
        boot_payload = json.loads(boot.stdout)
        assert boot_payload["schema"] == wuci_kaiju.BOOT_SCHEMA
        assert boot_payload["network"] == "none"
        assert "-nographic" in boot_payload["argv"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check WUCI-KAIJU catalog invariants.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="wuci-kaiju-") as tmp_name:
        tmp = Path(tmp_name)
        assert_manifest_validation()
        assert_public_manifest_rejections(tmp)
        assert_installed_boot_direct_path(tmp)
        assert_iso_disk_boot(tmp)
        assert_cli()
    if not args.quiet:
        print("wuci kaiju: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
