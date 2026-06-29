#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
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
            return
        assert_rejects("hardlinked manifest", lambda: wuci_kaiju.load_manifest(hardlink))


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
        assert_iso_disk_boot(tmp)
        assert_cli()
    if not args.quiet:
        print("wuci kaiju: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
