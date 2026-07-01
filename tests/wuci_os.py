#!/usr/bin/env python3
from __future__ import annotations

import io
import inspect
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_os  # noqa: E402


ISOLINUX = """\
LABEL linux
MENU LABEL Void Linux x86_64-musl
KERNEL /boot/vmlinuz
APPEND initrd=/boot/initrd root=live:CDLABEL=VOID_LIVE init=/sbin/init ro rd.luks=0 rd.md=0 rd.dm=0 loglevel=4 rd.live.overlay.overlayfs=1
"""


def layout_fixture(*, status: str = "pass", append: str | None = None, problems: list[str] | None = None) -> dict[str, object]:
    layout_append = wuci_os.first_isolinux_append(ISOLINUX) if append is None else append
    return {
        "schema": "wuci-os-void-musl-layout-v1",
        "status": status,
        "label": "VOID_LIVE",
        "append": layout_append,
        "problems": [] if problems is None else problems,
    }


def source_base_fixture(image_name: str) -> dict[str, str]:
    return {
        "distribution": "Wuci-OS live base",
        "libc": "musl",
        "image_kind": "live base ISO",
        "upstream_label": wuci_os.VOID_LIVE_LABEL,
        "release_stamp": wuci_os.release_stamp_from_name(image_name),
    }


def assert_core_policy() -> None:
    assert wuci_os.PRODUCT_NAME == "Wuci-OS"
    assert wuci_os.IMAGE_ID == "wuci-os"
    assert "runtime sandboxing" in " ".join(wuci_os.BOUNDARY_DENIALS)
    assert "offensive scanning" in " ".join(wuci_os.BOUNDARY_DENIALS)
    model = (REPO / "docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md").read_text(encoding="utf-8")
    for required in (
        "SSM_v1",
        "WUCI_D = Fix(Phi_D)",
        "Sub_D(S)",
        "PublicBeforePrivate_D",
        "I(K_priv ; W_pub) = 0",
        "PackageDAG*",
        "Boot_D_strong(ISO)",
        "FinalManifest_D",
        "Publish_D(ISO) = 0 otherwise",
    ):
        assert required in model
    daylight_v8 = (REPO / "docs/WUCI_DAYLIGHT_V8.md").read_text(encoding="utf-8")
    for required in (
        "Daylight_v8",
        "Sheaf-Gated Subtractive Cryptographic Substrate",
        "Gamma(X,F) != empty",
        "EvidenceSheaf",
        "SubtractiveCapabilityLattice",
        "ctx_D",
        "Artifact_i",
        "LedgerStep_D(t)=1",
        "NoProof_D(x) => NoClaim_D(x) => NoRelease_D(x)",
    ):
        assert required in daylight_v8
    daylight_v9 = (REPO / "docs/WUCI_DAYLIGHT_V9.md").read_text(encoding="utf-8")
    for required in (
        "Daylight v9",
        "Proof-Carrying Subtractive Cryptographic Operating Substrate",
        "Daylight v8 benchmark: 973/1000",
        "Daylight v9 target: 990-995",
        "AttackSurface_D(s) subseteq Closed_D",
        "rho_{U,U_intersect_V}",
        "from z3 import *",
        "structure DaylightState",
        "Artifact_i =",
        "NoProof_D(x) => NoClaim_D(x) => NoRelease_D(x)",
    ):
        assert required in daylight_v9
    daylight_v10 = (REPO / "docs/WUCI_DAYLIGHT_V10.md").read_text(encoding="utf-8")
    for required in (
        "Daylight v10",
        "Minimal Verified Release Kernel for Wuci-Ji",
        "Publish_D10(ISO)=1",
        "Daylight != new cipher",
        "ProofKernel_D10(S)",
        "S_max = 10^6 M",
        "EvidenceDensity",
        "DU_T(W)",
        "NoFresh_D(x) => NoOpen_D(x) => NoPublish_D(x)",
    ):
        assert required in daylight_v10
    daylight_v13 = (REPO / "docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md").read_text(encoding="utf-8")
    for required in (
        "Daylight v13 Sovereign Profile",
        "DAYLIGHT-SOVEREIGN-v13",
        "not a current release claim",
        "ML-KEM-1024",
        "AES-256-GCM-SIV",
        "U_13 = 0.9913",
        "Daylight_13 = 991300M / 1000000M",
        "DominanceMargin = 3.0457%",
        "GapCapture = 29300 / 38000 = 0.7710526 = 77.1053%",
        "NoProof(x) -> NoClaim(x) -> NoRelease(x)",
        "Do not claim Daylight is stronger than AES as a raw block cipher.",
    ):
        assert required in daylight_v13
    daylight_v9_svg = (REPO / "docs/wuci-os/assets/wuci-daylight-v9-spine.svg").read_text(encoding="utf-8")
    assert "Daylight v9" in daylight_v9_svg
    assert "NoProof_D(x) =&gt; NoClaim_D(x) =&gt; NoRelease_D(x)" in daylight_v9_svg
    daylight_v9_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v9-sheet.png").read_bytes()
    assert daylight_v9_png.startswith(wuci_os.PNG_SIGNATURE)
    daylight_v10_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v10-scoreboard.png").read_bytes()
    assert daylight_v10_png.startswith(wuci_os.PNG_SIGNATURE)
    daylight_v13_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v13-sovereign-math.png").read_bytes()
    assert daylight_v13_png.startswith(wuci_os.PNG_SIGNATURE)
    daylight_v14c_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png").read_bytes()
    assert daylight_v14c_png.startswith(wuci_os.PNG_SIGNATURE)
    daylight_v14c_math_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png").read_bytes()
    assert daylight_v14c_math_png.startswith(wuci_os.PNG_SIGNATURE)
    daylight_v14c_wide_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png").read_bytes()
    assert daylight_v14c_wide_png.startswith(wuci_os.PNG_SIGNATURE)
    daylight_v15_solstice_png = (REPO / "docs/wuci-os/assets/wuci-daylight-v15-plus-solstice.png").read_bytes()
    assert daylight_v15_solstice_png.startswith(wuci_os.PNG_SIGNATURE)
    assert wuci_os.safe_iso_name("void-live-x86_64-musl-20250202-base.iso")
    for bad in ("../void.iso", "/tmp/void.iso", "void.img", ".iso"):
        try:
            wuci_os.safe_iso_name(bad)
        except wuci_os.WuciOSError:
            continue
        raise AssertionError(f"expected unsafe ISO name rejection: {bad}")


def assert_append_parsing() -> None:
    append = wuci_os.first_isolinux_append(ISOLINUX)
    assert "root=live:CDLABEL=VOID_LIVE" in append
    serial = wuci_os.serial_append_from_void(append)
    assert "initrd=" not in serial
    assert "console=ttyS0,115200n8" in serial
    assert "console=tty0" in serial
    assert "nomodeset" in serial
    assert "rd.md=0" in serial
    assert "rd.luks=0" in serial
    assert "modprobe.blacklist=raid456,async_raid6_recov,dm_raid,md_mod,btrfs" in serial
    assert serial.count("console=ttyS0,115200n8") == 1
    assert serial.count("console=tty0") == 1
    boot_menu = wuci_os.rewrite_isolinux_config_for_wuci(
        ISOLINUX
        + "\nLABEL linuxram\nMENU LABEL Void Linux x86_64-musl (RAM)\nKERNEL /boot/vmlinuz\nAPPEND initrd=/boot/initrd root=live:CDLABEL=VOID_LIVE rd.live.ram\n"
        + "\nLABEL c\nMENU LABEL Boot first HD found by BIOS\nCOM32 chain.c32\nAPPEND hd0\n"
        + "\nLABEL reboot\nMENU LABEL Re^boot\nCOM32 reboot.c32\n"
    )
    assert "MENU LABEL Wuci-Ji Systems / Wuci-OS live" in boot_menu
    assert "MENU LABEL Wuci-OS live (copy to RAM)" in boot_menu
    assert "MENU LABEL Boot first hard disk" in boot_menu
    assert "MENU LABEL Reboot" in boot_menu
    assert "MENU BACKGROUND /boot/isolinux/wuci-splash.png" in boot_menu
    assert "initrd=/boot/initrd" in boot_menu
    assert "console=tty0" in boot_menu
    assert "rd.driver.pre=loop" in boot_menu
    assert "live.hostname=wuci-os-live" in boot_menu
    assert "rd.auto=0" not in boot_menu
    assert "rd.lvm=0" not in boot_menu
    assert "modprobe.blacklist=" not in boot_menu
    assert "APPEND hd0 console=" not in boot_menu
    assert "Void Linux" not in boot_menu
    grub = wuci_os.rewrite_grub_config_for_wuci(
        "menuentry 'Void Linux' --id linux {\n linux /boot/vmlinuz \\\n  root=live:CDLABEL=VOID_LIVE ro init=/sbin/init \\\n}\n"
        "menuentry 'Void Linux (RAM)' --id linuxram --hotkey r {\n linux /boot/vmlinuz \\\n  root=live:CDLABEL=VOID_LIVE ro init=/sbin/init rd.live.ram \\\n}\n"
        "menuentry 'System restart' --id restart {\n reboot\n}\n"
    )
    assert "menuentry 'Wuci-Ji Systems / Wuci-OS live' --id linux" in grub
    assert "menuentry 'Wuci-OS live (copy to RAM)' --id linuxram --hotkey r" in grub
    assert "menuentry 'Restart' --id restart" in grub
    assert "background_image /boot/grub/wuci-splash.png" in grub
    assert "console=tty0" in grub
    assert "rd.driver.pre=loop" in grub
    assert "Void Linux" not in grub


def assert_missing_source(tmp: Path) -> None:
    source_root = tmp / "source"
    result = wuci_os.verify_source(source_root)
    assert result["status"] == "missing"
    plan = wuci_os.build_plan(source_root)
    assert plan["status"] == "blocked"
    assert plan["image_id"] == "wuci-os"


def assert_bad_source_rejected(tmp: Path) -> None:
    source = tmp / "bad.iso"
    source.write_bytes(b"not a void live iso")
    try:
        wuci_os.install_source(source, source_root=tmp / "bad-source")
    except wuci_os.WuciOSError:
        return
    raise AssertionError("expected invalid Void ISO rejection")


def assert_rollback_backup_detects_changed_file(tmp: Path) -> None:
    victim = tmp / "rollback-victim.txt"
    victim.write_bytes(b"original rollback content\n")
    original_replace = wuci_os.os.replace

    def replace_after_mutation(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        if Path(src) == victim and Path(dst).name.startswith(f".{victim.name}.old."):
            victim.write_bytes(b"mutated before rollback staging\n")
        original_replace(src, dst)

    try:
        wuci_os.os.replace = replace_after_mutation
        try:
            wuci_os._backup_existing_regular_file(victim, "test rollback victim")
        except wuci_os.WuciOSError as exc:
            assert "changed while staging rollback" in str(exc)
        else:
            raise AssertionError("rollback staging accepted a changed file")
    finally:
        wuci_os.os.replace = original_replace
    assert not any(path.name.startswith(f".{victim.name}.old.") for path in tmp.iterdir())


def assert_source_install_safeio(tmp: Path) -> None:
    iso_name = "void-live-x86_64-musl-20250202-base.iso"
    source = tmp / iso_name
    source.write_bytes(b"void iso fixture\n")
    original_inspect = wuci_os.inspect_void_iso
    original_write_json_atomic = wuci_os.wuci_kaiju.write_json_atomic
    try:
        wuci_os.inspect_void_iso = lambda _path: {
            "schema": "wuci-os-void-musl-layout-v1",
            "status": "pass",
            "label": "VOID_LIVE",
            "append": wuci_os.first_isolinux_append(ISOLINUX),
            "problems": [],
        }
        source_root = tmp / "installed-source"
        manifest = wuci_os.install_source(source, source_root=source_root, force=True)
        installed = source_root / iso_name
        assert manifest["schema"] == wuci_os.SOURCE_SCHEMA
        assert manifest["image_path"] == str(installed)
        assert manifest["digest_vector"] == wuci_os.wuci_kaiju.file_digest_vector(installed, "installed source")[0]
        assert (source_root / "source.json").is_file()

        if hasattr(os, "symlink"):
            root_target = tmp / "source-root-target"
            root_target.mkdir()
            root_link = tmp / "source-root-link"
            root_link.symlink_to(root_target, target_is_directory=True)
            try:
                wuci_os.install_source(source, source_root=root_link, force=True)
            except wuci_os.WuciOSError as exc:
                assert "parent must not be a symlink" in str(exc)
            else:
                raise AssertionError("source install accepted a symlink source root")
            assert not any(root_target.iterdir())

            dest_target = tmp / "source-dest-target.iso"
            dest_target.write_text("do not overwrite\n", encoding="utf-8")
            dest_root = tmp / "source-dest-link-root"
            dest_root.mkdir()
            dest_link = dest_root / iso_name
            dest_link.symlink_to(dest_target)
            try:
                wuci_os.install_source(source, source_root=dest_root, force=True)
            except wuci_os.WuciOSError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("source install accepted a symlink destination")
            assert dest_target.read_text(encoding="utf-8") == "do not overwrite\n"

        if hasattr(os, "link"):
            hard_source = tmp / "hard-source.iso"
            hard_source.write_bytes(b"hardlinked fixture\n")
            hard_link = tmp / "hard-source-link.iso"
            try:
                os.link(hard_source, hard_link)
            except OSError:
                return
            try:
                wuci_os.install_source(hard_source, source_root=tmp / "hard-source-root", force=True)
            except wuci_os.WuciOSError as exc:
                assert "hardlinked" in str(exc)
            else:
                raise AssertionError("source install accepted a hardlinked source")

        preserve_root = tmp / "preserve-source-root"
        preserve_root.mkdir()
        preserve_dest = preserve_root / iso_name
        preserve_dest.write_bytes(b"old installed source\n")
        preserve_manifest = wuci_os.source_manifest_path(preserve_root)
        preserve_manifest.write_text('{"old": true}\n', encoding="utf-8")
        bad_replacement = tmp / "bad-replacement.iso"
        bad_replacement.write_bytes(b"new bad source\n")
        wuci_os.inspect_void_iso = lambda _path: {
            "schema": "wuci-os-void-musl-layout-v1",
            "status": "fail",
            "label": "VOID_LIVE",
            "append": "",
            "problems": ["fixture layout failure"],
        }
        try:
            wuci_os.install_source(bad_replacement, source_root=preserve_root, name=iso_name, force=True)
        except wuci_os.WuciOSError as exc:
            assert "layout verification failed" in str(exc)
        else:
            raise AssertionError("source install replaced existing source before layout failure")
        assert preserve_dest.read_bytes() == b"old installed source\n"
        assert preserve_manifest.read_text(encoding="utf-8") == '{"old": true}\n'
        assert not any(path.name.startswith(f".{iso_name}.") for path in preserve_root.iterdir())

        manifest_failure_source = tmp / "manifest-failure-replacement.iso"
        manifest_failure_source.write_bytes(b"new manifest failure source\n")
        wuci_os.inspect_void_iso = lambda _path: {
            "schema": "wuci-os-void-musl-layout-v1",
            "status": "pass",
            "label": "VOID_LIVE",
            "append": wuci_os.first_isolinux_append(ISOLINUX),
            "problems": [],
        }

        def write_then_fail(path: Path, value: dict[str, object]) -> None:
            original_write_json_atomic(path, value)
            if path == preserve_manifest:
                raise RuntimeError("fixture manifest failure")

        wuci_os.wuci_kaiju.write_json_atomic = write_then_fail
        try:
            wuci_os.install_source(manifest_failure_source, source_root=preserve_root, name=iso_name, force=True)
        except RuntimeError as exc:
            assert "fixture manifest failure" in str(exc)
        else:
            raise AssertionError("source install ignored a manifest write failure")
        assert preserve_dest.read_bytes() == b"old installed source\n"
        assert preserve_manifest.read_text(encoding="utf-8") == '{"old": true}\n'
        assert not any(path.name.startswith(f".{iso_name}.") for path in preserve_root.iterdir())
        assert not any(path.name.startswith(".source.json.") for path in preserve_root.iterdir())
    finally:
        wuci_os.inspect_void_iso = original_inspect
        wuci_os.wuci_kaiju.write_json_atomic = original_write_json_atomic


def assert_source_verify_manifest_bounds(tmp: Path) -> None:
    source_root = tmp / "verify-source-root"
    source_root.mkdir()
    image = source_root / "void-live-x86_64-musl-20250202-base.iso"
    image.write_bytes(b"valid source fixture\n")
    digest, size = wuci_os.wuci_kaiju.file_digest_vector(image, "verify fixture")
    base_layout = layout_fixture()
    base_manifest = {
        "schema": wuci_os.SOURCE_SCHEMA,
        "created_utc": "2026-06-29T00:00:00Z",
        "product": wuci_os.PRODUCT_NAME,
        "image_id": wuci_os.IMAGE_ID,
        "base": source_base_fixture(image.name),
        "operator_supplied": True,
        "image_name": image.name,
        "image_path": str(image),
        "image_bytes": size,
        "digest_vector": digest,
        "layout": base_layout,
        "boundary_denials": list(wuci_os.BOUNDARY_DENIALS),
    }
    wuci_os.wuci_kaiju.write_json_atomic(wuci_os.source_manifest_path(source_root), base_manifest)
    original_inspect = wuci_os.inspect_void_iso
    try:
        wuci_os.inspect_void_iso = lambda _path: base_layout
        valid = wuci_os.verify_source(source_root)
        assert valid["status"] == "pass", valid

        outside = tmp / "outside-source.iso"
        outside.write_bytes(b"outside source fixture\n")
        outside_digest, outside_size = wuci_os.wuci_kaiju.file_digest_vector(outside, "outside fixture")
        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {
                "image_name": outside.name,
                "image_path": str(outside),
                "image_bytes": outside_size,
                "digest_vector": outside_digest,
            },
        )
        outside_result = wuci_os.verify_source(source_root)
        assert outside_result["status"] == "fail"
        assert "image_path must stay under source_root" in outside_result["problems"]

        nested_dir = source_root / "nested"
        nested_dir.mkdir()
        nested = nested_dir / image.name
        nested.write_bytes(b"nested source fixture\n")
        nested_digest, nested_size = wuci_os.wuci_kaiju.file_digest_vector(nested, "nested fixture")
        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {
                "image_path": str(nested),
                "image_bytes": nested_size,
                "digest_vector": nested_digest,
            },
        )
        nested_result = wuci_os.verify_source(source_root)
        assert nested_result["status"] == "fail"
        assert "image_path must name one direct source_root ISO" in nested_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"image_name": "other-void-live-x86_64-musl-20250202-base.iso"},
        )
        mismatch_result = wuci_os.verify_source(source_root)
        assert mismatch_result["status"] == "fail"
        assert "image_path must match image_name" in mismatch_result["problems"]

        missing_name_manifest = dict(base_manifest)
        missing_name_manifest.pop("image_name")
        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            missing_name_manifest,
        )
        missing_name_result = wuci_os.verify_source(source_root)
        assert missing_name_result["status"] == "fail"
        assert "image_name must be a plain .iso filename" in missing_name_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"image_name": 7},
        )
        non_string_name_result = wuci_os.verify_source(source_root)
        assert non_string_name_result["status"] == "fail"
        assert "image_name must be a plain .iso filename" in non_string_name_result["problems"]

        missing_layout_manifest = dict(base_manifest)
        missing_layout_manifest.pop("layout")
        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            missing_layout_manifest,
        )
        missing_layout_result = wuci_os.verify_source(source_root)
        assert missing_layout_result["status"] == "fail"
        assert "layout missing" in missing_layout_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"layout": layout_fixture(append="stale append")},
        )
        mismatch_layout_result = wuci_os.verify_source(source_root)
        assert mismatch_layout_result["status"] == "fail"
        assert "source manifest layout mismatch" in mismatch_layout_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"product": "Other-OS"},
        )
        product_result = wuci_os.verify_source(source_root)
        assert product_result["status"] == "fail"
        assert "source manifest product mismatch" in product_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"image_id": "other-image"},
        )
        image_id_result = wuci_os.verify_source(source_root)
        assert image_id_result["status"] == "fail"
        assert "source manifest image_id mismatch" in image_id_result["problems"]

        missing_operator_manifest = dict(base_manifest)
        missing_operator_manifest.pop("operator_supplied")
        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            missing_operator_manifest,
        )
        operator_result = wuci_os.verify_source(source_root)
        assert operator_result["status"] == "fail"
        assert "operator_supplied must be true" in operator_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"boundary_denials": []},
        )
        boundary_result = wuci_os.verify_source(source_root)
        assert boundary_result["status"] == "fail"
        assert "boundary_denials mismatch" in boundary_result["problems"]

        missing_base_manifest = dict(base_manifest)
        missing_base_manifest.pop("base")
        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            missing_base_manifest,
        )
        missing_base_result = wuci_os.verify_source(source_root)
        assert missing_base_result["status"] == "fail"
        assert "source base metadata missing" in missing_base_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"base": source_base_fixture(image.name) | {"upstream_label": "OTHER"}},
        )
        label_result = wuci_os.verify_source(source_root)
        assert label_result["status"] == "fail"
        assert "source base upstream_label mismatch" in label_result["problems"]

        wuci_os.wuci_kaiju.write_json_atomic(
            wuci_os.source_manifest_path(source_root),
            base_manifest | {"base": source_base_fixture(image.name) | {"release_stamp": "19990101"}},
        )
        stamp_result = wuci_os.verify_source(source_root)
        assert stamp_result["status"] == "fail"
        assert "source base release_stamp mismatch" in stamp_result["problems"]

        if hasattr(os, "symlink"):
            symlink_target = tmp / "source-root-symlink-target"
            symlink_target.mkdir()
            wuci_os.wuci_kaiju.write_json_atomic(
                wuci_os.source_manifest_path(symlink_target),
                base_manifest | {"image_path": str(symlink_target / image.name)},
            )
            (symlink_target / image.name).write_bytes(b"symlink root fixture\n")
            symlink_root = tmp / "source-root-symlink"
            symlink_root.symlink_to(symlink_target, target_is_directory=True)
            symlink_result = wuci_os.verify_source(symlink_root)
            assert symlink_result["status"] == "fail"
            assert any("source root must not be a symlink" in problem for problem in symlink_result["problems"])
    finally:
        wuci_os.inspect_void_iso = original_inspect


def assert_boot_plan_ready(tmp: Path) -> None:
    source_root = tmp / "source"
    source_root.mkdir()
    image = source_root / "void.iso"
    image.write_bytes(b"void iso fixture")
    boot_layout = layout_fixture()
    wuci_os.wuci_kaiju.write_json_atomic(
        wuci_os.source_manifest_path(source_root),
        {
            "schema": wuci_os.SOURCE_SCHEMA,
            "created_utc": "2026-06-29T00:00:00Z",
            "product": wuci_os.PRODUCT_NAME,
            "image_id": wuci_os.IMAGE_ID,
            "base": source_base_fixture(image.name),
            "operator_supplied": True,
            "image_name": image.name,
            "image_path": str(image),
            "image_bytes": image.stat().st_size,
            "digest_vector": wuci_os.wuci_kaiju.file_digest_vector(image, "fixture")[0],
            "layout": boot_layout,
            "boundary_denials": list(wuci_os.BOUNDARY_DENIALS),
        },
    )

    original_inspect = wuci_os.inspect_void_iso
    try:
        wuci_os.inspect_void_iso = lambda _path: boot_layout
        plan = wuci_os.boot_plan(
            source_root=source_root,
            boot_root=tmp / "boot",
            qemu_bin="/bin/true",
            memory_mib=512,
            cpus=1,
            network=True,
        )
        share_plan = wuci_os.boot_plan(
            source_root=source_root,
            boot_root=tmp / "boot-share",
            qemu_bin="/bin/true",
            memory_mib=512,
            cpus=1,
            network=True,
            share_repo=tmp,
        )
    finally:
        wuci_os.inspect_void_iso = original_inspect
    assert plan["status"] == "ready", plan
    assert plan["qemu_discovered"] == "/bin/true"
    assert plan["network"] == "user"
    assert "-kernel" in plan["argv"]
    assert "-initrd" in plan["argv"]
    assert "pc,accel=kvm:tcg" in plan["argv"]
    assert "max" in plan["argv"]
    assert "console=ttyS0,115200n8" in plan["append"]
    assert "console=tty0" in plan["append"]
    assert plan["boot_profile"]["mode"] == "fast-live"
    assert "rd.auto=0" in plan["append"]
    assert any("user,model=virtio-net-pci" == item for item in plan["argv"])
    assert share_plan["status"] == "ready", share_plan
    assert share_plan["share_mode"] == "tar-drive"
    assert any(str(item).endswith("wuci-os-overlay.tar,format=raw,if=virtio,readonly=on") for item in share_plan["argv"])
    assert any(str(item).endswith("wuci-os-source-kit.tar,format=raw,if=virtio,readonly=on") for item in share_plan["argv"])
    assert share_plan["source_kit_path"].endswith("wuci-os-source-kit.tar")
    assert "tar -xf" in share_plan["guest_extract_hint"]
    assert "&& break" not in share_plan["guest_extract_hint"]

    overlay_root = tmp / "boot-ready-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    share_plan["overlay_root"] = str(overlay_root)
    original_extract = wuci_os.wuci_kaiju._extract_iso_file_content

    def fake_extract(_image: Path, subpath: str) -> bytes | None:
        if subpath == "boot/vmlinuz":
            return b"kernel payload\n"
        if subpath == "boot/initrd":
            return b"initrd payload\n"
        return None

    try:
        wuci_os.wuci_kaiju._extract_iso_file_content = fake_extract
        argv = wuci_os.build_live_boot_argv(share_plan)
    finally:
        wuci_os.wuci_kaiju._extract_iso_file_content = original_extract

    assert argv == share_plan["argv"]
    generated = share_plan["generated_artifacts"]
    assert generated["schema"] == "wuci-os-live-boot-generated-artifacts-v1"
    assert generated["kernel"]["digest_vector"] == wuci_os.digest_vector(b"kernel payload\n")
    assert generated["initrd"]["digest_vector"] == wuci_os.digest_vector(b"initrd payload\n")
    assert generated["overlay_tar"]["validation"]["status"] == "pass"
    assert generated["source_kit_tar"]["validation"]["status"] == "pass"
    assert generated["source_kit_tar"]["validation"]["tar_validation"]["status"] == "pass"


def assert_boot_share_rejects_stale_overlay_manifest(tmp: Path) -> None:
    overlay_root = tmp / "boot-stale-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    stale_file = overlay_root / "usr/local/bin/wuci-guide"
    stale_file.write_text(stale_file.read_text(encoding="utf-8") + "\n# stale before boot share\n", encoding="utf-8")
    boot_root = tmp / "boot-stale"
    source_image = tmp / "boot-source.iso"
    source_image.write_bytes(b"source fixture\n")
    plan = {
        "schema": wuci_os.BOOT_SCHEMA,
        "status": "ready",
        "source": {"image_path": str(source_image)},
        "boot_root": str(boot_root),
        "share_mode": "tar-drive",
        "overlay_root": str(overlay_root),
        "source_kit_path": "",
        "argv": ["/bin/true"],
    }
    original_extract = wuci_os.wuci_kaiju._extract_iso_file_content
    try:
        wuci_os.wuci_kaiju._extract_iso_file_content = lambda _image, _subpath: b"boot payload\n"
        try:
            wuci_os.build_live_boot_argv(plan)
        except wuci_os.WuciOSError as exc:
            assert "content_records mismatch" in str(exc)
        else:
            raise AssertionError("boot share accepted a stale overlay manifest")
    finally:
        wuci_os.wuci_kaiju._extract_iso_file_content = original_extract
    assert not (boot_root / "vmlinuz").exists()
    assert not (boot_root / "initrd").exists()
    assert not (boot_root / "wuci-os-overlay.tar").exists()


def assert_boot_payload_failure_cleans_partial_artifacts(tmp: Path) -> None:
    overlay_root = tmp / "boot-failure-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    source_image = tmp / "boot-failure-source.iso"
    source_image.write_bytes(b"source fixture\n")
    boot_root = tmp / "boot-failure"
    plan = {
        "schema": wuci_os.BOOT_SCHEMA,
        "status": "ready",
        "source": {"image_path": str(source_image)},
        "boot_root": str(boot_root),
        "share_mode": "tar-drive",
        "overlay_root": str(overlay_root),
        "source_kit_path": str(boot_root / wuci_os.SOURCE_KIT_TAR_NAME),
        "argv": ["/bin/true"],
        "generated_artifacts": {"stale": True},
    }
    original_extract = wuci_os.wuci_kaiju._extract_iso_file_content
    original_source_kit = wuci_os.write_deterministic_source_kit_tar

    def fake_extract(_image: Path, subpath: str) -> bytes | None:
        if subpath == "boot/vmlinuz":
            return b"kernel payload\n"
        if subpath == "boot/initrd":
            return b"initrd payload\n"
        return None

    def fail_source_kit(_tar_path: Path, *, ticker_mode: str = "auto") -> dict[str, object]:
        raise wuci_os.WuciOSError("fixture source-kit failure")

    try:
        wuci_os.wuci_kaiju._extract_iso_file_content = fake_extract
        wuci_os.write_deterministic_source_kit_tar = fail_source_kit
        try:
            wuci_os.build_live_boot_argv(plan)
        except wuci_os.WuciOSError as exc:
            assert "fixture source-kit failure" in str(exc)
        else:
            raise AssertionError("boot payload build ignored source-kit failure")
    finally:
        wuci_os.write_deterministic_source_kit_tar = original_source_kit
        wuci_os.wuci_kaiju._extract_iso_file_content = original_extract

    assert "generated_artifacts" not in plan
    assert not (boot_root / "vmlinuz").exists()
    assert not (boot_root / "initrd").exists()
    assert not (boot_root / "wuci-os-overlay.tar").exists()
    assert not (boot_root / wuci_os.SOURCE_KIT_TAR_NAME).exists()

    outside_plan = dict(plan)
    outside_plan["source_kit_path"] = str(tmp / "outside-source-kit.tar")
    try:
        wuci_os.wuci_kaiju._extract_iso_file_content = fake_extract
        wuci_os.build_live_boot_argv(outside_plan)
    except wuci_os.WuciOSError as exc:
        assert "must stay under boot_root" in str(exc)
    else:
        raise AssertionError("boot payload accepted a source-kit path outside boot_root")
    finally:
        wuci_os.wuci_kaiju._extract_iso_file_content = original_extract

    assert "generated_artifacts" not in outside_plan
    assert not (boot_root / "vmlinuz").exists()
    assert not (boot_root / "initrd").exists()
    assert not (boot_root / "wuci-os-overlay.tar").exists()
    assert not (tmp / "outside-source-kit.tar").exists()


def assert_boot_payload_cleanup_reports_tampered_artifact(tmp: Path) -> None:
    if not hasattr(os, "link"):
        return
    overlay_root = tmp / "boot-tamper-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    source_image = tmp / "boot-tamper-source.iso"
    source_image.write_bytes(b"source fixture\n")
    boot_root = tmp / "boot-tamper"
    plan = {
        "schema": wuci_os.BOOT_SCHEMA,
        "status": "ready",
        "source": {"image_path": str(source_image)},
        "boot_root": str(boot_root),
        "share_mode": "tar-drive",
        "overlay_root": str(overlay_root),
        "source_kit_path": str(boot_root / wuci_os.SOURCE_KIT_TAR_NAME),
        "argv": ["/bin/true"],
    }
    original_extract = wuci_os.wuci_kaiju._extract_iso_file_content
    original_source_kit = wuci_os.write_deterministic_source_kit_tar

    def fake_extract(_image: Path, subpath: str) -> bytes | None:
        if subpath == "boot/vmlinuz":
            return b"kernel payload\n"
        if subpath == "boot/initrd":
            return b"initrd payload\n"
        return None

    def tamper_then_fail(_tar_path: Path, *, ticker_mode: str = "auto") -> dict[str, object]:
        os.link(boot_root / "vmlinuz", boot_root / "vmlinuz-peer")
        raise wuci_os.WuciOSError("fixture source-kit failure after tamper")

    try:
        wuci_os.wuci_kaiju._extract_iso_file_content = fake_extract
        wuci_os.write_deterministic_source_kit_tar = tamper_then_fail
        try:
            wuci_os.build_live_boot_argv(plan)
        except wuci_os.WuciOSError as exc:
            message = str(exc)
            assert "cleanup failed" in message
            assert "must not be hardlinked" in message
        else:
            raise AssertionError("boot payload cleanup ignored a hardlinked transient artifact")
    finally:
        wuci_os.write_deterministic_source_kit_tar = original_source_kit
        wuci_os.wuci_kaiju._extract_iso_file_content = original_extract

    assert "generated_artifacts" not in plan
    assert (boot_root / "vmlinuz").exists()
    assert (boot_root / "vmlinuz-peer").exists()
    assert not (boot_root / "initrd").exists()
    assert not (boot_root / "wuci-os-overlay.tar").exists()


def assert_boot_cleanup_safeio(tmp: Path) -> None:
    cleanup_root = tmp / "boot-cleanup"
    cleanup_root.mkdir()
    for name in ("vmlinuz", "initrd", "wuci-os-overlay.tar", wuci_os.SOURCE_KIT_TAR_NAME):
        (cleanup_root / name).write_bytes(f"{name}\n".encode("ascii"))
    wuci_os.cleanup_boot_artifacts(cleanup_root)
    assert not cleanup_root.exists()

    if hasattr(os, "symlink"):
        root_target = tmp / "boot-cleanup-root-target"
        root_target.mkdir()
        protected = root_target / "vmlinuz"
        protected.write_text("do not remove through root link\n", encoding="utf-8")
        root_link = tmp / "boot-cleanup-root-link"
        root_link.symlink_to(root_target, target_is_directory=True)
        try:
            wuci_os.cleanup_boot_artifacts(root_link)
        except wuci_os.WuciOSError as exc:
            assert "root must not be a symlink" in str(exc)
        else:
            raise AssertionError("boot cleanup accepted a symlink root")
        assert protected.read_text(encoding="utf-8") == "do not remove through root link\n"

        artifact_target = tmp / "boot-cleanup-artifact-target"
        artifact_target.write_text("do not unlink through artifact link\n", encoding="utf-8")
        artifact_root = tmp / "boot-cleanup-artifact-link-root"
        artifact_root.mkdir()
        (artifact_root / "vmlinuz").symlink_to(artifact_target)
        try:
            wuci_os.cleanup_boot_artifacts(artifact_root)
        except wuci_os.WuciOSError as exc:
            assert "artifact must not be a symlink" in str(exc)
        else:
            raise AssertionError("boot cleanup accepted a symlink artifact")
        assert artifact_target.read_text(encoding="utf-8") == "do not unlink through artifact link\n"

    if hasattr(os, "link"):
        hard_root = tmp / "boot-cleanup-hardlink-root"
        hard_root.mkdir()
        hard_source = hard_root / "vmlinuz"
        hard_peer = hard_root / "vmlinuz-peer"
        hard_source.write_text("hardlinked cleanup artifact\n", encoding="utf-8")
        try:
            os.link(hard_source, hard_peer)
        except OSError:
            return
        try:
            wuci_os.cleanup_boot_artifacts(hard_root)
        except wuci_os.WuciOSError as exc:
            assert "artifact must not be hardlinked" in str(exc)
        else:
            raise AssertionError("boot cleanup accepted a hardlinked artifact")
        assert hard_source.exists()
        assert hard_peer.exists()


def assert_overlay_profile(tmp: Path) -> None:
    files = wuci_os.overlay_files()
    required = {
        "usr/local/bin/wuci-wallpaper",
        "usr/local/bin/wuci-wait-run",
        "usr/local/bin/wuci-attest",
        "usr/local/bin/wuci-live-banner",
        "usr/local/bin/sudo",
        "usr/local/bin/su",
        "usr/local/bin/ip",
        "usr/local/bin/dhcpcd",
        "usr/local/bin/iw",
        "usr/local/bin/rfkill",
        "usr/local/bin/wpa_supplicant",
        "usr/local/bin/wpa_passphrase",
        "usr/local/bin/xbps-install",
        "usr/local/bin/wuci-source-status",
        "usr/local/bin/wuci-selfupdate",
        "usr/local/bin/wuci-enter",
        "usr/local/bin/wuci-guide",
        "usr/local/bin/wuci-auto",
        "usr/local/bin/wuci-daylight-status",
        "usr/local/bin/wuci-terminal",
        "usr/local/bin/wuci-boot-chime",
        "usr/local/bin/wuci-network-connect",
        "usr/local/bin/wuci-network-apply",
        "usr/local/bin/wuci-network-status",
        "usr/local/bin/wuci-media-apply",
        "usr/local/bin/wuci-media-status",
        "usr/local/bin/wuci-media-session",
        "usr/local/bin/wuci-sdr-apply",
        "usr/local/bin/wuci-sdr-status",
        "usr/local/bin/wuci-update",
        "usr/local/bin/INSTALL",
        "usr/local/bin/wj",
        "usr/local/bin/wuci-users-apply",
        "usr/local/bin/wuci-users-status",
        "usr/local/bin/wuci-dev-install",
        "usr/local/bin/wuci-security-apply",
        "usr/local/bin/wuci-security-status",
        "usr/local/bin/wuci-selinux-status",
        "usr/local/bin/wuci-ai-setup",
        "usr/local/bin/wuci-grok-build",
        "usr/local/bin/wuci-daylight-v14c-plus",
        "usr/local/bin/wuci-daylight-meridian",
        "usr/share/wuci-os/accounts.json",
        "usr/share/wuci-os/packages.json",
        "usr/share/wuci-os/security-profile.json",
        "usr/share/wuci-os/full-suite-packages.txt",
        "usr/share/wuci-os/WUCI_DAYLIGHT_V8.md",
        "usr/share/wuci-os/WUCI_DAYLIGHT_V9.md",
        "usr/share/wuci-os/WUCI_DAYLIGHT_V10.md",
        "usr/share/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
        "etc/os-release",
        "usr/lib/os-release",
        "etc/profile.d/wuci-prompt.sh",
        "etc/xdg/autostart/wuci-boot-chime.desktop",
        "etc/xdg/autostart/wuci-media-session.desktop",
        "etc/runit/runsvdir/default/wuci-boot-chime/run",
        "etc/skel/.ratpoisonrc",
        "etc/skel/.config/kitty/kitty.conf",
    }
    assert required.issubset(files)
    assert "SELINUX=enforcing" in files["usr/local/bin/wuci-security-apply"]
    assert "SELINUXTYPE=targeted" in files["usr/local/bin/wuci-security-apply"]
    assert "policy drop" in files["usr/local/bin/wuci-security-apply"]
    assert "passwd -d wj" in files["usr/local/bin/wuci-users-apply"]
    assert "required Wuci-OS command is missing" in files["usr/local/bin/sudo"]
    assert 'exec "$candidate" "$@"' in files["usr/local/bin/wpa_supplicant"]
    assert "chpst" in files["usr/local/bin/wuci-enter"]
    assert "run as root to switch users" in files["usr/local/bin/wuci-enter"]
    assert '"$current_user" = "$target"' in files["usr/local/bin/wuci-enter"]
    assert "wuci-security-apply" in files["usr/local/bin/wuci-guide"]
    assert "wuci-source-status" in files["usr/local/bin/wuci-guide"]
    assert "wuci-update" in files["usr/local/bin/wuci-guide"]
    assert "wuci-network-apply" in files["usr/local/bin/wuci-guide"]
    assert "wuci-media-apply" in files["usr/local/bin/wuci-guide"]
    assert "wuci-sdr-apply" in files["usr/local/bin/wuci-guide"]
    assert "wuci-install-target-activate" in files["usr/share/wuci-os/README"]
    assert "auto-install Wuci-OS to disk" in files["usr/share/wuci-os/README"]
    assert "\nINSTALL\n" in files["usr/share/wuci-os/OFFLINE-INSTALL.txt"]
    assert "wuci-install` is kept as a compatibility alias for `INSTALL`" in files["usr/share/wuci-os/OFFLINE-INSTALL.txt"]
    assert "sudo wuci-install-target-activate /mnt" in files["usr/share/wuci-os/OFFLINE-INSTALL.txt"]
    install_script = files["usr/local/bin/INSTALL"]
    assert "required command missing" in install_script
    assert "xbps-install -y -Sy -r \"$target\" $repo_args $required_packages" in install_script
    assert "sudo opendoas bash" in install_script
    assert "sudo doas bash" not in install_script
    assert "grub-x86_64-efi" in install_script
    assert "wuci-install-target-activate \"$target\"" in install_script
    assert "grub-install \"$disk\"" in install_script
    assert "THIS ERASES" in install_script
    # Match the live arch and seed the target's repository config, else
    # xbps-install -r cannot resolve base-system on a fresh musl root.
    assert "export XBPS_ARCH=\"$arch\"" in install_script
    assert "cp -a /usr/share/xbps.d/. \"$target/usr/share/xbps.d/\"" in install_script
    assert "xbps-query -L" in install_script
    # Force reconfiguration so the initramfs/bootloader hooks actually run.
    assert "xbps-reconfigure -fa" in install_script
    # An installed disk must not ship with the live demo's empty passwords.
    assert "Set installed-system account passwords" in install_script
    assert "chroot \"$target\" chpasswd" in install_script
    assert "--empty-passwords" in install_script
    assert "WUCI_INSTALL_PASSWORD" in install_script
    # A failed install must not leave the target mounted.
    assert "trap on_exit EXIT INT TERM" in install_script
    assert "cleanup_mounts" in install_script
    assert "exec INSTALL \"$@\"" in files["usr/local/bin/wuci-install"]
    assert "void-installer" not in files["usr/local/bin/wuci-install"]
    assert "/usr/local/bin/INSTALL /usr/local/bin/wuci-*" in files["usr/local/bin/wuci-install-target-activate"]
    assert "wuci-install-target-activate: complete" in files["usr/local/bin/wuci-install-target-activate"]
    assert "wuci-boot-chime --once" in files["usr/local/bin/wuci-guide"]
    assert "wuci-terminal --print" in files["usr/local/bin/wuci-guide"]
    assert "sudo wj install vim emacs kitty" in files["usr/local/bin/wuci-guide"]
    assert "prepare AI tool setup plan" in files["usr/local/bin/wuci-guide"]
    assert "xbps-install -Sy" in files["usr/local/bin/wj"]
    assert "wuci-network-connect" in files["usr/local/bin/wj"]
    assert "network is not connected" in files["usr/local/bin/wj"]
    assert "os-update|live-update" in files["usr/local/bin/wj"]
    assert "WJ_ALLOW_REMOVE=1" in files["usr/local/bin/wj"]
    assert "Wi-Fi SSID" in files["usr/local/bin/wuci-network-connect"]
    assert "Wuci-OS network setup" in files["usr/local/bin/wuci-network-connect"]
    assert "DHCP probe" in files["usr/local/bin/wuci-network-connect"]
    assert "timeout 12s dhcpcd" in files["usr/local/bin/wuci-network-connect"]
    assert "wpa_supplicant" in files["usr/local/bin/wuci-network-connect"]
    assert "kernel wireless stack missing" in files["usr/local/bin/wuci-network-connect"]
    assert "cfg80211/mac80211" in files["usr/local/bin/wuci-network-connect"]
    assert "$module-unloaded" in files["usr/local/bin/wuci-network-connect"]
    assert "refusing Wi-Fi scan because the kernel cannot provide nl80211" in files["usr/local/bin/wuci-network-connect"]
    assert "NetworkManager reports Wi-Fi unavailable; trying wpa_supplicant fallback" in files["usr/local/bin/wuci-network-connect"]
    assert "NetworkManager scan unavailable; trying wpa_supplicant fallback" in files["usr/local/bin/wuci-network-connect"]
    assert "root-owned setuid" in files["usr/local/bin/wuci-network-connect"]
    assert "hardware snapshot follows" in files["usr/local/bin/wuci-network-connect"]
    assert "depmod -a" in files["usr/local/bin/wuci-network-connect"]
    assert "WUCI_WIFI_SSID" in files["usr/local/bin/wuci-network-connect"]
    assert "enable_service udevd" in files["usr/local/bin/wuci-network-connect"]
    assert "enable_service udevd" in files["usr/local/bin/wuci-network-apply"]
    assert "sudo wuci-network-connect" in files["usr/local/bin/wuci-network-apply"]
    assert "git -C \"$repo\" pull --ff-only origin \"$branch\"" in files["usr/local/bin/wuci-update"]
    # wuci-update prefers the measured, digest-verified overlay sync after a pull.
    assert "wuci-selfupdate --apply --source \"$repo\"" in files["usr/local/bin/wuci-update"]
    assert "xbps-install -Syu" in files["usr/local/bin/wuci-update"]
    assert "wuci-network-connect" in files["usr/local/bin/wuci-update"]
    assert "git clone" in files["usr/local/bin/wuci-update"]
    assert "https://github.com/chasebryan/-wuci-ji.git" in files["usr/local/bin/wuci-update"]
    assert "__TERMINAL_CANDIDATES__" not in files["usr/local/bin/wuci-terminal"]
    assert "kitty ghostty xfce4-terminal xterm" in files["usr/local/bin/wuci-terminal"]
    assert "wave.open" in files["usr/local/bin/wuci-boot-chime"]
    assert "pw-play aplay paplay ffplay mpv play" in files["usr/local/bin/wuci-boot-chime"]
    assert "NetworkManager" in files["usr/local/bin/wuci-network-apply"]
    assert "linux-firmware-network" in files["usr/local/bin/wuci-network-apply"]
    assert "nmcli --ask device wifi connect SSID" in files["usr/local/bin/wuci-network-apply"]
    media_session = files["usr/local/bin/wuci-media-session"]
    assert "prepare_runtime()" in media_session
    assert "runtime_fallback=\"/tmp/wuci-runtime-$uid\"" in media_session
    assert "runtime_owner_matches" in media_session
    assert "pw-cli info 0" in media_session
    assert "pactl info" in media_session
    assert "started_pipewire=1" in media_session
    assert "pipewire" in files["usr/local/bin/wuci-media-apply"]
    assert "mesa-vulkan-radeon" in files["usr/local/bin/wuci-media-apply"]
    assert "xdg-desktop-portal-gtk" in files["usr/local/bin/wuci-media-apply"]
    assert "gnuradio" in files["usr/local/bin/wuci-sdr-apply"]
    assert "rtl-sdr" in files["usr/local/bin/wuci-sdr-apply"]
    assert "hackrf" in files["usr/local/bin/wuci-sdr-apply"]
    assert "SoapySDR" in files["usr/local/bin/wuci-sdr-apply"]
    assert "60-wuci-sdr.rules" in files["usr/local/bin/wuci-sdr-apply"]
    assert "gnuradio-companion" in files["usr/local/bin/wuci-sdr-status"]
    assert "rtl_test" in files["usr/local/bin/wuci-sdr-status"]
    assert "WUCI_GUIDE_ASSUME_YES=1" in files["usr/local/bin/wuci-auto"]
    assert "Daylight/WJSEAL" in files["usr/local/bin/wuci-daylight-status"]
    assert "release seal pending" in files["usr/local/bin/wuci-daylight-status"]
    assert "DAYLIGHT v14C+ ASCENDANT CANDIDATE" in files["usr/local/bin/wuci-daylight-v14c-plus"]
    assert "PYTHONPATH=\"$pkg\"" in files["usr/local/bin/wuci-daylight-v14c-plus"]
    assert "final_score_M" in files["usr/local/bin/wuci-daylight-v14c-plus"]
    assert "wuci-daylight-v14c-plus" in files["usr/local/bin/wuci-guide"]
    # Daylight v15 Meridian live command: evidence-derived score + fail-closed vault.
    meridian = files["usr/local/bin/wuci-daylight-meridian"]
    assert "DAYLIGHT v15 MERIDIAN" in meridian
    assert "/usr/share/wuci-os/daylight/v15-meridian" in meridian
    assert "expected-scorecard.v15-meridian.json" in meridian
    assert "run_cli vault" in meridian
    assert "1,000,000M still requires external attestation" in meridian
    assert "daylight-meridian|meridian|v15)" in files["usr/local/bin/wj"]
    assert "exec wuci-daylight-meridian vault" in files["usr/local/bin/wj"]
    # Live no-reflash updater: git pull + measured overlay sync onto the running root.
    selfupdate = files["usr/local/bin/wuci-selfupdate"]
    assert "live-update" in selfupdate
    assert "git -C \"$src\" pull --ff-only" in selfupdate
    assert "/opt/wuci-os/source/wuci-ji" in selfupdate
    assert "xbps-install -Su" in selfupdate  # honest scope: base packages are separate
    assert "selfupdate)" in files["usr/local/bin/wj"]
    assert "exec wuci-selfupdate" in files["usr/local/bin/wj"]
    assert "wj selfupdate" in files["usr/local/bin/wj"]
    assert "Daylight v15 Meridian package present" in files["usr/local/bin/wuci-daylight-status"]
    assert "daylight-v14c" in files["usr/local/bin/wj"]
    assert "/opt/wuci-os/source/wuci-ji" in files["usr/local/bin/wuci-source-status"]
    assert "/opt/wuci-os/source/upstream" in files["usr/local/bin/wuci-source-status"]
    assert "WJ>_" in files["etc/profile.d/wuci-prompt.sh"]
    assert 'NAME="Wuci-OS"' in files["etc/os-release"]
    assert "ID_LIKE=linux" in files["etc/os-release"]
    assert "current_user\" = \"wj\"" in files["etc/profile.d/wuci-xfce-autostart.sh"]
    assert "exec startx" in files["etc/profile.d/wuci-xfce-autostart.sh"]
    assert not any(path.endswith("wuci-play") for path in files)
    assert "wuci-play" not in "\n".join(files.values())
    assert "grok-build-0.1" in files["usr/local/bin/wuci-grok-build"]
    ai_setup = files["usr/local/bin/wuci-ai-setup"]
    assert "This command is plan-only" in ai_setup
    assert "does not download installer scripts" in ai_setup
    assert "operator-reviewed Codex CLI" in ai_setup
    assert "curl -fsSL" not in ai_setup
    assert "install.sh" not in ai_setup
    assert "gh.io" not in ai_setup
    assert "npm install -g" not in ai_setup
    assert "plan-only" in files["usr/share/wuci-os/ai-tools.txt"]
    assert "remote installers" in files["usr/share/wuci-os/ai-tools.txt"]

    packages = json.loads(files["usr/share/wuci-os/packages.json"])
    assert packages["developer"]["desktop"]["default"] == "terminal-first"
    assert packages["developer"]["desktop"]["desktop_environment"] == "xfce4"
    assert packages["developer"]["desktop"]["preferred_terminal"] == "kitty"
    assert packages["developer"]["desktop"]["fallback_terminal"] == "xfce4-terminal"
    assert packages["developer"]["desktop"]["alternate_terminal"] == "ghostty"
    assert packages["developer"]["desktop"]["terminal_candidates"][0] == "kitty"
    assert "NetworkManager" in packages["developer"]["network"]["packages"]
    assert "wpa_supplicant" in packages["developer"]["network"]["wifi"]
    assert "linux-firmware-network" in packages["developer"]["network"]["firmware"]
    assert "pipewire" in packages["developer"]["audio"]["packages"]
    assert "mesa-dri" in packages["developer"]["video"]["packages"]
    assert "bluez" in packages["developer"]["peripherals"]["packages"]
    assert "gnuradio" in packages["developer"]["sdr"]["core_packages"]
    assert "rtl-sdr" in packages["developer"]["sdr"]["core_packages"]
    assert "sdrangel" in packages["developer"]["sdr"]["optional_packages"]
    assert "NetworkManager" in packages["developer"]["full_suite_packages"]
    assert "pipewire" in packages["developer"]["full_suite_packages"]
    assert "mesa-dri" in packages["developer"]["full_suite_packages"]
    assert "gnuradio" in packages["developer"]["full_suite_packages"]
    assert "ghostty" in packages["developer"]["desktop"]["packages"]
    assert "xterm" in packages["developer"]["desktop"]["packages"]
    assert "ratpoison" in packages["developer"]["desktop"]["packages"]
    assert "vim" in packages["developer"]["editors"]["packages"]
    assert "emacs" in packages["developer"]["editors"]["packages"]
    assert "rust" in packages["developer"]["language_package_groups"]
    assert "go" in packages["developer"]["language_package_groups"]

    security = json.loads(files["usr/share/wuci-os/security-profile.json"])
    assert security["selinux"]["default"] is True
    assert security["selinux"]["mode"] == "enforcing"
    assert security["selinux"]["policy"] == "targeted"
    assert security["priority"] == "security-over-privacy"
    assert security["accounts"]["operator_login"] == "wj"
    assert security["accounts"]["operator_prompt"] == "WJ>_"
    assert "daylight_required_components" in packages
    assert "rust_redesign_components" in packages
    assert "automation_boundary" in packages["developer"]["ai_tools"]["codex"]
    assert "download or execute remote installers" in packages["developer"]["ai_tools"]["codex"]["automation_boundary"]

    overlay_root = tmp / "overlay"
    manifest = wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    assert manifest["schema"] == wuci_os.OVERLAY_SCHEMA
    assert (overlay_root / wuci_os.OVERLAY_WALLPAPER_PATH).is_file()
    assert (overlay_root / "usr/local/bin/wuci-wallpaper").stat().st_mode & 0o111
    manifest_path = overlay_root / "usr/share/wuci-os/overlay-manifest.json"
    assert manifest_path.is_file()
    durable_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert durable_manifest == manifest
    assert manifest["manifest_path"] == "usr/share/wuci-os/overlay-manifest.json"
    assert "usr/share/wuci-os/overlay-manifest.json" in manifest["files"]
    records = wuci_os.overlay_file_records(overlay_root, ticker_mode="never")
    assert [record["path"] for record in records] == manifest["recorded_paths"]
    assert {record["path"] for record in records if record["type"] == "file"} == set(manifest["files"])
    assert manifest["content_records"] == [
        record
        for record in records
        if record["type"] == "file" and record["path"] != manifest["manifest_path"]
    ]
    assert wuci_os.validate_overlay_manifest_current(overlay_root, manifest, ticker_mode="never") == records
    duplicate_paths_manifest = dict(manifest)
    duplicate_paths_manifest["recorded_paths"] = manifest["recorded_paths"] + [manifest["recorded_paths"][0]]
    try:
        wuci_os.validate_overlay_manifest_current(overlay_root, duplicate_paths_manifest, ticker_mode="never")
    except wuci_os.WuciOSError as exc:
        assert "recorded_paths contains duplicate path" in str(exc)
    else:
        raise AssertionError("overlay manifest accepted duplicate recorded_paths")
    duplicate_files_manifest = dict(manifest)
    duplicate_files_manifest["files"] = manifest["files"] + [manifest["files"][0]]
    try:
        wuci_os.validate_overlay_manifest_current(overlay_root, duplicate_files_manifest, ticker_mode="never")
    except wuci_os.WuciOSError as exc:
        assert "files contains duplicate path" in str(exc)
    else:
        raise AssertionError("overlay manifest accepted duplicate files")
    non_string_manifest = dict(manifest)
    non_string_manifest["recorded_paths"] = list(manifest["recorded_paths"])
    non_string_manifest["recorded_paths"][0] = 7
    try:
        wuci_os.validate_overlay_manifest_current(overlay_root, non_string_manifest, ticker_mode="never")
    except wuci_os.WuciOSError as exc:
        assert "recorded_paths entries must be strings" in str(exc)
    else:
        raise AssertionError("overlay manifest accepted non-string recorded_paths")
    records_by_path = {record["path"]: record for record in records}
    script_record = records_by_path["usr/local/bin/wuci-security-apply"]
    assert script_record["mode"] == "0o755"
    assert script_record["digest_vector"] == wuci_os.digest_vector(files["usr/local/bin/wuci-security-apply"].encode("utf-8"))
    config_record = records_by_path["usr/share/wuci-os/packages.json"]
    assert config_record["mode"] == "0o644"
    assert config_record["digest_vector"] == wuci_os.digest_vector(
        (overlay_root / "usr/share/wuci-os/packages.json").read_bytes()
    )
    suite_record = records_by_path["usr/share/wuci-os/full-suite-packages.txt"]
    assert suite_record["digest_vector"] == wuci_os.digest_vector(
        (overlay_root / "usr/share/wuci-os/full-suite-packages.txt").read_bytes()
    )
    assert any(record["path"] == "usr/local/bin/wuci-security-apply" for record in records)
    assert any(record["path"] == "usr/share/wuci-os/daylight/v14c-plus/src/cli.py" for record in records)
    assert manifest["daylight_v14c_execution_package"]["path"] == "usr/share/wuci-os/daylight/v14c-plus"
    assert manifest["daylight_v14c_execution_package"]["command"] == "wuci-daylight-v14c-plus"
    assert manifest["daylight_v14c_execution_package"]["file_count"] > 0
    # Daylight v15 Meridian package is baked alongside v14C+.
    assert any(record["path"] == "usr/share/wuci-os/daylight/v15-meridian/src/cli.py" for record in records)
    assert any(record["path"] == "usr/share/wuci-os/daylight/v15-meridian/src/vault.py" for record in records)
    assert manifest["daylight_v15_meridian_execution_package"]["path"] == "usr/share/wuci-os/daylight/v15-meridian"
    assert manifest["daylight_v15_meridian_execution_package"]["command"] == "wuci-daylight-meridian"
    assert manifest["daylight_v15_meridian_execution_package"]["file_count"] > 0
    assert not any("__pycache__" in record["path"] for record in records)

    for relative in sorted(path for path in files if path.startswith("usr/local/bin/")):
        proc = subprocess.run(
            ["sh", "-n", str(overlay_root / relative)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"{relative}: {proc.stderr}"


def assert_media_session_runtime_fallback(tmp: Path) -> None:
    script = tmp / "wuci-media-session"
    script.write_text(wuci_os.overlay_files()["usr/local/bin/wuci-media-session"], encoding="utf-8")
    script.chmod(0o755)

    fake_bin = tmp / "media-bin"
    fake_bin.mkdir()
    fake_uid = f"424242{os.getpid()}"
    fallback = Path("/tmp") / f"wuci-runtime-{fake_uid}"
    if fallback.exists():
        shutil.rmtree(fallback)

    bad_parent = tmp / "runtime-parent"
    bad_parent.mkdir()
    bad_parent.chmod(0o500)
    bad_runtime = bad_parent / "runtime"

    def fake_command(name: str, body: str) -> None:
        path = fake_bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
        path.chmod(0o755)

    fake_command(
        "id",
        f"""if [ "${{1:-}}" = "-u" ]; then
    printf '{fake_uid}\\n'
else
    exec /usr/bin/id "$@"
fi
""",
    )
    fake_command(
        "pw-cli",
        """if [ -f "$XDG_RUNTIME_DIR/pipewire.started" ]; then
    exit 0
fi
exit 1
""",
    )
    fake_command(
        "pactl",
        """if [ -f "$XDG_RUNTIME_DIR/pulse.started" ]; then
    exit 0
fi
exit 1
""",
    )
    fake_command("pipewire", "printf 'pipewire\\n' >\"$XDG_RUNTIME_DIR/pipewire.started\"\n")
    fake_command("wireplumber", "printf 'wireplumber\\n' >\"$XDG_RUNTIME_DIR/wireplumber.started\"\n")
    fake_command("pipewire-pulse", "printf 'pulse\\n' >\"$XDG_RUNTIME_DIR/pulse.started\"\n")
    fake_command("pgrep", "exit 1\n")
    fake_command("sleep", "exit 0\n")

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["XDG_RUNTIME_DIR"] = str(bad_runtime)
    try:
        proc = subprocess.run(
            ["sh", str(script)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert not bad_runtime.exists()
        assert fallback.is_dir()
        assert oct(fallback.stat().st_mode & 0o777) == "0o700"
        assert (fallback / "pipewire.started").read_text(encoding="utf-8") == "pipewire\n"
        assert (fallback / "wireplumber.started").read_text(encoding="utf-8") == "wireplumber\n"
        assert (fallback / "pulse.started").read_text(encoding="utf-8") == "pulse\n"
    finally:
        bad_parent.chmod(0o700)
        if fallback.exists():
            shutil.rmtree(fallback)


def assert_overlay_force_rebuild(tmp: Path) -> None:
    wallpaper = REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png"
    overlay_root = tmp / "overlay-force"
    first = wuci_os.create_overlay(overlay_root, wallpaper_source=wallpaper, force=True)
    assert first["schema"] == wuci_os.OVERLAY_SCHEMA

    stale_file = overlay_root / "usr/local/bin/wuci-play"
    stale_file.write_text("stale\n", encoding="utf-8")
    stale_file.chmod(0o755)
    stale_dir_file = overlay_root / "var/lib/wuci-os/stale.txt"
    stale_dir_file.parent.mkdir(parents=True)
    stale_dir_file.write_text("stale\n", encoding="utf-8")

    rebuilt = wuci_os.create_overlay(overlay_root, wallpaper_source=wallpaper, force=True)
    assert rebuilt["schema"] == wuci_os.OVERLAY_SCHEMA
    assert not stale_file.exists()
    assert not stale_dir_file.exists()
    records = wuci_os.overlay_file_records(overlay_root, ticker_mode="never")
    paths = {record["path"] for record in records}
    assert "usr/local/bin/wuci-play" not in paths
    assert "var/lib/wuci-os/stale.txt" not in paths

    if hasattr(os, "symlink"):
        symlink_root = tmp / "overlay-stale-symlink"
        symlink_root.mkdir()
        target = tmp / "symlink-target.txt"
        target.write_text("target\n", encoding="utf-8")
        (symlink_root / "stale-link").symlink_to(target)
        try:
            wuci_os.create_overlay(symlink_root, wallpaper_source=wallpaper, force=True)
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("overlay force rebuild accepted a stale symlink")

        root_target = tmp / "overlay-root-target"
        root_target.mkdir()
        root_link = tmp / "overlay-root-link"
        root_link.symlink_to(root_target, target_is_directory=True)
        try:
            wuci_os.create_overlay(root_link, wallpaper_source=wallpaper, force=True)
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("overlay create accepted a symlink root")
        assert not any(root_target.iterdir())

        parent_target = tmp / "overlay-parent-target"
        parent_target.mkdir()
        parent_link = tmp / "overlay-parent-link"
        parent_link.symlink_to(parent_target, target_is_directory=True)
        try:
            wuci_os.create_overlay(parent_link / "overlay", wallpaper_source=wallpaper, force=True)
        except wuci_os.WuciOSError as exc:
            assert "parent must not be a symlink" in str(exc)
        else:
            raise AssertionError("overlay create accepted a symlink output parent")
        assert not (parent_target / "overlay").exists()

        wallpaper_target = tmp / "wallpaper-target.png"
        wallpaper_target.write_bytes(b"not really a png\n")
        wallpaper_link = tmp / "wallpaper-link.png"
        wallpaper_link.symlink_to(wallpaper_target)
        wallpaper_overlay = tmp / "overlay-wallpaper-link"
        try:
            wuci_os.create_overlay(wallpaper_overlay, wallpaper_source=wallpaper_link, force=True)
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("overlay create accepted a symlink wallpaper")
        assert not wallpaper_overlay.exists()

    if hasattr(os, "link"):
        wallpaper_hard_source = tmp / "wallpaper-hard-source.png"
        wallpaper_hard_source.write_bytes(b"not really a png\n")
        wallpaper_hard_link = tmp / "wallpaper-hard-link.png"
        try:
            os.link(wallpaper_hard_source, wallpaper_hard_link)
        except OSError:
            return
        wallpaper_hard_overlay = tmp / "overlay-wallpaper-hard"
        try:
            wuci_os.create_overlay(wallpaper_hard_overlay, wallpaper_source=wallpaper_hard_source, force=True)
        except wuci_os.WuciOSError as exc:
            assert "hardlinked" in str(exc)
        else:
            raise AssertionError("overlay create accepted a hardlinked wallpaper")
        assert not wallpaper_hard_overlay.exists()

        hard_root = tmp / "overlay-stale-hardlink"
        hard_root.mkdir()
        hard_source = hard_root / "hard-source.txt"
        hard_link = hard_root / "hard-link.txt"
        hard_source.write_text("hard\n", encoding="utf-8")
        try:
            os.link(hard_source, hard_link)
        except OSError:
            return
        try:
            wuci_os.create_overlay(hard_root, wallpaper_source=wallpaper, force=True)
        except wuci_os.WuciOSError as exc:
            assert "hardlinked" in str(exc)
        else:
            raise AssertionError("overlay force rebuild accepted a stale hardlink")


def assert_rootfs_overlay_identity_patch(tmp: Path) -> None:
    overlay_root = tmp / "identity-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    rootfs = tmp / "identity-rootfs"
    (rootfs / "etc/runit").mkdir(parents=True)
    (rootfs / "etc/sv/dbus").mkdir(parents=True)
    (rootfs / "etc/sv/NetworkManager").mkdir(parents=True)
    (rootfs / "etc/sv/udevd").mkdir(parents=True)
    (rootfs / "usr/bin").mkdir(parents=True)
    for command in ("sudo", "su", "doas"):
        path = rootfs / "usr/bin" / command
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    (rootfs / "etc").mkdir(exist_ok=True)
    (rootfs / "etc/runit/1").write_text("=> Welcome to Void!\nvoid-live\n", encoding="utf-8")
    (rootfs / "etc/issue").write_text(
        "Welcome to the Void Linux Live system\nroot:voidlinux\nanon:voidlinux\n",
        encoding="utf-8",
    )
    result = wuci_os.apply_wuci_overlay_to_rootfs(overlay_root, rootfs)
    assert result["schema"] == "wuci-os-rootfs-overlay-application-v1"
    assert result["status"] == "pass"
    assert "Welcome to Wuci-OS!" in (rootfs / "etc/runit/1").read_text(encoding="utf-8")
    assert "void-live" not in (rootfs / "etc/runit/1").read_text(encoding="utf-8")
    assert "wuci-os-live" in (rootfs / "etc/runit/core-services/04-wuci-hostname.sh").read_text(encoding="utf-8")
    live_access = (rootfs / "etc/runit/core-services/04-wuci-live-access.sh").read_text(encoding="utf-8")
    assert "90-wuci-os-wj" in live_access
    assert "usermod -aG" in live_access
    issue = (rootfs / "etc/issue").read_text(encoding="utf-8")
    assert "Wuci-OS live profile" in issue
    assert "Void Linux Live" not in issue
    assert (rootfs / "usr/local/bin/wuci-update").is_file()
    assert (rootfs / "usr/local/bin/wuci-terminal").is_file()
    assert (rootfs / "usr/local/bin/wuci-boot-chime").is_file()
    assert (rootfs / "usr/local/bin/wuci-network-apply").is_file()
    assert (rootfs / "usr/local/bin/wuci-network-connect").is_file()
    assert (rootfs / "usr/local/bin/wuci-media-apply").is_file()
    assert (rootfs / "usr/local/bin/wuci-sdr-apply").is_file()
    assert (rootfs / "usr/local/bin/INSTALL").is_file()
    assert (rootfs / "usr/local/bin/wuci-install-target-activate").is_file()
    assert (rootfs / "usr/local/bin/wuci-daylight-v14c-plus").is_file()
    assert (rootfs / "usr/share/wuci-os/OFFLINE-INSTALL.txt").is_file()
    assert (rootfs / "usr/share/wuci-os/WUCI_DAYLIGHT_V8.md").is_file()
    assert (rootfs / "usr/share/wuci-os/WUCI_DAYLIGHT_V9.md").is_file()
    assert (rootfs / "usr/share/wuci-os/WUCI_DAYLIGHT_V10.md").is_file()
    assert (rootfs / "usr/share/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-wire-model.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v8-sheet.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v9-sheet.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v9-spine.svg").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v10-scoreboard.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v13-sovereign-math.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png").is_file()
    assert (rootfs / "usr/share/wuci-os/wuci-daylight-v15-plus-solstice.png").is_file()
    assert (rootfs / "usr/share/wuci-os/daylight/v14c-plus/README.md").is_file()
    assert (rootfs / "usr/share/wuci-os/daylight/v14c-plus/src/cli.py").is_file()
    assert (rootfs / "usr/share/wuci-os/daylight/v14c-plus/rules/weights.v13.json").is_file()
    assert (rootfs / "usr/share/wuci-os/daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json").is_file()
    assert 'NAME="Wuci-OS"' in (rootfs / "etc/os-release").read_text(encoding="utf-8")
    assert "wj:x:" in (rootfs / "etc/passwd").read_text(encoding="utf-8")
    assert "wj_low:x:" in (rootfs / "etc/passwd").read_text(encoding="utf-8")
    assert "Wuci-OS Operator" in (rootfs / "etc/passwd").read_text(encoding="utf-8")
    shadow = (rootfs / "etc/shadow").read_text(encoding="utf-8")
    assert "wj::" in shadow
    assert "wj::0:" not in shadow
    assert "plugdev:" in (rootfs / "etc/group").read_text(encoding="utf-8")
    assert "dialout:" in (rootfs / "etc/group").read_text(encoding="utf-8")
    assert (rootfs / "etc/runit/runsvdir/default/dbus").is_symlink()
    assert (rootfs / "etc/runit/runsvdir/default/NetworkManager").is_symlink()
    assert (rootfs / "etc/runit/runsvdir/default/udevd").is_symlink()
    assert "wj ALL=(ALL:ALL) NOPASSWD: ALL" in (rootfs / "etc/sudoers.d/90-wuci-os-wj").read_text(encoding="utf-8")
    assert "permit nopass wj as root" in (rootfs / "etc/doas.d/90-wuci-os-wj.conf").read_text(encoding="utf-8")
    assert ((rootfs / "usr/bin/sudo").stat().st_mode & 0o4755) == 0o4755
    assert ((rootfs / "usr/bin/su").stat().st_mode & 0o4755) == 0o4755
    assert "chmod 4755 \"$tool\"" in (rootfs / "etc/runit/core-services/04-wuci-live-access.sh").read_text(encoding="utf-8")
    assert "--autologin wj" in (rootfs / "etc/sv/agetty-tty1/conf").read_text(encoding="utf-8")
    assert "--autologin wj" in (rootfs / "etc/sv/agetty-ttyS0/conf").read_text(encoding="utf-8")
    assert (rootfs / "etc/runit/runsvdir/default/agetty-ttyS0").is_symlink()
    assert (rootfs / "home/wj/.xinitrc").is_file()
    assert (rootfs / "home/wj/.config/kitty/kitty.conf").is_file()


def assert_remaster_squashfs_uses_live_safe_options() -> None:
    source = inspect.getsource(wuci_os.remaster_live_rootfs)
    assert '"-comp",' in source
    assert '"xz",' in source
    assert '"-no-xattrs",' in source


def assert_debugfs_safe_path_quotes_firmware_names() -> None:
    path = "usr/lib/firmware/brcm/brcmfmac43241b4-sdio.Intel Corp.-VALLEYVIEW C0 PLATFORM.txt.zst"
    assert wuci_os._debugfs_safe_path(path) == f'"/{path}"'
    assert wuci_os._debugfs_inode_mode_text(0o100000, 0o755) == "0100755"


def assert_debugfs_ext_image_command_surface_preserves_execute_bits(tmp: Path) -> None:
    if shutil.which("mke2fs") is None or shutil.which("debugfs") is None:
        return
    image = tmp / "command-surface.ext4"
    work_root = tmp / "command-surface-debugfs"
    work_root.mkdir()
    build = subprocess.run(
        ["mke2fs", "-q", "-t", "ext4", "-F", str(image), "16M"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        raise AssertionError(build.stderr or build.stdout)
    for relative in wuci_os.LIVE_COMMAND_SURFACE_REQUIRED:
        wuci_os._debugfs_write_text_file(
            image,
            relative,
            "#!/bin/sh\nexit 0\n",
            mode=0o755,
            work_root=work_root,
            label=f"test ext command {relative}",
        )
    stat_record = wuci_os._debugfs_path_stat(image, "usr/local/bin/INSTALL", work_root=work_root)
    assert stat_record["exists"] is True
    assert stat_record["mode"] == "0755"
    assert stat_record["executable"] is True
    command_surface = wuci_os.validate_ext_image_live_command_surface(image, work_root=work_root)
    assert command_surface["status"] == "pass"
    assert command_surface["missing_or_not_executable"] == []
    assert "usr/local/bin/INSTALL" in command_surface["required"]


def make_tiny_extracted_rootfs(rootfs: Path) -> None:
    for directory in (
        "etc/runit",
        "etc/runit/runsvdir/default/udevd",
        "etc/sv/agetty-tty1",
        "etc/sv/dbus",
        "etc/sv/NetworkManager",
        "etc/sv/udevd",
        "usr/bin",
        "usr/lib",
        "usr/lib/firmware",
        "usr/lib/udev/hwdb.d",
        "usr/lib/udev/rules.d",
        "proc",
        "home",
        "root",
        "tmp",
    ):
        (rootfs / directory).mkdir(parents=True, exist_ok=True)
    (rootfs / "bin").symlink_to("usr/bin")
    (rootfs / "sbin").symlink_to("usr/bin")
    (rootfs / "usr/bin/sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (rootfs / "usr/bin/sh").chmod(0o755)
    for command in (
        "sudo",
        "su",
        "doas",
        "sv",
        "depmod",
        "modprobe",
        "lspci",
        "lsusb",
        "udevadm",
        "udevd",
        "dracut",
        "parted",
        "ip",
        "dhcpcd",
        "iw",
        "rfkill",
        "wpa_supplicant",
        "wpa_passphrase",
        "nmcli",
        "NetworkManager",
        "dbus-daemon",
        "xbps-install",
    ):
        (rootfs / "usr/bin" / command).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (rootfs / "usr/bin" / command).chmod(0o755)
    (rootfs / "usr/bin/init").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (rootfs / "usr/bin/init").chmod(0o755)
    (rootfs / "usr/lib/firmware/iwlwifi-5000-5.ucode.zst").write_bytes(b"firmware-fixture\n")
    (rootfs / "usr/lib/firmware/mediatek").mkdir(parents=True, exist_ok=True)
    (rootfs / "usr/lib/firmware/mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin.zst").write_bytes(b"mt7961-patch\n")
    (rootfs / "usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7961_1.bin.zst").write_bytes(b"mt7961-ram\n")
    module_root = rootfs / "usr/lib/modules/6.12.11_1"
    for module in (
        "kernel/net/wireless/cfg80211.ko.zst",
        "kernel/net/mac80211/mac80211.ko.zst",
        "kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko.zst",
        "kernel/drivers/net/wireless/intel/iwlwifi/dvm/iwldvm.ko.zst",
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921u.ko.zst",
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921-common.ko.zst",
        "kernel/drivers/net/wireless/mediatek/mt76/mt76-usb.ko.zst",
        "kernel/drivers/net/wireless/mediatek/mt76/mt76.ko.zst",
        "kernel/drivers/usb/host/xhci-hcd.ko.zst",
        "kernel/drivers/usb/host/ehci-hcd.ko.zst",
        "kernel/drivers/usb/host/uhci-hcd.ko.zst",
    ):
        path = module_root / module
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"module-fixture\n")
    (module_root / "modules.dep").write_text("kernel/net/wireless/cfg80211.ko.zst:\n", encoding="utf-8")
    (module_root / "modules.alias").write_text("alias net-pf-16-proto-16-family-nl80211 cfg80211\n", encoding="utf-8")
    (rootfs / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
    (rootfs / "etc/group").write_text("root:x:0:\nwheel:x:10:root\n", encoding="utf-8")
    (rootfs / "etc/shadow").write_text("root:*:0:0:99999:7:::\n", encoding="utf-8")
    (rootfs / "etc/runit/1").write_text("=> Welcome to Void!\nvoid-live\n", encoding="utf-8")
    (rootfs / "etc/runit/2").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (rootfs / "etc/issue").write_text("Welcome to the Void Linux Live system\n", encoding="utf-8")
    (rootfs / "usr/lib/os-release").write_text('NAME="Void"\nID="void"\n', encoding="utf-8")

    (rootfs / "usr/lib/udev/rules.d/80-drivers.rules").write_text("ACTION==\"add\", RUN+=\"/sbin/modprobe $env{MODALIAS}\"\n", encoding="utf-8")
    (rootfs / "usr/lib/udev/hwdb.d/20-usb-vendor-model.hwdb").write_text("usb:v0000p0000*\n ID_VENDOR_FROM_DATABASE=Wuci fixture\n", encoding="utf-8")
    (rootfs / "usr/lib/udev/rules.d/75-net-description.rules").write_text("SUBSYSTEM==\"net\", ACTION==\"add\"\n", encoding="utf-8")
    for auth_tool in ("usr/bin/sudo", "usr/bin/su", "usr/bin/doas"):
        (rootfs / auth_tool).chmod(0o4755)


def assert_auto_rootfs_source_uses_single_extracted_rootfs(tmp: Path) -> None:
    default_root = tmp / "default-rootfs"
    extracted = default_root / "void-x86_64-musl-ROOTFS-fixture"
    make_tiny_extracted_rootfs(extracted)
    assert wuci_os.auto_rootfs_source(default_root) == extracted
    assert wuci_os.auto_rootfs_source(tmp / "missing-rootfs") is None


def assert_remaster_from_extracted_rootfs_is_wrapped(tmp: Path) -> None:
    if not shutil.which("mksquashfs") or not shutil.which("unsquashfs"):
        return
    try:
        import pycdlib  # type: ignore[import-not-found] # noqa: F401
    except ImportError:
        return
    source_iso = tmp / "tiny-rootfs-source.iso"
    make_tiny_void_iso(source_iso)
    if not source_iso.is_file():
        return
    overlay_root = tmp / "direct-rootfs-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    extracted_rootfs = tmp / "void-rootfs"
    make_tiny_extracted_rootfs(extracted_rootfs)
    result = wuci_os.remaster_live_rootfs(
        source_iso=source_iso,
        overlay_root=overlay_root,
        work_root=tmp / "direct-rootfs-remaster",
        rootfs_source=extracted_rootfs,
        ticker_mode="never",
    )
    assert result["status"] == "pass"
    assert result["rootfs_image_layout"] == "wrapped-rootfs-img"
    assert result["rootfs_source"]["layout"] == "direct-rootfs-tree"
    assert result["minimum_network_package_bootstrap"]["status"] == "already-present"
    assert result["generated_rootfs_image"]["filesystem"] == "ext4"
    ownership = result["generated_rootfs_image"]["ownership_normalization"]
    assert ownership["auth_setuid_required_missing"] == []
    assert "usr/bin/sudo" in ownership["auth_setuid_root_paths"]
    assert "usr/bin/su" in ownership["auth_setuid_root_paths"]
    assert "usr/bin/doas" in ownership["auth_setuid_root_paths"]
    assert result["live_command_surface"]["status"] == "pass"
    assert "usr/bin/wpa_supplicant" in result["live_command_surface"]["required"]
    assert any(
        record["service"] == "agetty-ttyS0" and record["status"] in {"enabled", "already-enabled"}
        for record in result["overlay_application"]["service_enablement"]["services"]
    )
    assert result["depmod_refresh"]["status"] == "pass"
    assert any(record["kernel_release"] == "6.12.11_1" for record in result["depmod_refresh"]["records"])
    assert result["kernel_hardware_surface"]["status"] == "pass"
    assert result["kernel_hardware_surface"]["kernel_release"] == "6.12.11_1"
    assert result["kernel_hardware_surface"]["kernel_package"] == "linux6.12"
    assert result["boot_kernel_selection"]["status"] == "source-iso-kernel"
    assert result["boot_kernel_selection"]["replacement_required"] is False
    assert result["boot_kernel_selection"]["effective_kernel_release"] == "6.12.11_1"
    assert any(
        record["requirement"] == "nl80211-cfg80211" and record["status"] == "pass"
        for record in result["kernel_hardware_surface"]["module_requirements"]
    )
    assert any(
        record["requirement"] == "usb-host-controllers" and record["status"] == "pass"
        for record in result["kernel_hardware_surface"]["module_requirements"]
    )
    remastered = Path(result["remastered_squashfs"]["path"])
    listing = subprocess.run(
        ["unsquashfs", "-ll", str(remastered)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert listing.returncode == 0, listing.stderr
    assert "squashfs-root/LiveOS/rootfs.img" in listing.stdout
    assert "squashfs-root/LiveOS/ext3fs.img" not in listing.stdout


def assert_overlay_tar_safeio(tmp: Path) -> None:
    overlay_root = tmp / "overlay-tar-safe"
    (overlay_root / "usr/local/bin").mkdir(parents=True)
    script = overlay_root / "usr/local/bin/wuci-ok"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    tar_path = tmp / "overlay.tar"
    validation = wuci_os.write_deterministic_overlay_tar(overlay_root, tar_path, ticker_mode="never")
    assert tar_path.is_file()
    assert validation["schema"] == "wuci-os-tar-validation-v1"
    assert validation["status"] == "pass"
    assert validation["regular_files"] == 1
    assert validation["extraction_policy"]["forbidden_paths"]

    if hasattr(os, "symlink"):
        output_target = tmp / "overlay-output-target.tar"
        output_target.write_text("do not overwrite\n", encoding="utf-8")
        output_link = tmp / "overlay-output-link.tar"
        output_link.symlink_to(output_target)
        try:
            wuci_os.write_deterministic_overlay_tar(overlay_root, output_link, ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("overlay tar writer accepted a symlink output path")
        assert output_target.read_text(encoding="utf-8") == "do not overwrite\n"

        output_dir_target = tmp / "overlay-output-dir-target"
        output_dir_target.mkdir()
        output_dir_link = tmp / "overlay-output-dir-link"
        output_dir_link.symlink_to(output_dir_target, target_is_directory=True)
        try:
            wuci_os.write_deterministic_overlay_tar(overlay_root, output_dir_link / "overlay.tar", ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "parent must not be a symlink" in str(exc)
        else:
            raise AssertionError("overlay tar writer accepted a symlink output parent")
        assert not (output_dir_target / "overlay.tar").exists()

    if hasattr(os, "symlink"):
        symlink_root = tmp / "overlay-tar-symlink"
        symlink_root.mkdir()
        target = tmp / "tar-target.txt"
        target.write_text("target\n", encoding="utf-8")
        (symlink_root / "link").symlink_to(target)
        cleanup_tar = tmp / "cleanup.tar"
        try:
            wuci_os.write_deterministic_overlay_tar(symlink_root, cleanup_tar, ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("overlay tar accepted a symlink")
        assert not cleanup_tar.exists()
        assert not any(path.name.startswith(".cleanup.tar.") for path in tmp.iterdir())

    if hasattr(os, "link"):
        hard_root = tmp / "overlay-tar-hardlink"
        hard_root.mkdir()
        hard_source = hard_root / "hard-source.txt"
        hard_link = hard_root / "hard-link.txt"
        hard_source.write_text("hard\n", encoding="utf-8")
        try:
            os.link(hard_source, hard_link)
        except OSError:
            return
        try:
            wuci_os.write_deterministic_overlay_tar(hard_root, tmp / "hardlink.tar", ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "hardlinked" in str(exc)
        else:
            raise AssertionError("overlay tar accepted a hardlink")


def assert_tar_member_policy(tmp: Path) -> None:
    good = tmp / "good.tar"
    with tarfile.open(good, "w", format=tarfile.PAX_FORMAT) as archive:
        directory = tarfile.TarInfo("usr/share/wuci-os")
        directory.mtime = 0
        directory.uid = 0
        directory.gid = 0
        directory.uname = "root"
        directory.gname = "root"
        directory.mode = 0o755
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)

        data = b"ok\n"
        regular = tarfile.TarInfo("usr/share/wuci-os/policy.txt")
        regular.mtime = 0
        regular.uid = 0
        regular.gid = 0
        regular.uname = "root"
        regular.gname = "root"
        regular.mode = 0o644
        regular.type = tarfile.REGTYPE
        regular.size = len(data)
        archive.addfile(regular, io.BytesIO(data))
    validation = wuci_os.validate_tar_member_policy(good, "test good tar")
    assert validation["status"] == "pass"
    assert validation["members"] == 2

    absolute = tmp / "absolute.tar"
    with tarfile.open(absolute, "w", format=tarfile.PAX_FORMAT) as archive:
        data = b"bad\n"
        member = tarfile.TarInfo("/usr/share/wuci-os/bad.txt")
        member.mtime = 0
        member.uid = 0
        member.gid = 0
        member.uname = "root"
        member.gname = "root"
        member.mode = 0o644
        member.type = tarfile.REGTYPE
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    try:
        wuci_os.validate_tar_member_policy(absolute, "test absolute tar")
    except wuci_os.WuciOSError as exc:
        assert "unsafe tar member path" in str(exc)
    else:
        raise AssertionError("tar validation accepted an absolute member path")

    symlink = tmp / "symlink-member.tar"
    with tarfile.open(symlink, "w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("usr/share/wuci-os/link")
        member.mtime = 0
        member.uid = 0
        member.gid = 0
        member.uname = "root"
        member.gname = "root"
        member.mode = 0o777
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    try:
        wuci_os.validate_tar_member_policy(symlink, "test symlink tar")
    except wuci_os.WuciOSError as exc:
        assert "unsupported tar member type" in str(exc)
    else:
        raise AssertionError("tar validation accepted a symlink member")


def assert_daylight_keygen(tmp: Path) -> None:
    keyfile = tmp / "daylight" / "overlay.key"
    result = wuci_os.generate_keyfile(keyfile)
    assert result["schema"] == "wuci-os-daylight-keyfile-v1"
    assert keyfile.stat().st_mode & 0o777 == 0o600
    data = keyfile.read_text(encoding="ascii")
    assert len(data.strip()) == 64
    assert all(char in "0123456789abcdef" for char in data.strip())

    if hasattr(os, "symlink"):
        key_target = tmp / "daylight-key-target"
        key_target.write_text("do not overwrite\n", encoding="ascii")
        key_link = tmp / "daylight-key-link"
        key_link.symlink_to(key_target)
        try:
            wuci_os.generate_keyfile(key_link, force=True)
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("keygen accepted a symlink output path")
        assert key_target.read_text(encoding="ascii") == "do not overwrite\n"

        parent_target = tmp / "daylight-parent-target"
        parent_target.mkdir()
        parent_link = tmp / "daylight-parent-link"
        parent_link.symlink_to(parent_target, target_is_directory=True)
        try:
            wuci_os.generate_keyfile(parent_link / "overlay.key")
        except wuci_os.WuciOSError as exc:
            assert "parent must not be a symlink" in str(exc)
        else:
            raise AssertionError("keygen accepted a symlink output parent")
        assert not (parent_target / "overlay.key").exists()


def assert_daylight_keyfile_safeio(tmp: Path) -> None:
    overlay_root = tmp / "keyfile-overlay"
    overlay_root.mkdir()
    bin_path = Path(sys.executable).resolve()
    keyfile = tmp / "daylight-safeio.key"
    keyfile.write_text(("ab" * 32) + "\n", encoding="ascii")
    assert wuci_os._read_regular_bytes(keyfile, "test keyfile") == (("ab" * 32) + "\n").encode("ascii")

    if hasattr(os, "symlink"):
        seal_target = tmp / "seal-output-target"
        seal_target.mkdir()
        seal_link = tmp / "seal-output-link"
        seal_link.symlink_to(seal_target, target_is_directory=True)
        try:
            wuci_os.seal_overlay(
                overlay_root=overlay_root,
                out_root=seal_link,
                keyfile=keyfile,
                bin_path=bin_path,
                force=True,
                ticker_mode="never",
            )
        except wuci_os.WuciOSError as exc:
            assert "parent must not be a symlink" in str(exc)
        else:
            raise AssertionError("seal-overlay accepted a symlink output parent")
        assert not any(seal_target.iterdir())

        link_key = tmp / "daylight-link.key"
        link_key.symlink_to(keyfile)
        try:
            wuci_os.seal_overlay(
                overlay_root=overlay_root,
                out_root=tmp / "seal-link",
                keyfile=link_key,
                bin_path=bin_path,
                force=True,
                ticker_mode="never",
            )
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("seal-overlay accepted a symlinked keyfile")

    if hasattr(os, "link"):
        hard_key = tmp / "daylight-hard.key"
        try:
            os.link(keyfile, hard_key)
        except OSError:
            return
        try:
            wuci_os.seal_overlay(
                overlay_root=overlay_root,
                out_root=tmp / "seal-hard",
                keyfile=keyfile,
                bin_path=bin_path,
                force=True,
                ticker_mode="never",
            )
        except wuci_os.WuciOSError as exc:
            assert "hardlinked" in str(exc)
        else:
            raise AssertionError("seal-overlay accepted a hardlinked keyfile")


def assert_daylight_seal_rejects_stale_overlay_manifest(tmp: Path) -> None:
    overlay_root = tmp / "seal-stale-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    stale_file = overlay_root / "usr/local/bin/wuci-guide"
    stale_file.write_text(stale_file.read_text(encoding="utf-8") + "\n# stale after manifest\n", encoding="utf-8")
    keyfile = tmp / "seal-stale.key"
    keyfile.write_text(("ef" * 32) + "\n", encoding="ascii")
    out_root = tmp / "seal-stale-out"
    try:
        wuci_os.seal_overlay(
            overlay_root=overlay_root,
            out_root=out_root,
            keyfile=keyfile,
            bin_path=Path(sys.executable).resolve(),
            force=True,
            ticker_mode="never",
        )
    except wuci_os.WuciOSError as exc:
        assert "content_records mismatch" in str(exc)
    else:
        raise AssertionError("seal-overlay accepted a stale overlay manifest")
    assert not out_root.exists()


def assert_daylight_seal_failure_preserves_outputs(tmp: Path) -> None:
    overlay_root = tmp / "seal-failure-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    keyfile = tmp / "seal-failure.key"
    keyfile.write_text(("cd" * 32) + "\n", encoding="ascii")
    fake_bin = tmp / "seal-failure-bin"
    fake_bin.write_text("#!/bin/sh\nexit 1\n", encoding="ascii")
    fake_bin.chmod(0o755)

    out_root = tmp / "seal-failure-out"
    out_root.mkdir()
    sealed = out_root / "wuci-os-overlay.wj"
    manifest = out_root / "manifest.json"
    sealed.write_bytes(b"old sealed artifact\n")
    manifest.write_text('{"old": true}\n', encoding="utf-8")

    try:
        wuci_os.seal_overlay(
            overlay_root=overlay_root,
            out_root=out_root,
            keyfile=keyfile,
            bin_path=fake_bin,
            force=True,
            ticker_mode="never",
        )
    except wuci_os.WuciOSError as exc:
        assert "seal-file-keyfile-v2 failed" in str(exc)
    else:
        raise AssertionError("seal-overlay succeeded with failing seal binary")
    assert sealed.read_bytes() == b"old sealed artifact\n"
    assert manifest.read_text(encoding="utf-8") == '{"old": true}\n'
    assert not any(path.name.startswith(".wuci-os-seal.") for path in out_root.iterdir())


def assert_daylight_seal_manifest_failure_preserves_outputs(tmp: Path) -> None:
    overlay_root = tmp / "seal-manifest-failure-overlay"
    wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    keyfile = tmp / "seal-manifest-failure.key"
    keyfile.write_text(("12" * 32) + "\n", encoding="ascii")
    fake_bin = tmp / "seal-manifest-failure-bin"
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import sys\n"
        "if len(sys.argv) != 6 or sys.argv[1] != 'seal-file-keyfile-v2':\n"
        "    raise SystemExit(17)\n"
        "Path(sys.argv[5]).write_bytes(b'fake sealed overlay\\n' + Path(sys.argv[4]).read_bytes()[:32])\n",
        encoding="ascii",
    )
    fake_bin.chmod(0o755)

    out_root = tmp / "seal-manifest-failure-out"
    out_root.mkdir()
    sealed = out_root / "wuci-os-overlay.wj"
    manifest = out_root / "manifest.json"
    sealed.write_bytes(b"old sealed artifact\n")
    manifest.write_text('{"old": true}\n', encoding="utf-8")
    original_write_json_atomic = wuci_os.wuci_kaiju.write_json_atomic

    def write_then_fail(path: Path, value: dict[str, object]) -> None:
        original_write_json_atomic(path, value)
        if path == manifest:
            raise RuntimeError("fixture seal manifest failure")

    try:
        wuci_os.wuci_kaiju.write_json_atomic = write_then_fail
        wuci_os.seal_overlay(
            overlay_root=overlay_root,
            out_root=out_root,
            keyfile=keyfile,
            bin_path=fake_bin,
            force=True,
            ticker_mode="never",
        )
    except RuntimeError as exc:
        assert "fixture seal manifest failure" in str(exc)
    else:
        raise AssertionError("seal-overlay ignored a seal manifest write failure")
    finally:
        wuci_os.wuci_kaiju.write_json_atomic = original_write_json_atomic
    assert sealed.read_bytes() == b"old sealed artifact\n"
    assert manifest.read_text(encoding="utf-8") == '{"old": true}\n'
    assert not any(path.name.startswith(".wuci-os-seal.") for path in out_root.iterdir())
    assert not any(path.name.startswith(".wuci-os-overlay.wj.old.") for path in out_root.iterdir())
    assert not any(path.name.startswith(".manifest.json.old.") for path in out_root.iterdir())


def assert_failure_specimen_ingest(tmp: Path) -> None:
    iso = tmp / "failed.iso"
    iso.write_bytes(b"failed iso specimen\n")
    boot_log = tmp / "failed-boot.log"
    boot_log.write_text("dracut fatal failed to find root filesystem\n", encoding="utf-8")
    notes = tmp / "failure-notes.json"
    notes.write_text(
        json.dumps(
            {
                "observed_failure": "dracut could not find live rootfs",
                "boot_log": "dracut fatal failed to find root filesystem",
                "qemu_plan": "legacy BIOS serial boot reproducer",
                "target_hardware": "ThinkPad X200s default BIOS",
                "evidence_files": {"boot_log": str(boot_log)},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    result = wuci_os.ingest_failure_specimen(iso, notes, failure_root=tmp / "failures")
    assert result["schema"] == wuci_os.FAILURE_SPECIMEN_SCHEMA
    assert result["status"] == "negative-evidence"
    assert result["claim_effect"]["release_allowed"] is False
    assert "working-iso" in result["claim_effect"]["subtracted_claims"]
    assert result["evidence_files"][0]["label"] == "boot_log"
    manifest = Path(result["manifest_path"])
    assert manifest.is_file()
    persisted = json.loads(manifest.read_text(encoding="utf-8"))
    assert persisted["failed_iso"]["digest_vector"] == result["failed_iso"]["digest_vector"]
    try:
        wuci_os.ingest_failure_specimen(iso, notes, failure_root=tmp / "failures")
    except wuci_os.WuciOSError as exc:
        assert "will not be overwritten" in str(exc)
    else:
        raise AssertionError("failure ingest overwrote an existing negative-evidence specimen")


def assert_source_kit(tmp: Path) -> None:
    out = tmp / "boot" / "wuci-os-source-kit.tar"
    result = wuci_os.write_deterministic_source_kit_tar(out, ticker_mode="never")
    assert result["schema"] == wuci_os.SOURCE_KIT_SCHEMA
    assert result["tar_path"] == str(out)
    assert result["created_utc"] == wuci_os.SOURCE_KIT_DETERMINISTIC_CREATED_UTC
    assert result["timestamp_policy"]["wall_clock_time"].startswith("intentionally omitted")
    assert result["guest_source_root"] == "opt/wuci-os/source/wuci-ji"
    assert result["guest_upstream_source_root"] == "opt/wuci-os/source/upstream"
    assert any(record["path"] == "tools/wuci_os.py" for record in result["files"])
    assert any(record["path"] == "docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md" for record in result["files"])
    assert any(record["path"] == "docs/WUCI_DAYLIGHT_V8.md" for record in result["files"])
    assert any(record["path"] == "docs/WUCI_DAYLIGHT_V9.md" for record in result["files"])
    assert any(record["path"] == "docs/WUCI_DAYLIGHT_V10.md" for record in result["files"])
    assert any(record["path"] == "docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-wire-model.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v8-sheet.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v9-sheet.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v9-spine.svg" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v10-scoreboard.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v13-sovereign-math.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png" for record in result["files"])
    assert any(record["path"] == "docs/wuci-os/assets/wuci-daylight-v15-plus-solstice.png" for record in result["files"])
    assert any(record["path"] == "daylight/v14c-plus/README.md" for record in result["files"])
    assert any(record["path"] == "daylight/v14c-plus/src/scoring.py" for record in result["files"])
    assert any(record["path"] == "daylight/v14c-plus/rules/weights.v13.json" for record in result["files"])
    assert result["extraction_policy"]["schema"] == "wuci-os-tar-extraction-policy-v1"
    assert result["tar_validation"]["status"] == "pass"
    assert result["tar_validation"]["members"] >= len(result["files"])
    assert result["source_kit_validation"]["status"] == "pass"
    assert result["source_kit_validation"]["tar_validation"]["status"] == "pass"

    with tarfile.open(out, "r") as archive:
        names = archive.getnames()
        manifest_handle = archive.extractfile("usr/share/wuci-os/source-kit.json")
        assert manifest_handle is not None
        archived_manifest = json.loads(manifest_handle.read().decode("utf-8"))
    assert "opt/wuci-os/source/wuci-ji/tools/wuci_os.py" in names
    assert "opt/wuci-os/source/wuci-ji/docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md" in names
    assert "opt/wuci-os/source/wuci-ji/docs/WUCI_DAYLIGHT_V8.md" in names
    assert "opt/wuci-os/source/wuci-ji/docs/WUCI_DAYLIGHT_V9.md" in names
    assert "opt/wuci-os/source/wuci-ji/docs/WUCI_DAYLIGHT_V10.md" in names
    assert "opt/wuci-os/source/wuci-ji/docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-wire-model.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v8-sheet.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v9-sheet.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v9-spine.svg" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v10-scoreboard.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v13-sovereign-math.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png" in names
    assert "opt/wuci-os/source/wuci-ji/docs/wuci-os/assets/wuci-daylight-v15-plus-solstice.png" in names
    assert "opt/wuci-os/source/wuci-ji/daylight/v14c-plus/README.md" in names
    assert "opt/wuci-os/source/wuci-ji/daylight/v14c-plus/src/scoring.py" in names
    assert "opt/wuci-os/source/wuci-ji/daylight/v14c-plus/rules/weights.v13.json" in names
    assert "usr/share/wuci-os/source-kit.json" in names
    assert "opt/wuci-os/source/wuci-ji/.wuci-os-source-kit.json" in names
    assert archived_manifest["created_utc"] == wuci_os.SOURCE_KIT_DETERMINISTIC_CREATED_UTC
    assert archived_manifest["timestamp_policy"] == result["timestamp_policy"]
    assert result["source_kit_validation"]["manifest_digest_vector"] == wuci_os.digest_vector(
        wuci_os.canonical_json_bytes(archived_manifest) + b"\n"
    )
    if (REPO / "build" / "wuci-os" / "upstream" / "void-mklive").is_dir():
        assert any(name.startswith("opt/wuci-os/source/upstream/void-mklive/") for name in names)

    repeat_out = tmp / "boot" / "wuci-os-source-kit-repeat.tar"
    repeat = wuci_os.write_deterministic_source_kit_tar(repeat_out, ticker_mode="never")
    assert repeat["created_utc"] == result["created_utc"]
    assert repeat["tar_bytes"] == result["tar_bytes"]
    assert repeat["tar_digest_vector"] == result["tar_digest_vector"]
    assert repeat_out.read_bytes() == out.read_bytes()

    if hasattr(os, "symlink"):
        output_target = tmp / "source-kit-target.tar"
        output_target.write_text("do not overwrite\n", encoding="utf-8")
        output_link = tmp / "source-kit-link.tar"
        output_link.symlink_to(output_target)
        try:
            wuci_os.write_deterministic_source_kit_tar(output_link, ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("source-kit writer accepted a symlink output path")
        assert output_target.read_text(encoding="utf-8") == "do not overwrite\n"


def assert_source_kit_avoids_output_self_capture(tmp: Path) -> None:
    fake_repo = tmp / "source-kit-fake-repo"
    fake_repo.mkdir()
    (fake_repo / "README.md").write_text("fake Wuci source\n", encoding="utf-8")
    out = fake_repo / "dist" / "wuci-os-source-kit.tar"
    original_repo_root = wuci_os.repo_root
    try:
        wuci_os.repo_root = lambda: fake_repo
        result = wuci_os.write_deterministic_source_kit_tar(out, ticker_mode="never")
    finally:
        wuci_os.repo_root = original_repo_root

    assert out.is_file()
    assert [record["path"] for record in result["files"]] == ["README.md"]
    with tarfile.open(out, "r") as archive:
        names = archive.getnames()
    assert "opt/wuci-os/source/wuci-ji/README.md" in names
    assert not any(name.startswith("opt/wuci-os/source/wuci-ji/dist/") for name in names)
    assert not any(".wuci-os-source-kit.tar." in name for name in names)


def assert_source_kit_rejects_stale_output_temp(tmp: Path) -> None:
    fake_repo = tmp / "source-kit-stale-temp-repo"
    fake_repo.mkdir()
    (fake_repo / "README.md").write_text("fake Wuci source\n", encoding="utf-8")
    dist = fake_repo / "dist"
    dist.mkdir()
    stale = dist / ".wuci-os-source-kit.tar.stale.tmp"
    stale.write_bytes(b"stale generated source-kit temp\n")
    out = dist / "wuci-os-source-kit.tar"
    original_repo_root = wuci_os.repo_root
    try:
        wuci_os.repo_root = lambda: fake_repo
        try:
            wuci_os.write_deterministic_source_kit_tar(out, ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "temporary output artifact must not be part of source evidence" in str(exc)
        else:
            raise AssertionError("source-kit accepted a stale output temp artifact")
    finally:
        wuci_os.repo_root = original_repo_root

    assert stale.read_bytes() == b"stale generated source-kit temp\n"
    assert not out.exists()


def assert_source_kit_rejects_changed_member_after_record(tmp: Path) -> None:
    fake_repo = tmp / "source-kit-change-after-record-repo"
    fake_repo.mkdir()
    readme = fake_repo / "README.md"
    readme.write_text("abcdef\n", encoding="utf-8")
    out = fake_repo / "wuci-os-source-kit.tar"
    original_repo_root = wuci_os.repo_root
    original_source_kit_records = wuci_os.source_kit_records

    def changing_records(*, ticker_mode: str = "auto", reserved_output_rel: Path | None = None) -> list[dict[str, object]]:
        records = original_source_kit_records(
            ticker_mode=ticker_mode,
            reserved_output_rel=reserved_output_rel,
        )
        readme.write_text("ABCDEF\n", encoding="utf-8")
        return records

    try:
        wuci_os.repo_root = lambda: fake_repo
        wuci_os.source_kit_records = changing_records
        try:
            wuci_os.write_deterministic_source_kit_tar(out, ticker_mode="never")
        except wuci_os.WuciOSError as exc:
            assert "member digest mismatch" in str(exc)
        else:
            raise AssertionError("source-kit accepted a file changed after record digesting")
    finally:
        wuci_os.source_kit_records = original_source_kit_records
        wuci_os.repo_root = original_repo_root

    assert not out.exists()
    assert readme.read_text(encoding="utf-8") == "ABCDEF\n"


def assert_iso_plan(tmp: Path) -> None:
    source_root = tmp / "iso-source"
    source_root.mkdir()
    image = source_root / "wuci-source.iso"
    image.write_bytes(b"wuci iso fixture")
    iso_layout = layout_fixture()
    wuci_os.wuci_kaiju.write_json_atomic(
        wuci_os.source_manifest_path(source_root),
        {
            "schema": wuci_os.SOURCE_SCHEMA,
            "created_utc": "2026-06-29T00:00:00Z",
            "product": wuci_os.PRODUCT_NAME,
            "image_id": wuci_os.IMAGE_ID,
            "base": source_base_fixture(image.name),
            "operator_supplied": True,
            "image_name": image.name,
            "image_path": str(image),
            "image_bytes": image.stat().st_size,
            "digest_vector": wuci_os.wuci_kaiju.file_digest_vector(image, "fixture")[0],
            "layout": iso_layout,
            "boundary_denials": list(wuci_os.BOUNDARY_DENIALS),
        },
    )
    original_inspect = wuci_os.inspect_void_iso
    try:
        wuci_os.inspect_void_iso = lambda _path: iso_layout
        plan = wuci_os.finished_iso_plan(source_root)
    finally:
        wuci_os.inspect_void_iso = original_inspect
    assert plan["schema"] == wuci_os.ISO_PLAN_SCHEMA
    assert plan["status"] == "ready-for-build-lane"
    assert any(output.endswith(".iso") for output in plan["required_outputs"])
    assert "Wuci-OS" in plan["goal"]
    assert any(phase["automation"] == "tools/wuci-os final-iso" for phase in plan["build_phases"])
    assert any(component["component"] == "wuci-os-guide" for component in wuci_os.RUST_REDESIGN_COMPONENTS)
    commands = wuci_os.demo_command_text()
    assert "6. tools/wuci-os final-iso --force --remaster-rootfs --install-suite-packages" in commands
    assert "11. wuci-live-banner" in commands
    assert "13. wuci-source-status" in commands
    assert "14. wuci-guide" in commands
    assert "15. sudo wj install vim emacs kitty" in commands
    assert "&& break" not in commands
    assert "wuci-play" not in commands


def make_tiny_void_iso(path: Path) -> None:
    try:
        import pycdlib  # type: ignore[import-not-found]
    except ImportError:
        return
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", joliet=3, vol_ident="VOID_LIVE")
    iso.add_directory("/BOOT", rr_name="boot", joliet_path="/boot")
    iso.add_directory("/BOOT/ISOLINUX", rr_name="isolinux", joliet_path="/boot/isolinux")
    iso.add_directory("/BOOT/GRUB", rr_name="grub", joliet_path="/boot/grub")
    iso.add_directory("/LIVEOS", rr_name="LiveOS", joliet_path="/LiveOS")
    for data, iso_path, rr_name, joliet_path in (
        (
            b"6.12.11_1 (voidlinux@voidlinux) #1 SMP PREEMPT_DYNAMIC Fri Jan 24 14:02:23 UTC 2025\n",
            "/BOOT/VMLINUZ.;1",
            "vmlinuz",
            "/boot/vmlinuz",
        ),
        (b"initrd\n", "/BOOT/INITRD.;1", "initrd", "/boot/initrd"),
        (b"squashfs\n", "/LIVEOS/SQUASHFS.IMG;1", "squashfs.img", "/LiveOS/squashfs.img"),
        (ISOLINUX.encode("utf-8"), "/BOOT/ISOLINUX/ISOLINUX.CFG;1", "isolinux.cfg", "/boot/isolinux/isolinux.cfg"),
        (b"source /boot/grub/grub_void.cfg\n", "/BOOT/GRUB/GRUB.CFG;1", "grub.cfg", "/boot/grub/grub.cfg"),
        (
            b"menuentry 'Void Linux' {\n linux /boot/vmlinuz \\\n  root=live:CDLABEL=VOID_LIVE ro init=/sbin/init \\\n}\n",
            "/BOOT/GRUB/GRUBVOID.CFG;1",
            "grub_void.cfg",
            "/boot/grub/grub_void.cfg",
        ),
        (b"boot image\n" * 256, "/BOOT/ISOLINUX/ISOLINUX.BIN;1", "isolinux.bin", "/boot/isolinux/isolinux.bin"),
    ):
        iso.add_fp(io.BytesIO(data), len(data), iso_path=iso_path, rr_name=rr_name, joliet_path=joliet_path)
    iso.add_eltorito("/BOOT/ISOLINUX/ISOLINUX.BIN;1", bootcatfile="/BOOT.CAT;1", boot_load_size=4)
    iso.write(str(path))
    iso.close()


def assert_final_iso_payload_builder(tmp: Path) -> None:
    try:
        import pycdlib  # type: ignore[import-not-found]
    except ImportError:
        return
    source_root = tmp / "final-iso-source"
    source_root.mkdir()
    source_iso = source_root / "void-live-x86_64-musl-20250202-base.iso"
    make_tiny_void_iso(source_iso)
    if not source_iso.is_file():
        return
    layout = wuci_os.inspect_void_iso(source_iso)
    assert layout["status"] == "pass"
    digest, size = wuci_os.wuci_kaiju.file_digest_vector(source_iso, "tiny source ISO")
    wuci_os.wuci_kaiju.write_json_atomic(
        wuci_os.source_manifest_path(source_root),
        {
            "schema": wuci_os.SOURCE_SCHEMA,
            "created_utc": "2026-06-29T00:00:00Z",
            "product": wuci_os.PRODUCT_NAME,
            "image_id": wuci_os.IMAGE_ID,
            "base": source_base_fixture(source_iso.name),
            "operator_supplied": True,
            "image_name": source_iso.name,
            "image_path": str(source_iso),
            "image_bytes": size,
            "digest_vector": digest,
            "layout": layout,
            "boundary_denials": list(wuci_os.BOUNDARY_DENIALS),
        },
    )

    original_create_overlay = wuci_os.create_overlay
    original_seal_overlay = wuci_os.seal_overlay
    original_source_kit = wuci_os.write_deterministic_source_kit_tar
    original_overlay_tar = wuci_os.write_deterministic_overlay_tar
    try:
        wuci_os.create_overlay = lambda overlay_root=None, **_kwargs: {
            "schema": wuci_os.OVERLAY_SCHEMA,
            "overlay_root": str(overlay_root),
            "files": [],
        }

        def fake_seal_overlay(**kwargs: object) -> dict[str, object]:
            out_root = Path(str(kwargs["out_root"]))
            out_root.mkdir(parents=True, exist_ok=True)
            artifact = out_root / "wuci-os-overlay.wj"
            artifact.write_bytes(b"sealed overlay\n")
            digest, artifact_size = wuci_os.wuci_kaiju.file_digest_vector(artifact, "fake sealed overlay")
            return {
                "schema": wuci_os.OVERLAY_SEAL_SCHEMA,
                "sealed_artifact": {
                    "path": str(artifact),
                    "bytes": artifact_size,
                    "digest_vector": digest,
                },
            }

        def fake_source_kit(path: Path, **_kwargs: object) -> dict[str, object]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"source kit\n")
            digest, kit_size = wuci_os.wuci_kaiju.file_digest_vector(path, "fake source kit")
            return {
                "tar_path": str(path),
                "tar_bytes": kit_size,
                "tar_digest_vector": digest,
                "source_kit_validation": {"status": "pass"},
            }

        def fake_overlay_tar(_overlay_root: Path, path: Path, **_kwargs: object) -> dict[str, object]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"overlay tar\n")
            return {"status": "pass"}

        wuci_os.seal_overlay = fake_seal_overlay
        wuci_os.write_deterministic_source_kit_tar = fake_source_kit
        wuci_os.write_deterministic_overlay_tar = fake_overlay_tar
        result = wuci_os.build_final_iso(
            source_root=source_root,
            overlay_root=tmp / "overlay",
            seal_root=tmp / "daylight",
            final_root=tmp / "final",
            keyfile=tmp / "daylight" / "wuci-os-overlay.key",
            bin_path=tmp / "fake-wuci-ji",
            force=True,
            ticker_mode="never",
        )
    finally:
        wuci_os.create_overlay = original_create_overlay
        wuci_os.seal_overlay = original_seal_overlay
        wuci_os.write_deterministic_source_kit_tar = original_source_kit
        wuci_os.write_deterministic_overlay_tar = original_overlay_tar

    assert result["schema"] == wuci_os.FINAL_ISO_SCHEMA
    assert result["status"] == "built"
    assert result["validation"]["status"] == "pass"
    assert result["payload_policy"]["rootfs_squashfs_rebuilt"] is False
    assert result["payload_policy"]["boot_menu_rewritten"] is True
    assert result["payload_policy"]["boot_splash_embedded"] is True
    assert result["release_gate"]["release_allowed"] is False
    assert result["release_gate"]["model"] == "docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md"
    assert "package-closure-fixed-point-missing" in result["release_gate"]["blockers"]
    # Every active blocker must carry an actionable, documented requirement, and the
    # self-documenting checklist must never flip release_allowed on its own.
    assert result["release_gate"]["release_runbook"] == "docs/WUCI_OS_RELEASE_RUNBOOK.md"
    requirements = result["release_gate"]["blocker_requirements"]
    assert set(requirements) == set(result["release_gate"]["blockers"])
    assert all(isinstance(text, str) and text for text in requirements.values())
    assert "hardware-boot-trace-missing" in requirements
    assert result["substract_substrate_model"]["formal_model_path"] == "docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md"
    assert result["substract_substrate_model"]["daylight_v8_model_path"] == "docs/WUCI_DAYLIGHT_V8.md"
    assert result["substract_substrate_model"]["daylight_v9_model_path"] == "docs/WUCI_DAYLIGHT_V9.md"
    assert result["substract_substrate_model"]["daylight_v10_model_path"] == "docs/WUCI_DAYLIGHT_V10.md"
    assert result["substract_substrate_model"]["daylight_v13_model_path"] == "docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md"
    assert result["substract_substrate_model"]["diagram_path"] == "docs/wuci-os/assets/wuci-daylight-wire-model.png"
    assert result["substract_substrate_model"]["daylight_v8_diagram_path"] == "docs/wuci-os/assets/wuci-daylight-v8-sheet.png"
    assert result["substract_substrate_model"]["daylight_v9_sheet_path"] == "docs/wuci-os/assets/wuci-daylight-v9-sheet.png"
    assert result["substract_substrate_model"]["daylight_v9_diagram_path"] == "docs/wuci-os/assets/wuci-daylight-v9-spine.svg"
    assert result["substract_substrate_model"]["daylight_v10_scoreboard_path"] == "docs/wuci-os/assets/wuci-daylight-v10-scoreboard.png"
    assert result["substract_substrate_model"]["daylight_v13_math_path"] == "docs/wuci-os/assets/wuci-daylight-v13-sovereign-math.png"
    assert result["substract_substrate_model"]["daylight_v14c_image_path"] == "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png"
    assert result["substract_substrate_model"]["daylight_v14c_math_path"] == "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png"
    assert result["substract_substrate_model"]["daylight_v14c_wide_path"] == "docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png"
    assert result["substract_substrate_model"]["daylight_v15_solstice_path"] == "docs/wuci-os/assets/wuci-daylight-v15-plus-solstice.png"
    assert "boot/grub/grub.cfg" in result["payload_policy"]["grub_entries_rewritten"]
    assert result["rootfs_remaster"]["status"] == "not-requested"
    assert "wuci-update" in result["self_host_payloads"]["update_command"]
    assert "wuci-terminal" in result["self_host_payloads"]["terminal_resolver"]
    assert "OFFLINE-INSTALL.txt" in result["self_host_payloads"]["offline_install_guide"]
    assert result["boot_splash"]["source_path"].endswith("wuci-os-boot-splash.svg")
    assert result["boot_splash"]["render_method"] in {"embedded-svg-png", "rsvg-convert", "magick", "convert"}
    assert Path(result["boot_splash"]["rendered_path"]).is_file()
    final_iso = Path(result["iso"]["path"])
    assert final_iso.is_file()
    boot_menu = wuci_os._extract_iso_text(final_iso, "boot/isolinux/isolinux.cfg")
    assert "Wuci-Ji Systems / Wuci-OS live" in boot_menu
    assert "wuci-splash.png" in boot_menu
    assert "console=tty0" in boot_menu
    assert "rd.driver.pre=loop" in boot_menu
    assert "rd.auto=0" not in boot_menu
    assert "rd.lvm=0" not in boot_menu
    assert "modprobe.blacklist=" not in boot_menu
    assert "Void Linux" not in boot_menu
    grub_menu = wuci_os._extract_iso_text(final_iso, "boot/grub/grub.cfg")
    assert "background_image /boot/grub/wuci-splash.png" in grub_menu
    assert "Void Linux" not in grub_menu
    grub_void_menu = wuci_os._extract_iso_text(final_iso, "boot/grub/grub_void.cfg")
    assert "Wuci-Ji Systems / Wuci-OS live" in grub_void_menu
    assert "console=tty0" in grub_void_menu
    assert "rd.driver.pre=loop" in grub_void_menu
    assert "live.hostname=wuci-os-live" in grub_void_menu
    assert "Void Linux" not in grub_void_menu
    for subpath in (
        "wuci-os/manifest.json",
        "wuci-os/wuci-os-overlay.tar",
        f"wuci-os/{wuci_os.SOURCE_KIT_TAR_NAME}",
        "wuci-os/rootfs-manifest.json",
        "wuci-os/OFFLINE-INSTALL.txt",
        "wuci-os/WUCI_DAYLIGHT_V8.md",
        "wuci-os/WUCI_DAYLIGHT_V9.md",
        "wuci-os/WUCI_DAYLIGHT_V10.md",
        "wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
        "wuci-os/wuci-daylight-wire-model.png",
        "wuci-os/wuci-daylight-v8-sheet.png",
        "wuci-os/wuci-daylight-v9-sheet.png",
        "wuci-os/wuci-daylight-v9-spine.svg",
        "wuci-os/wuci-daylight-v10-scoreboard.png",
        "wuci-os/wuci-daylight-v13-sovereign-math.png",
        "wuci-os/wuci-daylight-v14c-plus-ascendant.png",
        "wuci-os/wuci-daylight-v14c-plus-ascendant-math.png",
        "wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png",
        "wuci-os/wuci-daylight-v15-plus-solstice.png",
        "wuci-os/boot-splash.svg",
        "boot/isolinux/wuci-splash.png",
        "boot/grub/wuci-splash.png",
    ):
        assert wuci_os._extract_iso_bytes(final_iso, subpath, subpath)


def assert_cli(tmp: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "tools" / "wuci_os.py"),
            "source",
            "--source-root",
            str(tmp / "missing"),
            "status",
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "schema: wuci-os-source-status-v1" in proc.stdout

    plan = subprocess.run(
        [
            sys.executable,
            str(REPO / "tools" / "wuci_os.py"),
            "plan",
            "--source-root",
            str(tmp / "missing"),
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert plan.returncode == 1
    payload = json.loads(plan.stdout)
    assert payload["schema"] == wuci_os.BUILD_PLAN_SCHEMA
    assert payload["status"] == "blocked"


def assert_live_update(tmp: Path) -> None:
    target = tmp / "live-root"
    (target / "usr").mkdir(parents=True)

    preview = wuci_os.live_update_system(target_root=target, apply=False, ticker_mode="never")
    assert preview["schema"] == wuci_os.LIVE_UPDATE_SCHEMA
    assert preview["mode"] == "preview"
    assert preview["counts"]["files"] > 0
    # An empty root means every presented file is an add, and nothing is written yet.
    assert preview["counts"]["add"] == preview["counts"]["files"]
    assert preview["counts"]["applied"] == 0
    assert not (target / "usr/local/bin/wj").exists()
    # The build-only overlay manifest is never synced onto a live system.
    assert preview["counts"]["skipped_metadata"] >= 1
    assert all(c["path"] != "usr/share/wuci-os/overlay-manifest.json" for c in preview["changes"])

    applied = wuci_os.live_update_system(target_root=target, apply=True, ticker_mode="never")
    assert applied["mode"] == "applied"
    assert applied["counts"]["applied"] == applied["counts"]["files"]
    # Every written file is re-read and verified by digest (fail-closed otherwise).
    assert applied["counts"]["verified"] == applied["counts"]["applied"]
    wj = target / "usr/local/bin/wj"
    assert wj.is_file()
    assert os.access(wj, os.X_OK)
    assert not (target / "usr/share/wuci-os/overlay-manifest.json").exists()

    # A second apply is a true no-op: timestamp-only churn is normalized away.
    again = wuci_os.live_update_system(target_root=target, apply=True, ticker_mode="never")
    assert again["counts"]["add"] == 0
    assert again["counts"]["update"] == 0
    assert again["counts"]["applied"] == 0
    assert again["counts"]["unchanged"] == again["counts"]["files"]

    # A functional change on disk is detected and re-synced back to the presented bytes.
    presented = wj.read_bytes()
    wj.write_bytes(b"#!/bin/sh\necho tampered\n")
    drift = wuci_os.live_update_system(target_root=target, apply=False, ticker_mode="never")
    assert any(c["path"] == "usr/local/bin/wj" and c["status"] == "update" for c in drift["changes"])
    wuci_os.live_update_system(target_root=target, apply=True, ticker_mode="never")
    assert wj.read_bytes() == presented


def main() -> int:
    parser_quiet = "--quiet" in sys.argv
    with tempfile.TemporaryDirectory(prefix="wuci-os-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_core_policy()
        assert_append_parsing()
        assert_missing_source(tmp)
        assert_bad_source_rejected(tmp)
        assert_rollback_backup_detects_changed_file(tmp)
        assert_source_install_safeio(tmp)
        assert_source_verify_manifest_bounds(tmp)
        assert_boot_plan_ready(tmp)
        assert_boot_share_rejects_stale_overlay_manifest(tmp)
        assert_boot_payload_failure_cleans_partial_artifacts(tmp)
        assert_boot_payload_cleanup_reports_tampered_artifact(tmp)
        assert_boot_cleanup_safeio(tmp)
        assert_overlay_profile(tmp)
        assert_live_update(tmp)
        assert_media_session_runtime_fallback(tmp)
        assert_overlay_force_rebuild(tmp)
        assert_rootfs_overlay_identity_patch(tmp)
        assert_remaster_squashfs_uses_live_safe_options()
        assert_debugfs_safe_path_quotes_firmware_names()
        assert_debugfs_ext_image_command_surface_preserves_execute_bits(tmp)
        assert_auto_rootfs_source_uses_single_extracted_rootfs(tmp)
        assert_remaster_from_extracted_rootfs_is_wrapped(tmp)
        assert_overlay_tar_safeio(tmp)
        assert_tar_member_policy(tmp)
        assert_daylight_keygen(tmp)
        assert_daylight_keyfile_safeio(tmp)
        assert_daylight_seal_rejects_stale_overlay_manifest(tmp)
        assert_daylight_seal_failure_preserves_outputs(tmp)
        assert_daylight_seal_manifest_failure_preserves_outputs(tmp)
        assert_failure_specimen_ingest(tmp)
        assert_source_kit(tmp)
        assert_source_kit_avoids_output_self_capture(tmp)
        assert_source_kit_rejects_stale_output_temp(tmp)
        assert_source_kit_rejects_changed_member_after_record(tmp)
        assert_iso_plan(tmp)
        assert_final_iso_payload_builder(tmp)
        assert_cli(tmp)
    if not parser_quiet:
        print("wuci-os tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
