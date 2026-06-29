#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
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


def assert_core_policy() -> None:
    assert wuci_os.PRODUCT_NAME == "Wuci-OS"
    assert wuci_os.IMAGE_ID == "wuci-os"
    assert "runtime sandboxing" in " ".join(wuci_os.BOUNDARY_DENIALS)
    assert "offensive scanning" in " ".join(wuci_os.BOUNDARY_DENIALS)
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
    assert "nomodeset" in serial
    assert serial.count("console=ttyS0,115200n8") == 1


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


def assert_boot_plan_ready(tmp: Path) -> None:
    source_root = tmp / "source"
    source_root.mkdir()
    image = source_root / "void.iso"
    image.write_bytes(b"void iso fixture")
    wuci_os.wuci_kaiju.write_json_atomic(
        wuci_os.source_manifest_path(source_root),
        {
            "schema": wuci_os.SOURCE_SCHEMA,
            "created_utc": "2026-06-29T00:00:00Z",
            "product": wuci_os.PRODUCT_NAME,
            "image_id": wuci_os.IMAGE_ID,
            "image_path": str(image),
            "image_bytes": image.stat().st_size,
            "digest_vector": wuci_os.wuci_kaiju.file_digest_vector(image, "fixture")[0],
            "boundary_denials": list(wuci_os.BOUNDARY_DENIALS),
        },
    )

    original_inspect = wuci_os.inspect_void_iso
    try:
        wuci_os.inspect_void_iso = lambda _path: {
            "schema": "wuci-os-void-musl-layout-v1",
            "status": "pass",
            "label": "VOID_LIVE",
            "append": wuci_os.first_isolinux_append(ISOLINUX),
            "problems": [],
        }
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
    assert "pc,accel=tcg" in plan["argv"]
    assert "max" in plan["argv"]
    assert "console=ttyS0,115200n8" in plan["append"]
    assert any("user,model=virtio-net-pci" == item for item in plan["argv"])
    assert share_plan["status"] == "ready", share_plan
    assert share_plan["share_mode"] == "tar-drive"
    assert any(str(item).endswith("wuci-os-overlay.tar,format=raw,if=virtio,readonly=on") for item in share_plan["argv"])
    assert any(str(item).endswith("wuci-os-source-kit.tar,format=raw,if=virtio,readonly=on") for item in share_plan["argv"])
    assert share_plan["source_kit_path"].endswith("wuci-os-source-kit.tar")
    assert "tar -xf" in share_plan["guest_extract_hint"]
    assert "&& break" not in share_plan["guest_extract_hint"]


def assert_overlay_profile(tmp: Path) -> None:
    files = wuci_os.overlay_files()
    required = {
        "usr/local/bin/wuci-wallpaper",
        "usr/local/bin/wuci-wait-run",
        "usr/local/bin/wuci-attest",
        "usr/local/bin/wuci-live-banner",
        "usr/local/bin/wuci-source-status",
        "usr/local/bin/wuci-enter",
        "usr/local/bin/wuci-guide",
        "usr/local/bin/wuci-auto",
        "usr/local/bin/wuci-daylight-status",
        "usr/local/bin/wj",
        "usr/local/bin/wuci-users-apply",
        "usr/local/bin/wuci-users-status",
        "usr/local/bin/wuci-dev-install",
        "usr/local/bin/wuci-security-apply",
        "usr/local/bin/wuci-security-status",
        "usr/local/bin/wuci-selinux-status",
        "usr/local/bin/wuci-ai-setup",
        "usr/local/bin/wuci-grok-build",
        "usr/share/wuci-os/accounts.json",
        "usr/share/wuci-os/packages.json",
        "usr/share/wuci-os/security-profile.json",
        "etc/profile.d/wuci-prompt.sh",
        "etc/skel/.ratpoisonrc",
        "etc/skel/.config/kitty/kitty.conf",
    }
    assert required.issubset(files)
    assert "SELINUX=enforcing" in files["usr/local/bin/wuci-security-apply"]
    assert "SELINUXTYPE=targeted" in files["usr/local/bin/wuci-security-apply"]
    assert "policy drop" in files["usr/local/bin/wuci-security-apply"]
    assert "passwd -d wj" in files["usr/local/bin/wuci-users-apply"]
    assert "chpst" in files["usr/local/bin/wuci-enter"]
    assert "wuci-security-apply" in files["usr/local/bin/wuci-guide"]
    assert "wuci-source-status" in files["usr/local/bin/wuci-guide"]
    assert "sudo wj install vim emacs kitty" in files["usr/local/bin/wuci-guide"]
    assert "xbps-install -Sy" in files["usr/local/bin/wj"]
    assert "WJ_ALLOW_REMOVE=1" in files["usr/local/bin/wj"]
    assert "WUCI_GUIDE_ASSUME_YES=1" in files["usr/local/bin/wuci-auto"]
    assert "Daylight/WJSEAL" in files["usr/local/bin/wuci-daylight-status"]
    assert "release seal pending" in files["usr/local/bin/wuci-daylight-status"]
    assert "/opt/wuci-os/source/wuci-ji" in files["usr/local/bin/wuci-source-status"]
    assert "/opt/wuci-os/source/upstream" in files["usr/local/bin/wuci-source-status"]
    assert "WJ>_" in files["etc/profile.d/wuci-prompt.sh"]
    assert not any(path.endswith("wuci-play") for path in files)
    assert "wuci-play" not in "\n".join(files.values())
    assert "grok-build-0.1" in files["usr/local/bin/wuci-grok-build"]
    assert "https://chatgpt.com/codex/install.sh" in files["usr/local/bin/wuci-ai-setup"]
    assert "https://gh.io/copilot-install" in files["usr/local/bin/wuci-ai-setup"]

    packages = json.loads(files["usr/share/wuci-os/packages.json"])
    assert packages["developer"]["desktop"]["default"] == "xfce4"
    assert packages["developer"]["desktop"]["preferred_terminal"] == "kitty"
    assert packages["developer"]["desktop"]["fallback_terminal"] == "xfce4-terminal"
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

    overlay_root = tmp / "overlay"
    manifest = wuci_os.create_overlay(
        overlay_root,
        wallpaper_source=REPO / "docs" / "wuci-os" / "assets" / "wallpaper1.png",
        force=True,
    )
    assert manifest["schema"] == wuci_os.OVERLAY_SCHEMA
    assert (overlay_root / wuci_os.OVERLAY_WALLPAPER_PATH).is_file()
    assert (overlay_root / "usr/local/bin/wuci-wallpaper").stat().st_mode & 0o111
    assert (overlay_root / "usr/share/wuci-os/overlay-manifest.json").is_file()
    records = wuci_os.overlay_file_records(overlay_root, ticker_mode="never")
    assert any(record["path"] == "usr/local/bin/wuci-security-apply" for record in records)

    for relative in sorted(path for path in files if path.startswith("usr/local/bin/")):
        proc = subprocess.run(
            ["sh", "-n", str(overlay_root / relative)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"{relative}: {proc.stderr}"


def assert_daylight_keygen(tmp: Path) -> None:
    keyfile = tmp / "daylight" / "overlay.key"
    result = wuci_os.generate_keyfile(keyfile)
    assert result["schema"] == "wuci-os-daylight-keyfile-v1"
    assert keyfile.stat().st_mode & 0o777 == 0o600
    data = keyfile.read_text(encoding="ascii")
    assert len(data.strip()) == 64
    assert all(char in "0123456789abcdef" for char in data.strip())


def assert_source_kit(tmp: Path) -> None:
    out = tmp / "boot" / "wuci-os-source-kit.tar"
    result = wuci_os.write_deterministic_source_kit_tar(out, ticker_mode="never")
    assert result["schema"] == wuci_os.SOURCE_KIT_SCHEMA
    assert result["tar_path"] == str(out)
    assert result["guest_source_root"] == "opt/wuci-os/source/wuci-ji"
    assert result["guest_upstream_source_root"] == "opt/wuci-os/source/upstream"
    assert any(record["path"] == "tools/wuci_os.py" for record in result["files"])

    import tarfile

    with tarfile.open(out, "r") as archive:
        names = archive.getnames()
    assert "opt/wuci-os/source/wuci-ji/tools/wuci_os.py" in names
    assert "usr/share/wuci-os/source-kit.json" in names
    assert "opt/wuci-os/source/wuci-ji/.wuci-os-source-kit.json" in names
    if (REPO / "build" / "wuci-os" / "upstream" / "void-mklive").is_dir():
        assert any(name.startswith("opt/wuci-os/source/upstream/void-mklive/") for name in names)


def assert_iso_plan(tmp: Path) -> None:
    source_root = tmp / "iso-source"
    source_root.mkdir()
    image = source_root / "wuci-source.iso"
    image.write_bytes(b"wuci iso fixture")
    wuci_os.wuci_kaiju.write_json_atomic(
        wuci_os.source_manifest_path(source_root),
        {
            "schema": wuci_os.SOURCE_SCHEMA,
            "created_utc": "2026-06-29T00:00:00Z",
            "product": wuci_os.PRODUCT_NAME,
            "image_id": wuci_os.IMAGE_ID,
            "image_path": str(image),
            "image_bytes": image.stat().st_size,
            "digest_vector": wuci_os.wuci_kaiju.file_digest_vector(image, "fixture")[0],
            "boundary_denials": list(wuci_os.BOUNDARY_DENIALS),
        },
    )
    original_inspect = wuci_os.inspect_void_iso
    try:
        wuci_os.inspect_void_iso = lambda _path: {
            "schema": "wuci-os-void-musl-layout-v1",
            "status": "pass",
            "label": "VOID_LIVE",
            "append": wuci_os.first_isolinux_append(ISOLINUX),
            "problems": [],
        }
        plan = wuci_os.finished_iso_plan(source_root)
    finally:
        wuci_os.inspect_void_iso = original_inspect
    assert plan["schema"] == wuci_os.ISO_PLAN_SCHEMA
    assert plan["status"] == "ready-for-build-lane"
    assert any(output.endswith(".iso") for output in plan["required_outputs"])
    assert "Wuci-OS" in plan["goal"]
    assert any(component["component"] == "wuci-os-guide" for component in wuci_os.RUST_REDESIGN_COMPONENTS)
    commands = wuci_os.demo_command_text()
    assert "10. wuci-live-banner" in commands
    assert "12. wuci-source-status" in commands
    assert "13. wuci-guide" in commands
    assert "14. sudo wj install vim emacs kitty" in commands
    assert "&& break" not in commands
    assert "wuci-play" not in commands


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


def main() -> int:
    parser_quiet = "--quiet" in sys.argv
    with tempfile.TemporaryDirectory(prefix="wuci-os-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_core_policy()
        assert_append_parsing()
        assert_missing_source(tmp)
        assert_bad_source_rejected(tmp)
        assert_boot_plan_ready(tmp)
        assert_overlay_profile(tmp)
        assert_daylight_keygen(tmp)
        assert_source_kit(tmp)
        assert_iso_plan(tmp)
        assert_cli(tmp)
    if not parser_quiet:
        print("wuci-os tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
