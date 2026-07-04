#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import tarfile
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_virtualbox  # noqa: E402


def assert_appliance_has_no_host_paths(tmp: Path) -> None:
    iso = tmp / "Wuci-OS-x86_64-musl.iso"
    iso.write_bytes(b"fixture iso image\n")
    out = tmp / "virtualbox"
    manifest = wuci_virtualbox.build_appliance(iso=iso, out_root=out, force=True)
    assert manifest["schema"] == wuci_virtualbox.SCHEMA
    assert manifest["virtualbox_profile"]["network"] == "NAT"
    assert manifest["virtualbox_profile"]["shared_folders"] == []
    assert manifest["virtualbox_profile"]["credentials_embedded"] is False
    ovf = Path(manifest["artifacts"]["ovf"]["path"]).read_text(encoding="utf-8")
    assert str(tmp) not in ovf
    assert "SharedFolder" not in ovf
    assert "HostResource>ovf:/file/wuci_iso" in ovf
    assert "NAT" in ovf
    assert "4096 MiB memory" in ovf
    ova_path = Path(manifest["artifacts"]["ova"]["path"])
    with tarfile.open(ova_path, "r") as archive:
        names = archive.getnames()
    assert names == [
        "Wuci-Ji-v2.2-Aperture-Bastion.ovf",
        "Wuci-Ji-v2.2-Aperture-Bastion.mf",
        "Wuci-Ji-v2.2-Aperture-Bastion.iso",
    ]


def assert_unsafe_iso_rejected(tmp: Path) -> None:
    if hasattr(os, "symlink"):
        target = tmp / "target.iso"
        target.write_bytes(b"target\n")
        link = tmp / "link.iso"
        link.symlink_to(target)
        try:
            wuci_virtualbox.build_appliance(iso=link, out_root=tmp / "out-link", force=True)
        except wuci_virtualbox.VirtualBoxApplianceError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("VirtualBox appliance accepted a symlink ISO")

    if hasattr(os, "link"):
        source = tmp / "source.iso"
        source.write_bytes(b"source\n")
        peer = tmp / "peer.iso"
        try:
            os.link(source, peer)
        except OSError:
            return
        try:
            wuci_virtualbox.build_appliance(iso=source, out_root=tmp / "out-hardlink", force=True)
        except wuci_virtualbox.VirtualBoxApplianceError as exc:
            assert "hardlinked" in str(exc)
        else:
            raise AssertionError("VirtualBox appliance accepted a hardlinked ISO")


def assert_rejects_overwrite_without_force(tmp: Path) -> None:
    iso = tmp / "overwrite.iso"
    iso.write_bytes(b"overwrite\n")
    out = tmp / "overwrite-out"
    wuci_virtualbox.build_appliance(iso=iso, out_root=out, force=True)
    try:
        wuci_virtualbox.build_appliance(iso=iso, out_root=out, force=False)
    except wuci_virtualbox.VirtualBoxApplianceError as exc:
        assert "refusing to overwrite" in str(exc)
    else:
        raise AssertionError("VirtualBox appliance overwrote outputs without --force")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-virtualbox-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_appliance_has_no_host_paths(tmp)
        assert_unsafe_iso_rejected(tmp)
        assert_rejects_overwrite_without_force(tmp)
    print("wuci-virtualbox tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
