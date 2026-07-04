#!/usr/bin/env python3
"""Build a VirtualBox-ready OVF/OVA wrapper for a Wuci-OS ISO."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


SCHEMA = "wuci-virtualbox-appliance-v1"
DEFAULT_OUT_ROOT = Path("build/wuci-os/virtualbox")
DEFAULT_ISO = Path("build/wuci-os/final/Wuci-OS-x86_64-musl.iso")
DEFAULT_NAME = "Wuci-Ji v2.2 - Aperture Bastion"
DEFAULT_CPUS = 2
DEFAULT_MEMORY_MIB = 4096
READ_CHUNK = 1024 * 1024
FIXED_TAR_MTIME = 0
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._+-]+")
NON_CLAIM = (
    "This OVA is a VirtualBox appliance wrapper around the supplied ISO. It does "
    "not prove the ISO release gate, boot behavior, host cleanliness, or "
    "VirtualBox import success unless those checks are run and bound to the "
    "final artifact."
)


class VirtualBoxApplianceError(RuntimeError):
    pass


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def safe_basename(name: str) -> str:
    candidate = SAFE_NAME_RE.sub("-", name).strip("-._")
    candidate = re.sub(r"-{2,}", "-", candidate)
    if not candidate:
        raise VirtualBoxApplianceError("appliance name does not produce a safe filename")
    return candidate[:96]


def require_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise VirtualBoxApplianceError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise VirtualBoxApplianceError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise VirtualBoxApplianceError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise VirtualBoxApplianceError(f"{label} must not be hardlinked: {path}")
    if info.st_size <= 0:
        raise VirtualBoxApplianceError(f"{label} must not be empty: {path}")
    return info


def digest_file(path: Path) -> tuple[dict[str, str], int]:
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(READ_CHUNK), b""):
            total += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    return ({name: digest.hexdigest() for name, digest in digests.items()}, total)


def copy_iso(source: Path, dest: Path) -> dict[str, Any]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    try:
        with source.open("rb") as src, tmp.open("wb") as out:
            shutil.copyfileobj(src, out, READ_CHUNK)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
    digests, size = digest_file(dest)
    return {"path": str(dest), "bytes": size, "digest_vector": digests}


def appliance_uuid(name: str, iso_sha256: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"wuci-virtualbox:{name}:{iso_sha256}"))


def build_ovf_text(*, name: str, iso_name: str, iso_size: int, iso_sha256: str, cpus: int, memory_mib: int) -> str:
    system_id = safe_basename(name).lower()
    vm_uuid = appliance_uuid(name, iso_sha256)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References>
    <File ovf:id="wuci_iso" ovf:href="{escape(iso_name)}" ovf:size="{iso_size}"/>
  </References>
  <NetworkSection>
    <Info>VirtualBox NAT network for first-boot package and network configuration.</Info>
    <Network ovf:name="NAT">
      <Description>Default NAT adapter; no bridged host interface or shared folders are embedded.</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="{escape(system_id)}">
    <Info>Wuci-Ji v2.2 Aperture Bastion live ISO appliance.</Info>
    <Name>{escape(name)}</Name>
    <OperatingSystemSection ovf:id="100" vmw:osType="other26xLinux64Guest">
      <Info>64-bit Linux live ISO.</Info>
      <Description>Wuci-OS x86_64 musl</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection ovf:transport="iso">
      <Info>Virtual hardware requirements.</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>{escape(vm_uuid)}</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>{escape(system_id)}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>virtualbox-2.2</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:Caption>{cpus} virtual CPU(s)</rasd:Caption>
        <rasd:Description>Number of virtual CPUs</rasd:Description>
        <rasd:ElementName>{cpus} virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>{cpus}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>MegaBytes</rasd:AllocationUnits>
        <rasd:Caption>{memory_mib} MiB memory</rasd:Caption>
        <rasd:Description>Memory size</rasd:Description>
        <rasd:ElementName>{memory_mib} MiB memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>{memory_mib}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Caption>AHCI SATA controller</rasd:Caption>
        <rasd:Description>SATA storage controller</rasd:Description>
        <rasd:ElementName>sata-controller</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>AHCI</rasd:ResourceSubType>
        <rasd:ResourceType>20</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:Caption>Wuci-OS live ISO</rasd:Caption>
        <rasd:Description>Read-only CD/DVD device backed by the packaged ISO</rasd:Description>
        <rasd:ElementName>wuci-live-iso</rasd:ElementName>
        <rasd:HostResource>ovf:/file/wuci_iso</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>15</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Caption>NAT network adapter</rasd:Caption>
        <rasd:Connection>NAT</rasd:Connection>
        <rasd:Description>Network adapter</rasd:Description>
        <rasd:ElementName>network-adapter</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>virtio</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
"""


def write_manifest(path: Path, ovf_name: str, iso_name: str, ovf_sha256: str, iso_sha256: str) -> None:
    path.write_text(
        f"SHA256({ovf_name})= {ovf_sha256}\nSHA256({iso_name})= {iso_sha256}\n",
        encoding="ascii",
    )


def add_tar_file(archive: tarfile.TarFile, path: Path, arcname: str) -> None:
    info = path.stat()
    tar_info = tarfile.TarInfo(arcname)
    tar_info.size = info.st_size
    tar_info.mode = 0o644
    tar_info.uid = 0
    tar_info.gid = 0
    tar_info.uname = "root"
    tar_info.gname = "root"
    tar_info.mtime = FIXED_TAR_MTIME
    with path.open("rb") as handle:
        archive.addfile(tar_info, handle)


def build_ova(ova_path: Path, members: list[tuple[Path, str]]) -> dict[str, Any]:
    tmp = ova_path.with_name(ova_path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    try:
        with tarfile.open(tmp, "w", format=tarfile.USTAR_FORMAT) as archive:
            for path, arcname in members:
                add_tar_file(archive, path, arcname)
        os.replace(tmp, ova_path)
    finally:
        if tmp.exists():
            tmp.unlink()
    digests, size = digest_file(ova_path)
    return {"path": str(ova_path), "bytes": size, "digest_vector": digests}


def build_appliance(
    *,
    iso: Path,
    out_root: Path = DEFAULT_OUT_ROOT,
    name: str = DEFAULT_NAME,
    cpus: int = DEFAULT_CPUS,
    memory_mib: int = DEFAULT_MEMORY_MIB,
    force: bool = False,
) -> dict[str, Any]:
    if cpus < 1 or cpus > 64:
        raise VirtualBoxApplianceError("cpus must be between 1 and 64")
    if memory_mib < 512 or memory_mib > 262144:
        raise VirtualBoxApplianceError("memory_mib must be between 512 and 262144")
    source_info = require_regular_file(iso, "Wuci-OS final ISO")
    source_digests, source_size = digest_file(iso)
    base = safe_basename(name)
    out_root.mkdir(parents=True, exist_ok=True)
    ovf_path = out_root / f"{base}.ovf"
    mf_path = out_root / f"{base}.mf"
    ova_path = out_root / f"{base}.ova"
    iso_path = out_root / f"{base}.iso"
    manifest_path = out_root / "virtualbox-manifest.json"
    outputs = (ovf_path, mf_path, ova_path, iso_path, manifest_path)
    if not force:
        existing = [str(path) for path in outputs if path.exists()]
        if existing:
            raise VirtualBoxApplianceError("refusing to overwrite existing VirtualBox artifact(s): " + ", ".join(existing))

    with tempfile.TemporaryDirectory(prefix="wuci-virtualbox.", dir=str(out_root)) as tmp_name:
        staging = Path(tmp_name)
        staged_iso = staging / iso_path.name
        copied_iso = copy_iso(iso, staged_iso)
        if copied_iso["digest_vector"]["sha256"] != source_digests["sha256"] or copied_iso["bytes"] != source_size:
            raise VirtualBoxApplianceError("copied ISO digest mismatch")
        ovf_text = build_ovf_text(
            name=name,
            iso_name=iso_path.name,
            iso_size=source_size,
            iso_sha256=source_digests["sha256"],
            cpus=cpus,
            memory_mib=memory_mib,
        )
        staged_ovf = staging / ovf_path.name
        staged_ovf.write_text(ovf_text, encoding="utf-8")
        ovf_sha256 = hashlib.sha256(ovf_text.encode("utf-8")).hexdigest()
        staged_mf = staging / mf_path.name
        write_manifest(staged_mf, ovf_path.name, iso_path.name, ovf_sha256, source_digests["sha256"])
        staged_ova = staging / ova_path.name
        ova = build_ova(
            staged_ova,
            [(staged_ovf, ovf_path.name), (staged_mf, mf_path.name), (staged_iso, iso_path.name)],
        )
        os.replace(staged_iso, iso_path)
        os.replace(staged_ovf, ovf_path)
        os.replace(staged_mf, mf_path)
        os.replace(staged_ova, ova_path)

    manifest = {
        "schema": SCHEMA,
        "status": "built",
        "name": name,
        "virtualbox_profile": {
            "cpus": cpus,
            "memory_mib": memory_mib,
            "network": "NAT",
            "shared_folders": [],
            "snapshots": [],
            "credentials_embedded": False,
            "host_paths_embedded": False,
        },
        "source_iso": {
            "path": str(iso),
            "bytes": source_info.st_size,
            "digest_vector": source_digests,
        },
        "artifacts": {
            "iso": {"path": str(iso_path), "bytes": source_size, "digest_vector": source_digests},
            "ovf": {"path": str(ovf_path), "bytes": ovf_path.stat().st_size, "sha256": sha256_path(ovf_path)},
            "manifest": {"path": str(mf_path), "bytes": mf_path.stat().st_size, "sha256": sha256_path(mf_path)},
            "ova": ova | {"path": str(ova_path)},
        },
        "non_claim_boundary": NON_CLAIM,
    }
    manifest_path.write_text(stable_json(manifest), encoding="utf-8")
    return manifest


def sha256_path(path: Path) -> str:
    return digest_file(path)[0]["sha256"]


def run_build(args: argparse.Namespace) -> int:
    try:
        manifest = build_appliance(
            iso=Path(args.iso),
            out_root=Path(args.out_root),
            name=args.name,
            cpus=args.cpus,
            memory_mib=args.memory_mib,
            force=args.force,
        )
    except VirtualBoxApplianceError as exc:
        print(f"wuci-virtualbox: {exc}")
        return 2
    print("wuci-virtualbox: built")
    print(f"ova: {manifest['artifacts']['ova']['path']}")
    print(f"ovf: {manifest['artifacts']['ovf']['path']}")
    print(f"manifest: {Path(args.out_root) / 'virtualbox-manifest.json'}")
    if args.json:
        print(stable_json(manifest), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Wuci-OS VirtualBox OVF/OVA artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build a VirtualBox OVA from a final ISO")
    build.add_argument("--iso", default=str(DEFAULT_ISO), help="final Wuci-OS ISO path")
    build.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT), help="VirtualBox artifact output directory")
    build.add_argument("--name", default=DEFAULT_NAME, help="VirtualBox appliance name")
    build.add_argument("--cpus", type=int, default=DEFAULT_CPUS, help="virtual CPU count")
    build.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB, help="guest memory in MiB")
    build.add_argument("--force", action="store_true", help="replace existing generated artifacts")
    build.add_argument("--json", action="store_true", help="also print the JSON manifest")
    build.set_defaults(func=run_build)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
