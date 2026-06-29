#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import wuci_safeio


REPORT_SCHEMA = "wuci-prism-report-v1"
TOOL_NAME = "Wuci-Prism"
TAGLINE = (
    "Wuci-Prism refracts sealed WJSEAL artifacts into public, reviewable "
    "evidence without releasing plaintext."
)

WJSEAL_PREFIX_LEN = 8
WJSEAL_KEY_ID_LEN = 16
WJSEAL_EPHEMERAL_PUBLIC_LEN = 32
WJSEAL_NONCE_LEN = 12
WJSEAL_TAG_LEN = 16
ALGORITHM_ID = 1
ALGORITHM_NAME = "ChaCha20-Poly1305"


class PrismError(RuntimeError):
    pass


@dataclass(frozen=True)
class Layout:
    version: int
    prefix: bytes
    header_length: int
    key_id_start: int | None
    ephemeral_public_start: int | None

    @property
    def version_name(self) -> str:
        return f"WJSEAL-v{self.version}"


LAYOUTS = (
    Layout(
        version=1,
        prefix=b"WJSEAL\x01\x01",
        header_length=WJSEAL_PREFIX_LEN + WJSEAL_NONCE_LEN,
        key_id_start=None,
        ephemeral_public_start=None,
    ),
    Layout(
        version=2,
        prefix=b"WJSEAL\x02\x01",
        header_length=WJSEAL_PREFIX_LEN + WJSEAL_KEY_ID_LEN + WJSEAL_NONCE_LEN,
        key_id_start=WJSEAL_PREFIX_LEN,
        ephemeral_public_start=None,
    ),
    Layout(
        version=3,
        prefix=b"WJSEAL\x03\x01",
        header_length=(
            WJSEAL_PREFIX_LEN
            + WJSEAL_EPHEMERAL_PUBLIC_LEN
            + WJSEAL_KEY_ID_LEN
            + WJSEAL_NONCE_LEN
        ),
        key_id_start=WJSEAL_PREFIX_LEN + WJSEAL_EPHEMERAL_PUBLIC_LEN,
        ephemeral_public_start=WJSEAL_PREFIX_LEN,
    ),
)


def hex_digest(value: bytes, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    hasher.update(value)
    return hasher.hexdigest()


def digest_vector(value: bytes) -> dict[str, str]:
    return {
        "sha256": hex_digest(value, "sha256"),
        "sha384": hex_digest(value, "sha384"),
        "sha512": hex_digest(value, "sha512"),
    }


def classify_wjseal(artifact: bytes) -> Layout:
    if len(artifact) < WJSEAL_PREFIX_LEN:
        raise PrismError("truncated WJSEAL artifact: missing prefix")
    for layout in LAYOUTS:
        if artifact.startswith(layout.prefix):
            return layout
    raise PrismError("unsupported WJSEAL artifact prefix or algorithm")


def parse_artifact(path: Path) -> dict[str, Any]:
    try:
        artifact = wuci_safeio.read_regular_bytes(
            path,
            "WJSEAL artifact",
            reject_symlink=True,
        )
    except wuci_safeio.SafeIOError as exc:
        raise PrismError(str(exc)) from exc

    layout = classify_wjseal(artifact)
    minimum_length = layout.header_length + WJSEAL_TAG_LEN
    if len(artifact) < minimum_length:
        raise PrismError(
            "truncated WJSEAL artifact: "
            f"{layout.version_name} requires at least {minimum_length} bytes"
        )

    header = artifact[: layout.header_length]
    ciphertext = artifact[layout.header_length : -WJSEAL_TAG_LEN]
    tag = artifact[-WJSEAL_TAG_LEN:]
    nonce_start = layout.header_length - WJSEAL_NONCE_LEN
    nonce = header[nonce_start:layout.header_length]

    key_id = None
    if layout.key_id_start is not None:
        key_id = header[
            layout.key_id_start : layout.key_id_start + WJSEAL_KEY_ID_LEN
        ].hex()

    ephemeral_public = None
    if layout.ephemeral_public_start is not None:
        ephemeral_public = header[
            layout.ephemeral_public_start : layout.ephemeral_public_start
            + WJSEAL_EPHEMERAL_PUBLIC_LEN
        ].hex()

    manifest = manifest_text_from_parts(
        version=layout.version,
        header_length=layout.header_length,
        key_id=key_id,
        ephemeral_public=ephemeral_public,
        artifact_sha256=hex_digest(artifact, "sha256"),
        ciphertext_length=len(ciphertext),
        ciphertext_sha256=hex_digest(ciphertext, "sha256"),
        nonce=nonce.hex(),
        tag=tag.hex(),
    )
    manifest_bytes = manifest.encode("ascii")

    return {
        "schema": REPORT_SCHEMA,
        "tool": TOOL_NAME,
        "description": (
            "Wuci-Prism is a keyless WJSEAL artifact inspector. It decodes "
            "public structure, hashes, and claim-boundary evidence while "
            "keeping plaintext release bound to WUCI-GATE."
        ),
        "tagline": TAGLINE,
        "artifact": {
            "path": str(path),
            "size": len(artifact),
            "digest_vector": digest_vector(artifact),
        },
        "wjseal": {
            "version": layout.version,
            "version_name": layout.version_name,
            "magic": "WJSEAL",
            "algorithm_id": ALGORITHM_ID,
            "algorithm": ALGORITHM_NAME,
            "prefix_hex": layout.prefix.hex(),
            "header_length": layout.header_length,
        },
        "public_header": {
            "ephemeral_public": ephemeral_public,
            "key_id": key_id,
            "nonce": nonce.hex(),
        },
        "ciphertext": {
            "offset": layout.header_length,
            "length": len(ciphertext),
            "digest_vector": digest_vector(ciphertext),
        },
        "tag": {
            "offset": len(artifact) - WJSEAL_TAG_LEN,
            "length": WJSEAL_TAG_LEN,
            "hex": tag.hex(),
            "digest_vector": digest_vector(tag),
        },
        "artifact_manifest": parse_manifest_labels(manifest),
        "artifact_manifest_sha256": hex_digest(manifest_bytes, "sha256"),
        "artifact_manifest_digest_vector": digest_vector(manifest_bytes),
        "gate": {
            "required_for_plaintext_release": True,
            "required_status": "required-for-plaintext-release",
        },
        "boundary": {
            "mode": "keyless-public-artifact-inspection",
            "secret_key_input": "unsupported",
            "plaintext_output": "unsupported",
            "decrypts": False,
            "plaintext_released": False,
            "tag_verified": False,
            "aead_tag_verification": "not-performed-keyless-inspection",
            "wuci_gate_required_for_plaintext_release": True,
            "runtime_sandboxing_claimed": False,
            "quantum_safe_claimed": False,
            "production_authority_claimed": False,
        },
    }


def manifest_text_from_parts(
    *,
    version: int,
    header_length: int,
    key_id: str | None,
    ephemeral_public: str | None,
    artifact_sha256: str,
    ciphertext_length: int,
    ciphertext_sha256: str,
    nonce: str,
    tag: str,
) -> str:
    lines = [
        f"version: {version}",
        f"algorithm: {ALGORITHM_ID}",
        f"header-length: {header_length}",
    ]
    if ephemeral_public is not None:
        lines.append(f"ephemeral-public: {ephemeral_public}")
    if key_id is not None:
        lines.append(f"key-id: {key_id}")
    lines.extend(
        [
            f"artifact-sha256: {artifact_sha256}",
            f"ciphertext-length: {ciphertext_length}",
            f"ciphertext-sha256: {ciphertext_sha256}",
            f"nonce: {nonce}",
            f"tag: {tag}",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_manifest_labels(manifest: str) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in manifest.splitlines():
        label, value = line.split(": ", 1)
        labels[label.replace("-", "_")] = value
    return labels


def manifest_text(report: dict[str, Any]) -> str:
    manifest = report["artifact_manifest"]
    lines = [
        f"version: {manifest['version']}",
        f"algorithm: {manifest['algorithm']}",
        f"header-length: {manifest['header_length']}",
    ]
    if "ephemeral_public" in manifest:
        lines.append(f"ephemeral-public: {manifest['ephemeral_public']}")
    if "key_id" in manifest:
        lines.append(f"key-id: {manifest['key_id']}")
    lines.extend(
        [
            f"artifact-sha256: {manifest['artifact_sha256']}",
            f"ciphertext-length: {manifest['ciphertext_length']}",
            f"ciphertext-sha256: {manifest['ciphertext_sha256']}",
            f"nonce: {manifest['nonce']}",
            f"tag: {manifest['tag']}",
        ]
    )
    return "\n".join(lines) + "\n"


def inspect_text(report: dict[str, Any]) -> str:
    public = report["public_header"]
    artifact = report["artifact"]
    wjseal = report["wjseal"]
    ciphertext = report["ciphertext"]
    tag = report["tag"]
    lines = [
        f"schema: {report['schema']}",
        f"tool: {report['tool']}",
        f"artifact: {artifact['path']}",
        f"artifact-size: {artifact['size']}",
        f"version: {wjseal['version_name']}",
        f"algorithm: {wjseal['algorithm']}",
        f"header-length: {wjseal['header_length']}",
    ]
    if public["ephemeral_public"] is not None:
        lines.append(f"ephemeral-public: {public['ephemeral_public']}")
    if public["key_id"] is not None:
        lines.append(f"key-id: {public['key_id']}")
    lines.extend(
        [
            f"nonce: {public['nonce']}",
            f"ciphertext-length: {ciphertext['length']}",
            f"ciphertext-sha256: {ciphertext['digest_vector']['sha256']}",
            f"tag-offset: {tag['offset']}",
            f"tag: {tag['hex']}",
            f"artifact-sha256: {artifact['digest_vector']['sha256']}",
            f"artifact-sha384: {artifact['digest_vector']['sha384']}",
            f"artifact-sha512: {artifact['digest_vector']['sha512']}",
            f"artifact-manifest-sha256: {report['artifact_manifest_sha256']}",
            f"gate-required-status: {report['gate']['required_status']}",
            "secret-key-input: unsupported",
            "plaintext-output: unsupported",
            "tag-verified: false",
        ]
    )
    return "\n".join(lines) + "\n"


def boundary_text(report: dict[str, Any]) -> str:
    boundary = report["boundary"]
    gate = report["gate"]
    return "\n".join(
        [
            f"schema: {report['schema']}",
            f"tool: {report['tool']}",
            f"artifact: {report['artifact']['path']}",
            f"mode: {boundary['mode']}",
            f"secret-key-input: {boundary['secret_key_input']}",
            f"plaintext-output: {boundary['plaintext_output']}",
            f"decrypts: {str(boundary['decrypts']).lower()}",
            f"plaintext-released: {str(boundary['plaintext_released']).lower()}",
            f"tag-verified: {str(boundary['tag_verified']).lower()}",
            f"gate-required-status: {gate['required_status']}",
            "runtime-sandboxing-claimed: false",
            "quantum-safe-claimed: false",
            "production-authority-claimed: false",
        ]
    ) + "\n"


def explain_text(report: dict[str, Any]) -> str:
    public = report["public_header"]
    wjseal = report["wjseal"]
    tag = report["tag"]
    lines = [
        TAGLINE,
        "",
        f"artifact: {report['artifact']['path']}",
        f"version: {wjseal['version_name']}",
        f"visible header: {wjseal['header_length']} bytes",
    ]
    if public["ephemeral_public"] is not None:
        lines.append(f"ephemeral public key: {public['ephemeral_public']}")
    if public["key_id"] is not None:
        lines.append(f"key ID: {public['key_id']}")
    lines.extend(
        [
            f"nonce: {public['nonce']}",
            f"ciphertext length: {report['ciphertext']['length']} bytes",
            f"tag location: offset {tag['offset']}, {tag['length']} bytes",
            "",
            "boundary: keyless public inspection only",
            "secret key input: unsupported",
            "plaintext output: unsupported",
            "plaintext release: WUCI-GATE required",
        ]
    )
    return "\n".join(lines) + "\n"


def write_json(report: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")


def run_inspect(args: argparse.Namespace) -> int:
    report = parse_artifact(Path(args.artifact))
    if args.json:
        write_json(report)
    else:
        sys.stdout.write(inspect_text(report))
    return 0


def run_manifest(args: argparse.Namespace) -> int:
    sys.stdout.write(manifest_text(parse_artifact(Path(args.artifact))))
    return 0


def run_explain(args: argparse.Namespace) -> int:
    sys.stdout.write(explain_text(parse_artifact(Path(args.artifact))))
    return 0


def run_boundary(args: argparse.Namespace) -> int:
    report = parse_artifact(Path(args.artifact))
    if args.json:
        write_json(report)
    else:
        sys.stdout.write(boundary_text(report))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wuci-prism",
        description="Keyless WJSEAL artifact inspector.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser(
        "inspect",
        help="inspect public WJSEAL structure and evidence",
    )
    inspect.add_argument("artifact", help="sealed .wj artifact")
    inspect.add_argument("--json", action="store_true", help="emit wuci-prism-report-v1")
    inspect.set_defaults(func=run_inspect)

    manifest = subparsers.add_parser(
        "manifest",
        help="print Gate-compatible public artifact manifest",
    )
    manifest.add_argument("artifact", help="sealed .wj artifact")
    manifest.set_defaults(func=run_manifest)

    explain = subparsers.add_parser(
        "explain",
        help="explain visible fields and the no-plaintext boundary",
    )
    explain.add_argument("artifact", help="sealed .wj artifact")
    explain.set_defaults(func=run_explain)

    boundary = subparsers.add_parser(
        "boundary",
        help="print keyless inspection and Gate-release boundary",
    )
    boundary.add_argument("artifact", help="sealed .wj artifact")
    boundary.add_argument("--json", action="store_true", help="emit wuci-prism-report-v1")
    boundary.set_defaults(func=run_boundary)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PrismError as exc:
        print(f"wuci-prism: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
