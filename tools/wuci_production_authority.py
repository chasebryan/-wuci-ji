#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

import wuci_safeio


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "docs" / "wuci_production_authority_policy.json"
SIGNATURE_IDENTITY = "wuci-production-authority"
SIGNATURE_NAMESPACE = "wuci-production-authority-v1"
FIELDS = (
    "schema",
    "suite",
    "production",
    "authority-id",
    "group-public-key",
    "allow-open",
    "allow-release",
    "allow-trust",
    "allow-publish",
)
HEX_RE = re.compile(r"^[0-9a-f]+$")
CEREMONY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
KNOWN_NON_PRODUCTION_GROUP_KEYS = {
    "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
}


class ProductionAuthorityError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ProductionAuthorityError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, context: str = "file") -> str:
    try:
        return wuci_safeio.sha256_file(path, context)
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc


def read_bytes(path: Path, context: str, *, max_bytes: int | None = None) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(
            path,
            context,
            reject_symlink=True,
            reject_hardlink=True,
            max_bytes=max_bytes,
        )
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc


def read_ascii(path: Path, context: str, *, max_bytes: int | None = None) -> str:
    try:
        return wuci_safeio.read_regular_ascii(
            path,
            context,
            reject_symlink=True,
            reject_hardlink=True,
            max_bytes=max_bytes,
        )
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc


def write_text_new(path: Path, text: str, context: str, *, mode: int = 0o644) -> None:
    try:
        wuci_safeio.write_new_text(path, text, context, mode=mode)
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc


def write_json_new(path: Path, value: dict[str, Any], context: str, *, mode: int = 0o644) -> None:
    try:
        wuci_safeio.write_json_new(path, value, context, mode=mode)
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc


def require_hex(value: str, chars: int, context: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        fail(f"{context} must be {chars} lowercase hex characters")


def validate_compressed_secp256k1(group_public_key: str) -> None:
    require_hex(group_public_key, 66, "group-public-key")
    prefix = group_public_key[:2]
    if prefix not in {"02", "03"}:
        fail("group-public-key must be compressed SEC1")
    if group_public_key in KNOWN_NON_PRODUCTION_GROUP_KEYS:
        fail("group-public-key is known fixture or demo material")
    x = int(group_public_key[2:], 16)
    if x >= SECP256K1_P:
        fail("group-public-key x coordinate is out of range")
    rhs = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(rhs, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if (y * y) % SECP256K1_P != rhs:
        fail("group-public-key is not on secp256k1")
    if (y & 1) != (1 if prefix == "03" else 0):
        y = SECP256K1_P - y
    if (y & 1) != (1 if prefix == "03" else 0):
        fail("group-public-key parity is invalid")


def authority_id(group_public_key: str) -> str:
    return sha256_bytes(bytes.fromhex(group_public_key))


def canonical_authority_text(
    *,
    group_public_key: str,
    allow_open: bool,
    allow_release: bool,
    allow_trust: bool,
    allow_publish: bool,
) -> str:
    return (
        "schema: wuci-authority-root-v1\n"
        "suite: FROST-secp256k1-SHA256-v1\n"
        "production: true\n"
        f"authority-id: {authority_id(group_public_key)}\n"
        f"group-public-key: {group_public_key}\n"
        f"allow-open: {str(allow_open).lower()}\n"
        f"allow-release: {str(allow_release).lower()}\n"
        f"allow-trust: {str(allow_trust).lower()}\n"
        f"allow-publish: {str(allow_publish).lower()}\n"
    )


def parse_authority(text: str) -> dict[str, str]:
    if "\r" in text or not text.endswith("\n") or text.endswith("\n\n"):
        fail("authority root must be LF text with one trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) != len(FIELDS):
        fail("authority root has unexpected field count")
    fields: dict[str, str] = {}
    for line, expected in zip(lines, FIELDS):
        if ": " not in line:
            fail("authority root line is not label: value")
        label, value = line.split(": ", 1)
        if label != expected:
            fail(f"authority root expected label {expected}")
        fields[label] = value
    require_hex(fields["authority-id"], 64, "authority-id")
    validate_compressed_secp256k1(fields["group-public-key"])
    expected_id = authority_id(fields["group-public-key"])
    if fields["authority-id"] != expected_id:
        fail("authority-id does not match group-public-key")
    for label in ("allow-open", "allow-release", "allow-trust", "allow-publish"):
        if fields[label] not in {"true", "false"}:
            fail(f"{label} must be true or false")
    if not any(fields[label] == "true" for label in ("allow-open", "allow-release")):
        fail("production authority must enable at least open or release")
    if fields["allow-trust"] == "true" or fields["allow-publish"] == "true":
        fail("production trust/publish authority requires assembly Gate enforcement first")
    return fields


def load_json(path: Path, context: str) -> Any:
    try:
        return json.loads(read_bytes(path, context, max_bytes=256 * 1024).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProductionAuthorityError(f"{context} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ProductionAuthorityError(f"{context} is not valid JSON: {exc.msg}") from exc


def reject_fixture_path(path: Path) -> None:
    lowered = path.as_posix().lower()
    if "fixture" in lowered:
        fail("fixture or repo-local authority path is not production authority")
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to((REPO_ROOT / "authority").resolve(strict=True))
        fail("fixture or repo-local authority path is not production authority")
    except ValueError:
        return
    except OSError as exc:
        raise ProductionAuthorityError(f"could not resolve authority path: {path}") from exc


def reject_fixture_output_path(path: Path) -> None:
    lowered = path.as_posix().lower()
    if "fixture" in lowered:
        fail("production authority output path must not contain fixture")
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to((REPO_ROOT / "authority").resolve(strict=True))
        fail("production authority output must not be written under authority/")
    except ValueError:
        return
    except OSError as exc:
        raise ProductionAuthorityError(f"could not resolve authority output path: {path}") from exc


def ceremony_inputs_sha256(
    *,
    authority_sha256: str,
    authority_id_value: str,
    group_public_key: str,
    reviewed_policy_sha256: str,
    threshold: int,
    signer_count: int,
) -> str:
    value = {
        "authority_id": authority_id_value,
        "authority_sha256": authority_sha256,
        "group_public_key_sha256": sha256_bytes(bytes.fromhex(group_public_key)),
        "reviewed_policy_sha256": reviewed_policy_sha256,
        "signer_count": signer_count,
        "threshold": threshold,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return sha256_bytes(encoded)


def positive_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{context} must be a positive integer")
    return value


def validate_ceremony(
    *,
    path: Path,
    authority_sha256: str,
    fields: dict[str, str],
    policy_path: Path,
) -> dict[str, Any]:
    value = load_json(path, "production authority ceremony")
    if not isinstance(value, dict):
        fail("ceremony evidence must be a JSON object")
    if value.get("schema") != "wuci-production-authority-ceremony-v1":
        fail("unsupported ceremony schema")
    if value.get("authority_sha256") != authority_sha256:
        fail("ceremony authority digest mismatch")
    if value.get("authority_id") != fields["authority-id"]:
        fail("ceremony authority-id mismatch")
    if value.get("group_public_key_sha256") != sha256_bytes(bytes.fromhex(fields["group-public-key"])):
        fail("ceremony group public key digest mismatch")
    if not isinstance(value.get("operator"), str) or not value["operator"].strip():
        fail("ceremony operator is required")
    if "fixture" in value["operator"].lower():
        fail("ceremony operator must not be fixture material")
    if not isinstance(value.get("ceremony_id"), str) or CEREMONY_ID_RE.fullmatch(value["ceremony_id"]) is None:
        fail("ceremony_id must be a stable lowercase id")
    if not isinstance(value.get("created_utc"), str) or UTC_RE.fullmatch(value["created_utc"]) is None:
        fail("created_utc must be YYYY-MM-DDTHH:MM:SSZ")
    if value.get("fixture_material_used") is not False:
        fail("production ceremony must reject fixture material")
    if value.get("root_signature_required") is not True:
        fail("production ceremony must require root signature")
    threshold = positive_int(value.get("threshold"), "threshold")
    signer_count = positive_int(value.get("signer_count"), "signer_count")
    if threshold < 2:
        fail("production authority threshold must be at least 2")
    if signer_count < threshold:
        fail("signer_count must be greater than or equal to threshold")
    reviewed_policy_sha256 = sha256_file(policy_path, "production authority policy")
    if value.get("reviewed_policy_sha256") != reviewed_policy_sha256:
        fail("ceremony reviewed policy digest mismatch")
    expected_inputs = ceremony_inputs_sha256(
        authority_sha256=authority_sha256,
        authority_id_value=fields["authority-id"],
        group_public_key=fields["group-public-key"],
        reviewed_policy_sha256=reviewed_policy_sha256,
        threshold=threshold,
        signer_count=signer_count,
    )
    if value.get("ceremony_inputs_sha256") != expected_inputs:
        fail("ceremony inputs digest mismatch")
    return value


def ssh_keygen_path(override: str | None) -> str:
    if override:
        if "\0" in override:
            fail("ssh-keygen path contains NUL")
        path = Path(override)
        if not path.is_absolute():
            fail("--ssh-keygen must be an absolute path")
        if not path.exists():
            fail(f"ssh-keygen does not exist: {path}")
        return str(path)
    found = shutil.which("ssh-keygen")
    if not found:
        fail("ssh-keygen not found on PATH")
    return found


def read_public_key_line(path: Path) -> str:
    key_line = read_ascii(path, "production authority ceremony root key", max_bytes=8192).strip()
    if not key_line.startswith(("ssh-ed25519 ", "sk-ssh-ed25519@openssh.com ")):
        fail("ceremony root key must be an OpenSSH Ed25519 public key")
    return key_line


def verify_ssh_signature(
    *,
    message: bytes,
    root_key: Path,
    signature: Path,
    ssh_keygen: str | None,
) -> None:
    read_bytes(signature, "production authority ceremony signature", max_bytes=65536)
    key_line = read_public_key_line(root_key)
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="wuci-prod-auth-signers-") as tmp:
        allowed = Path(tmp) / "allowed_signers"
        allowed.write_text(f"{SIGNATURE_IDENTITY} {key_line}\n", encoding="ascii")
        proc = subprocess.run(
            [
                ssh,
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                SIGNATURE_IDENTITY,
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature),
            ],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        fail(f"production authority ceremony signature verification failed: {detail}")


def sign_ssh_message(
    *,
    message_path: Path,
    signing_key: Path,
    root_key: Path,
    signature_path: Path,
    ssh_keygen: str | None,
) -> None:
    try:
        wuci_safeio.require_private_file_mode(signing_key, "production authority signing key")
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc
    message = read_bytes(message_path, "production authority ceremony", max_bytes=256 * 1024)
    read_public_key_line(root_key)
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="wuci-prod-auth-sign-") as tmp:
        sign_input = Path(tmp) / "ceremony.json"
        sign_input.write_bytes(message)
        proc = subprocess.run(
            [
                ssh,
                "-Y",
                "sign",
                "-f",
                str(signing_key),
                "-n",
                SIGNATURE_NAMESPACE,
                str(sign_input),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
            fail(f"production authority ceremony signing failed: {detail}")
        generated = sign_input.with_suffix(sign_input.suffix + ".sig")
        signature_bytes = read_bytes(generated, "generated ceremony signature", max_bytes=65536)
        verify_path = Path(tmp) / "ceremony.json.sig.verify"
        verify_path.write_bytes(signature_bytes)
        verify_ssh_signature(
            message=message,
            root_key=root_key,
            signature=verify_path,
            ssh_keygen=ssh,
        )
    try:
        wuci_safeio.write_new_bytes(
            signature_path,
            signature_bytes,
            "production authority ceremony signature",
            mode=0o644,
        )
    except wuci_safeio.SafeIOError as exc:
        raise ProductionAuthorityError(str(exc)) from exc


def verify_authority(
    *,
    authority_path: Path,
    ceremony_path: Path,
    ceremony_root_key: Path | None,
    ceremony_signature: Path | None,
    policy_path: Path,
    ssh_keygen: str | None,
    allow_unsigned_ceremony: bool,
) -> dict[str, Any]:
    reject_fixture_path(authority_path)
    authority_text = read_ascii(authority_path, "production authority root", max_bytes=64 * 1024)
    fields = parse_authority(authority_text)
    if fields["production"] != "true":
        fail("production authority must set production: true")
    authority_sha256 = sha256_file(authority_path, "production authority root")
    ceremony = validate_ceremony(
        path=ceremony_path,
        authority_sha256=authority_sha256,
        fields=fields,
        policy_path=policy_path,
    )
    signature_verified = False
    if ceremony_root_key is not None or ceremony_signature is not None:
        if ceremony_root_key is None or ceremony_signature is None:
            fail("ceremony signature verification requires both root key and signature")
        verify_ssh_signature(
            message=read_bytes(ceremony_path, "production authority ceremony", max_bytes=256 * 1024),
            root_key=ceremony_root_key,
            signature=ceremony_signature,
            ssh_keygen=ssh_keygen,
        )
        signature_verified = True
    elif not allow_unsigned_ceremony:
        fail("production authority requires signed ceremony evidence")
    return {
        "schema": "wuci-production-authority-verification-v1",
        "authority_sha256": authority_sha256,
        "authority_id": fields["authority-id"],
        "group_public_key_sha256": sha256_bytes(bytes.fromhex(fields["group-public-key"])),
        "allow_open": fields["allow-open"] == "true",
        "allow_release": fields["allow-release"] == "true",
        "allow_trust": fields["allow-trust"] == "true",
        "allow_publish": fields["allow-publish"] == "true",
        "ceremony_sha256": sha256_file(ceremony_path, "production authority ceremony"),
        "ceremony_id": ceremony["ceremony_id"],
        "ceremony_signature_verified": signature_verified,
        "production_authority_verified": True,
        "non_claims": [
            "production authority does not imply runtime sandboxing",
            "production authority does not imply quantum safety",
            "production authority does not replace independent cryptographic audit",
        ],
    }


def run_emit_root(args: argparse.Namespace) -> int:
    group_public_key = args.group_public_key
    validate_compressed_secp256k1(group_public_key)
    if args.allow_trust or args.allow_publish:
        fail("production trust/publish authority requires assembly Gate enforcement first")
    if not (args.allow_open or args.allow_release):
        fail("emit-root requires --allow-open or --allow-release")
    out = Path(args.out)
    reject_fixture_output_path(out)
    text = canonical_authority_text(
        group_public_key=group_public_key,
        allow_open=args.allow_open,
        allow_release=args.allow_release,
        allow_trust=args.allow_trust,
        allow_publish=args.allow_publish,
    )
    write_text_new(out, text, "production authority root", mode=0o644)
    if not args.quiet:
        print(f"wrote production authority root: {out}")
    return 0


def run_ceremony(args: argparse.Namespace) -> int:
    authority_path = Path(args.authority)
    reject_fixture_path(authority_path)
    fields = parse_authority(read_ascii(authority_path, "production authority root", max_bytes=64 * 1024))
    if fields["production"] != "true":
        fail("production authority must set production: true")
    threshold = int(args.threshold)
    signer_count = int(args.signer_count)
    if threshold < 2 or signer_count < threshold:
        fail("ceremony requires signer_count >= threshold >= 2")
    created_utc = args.created_utc
    if created_utc is None:
        created_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if UTC_RE.fullmatch(created_utc) is None:
        fail("--created-utc must be YYYY-MM-DDTHH:MM:SSZ")
    if CEREMONY_ID_RE.fullmatch(args.ceremony_id) is None:
        fail("--ceremony-id must be a stable lowercase id")
    policy_path = Path(args.policy)
    authority_sha256 = sha256_file(authority_path, "production authority root")
    reviewed_policy_sha256 = sha256_file(policy_path, "production authority policy")
    value = {
        "schema": "wuci-production-authority-ceremony-v1",
        "authority_id": fields["authority-id"],
        "authority_sha256": authority_sha256,
        "ceremony_id": args.ceremony_id,
        "ceremony_inputs_sha256": ceremony_inputs_sha256(
            authority_sha256=authority_sha256,
            authority_id_value=fields["authority-id"],
            group_public_key=fields["group-public-key"],
            reviewed_policy_sha256=reviewed_policy_sha256,
            threshold=threshold,
            signer_count=signer_count,
        ),
        "created_utc": created_utc,
        "fixture_material_used": False,
        "group_public_key_sha256": sha256_bytes(bytes.fromhex(fields["group-public-key"])),
        "operator": args.operator,
        "reviewed_policy_sha256": reviewed_policy_sha256,
        "root_signature_required": True,
        "signer_count": signer_count,
        "threshold": threshold,
        "non_claims": [
            "ceremony evidence is not valid for production until signed by an external ceremony root",
            "ceremony evidence does not imply runtime sandboxing or quantum safety",
        ],
    }
    write_json_new(Path(args.out), value, "production authority ceremony", mode=0o644)
    if not args.quiet:
        print(f"wrote production authority ceremony: {args.out}")
    return 0


def run_sign_ceremony(args: argparse.Namespace) -> int:
    sign_ssh_message(
        message_path=Path(args.ceremony),
        signing_key=Path(args.signing_key).expanduser(),
        root_key=Path(args.ceremony_root_key),
        signature_path=Path(args.signature),
        ssh_keygen=args.ssh_keygen,
    )
    if not args.quiet:
        print(f"wrote production authority ceremony signature: {args.signature}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    if args.ceremony is None:
        reject_fixture_path(Path(args.authority))
        fail("production authority requires key ceremony evidence")
    result = verify_authority(
        authority_path=Path(args.authority),
        ceremony_path=Path(args.ceremony),
        ceremony_root_key=Path(args.ceremony_root_key) if args.ceremony_root_key else None,
        ceremony_signature=Path(args.ceremony_signature) if args.ceremony_signature else None,
        policy_path=Path(args.policy),
        ssh_keygen=args.ssh_keygen,
        allow_unsigned_ceremony=args.allow_unsigned_ceremony,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        print("wuci production authority: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify non-fixture WUCI production authority evidence.")
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit-root")
    emit.add_argument("--group-public-key", required=True)
    emit.add_argument("--allow-open", action="store_true")
    emit.add_argument("--allow-release", action="store_true")
    emit.add_argument("--allow-trust", action="store_true")
    emit.add_argument("--allow-publish", action="store_true")
    emit.add_argument("--out", required=True)
    emit.add_argument("--quiet", action="store_true")
    emit.set_defaults(func=run_emit_root)

    ceremony = sub.add_parser("ceremony")
    ceremony.add_argument("--authority", required=True)
    ceremony.add_argument("--operator", required=True)
    ceremony.add_argument("--ceremony-id", required=True)
    ceremony.add_argument("--threshold", required=True, type=int)
    ceremony.add_argument("--signer-count", required=True, type=int)
    ceremony.add_argument("--created-utc")
    ceremony.add_argument("--policy", default=str(POLICY))
    ceremony.add_argument("--out", required=True)
    ceremony.add_argument("--quiet", action="store_true")
    ceremony.set_defaults(func=run_ceremony)

    sign = sub.add_parser("sign-ceremony")
    sign.add_argument("--ceremony", required=True)
    sign.add_argument("--signing-key", required=True)
    sign.add_argument("--ceremony-root-key", required=True)
    sign.add_argument("--signature", required=True)
    sign.add_argument("--ssh-keygen")
    sign.add_argument("--quiet", action="store_true")
    sign.set_defaults(func=run_sign_ceremony)

    verify = sub.add_parser("verify")
    verify.add_argument("--authority", required=True)
    verify.add_argument("--ceremony")
    verify.add_argument("--ceremony-root-key")
    verify.add_argument("--ceremony-signature")
    verify.add_argument("--policy", default=str(POLICY))
    verify.add_argument("--ssh-keygen")
    verify.add_argument("--allow-unsigned-ceremony", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        wuci_safeio.SafeIOError,
        ProductionAuthorityError,
    ) as exc:
        print(f"wuci production authority: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
