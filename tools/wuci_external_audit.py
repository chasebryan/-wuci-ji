#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

import wuci_safeio


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "docs" / "wuci_crypto_audit_policy.json"
TRUSTED_SSH_KEYGEN = Path("/usr/bin/ssh-keygen")
SIGNATURE_IDENTITY = "wuci-external-audit"
SIGNATURE_NAMESPACE = "wuci-external-audit-v1"
EVIDENCE_SCHEMA = "wuci-external-audit-evidence-v1"
VERIFY_SCHEMA = "wuci-external-audit-verification-v1"
REQUIRED_SCOPES = {
    "crypto",
    "pq-verifier",
    "production-authority",
    "release-bundle",
    "runtime-sandbox",
}
AUDIT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX96_RE = re.compile(r"^[0-9a-f]{96}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ExternalAuditError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ExternalAuditError(message)


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
        raise ExternalAuditError(str(exc)) from exc


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
        raise ExternalAuditError(str(exc)) from exc


def read_json(path: Path, context: str) -> Any:
    try:
        return json.loads(read_bytes(path, context, max_bytes=512 * 1024).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ExternalAuditError(f"{context} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ExternalAuditError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_json_new(path: Path, value: dict[str, Any], context: str) -> None:
    try:
        wuci_safeio.write_json_new(path, value, context, mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise ExternalAuditError(str(exc)) from exc


def write_bytes_new(path: Path, data: bytes, context: str) -> None:
    try:
        wuci_safeio.write_new_bytes(path, data, context, mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise ExternalAuditError(str(exc)) from exc


def sha_file(path: Path, algorithm: str, context: str) -> str:
    data = read_bytes(path, context)
    digest = hashlib.new(algorithm)
    digest.update(data)
    return digest.hexdigest()


def current_git_commit(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        fail(f"could not read current git commit: {detail}")
    commit = proc.stdout.strip()
    if COMMIT_RE.fullmatch(commit) is None:
        fail("current git commit is not a full lowercase SHA-1")
    return commit


def ssh_keygen_path(override: str | None) -> str:
    trusted = TRUSTED_SSH_KEYGEN
    try:
        wuci_safeio.lstat_regular_file(
            trusted,
            "trusted ssh-keygen verifier",
            reject_symlink=True,
            reject_hardlink=True,
        )
        trusted_resolved = trusted.resolve(strict=True)
    except (OSError, wuci_safeio.SafeIOError):
        fail(f"trusted ssh-keygen verifier is unavailable: {trusted}")
    if override:
        if "\0" in override:
            fail("ssh-keygen path contains NUL")
        path = Path(override)
        if not path.is_absolute():
            fail("--ssh-keygen must be an absolute path")
        try:
            wuci_safeio.lstat_regular_file(
                path,
                "ssh-keygen verifier",
                reject_symlink=True,
                reject_hardlink=True,
            )
            if path.resolve(strict=True) != trusted_resolved:
                fail(f"--ssh-keygen must resolve to trusted verifier: {trusted}")
        except (OSError, wuci_safeio.SafeIOError) as exc:
            fail(f"ssh-keygen verifier is not a trusted regular file: {path}")  # noqa: B904
    return str(trusted)


def read_public_key_line(path: Path) -> str:
    key_line = read_ascii(path, "external audit root key", max_bytes=8192).strip()
    if not key_line.startswith(("ssh-ed25519 ", "sk-ssh-ed25519@openssh.com ")):
        fail("external audit root key must be an OpenSSH Ed25519 public key")
    return key_line


def verify_ssh_signature(
    *,
    message: bytes,
    root_key: Path,
    signature: Path,
    ssh_keygen: str | None,
) -> None:
    read_bytes(signature, "external audit evidence signature", max_bytes=65536)
    key_line = read_public_key_line(root_key)
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="wuci-external-audit-signers-") as tmp:
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
        fail(f"external audit evidence signature verification failed: {detail}")


def sign_ssh_message(
    *,
    evidence_path: Path,
    signing_key: Path,
    root_key: Path,
    signature_path: Path,
    ssh_keygen: str | None,
) -> None:
    try:
        wuci_safeio.require_private_file_mode(signing_key, "external audit signing key")
    except wuci_safeio.SafeIOError as exc:
        raise ExternalAuditError(str(exc)) from exc
    message = read_bytes(evidence_path, "external audit evidence", max_bytes=512 * 1024)
    read_public_key_line(root_key)
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="wuci-external-audit-sign-") as tmp:
        sign_input = Path(tmp) / "external-audit.json"
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
            fail(f"external audit evidence signing failed: {detail}")
        generated = sign_input.with_suffix(sign_input.suffix + ".sig")
        signature_bytes = read_bytes(generated, "generated external audit signature", max_bytes=65536)
        verify_path = Path(tmp) / "external-audit.json.sig.verify"
        verify_path.write_bytes(signature_bytes)
        verify_ssh_signature(
            message=message,
            root_key=root_key,
            signature=verify_path,
            ssh_keygen=ssh,
        )
    write_bytes_new(signature_path, signature_bytes, "external audit evidence signature")


def validate_digest(value: Any, pattern: re.Pattern[str], context: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{context} must be lowercase hex")
    return value


def validate_scope(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        fail("external audit scope must be a non-empty list")
    scopes: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            fail("external audit scope entries must be non-empty strings")
        scopes.append(item)
    missing = sorted(REQUIRED_SCOPES.difference(scopes))
    if missing:
        fail(f"external audit scope missing required entries: {', '.join(missing)}")
    return scopes


def validate_evidence(
    *,
    evidence_path: Path,
    report_path: Path,
    repo: Path,
) -> dict[str, Any]:
    evidence = read_json(evidence_path, "external audit evidence")
    if not isinstance(evidence, dict):
        fail("external audit evidence must be a JSON object")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        fail("unsupported external audit evidence schema")
    if not isinstance(evidence.get("auditor_identity"), str) or not evidence["auditor_identity"].strip():
        fail("auditor_identity is required")
    if not isinstance(evidence.get("audit_id"), str) or AUDIT_ID_RE.fullmatch(evidence["audit_id"]) is None:
        fail("audit_id must be a stable lowercase id")
    if not isinstance(evidence.get("completed_utc"), str) or UTC_RE.fullmatch(evidence["completed_utc"]) is None:
        fail("completed_utc must be YYYY-MM-DDTHH:MM:SSZ")
    if not isinstance(evidence.get("reviewed_commit"), str) or COMMIT_RE.fullmatch(evidence["reviewed_commit"]) is None:
        fail("reviewed_commit must be a full lowercase git commit")
    if evidence["reviewed_commit"] != current_git_commit(repo):
        fail("external audit evidence reviewed_commit does not match current HEAD")
    if evidence.get("external_audit") is not True:
        fail("external audit evidence must set external_audit true")
    if evidence.get("production_sufficient") is not True:
        fail("external audit evidence must set production_sufficient true")
    if evidence.get("fixture_material_used") is not False:
        fail("external audit evidence must reject fixture material")
    if evidence.get("network_required") is not False:
        fail("external audit verification must not require network")
    if evidence.get("offensive_tooling_included") is not False:
        fail("external audit evidence must not include offensive tooling")
    if evidence.get("signature_required") is not True:
        fail("external audit evidence must require a root signature")
    if evidence.get("signature_namespace") != SIGNATURE_NAMESPACE:
        fail("external audit evidence signature namespace mismatch")
    if evidence.get("finding_disposition") != "all-production-blocking-findings-closed":
        fail("external audit evidence must close production-blocking findings")
    validate_scope(evidence.get("scope"))
    policy_sha256 = sha_file(POLICY, "sha256", "crypto audit policy")
    if evidence.get("reviewed_policy_sha256") != policy_sha256:
        fail("external audit evidence reviewed policy digest mismatch")
    report_sha256 = sha_file(report_path, "sha256", "external audit report")
    report_sha384 = sha_file(report_path, "sha384", "external audit report")
    report_sha512 = sha_file(report_path, "sha512", "external audit report")
    if validate_digest(evidence.get("report_sha256"), HEX64_RE, "report_sha256") != report_sha256:
        fail("external audit report SHA-256 mismatch")
    if validate_digest(evidence.get("report_sha384"), HEX96_RE, "report_sha384") != report_sha384:
        fail("external audit report SHA-384 mismatch")
    if validate_digest(evidence.get("report_sha512"), HEX128_RE, "report_sha512") != report_sha512:
        fail("external audit report SHA-512 mismatch")
    return evidence


def verify_external_audit(
    *,
    evidence_path: Path,
    report_path: Path,
    audit_root_key: Path | None,
    audit_signature: Path | None,
    repo: Path,
    ssh_keygen: str | None = None,
    allow_unsigned_audit: bool = False,
) -> dict[str, Any]:
    evidence = validate_evidence(evidence_path=evidence_path, report_path=report_path, repo=repo)
    signature_verified = False
    if audit_root_key is not None or audit_signature is not None:
        if audit_root_key is None or audit_signature is None:
            fail("external audit signature verification requires both root key and signature")
        verify_ssh_signature(
            message=read_bytes(evidence_path, "external audit evidence", max_bytes=512 * 1024),
            root_key=audit_root_key,
            signature=audit_signature,
            ssh_keygen=ssh_keygen,
        )
        signature_verified = True
    elif not allow_unsigned_audit:
        fail("release use requires signed external audit evidence")
    return {
        "schema": VERIFY_SCHEMA,
        "audit_id": evidence["audit_id"],
        "auditor_identity": evidence["auditor_identity"],
        "completed_utc": evidence["completed_utc"],
        "evidence_sha256": sha_file(evidence_path, "sha256", "external audit evidence"),
        "external_audit_verified": signature_verified,
        "production_sufficient": signature_verified,
        "report_sha256": evidence["report_sha256"],
        "report_sha384": evidence["report_sha384"],
        "report_sha512": evidence["report_sha512"],
        "reviewed_commit": evidence["reviewed_commit"],
        "scope": evidence["scope"],
        "signature_verified": signature_verified,
        "unsigned_local_review_only": not signature_verified,
        "non_claims": [
            "external audit evidence does not by itself create production authority",
            "external audit evidence does not by itself make WUCI-JI quantum-safe",
            "external audit evidence does not replace kernel sandbox proof evidence",
        ],
    }


def run_emit(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    completed_utc = args.completed_utc
    if completed_utc is None:
        completed_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if UTC_RE.fullmatch(completed_utc) is None:
        fail("--completed-utc must be YYYY-MM-DDTHH:MM:SSZ")
    report = Path(args.report)
    scope = sorted(set(args.scope or sorted(REQUIRED_SCOPES)))
    reviewed_commit = args.reviewed_commit or current_git_commit(repo)
    value = {
        "schema": EVIDENCE_SCHEMA,
        "audit_id": args.audit_id,
        "auditor_identity": args.auditor,
        "completed_utc": completed_utc,
        "external_audit": True,
        "finding_disposition": args.finding_disposition,
        "fixture_material_used": False,
        "network_required": False,
        "offensive_tooling_included": False,
        "production_sufficient": args.production_sufficient,
        "report_sha256": sha_file(report, "sha256", "external audit report"),
        "report_sha384": sha_file(report, "sha384", "external audit report"),
        "report_sha512": sha_file(report, "sha512", "external audit report"),
        "reviewed_commit": reviewed_commit,
        "reviewed_policy_sha256": sha_file(POLICY, "sha256", "crypto audit policy"),
        "scope": scope,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signature_required": True,
        "non_claims": [
            "external audit evidence is not release-usable until signed by an external audit root",
            "external audit evidence does not imply quantum safety",
            "external audit evidence does not imply runtime sandboxing without runtime evidence",
        ],
    }
    if AUDIT_ID_RE.fullmatch(args.audit_id) is None:
        fail("--audit-id must be a stable lowercase id")
    if not args.auditor.strip():
        fail("--auditor is required")
    write_json_new(Path(args.out), value, "external audit evidence")
    if not args.quiet:
        print(f"wrote external audit evidence: {args.out}")
    return 0


def run_sign_evidence(args: argparse.Namespace) -> int:
    sign_ssh_message(
        evidence_path=Path(args.evidence),
        signing_key=Path(args.signing_key).expanduser(),
        root_key=Path(args.audit_root_key),
        signature_path=Path(args.signature),
        ssh_keygen=args.ssh_keygen,
    )
    if not args.quiet:
        print(f"wrote external audit evidence signature: {args.signature}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    summary = verify_external_audit(
        evidence_path=Path(args.evidence),
        report_path=Path(args.report),
        audit_root_key=Path(args.audit_root_key) if args.audit_root_key else None,
        audit_signature=Path(args.signature) if args.signature else None,
        repo=Path(args.repo).resolve(),
        ssh_keygen=args.ssh_keygen,
        allow_unsigned_audit=args.allow_unsigned_audit,
    )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif not args.quiet:
        print("wuci external audit evidence: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit, sign, and verify WUCI external audit evidence.")
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit")
    emit.add_argument("--repo", default=".")
    emit.add_argument("--report", required=True)
    emit.add_argument("--auditor", required=True)
    emit.add_argument("--audit-id", required=True)
    emit.add_argument("--reviewed-commit")
    emit.add_argument("--completed-utc")
    emit.add_argument("--scope", action="append")
    emit.add_argument(
        "--finding-disposition",
        default="all-production-blocking-findings-closed",
    )
    emit.add_argument("--production-sufficient", action="store_true")
    emit.add_argument("--out", required=True)
    emit.add_argument("--quiet", action="store_true")
    emit.set_defaults(func=run_emit)

    sign = sub.add_parser("sign-evidence")
    sign.add_argument("--evidence", required=True)
    sign.add_argument("--signing-key", required=True)
    sign.add_argument("--audit-root-key", required=True)
    sign.add_argument("--signature", required=True)
    sign.add_argument("--ssh-keygen")
    sign.add_argument("--quiet", action="store_true")
    sign.set_defaults(func=run_sign_evidence)

    verify = sub.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--report", required=True)
    verify.add_argument("--audit-root-key")
    verify.add_argument("--signature")
    verify.add_argument("--ssh-keygen")
    verify.add_argument("--allow-unsigned-audit", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError, ExternalAuditError) as exc:
        print(f"wuci external audit: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
