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
PACKET = REPO_ROOT / "daylight-equation" / "evidence" / "daylight-v06-external-review-packet.v1.json"
EVIDENCE_SCHEMA = "daylight-v06-external-review-v1"
SET_SCHEMA = "daylight-v06-external-review-set-v1"
VERIFY_SCHEMA = "daylight-v06-external-review-verification-v1"
SIGNATURE_IDENTITY = "daylight-v06-external-review"
SIGNATURE_NAMESPACE = "daylight-v06-external-review-v1"
REQUIRED_SCOPES = {
    "formal-model",
    "provider-backed-vectors",
    "cryptographic-boundary",
    "production-authority-blockers",
    "claim-discipline",
}
REVIEW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX96_RE = re.compile(r"^[0-9a-f]{96}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


class DaylightReviewError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise DaylightReviewError(message)


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
        raise DaylightReviewError(str(exc)) from exc


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
        raise DaylightReviewError(str(exc)) from exc


def read_json(path: Path, context: str) -> Any:
    try:
        return json.loads(read_bytes(path, context, max_bytes=512 * 1024).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise DaylightReviewError(f"{context} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise DaylightReviewError(f"{context} is not valid JSON: {exc.msg}") from exc


def write_json_new(path: Path, value: dict[str, Any], context: str) -> None:
    try:
        wuci_safeio.write_json_new(path, value, context, mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise DaylightReviewError(str(exc)) from exc


def write_bytes_new(path: Path, data: bytes, context: str) -> None:
    try:
        wuci_safeio.write_new_bytes(path, data, context, mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise DaylightReviewError(str(exc)) from exc


def sha_file(path: Path, algorithm: str, context: str) -> str:
    digest = hashlib.new(algorithm)
    digest.update(read_bytes(path, context))
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
        fail("could not read current git commit: " + (proc.stderr or proc.stdout).strip())
    commit = proc.stdout.strip()
    if COMMIT_RE.fullmatch(commit) is None:
        fail("current git commit is not a full lowercase SHA-1")
    return commit


def validate_digest(value: Any, pattern: re.Pattern[str], context: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{context} must be lowercase hex")
    return value


def validate_scope(value: Any) -> list[str]:
    if not isinstance(value, list):
        fail("review scope must be a list")
    scopes: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            fail("review scope entries must be non-empty strings")
        scopes.append(item)
    missing = sorted(REQUIRED_SCOPES.difference(scopes))
    if missing:
        fail("review scope missing required entries: " + ", ".join(missing))
    return scopes


def ssh_keygen_path(override: str | None) -> str:
    if override:
        path = Path(override)
        if "\0" in override or not path.is_absolute() or not path.exists():
            fail("--ssh-keygen must be an existing absolute path")
        return str(path)
    found = shutil.which("ssh-keygen")
    if not found:
        fail("ssh-keygen not found on PATH")
    return found


def read_public_key_line(path: Path) -> str:
    key_line = read_ascii(path, "Daylight external review root key", max_bytes=8192).strip()
    if not key_line.startswith(("ssh-ed25519 ", "sk-ssh-ed25519@openssh.com ")):
        fail("review root key must be an OpenSSH Ed25519 public key")
    return key_line


def verify_ssh_signature(
    *,
    message: bytes,
    root_key: Path,
    signature: Path,
    ssh_keygen: str | None,
) -> None:
    read_bytes(signature, "Daylight external review signature", max_bytes=65536)
    key_line = read_public_key_line(root_key)
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="daylight-review-signers-") as tmp:
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
        fail(f"Daylight external review signature verification failed: {detail}")


def sign_ssh_message(
    *,
    evidence_path: Path,
    signing_key: Path,
    root_key: Path,
    signature_path: Path,
    ssh_keygen: str | None,
) -> None:
    try:
        wuci_safeio.require_private_file_mode(signing_key, "Daylight external review signing key")
    except wuci_safeio.SafeIOError as exc:
        raise DaylightReviewError(str(exc)) from exc
    message = read_bytes(evidence_path, "Daylight external review evidence", max_bytes=512 * 1024)
    read_public_key_line(root_key)
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="daylight-review-sign-") as tmp:
        sign_input = Path(tmp) / "review.json"
        sign_input.write_bytes(message)
        proc = subprocess.run(
            [ssh, "-Y", "sign", "-f", str(signing_key), "-n", SIGNATURE_NAMESPACE, str(sign_input)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
            fail(f"Daylight external review signing failed: {detail}")
        generated = sign_input.with_suffix(sign_input.suffix + ".sig")
        signature_bytes = read_bytes(generated, "generated Daylight review signature", max_bytes=65536)
        verify_path = Path(tmp) / "review.json.sig.verify"
        verify_path.write_bytes(signature_bytes)
        verify_ssh_signature(message=message, root_key=root_key, signature=verify_path, ssh_keygen=ssh)
    write_bytes_new(signature_path, signature_bytes, "Daylight external review signature")


def validate_evidence(*, evidence_path: Path, report_path: Path, repo: Path) -> dict[str, Any]:
    evidence = read_json(evidence_path, "Daylight external review evidence")
    if not isinstance(evidence, dict):
        fail("Daylight external review evidence must be a JSON object")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        fail("unsupported Daylight external review evidence schema")
    if evidence.get("subject") != "Daylight_v0.6":
        fail("Daylight external review subject mismatch")
    if not isinstance(evidence.get("reviewer_identity"), str) or not evidence["reviewer_identity"].strip():
        fail("reviewer_identity is required")
    if not isinstance(evidence.get("review_id"), str) or REVIEW_ID_RE.fullmatch(evidence["review_id"]) is None:
        fail("review_id must be a stable lowercase id")
    if not isinstance(evidence.get("completed_utc"), str) or UTC_RE.fullmatch(evidence["completed_utc"]) is None:
        fail("completed_utc must be YYYY-MM-DDTHH:MM:SSZ")
    if evidence.get("external_review") is not True:
        fail("external review evidence must set external_review true")
    if evidence.get("independent_reviewer") is not True:
        fail("external review evidence must set independent_reviewer true")
    if evidence.get("production_blocking_findings_closed") is not True:
        fail("external review evidence must close production-blocking findings")
    if evidence.get("fixture_material_used") is not False:
        fail("external review evidence must reject fixture material")
    if evidence.get("network_required") is not False:
        fail("external review verification must not require network")
    if evidence.get("offensive_tooling_included") is not False:
        fail("external review evidence must not include offensive tooling")
    if evidence.get("signature_required") is not True:
        fail("external review evidence must require a root signature")
    if evidence.get("signature_namespace") != SIGNATURE_NAMESPACE:
        fail("external review signature namespace mismatch")
    if not isinstance(evidence.get("reviewed_commit"), str) or COMMIT_RE.fullmatch(evidence["reviewed_commit"]) is None:
        fail("reviewed_commit must be a full lowercase git commit")
    if evidence["reviewed_commit"] != current_git_commit(repo):
        fail("reviewed_commit does not match current HEAD")

    validate_scope(evidence.get("scope"))
    packet_sha256 = sha_file(PACKET, "sha256", "Daylight external review packet")
    if evidence.get("review_packet_sha256") != packet_sha256:
        fail("review packet SHA-256 mismatch")
    report_sha256 = sha_file(report_path, "sha256", "Daylight external review report")
    report_sha384 = sha_file(report_path, "sha384", "Daylight external review report")
    report_sha512 = sha_file(report_path, "sha512", "Daylight external review report")
    if validate_digest(evidence.get("report_sha256"), HEX64_RE, "report_sha256") != report_sha256:
        fail("review report SHA-256 mismatch")
    if validate_digest(evidence.get("report_sha384"), HEX96_RE, "report_sha384") != report_sha384:
        fail("review report SHA-384 mismatch")
    if validate_digest(evidence.get("report_sha512"), HEX128_RE, "report_sha512") != report_sha512:
        fail("review report SHA-512 mismatch")
    return evidence


def verify_review(
    *,
    evidence_path: Path,
    report_path: Path,
    review_root_key: Path | None,
    signature: Path | None,
    repo: Path,
    ssh_keygen: str | None = None,
    allow_unsigned_review: bool = False,
) -> dict[str, Any]:
    evidence = validate_evidence(evidence_path=evidence_path, report_path=report_path, repo=repo)
    signature_verified = False
    root_key_sha256 = None
    if review_root_key is not None or signature is not None:
        if review_root_key is None or signature is None:
            fail("external review signature verification requires root key and signature")
        verify_ssh_signature(
            message=read_bytes(evidence_path, "Daylight external review evidence", max_bytes=512 * 1024),
            root_key=review_root_key,
            signature=signature,
            ssh_keygen=ssh_keygen,
        )
        signature_verified = True
        root_key_sha256 = sha_file(review_root_key, "sha256", "Daylight external review root key")
    elif not allow_unsigned_review:
        fail("score use requires signed Daylight external review evidence")
    return {
        "review_id": evidence["review_id"],
        "reviewer_identity": evidence["reviewer_identity"],
        "completed_utc": evidence["completed_utc"],
        "evidence_sha256": sha_file(evidence_path, "sha256", "Daylight external review evidence"),
        "report_sha256": evidence["report_sha256"],
        "review_packet_sha256": evidence["review_packet_sha256"],
        "reviewed_commit": evidence["reviewed_commit"],
        "root_key_sha256": root_key_sha256,
        "scope": evidence["scope"],
        "signature_verified": signature_verified,
    }


def resolve_manifest_path(base: Path, value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{context} must be a portable relative path under the review set manifest")
    try:
        return wuci_safeio.require_under_directory(base / path, base, context)
    except wuci_safeio.SafeIOError as exc:
        raise DaylightReviewError(str(exc)) from exc


def verify_review_set(*, manifest_path: Path, repo: Path, ssh_keygen: str | None = None) -> dict[str, Any]:
    manifest = read_json(manifest_path, "Daylight external review set")
    if not isinstance(manifest, dict):
        fail("Daylight external review set must be a JSON object")
    if manifest.get("schema") != SET_SCHEMA:
        fail("unsupported Daylight external review set schema")
    if manifest.get("subject") != "Daylight_v0.6":
        fail("Daylight external review set subject mismatch")
    reviews = manifest.get("reviews")
    if not isinstance(reviews, list) or len(reviews) != 2:
        fail("Daylight external review set must contain exactly two reviews")
    base = manifest_path.parent
    summaries: list[dict[str, Any]] = []
    for index, entry in enumerate(reviews):
        if not isinstance(entry, dict):
            fail("review set entries must be objects")
        summaries.append(
            verify_review(
                evidence_path=resolve_manifest_path(base, entry.get("evidence"), f"review {index} evidence"),
                report_path=resolve_manifest_path(base, entry.get("report"), f"review {index} report"),
                review_root_key=resolve_manifest_path(base, entry.get("review_root_key"), f"review {index} root key"),
                signature=resolve_manifest_path(base, entry.get("signature"), f"review {index} signature"),
                repo=repo,
                ssh_keygen=ssh_keygen,
            )
        )
    review_ids = {summary["review_id"] for summary in summaries}
    reviewer_identities = {summary["reviewer_identity"] for summary in summaries}
    root_keys = {summary["root_key_sha256"] for summary in summaries}
    if len(review_ids) != 2:
        fail("Daylight external review set must use two distinct review ids")
    if len(reviewer_identities) != 2:
        fail("Daylight external review set must use two distinct reviewer identities")
    if len(root_keys) != 2:
        fail("Daylight external review set must use two distinct review root keys")
    return {
        "schema": VERIFY_SCHEMA,
        "subject": "Daylight_v0.6",
        "external_review_set_verified": True,
        "review_count": 2,
        "reviewed_commit": summaries[0]["reviewed_commit"],
        "review_packet_sha256": summaries[0]["review_packet_sha256"],
        "reviews": summaries,
        "external_review_claim_ready": True,
        "non_claims": [
            "verified external reviews do not create production authority",
            "verified external reviews do not claim runtime containment",
            "verified external reviews do not claim whole-system post-quantum safety",
        ],
    }


def run_emit(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    completed_utc = args.completed_utc
    if completed_utc is None:
        completed_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if UTC_RE.fullmatch(completed_utc) is None:
        fail("--completed-utc must be YYYY-MM-DDTHH:MM:SSZ")
    if REVIEW_ID_RE.fullmatch(args.review_id) is None:
        fail("--review-id must be a stable lowercase id")
    if not args.reviewer.strip():
        fail("--reviewer is required")
    scope = sorted(set(args.scope or sorted(REQUIRED_SCOPES)))
    value = {
        "schema": EVIDENCE_SCHEMA,
        "subject": "Daylight_v0.6",
        "completed_utc": completed_utc,
        "external_review": True,
        "fixture_material_used": False,
        "independent_reviewer": True,
        "network_required": False,
        "offensive_tooling_included": False,
        "production_blocking_findings_closed": args.production_blocking_findings_closed,
        "report_sha256": sha_file(Path(args.report), "sha256", "Daylight external review report"),
        "report_sha384": sha_file(Path(args.report), "sha384", "Daylight external review report"),
        "report_sha512": sha_file(Path(args.report), "sha512", "Daylight external review report"),
        "review_id": args.review_id,
        "review_packet_sha256": sha_file(PACKET, "sha256", "Daylight external review packet"),
        "reviewed_commit": args.reviewed_commit or current_git_commit(repo),
        "reviewer_identity": args.reviewer,
        "scope": scope,
        "signature_namespace": SIGNATURE_NAMESPACE,
        "signature_required": True,
        "non_claims": [
            "unsigned Daylight external review evidence is not score-usable",
            "Daylight external review evidence does not create production authority",
            "Daylight external review evidence does not imply runtime containment",
        ],
    }
    write_json_new(Path(args.out), value, "Daylight external review evidence")
    if not args.quiet:
        print(f"wrote Daylight external review evidence: {args.out}")
    return 0


def run_sign(args: argparse.Namespace) -> int:
    sign_ssh_message(
        evidence_path=Path(args.evidence),
        signing_key=Path(args.signing_key).expanduser(),
        root_key=Path(args.review_root_key),
        signature_path=Path(args.signature),
        ssh_keygen=args.ssh_keygen,
    )
    if not args.quiet:
        print(f"wrote Daylight external review signature: {args.signature}")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    summary = verify_review(
        evidence_path=Path(args.evidence),
        report_path=Path(args.report),
        review_root_key=Path(args.review_root_key) if args.review_root_key else None,
        signature=Path(args.signature) if args.signature else None,
        repo=Path(args.repo).resolve(),
        ssh_keygen=args.ssh_keygen,
        allow_unsigned_review=args.allow_unsigned_review,
    )
    output = {"schema": VERIFY_SCHEMA, "subject": "Daylight_v0.6", "external_review_verified": True, **summary}
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    elif not args.quiet:
        print("Daylight external review evidence: PASS")
    return 0


def review_set_entry(args: argparse.Namespace, prefix: str) -> dict[str, str]:
    entry = {
        "evidence": getattr(args, f"{prefix}_evidence"),
        "report": getattr(args, f"{prefix}_report"),
        "review_root_key": getattr(args, f"{prefix}_root_key"),
        "signature": getattr(args, f"{prefix}_signature"),
    }
    for name, value in entry.items():
        if not isinstance(value, str) or not value or "\0" in value:
            fail(f"{prefix.replace('_', '-')} {name} must be a non-empty path")
        if Path(value).is_absolute() or ".." in Path(value).parts:
            fail(f"{prefix.replace('_', '-')} {name} must be a portable relative path")
    return entry


def run_emit_set(args: argparse.Namespace) -> int:
    value = {
        "schema": SET_SCHEMA,
        "subject": "Daylight_v0.6",
        "reviews": [
            review_set_entry(args, "review_a"),
            review_set_entry(args, "review_b"),
        ],
        "non_claims": [
            "external review set manifests are not score-usable until verify-set passes",
            "external review set manifests do not create production authority",
            "external review set manifests do not claim runtime containment",
            "external review set manifests do not claim whole-system post-quantum safety",
        ],
    }
    write_json_new(Path(args.out), value, "Daylight external review set")
    if not args.quiet:
        print(f"wrote Daylight external review set manifest: {args.out}")
    return 0


def run_verify_set(args: argparse.Namespace) -> int:
    summary = verify_review_set(
        manifest_path=Path(args.manifest),
        repo=Path(args.repo).resolve(),
        ssh_keygen=args.ssh_keygen,
    )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif not args.quiet:
        print("Daylight external review set: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit, sign, and verify Daylight v0.6 external review evidence.")
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit")
    emit.add_argument("--repo", default=".")
    emit.add_argument("--report", required=True)
    emit.add_argument("--reviewer", required=True)
    emit.add_argument("--review-id", required=True)
    emit.add_argument("--reviewed-commit")
    emit.add_argument("--completed-utc")
    emit.add_argument("--scope", action="append")
    emit.add_argument("--production-blocking-findings-closed", action="store_true")
    emit.add_argument("--out", required=True)
    emit.add_argument("--quiet", action="store_true")
    emit.set_defaults(func=run_emit)

    sign = sub.add_parser("sign-evidence")
    sign.add_argument("--evidence", required=True)
    sign.add_argument("--signing-key", required=True)
    sign.add_argument("--review-root-key", required=True)
    sign.add_argument("--signature", required=True)
    sign.add_argument("--ssh-keygen")
    sign.add_argument("--quiet", action="store_true")
    sign.set_defaults(func=run_sign)

    verify = sub.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--report", required=True)
    verify.add_argument("--review-root-key")
    verify.add_argument("--signature")
    verify.add_argument("--ssh-keygen")
    verify.add_argument("--allow-unsigned-review", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    emit_set = sub.add_parser("emit-set")
    emit_set.add_argument("--review-a-evidence", required=True)
    emit_set.add_argument("--review-a-report", required=True)
    emit_set.add_argument("--review-a-root-key", required=True)
    emit_set.add_argument("--review-a-signature", required=True)
    emit_set.add_argument("--review-b-evidence", required=True)
    emit_set.add_argument("--review-b-report", required=True)
    emit_set.add_argument("--review-b-root-key", required=True)
    emit_set.add_argument("--review-b-signature", required=True)
    emit_set.add_argument("--out", required=True)
    emit_set.add_argument("--quiet", action="store_true")
    emit_set.set_defaults(func=run_emit_set)

    verify_set = sub.add_parser("verify-set")
    verify_set.add_argument("--repo", default=".")
    verify_set.add_argument("--manifest", required=True)
    verify_set.add_argument("--ssh-keygen")
    verify_set.add_argument("--json", action="store_true")
    verify_set.add_argument("--quiet", action="store_true")
    verify_set.set_defaults(func=run_verify_set)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError, DaylightReviewError) as exc:
        print(f"Daylight external review: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
