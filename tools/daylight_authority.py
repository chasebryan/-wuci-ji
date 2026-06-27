#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import wuci_production_authority
import wuci_safeio


EVIDENCE_SCHEMA = "daylight-v06-authority-evidence-v1"
VERIFY_SCHEMA = "daylight-v06-authority-verification-v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE_KEYS = {
    "schema",
    "subject",
    "fixture_material_used",
    "external_public_precheck_evidence",
    "network_required",
    "offensive_tooling_included",
    "reviewed_commit",
    "production_authority",
    "public_authority_predicates",
    "public_authority_proofs",
    "non_claims",
}
PRODUCTION_AUTHORITY_KEYS = {
    "authority",
    "ceremony",
    "ceremony_root_key",
    "ceremony_signature",
}
MISSING_PROOF_KEYS = {"status", "reason"}
VERIFIED_PROOF_KEYS = {"status", "evidence", "evidence_sha256", "verification_command"}
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_PUBLIC_AUTHORITY_PREDICATES = (
    "certificate",
    "revocation",
    "transparency_log",
    "install",
    "witness",
    "publish",
    "trust",
)


class DaylightAuthorityError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise DaylightAuthorityError(message)


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
        raise DaylightAuthorityError(str(exc)) from exc


def read_json(path: Path, context: str) -> Any:
    try:
        return json.loads(read_bytes(path, context, max_bytes=512 * 1024).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise DaylightAuthorityError(f"{context} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise DaylightAuthorityError(f"{context} is not valid JSON: {exc.msg}") from exc


def sha256_file(path: Path, context: str) -> str:
    digest = hashlib.sha256()
    digest.update(read_bytes(path, context))
    return digest.hexdigest()


def write_json_new(path: Path, value: dict[str, Any], context: str) -> None:
    try:
        wuci_safeio.write_json_new(path, value, context, mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise DaylightAuthorityError(str(exc)) from exc


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


def resolve_manifest_path(base: Path, value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty path")
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path


def validate_predicates(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        fail("public_authority_predicates must be an object")
    result: dict[str, bool] = {}
    for name in REQUIRED_PUBLIC_AUTHORITY_PREDICATES:
        item = value.get(name)
        if not isinstance(item, bool):
            fail(f"public authority predicate must be boolean: {name}")
        result[name] = item
    unexpected = sorted(set(value).difference(REQUIRED_PUBLIC_AUTHORITY_PREDICATES))
    if unexpected:
        fail("unexpected public authority predicates: " + ", ".join(unexpected))
    return result


def resolve_relative_path(base: Path, value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"{context} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        fail(f"{context} must stay under the Daylight authority evidence directory")
    try:
        return wuci_safeio.require_under_directory(base / path, base, context)
    except wuci_safeio.SafeIOError as exc:
        raise DaylightAuthorityError(str(exc)) from exc


def validate_predicate_proofs(
    *,
    value: Any,
    predicates: dict[str, bool],
    base: Path,
    repo: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, bool], list[str]]:
    if not isinstance(value, dict):
        fail("public_authority_proofs must be an object")
    unexpected = sorted(set(value).difference(REQUIRED_PUBLIC_AUTHORITY_PREDICATES))
    if unexpected:
        fail("unexpected public authority proof predicates: " + ", ".join(unexpected))
    makefile = (repo / "Makefile").read_text(encoding="utf-8")
    proofs: dict[str, dict[str, Any]] = {}
    bound: dict[str, bool] = {}
    blockers: list[str] = []
    for name in REQUIRED_PUBLIC_AUTHORITY_PREDICATES:
        proof = value.get(name)
        if not isinstance(proof, dict):
            fail(f"public authority proof must be an object: {name}")
        status = proof.get("status")
        if status == "missing":
            unexpected_keys = sorted(set(proof).difference(MISSING_PROOF_KEYS))
            if unexpected_keys:
                fail(f"unexpected missing proof fields for {name}: " + ", ".join(unexpected_keys))
            if not isinstance(proof.get("reason"), str) or not proof["reason"]:
                fail(f"missing public authority proof reason is required: {name}")
            proofs[name] = {"status": "missing", "reason": proof["reason"]}
            bound[name] = False
        elif status == "verified":
            unexpected_keys = sorted(set(proof).difference(VERIFIED_PROOF_KEYS))
            if unexpected_keys:
                fail(f"unexpected verified proof fields for {name}: " + ", ".join(unexpected_keys))
            evidence_path = resolve_relative_path(base, proof.get("evidence"), f"{name} public authority proof")
            expected_sha256 = proof.get("evidence_sha256")
            if not isinstance(expected_sha256, str) or HEX64_RE.fullmatch(expected_sha256) is None:
                fail(f"{name} public authority proof evidence_sha256 must be lowercase SHA-256")
            actual_sha256 = sha256_file(evidence_path, f"{name} public authority proof")
            if actual_sha256 != expected_sha256:
                fail(f"{name} public authority proof digest mismatch")
            command = proof.get("verification_command")
            if not isinstance(command, str) or not command.startswith("make "):
                fail(f"{name} public authority proof verification_command must be a make target")
            target = command.removeprefix("make ")
            if f"{target}:" not in makefile:
                fail(f"{name} public authority proof verification target is missing: {target}")
            proofs[name] = {
                "status": "verified",
                "evidence": proof["evidence"],
                "evidence_sha256": expected_sha256,
                "verification_command": command,
            }
            bound[name] = True
        else:
            fail(f"unsupported public authority proof status for {name}")
        if predicates[name] and not bound[name]:
            blockers.append(f"public authority predicate proof missing: {name}")
    return proofs, bound, blockers


def verify_daylight_authority(
    *,
    evidence_path: Path,
    repo: Path,
    ssh_keygen: str | None,
    require_integrated: bool,
) -> dict[str, Any]:
    evidence = read_json(evidence_path, "Daylight authority evidence")
    if not isinstance(evidence, dict):
        fail("Daylight authority evidence must be a JSON object")
    unexpected_evidence_keys = sorted(set(evidence).difference(EVIDENCE_KEYS))
    if unexpected_evidence_keys:
        fail("unexpected Daylight authority evidence fields: " + ", ".join(unexpected_evidence_keys))
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        fail("unsupported Daylight authority evidence schema")
    if evidence.get("subject") != "Daylight_v0.6":
        fail("Daylight authority evidence subject mismatch")
    if evidence.get("fixture_material_used") is not False:
        fail("Daylight authority evidence must reject fixture material")
    if evidence.get("external_public_precheck_evidence") is not False:
        fail("Daylight authority evidence must not rely on external public precheck evidence")
    if evidence.get("network_required") is not False:
        fail("Daylight authority verification must not require network")
    if evidence.get("offensive_tooling_included") is not False:
        fail("Daylight authority evidence must not include offensive tooling")
    if not isinstance(evidence.get("reviewed_commit"), str) or COMMIT_RE.fullmatch(evidence["reviewed_commit"]) is None:
        fail("reviewed_commit must be a full lowercase git commit")
    if evidence["reviewed_commit"] != current_git_commit(repo):
        fail("reviewed_commit does not match current HEAD")
    base = evidence_path.parent
    predicates = validate_predicates(evidence.get("public_authority_predicates"))
    predicate_proofs, predicate_proofs_bound, proof_blockers = validate_predicate_proofs(
        value=evidence.get("public_authority_proofs"),
        predicates=predicates,
        base=base,
        repo=repo,
    )
    production = evidence.get("production_authority")
    if not isinstance(production, dict):
        fail("production_authority must be an object")
    unexpected_production_keys = sorted(set(production).difference(PRODUCTION_AUTHORITY_KEYS))
    if unexpected_production_keys:
        fail("unexpected production_authority fields: " + ", ".join(unexpected_production_keys))
    try:
        authority = wuci_production_authority.verify_authority(
            authority_path=resolve_manifest_path(base, production.get("authority"), "production authority root"),
            ceremony_path=resolve_manifest_path(base, production.get("ceremony"), "production authority ceremony"),
            ceremony_root_key=resolve_manifest_path(
                base,
                production.get("ceremony_root_key"),
                "production authority ceremony root key",
            ),
            ceremony_signature=resolve_manifest_path(
                base,
                production.get("ceremony_signature"),
                "production authority ceremony signature",
            ),
            policy_path=repo / "docs" / "wuci_production_authority_policy.json",
            ssh_keygen=ssh_keygen,
            allow_unsigned_ceremony=False,
        )
    except wuci_production_authority.ProductionAuthorityError as exc:
        raise DaylightAuthorityError(str(exc)) from exc

    integrated_predicates = all(predicates.values()) and all(predicate_proofs_bound.values())
    authority_supports_public_gate = (
        authority["allow_open"]
        and authority["allow_release"]
        and authority["allow_trust"]
        and authority["allow_publish"]
    )
    integrated_public_authority = integrated_predicates and authority_supports_public_gate
    remaining_blockers = [f"public authority predicate missing: {name}" for name, ok in predicates.items() if not ok]
    remaining_blockers.extend(proof_blockers)
    if not authority["allow_trust"]:
        remaining_blockers.append("signed production authority must support trust authority")
    if not authority["allow_publish"]:
        remaining_blockers.append("signed production authority must support publish authority")
    if require_integrated and not integrated_public_authority:
        missing = [name for name, ok in predicates.items() if not ok]
        missing.extend([f"{name}-proof" for name, ok in predicate_proofs_bound.items() if predicates[name] and not ok])
        if not authority["allow_trust"]:
            missing.append("trust-authority")
        if not authority["allow_publish"]:
            missing.append("publish-authority")
        fail("Daylight integrated public authority is incomplete: " + ", ".join(missing))

    return {
        "schema": VERIFY_SCHEMA,
        "subject": "Daylight_v0.6",
        "authority_sha256": authority["authority_sha256"],
        "ceremony_sha256": authority["ceremony_sha256"],
        "reviewed_commit": evidence["reviewed_commit"],
        "signed_wuci_authority_verified": True,
        "public_authority_predicates": predicates,
        "public_authority_proofs": predicate_proofs,
        "predicate_proofs_bound": predicate_proofs_bound,
        "integrated_predicates": integrated_predicates,
        "authority_supports_public_gate": authority_supports_public_gate,
        "integrated_public_authority": integrated_public_authority,
        "production_authority_for_daylight": integrated_public_authority,
        "remaining_blockers": remaining_blockers,
        "non_claims": [
            "candidate authority evidence does not claim runtime containment",
            "candidate authority evidence does not claim whole-system post-quantum safety",
            "candidate authority evidence does not replace external review",
        ],
    }


def run_verify(args: argparse.Namespace) -> int:
    result = verify_daylight_authority(
        evidence_path=Path(args.evidence),
        repo=Path(args.repo).resolve(),
        ssh_keygen=args.ssh_keygen,
        require_integrated=args.require_integrated,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        print("Daylight authority evidence: PASS")
    return 0


def run_emit_candidate(args: argparse.Namespace) -> int:
    value = {
        "schema": EVIDENCE_SCHEMA,
        "subject": "Daylight_v0.6",
        "fixture_material_used": False,
        "external_public_precheck_evidence": False,
        "network_required": False,
        "offensive_tooling_included": False,
        "reviewed_commit": args.reviewed_commit or current_git_commit(Path(args.repo).resolve()),
        "production_authority": {
            "authority": args.authority,
            "ceremony": args.ceremony,
            "ceremony_root_key": args.ceremony_root_key,
            "ceremony_signature": args.ceremony_signature,
        },
        "public_authority_predicates": {
            "certificate": args.certificate,
            "revocation": args.revocation,
            "transparency_log": args.transparency_log,
            "install": args.install,
            "witness": args.witness,
            "publish": args.publish,
            "trust": args.trust,
        },
        "public_authority_proofs": {
            name: {
                "status": "missing",
                "reason": "no integrated Daylight public-authority proof artifact supplied",
            }
            for name in REQUIRED_PUBLIC_AUTHORITY_PREDICATES
        },
        "non_claims": [
            "candidate authority evidence is not integrated public authority unless every predicate is true, proof-bound, and signed authority supports publish and trust",
            "candidate authority evidence does not claim runtime containment",
            "candidate authority evidence does not claim whole-system post-quantum safety",
        ],
    }
    write_json_new(Path(args.out), value, "Daylight authority evidence")
    if not args.quiet:
        print(f"wrote Daylight authority evidence: {args.out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Daylight v0.6 public-authority evidence.")
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit-candidate")
    emit.add_argument("--repo", default=".")
    emit.add_argument("--authority", required=True)
    emit.add_argument("--ceremony", required=True)
    emit.add_argument("--ceremony-root-key", required=True)
    emit.add_argument("--ceremony-signature", required=True)
    emit.add_argument("--reviewed-commit")
    for name in REQUIRED_PUBLIC_AUTHORITY_PREDICATES:
        emit.add_argument(f"--{name.replace('_', '-')}", action="store_true")
    emit.add_argument("--out", required=True)
    emit.add_argument("--quiet", action="store_true")
    emit.set_defaults(func=run_emit_candidate)

    verify = sub.add_parser("verify")
    verify.add_argument("--repo", default=".")
    verify.add_argument("--evidence", required=True)
    verify.add_argument("--ssh-keygen")
    verify.add_argument("--require-integrated", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.add_argument("--quiet", action="store_true")
    verify.set_defaults(func=run_verify)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, UnicodeDecodeError, DaylightAuthorityError) as exc:
        print(f"Daylight authority: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
