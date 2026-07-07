"""Aperture Review Capsule: build, validate, and verify.

The capsule is a deterministic, claim-bounded public review record. Its
digest is derived from canonical JSON (sorted keys, stable separators) with a
domain separator, so any edit to a score, claim, subject digest, manifest
entry, boundary statement, or public-file hash fails verification. Semantic
claim checks run in addition to the digest, so re-digesting an edited capsule
does not launder a forbidden authority claim.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from . import claims
from . import evidence_refs
from . import profile
from .canonical_json import canonical_sha256, load_json_no_floats, reject_floats_recursive
from .pathsafe import (
    PathSafetyError,
    hash_file_dual,
    normalize_rel_path,
    read_public_bytes,
    require_regular_file,
    resolve_under_base,
    sha256_file,
)

SCHEMA_ID = "daylight-v19-aperture-review-capsule"
SCHEMA_VERSION = "0.1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})
D_CAPSULE = "DAYLIGHT-v19-APERTURE-REVIEW-CAPSULE:"
PROJECT = "wuci-ji"
LAYER_NAME = "Wuci-Ji v2 — Aperture Bastion"
GENERATED_BY_PREFIX = "daylight-v19-aperture-bastion/"

CAPSULE_FILENAME = "aperture-review-capsule.v19.json"
SUMS_FILENAME = "SHA256SUMS"

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]

REQUIRED_KEYS = frozenset(
    {
        "schema_id",
        "schema_version",
        "project",
        "layer_name",
        "generated_by",
        "repo_commit",
        "repo_dirty_state",
        "fixture",
        "input_subjects",
        "subject_sha256",
        "subject_sha3_512",
        "subject_size",
        "optional_binaric_vector_digest",
        "optional_transition_ledger_head",
        "optional_meridian_scorecard_digest",
        "optional_event_horizon_scorecard_digest",
        "optional_policy_digest",
        "evidence_refs",
        "public_manifest",
        "allowed_extra_files",
        "public_sha256sums",
        "claim_boundary",
        "non_claims",
        "forbidden_private_material_profile",
        "firewall_result",
        "capsule_digest",
    }
)

EVIDENCE_KINDS = (
    "binaric-vector-chain",
    "event-horizon-scorecard",
    "meridian-scorecard",
    "policy",
    "transition-ledger",
)

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class CapsuleError(ValueError):
    pass


def _require_hex(value: Any, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CapsuleError(f"{name} must be a lowercase hex digest of the expected length")
    return value


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CapsuleError(f"{name} must be a nonnegative integer")
    return value


def _git_state(base_dir: Path) -> tuple[str, str]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=base_dir, capture_output=True, text=True, timeout=30, check=False,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=base_dir, capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown", "unknown"
    if commit.returncode != 0 or status.returncode != 0:
        return "unknown", "unknown"
    sha = commit.stdout.strip()
    if not COMMIT_RE.fullmatch(sha):
        return "unknown", "unknown"
    return sha, ("dirty" if status.stdout.strip() else "clean")


def sums_text_for_manifest(entries: list[dict[str, Any]]) -> str:
    return "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)


def capsule_digest(capsule: dict[str, Any]) -> str:
    reject_floats_recursive(capsule, "capsule")
    body = {key: value for key, value in capsule.items() if key != "capsule_digest"}
    return canonical_sha256(body, D_CAPSULE)


def _manifest_entry(rel_path: str, base_dir: Path, *, max_file_bytes: int) -> tuple[dict[str, Any], list[str]]:
    source = resolve_under_base(rel_path, base_dir)
    data = read_public_bytes(source, rel_path, max_bytes=max_file_bytes)
    reasons = profile.check_path_name(rel_path)
    reasons.extend(profile.check_content(data, rel_path=rel_path))
    entry = {
        "path": rel_path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
    return entry, reasons


def _build_evidence_refs(
    base_dir: Path,
    *,
    binaric_vector_paths: list[str] | None,
    transition_ledger_path: str | None,
    meridian_scorecard_path: str | None,
    event_horizon_scorecard_path: str | None,
    policy_path: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    optional: dict[str, Any] = {
        "optional_binaric_vector_digest": None,
        "optional_transition_ledger_head": None,
        "optional_meridian_scorecard_digest": None,
        "optional_event_horizon_scorecard_digest": None,
        "optional_policy_digest": None,
    }

    def _read(rel_path: str) -> tuple[str, str]:
        normalized = normalize_rel_path(rel_path)
        source = resolve_under_base(normalized, base_dir)
        require_regular_file(source, normalized)
        return normalized, sha256_file(source)

    if binaric_vector_paths:
        normalized_paths: list[str] = []
        digests: list[str] = []
        vectors: list[dict[str, Any]] = []
        for rel_path in binaric_vector_paths:
            normalized, file_sha256 = _read(rel_path)
            normalized_paths.append(normalized)
            digests.append(file_sha256)
            vectors.append(load_json_no_floats(resolve_under_base(normalized, base_dir)))
        head = evidence_refs.check_binaric_vector_chain(vectors)
        refs.append(
            {
                "kind": "binaric-vector-chain",
                "paths": normalized_paths,
                "file_sha256s": digests,
                "head_vector_digest": head,
            }
        )
        optional["optional_binaric_vector_digest"] = head
    if transition_ledger_path is not None:
        normalized, file_sha256 = _read(transition_ledger_path)
        text = resolve_under_base(normalized, base_dir).read_text(encoding="utf-8")
        head = evidence_refs.check_transition_ledger(text)
        refs.append(
            {
                "kind": "transition-ledger",
                "paths": [normalized],
                "file_sha256s": [file_sha256],
                "ledger_head": head,
            }
        )
        optional["optional_transition_ledger_head"] = head
    if meridian_scorecard_path is not None:
        normalized, file_sha256 = _read(meridian_scorecard_path)
        scorecard = load_json_no_floats(resolve_under_base(normalized, base_dir))
        summary = evidence_refs.check_meridian_scorecard(scorecard)
        refs.append(
            {
                "kind": "meridian-scorecard",
                "paths": [normalized],
                "file_sha256s": [file_sha256],
                "final_score_M": summary["final_score_M"],
                "perfect_score_M": summary["perfect_score_M"],
                "open_obligation_count": summary["open_obligation_count"],
            }
        )
        optional["optional_meridian_scorecard_digest"] = file_sha256
    if event_horizon_scorecard_path is not None:
        normalized, file_sha256 = _read(event_horizon_scorecard_path)
        scorecard = load_json_no_floats(resolve_under_base(normalized, base_dir))
        summary = evidence_refs.check_event_horizon_scorecard(scorecard)
        refs.append(
            {
                "kind": "event-horizon-scorecard",
                "paths": [normalized],
                "file_sha256s": [file_sha256],
                "embedded_scorecard_digest": summary["scorecard_digest"],
            }
        )
        optional["optional_event_horizon_scorecard_digest"] = file_sha256
    if policy_path is not None:
        normalized, file_sha256 = _read(policy_path)
        policy = load_json_no_floats(resolve_under_base(normalized, base_dir))
        if not isinstance(policy, dict):
            raise CapsuleError("policy evidence must be a JSON object")
        refs.append({"kind": "policy", "paths": [normalized], "file_sha256s": [file_sha256]})
        optional["optional_policy_digest"] = file_sha256
    refs.sort(key=lambda ref: ref["kind"])
    return refs, optional


def build_capsule(
    *,
    subjects: list[str],
    base_dir: Path | str | None = None,
    public_files: list[str] | None = None,
    allowed_extra_files: list[str] | None = None,
    binaric_vector_paths: list[str] | None = None,
    transition_ledger_path: str | None = None,
    meridian_scorecard_path: str | None = None,
    event_horizon_scorecard_path: str | None = None,
    policy_path: str | None = None,
    fixture: bool = False,
    max_file_bytes: int = profile.DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    base = Path(base_dir).resolve() if base_dir is not None else Path.cwd().resolve()
    if not subjects:
        raise CapsuleError("at least one subject is required")

    subject_entries: list[dict[str, Any]] = []
    seen_subjects: set[str] = set()
    for rel_path in subjects:
        normalized = normalize_rel_path(rel_path)
        if normalized in seen_subjects:
            raise CapsuleError(f"duplicate subject: {normalized}")
        seen_subjects.add(normalized)
        source = resolve_under_base(normalized, base)
        require_regular_file(source, normalized)
        sha256, sha3_512, size = hash_file_dual(source)
        subject_entries.append(
            {
                "subject_path": normalized,
                "subject_sha256": sha256,
                "subject_sha3_512": sha3_512,
                "subject_size_bytes": size,
            }
        )

    refs, optional = _build_evidence_refs(
        base,
        binaric_vector_paths=binaric_vector_paths,
        transition_ledger_path=transition_ledger_path,
        meridian_scorecard_path=meridian_scorecard_path,
        event_horizon_scorecard_path=event_horizon_scorecard_path,
        policy_path=policy_path,
    )

    manifest_inputs = public_files if public_files is not None else [entry["subject_path"] for entry in subject_entries]
    manifest_entries: list[dict[str, Any]] = []
    firewall_reasons: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for rel_path in manifest_inputs:
        normalized = normalize_rel_path(rel_path)
        if normalized in seen_paths:
            raise CapsuleError(f"duplicate public manifest entry: {normalized}")
        seen_paths.add(normalized)
        entry, reasons = _manifest_entry(normalized, base, max_file_bytes=max_file_bytes)
        manifest_entries.append(entry)
        firewall_reasons.extend((normalized, reason) for reason in reasons)
    if firewall_reasons:
        summary = "; ".join(f"{path}: {reason}" for path, reason in firewall_reasons[:5])
        raise CapsuleError(f"pre-publication firewall rejected public manifest input: {summary}")
    manifest_entries.sort(key=lambda entry: entry["path"])

    extras = sorted({normalize_rel_path(name) for name in (allowed_extra_files or [])})
    for name in extras:
        if profile.check_path_name(name):
            raise CapsuleError(f"allowed extra file name violates the firewall profile: {name}")
        if name in seen_paths or name in (CAPSULE_FILENAME, SUMS_FILENAME):
            raise CapsuleError(f"allowed extra file collides with public artifact contents: {name}")

    if fixture:
        repo_commit, repo_dirty_state = "fixture", "fixture"
    else:
        repo_commit, repo_dirty_state = _git_state(base)

    capsule: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "project": PROJECT,
        "layer_name": LAYER_NAME,
        "generated_by": GENERATED_BY_PREFIX + __version__,
        "repo_commit": repo_commit,
        "repo_dirty_state": repo_dirty_state,
        "fixture": fixture,
        "input_subjects": subject_entries,
        "subject_sha256": subject_entries[0]["subject_sha256"],
        "subject_sha3_512": subject_entries[0]["subject_sha3_512"],
        "subject_size": subject_entries[0]["subject_size_bytes"],
        "evidence_refs": refs,
        "public_manifest": manifest_entries,
        "allowed_extra_files": extras,
        "public_sha256sums": hashlib.sha256(sums_text_for_manifest(manifest_entries).encode("utf-8")).hexdigest(),
        "claim_boundary": claims.claim_boundary(),
        "non_claims": claims.non_claims(),
        "forbidden_private_material_profile": {
            "profile_id": profile.PROFILE_ID,
            "profile_digest": profile.PROFILE_DIGEST,
        },
        "firewall_result": {
            "phase": "pre-publication",
            "profile_id": profile.PROFILE_ID,
            "checked_file_count": len(manifest_entries),
            "passed": True,
        },
    }
    capsule.update(optional)
    capsule["capsule_digest"] = capsule_digest(capsule)
    validate_capsule_shape(capsule)
    return capsule


def _validate_subjects(capsule: dict[str, Any]) -> None:
    entries = capsule["input_subjects"]
    if not isinstance(entries, list) or not entries:
        raise CapsuleError("input_subjects must be a non-empty list")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"input_subjects[{index}]"
        if not isinstance(entry, dict) or set(entry) != {
            "subject_path",
            "subject_sha256",
            "subject_sha3_512",
            "subject_size_bytes",
        }:
            raise CapsuleError(f"{label} has an invalid field set")
        normalized = normalize_rel_path(entry["subject_path"])
        if normalized != entry["subject_path"]:
            raise CapsuleError(f"{label}.subject_path is not normalized")
        if normalized in seen:
            raise CapsuleError(f"{label} duplicates subject {normalized}")
        seen.add(normalized)
        _require_hex(entry["subject_sha256"], f"{label}.subject_sha256", HEX64_RE)
        _require_hex(entry["subject_sha3_512"], f"{label}.subject_sha3_512", HEX128_RE)
        _require_int(entry["subject_size_bytes"], f"{label}.subject_size_bytes")
    primary = entries[0]
    if (
        capsule["subject_sha256"] != primary["subject_sha256"]
        or capsule["subject_sha3_512"] != primary["subject_sha3_512"]
        or capsule["subject_size"] != primary["subject_size_bytes"]
    ):
        raise CapsuleError("top-level subject digest fields must match the primary input subject")


def _validate_manifest(capsule: dict[str, Any]) -> None:
    entries = capsule["public_manifest"]
    if not isinstance(entries, list):
        raise CapsuleError("public_manifest must be a list")
    paths: list[str] = []
    for index, entry in enumerate(entries):
        label = f"public_manifest[{index}]"
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise CapsuleError(f"{label} has an invalid field set")
        normalized = normalize_rel_path(entry["path"])
        if normalized != entry["path"]:
            raise CapsuleError(f"{label}.path is not normalized")
        reasons = profile.check_path_name(normalized)
        if reasons:
            raise CapsuleError(f"{label}.path violates the firewall profile: {reasons[0]}")
        if normalized in (CAPSULE_FILENAME, SUMS_FILENAME):
            raise CapsuleError(f"{label}.path collides with reserved public artifact names")
        _require_hex(entry["sha256"], f"{label}.sha256", HEX64_RE)
        _require_int(entry["size_bytes"], f"{label}.size_bytes")
        paths.append(normalized)
    if paths != sorted(paths):
        raise CapsuleError("public_manifest must be sorted by path")
    if len(set(paths)) != len(paths):
        raise CapsuleError("public_manifest paths must be unique")
    extras = capsule["allowed_extra_files"]
    if not isinstance(extras, list):
        raise CapsuleError("allowed_extra_files must be a list")
    for name in extras:
        normalized = normalize_rel_path(name)
        if normalized != name:
            raise CapsuleError("allowed_extra_files entries must be normalized")
        if profile.check_path_name(normalized):
            raise CapsuleError(f"allowed extra file name violates the firewall profile: {name}")
        if normalized in paths or normalized in (CAPSULE_FILENAME, SUMS_FILENAME):
            raise CapsuleError(f"allowed extra file collides with public artifact contents: {name}")
    if extras != sorted(extras) or len(set(extras)) != len(extras):
        raise CapsuleError("allowed_extra_files must be sorted and unique")
    expected_sums = hashlib.sha256(sums_text_for_manifest(entries).encode("utf-8")).hexdigest()
    if capsule["public_sha256sums"] != expected_sums:
        raise CapsuleError("public_sha256sums does not match the public manifest")


def _validate_evidence_refs(capsule: dict[str, Any]) -> None:
    refs = capsule["evidence_refs"]
    if not isinstance(refs, list):
        raise CapsuleError("evidence_refs must be a list")
    kinds: list[str] = []
    by_kind: dict[str, dict[str, Any]] = {}
    for index, ref in enumerate(refs):
        label = f"evidence_refs[{index}]"
        if not isinstance(ref, dict):
            raise CapsuleError(f"{label} must be an object")
        kind = ref.get("kind")
        if kind not in EVIDENCE_KINDS:
            raise CapsuleError(f"{label}.kind is not a supported evidence kind")
        kinds.append(kind)
        by_kind[kind] = ref
        paths = ref.get("paths")
        digests = ref.get("file_sha256s")
        if not isinstance(paths, list) or not paths or not isinstance(digests, list):
            raise CapsuleError(f"{label} paths/file_sha256s malformed")
        if len(paths) != len(digests):
            raise CapsuleError(f"{label} paths and file_sha256s must align")
        for path in paths:
            if normalize_rel_path(path) != path:
                raise CapsuleError(f"{label} paths must be normalized")
        for digest in digests:
            _require_hex(digest, f"{label}.file_sha256s", HEX64_RE)
    if kinds != sorted(kinds) or len(set(kinds)) != len(kinds):
        raise CapsuleError("evidence_refs must be sorted by kind and unique per kind")

    def _expect(kind: str, field: str, optional_key: str) -> None:
        ref = by_kind.get(kind)
        recorded = capsule[optional_key]
        if ref is None:
            if recorded is not None:
                raise CapsuleError(f"{optional_key} set without a matching evidence reference")
            return
        expected = ref.get(field) if field else ref["file_sha256s"][0]
        if not isinstance(expected, str) or not HEX64_RE.fullmatch(expected):
            raise CapsuleError(f"evidence reference {kind} digest field malformed")
        if recorded != expected:
            raise CapsuleError(f"{optional_key} does not match its evidence reference")

    _expect("binaric-vector-chain", "head_vector_digest", "optional_binaric_vector_digest")
    _expect("transition-ledger", "ledger_head", "optional_transition_ledger_head")
    _expect("meridian-scorecard", "", "optional_meridian_scorecard_digest")
    _expect("event-horizon-scorecard", "", "optional_event_horizon_scorecard_digest")
    _expect("policy", "", "optional_policy_digest")
    meridian = by_kind.get("meridian-scorecard")
    if meridian is not None:
        final = _require_int(meridian.get("final_score_M"), "meridian final_score_M")
        perfect = _require_int(meridian.get("perfect_score_M"), "meridian perfect_score_M")
        open_count = _require_int(meridian.get("open_obligation_count"), "meridian open_obligation_count")
        if final >= perfect and open_count > 0:
            raise CapsuleError("perfect meridian score reference with open obligations is contradictory")


def validate_capsule_shape(capsule: dict[str, Any]) -> None:
    if not isinstance(capsule, dict):
        raise CapsuleError("capsule must be a JSON object")
    reject_floats_recursive(capsule, "capsule")
    if capsule.get("schema_id") != SCHEMA_ID:
        raise CapsuleError("unsupported schema_id")
    if capsule.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise CapsuleError("unsupported schema_version")
    if set(capsule) != set(REQUIRED_KEYS):
        unknown = sorted(set(capsule) - REQUIRED_KEYS)
        missing = sorted(REQUIRED_KEYS - set(capsule))
        raise CapsuleError(f"capsule field set invalid (unknown={unknown}, missing={missing})")
    if capsule["project"] != PROJECT:
        raise CapsuleError("unsupported project")
    if capsule["layer_name"] != LAYER_NAME:
        raise CapsuleError("unsupported layer_name")
    generated_by = capsule["generated_by"]
    if not isinstance(generated_by, str) or not generated_by.startswith(GENERATED_BY_PREFIX):
        raise CapsuleError("generated_by malformed")
    if not isinstance(capsule["fixture"], bool):
        raise CapsuleError("fixture must be boolean")
    repo_commit = capsule["repo_commit"]
    repo_dirty_state = capsule["repo_dirty_state"]
    if capsule["fixture"]:
        if repo_commit != "fixture" or repo_dirty_state != "fixture":
            raise CapsuleError("fixture capsules must record fixture repo state")
    else:
        if repo_commit != "unknown" and not COMMIT_RE.fullmatch(str(repo_commit)):
            raise CapsuleError("repo_commit malformed")
        if repo_dirty_state not in ("clean", "dirty", "unknown"):
            raise CapsuleError("repo_dirty_state malformed")
    _validate_subjects(capsule)
    for key in (
        "optional_binaric_vector_digest",
        "optional_transition_ledger_head",
        "optional_meridian_scorecard_digest",
        "optional_event_horizon_scorecard_digest",
        "optional_policy_digest",
    ):
        if capsule[key] is not None:
            _require_hex(capsule[key], key, HEX64_RE)
    _validate_evidence_refs(capsule)
    _validate_manifest(capsule)
    claims.validate_claim_boundary(capsule["claim_boundary"])
    claims.validate_non_claims(capsule["non_claims"])
    profile_ref = capsule["forbidden_private_material_profile"]
    if profile_ref != {"profile_id": profile.PROFILE_ID, "profile_digest": profile.PROFILE_DIGEST}:
        raise CapsuleError("forbidden_private_material_profile does not match the pinned profile")
    firewall_result = capsule["firewall_result"]
    if not isinstance(firewall_result, dict) or set(firewall_result) != {
        "phase",
        "profile_id",
        "checked_file_count",
        "passed",
    }:
        raise CapsuleError("firewall_result has an invalid field set")
    if firewall_result["phase"] != "pre-publication":
        raise CapsuleError("firewall_result phase malformed")
    if firewall_result["profile_id"] != profile.PROFILE_ID:
        raise CapsuleError("firewall_result profile mismatch")
    if firewall_result["passed"] is not True:
        raise CapsuleError("capsule requires a passing pre-publication firewall result")
    if _require_int(firewall_result["checked_file_count"], "firewall_result.checked_file_count") != len(
        capsule["public_manifest"]
    ):
        raise CapsuleError("firewall_result.checked_file_count does not match the public manifest")
    _require_hex(capsule["capsule_digest"], "capsule_digest", HEX64_RE)
    if capsule_digest(capsule) != capsule["capsule_digest"]:
        raise CapsuleError("capsule_digest mismatch")


def load_capsule(path: Path | str) -> dict[str, Any]:
    capsule = load_json_no_floats(path)
    validate_capsule_shape(capsule)
    return capsule


def _recheck_evidence(
    capsule: dict[str, Any],
    base: Path,
    blockers: list[str],
    notes: list[str],
    *,
    require_evidence: bool,
) -> None:
    for ref in capsule["evidence_refs"]:
        kind = ref["kind"]
        sources: list[Path] = []
        missing = False
        for rel_path, expected_sha256 in zip(ref["paths"], ref["file_sha256s"]):
            try:
                source = resolve_under_base(rel_path, base)
            except PathSafetyError as exc:
                blockers.append(f"evidence {kind}: {exc}")
                missing = True
                break
            if not source.exists():
                missing = True
                break
            try:
                require_regular_file(source, rel_path)
            except PathSafetyError as exc:
                blockers.append(f"evidence {kind}: {exc}")
                missing = True
                break
            if sha256_file(source) != expected_sha256:
                blockers.append(f"evidence {kind}: file digest mismatch for {rel_path}")
                missing = True
                break
            sources.append(source)
        perfect_reference = (
            kind == "meridian-scorecard"
            and ref["final_score_M"] >= ref["perfect_score_M"]
        )
        if missing:
            if not any(blocker.startswith(f"evidence {kind}:") for blocker in blockers):
                message = f"evidence {kind}: referenced file not present; digest pinned but not re-checked"
                if require_evidence or perfect_reference:
                    blockers.append(message)
                else:
                    notes.append(message)
            continue
        try:
            if kind == "binaric-vector-chain":
                vectors = [load_json_no_floats(source) for source in sources]
                head = evidence_refs.check_binaric_vector_chain(vectors)
                if head != ref["head_vector_digest"]:
                    blockers.append("evidence binaric-vector-chain: head digest mismatch")
            elif kind == "transition-ledger":
                head = evidence_refs.check_transition_ledger(sources[0].read_text(encoding="utf-8"))
                if head != ref["ledger_head"]:
                    blockers.append("evidence transition-ledger: ledger head mismatch")
            elif kind == "meridian-scorecard":
                summary = evidence_refs.check_meridian_scorecard(load_json_no_floats(sources[0]))
                if (
                    summary["final_score_M"] != ref["final_score_M"]
                    or summary["perfect_score_M"] != ref["perfect_score_M"]
                    or summary["open_obligation_count"] != ref["open_obligation_count"]
                ):
                    blockers.append("evidence meridian-scorecard: recorded score summary mismatch")
            elif kind == "event-horizon-scorecard":
                summary = evidence_refs.check_event_horizon_scorecard(load_json_no_floats(sources[0]))
                if summary["scorecard_digest"] != ref["embedded_scorecard_digest"]:
                    blockers.append("evidence event-horizon-scorecard: embedded digest mismatch")
            elif kind == "policy":
                if not isinstance(load_json_no_floats(sources[0]), dict):
                    blockers.append("evidence policy: policy must be a JSON object")
        except (ValueError, OSError) as exc:
            blockers.append(f"evidence {kind}: {exc}")


def verify_capsule(
    capsule: dict[str, Any],
    *,
    base_dir: Path | str | None = None,
    check_subject_files: bool = True,
    check_public_files: bool = True,
    require_evidence: bool = False,
) -> dict[str, Any]:
    blockers: list[str] = []
    notes: list[str] = []
    recorded_digest = capsule.get("capsule_digest") if isinstance(capsule, dict) else None
    try:
        validate_capsule_shape(capsule)
    except (CapsuleError, claims.ClaimBoundaryError, PathSafetyError, ValueError) as exc:
        blockers.append(str(exc))
        return {
            "verified": False,
            "blockers": blockers,
            "notes": notes,
            "capsule_digest": recorded_digest if isinstance(recorded_digest, str) else None,
        }

    base = Path(base_dir).resolve() if base_dir is not None else Path.cwd().resolve()
    if check_subject_files:
        for entry in capsule["input_subjects"]:
            rel_path = entry["subject_path"]
            try:
                source = resolve_under_base(rel_path, base)
                require_regular_file(source, rel_path)
            except PathSafetyError as exc:
                blockers.append(f"subject {rel_path}: {exc}")
                continue
            sha256, sha3_512, size = hash_file_dual(source)
            if (
                sha256 != entry["subject_sha256"]
                or sha3_512 != entry["subject_sha3_512"]
                or size != entry["subject_size_bytes"]
            ):
                blockers.append(f"subject {rel_path}: digest mismatch")
    else:
        notes.append("subject files not re-checked (explicitly disabled)")

    if check_public_files:
        for entry in capsule["public_manifest"]:
            rel_path = entry["path"]
            try:
                source = resolve_under_base(rel_path, base)
                require_regular_file(source, rel_path)
            except PathSafetyError as exc:
                blockers.append(f"public file {rel_path}: {exc}")
                continue
            if sha256_file(source) != entry["sha256"]:
                blockers.append(f"public file {rel_path}: digest mismatch")
            elif source.stat().st_size != entry["size_bytes"]:
                blockers.append(f"public file {rel_path}: size mismatch")
    else:
        notes.append("public manifest files not re-checked (explicitly disabled)")

    _recheck_evidence(capsule, base, blockers, notes, require_evidence=require_evidence)

    return {
        "verified": not blockers,
        "blockers": blockers,
        "notes": notes,
        "capsule_digest": capsule["capsule_digest"],
    }


def verify_capsule_file(
    path: Path | str,
    *,
    base_dir: Path | str | None = None,
    check_subject_files: bool = True,
    check_public_files: bool = True,
    require_evidence: bool = False,
) -> dict[str, Any]:
    capsule = load_json_no_floats(path)
    return verify_capsule(
        capsule,
        base_dir=base_dir,
        check_subject_files=check_subject_files,
        check_public_files=check_public_files,
        require_evidence=require_evidence,
    )
