"""Daylight Horizon Release Gate Alpha."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical_json import json_bytes, load_json_no_floats
from . import horizon_crypto
from . import horizon_policy
from . import proof_atoms
from . import registry
from . import scorecard


RELEASE_VERSION = "daylight-horizon-release-capsule-v0.1"
DEFAULT_STATE = Path(__file__).resolve().parents[1] / "examples" / "state.current.json"
BOUNDARY = {
    "research_alpha": True,
    "production_release_authority": False,
    "production_allowed": False,
    "external_certification_claim": False,
    "runtime_containment_claim": False,
    "whole_system_post_quantum_safety_claim": False,
}


class HorizonReleaseError(ValueError):
    pass


def _safe_artifact(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.exists():
        raise HorizonReleaseError(f"artifact does not exist: {path}")
    if resolved.is_symlink():
        raise HorizonReleaseError(f"refusing symlink artifact: {path}")
    if not resolved.is_file():
        raise HorizonReleaseError(f"artifact is not a regular file: {path}")
    return resolved


def _scorecard_for_state(state_path: Path | str) -> dict[str, Any]:
    return scorecard.build_scorecard_from_paths(
        state_path=state_path,
        fields_path=registry.DEFAULT_FIELDS_PATH,
        proof_atoms_path=proof_atoms.DEFAULT_PROOF_ATOMS_PATH,
    )


def _load_policy(path: Path | str | None, *, mode: str) -> dict[str, Any]:
    if path is None:
        return horizon_policy.policy_for_mode(mode)
    policy = load_json_no_floats(path)
    horizon_policy.validate_policy(policy)
    return horizon_policy.canonical_policy(policy)


def _status_for(mode: str, blockers: list[str]) -> str:
    if blockers:
        return f"{mode}_release_blocked"
    if mode == "research":
        return "research_release_allowed"
    if mode == "declaration":
        return "declaration_release_allowed"
    if mode == "production":
        return "production_release_allowed"
    return "release_allowed"


def prepare_release(
    *,
    artifact_path: Path | str,
    output_path: Path | str | None = None,
    state_path: Path | str = DEFAULT_STATE,
    policy_path: Path | str | None = None,
    mode: str = "research",
) -> dict[str, Any]:
    artifact = _safe_artifact(Path(artifact_path))
    artifact_bytes = artifact.read_bytes()
    artifact_digest = horizon_crypto.sha256_hex(artifact_bytes)
    policy = _load_policy(policy_path, mode=mode)
    card = _scorecard_for_state(state_path)
    policy_blockers = horizon_policy.policy_blockers(card, policy)
    declaration_blockers = scorecard.declaration_blockers(card)
    mode_blockers: list[str] = []
    if mode == "declaration" and card.get("declared") is not True:
        mode_blockers.append("declaration release requires declared=true")
    if mode == "production" and card.get("boundary", {}).get("production_allowed") is not True:
        mode_blockers.append("production release requires production_allowed=true")
    auth_tag = horizon_policy.authorization_tag(
        scorecard=card,
        policy=policy,
        object_type="release",
        artifact_digest=artifact_digest,
    )
    blockers = policy_blockers + mode_blockers
    capsule = {
        "release_version": RELEASE_VERSION,
        "name": "Daylight Horizon Release Capsule",
        "mode": mode,
        "artifact": {
            "name": artifact.name,
            "sha256": artifact_digest,
            "size": len(artifact_bytes),
        },
        "policy": policy,
        "policy_digest": horizon_policy.policy_digest(policy),
        "authorization": {
            "authorization_tag": auth_tag,
            "scorecard_digest": card["scorecard_digest"],
            "event_horizon_score_AM_plus": card["score_AM_plus"],
            "daylight_claim_score_M": horizon_policy.daylight_claim_score_m(card),
            "declared": card["declared"],
            "status": card["status"],
            "fields_digest": card["fields_digest"],
            "proof_atoms_digest": card["proof_atoms_digest"],
            "state_digest": card["state_digest"],
            "fracture_digest": card["fracture_digest"],
        },
        "blocker_vector": {
            "policy_blockers": policy_blockers,
            "declaration_blockers": declaration_blockers,
            "mode_blockers": mode_blockers,
        },
        "release_status": _status_for(mode, blockers),
        "non_claims": [
            "Daylight Horizon Alpha release capsules are research artifacts.",
            "Research release allowed is not production authority.",
            "No external certification, FIPS validation, runtime containment, or whole-system PQ safety is claimed.",
        ],
        "boundary": BOUNDARY,
    }
    capsule["capsule_digest"] = horizon_crypto.sha256_hex(json_bytes({k: v for k, v in capsule.items() if k != "capsule_digest"}))
    out = Path(output_path) if output_path is not None else artifact.with_suffix(artifact.suffix + ".dhr")
    out.write_bytes(json_bytes(capsule))
    return capsule


def _load_capsule(path: Path | str) -> dict[str, Any]:
    capsule = load_json_no_floats(path)
    if not isinstance(capsule, dict):
        raise HorizonReleaseError("release capsule must be an object")
    if capsule.get("release_version") != RELEASE_VERSION:
        raise HorizonReleaseError("unsupported release capsule version")
    stored = capsule.get("capsule_digest")
    body = {key: value for key, value in capsule.items() if key != "capsule_digest"}
    if stored != horizon_crypto.sha256_hex(json_bytes(body)):
        raise HorizonReleaseError("release capsule digest mismatch")
    return capsule


def verify_release(
    *,
    release_path: Path | str,
    artifact_path: Path | str | None = None,
    state_path: Path | str = DEFAULT_STATE,
) -> dict[str, Any]:
    release_path = Path(release_path)
    capsule = _load_capsule(release_path)
    artifact_info = capsule.get("artifact", {})
    if artifact_path is None:
        artifact_path = release_path.parent / artifact_info.get("name", "")
    artifact = _safe_artifact(Path(artifact_path))
    artifact_digest = horizon_crypto.sha256_hex(artifact.read_bytes())
    blockers: list[str] = []
    if artifact_digest != artifact_info.get("sha256"):
        blockers.append("artifact digest mismatch")
    if artifact.stat().st_size != int(artifact_info.get("size", -1)):
        blockers.append("artifact size mismatch")
    policy = capsule.get("policy")
    if not isinstance(policy, dict):
        raise HorizonReleaseError("release capsule missing policy")
    policy = horizon_policy.canonical_policy(policy)
    if capsule.get("policy_digest") != horizon_policy.policy_digest(policy):
        blockers.append("policy digest mismatch")
    card = _scorecard_for_state(state_path)
    blockers.extend(horizon_policy.policy_blockers(card, policy))
    mode = capsule.get("mode", "research")
    if mode == "declaration" and card.get("declared") is not True:
        blockers.append("declaration release requires declared=true")
    if mode == "production" and card.get("boundary", {}).get("production_allowed") is not True:
        blockers.append("production release requires production_allowed=true")
    expected_auth = horizon_policy.authorization_tag(
        scorecard=card,
        policy=policy,
        object_type="release",
        artifact_digest=artifact_info.get("sha256"),
    )
    sealed_auth = capsule.get("authorization", {}).get("authorization_tag")
    if sealed_auth != expected_auth:
        blockers.append("authorization tag mismatch")
    return {
        "verified": not blockers,
        "mode": mode,
        "release_status": _status_for(mode, blockers),
        "blockers": blockers,
        "artifact_sha256": artifact_digest,
        "score_AM_plus": card["score_AM_plus"],
        "declared": card["declared"],
        "boundary": BOUNDARY,
    }


def gate_release(
    *,
    release_path: Path | str,
    artifact_path: Path | str | None = None,
    state_path: Path | str = DEFAULT_STATE,
) -> dict[str, Any]:
    result = verify_release(release_path=release_path, artifact_path=artifact_path, state_path=state_path)
    mode = result["mode"]
    allowed = bool(result["verified"])
    return {
        **result,
        "gate_allowed": allowed,
        "decision": f"{mode}_release_allowed" if allowed else f"{mode}_release_refused",
        "non_claim": "release gate pass is policy-bound; research pass is not production authority",
    }
