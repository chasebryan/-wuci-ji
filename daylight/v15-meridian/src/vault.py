"""Meridian Vault: evidence-gated, fail-closed encryption for any host.

This is the offline, host-side realization of Daylight v15 Meridian. A vault is a
self-contained directory that turns the Meridian Authorized Envelope
(:mod:`src.envelope`) into a usable encrypt/decrypt store for ordinary files and
secrets on a machine the user already runs.

The model, stated honestly:

    A vault binds an *evidence base* (a frozen Daylight v15 ledger + corpus) and
    a *policy* (minimum final score, required closed obligations). Sealing a file
    succeeds only when that evidence re-derives a verifying scorecard satisfying
    the policy. Opening is fail-closed: the bytes come back only when the host's
    Meridian evidence still verifies and still satisfies the sealed policy, and
    the caller holds the vault key.

        NoEvidence -> NoScore -> NoSeal
        NoProof    -> NoClaim -> NoOpen
        ManualScore -> Reject -> NoOpen

The host stays usable exactly as before: a vault is additive and reversible.
Originals are kept by default; nothing about the operating system, boot path, or
existing files is modified. Removing an original is opt-in.

Boundary (no overclaim): the AEAD (:mod:`src.aead`) is a research reference and
is *not* constant-time, this is *not* full-disk encryption, and the vault key is
stored locally unless you choose passphrase mode. What Meridian adds over a plain
encrypted file is the evidence-derived, fail-closed *authorization* layer: data
that refuses to open on a host whose Daylight v15 evidence does not verify.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from . import api
from .corpus import CorpusError
from .daylight_harness import HarnessError
from .envelope import EnvelopeRefused
from .ledger import LedgerError
from .obligations import ObligationError
from .scoring import ScoreError

# Any failure to derive a trustworthy scorecard from the vault's evidence is a
# fail-closed refusal, not an opaque crash: NoEvidence -> NoScore -> NoSeal and
# NoProof -> NoOpen. Tampered or degraded evidence collapses to one signal.
_EVIDENCE_ERRORS = (LedgerError, CorpusError, ObligationError, ScoreError, HarnessError)

VAULT_VERSION = "daylight-v15-meridian-vault-v1"
DEFAULT_VAULT_ROOT = Path(os.environ.get("MERIDIAN_VAULT", str(Path.home() / ".meridian-vault")))
# The shipped seed evidence closes every internal obligation: the honest
# internal ceiling. A vault defaults to that floor so it opens on a faithful
# install and fail-closes the moment the evidence base is degraded.
DEFAULT_MIN_SCORE_M = 998_900
KDF_ITERATIONS = 200_000
KEY_LEN = 32


class VaultError(Exception):
    """Vault could not be created, loaded, or operated as requested."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_private(path: Path, data: bytes) -> None:
    """Write a 0600 file, replacing any existing one, without leaking via umask."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_private(path: Path) -> bytes:
    """Read a private file without following a symlink placed at its path."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _safe_name(original: str) -> str:
    """Deterministic, collision-resistant vault entry name from a source path."""
    base = Path(original).name or "entry"
    base = "".join(ch if (ch.isalnum() or ch in "-._") else "_" for ch in base)
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:12]
    return f"{base}.{digest}"


class Vault:
    """An opened vault: paths, configuration, policy, and registry."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.config_path = self.root / "vault.json"
        self.key_path = self.root / "vault.key"
        self.store_dir = self.root / "store"
        self.index_path = self.root / "index.json"
        self.evidence_ledger = self.root / "evidence" / "ledger.jsonl"
        self.evidence_corpus = self.root / "evidence" / "corpus.jsonl"
        if not self.config_path.is_file():
            raise VaultError(f"no Meridian vault at {self.root} (run: vault init)")
        try:
            self.config = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"vault config is unreadable: {exc}") from exc
        if self.config.get("vault_version") != VAULT_VERSION:
            raise VaultError("vault config version is not recognized")
        self.registry = api.load_registry()

    # -- policy / key ----------------------------------------------------------

    @property
    def key_mode(self) -> str:
        return self.config.get("key_mode", "keyfile")

    def policy(self) -> dict[str, Any]:
        pol = self.config["policy"]
        return api.make_policy(
            self.registry,
            min_score_M=int(pol["min_score_M"]),
            required_closed_obligations=list(pol.get("required_closed_obligations", [])),
        )

    def caller_key(self, passphrase: str | None = None) -> bytes:
        if self.key_mode == "passphrase":
            if not passphrase:
                raise VaultError("this vault is passphrase-protected: a passphrase is required")
            salt = bytes.fromhex(self.config["kdf_salt"])
            iters = int(self.config.get("kdf_iterations", KDF_ITERATIONS))
            return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iters, dklen=KEY_LEN)
        try:
            text = _read_private(self.key_path).decode("utf-8").strip()
        except OSError as exc:
            raise VaultError(f"vault key is unreadable (symlinked key files are refused): {exc}") from exc
        try:
            key = bytes.fromhex(text)
        except ValueError as exc:
            raise VaultError("vault key file is not valid hex") from exc
        if len(key) != KEY_LEN:
            raise VaultError("vault key must be 32 bytes")
        return key

    # -- index -----------------------------------------------------------------

    def _load_index(self) -> dict[str, Any]:
        if not self.index_path.is_file():
            return {"vault_version": VAULT_VERSION, "entries": {}}
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def _save_index(self, index: dict[str, Any]) -> None:
        # The index names every sealed entry; keep it private like the store.
        _write_private(
            self.index_path,
            (json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
        )

    def entries(self) -> dict[str, Any]:
        return self._load_index().get("entries", {})

    # -- core seal/open over raw bytes ----------------------------------------

    def seal_bytes(self, name: str, plaintext: bytes, *, passphrase: str | None = None,
                   meta: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            envelope = api.seal_envelope(
                plaintext=plaintext,
                caller_key=self.caller_key(passphrase),
                ledger_path=self.evidence_ledger,
                corpus_path=self.evidence_corpus,
                policy=self.policy(),
            )
        except _EVIDENCE_ERRORS as exc:
            raise EnvelopeRefused(f"seal refused (NoScore -> NoSeal): evidence is not trustworthy: {exc}") from exc
        self.store_dir.mkdir(parents=True, exist_ok=True)
        out = self.store_dir / f"{name}.mae"
        _write_private(out, envelope)
        index = self._load_index()
        record = {
            "name": name,
            "sealed_utc": _now(),
            "plaintext_bytes": len(plaintext),
            "envelope_bytes": len(envelope),
            # Hash the sealed envelope, not the plaintext: a plaintext digest in
            # the index would let anyone who reads it confirm guessed contents.
            "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        }
        if meta:
            record.update(meta)
        index.setdefault("entries", {})[name] = record
        self._save_index(index)
        return record

    def open_bytes(self, name: str, *, passphrase: str | None = None) -> bytes:
        out = self.store_dir / f"{name}.mae"
        if not out.is_file():
            raise VaultError(f"no sealed entry named {name!r}")
        envelope = out.read_bytes()
        try:
            return api.open_envelope(
                envelope=envelope,
                caller_key=self.caller_key(passphrase),
                ledger_path=self.evidence_ledger,
                corpus_path=self.evidence_corpus,
            )
        except _EVIDENCE_ERRORS as exc:
            raise EnvelopeRefused(f"open refused (NoProof -> NoOpen): evidence is not trustworthy: {exc}") from exc

    # -- file-oriented operations ---------------------------------------------

    def seal_file(self, src: Path | str, *, name: str | None = None, keep_original: bool = True,
                  passphrase: str | None = None) -> dict[str, Any]:
        src = Path(src)
        if not src.is_file():
            raise VaultError(f"not a regular file: {src}")
        if src.is_symlink():
            raise VaultError(f"refusing to seal a symlink: {src}")
        plaintext = src.read_bytes()
        entry = name or _safe_name(str(src.resolve()))
        record = self.seal_bytes(
            entry, plaintext, passphrase=passphrase,
            meta={"original_path": str(src.resolve()), "kept_original": keep_original},
        )
        if not keep_original:
            # Best-effort overwrite-then-unlink so the cleartext does not linger.
            try:
                with open(src, "r+b") as handle:
                    length = handle.seek(0, os.SEEK_END)
                    handle.seek(0)
                    handle.write(secrets.token_bytes(length))
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                pass
            src.unlink()
        return record

    def open_file(self, name: str, *, out_path: Path | str | None = None,
                  passphrase: str | None = None, restore: bool = False) -> dict[str, Any]:
        plaintext = self.open_bytes(name, passphrase=passphrase)
        index = self._load_index()
        record = index.get("entries", {}).get(name, {})
        target: Path | None = None
        if out_path is not None:
            target = Path(out_path)
        elif restore and record.get("original_path"):
            target = Path(record["original_path"])
        if target is not None:
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_private(target, plaintext)
            return {"name": name, "restored_to": str(target), "bytes": len(plaintext)}
        os.write(1, plaintext)
        return {"name": name, "restored_to": None, "bytes": len(plaintext)}

    # -- status ----------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        scorecard, _, _ = api.generate_scorecard(
            ledger_path=self.evidence_ledger, corpus_path=self.evidence_corpus, command="vault-status"
        )
        verdict = api.verify_scorecard(
            scorecard, ledger_path=self.evidence_ledger, corpus_path=self.evidence_corpus
        )
        pol = self.config["policy"]
        authorized = verdict.ok and int(scorecard["final_score_M"]) >= int(pol["min_score_M"])
        return {
            "vault_version": VAULT_VERSION,
            "meridian_version": __version__,
            "root": str(self.root),
            "key_mode": self.key_mode,
            "policy": pol,
            "evidence_verifies": verdict.ok,
            "evidence_final_score_M": int(scorecard["final_score_M"]),
            "authorized": bool(authorized),
            "entry_count": len(self.entries()),
        }


# -- construction --------------------------------------------------------------


def init_vault(
    root: Path | str = DEFAULT_VAULT_ROOT,
    *,
    min_score_M: int = DEFAULT_MIN_SCORE_M,
    required_closed_obligations: Iterable[str] | None = None,
    evidence_ledger: Path | str | None = None,
    evidence_corpus: Path | str | None = None,
    passphrase: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Create a new vault. Refuses to create one the current evidence cannot open."""
    root = Path(root)
    if root.exists() and any(root.iterdir()) and not force:
        raise VaultError(f"vault root already exists and is not empty: {root} (use force to rebuild)")

    pkg_examples = api.DEFAULT_OBLIGATIONS.parent.parent / "examples"
    ledger_src = Path(evidence_ledger) if evidence_ledger else pkg_examples / "ledger.seed.jsonl"
    corpus_src = Path(evidence_corpus) if evidence_corpus else pkg_examples / "corpus.seed.jsonl"
    for label, path in (("ledger", ledger_src), ("corpus", corpus_src)):
        if not path.is_file():
            raise VaultError(f"evidence {label} not found: {path}")

    registry = api.load_registry()
    required = sorted(set(required_closed_obligations or []))
    # Validate the policy and confirm the evidence can actually satisfy it, so a
    # vault is never born unopenable.
    policy = api.make_policy(registry, min_score_M=int(min_score_M), required_closed_obligations=required)
    scorecard, _, _ = api.generate_scorecard(
        ledger_path=ledger_src, corpus_path=corpus_src, command="vault-init"
    )
    verdict = api.verify_scorecard(scorecard, ledger_path=ledger_src, corpus_path=corpus_src)
    if not verdict.ok:
        raise VaultError(f"refusing to init: evidence does not verify: {verdict.error}")
    closed_ids = {rec["obligation_id"] for rec in scorecard["closed_obligations"]}
    if int(scorecard["final_score_M"]) < int(min_score_M):
        raise VaultError(
            f"refusing to init: evidence scores {scorecard['final_score_M']}M "
            f"< requested floor {min_score_M}M (a perfect 1,000,000M floor needs external attestation)"
        )
    missing = [ob for ob in required if ob not in closed_ids]
    if missing:
        raise VaultError("refusing to init: evidence does not close required obligations: " + ", ".join(missing))

    (root / "evidence").mkdir(parents=True, exist_ok=True)
    (root / "store").mkdir(parents=True, exist_ok=True)
    (root / "evidence" / "ledger.jsonl").write_bytes(ledger_src.read_bytes())
    (root / "evidence" / "corpus.jsonl").write_bytes(corpus_src.read_bytes())

    config: dict[str, Any] = {
        "vault_version": VAULT_VERSION,
        "meridian_version": __version__,
        "created_utc": _now(),
        "policy": {
            "min_score_M": int(min_score_M),
            "required_closed_obligations": required,
            "obligations_digest": policy["obligations_digest"],
        },
    }
    if passphrase:
        salt = secrets.token_bytes(16)
        config["key_mode"] = "passphrase"
        config["kdf"] = "pbkdf2-hmac-sha256"
        config["kdf_salt"] = salt.hex()
        config["kdf_iterations"] = KDF_ITERATIONS
    else:
        config["key_mode"] = "keyfile"
        _write_private(root / "vault.key", secrets.token_bytes(KEY_LEN).hex().encode("ascii"))

    (root / "vault.json").write_text(
        json.dumps(config, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return {
        "root": str(root),
        "key_mode": config["key_mode"],
        "policy": config["policy"],
        "evidence_final_score_M": int(scorecard["final_score_M"]),
    }


# -- auto-seal home profile ----------------------------------------------------

# Common credential/secret locations. Each existing regular file is sealed; the
# host keeps working because originals are kept unless the caller removes them.
DEFAULT_AUTOSEAL_TARGETS: tuple[str, ...] = (
    "~/.ssh/id_rsa",
    "~/.ssh/id_ecdsa",
    "~/.ssh/id_ed25519",
    "~/.aws/credentials",
    "~/.netrc",
    "~/.git-credentials",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.config/gh/hosts.yml",
    "~/.gnupg/secring.gpg",
)


def _expand(pattern: str) -> list[Path]:
    expanded = Path(os.path.expanduser(pattern))
    if any(ch in pattern for ch in "*?["):
        return sorted(p for p in expanded.parent.glob(expanded.name) if p.is_file() and not p.is_symlink())
    return [expanded] if expanded.is_file() and not expanded.is_symlink() else []


def autoseal(
    vault: Vault,
    targets: Iterable[str] | None = None,
    *,
    keep_original: bool = True,
    passphrase: str | None = None,
) -> dict[str, Any]:
    """Seal each existing target into the vault. Non-destructive by default."""
    patterns = list(targets) if targets is not None else list(DEFAULT_AUTOSEAL_TARGETS)
    sealed: list[dict[str, Any]] = []
    skipped: list[str] = []
    for pattern in patterns:
        matches = _expand(pattern)
        if not matches:
            skipped.append(pattern)
            continue
        for path in matches:
            sealed.append(vault.seal_file(path, keep_original=keep_original, passphrase=passphrase))
    return {"sealed": sealed, "sealed_count": len(sealed), "skipped_patterns": skipped}
