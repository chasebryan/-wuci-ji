#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import wuci_safeio
import wuci_verifier_identity


TOOL_PATH = Path(__file__).resolve()
REPO_ROOT = TOOL_PATH.parents[1]
INSTALL_DIR = REPO_ROOT / "install"
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_MANIFEST = INSTALL_DIR / "wuci-install-manifest.v1"
DEFAULT_SIGNATURE = INSTALL_DIR / "wuci-install-manifest.v1.sig"
DEFAULT_REPO_ROOT_KEY = INSTALL_DIR / "wuci-install-root.v1.pub"
DEFAULT_REPO_ROOT_KEY_SHA256 = INSTALL_DIR / "wuci-install-root.v1.pub.sha256"
DEFAULT_POLICY = INSTALL_DIR / "wuci-install-policy.json"
DEFAULT_PREFIX = Path.home() / ".local"

MANIFEST_SCHEMA = "wuci-install-manifest-v1"
RECEIPT_SCHEMA = "wuci-install-receipt-v1"
POLICY_SCHEMA = "wuci-install-policy-v1"
VERSION = "0.1"
PLATFORM = "linux-x86_64"
SIGNATURE_NAMESPACE = "wuci-install-v1"
SIGNATURE_IDENTITY = "wuci-install"
ZERO_SHA512 = "0" * 128
PRODUCT_UTF8_SHA256 = hashlib.sha256("无此机".encode("utf-8")).hexdigest()
TICKER_FRAMES = (
    "[=-------]",
    "[==------]",
    "[===-----]",
    "[====----]",
    "[=====---]",
    "[======--]",
    "[=======-]",
    "[========]",
    "[-=======]",
    "[--======]",
    "[---=====]",
    "[----====]",
    "[-----===]",
    "[------==]",
    "[-------=]",
    "[--------]",
)
TICKER_SIGNALS = ("AUTH", "SEAL", "GATE", "ROOT", "CAGE", "QBIT", "WITN", "LEDG")

MANIFEST_FIELDS = (
    "schema",
    "product-unicode-name-utf8-sha256",
    "product-english-name",
    "version",
    "platform",
    "binary-path",
    "binary-sha256",
    "binary-sha384",
    "binary-sha512",
    "install-policy-sha512",
    "witness-bundle-sha512",
    "cage-attestation-sha512",
    "qcage-attestation-sha512",
    "runtime-sandbox-claimed",
    "quantum-safe-claimed",
)

HEX_LENGTHS = {
    "product-unicode-name-utf8-sha256": 64,
    "binary-sha256": 64,
    "binary-sha384": 96,
    "binary-sha512": 128,
    "install-policy-sha512": 128,
    "witness-bundle-sha512": 128,
    "cage-attestation-sha512": 128,
    "qcage-attestation-sha512": 128,
}


class InstallError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise InstallError(message)


def reject_nul(value: str, context: str) -> None:
    if "\x00" in value:
        fail(f"{context} must not contain NUL")


def read_bytes(path: Path, context: str, *, max_bytes: int | None = None) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(
            path,
            context,
            reject_symlink=True,
            max_bytes=max_bytes,
        )
    except wuci_safeio.SafeIOError as exc:
        raise InstallError(str(exc)) from exc


def read_ascii(path: Path, context: str, *, max_bytes: int | None = None) -> str:
    try:
        return wuci_safeio.read_regular_ascii(
            path,
            context,
            reject_symlink=True,
            max_bytes=max_bytes,
        )
    except wuci_safeio.SafeIOError as exc:
        raise InstallError(str(exc)) from exc


def sha256_file(path: Path, context: str = "file") -> str:
    try:
        return wuci_safeio.sha256_file(path, context)
    except wuci_safeio.SafeIOError as exc:
        raise InstallError(str(exc)) from exc


def sha384_file(path: Path, context: str = "file") -> str:
    try:
        return wuci_safeio.sha384_file(path, context)
    except wuci_safeio.SafeIOError as exc:
        raise InstallError(str(exc)) from exc


def sha512_file(path: Path, context: str = "file") -> str:
    try:
        return wuci_safeio.sha512_file(path, context)
    except wuci_safeio.SafeIOError as exc:
        raise InstallError(str(exc)) from exc


def sha512_path(path: Path, context: str) -> str:
    if path.exists():
        return sha512_file(path, context)
    return ZERO_SHA512


def hash_tree_sha512(path: Path, context: str) -> str:
    if not path.exists():
        return ZERO_SHA512
    if path.is_file():
        return sha512_file(path, context)
    if not path.is_dir():
        fail(f"{context} must be a file or directory: {path}")
    digest = hashlib.sha512()
    for child in sorted(path.rglob("*")):
        rel = child.relative_to(path).as_posix()
        info = os.lstat(child)
        if stat.S_ISLNK(info.st_mode):
            fail(f"{context} must not contain symlink: {child}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            fail(f"{context} must contain only regular files: {child}")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(read_bytes(child, f"{context} file {rel}"))
        digest.update(b"\0")
    return digest.hexdigest()


def canonical_manifest(fields: dict[str, str]) -> str:
    validate_manifest_fields(fields)
    return "".join(f"{name}: {fields[name]}\n" for name in MANIFEST_FIELDS)


def parse_manifest(text: str) -> dict[str, str]:
    if "\r" in text:
        fail("install manifest must not contain CRLF")
    if not text.endswith("\n"):
        fail("install manifest must end with one trailing newline")
    if text.endswith("\n\n"):
        fail("install manifest must end with exactly one trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) != len(MANIFEST_FIELDS):
        fail("install manifest has unexpected field count")
    fields: dict[str, str] = {}
    for line, expected in zip(lines, MANIFEST_FIELDS, strict=True):
        if ": " not in line:
            fail("install manifest line is not label: value")
        label, value = line.split(": ", 1)
        if label != expected:
            fail(f"install manifest expected field {expected}")
        if value == "":
            fail(f"install manifest field is empty: {label}")
        fields[label] = value
    validate_manifest_fields(fields)
    if text != canonical_manifest(fields):
        fail("install manifest is not canonical")
    return fields


def is_lower_hex(value: str, chars: int) -> bool:
    return len(value) == chars and all(byte in "0123456789abcdef" for byte in value)


def validate_manifest_fields(fields: dict[str, str]) -> None:
    if tuple(fields) != MANIFEST_FIELDS:
        fail("install manifest fields are not canonical")
    if fields["schema"] != MANIFEST_SCHEMA:
        fail("install manifest has unsupported schema")
    if fields["product-unicode-name-utf8-sha256"] != PRODUCT_UTF8_SHA256:
        fail("install manifest product unicode digest mismatch")
    if fields["product-english-name"] != "Wuci-ji":
        fail("install manifest product name mismatch")
    if fields["version"] != VERSION:
        fail("install manifest version mismatch")
    if fields["platform"] != PLATFORM:
        fail("install manifest platform mismatch")
    if fields["runtime-sandbox-claimed"] != "false":
        fail("install manifest must not claim runtime sandboxing")
    if fields["quantum-safe-claimed"] != "false":
        fail("install manifest must not claim quantum safety")
    for label, chars in HEX_LENGTHS.items():
        if not is_lower_hex(fields[label], chars):
            fail(f"install manifest {label} must be {chars} lowercase hex characters")


def policy() -> dict[str, Any]:
    try:
        raw = json.loads(read_bytes(DEFAULT_POLICY, "install policy").decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise InstallError(f"install policy is not JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        fail("install policy must be a JSON object")
    if raw.get("schema") != POLICY_SCHEMA:
        fail("install policy has unsupported schema")
    if raw.get("version") != VERSION:
        fail("install policy version mismatch")
    if raw.get("install_root_key_required") is not True:
        fail("install policy must require install root key")
    if raw.get("signature_required") is not True:
        fail("install policy must require signature")
    if raw.get("runtime_sandbox_claimed") is not False:
        fail("install policy must not claim runtime sandbox")
    if raw.get("quantum_safe_claimed") is not False:
        fail("install policy must not claim quantum safety")
    return raw


def manifest_fields_for_binary(bin_path: Path) -> dict[str, str]:
    policy()
    return {
        "schema": MANIFEST_SCHEMA,
        "product-unicode-name-utf8-sha256": PRODUCT_UTF8_SHA256,
        "product-english-name": "Wuci-ji",
        "version": VERSION,
        "platform": PLATFORM,
        "binary-path": str(bin_path),
        "binary-sha256": sha256_file(bin_path, "candidate binary"),
        "binary-sha384": sha384_file(bin_path, "candidate binary"),
        "binary-sha512": sha512_file(bin_path, "candidate binary"),
        "install-policy-sha512": sha512_file(DEFAULT_POLICY, "install policy"),
        "witness-bundle-sha512": ZERO_SHA512,
        "cage-attestation-sha512": ZERO_SHA512,
        "qcage-attestation-sha512": ZERO_SHA512,
        "runtime-sandbox-claimed": "false",
        "quantum-safe-claimed": "false",
    }


def validate_repo_key_sidecar(repo_key: Path = DEFAULT_REPO_ROOT_KEY) -> str:
    key_hash = sha256_file(repo_key, "repository install root key")
    sidecar = read_ascii(DEFAULT_REPO_ROOT_KEY_SHA256, "install root key sha256 sidecar")
    expected = f"{key_hash}  install/wuci-install-root.v1.pub\n"
    legacy_expected = f"{key_hash}  wuci-install-root.v1.pub\n"
    if sidecar not in {expected, legacy_expected}:
        fail("install root key sha256 sidecar mismatch")
    return key_hash


def trust_key_check(local_key: Path, *, quiet: bool = False) -> str:
    if not local_key.exists():
        fail(
            "missing local install root key.\n"
            "Copy install/wuci-install-root.v1.pub to ~/.config/wuci-ji/install-root.pub before installing."
        )
    repo_bytes = read_bytes(DEFAULT_REPO_ROOT_KEY, "repository install root key", max_bytes=8192)
    local_bytes = read_bytes(local_key, "local install root key", max_bytes=8192)
    repo_hash = validate_repo_key_sidecar()
    local_hash = hashlib.sha256(local_bytes).hexdigest()
    if local_bytes != repo_bytes:
        fail("local install root key does not match repository install root key")
    if local_hash != repo_hash:
        fail("local install root key SHA-256 mismatch")
    if not quiet:
        print("install-root-key-copied: PASS")
        print(f"install-root-key-sha256: {local_hash}")
    return local_hash


def ssh_keygen_path(value: str | None) -> str:
    if value:
        reject_nul(value, "ssh-keygen path")
        path = Path(value)
        if not path.is_absolute():
            fail("--ssh-keygen must be an absolute path")
        if not path.exists():
            fail(f"ssh-keygen does not exist: {path}")
        return str(path)
    found = shutil.which("ssh-keygen")
    if not found:
        fail("ssh-keygen not found on PATH")
    return found


def verify_manifest_signature(
    *,
    install_root_key: Path,
    manifest_path: Path,
    signature_path: Path,
    ssh_keygen: str | None = None,
    quiet: bool = False,
) -> dict[str, str]:
    trust_key_check(install_root_key, quiet=True)
    manifest_bytes = read_bytes(manifest_path, "install manifest", max_bytes=65536)
    manifest = parse_manifest(manifest_bytes.decode("ascii"))
    read_bytes(signature_path, "install manifest signature", max_bytes=65536)
    key_line = read_bytes(install_root_key, "local install root key", max_bytes=8192).decode("ascii").strip()
    if not key_line.startswith(("ssh-ed25519 ", "sk-ssh-ed25519@openssh.com ")):
        fail("install root key must be an OpenSSH Ed25519 public key")
    ssh = ssh_keygen_path(ssh_keygen)
    with tempfile.TemporaryDirectory(prefix="wuci-install-signers-") as tmp:
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
                str(signature_path),
            ],
            input=manifest_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        fail(f"install manifest signature verification failed: {detail}")
    if not quiet:
        print("install-manifest-signature: PASS")
    return manifest


def start_ticker(label: str) -> tuple[threading.Event, threading.Thread] | None:
    if not sys.stderr.isatty():
        print(f"WUCI-INSTALL // START // {label}", file=sys.stderr, flush=True)
        return None
    stop = threading.Event()

    def animate() -> None:
        tick = 0
        started = time.monotonic()
        while not stop.is_set():
            elapsed = time.monotonic() - started
            frame = TICKER_FRAMES[tick % len(TICKER_FRAMES)]
            signal = TICKER_SIGNALS[tick % len(TICKER_SIGNALS)]
            sys.stderr.write(
                f"\rWUCI-INSTALL // {frame} // SIG:{signal} // CYCLE:{tick:04d} // {label} // T+{elapsed:05.1f}s"
            )
            sys.stderr.flush()
            tick += 1
            stop.wait(0.12)

    thread = threading.Thread(target=animate, daemon=True)
    thread.start()
    return stop, thread


def stop_ticker(handle: tuple[threading.Event, threading.Thread] | None, label: str, *, ok: bool) -> None:
    state = "PASS" if ok else "FAIL"
    if handle is None:
        print(f"WUCI-INSTALL // {state} // {label}", file=sys.stderr, flush=True)
        return
    stop, thread = handle
    stop.set()
    thread.join(timeout=1.0)
    sys.stderr.write("\r" + (" " * 120) + "\r")
    sys.stderr.write(f"WUCI-INSTALL // {state} // {label}\n")
    sys.stderr.flush()


def run_checked(
    argv: list[str],
    context: str,
    *,
    cwd: Path | None = None,
    ticker_label: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if not isinstance(argv, list) or not argv:
        fail(f"{context} argv must be a non-empty list")
    for item in argv:
        reject_nul(item, context)
    ticker = start_ticker(ticker_label) if ticker_label else None
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        if ticker_label:
            stop_ticker(ticker, ticker_label, ok=False)
        raise InstallError(f"{context} failed to execute: {argv[0]}") from exc
    if proc.returncode != 0:
        if ticker_label:
            stop_ticker(ticker, ticker_label, ok=False)
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        fail(f"{context} failed: {detail}")
    if ticker_label:
        stop_ticker(ticker, ticker_label, ok=True)
    return proc


def verify_digest_vector(bin_path: Path, manifest: dict[str, str]) -> tuple[str, str, str]:
    sha256 = sha256_file(bin_path, "candidate binary")
    sha384 = sha384_file(bin_path, "candidate binary")
    sha512 = sha512_file(bin_path, "candidate binary")
    if sha256 != manifest["binary-sha256"]:
        fail("candidate binary SHA-256 does not match install manifest")
    if sha384 != manifest["binary-sha384"]:
        fail("candidate binary SHA-384 does not match install manifest")
    if sha512 != manifest["binary-sha512"]:
        fail("candidate binary SHA-512 does not match install manifest")
    return sha256, sha384, sha512


def prefix_path(value: str, *, allow_prefix: bool = False) -> Path:
    reject_nul(value, "install prefix")
    expanded = Path(value).expanduser()
    allowed = {DEFAULT_PREFIX.resolve(strict=False), Path("/usr/local")}
    resolved = expanded.resolve(strict=False)
    if not allow_prefix and resolved not in allowed:
        fail("install prefix is not allowed; use ~/.local or /usr/local")
    return resolved


def ensure_safe_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    current = path.parent
    while current != current.parent:
        if current.exists() and current.is_symlink():
            fail(f"install path parent must not be a symlink: {current}")
        current = current.parent


def atomic_install_bytes(path: Path, data: bytes, *, mode: int, context: str) -> None:
    ensure_safe_parent(path)
    if path.exists() or path.is_symlink():
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            fail(f"{context} target must not be a symlink: {path}")
    with tempfile.NamedTemporaryFile(
        "wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise InstallError(f"could not install {context}: {path}") from exc


def copy_regular(src: Path, dst: Path, *, mode: int, context: str) -> None:
    if not src.exists():
        fail(f"{context} is missing: {src}")
    atomic_install_bytes(dst, read_bytes(src, context), mode=mode, context=context)


def write_json_atomic(path: Path, value: dict[str, Any], *, mode: int = 0o600) -> None:
    atomic_install_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=mode,
        context="install receipt",
    )


def proof_hashes() -> dict[str, str]:
    return {
        "witness_bundle_sha512": hash_tree_sha512(REPO_ROOT / "build" / "wuci-witness-bundle", "witness bundle"),
        "ledger_history_sha512": hash_tree_sha512(REPO_ROOT / "build" / "wuci-ledger", "ledger history"),
        "cage_attestation_sha512": sha512_path(REPO_ROOT / "build" / "wuci-cage-attestation.json", "CAGE attestation"),
        "qcage_attestation_sha512": sha512_path(REPO_ROOT / "build" / "wuci-qcage-attestation.json", "QCAGE attestation"),
    }


def install_audit_script(prefix: Path) -> bytes:
    python = sys.executable
    tool = prefix / "share" / "wuci-ji" / "tools" / "wuci_install.py"
    return (
        f"#!{python}\n"
        "import os\n"
        "import sys\n"
        f"tool = {str(tool)!r}\n"
        f"prefix = {str(prefix)!r}\n"
        "os.environ['PYTHONDONTWRITEBYTECODE'] = '1'\n"
        "os.execv(sys.executable, [sys.executable, tool, 'audit', '--prefix', prefix])\n"
    ).encode("utf-8")


def install_files(
    *,
    prefix: Path,
    bin_path: Path,
    install_root_key: Path,
    manifest_path: Path,
    signature_path: Path,
    manifest: dict[str, str],
    key_sha256: str,
    binary_hashes: tuple[str, str, str],
) -> dict[str, Any]:
    binary_dest = prefix / "bin" / "wuci-ji"
    audit_dest = prefix / "bin" / "wuci-ji-audit"
    share = prefix / "share" / "wuci-ji"
    tools_dir = share / "tools"
    install_dir = share / "install"
    proof_dir = share / "proofs"

    previous_hash = sha256_file(binary_dest, "previous installed binary") if binary_dest.exists() and not binary_dest.is_symlink() else None
    atomic_install_bytes(binary_dest, read_bytes(bin_path, "candidate binary"), mode=0o755, context="wuci-ji binary")
    atomic_install_bytes(audit_dest, install_audit_script(prefix), mode=0o755, context="wuci-ji audit command")

    copy_regular(TOOL_PATH, tools_dir / "wuci_install.py", mode=0o644, context="installer tool")
    copy_regular(REPO_ROOT / "tools" / "wuci_safeio.py", tools_dir / "wuci_safeio.py", mode=0o644, context="safe I/O helper")
    copy_regular(REPO_ROOT / "tools" / "wuci_verifier_identity.py", tools_dir / "wuci_verifier_identity.py", mode=0o644, context="verifier identity helper")
    copy_regular(manifest_path, share / "wuci-install-manifest.v1", mode=0o644, context="install manifest")
    copy_regular(signature_path, share / "wuci-install-manifest.v1.sig", mode=0o644, context="install manifest signature")
    copy_regular(install_root_key, share / "install-root.pub", mode=0o644, context="install root key")
    copy_regular(DEFAULT_REPO_ROOT_KEY, install_dir / "wuci-install-root.v1.pub", mode=0o644, context="repository install root key")
    copy_regular(DEFAULT_REPO_ROOT_KEY_SHA256, install_dir / "wuci-install-root.v1.pub.sha256", mode=0o644, context="repository install root key SHA-256")
    copy_regular(DEFAULT_POLICY, install_dir / "wuci-install-policy.json", mode=0o644, context="repository install policy")
    copy_regular(DEFAULT_POLICY, share / "wuci-install-policy.json", mode=0o644, context="install policy")
    for source, name in (
        (REPO_ROOT / "build" / "wuci-cage-attestation.json", "wuci-cage-attestation.json"),
        (REPO_ROOT / "build" / "wuci-qcage-attestation.json", "wuci-qcage-attestation.json"),
        (REPO_ROOT / "build" / "wuci-cage-ledger-entry.txt", "wuci-cage-ledger-entry.txt"),
        (REPO_ROOT / "build" / "wuci-cage-ledger-leaf.txt", "wuci-cage-ledger-leaf.txt"),
    ):
        copy_regular(source, proof_dir / name, mode=0o644, context=name)

    live_hashes = proof_hashes()
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "product": "无此机 / Wuci-ji",
        "version": VERSION,
        "installed": True,
        "install_status": "nominal",
        "prefix": str(prefix),
        "binary_path": str(binary_dest),
        "audit_command": str(audit_dest),
        "previous_binary_sha256": previous_hash,
        "install_root_key_sha256": key_sha256,
        "install_manifest_sha512": sha512_file(manifest_path, "install manifest"),
        "install_signature_verified": True,
        "binary_sha256": binary_hashes[0],
        "binary_sha384": binary_hashes[1],
        "binary_sha512": binary_hashes[2],
        "manifest_binary_sha256": manifest["binary-sha256"],
        "manifest_binary_sha384": manifest["binary-sha384"],
        "manifest_binary_sha512": manifest["binary-sha512"],
        "selftest": True,
        "harden_proof": True,
        "cage_proof": True,
        "qcage_compat_proof": True,
        "witness_bundle": True,
        "ledger_history": True,
        "proof_hashes": live_hashes,
        "runtime_sandbox_claimed": False,
        "quantum_safe_claimed": False,
    }
    write_json_atomic(share / "install-receipt.json", receipt, mode=0o600)
    return receipt


def receipt_path(prefix: Path) -> Path:
    return prefix / "share" / "wuci-ji" / "install-receipt.json"


def load_receipt(prefix: Path) -> dict[str, Any]:
    try:
        receipt = json.loads(read_bytes(receipt_path(prefix), "install receipt").decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise InstallError(f"install receipt is not JSON: {exc.msg}") from exc
    if not isinstance(receipt, dict):
        fail("install receipt must be a JSON object")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        fail("install receipt has unsupported schema")
    return receipt


def print_audit(receipt: dict[str, Any]) -> None:
    print("无此机 / Wuci-ji systems nominal.")
    print(f"Version {receipt['version']} installed.")
    print(f"Install status: {receipt['install_status']}")
    print()
    print("Proofs:")
    print("  install-root-key-copied: PASS")
    print(f"  install-root-key-sha256: {receipt['install_root_key_sha256']}")
    print("  install-manifest-signature: PASS")
    print(f"  install-manifest-sha512: {receipt['install_manifest_sha512']}")
    print(f"  installed-binary-sha256: {receipt['binary_sha256']}")
    print(f"  installed-binary-sha384: {receipt['binary_sha384']}")
    print(f"  installed-binary-sha512: {receipt['binary_sha512']}")
    print("  verifier-identity: PASS")
    print("  selftest: PASS")
    print("  harden-proof: PASS")
    print("  cage-proof: PASS")
    print("  qcage-compat-proof: PASS")
    print("  witness-bundle: PASS")
    print("  ledger-history: PASS")
    print(f"  runtime-sandbox-claimed: {str(receipt['runtime_sandbox_claimed']).lower()}")
    print(f"  quantum-safe-claimed: {str(receipt['quantum_safe_claimed']).lower()}")
    print()
    print("无此机 / Wuci-ji systems nominal. Version 0.1 installed.")


def run_trust_key_check(args: argparse.Namespace) -> int:
    trust_key_check(Path(args.install_root_key).expanduser())
    return 0


def run_manifest(args: argparse.Namespace) -> int:
    bin_path = Path(args.bin)
    fields = manifest_fields_for_binary(bin_path)
    text = canonical_manifest(fields)
    out = Path(args.out)
    try:
        wuci_safeio.atomic_replace_text(out, text, "install manifest", mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise InstallError(str(exc)) from exc
    print(f"wrote install manifest: {out}")
    return 0


def run_verify_manifest(args: argparse.Namespace) -> int:
    verify_manifest_signature(
        install_root_key=Path(args.install_root_key).expanduser(),
        manifest_path=Path(args.manifest),
        signature_path=Path(args.signature),
        ssh_keygen=args.ssh_keygen,
    )
    return 0


def run_install(args: argparse.Namespace) -> int:
    if args.version != VERSION:
        fail("unsupported install version")
    prefix = prefix_path(args.prefix, allow_prefix=args.allow_prefix)
    bin_path = DEFAULT_BIN
    if not bin_path.exists():
        run_checked(["make", "all"], "make all", cwd=REPO_ROOT, ticker_label="build native verifier")
    install_key = Path(args.install_root_key).expanduser()
    key_sha256 = trust_key_check(install_key, quiet=True)
    manifest = verify_manifest_signature(
        install_root_key=install_key,
        manifest_path=Path(args.manifest),
        signature_path=Path(args.signature),
        ssh_keygen=args.ssh_keygen,
        quiet=True,
    )
    binary_hashes = verify_digest_vector(bin_path, manifest)
    wuci_verifier_identity.require_trusted_verifier(bin_path, binary_hashes[0], "", strict=True)
    run_checked([str(bin_path), "selftest"], "wuci-ji selftest", ticker_label="selftest verifier core")

    run_checked(["make", "harden-proof"], "harden proof", cwd=REPO_ROOT, ticker_label="HARDEN perimeter proof")
    run_checked(["make", "cage-proof"], "cage proof", cwd=REPO_ROOT, ticker_label="CAGE airlock proof")
    run_checked(["make", "qcage-proof"], "qcage proof", cwd=REPO_ROOT, ticker_label="QCAGE digest-vector proof")
    run_checked(
        ["make", "self-release-witness-bundle"],
        "witness bundle proof",
        cwd=REPO_ROOT,
        ticker_label="WITNESS public bundle proof",
    )
    run_checked(
        ["make", "self-release-ledger-bundle"],
        "ledger proof",
        cwd=REPO_ROOT,
        ticker_label="LEDGER append-only proof",
    )

    install_files(
        prefix=prefix,
        bin_path=bin_path,
        install_root_key=install_key,
        manifest_path=Path(args.manifest),
        signature_path=Path(args.signature),
        manifest=manifest,
        key_sha256=key_sha256,
        binary_hashes=binary_hashes,
    )
    print("无此机 / Wuci-ji systems nominal. Version 0.1 installed.")
    return 0


def run_audit(args: argparse.Namespace) -> int:
    prefix = prefix_path(args.prefix, allow_prefix=True)
    receipt = load_receipt(prefix)
    binary = Path(receipt["binary_path"])
    if sha256_file(binary, "installed binary") != receipt["binary_sha256"]:
        fail("installed binary SHA-256 does not match receipt")
    if sha384_file(binary, "installed binary") != receipt["binary_sha384"]:
        fail("installed binary SHA-384 does not match receipt")
    if sha512_file(binary, "installed binary") != receipt["binary_sha512"]:
        fail("installed binary SHA-512 does not match receipt")
    key = prefix / "share" / "wuci-ji" / "install-root.pub"
    if sha256_file(key, "installed install root key") != receipt["install_root_key_sha256"]:
        fail("installed install root key SHA-256 does not match receipt")
    manifest = prefix / "share" / "wuci-ji" / "wuci-install-manifest.v1"
    signature = prefix / "share" / "wuci-ji" / "wuci-install-manifest.v1.sig"
    verify_manifest_signature(
        install_root_key=key,
        manifest_path=manifest,
        signature_path=signature,
        ssh_keygen=args.ssh_keygen,
        quiet=True,
    )
    run_checked([str(binary), "selftest"], "installed selftest")
    print_audit(receipt)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="WUCI-INSTALL zero-prompt signed installer.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    trust = subparsers.add_parser("trust-key-check")
    trust.add_argument("--install-root-key", required=True)
    trust.set_defaults(func=run_trust_key_check)

    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--bin", default=str(DEFAULT_BIN))
    manifest.add_argument("--out", default=str(DEFAULT_MANIFEST))
    manifest.set_defaults(func=run_manifest)

    verify = subparsers.add_parser("verify-manifest")
    verify.add_argument("--install-root-key", required=True)
    verify.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    verify.add_argument("--signature", default=str(DEFAULT_SIGNATURE))
    verify.add_argument("--ssh-keygen")
    verify.set_defaults(func=run_verify_manifest)

    install = subparsers.add_parser("install")
    install.add_argument("--install-root-key", required=True)
    install.add_argument("--prefix", default=str(DEFAULT_PREFIX))
    install.add_argument("--version", default=VERSION)
    install.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    install.add_argument("--signature", default=str(DEFAULT_SIGNATURE))
    install.add_argument("--ssh-keygen")
    install.add_argument("--allow-prefix", action="store_true")
    install.set_defaults(func=run_install)

    audit = subparsers.add_parser("audit")
    audit.add_argument("--prefix", default=str(DEFAULT_PREFIX))
    audit.add_argument("--ssh-keygen")
    audit.set_defaults(func=run_audit)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except InstallError as exc:
        print(f"wuci install: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
