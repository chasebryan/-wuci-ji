#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import wuci_witness
import wuci_safeio
import wuci_verifier_identity


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "build" / "wuci-ji"
DEFAULT_LEDGER_DIR = REPO_ROOT / "build" / "wuci-ledger"
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))

ENTRY_SCHEMA = "wuci-ledger-entry-v1"
HEAD_SCHEMA = "wuci-ledger-head-v1"
INCLUSION_SCHEMA = "wuci-ledger-inclusion-proof-v1"
CONSISTENCY_SCHEMA = "wuci-ledger-consistency-proof-v1"
ZERO64 = "0" * 64

ENTRY_FIELDS = (
    "schema",
    "sequence",
    "artifact-sha256",
    "manifest-sha256",
    "warrant-message-sha256",
    "release-receipt-sha256",
    "receipt-contract-sha256",
    "authority-root-sha256",
    "release-decision-sha256",
    "attestation-sha256",
    "release-authority-group-public-key",
)
HEAD_FIELDS = (
    "schema",
    "tree-size",
    "root-hash",
    "previous-tree-size",
    "previous-root-hash",
    "entry-hash",
)
INCLUSION_FIELDS = (
    "schema",
    "tree-size",
    "leaf-index",
    "leaf-hash",
    "root-hash",
    "path-count",
)
CONSISTENCY_FIELDS = (
    "schema",
    "first-size",
    "first-root-hash",
    "second-size",
    "second-root-hash",
    "path-count",
)
HEX_RE = re.compile(r"^[0-9a-f]+$")


class LedgerError(RuntimeError):
    pass


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def seq_name(sequence: int) -> str:
    return f"{sequence:020d}.txt"


def head_name(size: int) -> str:
    return f"{size:020d}.txt"


def ledger_paths(ledger_dir: Path) -> dict[str, Path]:
    return {
        "entries": ledger_dir / "entries",
        "heads": ledger_dir / "heads",
        "latest_entry": ledger_dir / "ledger-entry.txt",
        "latest_head": ledger_dir / "ledger-head.txt",
        "previous_head": ledger_dir / "previous-ledger-head.txt",
        "lock": ledger_dir / ".wuci-ledger.lock",
    }


def sha256_file(path: Path) -> str:
    try:
        return wuci_safeio.sha256_file(path)
    except wuci_safeio.SafeIOError as exc:
        raise LedgerError(str(exc)) from exc


def read_ascii(path: Path, context: str) -> str:
    try:
        return wuci_safeio.read_regular_ascii(path, context, reject_symlink=True)
    except wuci_safeio.SafeIOError as exc:
        raise LedgerError(str(exc)) from exc


def write_ascii(path: Path, value: str) -> None:
    try:
        wuci_safeio.write_new_text(path, value, str(path))
    except wuci_safeio.SafeIOError as exc:
        raise LedgerError(str(exc)) from exc


def atomic_replace_ascii(path: Path, value: str) -> None:
    try:
        wuci_safeio.atomic_replace_text(path, value, str(path))
    except wuci_safeio.SafeIOError as exc:
        raise LedgerError(str(exc)) from exc


class LedgerLock:
    def __init__(self, ledger_dir: Path) -> None:
        self.path = ledger_paths(ledger_dir)["lock"]

    def __enter__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError as exc:
            raise LedgerError(f"ledger lock exists: {self.path}") from exc
        except OSError as exc:
            raise LedgerError(f"could not create ledger lock: {self.path}") from exc
        os.close(fd)

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def require_hex(value: str, chars: int, context: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        raise LedgerError(f"{context} must be {chars} lowercase hex characters")


def parse_decimal(value: str, context: str) -> int:
    if not value.isdigit():
        raise LedgerError(f"{context} must be decimal")
    if len(value) > 1 and value.startswith("0"):
        raise LedgerError(f"{context} must not have leading zeroes")
    return int(value)


def run_wuci(bin_path: Path, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            [*RUNNER, str(bin_path), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise LedgerError(f"could not execute {bin_path}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace").strip()
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        detail = stderr or stdout or f"exit status {proc.returncode}"
        raise LedgerError(f"{args[0]} failed: {detail}")
    try:
        text = proc.stdout.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LedgerError(f"{args[0]} output is not ASCII") from exc
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise LedgerError(f"{args[0]} output is not one newline terminated")
    value = text[:-1]
    require_hex(value, 64, args[0])
    return value


def empty_root(bin_path: Path) -> str:
    return run_wuci(bin_path, ["ledger-empty-root"])


def leaf_file(bin_path: Path, path: Path) -> str:
    return run_wuci(bin_path, ["ledger-leaf-file", str(path)])


def node_hash(bin_path: Path, left: str, right: str) -> str:
    require_hex(left, 64, "left child hash")
    require_hex(right, 64, "right child hash")
    return run_wuci(bin_path, ["ledger-node", left, right])


def split_power(size: int) -> int:
    if size <= 1:
        raise LedgerError("cannot split a tree smaller than two leaves")
    return 1 << ((size - 1).bit_length() - 1)


def merkle_root(bin_path: Path, hashes: list[str]) -> str:
    if not hashes:
        return empty_root(bin_path)
    if len(hashes) == 1:
        return hashes[0]
    k = split_power(len(hashes))
    return node_hash(
        bin_path,
        merkle_root(bin_path, hashes[:k]),
        merkle_root(bin_path, hashes[k:]),
    )


def inclusion_path(bin_path: Path, hashes: list[str], index: int) -> list[str]:
    if not 0 <= index < len(hashes):
        raise LedgerError("inclusion sequence is outside tree")
    if len(hashes) == 1:
        return []
    k = split_power(len(hashes))
    if index < k:
        return inclusion_path(bin_path, hashes[:k], index) + [
            merkle_root(bin_path, hashes[k:])
        ]
    return inclusion_path(bin_path, hashes[k:], index - k) + [
        merkle_root(bin_path, hashes[:k])
    ]


def consistency_path(
    bin_path: Path,
    hashes: list[str],
    first_size: int,
    *,
    seed: bool = True,
) -> list[str]:
    second_size = len(hashes)
    if first_size < 0 or first_size > second_size:
        raise LedgerError("consistency size range is invalid")
    if first_size == 0:
        return []
    if first_size == second_size:
        return [] if seed else [merkle_root(bin_path, hashes)]
    k = split_power(second_size)
    if first_size <= k:
        return consistency_path(bin_path, hashes[:k], first_size, seed=seed) + [
            merkle_root(bin_path, hashes[k:])
        ]
    return consistency_path(
        bin_path,
        hashes[k:],
        first_size - k,
        seed=False,
    ) + [merkle_root(bin_path, hashes[:k])]


def parse_fixed_lines(
    text: str,
    fields: tuple[str, ...],
    schema: str,
    context: str,
) -> dict[str, str]:
    if "\r" in text:
        raise LedgerError(f"{context} must not contain CRLF")
    if not text.endswith("\n"):
        raise LedgerError(f"{context} must end with one trailing newline")
    if text.endswith("\n\n"):
        raise LedgerError(f"{context} must end with exactly one trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) != len(fields):
        raise LedgerError(f"{context} has unexpected field count")
    parsed: dict[str, str] = {}
    for line_no, (line, expected) in enumerate(zip(lines, fields), start=1):
        if ": " not in line:
            raise LedgerError(f"{context} line {line_no} is not label: value")
        label, value = line.split(": ", 1)
        if label != expected:
            raise LedgerError(f"{context} line {line_no} expected label {expected}")
        if value == "":
            raise LedgerError(f"{context} field {label} is empty")
        parsed[label] = value
    if parsed["schema"] != schema:
        raise LedgerError(f"{context} has unsupported schema")
    return parsed


def format_fixed(fields: dict[str, str], order: tuple[str, ...]) -> str:
    return "".join(f"{name}: {fields[name]}\n" for name in order)


def validate_entry(fields: dict[str, str]) -> None:
    parse_decimal(fields["sequence"], "sequence")
    for label in ENTRY_FIELDS:
        if label.endswith("-sha256"):
            require_hex(fields[label], 64, label)
    group_key = fields["release-authority-group-public-key"]
    require_hex(group_key, 66, "release-authority-group-public-key")
    if group_key[:2] not in {"02", "03"}:
        raise LedgerError("release-authority-group-public-key must be compressed SEC1")


def parse_entry(text: str) -> dict[str, str]:
    fields = parse_fixed_lines(text, ENTRY_FIELDS, ENTRY_SCHEMA, "ledger entry")
    validate_entry(fields)
    return fields


def format_entry(fields: dict[str, str]) -> str:
    validate_entry(fields)
    return format_fixed(fields, ENTRY_FIELDS)


def validate_head(fields: dict[str, str]) -> None:
    tree_size = parse_decimal(fields["tree-size"], "tree-size")
    previous_size = parse_decimal(fields["previous-tree-size"], "previous-tree-size")
    if tree_size == 0:
        if previous_size != 0:
            raise LedgerError("empty ledger head previous-tree-size must be zero")
        if fields["entry-hash"] != ZERO64:
            raise LedgerError("empty ledger head entry-hash must be zero")
    elif previous_size >= tree_size:
        raise LedgerError("ledger head previous-tree-size must be smaller than tree-size")
    require_hex(fields["root-hash"], 64, "root-hash")
    require_hex(fields["previous-root-hash"], 64, "previous-root-hash")
    require_hex(fields["entry-hash"], 64, "entry-hash")


def parse_head(text: str) -> dict[str, str]:
    fields = parse_fixed_lines(text, HEAD_FIELDS, HEAD_SCHEMA, "ledger head")
    validate_head(fields)
    return fields


def format_head(fields: dict[str, str]) -> str:
    validate_head(fields)
    return format_fixed(fields, HEAD_FIELDS)


def parse_proof(
    text: str,
    fields: tuple[str, ...],
    schema: str,
    context: str,
) -> tuple[dict[str, str], list[str]]:
    if "\r" in text:
        raise LedgerError(f"{context} must not contain CRLF")
    if not text.endswith("\n"):
        raise LedgerError(f"{context} must end with one trailing newline")
    if text.endswith("\n\n"):
        raise LedgerError(f"{context} must end with exactly one trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) < len(fields) + 1:
        raise LedgerError(f"{context} is truncated")
    header = "\n".join(lines[: len(fields)]) + "\n"
    parsed = parse_fixed_lines(header, fields, schema, context)
    if lines[len(fields)] != "path:":
        raise LedgerError(f"{context} missing path block")
    path = lines[len(fields) + 1 :]
    count = parse_decimal(parsed["path-count"], "path-count")
    if count != len(path):
        raise LedgerError(f"{context} path-count does not match path length")
    for index, value in enumerate(path):
        require_hex(value, 64, f"{context} path hash {index}")
    return parsed, path


def format_proof(fields: dict[str, str], order: tuple[str, ...], path: list[str]) -> str:
    fields = dict(fields)
    fields["path-count"] = str(len(path))
    return format_fixed(fields, order) + "path:\n" + "".join(
        f"{value}\n" for value in path
    )


def derive_entry_from_bundle(
    *,
    bin_path: Path,
    bundle_dir: Path,
    sequence: int,
) -> str:
    try:
        paths = wuci_witness.bundle_paths(bundle_dir)
        observed, _ = wuci_witness.build_witness_attestation(
            bin_path=bin_path,
            bundle_dir=bundle_dir,
            require_index=True,
            require_attestation=True,
        )
        expected = wuci_witness.load_json_file(
            paths["attestation"],
            "witness attestation",
        )
        wuci_witness.compare_attestations(expected, observed)
        index_text = wuci_witness.read_ascii(paths["publish_index"], "publish index")
        index_fields = wuci_witness.parse_index(index_text)
    except wuci_witness.WitnessError as exc:
        raise LedgerError(f"witness bundle is not valid: {exc}") from exc

    fields = {
        "schema": ENTRY_SCHEMA,
        "sequence": str(sequence),
        "artifact-sha256": index_fields["artifact-sha256"],
        "manifest-sha256": index_fields["manifest-sha256"],
        "warrant-message-sha256": index_fields["warrant-message-sha256"],
        "release-receipt-sha256": index_fields["release-receipt-sha256"],
        "receipt-contract-sha256": index_fields["receipt-contract-sha256"],
        "authority-root-sha256": index_fields["authority-root-sha256"],
        "release-decision-sha256": index_fields["release-decision-sha256"],
        "attestation-sha256": sha256_file(paths["attestation"]),
        "release-authority-group-public-key": index_fields[
            "release-authority-group-public-key"
        ],
    }
    return format_entry(fields)


def load_latest_head(ledger_dir: Path) -> dict[str, str]:
    paths = ledger_paths(ledger_dir)
    if not paths["latest_head"].is_file():
        raise LedgerError(f"ledger is not initialized: {ledger_dir}")
    return parse_head(read_ascii(paths["latest_head"], "ledger head"))


def load_entries_for_size(ledger_dir: Path, size: int) -> list[Path]:
    paths = ledger_paths(ledger_dir)
    entries_dir = paths["entries"]
    if not entries_dir.is_dir():
        raise LedgerError(f"ledger entries directory is missing: {entries_dir}")
    expected = {seq_name(index) for index in range(size)}
    observed = {path.name for path in entries_dir.iterdir()}
    if observed != expected:
        raise LedgerError("ledger entries do not match ledger tree size")
    entry_paths: list[Path] = []
    for index in range(size):
        path = entries_dir / seq_name(index)
        fields = parse_entry(read_ascii(path, "ledger entry"))
        if parse_decimal(fields["sequence"], "sequence") != index:
            raise LedgerError("ledger entry sequence does not match its position")
        if read_ascii(path, "ledger entry") != format_entry(fields):
            raise LedgerError("ledger entry bytes are not canonical")
        entry_paths.append(path)
    return entry_paths


def leaf_hashes_for_entries(bin_path: Path, entry_paths: list[Path]) -> list[str]:
    return [leaf_file(bin_path, path) for path in entry_paths]


def root_for_entries(bin_path: Path, entry_paths: list[Path]) -> str:
    return merkle_root(bin_path, leaf_hashes_for_entries(bin_path, entry_paths))


def init_head(bin_path: Path) -> str:
    return format_head(
        {
            "schema": HEAD_SCHEMA,
            "tree-size": "0",
            "root-hash": empty_root(bin_path),
            "previous-tree-size": "0",
            "previous-root-hash": ZERO64,
            "entry-hash": ZERO64,
        }
    )


def run_init(args: argparse.Namespace) -> int:
    ledger_dir = Path(args.ledger)
    paths = ledger_paths(ledger_dir)
    if ledger_dir.exists() and args.force:
        shutil.rmtree(ledger_dir)
    if ledger_dir.exists() and any(ledger_dir.iterdir()):
        raise LedgerError(f"refusing to initialize non-empty ledger: {ledger_dir}")
    paths["entries"].mkdir(parents=True, exist_ok=True)
    paths["heads"].mkdir(parents=True, exist_ok=True)
    head_text = init_head(Path(args.bin))
    write_ascii(paths["latest_head"], head_text)
    write_ascii(paths["heads"] / head_name(0), head_text)
    print(f"initialized WUCI-LEDGER: {display_path(ledger_dir)}")
    print(f"ledger head: {display_path(paths['latest_head'])}")
    return 0


def run_append(args: argparse.Namespace) -> int:
    ledger_dir = Path(args.ledger)
    bin_path = Path(args.bin)
    paths = ledger_paths(ledger_dir)
    with LedgerLock(ledger_dir):
        old_head_text = read_ascii(paths["latest_head"], "ledger head")
        old_head = parse_head(old_head_text)
        old_size = parse_decimal(old_head["tree-size"], "tree-size")
        load_entries_for_size(ledger_dir, old_size)

        entry_text = derive_entry_from_bundle(
            bin_path=bin_path,
            bundle_dir=Path(args.witness_bundle),
            sequence=old_size,
        )
        entry_path = paths["entries"] / seq_name(old_size)
        if entry_path.exists():
            raise LedgerError(f"ledger entry already exists: {entry_path}")
        write_ascii(entry_path, entry_text)
        atomic_replace_ascii(paths["latest_entry"], entry_text)

        entry_paths = load_entries_for_size(ledger_dir, old_size + 1)
        new_root = root_for_entries(bin_path, entry_paths)
        new_head_text = format_head(
            {
                "schema": HEAD_SCHEMA,
                "tree-size": str(old_size + 1),
                "root-hash": new_root,
                "previous-tree-size": str(old_size),
                "previous-root-hash": old_head["root-hash"],
                "entry-hash": hashlib.sha256(entry_text.encode("ascii")).hexdigest(),
            }
        )
        atomic_replace_ascii(paths["previous_head"], old_head_text)
        atomic_replace_ascii(paths["latest_head"], new_head_text)
        write_ascii(paths["heads"] / head_name(old_size + 1), new_head_text)
    print(f"appended WUCI-LEDGER entry: {old_size}")
    print(f"ledger entry: {display_path(paths['latest_entry'])}")
    print(f"ledger head: {display_path(paths['latest_head'])}")
    return 0


def run_prove_inclusion(args: argparse.Namespace) -> int:
    ledger_dir = Path(args.ledger)
    bin_path = Path(args.bin)
    head = load_latest_head(ledger_dir)
    size = parse_decimal(head["tree-size"], "tree-size")
    sequence = args.sequence
    entry_paths = load_entries_for_size(ledger_dir, size)
    if not 0 <= sequence < size:
        raise LedgerError("inclusion sequence is outside ledger")
    hashes = leaf_hashes_for_entries(bin_path, entry_paths)
    root = merkle_root(bin_path, hashes)
    if root != head["root-hash"]:
        raise LedgerError("ledger head root does not match entries")
    leaf = hashes[sequence]
    proof_path = inclusion_path(bin_path, hashes, sequence)
    proof_text = format_proof(
        {
            "schema": INCLUSION_SCHEMA,
            "tree-size": str(size),
            "leaf-index": str(sequence),
            "leaf-hash": leaf,
            "root-hash": root,
        },
        INCLUSION_FIELDS,
        proof_path,
    )
    write_ascii(Path(args.out), proof_text)
    print(f"wrote inclusion proof: {display_path(Path(args.out))}")
    return 0


def root_from_inclusion(
    bin_path: Path,
    leaf_hash: str,
    index: int,
    size: int,
    path: list[str],
) -> str:
    if size <= 0:
        raise LedgerError("inclusion tree-size must be positive")
    if not 0 <= index < size:
        raise LedgerError("inclusion leaf-index is outside tree")

    def rec(local_index: int, local_size: int, local_path: list[str]) -> str:
        if local_size == 1:
            if local_path:
                raise LedgerError("inclusion path has too many hashes")
            return leaf_hash
        if not local_path:
            raise LedgerError("inclusion path is too short")
        k = split_power(local_size)
        sibling = local_path[-1]
        rest = local_path[:-1]
        if local_index < k:
            return node_hash(bin_path, rec(local_index, k, rest), sibling)
        return node_hash(bin_path, sibling, rec(local_index - k, local_size - k, rest))

    return rec(index, size, path)


def run_verify_inclusion(args: argparse.Namespace) -> int:
    bin_path = Path(args.bin)
    entry_path = Path(args.entry)
    entry_text = read_ascii(entry_path, "ledger entry")
    entry_fields = parse_entry(entry_text)
    proof_fields, proof_path = parse_proof(
        read_ascii(Path(args.proof), "inclusion proof"),
        INCLUSION_FIELDS,
        INCLUSION_SCHEMA,
        "inclusion proof",
    )
    head = parse_head(read_ascii(Path(args.head), "ledger head"))
    size = parse_decimal(proof_fields["tree-size"], "tree-size")
    index = parse_decimal(proof_fields["leaf-index"], "leaf-index")
    if parse_decimal(entry_fields["sequence"], "sequence") != index:
        raise LedgerError("ledger entry sequence does not match inclusion proof")
    if head["tree-size"] != proof_fields["tree-size"]:
        raise LedgerError("inclusion proof tree-size does not match ledger head")
    if head["root-hash"] != proof_fields["root-hash"]:
        raise LedgerError("inclusion proof root does not match ledger head")
    leaf = leaf_file(bin_path, entry_path)
    if leaf != proof_fields["leaf-hash"]:
        raise LedgerError("inclusion proof leaf hash does not match entry")
    root = root_from_inclusion(bin_path, leaf, index, size, proof_path)
    if root != proof_fields["root-hash"]:
        raise LedgerError("inclusion proof does not reconstruct ledger root")
    print(f"valid inclusion proof: {display_path(Path(args.proof))}")
    return 0


def run_prove_consistency(args: argparse.Namespace) -> int:
    ledger_dir = Path(args.ledger)
    bin_path = Path(args.bin)
    first = parse_head(read_ascii(Path(args.from_head), "first ledger head"))
    second = parse_head(read_ascii(Path(args.to_head), "second ledger head"))
    first_size = parse_decimal(first["tree-size"], "first tree-size")
    second_size = parse_decimal(second["tree-size"], "second tree-size")
    if first_size > second_size:
        raise LedgerError("first head is larger than second head")
    entries = load_entries_for_size(ledger_dir, second_size)
    hashes = leaf_hashes_for_entries(bin_path, entries)
    first_root = merkle_root(bin_path, hashes[:first_size])
    second_root = merkle_root(bin_path, hashes)
    if first_root != first["root-hash"]:
        raise LedgerError("first head is not a prefix root for this ledger")
    if second_root != second["root-hash"]:
        raise LedgerError("second head root does not match ledger entries")
    proof_path = consistency_path(bin_path, hashes, first_size)
    proof_text = format_proof(
        {
            "schema": CONSISTENCY_SCHEMA,
            "first-size": str(first_size),
            "first-root-hash": first_root,
            "second-size": str(second_size),
            "second-root-hash": second_root,
        },
        CONSISTENCY_FIELDS,
        proof_path,
    )
    write_ascii(Path(args.out), proof_text)
    print(f"wrote consistency proof: {display_path(Path(args.out))}")
    return 0


def consistency_roots_from_proof(
    bin_path: Path,
    *,
    first_size: int,
    second_size: int,
    first_root: str,
    path: list[str],
) -> tuple[str, str]:
    if first_size > second_size:
        raise LedgerError("consistency proof first-size is larger than second-size")
    if first_size == second_size:
        if path:
            raise LedgerError("same-size consistency proof must have an empty path")
        return first_root, first_root
    if first_size == 0:
        if path:
            raise LedgerError("empty-prefix consistency proof must have an empty path")
        return first_root, ""

    def rec(
        local_first: int,
        local_second: int,
        seed: bool,
        offset: int,
    ) -> tuple[str, str, int]:
        if local_first == local_second:
            if seed:
                return first_root, first_root, offset
            if offset >= len(path):
                raise LedgerError("consistency proof path is too short")
            value = path[offset]
            return value, value, offset + 1
        k = split_power(local_second)
        if local_first <= k:
            old_left, new_left, next_offset = rec(local_first, k, seed, offset)
            if next_offset >= len(path):
                raise LedgerError("consistency proof path is too short")
            right = path[next_offset]
            return old_left, node_hash(bin_path, new_left, right), next_offset + 1
        old_right, new_right, next_offset = rec(
            local_first - k,
            local_second - k,
            False,
            offset,
        )
        if next_offset >= len(path):
            raise LedgerError("consistency proof path is too short")
        left = path[next_offset]
        return (
            node_hash(bin_path, left, old_right),
            node_hash(bin_path, left, new_right),
            next_offset + 1,
        )

    old_root, new_root, consumed = rec(first_size, second_size, True, 0)
    if consumed != len(path):
        raise LedgerError("consistency proof path has too many hashes")
    return old_root, new_root


def run_verify_consistency(args: argparse.Namespace) -> int:
    bin_path = Path(args.bin)
    fields, proof_path = parse_proof(
        read_ascii(Path(args.proof), "consistency proof"),
        CONSISTENCY_FIELDS,
        CONSISTENCY_SCHEMA,
        "consistency proof",
    )
    first_size = parse_decimal(fields["first-size"], "first-size")
    second_size = parse_decimal(fields["second-size"], "second-size")
    first_root = fields["first-root-hash"]
    second_root = fields["second-root-hash"]
    require_hex(first_root, 64, "first-root-hash")
    require_hex(second_root, 64, "second-root-hash")
    if first_size == 0:
        if proof_path:
            raise LedgerError("empty-prefix consistency proof must have an empty path")
        if first_root != empty_root(bin_path):
            raise LedgerError("empty first root does not match ledger-empty-root")
        computed_second = second_root
    else:
        computed_first, computed_second = consistency_roots_from_proof(
            bin_path,
            first_size=first_size,
            second_size=second_size,
            first_root=first_root,
            path=proof_path,
        )
        if computed_first != first_root:
            raise LedgerError("consistency proof does not reconstruct first root")
    if first_size == second_size:
        computed_second = first_root
    if computed_second and computed_second != second_root:
        raise LedgerError("consistency proof does not reconstruct second root")
    print(f"valid consistency proof: {display_path(Path(args.proof))}")
    return 0


def load_heads_for_size(ledger_dir: Path, size: int) -> list[tuple[Path, dict[str, str], str]]:
    paths = ledger_paths(ledger_dir)
    heads_dir = paths["heads"]
    if not heads_dir.is_dir():
        raise LedgerError(f"ledger heads directory is missing: {heads_dir}")
    expected = {head_name(index) for index in range(size + 1)}
    observed = {path.name for path in heads_dir.iterdir()}
    if observed != expected:
        raise LedgerError("ledger heads do not match ledger history size")
    heads: list[tuple[Path, dict[str, str], str]] = []
    for index in range(size + 1):
        path = heads_dir / head_name(index)
        text = read_ascii(path, "ledger head")
        fields = parse_head(text)
        if parse_decimal(fields["tree-size"], "tree-size") != index:
            raise LedgerError("ledger head tree-size does not match its filename")
        if text != format_head(fields):
            raise LedgerError("ledger head bytes are not canonical")
        heads.append((path, fields, text))
    return heads


def run_verify_history(args: argparse.Namespace) -> int:
    ledger_dir = Path(args.ledger)
    bin_path = Path(args.bin)
    paths = ledger_paths(ledger_dir)
    latest_text = read_ascii(paths["latest_head"], "latest ledger head")
    latest = parse_head(latest_text)
    size = parse_decimal(latest["tree-size"], "tree-size")
    entry_paths = load_entries_for_size(ledger_dir, size)
    heads = load_heads_for_size(ledger_dir, size)
    leaf_hashes = leaf_hashes_for_entries(bin_path, entry_paths)

    for index, (_path, head, head_text) in enumerate(heads):
        root = merkle_root(bin_path, leaf_hashes[:index])
        if head["root-hash"] != root:
            raise LedgerError("ledger history head root does not match entries")
        if index == 0:
            if head["previous-tree-size"] != "0":
                raise LedgerError("empty head previous-tree-size must be zero")
            if head["previous-root-hash"] != ZERO64:
                raise LedgerError("empty head previous-root-hash must be zero")
            if head["entry-hash"] != ZERO64:
                raise LedgerError("empty head entry-hash must be zero")
        else:
            previous = heads[index - 1][1]
            if head["previous-tree-size"] != str(index - 1):
                raise LedgerError("ledger head previous-tree-size is not append-only")
            if head["previous-root-hash"] != previous["root-hash"]:
                raise LedgerError("ledger head previous-root-hash does not match prior head")
            entry_text = read_ascii(entry_paths[index - 1], "ledger entry")
            entry_hash = hashlib.sha256(entry_text.encode("ascii")).hexdigest()
            if head["entry-hash"] != entry_hash:
                raise LedgerError("ledger head entry-hash does not match entry bytes")
        if index == size and head_text != latest_text:
            raise LedgerError("latest ledger head does not match numbered history head")

    if size > 0:
        previous_text = read_ascii(paths["previous_head"], "previous ledger head")
        if previous_text != heads[size - 1][2]:
            raise LedgerError("previous ledger head does not match history")
        latest_entry = read_ascii(paths["latest_entry"], "latest ledger entry")
        if latest_entry != read_ascii(entry_paths[-1], "ledger entry"):
            raise LedgerError("latest ledger entry does not match history")
    print(f"valid ledger history: {display_path(ledger_dir)}")
    return 0


def add_bin_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", str(DEFAULT_BIN)),
        help="path to wuci-ji; defaults to WUCI_JI_BIN or build/wuci-ji",
    )
    wuci_verifier_identity.add_strict_args(parser)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WUCI-LEDGER append-only Merkle transparency log."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="initialize an empty ledger")
    add_bin_arg(init_parser)
    init_parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_DIR))
    init_parser.add_argument("--force", action="store_true")
    init_parser.set_defaults(func=run_init)

    append_parser = subparsers.add_parser("append", help="append a witness bundle")
    add_bin_arg(append_parser)
    append_parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_DIR))
    append_parser.add_argument("--witness-bundle", required=True)
    append_parser.set_defaults(func=run_append)

    inclusion_parser = subparsers.add_parser(
        "prove-inclusion",
        help="write an inclusion proof for a ledger sequence",
    )
    add_bin_arg(inclusion_parser)
    inclusion_parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_DIR))
    inclusion_parser.add_argument("--sequence", type=int, required=True)
    inclusion_parser.add_argument("--out", required=True)
    inclusion_parser.set_defaults(func=run_prove_inclusion)

    verify_inclusion_parser = subparsers.add_parser(
        "verify-inclusion",
        help="verify an inclusion proof against an entry and head",
    )
    add_bin_arg(verify_inclusion_parser)
    verify_inclusion_parser.add_argument("--entry", required=True)
    verify_inclusion_parser.add_argument("--proof", required=True)
    verify_inclusion_parser.add_argument("--head", required=True)
    verify_inclusion_parser.set_defaults(func=run_verify_inclusion)

    consistency_parser = subparsers.add_parser(
        "prove-consistency",
        help="write an append-only consistency proof between two heads",
    )
    add_bin_arg(consistency_parser)
    consistency_parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_DIR))
    consistency_parser.add_argument("--from-head", required=True)
    consistency_parser.add_argument("--to-head", required=True)
    consistency_parser.add_argument("--out", required=True)
    consistency_parser.set_defaults(func=run_prove_consistency)

    verify_consistency_parser = subparsers.add_parser(
        "verify-consistency",
        help="verify an append-only consistency proof",
    )
    add_bin_arg(verify_consistency_parser)
    verify_consistency_parser.add_argument("--proof", required=True)
    verify_consistency_parser.set_defaults(func=run_verify_consistency)

    verify_history_parser = subparsers.add_parser(
        "verify-history",
        help="verify the complete append-only local ledger history",
    )
    add_bin_arg(verify_history_parser)
    verify_history_parser.add_argument("--ledger", default=str(DEFAULT_LEDGER_DIR))
    verify_history_parser.set_defaults(func=run_verify_history)

    args = parser.parse_args()
    try:
        if hasattr(args, "bin"):
            wuci_verifier_identity.enforce_args(args, Path(args.bin))
        return args.func(args)
    except (LedgerError, wuci_verifier_identity.VerifierIdentityError) as exc:
        print(f"wuci ledger: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
