"""Numeric token extraction for DaylightNPT v1."""

from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path


NUMBER_RE = re.compile(
    r"(?P<score>\b\d[\d,]*(?:\.\d+)?\s*M\s*/\s*\d[\d,]*(?:\.\d+)?\s*M\b)"
    r"|(?P<digest>\b(?:sha256|SHA-256|sha3-512|SHA3-512)\s*[:=]\s*[0-9A-Za-z]{8,160}\b)"
    r"|(?P<quorum>\b\d+\s*(?:-of-| of )\s*\d+\b|\bexactly\s+\d+\b)"
    r"|(?P<ratio>\b\d[\d,]*(?:\.\d+)?\s*/\s*\d[\d,]*(?:\.\d+)?\b)"
    r"|(?P<percent>\b\d[\d,]*(?:\.\d+)?%)"
    r"|(?P<date>\b\d{4}-\d{2}-\d{2}\b)"
    r"|(?P<version>\bv\d+(?:\.\d+)+\b|\b\d+\.\d+\.\d+\b)"
    r"|(?P<number>\b\d[\d,]*(?:\.\d+)?\b)"
)

CODE_FENCE_RE = re.compile(r"^\s*```")


@dataclass(frozen=True)
class NumberToken:
    path: str
    line: int
    column: int
    value_raw: str
    value_canonical: str
    kind: str
    context: str


def canonical_number(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip()).replace(",", "")


def strip_code_fences(text: str) -> str:
    """Blank fenced code blocks while preserving line numbers."""
    in_fence = False
    out: list[str] = []
    for line in text.splitlines():
        if CODE_FENCE_RE.match(line):
            in_fence = not in_fence
            out.append("")
            continue
        if in_fence or line.startswith("    "):
            out.append("")
        else:
            out.append(line)
    return "\n".join(out)


def is_probably_binary(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return True
    return b"\x00" in chunk


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if b"\x00" in raw[:4096]:
        raise UnicodeDecodeError("utf-8", raw, 0, 1, "binary file")
    return raw.decode("utf-8")


def extract_tokens_from_text(text: str, path: str) -> list[NumberToken]:
    scanned = strip_code_fences(text)
    tokens: list[NumberToken] = []
    for line_no, line in enumerate(scanned.splitlines(), start=1):
        for match in NUMBER_RE.finditer(line):
            kind = match.lastgroup or "number"
            value_raw = match.group(0)
            tokens.append(
                NumberToken(
                    path=path,
                    line=line_no,
                    column=match.start() + 1,
                    value_raw=value_raw,
                    value_canonical=canonical_number(value_raw),
                    kind=kind,
                    context=line.strip(),
                )
            )
    return tokens


def extract_tokens(path: Path, display_path: str) -> list[NumberToken]:
    return extract_tokens_from_text(read_text(path), display_path)
