#!/usr/bin/env python3
"""Deterministic, safe-I/O phrase firewall for bounded Daylight claims.

This scanner is defensive claim-policy tooling. It does not attempt semantic
proof, vulnerability discovery, or runtime enforcement.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import html
import json
import os
import re
import stat
import subprocess
import sys
from array import array
from pathlib import Path
from typing import Any, Sequence

try:
    import wuci_safeio
    if not hasattr(wuci_safeio, "read_regular_bytes"):
        raise ImportError("wrong wuci_safeio module")
except ImportError:  # pragma: no cover - package import path used by tests
    from tools import wuci_safeio  # type: ignore[no-redef]


SCHEMA = "daylight-claim-scan-report-v1"
POLICY = "daylight-authority-phrase-firewall-v1"
BOUNDARY = (
    "This local phrase firewall detects configured authority phrases. "
    "It does not prove security, certification, production readiness, runtime "
    "containment, quantum safety, or the absence of other unsupported claims."
)

DEFAULT_MAX_FILE_BYTES = 1_048_576
DEFAULT_MAX_FILES = 256
DEFAULT_MAX_TOTAL_BYTES = 8_388_608
DEFAULT_MAX_OCCURRENCES = 10_000
DEFAULT_MAX_INLINE_BYTES = 65_536
DEFAULT_MAX_INLINE_OCCURRENCES = 256
DEFAULT_MAX_JSON_STRINGS = 20_000
DEFAULT_MAX_JSON_DEPTH = 64
MAX_NEGATION_CLAUSE_CHARS = 16_384
MAX_DISCOVERY_DEPTH = 64
DISCOVERY_ENTRY_FACTOR = 16

FORBIDDEN_AUTHORITY_PATTERNS = (
    "production cryptography",
    "general runtime sandbox",
    "runtime sandboxing",
    "runtime containment",
    "post-quantum secure",
    "quantum-safe",
    "independently audited",
    "department of war approved",
    "government endorsed",
    "government approved",
    "cato authorized",
    "rmf authorized",
    "fips validated",
    "fedramp authorized",
    "common criteria certified",
    "niap certified",
    "production authority",
    "publish authority",
    "trust authority",
    "replacement for edr",
    "replacement for siem",
    "replacement for iam",
)

_NEGATED_LIST_RE = re.compile(
    r"(?:"
    r"\b(?:do|does|did|must|should|shall|can|could|would)\s+not\s+"
    r"(?:claim|assert|prove|establish|confer|imply|create|provide|constitute|represent|"
    r"certify|validate|authorize|endorse|grant|make|describe|say)\b"
    r"|\bcannot\s+(?:claim|assert|prove|establish|confer|imply|create|provide|constitute|"
    r"represent|certify|validate|authorize|endorse|grant|make|describe)\b"
    r"|\bwithout\s+(?:claiming|asserting|proving|establishing|conferring|implying|creating|"
    r"providing|certifying|validating|authorizing|endorsing|granting|describing)\b"
    r"|\bdo\s+not\s+say\s*:"
    r"|\b(?:must|should|shall|can|could|would|may)\s+not\s+be\s+described\s+as\b"
    r"|\bnot\s+(?:a\s+)?claim(?:\s+of)?\b"
    r"|\bno(?:\s+[\w-]+){0,6}\s+may\s+(?:claim|assert|describe)\b"
    r"|\b(?:forbidden|unsupported|rejected|reserved)\s*:"
    r"|\b(?:forbidden|unsupported|rejected|reserved)\s+"
    r"(?:authority\s+)?(?:claim|claims|language|phrase|phrases|expansion|expansions)\b"
    r"|\bnon[- ]claims?\b"
    r")",
    re.IGNORECASE,
)
_DIRECT_NEGATION_RE = re.compile(
    r"(?:"
    r"\bnot(?:\s+(?:a|an|the|whole-system|general|current|external|local)){0,3}"
    r"|\bno(?:\s+(?:claim|assertion|authority)\s+(?:of|that|to))?"
    r"|\b(?:has|have|had)\s+not\s+been"
    r")\s*$",
    re.IGNORECASE,
)
_IMMEDIATE_FOLLOWING_NEGATION_RE = re.compile(
    r"^\s+(?:is|are|was|were|remain|remains)\s+"
    r"(?:not\s+(?:allowed|authorized|available|claimed|complete|created|enforced|established|"
    r"implemented|proven|provided|supplied|supported)"
    r"|future-gated)\b",
    re.IGNORECASE,
)
_NEGATION_SUFFIX_REVERSAL_RE = re.compile(
    r"\b(?:albeit|although|as|asserts?|because|boasts?|but|claims?|despite|except|grants?|"
    r"however|is|are|was|were|has|have|had|nevertheless|nonetheless|notwithstanding|"
    r"offers?|plus|provides?|remain|remains|establishes?|then|though|while|whereas|yet)\b",
    re.IGNORECASE,
)
_DIRECT_NEGATION_CONTRAST_RE = re.compile(
    r"\b(?:albeit|although|but|despite|except|however|nevertheless|nonetheless|"
    r"notwithstanding|save|though|whereas|yet)\b",
    re.IGNORECASE,
)
_DIRECT_NEGATION_POSITIVE_RE = re.compile(
    r"(?:"
    r"\b(?:can\s+be|has\s+been|have\s+been|is|are|was|were|remain|remains)\s+"
    r"(?:(?:actually|already|certainly|definitely|fully|indeed|now|really|still)\s+){0,3}"
    r"(?!not\b)(?:allowed|authorized|available|claimed|complete|created|enforced|"
    r"established|granted|implemented|proven|provided|real|supplied|supported|true)\b"
    r"|(?:^|[,/])\s*(?:(?:actually|certainly|definitely|indeed|really)\s+){0,3}"
    r"(?:allowed|authorized|available|claimed|complete|created|enforced|established|"
    r"granted|implemented|proven|provided|real|supplied|supported|true)\b"
    r")",
    re.IGNORECASE,
)
_CLAUSE_BOUNDARY_RE = re.compile(
    r"[.!?;]|\n\s*\n|</(?:p|li|article|section|h[1-6])\s*>",
    re.IGNORECASE,
)
_MARKUP_TOKEN_RE = re.compile(
    r"<!--.*?-->|<!\[CDATA\[|\]\]>|<[^>]*>|"
    r"&(?:#[0-9]{1,8}|#x[0-9A-Fa-f]{1,8}|[A-Za-z][A-Za-z0-9]{1,31});?",
    re.DOTALL,
)
_CANONICAL_HTML_DOCTYPE_RE = re.compile(r"<!\s*DOCTYPE\s+html\s*>", re.IGNORECASE)
_MARKUP_DECLARATION_START_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_MARKDOWN_NONCLAIM_HEADING_RE = re.compile(
    r"^\s{0,3}#{1,6}\s+.*\b(?:forbidden|unsupported|rejected|reserved|non[- ]claims?|does not claim)\b",
    re.IGNORECASE,
)
_PLAIN_NONCLAIM_LIST_MARKER_RE = re.compile(
    r"^\s*(?:do not say|forbidden(?: current)? claims?|unsupported claims?|explicit non[- ]claims?)\s*:\s*$",
    re.IGNORECASE,
)
_MARKDOWN_NONCLAIM_INTRO_RE = re.compile(
    r"^\s*(?:.*\b(?:is|are)\s+not\s+currently|the following\s+(?:is|are)\s+not\s+claimed)\s*:\s*$",
    re.IGNORECASE,
)
_MARKDOWN_LIST_PREFIX_RE = re.compile(r"^\s*(?:[-+*]|\d+[.)])\s+")
PUBLIC_TEXT_SUFFIXES = frozenset({".html", ".js", ".md", ".svg", ".txt", ".webmanifest", ".xml"})
PUBLIC_BOTTLE_SOURCE_SUFFIXES = frozenset({".html", ".json", ".md", ".svg", ".ts", ".txt"})
PUBLIC_RELEASE_TEXT_SUFFIXES = frozenset({".json", ".md", ".txt"})
PUBLIC_DOC_PATHS = frozenset({
    "docs/DAYLIGHT_EQUATION_STANDARD.md",
    "docs/PRODUCTION_READINESS.md",
    "docs/RELEASE_PROCESS.md",
    "docs/SECURITY_BOUNDARY.md",
    "docs/THREAT_MODEL.md",
    "docs/WUCI_ENTERPRISE_ADOPTION.md",
    "docs/WUCI_MARKET_POSITIONING.md",
    "docs/WUCI_SECURITY_PRODUCT_BOUNDARY.md",
    "docs/wucios/NOETHER_FORGE_EXTERNAL_REVIEW.md",
    "docs/wucios/NOETHER_FORGE_V240.md",
    "docs/wucios/NOETHER_CORE.md",
})


class ClaimScanWriteError(RuntimeError):
    """Raised when a deterministic report cannot be written safely."""


class ClaimOccurrenceLimitError(RuntimeError):
    """Raised when configured phrase occurrences exceed the report limit."""


class UnsupportedMarkupDeclarationError(RuntimeError):
    """Raised when rendered text depends on unexpanded DTD/entity declarations."""


class ClaimTextLimitError(ValueError):
    """Raised when an inline/structured claim exceeds deterministic limits."""


class TrackedSurfaceInventoryError(RuntimeError):
    """Raised when the deterministic tracked public-text inventory is unavailable."""


class DuplicateJsonKeyError(ValueError):
    """Raised when a public JSON surface contains an ambiguous duplicate key."""


def _phrase_regex(phrase: str) -> re.Pattern[str]:
    tokens = [re.escape(token) for token in re.split(r"[\s-]+", phrase) if token]
    body = r"(?:[\s-]+)".join(tokens)
    return re.compile(rf"(?<![\w-]){body}(?![\w-])", re.IGNORECASE)


_PHRASE_REGEXES = tuple((phrase, _phrase_regex(phrase)) for phrase in FORBIDDEN_AUTHORITY_PATTERNS)

_SIMPLE_PHRASE_LIST_WORDS = frozenset({
    "a",
    "an",
    "and",
    "any",
    "current",
    "external",
    "general",
    "its",
    "local",
    "niap",
    "or",
    "our",
    "production",
    "publish",
    "the",
    "their",
    "whole-system",
    "your",
})


def _configured_phrase_spans(text: str) -> list[tuple[int, int]]:
    candidates: list[tuple[int, int]] = []
    for _phrase, pattern in _PHRASE_REGEXES:
        candidates.extend((match.start(), match.end()) for match in pattern.finditer(text))
    candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    spans: list[tuple[int, int]] = []
    for start, end in candidates:
        if spans and start < spans[-1][1]:
            continue
        spans.append((start, end))
    return spans


def _is_simple_configured_phrase_list(text: str) -> bool:
    """Accept only configured phrases plus flat list punctuation/modifiers."""

    normalized = re.sub(
        r"<!--.*?-->|<!\[CDATA\[|\]\]>|<[^>]*>",
        " ",
        text,
        flags=re.DOTALL,
    )
    normalized = html.unescape(normalized)
    normalized = re.sub(r"(?m)^\s*(?:>|[-+*]|\d+[.)])\s?", " ", normalized)
    spans = _configured_phrase_spans(normalized)
    if not spans:
        return False
    outside_parts: list[str] = []
    cursor = 0
    for start, end in spans:
        outside_parts.append(normalized[cursor:start])
        outside_parts.append(" ")
        cursor = end
    outside_parts.append(normalized[cursor:])
    outside = "".join(outside_parts)
    words = [word.lower() for word in re.findall(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", outside)]
    if any(word not in _SIMPLE_PHRASE_LIST_WORDS for word in words):
        return False
    punctuation = re.sub(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", "", outside)
    return re.fullmatch(r"[\s,.!?;:/&()\[\]{}'\"`*_-]*", punctuation) is not None


def _markup_separator_view(text: str) -> tuple[str, array, array]:
    """Return rendered text plus normalized-index to source-span maps."""

    if _MARKUP_TOKEN_RE.search(text) is None:
        return text, array("I"), array("I")
    rendered: list[str] = []
    source_starts = array("I")
    source_ends = array("I")
    cursor = 0
    for match in _MARKUP_TOKEN_RE.finditer(text):
        if cursor < match.start():
            rendered.append(text[cursor:match.start()])
            source_starts.extend(range(cursor, match.start()))
            source_ends.extend(range(cursor + 1, match.start() + 1))
        token = match.group(0)
        replacement = html.unescape(token) if token.startswith("&") else " "
        if replacement == token:
            replacement = " "
        rendered.append(replacement)
        source_starts.extend([match.start()] * len(replacement))
        source_ends.extend([match.end()] * len(replacement))
        cursor = match.end()
    if cursor < len(text):
        rendered.append(text[cursor:])
        source_starts.extend(range(cursor, len(text)))
        source_ends.extend(range(cursor + 1, len(text) + 1))
    return "".join(rendered), source_starts, source_ends


def _has_unsupported_markup_declaration(text: str) -> bool:
    without_inert_html_doctype = _CANONICAL_HTML_DOCTYPE_RE.sub("", text)
    return _MARKUP_DECLARATION_START_RE.search(without_inert_html_doctype) is not None


def _markdown_table_cell_is_explicit_non_claim(text: str, start: int, end: int | None) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    relative_start = start - line_start
    if "|" not in line:
        return False
    cell_spans: list[tuple[int, int, str]] = []
    cursor = 0
    for raw_cell in line.split("|"):
        cell_start = cursor
        cell_end = cell_start + len(raw_cell)
        cell_spans.append((cell_start, cell_end, raw_cell))
        cursor = cell_end + 1
    matching = [item for item in cell_spans if item[0] <= relative_start <= item[1]]
    matching_cells = [cell for _begin, _finish, cell in matching]
    if len(matching_cells) != 1:
        return False
    cell_begin, _cell_finish, cell = matching[0]
    phrase_start = relative_start - cell_begin
    phrase_end = phrase_start + ((end - start) if end is not None else 0)
    marker_text = r"(?:not claimed|not supported|forbidden|unsupported|rejected|reserved|non[- ]claim)"
    global_leading = re.match(rf"^[\s:()\[\]-]*{marker_text}\b[\s:()\[\]-]*", cell, flags=re.IGNORECASE)
    global_trailing = re.search(rf"[\s:()\[\]-]*{marker_text}\b[\s:()\[\]-]*$", cell, flags=re.IGNORECASE)
    if global_leading is not None:
        return _is_simple_configured_phrase_list(cell[global_leading.end():])
    if global_trailing is not None:
        return _is_simple_configured_phrase_list(cell[:global_trailing.start()])
    prefix = re.sub(r"[*_`<>]", " ", cell[:phrase_start])
    suffix = re.sub(r"[*_`<>]", " ", cell[phrase_end:])
    leading_marker = re.search(
        r"\b(?:not claimed|not supported|forbidden|unsupported|rejected|reserved|non[- ]claim)\b"
        r"[\s:()\[\]-]*$",
        prefix,
        flags=re.IGNORECASE,
    )
    trailing_marker = re.match(
        r"^[\s:()\[\]-]*"
        r"(?:not claimed|not supported|forbidden|unsupported|rejected|reserved|non[- ]claim)\b",
        suffix,
        flags=re.IGNORECASE,
    )
    if leading_marker is not None:
        without_marker = cell[:leading_marker.start()] + cell[leading_marker.end():]
        return _is_simple_configured_phrase_list(without_marker)
    if trailing_marker is not None:
        marker_start = phrase_end + trailing_marker.start()
        marker_end = phrase_end + trailing_marker.end()
        without_marker = cell[:marker_start] + cell[marker_end:]
        return _is_simple_configured_phrase_list(without_marker)
    return False


def _markdown_list_is_under_nonclaim_heading(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    current_prefix = text[line_start:start]
    if _MARKDOWN_LIST_PREFIX_RE.match(current_prefix) is None:
        return False
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    if not _is_simple_configured_phrase_list(text[line_start:line_end]):
        return False
    previous_lines = text[max(0, line_start - 4_096):line_start].splitlines()
    for candidate in reversed(previous_lines[-32:]):
        if re.match(r"^\s{0,3}#{1,6}\s+", candidate):
            return _MARKDOWN_NONCLAIM_HEADING_RE.search(candidate) is not None
        if candidate.strip() and _PLAIN_NONCLAIM_LIST_MARKER_RE.fullmatch(candidate):
            return True
        if candidate.strip() and _MARKDOWN_NONCLAIM_INTRO_RE.fullmatch(candidate):
            continue
        if candidate.strip() and _MARKDOWN_LIST_PREFIX_RE.match(candidate) is None:
            return False
    return False


def _html_content_is_under_nonclaim_heading(text: str, start: int) -> bool:
    base = max(0, start - 8_192)
    prefix = text[base:start]
    headings = list(re.finditer(
        r"<h[1-6]\b[^>]*>(.*?)</h[1-6]\s*>",
        prefix,
        flags=re.IGNORECASE | re.DOTALL,
    ))
    if not headings:
        return False
    last_heading = headings[-1]
    heading = re.sub(r"<[^>]+>", " ", last_heading.group(1))
    heading = re.sub(r"\s+", " ", heading).strip()
    if re.search(
        r"\b(?:forbidden|unsupported|non[- ]claim|cannot be claimed|does not mean authority|do not use)\b",
        heading,
        flags=re.IGNORECASE,
    ) is None:
        return False
    after_heading = prefix[last_heading.end():]
    if re.search(r"</(?:article|section)\s*>", after_heading, flags=re.IGNORECASE):
        return False
    for tag in ("li", "p"):
        opened = list(re.finditer(rf"<{tag}\b[^>]*>", after_heading, flags=re.IGNORECASE))
        if not opened:
            continue
        last_open = opened[-1]
        last_close = after_heading.lower().rfind(f"</{tag}>")
        if last_close < last_open.start():
            if tag == "p" and "</p>" in after_heading[:last_open.start()].lower():
                return False
            open_end = base + last_heading.end() + last_open.end()
            close_start = text.lower().find(f"</{tag}>", start)
            if close_start == -1:
                return False
            return _is_simple_configured_phrase_list(text[open_end:close_start])
    return False


def _explicit_negative_list_applies(clause: str, phrase_text: str, suffix: str) -> bool:
    markers = list(_NEGATED_LIST_RE.finditer(clause))
    if not markers:
        return False
    whole_scope = clause[markers[-1].end():] + phrase_text + suffix
    return _is_simple_configured_phrase_list(whole_scope)


def _direct_negation_applies(suffix: str) -> bool:
    """Reject contrast or an active positive predicate after a direct negation."""

    if _DIRECT_NEGATION_CONTRAST_RE.search(suffix):
        return False
    return _DIRECT_NEGATION_POSITIVE_RE.search(suffix) is None


def _following_negation_applies(suffix: str) -> bool:
    matched = _IMMEDIATE_FOLLOWING_NEGATION_RE.match(suffix)
    if matched is None:
        return False
    local_tail = re.split(r"[.!?;\n]", suffix[matched.end():], maxsplit=1)[0]
    if "," in local_tail:
        return False
    return _NEGATION_SUFFIX_REVERSAL_RE.search(local_tail) is None


def phrase_is_negated(
    text: str,
    start: int,
    end: int | None = None,
    *,
    clause_start: int | None = None,
    clause_end: int | None = None,
) -> bool:
    """Return whether the occurrence at *start* is inside an explicit non-claim."""

    occurrence_end = end if end is not None else start
    if clause_start is None:
        clause_start = 0
        for boundary in _CLAUSE_BOUNDARY_RE.finditer(text, 0, start):
            clause_start = boundary.end()
    if clause_end is None:
        next_boundary = _CLAUSE_BOUNDARY_RE.search(text, occurrence_end)
        clause_end = next_boundary.start() if next_boundary is not None else len(text)
    if start - clause_start > MAX_NEGATION_CLAUSE_CHARS:
        return False
    if clause_end - occurrence_end > MAX_NEGATION_CLAUSE_CHARS:
        return False
    if _markdown_table_cell_is_explicit_non_claim(text, start, end):
        return True
    if _markdown_list_is_under_nonclaim_heading(text, start):
        return True
    if _html_content_is_under_nonclaim_heading(text, start):
        return True
    clause = text[clause_start:start]
    phrase_text = text[start:end] if end is not None else ""
    suffix = text[occurrence_end:clause_end]
    if _DIRECT_NEGATION_RE.search(clause) and _direct_negation_applies(suffix):
        return True
    if phrase_text and _explicit_negative_list_applies(clause, phrase_text, suffix):
        return True
    return _following_negation_applies(suffix)


def _line_start_offsets(text: str) -> list[int]:
    return [0, *(index + 1 for index, character in enumerate(text) if character == "\n")]


def _line_column(line_starts: list[int], start: int) -> tuple[int, int]:
    line_index = bisect.bisect_right(line_starts, start) - 1
    return line_index + 1, start - line_starts[line_index] + 1


def claim_phrase_occurrences(
    text: str,
    *,
    max_occurrences: int | None = None,
) -> list[dict[str, Any]]:
    """Return every configured phrase occurrence in deterministic source order."""

    if _has_unsupported_markup_declaration(text):
        raise UnsupportedMarkupDeclarationError
    matched_occurrences: dict[tuple[int, int, str], None] = {}
    markup_view, markup_starts, markup_ends = _markup_separator_view(text)
    for phrase, pattern in _PHRASE_REGEXES:
        for match in pattern.finditer(text):
            matched_occurrences[(match.start(), match.end(), phrase)] = None
            if max_occurrences is not None and len(matched_occurrences) > max_occurrences:
                raise ClaimOccurrenceLimitError
        if markup_starts:
            for match in pattern.finditer(markup_view):
                source_start = markup_starts[match.start()]
                source_end = markup_ends[match.end() - 1]
                matched_occurrences[(source_start, source_end, phrase)] = None
                if max_occurrences is not None and len(matched_occurrences) > max_occurrences:
                    raise ClaimOccurrenceLimitError

    boundaries = list(_CLAUSE_BOUNDARY_RE.finditer(text))
    boundary_starts = [match.start() for match in boundaries]
    boundary_ends = [match.end() for match in boundaries]
    occurrences: list[dict[str, Any]] = []
    line_starts = _line_start_offsets(text)
    for start, end, phrase in sorted(matched_occurrences, key=lambda item: (item[0], item[2], item[1])):
        previous_index = bisect.bisect_right(boundary_ends, start) - 1
        next_index = bisect.bisect_left(boundary_starts, end)
        clause_start = boundary_ends[previous_index] if previous_index >= 0 else 0
        clause_end = boundary_starts[next_index] if next_index < len(boundary_starts) else len(text)
        line, column = _line_column(line_starts, start)
        occurrences.append({
            "start": start,
            "line": line,
            "column": column,
            "phrase": phrase,
            "negated": phrase_is_negated(
                text,
                start,
                end,
                clause_start=clause_start,
                clause_end=clause_end,
            ),
        })
    return occurrences


def unsupported_claims_in_text(
    text: str,
    *,
    max_bytes: int = DEFAULT_MAX_INLINE_BYTES,
    max_occurrences: int = DEFAULT_MAX_INLINE_OCCURRENCES,
) -> list[str]:
    """Compatibility view returning each unsupported canonical phrase once."""

    if not isinstance(text, str):
        raise ClaimTextLimitError("claim text must be a string")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ClaimTextLimitError("claim text max_bytes must be a positive integer")
    if not isinstance(max_occurrences, int) or isinstance(max_occurrences, bool) or max_occurrences < 1:
        raise ClaimTextLimitError("claim text max_occurrences must be a positive integer")
    if len(text) > max_bytes:
        raise ClaimTextLimitError(f"claim text exceeds {max_bytes} UTF-8 bytes")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ClaimTextLimitError("claim text must be valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise ClaimTextLimitError(f"claim text exceeds {max_bytes} UTF-8 bytes")
    try:
        occurrences = claim_phrase_occurrences(text, max_occurrences=max_occurrences)
    except ClaimOccurrenceLimitError as exc:
        raise ClaimTextLimitError(f"claim text exceeds {max_occurrences} phrase occurrences") from exc
    except UnsupportedMarkupDeclarationError as exc:
        raise ClaimTextLimitError("claim text contains unsupported DTD/entity declarations") from exc

    unsupported = {
        occurrence["phrase"]
        for occurrence in occurrences
        if not occurrence["negated"]
    }
    return [phrase for phrase in FORBIDDEN_AUTHORITY_PATTERNS if phrase in unsupported]


def _is_tracked_public_claim_surface(path: str) -> bool:
    candidate = Path(path)
    suffix = candidate.suffix.lower()
    if path in {"README.md", "SECURITY.md"}:
        return True
    if path.startswith("docs/"):
        return path in PUBLIC_DOC_PATHS
    if path.startswith("site/"):
        return suffix in PUBLIC_TEXT_SUFFIXES
    if path.startswith("specs/"):
        return candidate.name == "README.md"
    if path.startswith("apps/bottle/"):
        if candidate.name in {"README.md", "DEPLOYMENT.md", "index.html"}:
            return True
        if path.startswith("apps/bottle/src/") and suffix == ".ts":
            return not candidate.name.endswith(".test.ts") and candidate.name != "build.d.ts"
        if path == "apps/bottle/worker/index.ts":
            return True
        if path.startswith("apps/bottle/public/"):
            return suffix in PUBLIC_BOTTLE_SOURCE_SUFFIXES or candidate.name == "_headers"
        return False
    if path.startswith("wucios/releases/"):
        return suffix in PUBLIC_RELEASE_TEXT_SUFFIXES
    return False


def _git_index_paths(scan_root: Path, pathspecs: Sequence[str]) -> list[str]:
    command = [
        "git",
        "-C",
        os.fspath(scan_root),
        "ls-files",
        "-z",
        "--",
        *pathspecs,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise TrackedSurfaceInventoryError("tracked public claim inventory could not run git") from exc
    if completed.returncode != 0:
        raise TrackedSurfaceInventoryError("tracked public claim inventory could not read the Git index")
    try:
        decoded = [item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise TrackedSurfaceInventoryError("tracked public claim inventory contains a non-UTF-8 path") from exc
    return sorted(set(decoded))


def tracked_public_claim_paths(root: Path | None = None) -> list[str]:
    """Return a deterministic Git-index inventory of current public claim text."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    indexed = _git_index_paths(scan_root, [
        "README.md",
        "SECURITY.md",
        "docs/**",
        "site/**",
        "specs/**",
        "apps/bottle/**",
        "wucios/releases/**",
    ])
    paths = [path for path in indexed if _is_tracked_public_claim_surface(path)]
    if not paths:
        raise TrackedSurfaceInventoryError("tracked public claim inventory is empty")
    return paths


def tracked_public_json_claim_paths(root: Path | None = None) -> list[str]:
    """Return every tracked public site JSON surface in deterministic order."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    paths = [
        path
        for path in _git_index_paths(scan_root, ["site/**"])
        if path.startswith("site/") and Path(path).suffix.lower() == ".json"
    ]
    if not paths:
        raise TrackedSurfaceInventoryError("tracked public JSON claim inventory is empty")
    return paths


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _json_path_key(path: str, key: str) -> str:
    return f"{path}[{json.dumps(key, ensure_ascii=True)}]"


def _normalized_json_key(key: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _explicit_json_nonclaim_key(key: str) -> bool:
    normalized = _normalized_json_key(key)
    if normalized in {"non_claim", "non_claims", "does_not_prove"}:
        return True
    return re.fullmatch(r"forbidden(?:_[a-z0-9]+)*_claims?", normalized) is not None


def _walk_public_json_strings(
    value: Any,
    *,
    json_path: str,
    explicit_nonclaim: bool,
    depth: int,
    counters: dict[str, int],
    findings: list[dict[str, str]],
    source_path: str,
    max_strings: int,
    max_occurrences: int,
    max_depth: int,
) -> None:
    if depth > max_depth:
        raise ClaimTextLimitError(f"public JSON exceeds nesting depth {max_depth}")
    if isinstance(value, dict):
        for key in sorted(value):
            child = value[key]
            rendered_key = json.dumps(key, ensure_ascii=True)
            _walk_public_json_strings(
                key,
                json_path=f"{json_path}.<key:{rendered_key}>",
                explicit_nonclaim=False,
                depth=depth + 1,
                counters=counters,
                findings=findings,
                source_path=source_path,
                max_strings=max_strings,
                max_occurrences=max_occurrences,
                max_depth=max_depth,
            )
            declared = _explicit_json_nonclaim_key(key)
            _walk_public_json_strings(
                child,
                json_path=_json_path_key(json_path, key),
                explicit_nonclaim=declared if isinstance(child, (str, list)) else False,
                depth=depth + 1,
                counters=counters,
                findings=findings,
                source_path=source_path,
                max_strings=max_strings,
                max_occurrences=max_occurrences,
                max_depth=max_depth,
            )
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk_public_json_strings(
                child,
                json_path=f"{json_path}[{index}]",
                explicit_nonclaim=explicit_nonclaim if isinstance(child, str) else False,
                depth=depth + 1,
                counters=counters,
                findings=findings,
                source_path=source_path,
                max_strings=max_strings,
                max_occurrences=max_occurrences,
                max_depth=max_depth,
            )
        return
    if not isinstance(value, str):
        return

    counters["strings"] += 1
    if counters["strings"] > max_strings:
        raise ClaimTextLimitError(f"public JSON exceeds {max_strings} string values")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ClaimTextLimitError("public JSON string must be valid UTF-8") from exc
    if len(encoded) > DEFAULT_MAX_INLINE_BYTES:
        raise ClaimTextLimitError(
            f"public JSON string exceeds {DEFAULT_MAX_INLINE_BYTES} UTF-8 bytes at {json_path}"
        )
    remaining = max_occurrences - counters["occurrences"]
    try:
        occurrences = claim_phrase_occurrences(value, max_occurrences=remaining)
    except ClaimOccurrenceLimitError as exc:
        raise ClaimTextLimitError(f"public JSON exceeds {max_occurrences} phrase occurrences") from exc
    except UnsupportedMarkupDeclarationError as exc:
        raise ClaimTextLimitError("public JSON contains unsupported DTD/entity declarations") from exc
    counters["occurrences"] += len(occurrences)
    if explicit_nonclaim and _is_simple_configured_phrase_list(value):
        return
    for occurrence in occurrences:
        if occurrence["negated"]:
            continue
        findings.append({
            "path": source_path,
            "json_path": json_path,
            "phrase": occurrence["phrase"],
        })


def scan_tracked_public_json_claims(
    *,
    root: Path | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_strings: int = DEFAULT_MAX_JSON_STRINGS,
    max_occurrences: int = DEFAULT_MAX_OCCURRENCES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
) -> dict[str, Any]:
    """Validate every key and string value in tracked public site JSON."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    limits = {
        "max_file_bytes": max_file_bytes,
        "max_files": max_files,
        "max_occurrences": max_occurrences,
        "max_depth": max_depth,
        "max_strings": max_strings,
        "max_total_bytes": max_total_bytes,
    }
    report: dict[str, Any] = {
        "schema": "daylight-public-json-claim-report-v1",
        "policy": POLICY,
        "boundary": BOUNDARY,
        "inputs": [],
        "limits": limits,
        "summary": {
            "bytes_scanned": 0,
            "files_scanned": 0,
            "phrase_occurrences": 0,
            "strings_scanned": 0,
            "unsupported_occurrences": 0,
        },
        "files": [],
        "findings": [],
        "errors": [],
        "status": "pass",
    }
    errors = report["errors"]
    for name, value in limits.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(_error("<limits>", "invalid-limit", f"{name} must be a positive integer"))
    if errors:
        report["status"] = "invalid-input"
        return report
    try:
        paths = tracked_public_json_claim_paths(scan_root)
    except TrackedSurfaceInventoryError as exc:
        errors.append(_error("<inputs>", "inventory-failed", str(exc)))
        paths = []
    report["inputs"] = paths
    if len(paths) > max_files:
        errors.append(_error("<inputs>", "max-files-exceeded", "public JSON scan exceeds file-count limit"))
        paths = paths[:max_files]

    total_bytes = 0
    counters = {"strings": 0, "occurrences": 0}
    file_records: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    for display in paths:
        path = _absolute_lexical(Path(display), scan_root)
        path_errors: list[dict[str, str]] = []
        if not _validate_ancestors(path, scan_root, path_errors):
            errors.extend(path_errors)
            continue
        try:
            info = os.lstat(path)
        except OSError:
            errors.append(_error(display, "read-failed", "public JSON input could not be inspected"))
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(_error(display, "input-symlink", "public JSON input must not be a symlink"))
            continue
        if not stat.S_ISREG(info.st_mode):
            errors.append(_error(display, "input-not-regular", "public JSON input must be a regular file"))
            continue
        if info.st_nlink != 1:
            errors.append(_error(display, "input-hardlink", "public JSON input must not be hardlinked"))
            continue
        if info.st_size > max_file_bytes:
            errors.append(_error(display, "file-too-large", "public JSON input exceeds per-file limit"))
            continue
        if total_bytes + info.st_size > max_total_bytes:
            errors.append(_error(display, "max-total-bytes-exceeded", "public JSON scan exceeds total-byte limit"))
            break
        try:
            data = wuci_safeio.read_regular_bytes(
                path,
                f"public JSON claim input {display}",
                reject_symlink=True,
                reject_hardlink=True,
                max_bytes=max_file_bytes,
            )
            if total_bytes + len(data) > max_total_bytes:
                errors.append(_error(
                    display,
                    "max-total-bytes-exceeded",
                    "public JSON scan exceeds total-byte limit",
                ))
                break
            text_value = data.decode("utf-8")
            parsed = json.loads(
                text_value,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonfinite_json_constant,
            )
        except wuci_safeio.SafeIOError:
            errors.append(_error(display, "read-failed", "public JSON failed safe regular-file reading"))
            continue
        except UnicodeDecodeError:
            errors.append(_error(display, "invalid-utf8", "public JSON must be valid UTF-8"))
            continue
        except DuplicateJsonKeyError:
            errors.append(_error(display, "duplicate-json-key", "public JSON must not contain duplicate keys"))
            continue
        except (json.JSONDecodeError, RecursionError, ValueError):
            errors.append(_error(display, "invalid-json", "public JSON must be valid bounded JSON"))
            continue

        strings_before = counters["strings"]
        try:
            _walk_public_json_strings(
                parsed,
                json_path="$",
                explicit_nonclaim=False,
                depth=0,
                counters=counters,
                findings=findings,
                source_path=display,
                max_strings=max_strings,
                max_occurrences=max_occurrences,
                max_depth=max_depth,
            )
        except ClaimTextLimitError as exc:
            errors.append(_error(display, "json-claim-limit-exceeded", str(exc)))
            break
        total_bytes += len(data)
        file_records.append({
            "path": display,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "strings_scanned": counters["strings"] - strings_before,
        })

    findings.sort(key=lambda item: (item["path"], item["json_path"], item["phrase"]))
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))
    report["files"] = file_records
    report["findings"] = findings
    report["summary"] = {
        "bytes_scanned": sum(item["bytes"] for item in file_records),
        "files_scanned": len(file_records),
        "phrase_occurrences": counters["occurrences"],
        "strings_scanned": counters["strings"],
        "unsupported_occurrences": len(findings),
    }
    report["status"] = "invalid-input" if errors else "fail" if findings else "pass"
    return report


def _absolute_lexical(path: Path, root: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    return Path(os.path.abspath(os.fspath(candidate)))


def _display_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "<outside-scan-root>"
    value = relative.as_posix()
    return value or "."


def _error(path: str, code: str, message: str) -> dict[str, str]:
    return {"path": path, "code": code, "message": message}


def _validate_ancestors(path: Path, root: Path, errors: list[dict[str, str]]) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        errors.append(_error("<outside-scan-root>", "unsafe-input-path", "input must stay under the scan root"))
        return False
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        display = _display_path(current, root)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            errors.append(_error(display, "input-not-found", "input ancestor does not exist"))
            return False
        except OSError:
            errors.append(_error(display, "read-failed", "input ancestor could not be inspected"))
            return False
        if stat.S_ISLNK(info.st_mode):
            errors.append(_error(display, "input-symlink", "input ancestor must not be a symlink"))
            return False
        if not stat.S_ISDIR(info.st_mode):
            errors.append(_error(display, "input-not-regular", "input ancestor must be a directory"))
            return False
    return True


def _discover_path(
    path: Path,
    root: Path,
    files: list[Path],
    seen_files: set[Path],
    seen_directories: set[Path],
    errors: list[dict[str, str]],
    max_files: int,
    limit_reached: list[bool],
    discovery_entries: list[int],
    max_discovery_entries: int,
    depth: int,
) -> None:
    if limit_reached[0]:
        return
    display = _display_path(path, root)
    if depth > MAX_DISCOVERY_DEPTH:
        errors.append(_error(
            display,
            "max-discovery-depth-exceeded",
            "scan exceeds the bounded directory-depth limit",
        ))
        limit_reached[0] = True
        return
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        errors.append(_error(display, "input-not-found", "input does not exist"))
        return
    except OSError:
        errors.append(_error(display, "read-failed", "input could not be inspected"))
        return

    if stat.S_ISLNK(info.st_mode):
        errors.append(_error(display, "input-symlink", "input must not be a symlink"))
        return
    if stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1:
            errors.append(_error(display, "input-hardlink", "input file must not be hardlinked"))
            return
        if path in seen_files:
            return
        if len(files) >= max_files:
            errors.append(_error(display, "max-files-exceeded", "scan exceeds the configured file-count limit"))
            limit_reached[0] = True
            return
        seen_files.add(path)
        files.append(path)
        return
    if stat.S_ISDIR(info.st_mode):
        if path in seen_directories:
            return
        seen_directories.add(path)
        children: list[Path] = []
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if discovery_entries[0] >= max_discovery_entries:
                        errors.append(_error(
                            display,
                            "max-discovery-entries-exceeded",
                            "scan exceeds the bounded directory-entry limit",
                        ))
                        limit_reached[0] = True
                        return
                    discovery_entries[0] += 1
                    children.append(Path(entry.path))
        except OSError:
            errors.append(_error(display, "read-failed", "input directory could not be enumerated"))
            return
        children.sort(key=lambda child: child.name)
        for child in children:
            _discover_path(
                child,
                root,
                files,
                seen_files,
                seen_directories,
                errors,
                max_files,
                limit_reached,
                discovery_entries,
                max_discovery_entries,
                depth + 1,
            )
        return
    errors.append(_error(display, "input-not-regular", "input must be a regular file or directory"))


def _base_report(
    inputs: list[str],
    max_file_bytes: int,
    max_files: int,
    max_total_bytes: int,
    max_occurrences: int,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "policy": POLICY,
        "boundary": BOUNDARY,
        "inputs": inputs,
        "limits": {
            "max_file_bytes": max_file_bytes,
            "max_files": max_files,
            "max_occurrences": max_occurrences,
            "max_total_bytes": max_total_bytes,
        },
        "summary": {
            "files_scanned": 0,
            "bytes_scanned": 0,
            "phrase_occurrences": 0,
            "negated_occurrences": 0,
            "unsupported_occurrences": 0,
        },
        "files": [],
        "findings": [],
        "errors": [],
        "status": "pass",
    }


def scan_paths(
    paths: Sequence[str | os.PathLike[str]],
    *,
    root: Path | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_occurrences: int = DEFAULT_MAX_OCCURRENCES,
) -> dict[str, Any]:
    """Scan explicit files/directories below *root* and return a stable report."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    normalized: list[Path] = []
    initial_errors: list[dict[str, str]] = []
    for raw_path in paths:
        candidate = _absolute_lexical(Path(raw_path), scan_root)
        if candidate in normalized:
            continue
        try:
            candidate.relative_to(scan_root)
        except ValueError:
            initial_errors.append(_error("<outside-scan-root>", "unsafe-input-path", "input must stay under the scan root"))
            continue
        if not _validate_ancestors(candidate, scan_root, initial_errors):
            continue
        normalized.append(candidate)
    normalized.sort(key=lambda path: _display_path(path, scan_root))
    inputs = [_display_path(path, scan_root) for path in normalized]
    reported_limits = [
        value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 1
        for value in (max_file_bytes, max_files, max_total_bytes, max_occurrences)
    ]
    report = _base_report(inputs, *reported_limits)
    errors = report["errors"]
    errors.extend(initial_errors)

    for name, value in [
        ("max_file_bytes", max_file_bytes),
        ("max_files", max_files),
        ("max_total_bytes", max_total_bytes),
        ("max_occurrences", max_occurrences),
    ]:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(_error("<limits>", "invalid-limit", f"{name} must be a positive integer"))
    if not paths:
        errors.append(_error("<inputs>", "no-inputs", "at least one input path is required"))
    if errors:
        report["errors"] = sorted(errors, key=lambda item: (item["path"], item["code"], item["message"]))
        report["status"] = "invalid-input"
        return report

    discovered: list[Path] = []
    seen_files: set[Path] = set()
    seen_directories: set[Path] = set()
    limit_reached = [False]
    discovery_entries = [0]
    max_discovery_entries = max_files * DISCOVERY_ENTRY_FACTOR
    for path in normalized:
        _discover_path(
            path,
            scan_root,
            discovered,
            seen_files,
            seen_directories,
            errors,
            max_files,
            limit_reached,
            discovery_entries,
            max_discovery_entries,
            0,
        )
    discovered.sort(key=lambda path: _display_path(path, scan_root))
    if not discovered and not errors:
        errors.append(_error("<inputs>", "no-files", "scan inputs contain no regular files"))

    total_bytes = 0
    phrase_occurrences = 0
    negated_occurrences = 0
    findings: list[dict[str, Any]] = []
    file_records: list[dict[str, Any]] = []
    for path in discovered:
        display = _display_path(path, scan_root)
        try:
            info = os.lstat(path)
        except OSError:
            errors.append(_error(display, "read-failed", "input could not be inspected before reading"))
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(_error(display, "input-symlink", "input must not be a symlink"))
            continue
        if not stat.S_ISREG(info.st_mode):
            errors.append(_error(display, "input-not-regular", "input must remain a regular file"))
            continue
        if info.st_nlink != 1:
            errors.append(_error(display, "input-hardlink", "input file must not be hardlinked"))
            continue
        if info.st_size > max_file_bytes:
            errors.append(_error(display, "file-too-large", "input exceeds the configured per-file size limit"))
            continue
        if total_bytes + info.st_size > max_total_bytes:
            errors.append(_error(display, "max-total-bytes-exceeded", "scan exceeds the configured total-byte limit"))
            break
        try:
            data = wuci_safeio.read_regular_bytes(
                path,
                f"claim scan input {display}",
                reject_symlink=True,
                reject_hardlink=True,
                max_bytes=max_file_bytes,
            )
        except wuci_safeio.SafeIOError:
            errors.append(_error(display, "read-failed", "input failed safe regular-file reading"))
            continue
        if total_bytes + len(data) > max_total_bytes:
            errors.append(_error(display, "max-total-bytes-exceeded", "scan exceeds the configured total-byte limit"))
            break
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(_error(display, "invalid-utf8", "input must be valid UTF-8 text"))
            continue

        total_bytes += len(data)
        file_records.append({
            "path": display,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        try:
            occurrences = claim_phrase_occurrences(
                text,
                max_occurrences=max_occurrences - phrase_occurrences,
            )
        except ClaimOccurrenceLimitError:
            errors.append(_error(
                display,
                "max-occurrences-exceeded",
                "scan exceeds the configured phrase-occurrence limit",
            ))
            break
        except UnsupportedMarkupDeclarationError:
            errors.append(_error(
                display,
                "unsupported-markup-declaration",
                "input contains unsupported DTD/entity declarations",
            ))
            break
        phrase_occurrences += len(occurrences)
        negated_occurrences += sum(1 for occurrence in occurrences if occurrence["negated"])
        for occurrence in occurrences:
            if occurrence["negated"]:
                continue
            findings.append({
                "path": display,
                "line": occurrence["line"],
                "column": occurrence["column"],
                "phrase": occurrence["phrase"],
            })

    file_records.sort(key=lambda item: item["path"])
    findings.sort(key=lambda item: (item["path"], item["line"], item["column"], item["phrase"]))
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))
    report["files"] = file_records
    report["findings"] = findings
    report["errors"] = errors
    report["summary"] = {
        "files_scanned": len(file_records),
        "bytes_scanned": sum(item["bytes"] for item in file_records),
        "phrase_occurrences": phrase_occurrences,
        "negated_occurrences": negated_occurrences,
        "unsupported_occurrences": len(findings),
    }
    report["status"] = "invalid-input" if errors else "fail" if findings else "pass"
    return report


def dump_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def write_report(path: Path, report: dict[str, Any]) -> None:
    try:
        wuci_safeio.atomic_replace_text(
            path,
            dump_report(report),
            "Daylight claim scan report",
            mode=0o644,
        )
    except wuci_safeio.SafeIOError as exc:
        raise ClaimScanWriteError("claim scan report could not be written safely") from exc


def report_path_overlaps_inputs(
    output: Path,
    paths: Sequence[str | os.PathLike[str]],
    *,
    root: Path | None = None,
) -> bool:
    """Return whether an output would overwrite or enter a scanned input tree."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    output_path = _absolute_lexical(output, scan_root)
    for raw_path in paths:
        input_path = _absolute_lexical(Path(raw_path), scan_root)
        try:
            info = os.lstat(input_path)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            if output_path == input_path or input_path in output_path.parents:
                return True
        elif output_path == input_path:
            return True
    return False


def report_exit_code(report: dict[str, Any]) -> int:
    if report["status"] == "invalid-input":
        return 2
    if report["status"] == "fail":
        return 1
    return 0


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", action="append", default=[], help="file or directory below the current directory")
    parser.add_argument(
        "--tracked-public",
        action="store_true",
        help="scan the deterministic Git-index inventory of current public claim surfaces",
    )
    parser.add_argument("--out", default="-", help="report path, or - for stdout")
    parser.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-files", type=_positive_int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-total-bytes", type=_positive_int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-occurrences", type=_positive_int, default=DEFAULT_MAX_OCCURRENCES)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = list(args.path)
    if args.tracked_public:
        try:
            paths.extend(tracked_public_claim_paths())
        except TrackedSurfaceInventoryError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    paths = sorted(set(paths))
    if not paths:
        print("at least one --path or --tracked-public input is required", file=sys.stderr)
        return 2
    report = scan_paths(
        paths,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
        max_total_bytes=args.max_total_bytes,
        max_occurrences=args.max_occurrences,
    )
    if args.out == "-":
        print(dump_report(report), end="")
    else:
        output = _absolute_lexical(Path(args.out), Path.cwd().resolve(strict=True))
        try:
            output.relative_to(Path.cwd().resolve(strict=True))
        except ValueError:
            print("claim scan report path must stay under the current directory", file=sys.stderr)
            return 2
        if report_path_overlaps_inputs(output, paths):
            print("claim scan report path must not overlap a scanned input", file=sys.stderr)
            return 2
        try:
            write_report(output, report)
        except ClaimScanWriteError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    return report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
