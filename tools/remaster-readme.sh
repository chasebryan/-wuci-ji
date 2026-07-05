#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
README="README.md"
SCORE="96.0 / 100.0"
ARTIFACT_SHA256="95f3cb750357eeb2cd840ddfc7b62c6addf08b2d66079871a4d8e8efdd9ae45f"
SECTION_TITLE="## WuciOS v2.4 Reviewer/Status Baseline"
POST_MAIN_DOC="docs/wucios/v2.4/post-main-adoption-stabilization.md"
PR_PACKET_DOC="docs/wucios/v2.4/pr-merge-consideration-packet.md"
LEDGER_DOC="docs/wucios/v2.4/gate-status-ledger.md"

usage() {
  printf '%s\n' "usage: tools/remaster-readme.sh --check|--fix|--write" >&2
}

fail() {
  printf 'readme-remaster: %s\n' "$1" >&2
  exit 1
}

require_readme() {
  [ -f "$README" ] || fail "missing $README"
}

check_contains() {
  local needle="$1"
  if ! grep -Fq "$needle" "$README"; then
    fail "README.md missing required anchor: $needle"
  fi
}

check_claim_boundaries() {
  python3 - "$README" <<'PY'
import sys
from pathlib import Path

readme = Path(sys.argv[1])
text = readme.read_text(encoding="utf-8")
lines = text.splitlines()

forbidden_phrases = [
    "is production ready",
    "production-ready",
    "externally validated",
    "external validation is claimed",
    "claims external validation",
    "full runtime validation is claimed",
    "claims full runtime validation",
    "runtime validation complete",
    "production readiness is claimed",
    "claims production readiness",
    "operational deployment approved",
]

allowed_boundary_markers = [
    "does not",
    "do not",
    "not ",
    "no ",
    "without",
    "non-claim",
    "boundary",
    "blocker",
    "refuses",
    "unproven",
    "cannot",
]

for index, line in enumerate(lines, start=1):
    lowered = line.lower()
    for phrase in forbidden_phrases:
        if phrase in lowered:
            print(
                f"readme-remaster: unsupported README claim at line {index}: {line}",
                file=sys.stderr,
            )
            sys.exit(1)
    for sensitive in [
        "production readiness",
        "external validation",
        "full runtime validation",
    ]:
        if sensitive in lowered and not any(marker in lowered for marker in allowed_boundary_markers):
            print(
                f"readme-remaster: unbounded README phrase at line {index}: {line}",
                file=sys.stderr,
            )
            sys.exit(1)
PY
}

check_readme() {
  require_readme
  check_contains "WuciOS v2.4 Reviewer/Status Baseline"
  check_contains "$SCORE"
  check_contains "$ARTIFACT_SHA256"
  check_contains "$POST_MAIN_DOC"
  check_contains "$PR_PACKET_DOC"
  check_contains "does not claim production readiness"
  check_contains "external validation"
  check_contains "full runtime"
  check_claim_boundaries
  printf '%s\n' "readme-remaster: README anchors and claim boundaries OK"
}

write_readme() {
  require_readme
  python3 - "$README" "$SCORE" "$ARTIFACT_SHA256" "$POST_MAIN_DOC" "$PR_PACKET_DOC" "$LEDGER_DOC" "$SECTION_TITLE" <<'PY'
import sys
from pathlib import Path

readme = Path(sys.argv[1])
score = sys.argv[2]
artifact_hash = sys.argv[3]
post_main_doc = sys.argv[4]
pr_packet_doc = sys.argv[5]
ledger_doc = sys.argv[6]
section_title = sys.argv[7]

text = readme.read_text(encoding="utf-8")
section = f"""{section_title}

`main` adopts the WuciOS v2.4 reviewer/status-documentation baseline. The
baseline is a public review and status integration boundary, not a production or
deployment authorization.

- Post-main adoption stabilization: [{post_main_doc}]({post_main_doc})
- PR/merge packet: [{pr_packet_doc}]({pr_packet_doc})
- Gate status ledger: [{ledger_doc}]({ledger_doc})
- WuciOS v2.4 Alpine Substrate Trial Score: `{score}`
- Canonical artifact SHA-256:
  `{artifact_hash}`

This does not claim production readiness, external validation, full runtime
validation, bootability, long-running stability, operational deployment
approval, certification or accreditation, government endorsement, or a score
increase. Raw runtime evidence remains local/ignored unless separately
authorized.
"""

lines = text.splitlines()
out = []
index = 0
replaced = False
while index < len(lines):
    line = lines[index]
    if line == section_title:
        if out and out[-1] != "":
            out.append("")
        out.extend(section.splitlines())
        replaced = True
        index += 1
        while index < len(lines) and not lines[index].startswith("## "):
            index += 1
        if index < len(lines) and out and out[-1] != "":
            out.append("")
        continue
    if not replaced and line == "## Daylight score-integrity audits":
        if out and out[-1] != "":
            out.append("")
        out.extend(section.splitlines())
        out.append("")
        replaced = True
    out.append(line)
    index += 1

if not replaced:
    if out and out[-1] != "":
        out.append("")
    out.extend(section.splitlines())

new_text = "\n".join(out).rstrip() + "\n"
if new_text != text:
    readme.write_text(new_text, encoding="utf-8")
    print("readme-remaster: README.md updated")
else:
    print("readme-remaster: README.md already current")
PY
}

case "$MODE" in
  --check)
    check_readme
    ;;
  --fix|--write)
    write_readme
    check_readme
    ;;
  *)
    usage
    exit 2
    ;;
esac
