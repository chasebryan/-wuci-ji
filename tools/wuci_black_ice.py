#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


TOOL_NAME = "WUCI-NOXFRAME"
LEGACY_TOOL_NAME = "WUCI-BLACK-ICE"
REPORT_SCHEMA = "wuci-noxframe-launch-report-v1"
SEAL_SCHEMA = "wuci-noxframe-seal-v1"
DEFAULT_REPORT = "docs/noxframe/WUCI_NOXFRAME_LAUNCH_REPORT.md"
DEFAULT_SEAL = "docs/noxframe/WUCI_NOXFRAME_SELF_SEAL.json"
DEFAULT_CLOCK = "build/noxframe/WUCI_NOXFRAME_CLOCK.json"
DEFAULT_DEMO_ROOT = "build/wuci-noxframe-runs"
GATE_DEMO_DIRNAME = "gate-demo"
WEEK_SECONDS = 7 * 24 * 60 * 60
ANCHOR_PATHS = (
    "docs/SECURITY_BOUNDARY.md",
    "docs/wuci_gate_boundary.json",
    "docs/wuci_cage_policy.json",
    "docs/wuci_qcage_policy.json",
    "docs/wuci_high_attestation_profile.json",
    "daylight-equation/SCORECARD.v1.json",
    "daylight-equation/specs/daylight-minimal-core-v0.4.md",
    "daylight-equation/rust/daylight-crypto/src/wuci_daylight.rs",
)
BOOT_LINES = (
    "SYSTEMS BOOTING...",
    "ENTROPY BUS WARMING...",
    "GATE MATRIX LOCKING...",
    "PRISM TICKERS ARMED...",
    "WUCI-JI SYSTEM INITIALIZED...",
)
FRAMES = ("[////]", "[////]", "[\\\\\\\\]", "[||||]", "[====]", "[####]")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


@dataclass(frozen=True)
class Step:
    signal: str
    label: str
    command: tuple[str, ...]
    note: str
    requires_python_modules: tuple[str, ...] = ()


@dataclass
class StepResult:
    step: Step
    returncode: int
    started_utc: str
    ended_utc: str
    elapsed_seconds: float
    output: str


@dataclass(frozen=True)
class SkippedLane:
    label: str
    reason: str
    command: str


@dataclass(frozen=True)
class ClockDecision:
    requested_profile: str
    effective_profile: str
    clock_path: Path
    reason: str
    now_utc: str
    anchor_utc: str | None
    next_full_due_utc: str | None
    seconds_until_full: int
    state: dict[str, object]


class NoxframeError(RuntimeError):
    pass


class Palette:
    def __init__(self, mode: str) -> None:
        self.enabled = mode == "always" or (mode == "auto" and sys.stderr.isatty())

    def paint(self, text: str, code: str) -> str:
        if not self.enabled:
            return text
        return f"\x1b[{code}m{text}\x1b[0m"

    @property
    def cyan(self) -> str:
        return "36"

    @property
    def green(self) -> str:
        return "32"

    @property
    def red(self) -> str:
        return "31"

    @property
    def yellow(self) -> str:
        return "33"

    @property
    def magenta(self) -> str:
        return "35"

    @property
    def dim(self) -> str:
        return "2"

    @property
    def bold(self) -> str:
        return "1"


class LiveTicker:
    def __init__(self, palette: Palette, label: str) -> None:
        self.palette = palette
        self.label = label
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.started = time.monotonic()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def _spin(self) -> None:
        tick = 0
        while not self.stop_event.is_set():
            elapsed = time.monotonic() - self.started
            frame = FRAMES[tick % len(FRAMES)]
            color = (self.palette.cyan, self.palette.green, self.palette.yellow, self.palette.magenta)[
                tick % 4
            ]
            line = (
                f"\r{self.palette.paint(frame, color)} "
                f"{self.palette.paint(TOOL_NAME, self.palette.bold)} // "
                f"{self.palette.paint(self.label, color)} // T+{elapsed:06.1f}s"
            )
            with self.lock:
                sys.stderr.write(line)
                sys.stderr.flush()
            tick += 1
            time.sleep(0.16)

    def clear(self) -> None:
        with self.lock:
            sys.stderr.write("\r" + " " * 120 + "\r")
            sys.stderr.flush()

    def stop(self, ok: bool) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
        self.clear()
        status = "PASS" if ok else "FAIL"
        color = self.palette.green if ok else self.palette.red
        sys.stderr.write(
            f"{self.palette.paint(status, color)} // {TOOL_NAME} // {self.label}\n"
        )
        sys.stderr.flush()


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run_demo_dir() -> str:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    nonce = uuid.uuid4().hex[:12]
    return f"{DEFAULT_DEMO_ROOT}/{stamp}-{os.getpid()}-{nonce}/{GATE_DEMO_DIRNAME}"


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def format_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def command_text(command: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def sanitize_output(value: str) -> str:
    cleaned = ANSI_RE.sub("", value)
    cleaned = cleaned.replace("\r", "\n")
    return "".join(ch for ch in cleaned if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def missing_python_modules(step: Step) -> tuple[str, ...]:
    return tuple(
        module
        for module in step.requires_python_modules
        if importlib.util.find_spec(module) is None
    )


def digest_vector(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": hashlib.sha384(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def read_public_anchor(root: Path, relative_path: str) -> tuple[bytes, os.stat_result]:
    path = root / relative_path
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise NoxframeError(f"missing public anchor: {relative_path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise NoxframeError(f"public anchor must not be a symlink: {relative_path}")
    if not stat.S_ISREG(info.st_mode):
        raise NoxframeError(f"public anchor must be a regular file: {relative_path}")
    if info.st_nlink != 1:
        raise NoxframeError(f"public anchor must not be hardlinked: {relative_path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise NoxframeError(f"could not open public anchor: {relative_path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise NoxframeError(f"public anchor changed type while opening: {relative_path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise NoxframeError(f"public anchor changed while opening: {relative_path}")
        if opened.st_nlink != 1:
            raise NoxframeError(f"public anchor must not be hardlinked: {relative_path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), opened
    finally:
        os.close(fd)


def anchor_record(root: Path, relative_path: str) -> dict[str, object]:
    data, info = read_public_anchor(root, relative_path)
    return {
        "path": relative_path,
        "bytes": len(data),
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "digest_vector": digest_vector(data),
    }


def read_clock_state(clock_path: Path) -> dict[str, object]:
    try:
        info = os.lstat(clock_path)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise NoxframeError(f"could not stat NOXFRAME clock: {clock_path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise NoxframeError(f"NOXFRAME clock must not be a symlink: {clock_path}")
    if not stat.S_ISREG(info.st_mode):
        raise NoxframeError(f"NOXFRAME clock must be a regular file: {clock_path}")
    if info.st_nlink != 1:
        raise NoxframeError(f"NOXFRAME clock must not be hardlinked: {clock_path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(clock_path, flags)
    except OSError as exc:
        raise NoxframeError(f"could not open NOXFRAME clock: {clock_path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise NoxframeError(f"NOXFRAME clock changed type while opening: {clock_path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise NoxframeError(f"NOXFRAME clock changed while opening: {clock_path}")
        raw = b""
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"schema": "wuci-noxframe-clock-v1", "clock_invalid": True}
    if not isinstance(value, dict):
        return {"schema": "wuci-noxframe-clock-v1", "clock_invalid": True}
    return dict(value)


def resolve_profile(
    requested_profile: str,
    *,
    clock_path: Path,
    state: dict[str, object],
    now: dt.datetime,
) -> ClockDecision:
    now = now.astimezone(dt.UTC)
    if requested_profile != "auto":
        anchor = (
            parse_utc(state.get("full_due_anchor_utc"))
            or parse_utc(state.get("last_full_launch_utc"))
            or parse_utc(state.get("clock_started_utc"))
        )
        next_due = anchor + dt.timedelta(seconds=WEEK_SECONDS) if anchor else None
        return ClockDecision(
            requested_profile=requested_profile,
            effective_profile=requested_profile,
            clock_path=clock_path,
            reason=f"explicit {requested_profile} profile requested",
            now_utc=format_utc(now),
            anchor_utc=format_utc(anchor) if anchor else None,
            next_full_due_utc=format_utc(next_due) if next_due else None,
            seconds_until_full=max(0, int((next_due - now).total_seconds())) if next_due else 0,
            state=state,
        )

    if not state:
        anchor = now
        next_due = anchor + dt.timedelta(seconds=WEEK_SECONDS)
        return ClockDecision(
            requested_profile="auto",
            effective_profile="smoke",
            clock_path=clock_path,
            reason="clock initialized; quick mode selected until the first 7-day full check",
            now_utc=format_utc(now),
            anchor_utc=format_utc(anchor),
            next_full_due_utc=format_utc(next_due),
            seconds_until_full=WEEK_SECONDS,
            state=state,
        )

    anchor = (
        parse_utc(state.get("full_due_anchor_utc"))
        or parse_utc(state.get("last_full_launch_utc"))
        or parse_utc(state.get("clock_started_utc"))
    )
    if state.get("clock_invalid") or anchor is None:
        return ClockDecision(
            requested_profile="auto",
            effective_profile="full",
            clock_path=clock_path,
            reason="clock state has no valid 7-day anchor; full mode selected",
            now_utc=format_utc(now),
            anchor_utc=None,
            next_full_due_utc=None,
            seconds_until_full=0,
            state=state,
        )

    next_due = anchor + dt.timedelta(seconds=WEEK_SECONDS)
    seconds_until_full = int((next_due - now).total_seconds())
    if seconds_until_full <= 0:
        return ClockDecision(
            requested_profile="auto",
            effective_profile="full",
            clock_path=clock_path,
            reason="7-day NOXFRAME clock elapsed; full mode selected",
            now_utc=format_utc(now),
            anchor_utc=format_utc(anchor),
            next_full_due_utc=format_utc(next_due),
            seconds_until_full=0,
            state=state,
        )
    return ClockDecision(
        requested_profile="auto",
        effective_profile="smoke",
        clock_path=clock_path,
        reason="7-day NOXFRAME clock has not elapsed; quick mode selected",
        now_utc=format_utc(now),
        anchor_utc=format_utc(anchor),
        next_full_due_utc=format_utc(next_due),
        seconds_until_full=seconds_until_full,
        state=state,
    )


def write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_name, path)


def update_clock_state(
    decision: ClockDecision,
    *,
    ended_utc: str,
    launch_complete: bool,
) -> None:
    state = dict(decision.state)
    if state.get("clock_invalid"):
        state = {}
    state["schema"] = "wuci-noxframe-clock-v1"
    state["interval_days"] = 7
    state.setdefault("clock_started_utc", decision.now_utc)
    state["last_launch_utc"] = ended_utc
    state["last_requested_profile"] = decision.requested_profile
    state["last_effective_profile"] = decision.effective_profile
    state["last_result"] = "pass" if launch_complete else "fail"

    if decision.effective_profile == "full" and launch_complete:
        state["last_full_launch_utc"] = ended_utc
        state["full_due_anchor_utc"] = ended_utc
    elif decision.effective_profile == "smoke":
        state["last_quick_launch_utc"] = ended_utc
        state.setdefault("full_due_anchor_utc", decision.anchor_utc or decision.now_utc)

    anchor = parse_utc(state.get("full_due_anchor_utc"))
    if anchor is not None:
        state["next_full_due_utc"] = format_utc(anchor + dt.timedelta(seconds=WEEK_SECONDS))

    write_json_atomic(decision.clock_path, state)


def build_steps(
    profile: str,
    *,
    include_local_install: bool,
    demo_dir: str,
) -> list[Step]:
    demo_artifact = f"{demo_dir}/sealed.wj"
    demo_make_arg = f"GATE_DEMO_DIR={demo_dir}"
    smoke = [
        Step("SYSTEMS BOOTING...", "native artifact build", ("make", "all"), "Build the local assembly artifact."),
        Step(
            "WUCI-JI SYSTEM INITIALIZED...",
            "verifier core selftest",
            ("build/wuci-ji", "selftest"),
            "Exercise the native verifier selftest.",
        ),
        Step(
            "PRISM ARTIFACT FORGE...",
            "Gate demo artifact",
            ("make", "gate-demo", demo_make_arg),
            "Generate a disposable WJSEAL artifact and Gate receipt.",
        ),
        Step(
            "PRISM LIVE VIEW...",
            "Wuci-Prism live inspector",
            (
                "tools/wuci-prism",
                "inspect",
                demo_artifact,
                "--ticker",
                "always",
            ),
            "Inspect public WJSEAL structure without keys or plaintext release.",
        ),
        Step(
            "PRISM BOUNDARY LOCK...",
            "Wuci-Prism boundary",
            (
                "tools/wuci-prism",
                "boundary",
                demo_artifact,
                "--ticker",
                "always",
            ),
            "Show the keyless inspection and Gate-required boundary.",
        ),
        Step(
            "PRISM REGRESSION GRID...",
            "Wuci-Prism regression",
            ("make", "wuci-prism-test"),
            "Run the PRISM artifact-inspector regression tests.",
        ),
    ]
    if profile == "smoke":
        return smoke

    full = [
        Step("SYSTEMS BOOTING...", "native artifact build", ("make", "all"), "Build the local assembly artifact."),
        Step("CORE MEMORY CHECK...", "native test suite", ("make", "test"), "Run the full native test target."),
        Step("PRISM ARTIFACT FORGE...", "Gate demo artifact", ("make", "gate-demo", demo_make_arg), "Generate the demo sealed artifact."),
        Step(
            "PRISM LIVE VIEW...",
            "Wuci-Prism inspect",
            ("tools/wuci-prism", "inspect", demo_artifact, "--ticker", "always"),
            "Visible WJSEAL public-field inspection.",
        ),
        Step(
            "PRISM MANIFEST VECTOR...",
            "Wuci-Prism manifest",
            ("tools/wuci-prism", "manifest", demo_artifact, "--ticker", "always"),
            "Gate-compatible artifact manifest view.",
        ),
        Step(
            "PRISM NARRATIVE...",
            "Wuci-Prism explain",
            ("tools/wuci-prism", "explain", demo_artifact, "--ticker", "always"),
            "Human-readable no-plaintext boundary explanation.",
        ),
        Step(
            "PRISM BOUNDARY LOCK...",
            "Wuci-Prism boundary",
            ("tools/wuci-prism", "boundary", demo_artifact, "--ticker", "always"),
            "Keyless inspection and Gate-required release boundary.",
        ),
        Step("DAYLIGHT LINK...", "WUCI-Daylight bridge", ("make", "wuci-daylight-bridge-test"), "Bridge WJSEAL to the Daylight boundary."),
        Step("DAYLIGHT SCORE GRID...", "Daylight scorecard", ("make", "daylight-scorecard-test"), "Check Daylight score gates."),
        Step("DAYLIGHT REVIEW MODEL...", "Daylight peer review score", ("make", "daylight-v06-peer-review-score-test"), "Check the 10,000-point review model."),
        Step("DAYLIGHT CAP LOCK...", "Daylight cap removal", ("make", "daylight-v06-cap-removal-test"), "Check cap-removal blocker discipline."),
        Step("DAYLIGHT FAIL-CLOSED...", "Daylight fail-closed model", ("make", "daylight-v06-fail-closed-model-test"), "Check fail-closed ordering."),
        Step("DAYLIGHT M4...", "Daylight M4 symbolic model", ("make", "daylight-v06-m4-symbolic-model-test"), "Check M4 symbolic evidence."),
        Step("DAYLIGHT Z3...", "Daylight Z3 proof", ("make", "daylight-v06-m4-z3-proof-test"), "Check negated obligations with Z3 when available."),
        Step("DAYLIGHT SCHEMA...", "Daylight schema freeze", ("make", "daylight-v06-schema-freeze-test"), "Check schema freeze evidence."),
        Step("DAYLIGHT AUTHORITY...", "Daylight authority verifier", ("make", "daylight-v06-authority-verifier-test"), "Check public-authority candidate verifier."),
        Step("DAYLIGHT EXTERNAL REVIEW...", "Daylight external review packet", ("make", "daylight-v06-external-review-packet-test"), "Check external-review packet evidence."),
        Step("DAYLIGHT REVIEW VERIFY...", "Daylight external review verifier", ("make", "daylight-v06-external-review-verifier-test"), "Check signed external-review verifier."),
        Step("DAYLIGHT 1000 PREFLIGHT...", "Daylight 1000 preflight", ("make", "daylight-v06-1000-preflight-test"), "Check 1000 preflight gates."),
        Step("DAYLIGHT 1000 CLAIM...", "Daylight 1000 claim gate", ("make", "daylight-v06-1000-claim-gate-test"), "Check 1000 claim gate."),
        Step("DAYLIGHT 1000 CHECKPOINT...", "Daylight 1000 checkpoint", ("make", "daylight-v06-1000-checkpoint-test"), "Check guarded checkpoint writer."),
        Step(
            "DAYLIGHT M1 CROSS...",
            "Daylight M1 cross agreement",
            ("make", "daylight-v06-m1-cross-agreement-test"),
            "Check M1 fixture cross agreement.",
            ("cryptography",),
        ),
        Step(
            "DAYLIGHT M1 FIXTURE...",
            "Daylight M1 fixture",
            ("make", "daylight-v06-m1-fixture-test"),
            "Check M1 fixture lane.",
            ("cryptography",),
        ),
        Step(
            "DAYLIGHT M1 OPEN...",
            "Daylight M1 independent open",
            ("make", "daylight-v06-m1-independent-open-test"),
            "Check independent open fixture lane.",
            ("cryptography",),
        ),
        Step("DAYLIGHT M1 STATIC...", "Daylight M1 static vectors", ("make", "daylight-v06-m1-static-test"), "Check static M1 vectors."),
        Step("DAYLIGHT PROVIDER KEM...", "Daylight provider KEM", ("make", "daylight-v6-provider-kem-evidence-test"), "Check provider-backed KEM evidence."),
        Step("DAYLIGHT PRIVATE ROUND...", "Daylight private roundtrip", ("make", "daylight-v6-provider-private-roundtrip-test"), "Check provider-backed private roundtrip."),
        Step("DAYLIGHT VECTOR AGREEMENT...", "Daylight provider vector agreement", ("make", "daylight-v6-provider-vector-agreement-test"), "Check provider vector agreement."),
        Step("DAYLIGHT KAT...", "Daylight KAT reproduction", ("make", "daylight-v6-kat-reproduction-bundle-test"), "Check KAT reproduction bundle."),
        Step("DAYLIGHT REFERENCE OPEN...", "Daylight reference seal/open", ("make", "daylight-v6-reference-seal-open-test"), "Check reference seal/open evidence."),
        Step("NIGHTLIGHT NEGATIVE CORPUS...", "Daylight negative corpus", ("make", "daylight-v6-reference-negative-corpus-test"), "Check fail-closed negative corpus."),
        Step("NIGHTLIGHT BATTERY...", "Nightlight battery", ("make", "daylight-v6-nightlight-battery-test"), "Run the deterministic Nightlight battery."),
        Step("NIGHTLIGHT DEEP LEARN...", "Nightlight deep assessment", ("make", "daylight-v6-nightlight-deep-assessment-test"), "Run the deep defensive assessment."),
        Step(
            "NIGHTLIGHT SPARRING...",
            "Daylight/Nightlight sparring",
            ("bash", "daylight-equation/.nightlight/sparring.sh", "--quick", "--rounds", "1", "--no-clear"),
            "Run one local defensive sparring round.",
        ),
        Step("GATE MATRIX...", "Gate policy matrix", ("make", "gate-policy-matrix"), "Run Gate rejection matrix."),
        Step("GATE CONTRACT...", "Gate contract assembly", ("make", "gate-contract-asm"), "Run assembly Gate contract checks."),
        Step("GATE CONTRACT ZIG...", "Gate contract Zig", ("make", "gate-contract-zig"), "Run Zig Gate contract checks."),
        Step("PARSER HARDENING...", "Parser hardening proof", ("make", "parser-hardening-proof"), "Run parser corpus replay and checks."),
        Step("HARDEN-0...", "HARDEN-0 proof", ("make", "harden0-proof"), "Run the narrow HARDEN-0 perimeter."),
        Step("HARDEN...", "HARDEN proof", ("make", "harden-proof"), "Run the broader defensive hardening proof."),
        Step("CAGE AIRLOCK...", "CAGE proof", ("make", "cage-proof"), "Run CAGE public-evidence airlock proof."),
        Step("QCAGE CLAIM FILTER...", "QCAGE proof", ("make", "qcage-proof"), "Run QCAGE claim discipline proof."),
        Step("INSTALL SIGNATURE...", "Install verify", ("make", "install-verify"), "Verify signed install manifest and digest vector."),
        Step("INSTALL REGRESSION...", "Install tests", ("make", "install-test"), "Run install regression suite."),
        Step("RELEASE BUNDLE...", "Release bundle verification", ("make", "verify-release-bundle"), "Run release-bundle verification."),
        Step("PUBLIC VERIFY...", "Pythonless public verify", ("make", "pythonless-public-verify"), "Verify witness and ledger through public binaries."),
        Step("HIGH ATTESTATION...", "High-attestation proof", ("make", "high-attestation-proof"), "Run the composed high-attestation lane."),
    ]
    if include_local_install:
        full.append(
            Step(
                "LOCAL INSTALL MUTATION...",
                "Local install proof",
                ("make", "install-local"),
                "Copy local trust root, install under the configured prefix, and audit.",
            )
        )
    return full


def skipped_lanes(include_local_install: bool) -> list[SkippedLane]:
    lanes = [
        SkippedLane(
            "production-authority-verify",
            "requires an externally supplied non-fixture production authority root, ceremony, root key, and signature",
            "make production-authority-verify PRODUCTION_AUTHORITY_ROOT=... PRODUCTION_AUTHORITY_CEREMONY=... PRODUCTION_AUTHORITY_CEREMONY_ROOT_KEY=... PRODUCTION_AUTHORITY_CEREMONY_SIGNATURE=...",
        ),
        SkippedLane(
            "pq-verifier-real-attest",
            "requires an externally supplied pinned real PQ verifier and KAT material",
            "make pq-verifier-real-attest PQ_VERIFIER_BIN=... PQ_KAT_PUBLIC_KEY=... PQ_KAT_MESSAGE=... PQ_KAT_SIGNATURE=... REAL_PQ_VERIFIER_EVIDENCE=...",
        ),
        SkippedLane(
            "pq-verifier-real",
            "requires existing externally supplied real PQ verifier evidence",
            "make pq-verifier-real REAL_PQ_VERIFIER_EVIDENCE=...",
        ),
    ]
    if not include_local_install:
        lanes.append(
            SkippedLane(
                "install-local",
                "mutates the operator home prefix; pass --include-local-install to run it",
                "make install-local",
            )
        )
    return lanes


def print_banner(palette: Palette) -> None:
    lines = [
        " _   _  _____  __  __ _____ ____      _    __  __ _____ ",
        "| \\ | |/ _ \\ \\/ / |  ___|  _ \\    / \\  |  \\/  | ____|",
        "|  \\| | | | \\  /  | |_  | |_) |  / _ \\ | |\\/| |  _|  ",
        "| |\\  | |_| /  \\  |  _| |  _ <  / ___ \\| |  | | |___ ",
        "|_| \\_|\\___/_/\\_\\ |_|   |_| \\_\\/_/   \\_\\_|  |_|_____|",
    ]
    for line in lines:
        sys.stderr.write(palette.paint(line, palette.cyan) + "\n")
    sys.stderr.write(
        palette.paint(
            "WUCI-JI + Daylight defensive proof launch\n",
            palette.dim,
        )
    )
    sys.stderr.write(palette.paint(f"legacy alias: {LEGACY_TOOL_NAME}\n", palette.dim))
    sys.stderr.flush()


def countdown(seconds: int, palette: Palette) -> None:
    if seconds <= 0:
        return
    for remaining in range(seconds, 0, -1):
        label = BOOT_LINES[(seconds - remaining) % len(BOOT_LINES)]
        sys.stderr.write(
            f"{palette.paint('[BOOT]', palette.magenta)} {label} "
            f"{palette.paint(str(remaining), palette.yellow)}\n"
        )
        sys.stderr.flush()
        time.sleep(1)
    sys.stderr.write(palette.paint("[BOOT] WUCI-JI SYSTEM INITIALIZED...\n", palette.green))
    sys.stderr.flush()


def run_step(step: Step, root: Path, palette: Palette) -> StepResult:
    sys.stderr.write(
        f"\n{palette.paint('>>>', palette.cyan)} {palette.paint(step.signal, palette.yellow)} "
        f"{palette.paint(step.label, palette.bold)}\n"
    )
    sys.stderr.write(palette.paint(f"$ {command_text(step.command)}\n", palette.dim))
    sys.stderr.flush()

    ticker = LiveTicker(palette, step.signal)
    started = time.monotonic()
    started_utc = utc_now()
    output_parts: list[str] = []
    proc = subprocess.Popen(
        list(step.command),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        shell=False,
    )
    ticker.start()
    assert proc.stdout is not None
    for line in proc.stdout:
        ticker.clear()
        output_parts.append(line)
        sys.stdout.write(line)
        sys.stdout.flush()
    returncode = proc.wait()
    elapsed = time.monotonic() - started
    ticker.stop(returncode == 0)
    return StepResult(
        step=step,
        returncode=returncode,
        started_utc=started_utc,
        ended_utc=utc_now(),
        elapsed_seconds=elapsed,
        output="".join(output_parts),
    )


def skip_step(step: Step, palette: Palette, reason: str) -> None:
    sys.stderr.write(
        f"\n{palette.paint('SKIP', palette.yellow)} // {TOOL_NAME} // "
        f"{palette.paint(step.label, palette.bold)}\n"
    )
    sys.stderr.write(palette.paint(f"{reason}\n", palette.dim))
    sys.stderr.write(palette.paint(f"$ {command_text(step.command)}\n", palette.dim))
    sys.stderr.flush()


def git_value(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
        shell=False,
    )
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip() or "unknown"


def write_report(
    report_path: Path,
    *,
    root: Path,
    profile: str,
    requested_profile: str,
    clock_decision: ClockDecision,
    demo_dir: str,
    started_utc: str,
    ended_utc: str,
    results: list[StepResult],
    skipped: list[SkippedLane],
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    ok = all(result.returncode == 0 for result in results)
    total_seconds = sum(result.elapsed_seconds for result in results)
    head = git_value(root, "rev-parse", "HEAD")
    branch = git_value(root, "branch", "--show-current")
    lines = [
        "# WUCI-NOXFRAME Launch Report",
        "",
        f"- Schema: `{REPORT_SCHEMA}`",
        f"- Name: `{TOOL_NAME}`",
        f"- Working-title alias: `{LEGACY_TOOL_NAME}`",
        f"- Profile: `{profile}`",
        f"- Requested profile: `{requested_profile}`",
        f"- Clock reason: {clock_decision.reason}",
        f"- Clock path: `{clock_decision.clock_path}`",
        f"- Next full due UTC: `{clock_decision.next_full_due_utc or 'pending-full'}`",
        f"- Status: `{'PASS' if ok else 'FAIL'}`",
        f"- Started UTC: `{started_utc}`",
        f"- Ended UTC: `{ended_utc}`",
        f"- Runtime seconds: `{total_seconds:.1f}`",
        f"- Skipped/report-only lanes: `{len(skipped)}`",
        f"- Git branch: `{branch}`",
        f"- Git commit: `{head}`",
        f"- Working directory: `{root}`",
        f"- Gate demo workspace: `{demo_dir}`",
        "",
        "> Defensive launch output. NOXFRAME binds existing WUCI-JI and",
        "> Daylight evidence lanes into a launch record. It does not claim",
        "> production authority, runtime sandboxing, independent audit status,",
        "> hostile-code containment, or whole-system post-quantum safety.",
        "",
        "## Launch Matrix",
        "",
        "| # | Signal | Lane | Status | Seconds | Command |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for index, result in enumerate(results, 1):
        status = "PASS" if result.returncode == 0 else f"FAIL({result.returncode})"
        lines.append(
            "| {idx} | `{signal}` | {lane} | `{status}` | {seconds:.1f} | `{command}` |".format(
                idx=index,
                signal=result.step.signal,
                lane=result.step.label,
                status=status,
                seconds=result.elapsed_seconds,
                command=command_text(result.step.command).replace("|", "\\|"),
            )
        )
    lines.extend(["", "## Skipped And Report-Only Lanes", ""])
    if skipped:
        lines.extend(["| Lane | Reason | Command |", "| --- | --- | --- |"])
        for lane in skipped:
            escaped_command = lane.command.replace("|", "\\|")
            lines.append(f"| `{lane.label}` | {lane.reason} | `{escaped_command}` |")
    else:
        lines.append("No lanes were skipped.")
    lines.extend(["", "## Logs", ""])
    for index, result in enumerate(results, 1):
        status = "PASS" if result.returncode == 0 else f"FAIL({result.returncode})"
        lines.extend(
            [
                f"### {index}. {result.step.label} - {status}",
                "",
                f"Signal: `{result.step.signal}`",
                f"Command: `{command_text(result.step.command)}`",
                f"Note: {result.step.note}",
                "",
                "```text",
                sanitize_output(result.output).rstrip() or "(no output)",
                "```",
                "",
            ]
        )
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{report_path.name}.", dir=str(report_path.parent), text=True
    )
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip() + "\n")
    os.replace(tmp_name, report_path)


def write_self_seal(
    seal_path: Path,
    *,
    root: Path,
    profile: str,
    requested_profile: str,
    clock_decision: ClockDecision,
    demo_dir: str,
    results: list[StepResult],
    skipped: list[SkippedLane],
    include_local_install: bool,
    preflight_skipped_count: int,
) -> None:
    seal_path.parent.mkdir(parents=True, exist_ok=True)
    steps = build_steps(
        profile,
        include_local_install=include_local_install,
        demo_dir=demo_dir,
    )
    anchors = [anchor_record(root, relative_path) for relative_path in ANCHOR_PATHS]
    payload = {
        "schema": SEAL_SCHEMA,
        "name": TOOL_NAME,
        "working_title_alias": LEGACY_TOOL_NAME,
        "lineage": {
            "source_idea": "Bryforge/phase1 operator-console and nested-metadata concept",
            "adaptation": "WUCI-native defensive proof substrate; no Phase1 code import",
        },
        "posture": "defensive-public-evidence-orchestrator",
        "profile": profile,
        "requested_profile": requested_profile,
        "clock": {
            "schema": "wuci-noxframe-clock-v1",
            "path": str(clock_decision.clock_path),
            "reason": clock_decision.reason,
            "now_utc": clock_decision.now_utc,
            "anchor_utc": clock_decision.anchor_utc,
            "next_full_due_utc": clock_decision.next_full_due_utc,
            "seconds_until_full": clock_decision.seconds_until_full,
        },
        "gate_demo_workspace": demo_dir,
        "status": (
            "pass"
            if results
            and all(result.returncode == 0 for result in results)
            and len(results) + preflight_skipped_count == len(steps)
            else "fail"
        ),
        "host_effects": {
            "network": "unused",
            "shell": "disabled; subprocesses are invoked with shell=False",
            "local_install": "operator-opt-in" if include_local_install else "skipped",
        },
        "non_claims": [
            "not a kernel",
            "not OS runtime containment",
            "not hostile-code sandboxing",
            "not production authority",
            "not independent audit status",
            "not whole-system post-quantum safety",
        ],
        "anchors": anchors,
        "launch_commands": [
            {
                "signal": step.signal,
                "label": step.label,
                "command": list(step.command),
                "note": step.note,
                "requires_python_modules": list(step.requires_python_modules),
            }
            for step in steps
        ],
        "skipped_and_report_only_lanes": [
            {"label": lane.label, "reason": lane.reason, "command": lane.command}
            for lane in skipped
        ],
        "executed_results": [
            {
                "label": result.step.label,
                "signal": result.step.signal,
                "returncode": result.returncode,
                "elapsed_seconds": round(result.elapsed_seconds, 3),
            }
            for result in results
        ],
    }
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{seal_path.name}.", dir=str(seal_path.parent), text=True
    )
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_name, seal_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wuci-noxframe",
        description="NOXFRAME launcher for Wuci-Ji and Daylight proof lanes.",
    )
    parser.add_argument(
        "--profile",
        choices=("auto", "full", "smoke"),
        default="auto",
        help=(
            "auto runs quick mode until the 7-day clock is due; full runs the "
            "heavy proof matrix; smoke runs a short PRISM boot path"
        ),
    )
    parser.add_argument(
        "--report",
        default=DEFAULT_REPORT,
        help="Markdown report path, relative to the repository root unless absolute",
    )
    parser.add_argument(
        "--seal",
        default=DEFAULT_SEAL,
        help="JSON self-seal path, relative to the repository root unless absolute",
    )
    parser.add_argument(
        "--clock",
        default=DEFAULT_CLOCK,
        help="internal NOXFRAME clock path, relative to the repository root unless absolute",
    )
    parser.add_argument("--countdown", type=int, default=5, help="slow boot countdown seconds")
    parser.add_argument("--no-countdown", action="store_true", help="skip the boot countdown")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="terminal color mode",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="continue later lanes after a failure while still writing a failing report",
    )
    parser.add_argument(
        "--include-local-install",
        action="store_true",
        help="include make install-local, which writes to the configured local install prefix",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = root / report_path
    seal_path = Path(args.seal)
    if not seal_path.is_absolute():
        seal_path = root / seal_path
    clock_path = Path(args.clock)
    if not clock_path.is_absolute():
        clock_path = root / clock_path
    palette = Palette(args.color)
    print_banner(palette)
    if not args.no_countdown:
        countdown(max(args.countdown, 0), palette)

    started_utc = utc_now()
    demo_dir = run_demo_dir()
    clock_state = read_clock_state(clock_path)
    clock_decision = resolve_profile(
        args.profile,
        clock_path=clock_path,
        state=clock_state,
        now=dt.datetime.now(dt.UTC),
    )
    sys.stderr.write(
        f"{palette.paint('PROFILE', palette.cyan)} // requested={clock_decision.requested_profile} "
        f"effective={clock_decision.effective_profile} // {clock_decision.reason}\n"
    )
    sys.stderr.flush()
    steps = build_steps(
        clock_decision.effective_profile,
        include_local_install=args.include_local_install,
        demo_dir=demo_dir,
    )
    skipped = skipped_lanes(args.include_local_install)
    preflight_skipped_count = 0
    results: list[StepResult] = []
    try:
        for step in steps:
            missing_modules = missing_python_modules(step)
            if missing_modules:
                module_text = ", ".join(missing_modules)
                reason = (
                    "missing optional Python module(s): "
                    f"{module_text}; install this lane's requirements to run it"
                )
                skip_step(step, palette, reason)
                skipped.append(
                    SkippedLane(
                        step.label,
                        reason,
                        command_text(step.command),
                    )
                )
                preflight_skipped_count += 1
                continue
            result = run_step(step, root, palette)
            results.append(result)
            if result.returncode != 0 and not args.keep_going:
                break
    finally:
        ended_utc = utc_now()
        write_report(
            report_path,
            root=root,
            profile=clock_decision.effective_profile,
            requested_profile=clock_decision.requested_profile,
            clock_decision=clock_decision,
            demo_dir=demo_dir,
            started_utc=started_utc,
            ended_utc=ended_utc,
            results=results,
            skipped=skipped,
        )
        write_self_seal(
            seal_path,
            root=root,
            profile=clock_decision.effective_profile,
            requested_profile=clock_decision.requested_profile,
            clock_decision=clock_decision,
            demo_dir=demo_dir,
            results=results,
            skipped=skipped,
            include_local_install=args.include_local_install,
            preflight_skipped_count=preflight_skipped_count,
        )
        complete = (
            bool(results)
            and all(result.returncode == 0 for result in results)
            and len(results) + preflight_skipped_count == len(steps)
        )
        update_clock_state(
            clock_decision,
            ended_utc=ended_utc,
            launch_complete=complete,
        )
        sys.stderr.write(
            f"\n{palette.paint('REPORT SEALED', palette.green)} // {report_path}\n"
        )
        sys.stderr.write(
            f"{palette.paint('SELF SEAL WRITTEN', palette.green)} // {seal_path}\n"
        )
        sys.stderr.write(
            f"{palette.paint('CLOCK UPDATED', palette.green)} // {clock_path}\n"
        )
        sys.stderr.flush()

    if complete:
        sys.stderr.write(palette.paint("WUCI-JI NOXFRAME LAUNCH COMPLETE\n", palette.green))
        return 0
    sys.stderr.write(palette.paint("WUCI-JI NOXFRAME LAUNCH FAILED\n", palette.red))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
