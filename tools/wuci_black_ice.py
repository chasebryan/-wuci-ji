#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import select
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ConsoleCommandSpec:
    name: str
    aliases: tuple[str, ...]
    category: str
    usage: str
    description: str
    capability: str
    guard: str


@dataclass
class ConsoleSession:
    cwd: str = "/"
    started_monotonic: float = field(default_factory=time.monotonic)
    history: list[str] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)
    env: dict[str, str] = field(
        default_factory=lambda: {
            "USER": "operator",
            "HOME": "/wuci",
            "SHELL": "noxframe",
            "TERM": "xterm-256color",
        }
    )


TOOL_NAME = "WUCI-NOXFRAME"
LEGACY_TOOL_NAME = "WUCI-BLACK-ICE"
REPORT_SCHEMA = "wuci-noxframe-launch-report-v1"
SEAL_SCHEMA = "wuci-noxframe-seal-v1"
SUBSTRATE_SPEC_SCHEMA = "wuci-noxframe-substrate-contract-v1"
SUBSTRATE_STATE_SCHEMA = "wuci-noxframe-state-v1"
SUBSTRATE_SEAL_SCHEMA = "wuci-noxframe-substrate-seal-v1"
DEFAULT_REPORT = "docs/noxframe/WUCI_NOXFRAME_LAUNCH_REPORT.md"
DEFAULT_SEAL = "docs/noxframe/WUCI_NOXFRAME_SELF_SEAL.json"
DEFAULT_CLOCK = "build/noxframe/WUCI_NOXFRAME_CLOCK.json"
DEFAULT_STATE = "build/noxframe/WUCI_NOXFRAME_STATE.json"
DEFAULT_SUBSTRATE_SEAL = "build/noxframe/WUCI_NOXFRAME_SUBSTRATE_SEAL.json"
DEFAULT_DEMO_ROOT = "build/wuci-noxframe-runs"
DEFAULT_CODEX_BIN = "codex"
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
ANCHOR_ROLES = {
    "docs/SECURITY_BOUNDARY.md": "claim boundary",
    "docs/wuci_gate_boundary.json": "Gate boundary",
    "docs/wuci_cage_policy.json": "CAGE policy",
    "docs/wuci_qcage_policy.json": "QCAGE policy",
    "docs/wuci_high_attestation_profile.json": "high attestation profile",
    "daylight-equation/SCORECARD.v1.json": "Daylight score boundary",
    "daylight-equation/specs/daylight-minimal-core-v0.4.md": "Daylight core spec",
    "daylight-equation/rust/daylight-crypto/src/wuci_daylight.rs": "Daylight bridge source",
}
SUBSTRATE_CELLS = (
    ("root", "NOXFRAME root context", ("status", "seal", "verify", "launch")),
    ("wuci-ji", "assembly artifact and proof-lane context", ("status", "seal")),
    ("daylight", "Daylight evidence and score-boundary context", ("status", "seal")),
    ("gate", "Gate contract and release-boundary context", ("status", "seal")),
    ("witness", "public witness evidence context", ("status", "seal")),
    ("ledger", "local public-history evidence context", ("status", "seal")),
    ("cage", "public-evidence airlock context", ("status", "seal")),
    ("qcage", "quantum-claim discipline context", ("status", "seal")),
    ("install", "signed local install proof context", ("status", "seal")),
    ("codex", "opt-in Codex host bridge context", ("status", "handoff", "start", "exec", "resume")),
)
NON_CLAIMS = (
    "not a kernel",
    "not OS runtime containment",
    "not hostile-code sandboxing",
    "not production authority",
    "not independent audit status",
    "not whole-system post-quantum safety",
)
CONSOLE_CATEGORIES = (
    "substrate",
    "fs",
    "text",
    "proc",
    "sys",
    "user",
    "net",
    "host",
    "dev",
    "misc",
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
DEFAULT_TERMINAL_COLUMNS = 96
MIN_BANNER_INNER_WIDTH = 38
MAX_BANNER_INNER_WIDTH = 112


def console_cmd(
    name: str,
    aliases: tuple[str, ...],
    category: str,
    usage: str,
    description: str,
    capability: str,
    guard: str,
) -> ConsoleCommandSpec:
    return ConsoleCommandSpec(name, aliases, category, usage, description, capability, guard)


CONSOLE_COMMANDS = (
    console_cmd("status", (), "substrate", "status", "Show substrate state and seal status.", "substrate.read", "local"),
    console_cmd("seal", (), "substrate", "seal", "Refresh the NOXFRAME substrate seal.", "substrate.write", "local"),
    console_cmd("verify", (), "substrate", "verify", "Verify current substrate state and seal.", "substrate.read", "local"),
    console_cmd("contract", (), "substrate", "contract", "Print the canonical substrate contract.", "substrate.read", "local"),
    console_cmd("launch", (), "substrate", "launch [auto|smoke|full]", "Run the Wuci-Ji launch matrix.", "proof.run", "explicit"),
    console_cmd("pwd", (), "fs", "pwd", "Print the current virtual substrate path.", "fs.read", "metadata-only"),
    console_cmd("ls", (), "fs", "ls [path]", "List virtual substrate files and directories.", "fs.read", "metadata-only"),
    console_cmd("cd", (), "fs", "cd [dir]", "Change virtual substrate directory.", "fs.read", "metadata-only"),
    console_cmd("cat", (), "fs", "cat <file>", "Read a virtual substrate file.", "fs.read", "metadata-only"),
    console_cmd("tree", (), "fs", "tree [path]", "Show a virtual substrate tree.", "fs.read", "metadata-only"),
    console_cmd("echo", (), "fs", "echo <text>", "Print text in the console.", "none", "local"),
    console_cmd("mkdir", (), "fs", "mkdir <dir>", "VFS mutation route retained as a blocked Phase1-compatible command.", "fs.write", "unavailable"),
    console_cmd("touch", (), "fs", "touch <file>", "VFS mutation route retained as a blocked Phase1-compatible command.", "fs.write", "unavailable"),
    console_cmd("rm", (), "fs", "rm <path>", "VFS mutation route retained as a blocked Phase1-compatible command.", "fs.write", "unavailable"),
    console_cmd("cp", (), "fs", "cp <src> <dst>", "VFS mutation route retained as a blocked Phase1-compatible command.", "fs.write", "unavailable"),
    console_cmd("mv", (), "fs", "mv <src> <dst>", "VFS mutation route retained as a blocked Phase1-compatible command.", "fs.write", "unavailable"),
    console_cmd("grep", (), "text", "grep <pattern> <file>...", "Search virtual file text.", "fs.read", "metadata-only"),
    console_cmd("wc", (), "text", "wc <file>...", "Count lines, words, and bytes in virtual files.", "fs.read", "metadata-only"),
    console_cmd("head", (), "text", "head [-n count] <file>", "Show first lines from a virtual file.", "fs.read", "metadata-only"),
    console_cmd("tail", (), "text", "tail [-n count] <file>", "Show last lines from a virtual file.", "fs.read", "metadata-only"),
    console_cmd("find", (), "text", "find [path] [-name text]", "Search virtual substrate paths.", "fs.read", "metadata-only"),
    console_cmd("pipeline", ("pipes",), "text", "pipeline", "Show supported text-command composition.", "none", "metadata-only"),
    console_cmd("ps", (), "proc", "ps", "Show simulated substrate processes.", "proc.read", "metadata-only"),
    console_cmd("top", (), "proc", "top", "Show a compact simulated process summary.", "proc.read", "metadata-only"),
    console_cmd("jobs", (), "proc", "jobs", "List console-local background jobs.", "proc.read", "metadata-only"),
    console_cmd("spawn", (), "proc", "spawn <name>", "Process mutation route retained as a blocked Phase1-compatible command.", "proc.spawn", "unavailable"),
    console_cmd("fg", (), "proc", "fg <pid>", "Process mutation route retained as a blocked Phase1-compatible command.", "proc.manage", "unavailable"),
    console_cmd("bg", (), "proc", "bg <pid>", "Process mutation route retained as a blocked Phase1-compatible command.", "proc.manage", "unavailable"),
    console_cmd("kill", (), "proc", "kill <pid>", "Process mutation route retained as a blocked Phase1-compatible command.", "proc.kill", "unavailable"),
    console_cmd("nice", (), "proc", "nice <pid> <priority>", "Process mutation route retained as a blocked Phase1-compatible command.", "proc.manage", "unavailable"),
    console_cmd("sysinfo", ("fetch", "neofetch"), "sys", "sysinfo", "Show a one-screen NOXFRAME system summary.", "sys.read", "metadata-only"),
    console_cmd("dash", ("dashboard",), "sys", "dash", "Show a compact operator dashboard.", "sys.read", "metadata-only"),
    console_cmd("free", ("mem",), "sys", "free", "Show virtual memory model.", "sys.read", "metadata-only"),
    console_cmd("df", (), "sys", "df", "Show virtual substrate storage model.", "sys.read", "metadata-only"),
    console_cmd("dmesg", (), "sys", "dmesg", "Show boot and substrate messages.", "sys.log", "metadata-only"),
    console_cmd("vmstat", (), "sys", "vmstat", "Show compact virtual system stats.", "sys.read", "metadata-only"),
    console_cmd("uname", (), "sys", "uname", "Show NOXFRAME kernel-profile identity.", "sys.read", "metadata-only"),
    console_cmd("date", (), "sys", "date", "Show current UTC time.", "sys.read", "local"),
    console_cmd("uptime", (), "sys", "uptime", "Show console session uptime.", "sys.read", "local"),
    console_cmd("hostname", (), "sys", "hostname", "Show virtual substrate hostname.", "sys.read", "metadata-only"),
    console_cmd("audit", (), "sys", "audit", "Show console audit events.", "sys.audit", "local"),
    console_cmd("opslog", (), "sys", "opslog [status|tail]", "Show local operator log status or tail.", "sys.audit", "local"),
    console_cmd("env", (), "user", "env", "Print console-local environment.", "user.read", "local"),
    console_cmd("export", (), "user", "export KEY=value", "Set a console-local environment value.", "user.env", "local"),
    console_cmd("unset", (), "user", "unset KEY", "Remove a console-local environment value.", "user.env", "local"),
    console_cmd("whoami", (), "user", "whoami", "Show the simulated operator identity.", "user.read", "metadata-only"),
    console_cmd("id", (), "user", "id", "Show simulated operator uid/gid.", "user.read", "metadata-only"),
    console_cmd("accounts", ("users",), "user", "accounts", "Show privacy-safe account model.", "user.read", "metadata-only"),
    console_cmd("history", (), "user", "history", "Show console command history.", "user.read", "local"),
    console_cmd("security", ("sec", "policy"), "user", "security", "Show NOXFRAME command-surface posture.", "user.read", "metadata-only"),
    console_cmd("theme", ("style",), "user", "theme [show|list]", "Inspect available console palettes.", "user.env", "metadata-only"),
    console_cmd("banner", ("splash",), "user", "banner", "Describe the active responsive boot banner.", "user.read", "metadata-only"),
    console_cmd("tips", ("hint", "hints"), "user", "tips", "Show concise operator tips.", "user.read", "metadata-only"),
    console_cmd("ifconfig", (), "net", "ifconfig", "Phase1-compatible network route retained as non-executing metadata.", "net.read", "unavailable"),
    console_cmd("iwconfig", (), "net", "iwconfig", "Phase1-compatible network route retained as non-executing metadata.", "net.read", "unavailable"),
    console_cmd("wifi-scan", (), "net", "wifi-scan", "Phase1-compatible network route retained as non-executing metadata.", "net.read", "unavailable"),
    console_cmd("wifi-connect", (), "net", "wifi-connect <ssid>", "Phase1-compatible network route retained as non-executing metadata.", "net.admin", "unavailable"),
    console_cmd("ping", (), "net", "ping <host>", "Phase1-compatible network route retained as non-executing metadata.", "net.read", "unavailable"),
    console_cmd("nmcli", (), "net", "nmcli", "Phase1-compatible network route retained as non-executing metadata.", "net.read", "unavailable"),
    console_cmd("browser", (), "host", "browser <url|about>", "Phase1 browser route retained without network fetching.", "host.net", "unavailable"),
    console_cmd("git", (), "host", "git <args...>", "Host passthrough route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("gh", ("github",), "host", "gh <args...>", "Host passthrough route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("cargo", (), "host", "cargo <args...>", "Host passthrough route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("rustc", (), "host", "rustc <args...>", "Host passthrough route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("python3", (), "host", "python3 <args...>", "Host passthrough route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("go", ("golang",), "host", "go <args...>", "Host passthrough route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("python", ("py",), "host", "python <file.py>", "Host language route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("gcc", ("cc",), "host", "gcc <file.c>", "Host compiler route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("plugins", ("plugin",), "host", "plugins", "Plugin route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("wasm", ("wasi",), "host", "wasm [list|inspect|run]", "WASI route retained as unavailable inside NOXFRAME console.", "wasm.exec", "unavailable"),
    console_cmd("update", ("upgrade",), "host", "update [plan|protocol]", "Update route retained as read-only guidance.", "host.exec", "metadata-only"),
    console_cmd("codex", ("agent",), "dev", "codex [status|handoff|version|doctor|start|exec|resume]", "Use the opt-in Codex bridge pinned to this Wuci-Ji checkout.", "host.exec", "explicit-opt-in"),
    console_cmd("avim", ("vim", "edit"), "dev", "avim <file>", "Editor route retained as unavailable inside NOXFRAME console.", "fs.write", "unavailable"),
    console_cmd("dev", ("dock", "selfdev"), "dev", "dev [status]", "Self-development route retained as unavailable inside NOXFRAME console.", "host.exec", "unavailable"),
    console_cmd("repo", ("channels", "branches", "doctrine"), "dev", "repo [status]", "Show repository channel metadata.", "none", "metadata-only"),
    console_cmd("fyr", ("phase1lang", "forge"), "dev", "fyr [status]", "Show Fyr lineage metadata.", "none", "metadata-only"),
    console_cmd("lang", ("language", "runlang"), "dev", "lang [support|security]", "Language runtime route retained as non-executing metadata.", "host.exec", "metadata-only"),
    console_cmd("lspci", (), "sys", "lspci", "Show virtual hardware anchors.", "hw.read", "metadata-only"),
    console_cmd("pcie", (), "sys", "pcie", "Show virtual PCIe model.", "hw.read", "metadata-only"),
    console_cmd("cr3", (), "sys", "cr3", "Show virtual CR3 value.", "hw.read", "metadata-only"),
    console_cmd("loadcr3", (), "sys", "loadcr3 <value>", "Hardware mutation route retained as unavailable.", "hw.write", "unavailable"),
    console_cmd("cr4", (), "sys", "cr4", "Show virtual CR4 flags.", "hw.read", "metadata-only"),
    console_cmd("pcide", (), "sys", "pcide on|off", "Hardware mutation route retained as unavailable.", "hw.write", "unavailable"),
    console_cmd("help", ("commands",), "misc", "help [--compact|category|command]", "Show registry-backed command help.", "none", "open"),
    console_cmd("man", (), "misc", "man <command>", "Show command manual card.", "none", "open"),
    console_cmd("complete", (), "misc", "complete [prefix]", "Show registry-backed completions.", "none", "open"),
    console_cmd("capabilities", ("caps",), "misc", "capabilities", "Show command capabilities and guards.", "none", "open"),
    console_cmd("matrix", ("rain",), "misc", "matrix", "Matrix-style animation route retained as static banner guidance.", "none", "metadata-only"),
    console_cmd("bootcfg", ("bootconfig",), "misc", "bootcfg [show|path]", "Show boot profile metadata.", "none", "metadata-only"),
    console_cmd("clear", (), "misc", "clear", "Clear and redraw the console.", "none", "open"),
    console_cmd("version", ("ver",), "misc", "version", "Show NOXFRAME version metadata.", "none", "open"),
    console_cmd("roadmap", ("map",), "misc", "roadmap", "Show NOXFRAME continuation path.", "none", "metadata-only"),
    console_cmd("sandbox", ("nsinfo",), "misc", "sandbox", "Show command-boundary summary.", "none", "metadata-only"),
    console_cmd("nest", ("nests",), "misc", "nest [status]", "Show nested-context metadata.", "none", "metadata-only"),
    console_cmd("exit", ("quit", "shutdown", "poweroff"), "misc", "exit", "Leave NOXFRAME console.", "none", "open"),
)


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
    def blue(self) -> str:
        return "34"

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


def display_width(text: str) -> int:
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return width


def terminal_columns(default: int = DEFAULT_TERMINAL_COLUMNS) -> int:
    return max(40, shutil.get_terminal_size(fallback=(default, 24)).columns)


def terminal_lines(default: int = 32) -> int:
    return max(12, shutil.get_terminal_size(fallback=(DEFAULT_TERMINAL_COLUMNS, default)).lines)


def fit_display(text: str, width: int) -> str:
    if display_width(text) <= width:
        return text
    if width <= 3:
        return "." * max(width, 0)
    kept: list[str] = []
    used = 0
    target = width - 3
    for char in text:
        char_width = 0 if unicodedata.combining(char) else (
            2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
        )
        if used + char_width > target:
            break
        kept.append(char)
        used += char_width
    return "".join(kept) + "..."


def console_lookup(name: str) -> ConsoleCommandSpec | None:
    lowered = name.lower()
    return next(
        (
            spec
            for spec in CONSOLE_COMMANDS
            if spec.name == lowered or lowered in spec.aliases
        ),
        None,
    )


def console_canonical_name(name: str) -> str | None:
    spec = console_lookup(name)
    return spec.name if spec else None


def console_command_names(category: str) -> str:
    return " ".join(spec.name for spec in CONSOLE_COMMANDS if spec.category == category)


def console_help_text(args: list[str]) -> str:
    topic = args[0].lower() if args else ""
    if topic in {"--compact", "-c", "compact"}:
        rows = ["noxframe help // compact", ""]
        for category in CONSOLE_CATEGORIES:
            rows.append(f"{category:<9}: {console_command_names(category)}")
        rows.append("")
        rows.append("try: help substrate | help fs | help sys | man status | complete se")
        return "\n".join(rows)
    if topic in CONSOLE_CATEGORIES:
        rows = [f"noxframe help // {topic}", "", "command        usage                         summary"]
        for spec in CONSOLE_COMMANDS:
            if spec.category == topic:
                rows.append(f"{spec.name:<14} {spec.usage:<29} {spec.description}")
        return "\n".join(rows)
    if topic:
        manual = console_man_text(topic)
        if manual is not None:
            return f"noxframe help // {topic}\n\n{manual}"
        return f"noxframe help // no match\n\nunknown topic: {topic}\ntry: help --compact"

    rows = [
        "noxframe help // operator console",
        "",
        "substrate : status seal verify contract launch",
        "fs        : pwd ls cd cat tree echo mkdir touch rm cp mv",
        "text      : grep wc head tail find pipeline",
        "proc      : ps top jobs spawn fg bg kill nice",
        "sys       : sysinfo dash free df dmesg vmstat uname date uptime hostname audit opslog",
        "user      : env export unset whoami id accounts history security theme banner tips",
        "dev       : codex repo fyr lang avim dev",
        "misc      : help man complete capabilities clear version roadmap sandbox nest exit",
        "",
        "Phase1-compatible host, network, dev, and hardware routes are discoverable through help",
        "and capabilities. Host passthrough and network execution are not enabled by default.",
        "Codex is the explicit opt-in bridge: use codex status, codex handoff, and --allow-codex.",
        "",
        "routes",
        "  help --compact       compact command map",
        "  help <category>      category deck",
        "  man <command>        command card",
        "  complete <prefix>    registry completions",
        "  capabilities         guard map",
    ]
    return "\n".join(rows)


def console_man_text(name: str) -> str | None:
    spec = console_lookup(name)
    if spec is None:
        return None
    aliases = ", ".join(spec.aliases) if spec.aliases else "none"
    return "\n".join(
        [
            spec.name,
            "",
            f"usage      : {spec.usage}",
            f"category   : {spec.category}",
            f"aliases    : {aliases}",
            f"capability : {spec.capability}",
            f"guard      : {spec.guard}",
            "",
            spec.description,
        ]
    )


def console_completions(prefix: str) -> list[str]:
    lowered = prefix.lower()
    matches: list[str] = []
    for spec in CONSOLE_COMMANDS:
        if spec.name.startswith(lowered):
            matches.append(spec.name)
        for alias in spec.aliases:
            if alias.startswith(lowered):
                matches.append(alias)
    return sorted(set(matches))


def console_capabilities_text() -> str:
    rows = ["noxframe capabilities", "", "command        category   capability       guard"]
    for spec in CONSOLE_COMMANDS:
        rows.append(f"{spec.name:<14} {spec.category:<10} {spec.capability:<16} {spec.guard}")
    return "\n".join(rows)


def codex_executable_status(args: argparse.Namespace) -> str:
    codex_bin = getattr(args, "codex_bin", DEFAULT_CODEX_BIN)
    if os.sep in codex_bin or (os.altsep is not None and os.altsep in codex_bin):
        path = Path(codex_bin)
        return str(path) if path.exists() else "not found"
    return shutil.which(codex_bin) or "not found on PATH"


def codex_common_options(root: Path) -> list[str]:
    return [
        "--cd",
        str(root),
        "--sandbox",
        "workspace-write",
        "--ask-for-approval",
        "on-request",
        "--no-alt-screen",
    ]


def codex_handoff_prompt(user_prompt: str) -> str:
    prefix = (
        "NOXFRAME Codex handoff for WUCI-JI. Work in this repository. "
        "Follow AGENTS.md and docs/SECURITY_BOUNDARY.md. Keep CAGE, QCAGE, "
        "HARDEN, and INSTALL claims conservative. Do not add offensive tooling, "
        "runtime sandbox claims, or quantum-safety claims unless enforcement and "
        "evidence exist."
    )
    if not user_prompt:
        return prefix
    return f"{prefix}\n\nOperator request: {user_prompt}"


def codex_bridge_usage() -> str:
    return "\n".join(
        [
            "usage: codex [status|handoff|version|doctor|start|exec|resume]",
            "  codex status           show bridge posture and executable discovery",
            "  codex handoff          print the WUCI-JI handoff guardrails",
            "  codex version          run: codex --version",
            "  codex doctor           run: codex doctor --summary --ascii",
            "  codex start [prompt]   start interactive Codex in this checkout",
            "  codex exec <prompt>    run non-interactive Codex in this checkout",
            "  codex resume [args]    resume Codex in this checkout; defaults to --last",
        ]
    )


def codex_bridge_status_text(root: Path, args: argparse.Namespace) -> str:
    enabled = bool(getattr(args, "allow_codex", False))
    lines = [
        "codex bridge: " + ("enabled" if enabled else "disabled"),
        f"schema: wuci-noxframe-codex-bridge-v1",
        f"workspace: {root}",
        f"codex-bin: {getattr(args, 'codex_bin', DEFAULT_CODEX_BIN)}",
        f"discovered: {codex_executable_status(args)}",
        "default guard: metadata-only unless --allow-codex was passed",
        "launch guard: --cd <repo>, --sandbox workspace-write, --ask-for-approval on-request",
        "boundary: Codex uses host/API configuration when launched; NOXFRAME makes no no-network or runtime-containment claim for that bridge",
        "shell: disabled; NOXFRAME invokes Codex with shell=False",
        "",
        codex_bridge_usage(),
        "",
    ]
    return "\n".join(lines)


def codex_handoff_text(root: Path) -> str:
    prompt = codex_handoff_prompt("")
    return "\n".join(
        [
            "codex handoff // WUCI-JI within NOXFRAME",
            "",
            f"workspace: {root}",
            "operator command examples:",
            "  tools/wuci-noxframe --console --allow-codex",
            "  codex start",
            "  codex exec tighten the NOXFRAME docs without expanding security claims",
            "  codex resume --last",
            "",
            "handoff prompt:",
            prompt,
            "",
            "NOXFRAME bridge rules:",
            "  - no shell=True, eval, or remote-code shell pipeline is used by the launcher",
            "  - Codex is pinned to this checkout with --cd",
            "  - Codex uses workspace-write sandboxing and on-request approvals",
            "  - host/API network behavior belongs to Codex, not to a NOXFRAME sandbox claim",
            "",
        ]
    )


def codex_bridge_command(
    root: Path,
    args: argparse.Namespace,
    action: str,
    rest: list[str],
) -> list[str]:
    codex_bin = getattr(args, "codex_bin", DEFAULT_CODEX_BIN)
    if action == "version":
        return [codex_bin, "--version"]
    if action == "doctor":
        return [codex_bin, "doctor", "--summary", "--ascii"]
    if action == "start":
        command = [codex_bin, *codex_common_options(root)]
        if rest:
            command.append(codex_handoff_prompt(" ".join(rest)))
        return command
    if action == "exec":
        if not rest:
            raise NoxframeError("codex exec requires a prompt")
        return [
            codex_bin,
            *codex_common_options(root),
            "exec",
            codex_handoff_prompt(" ".join(rest)),
        ]
    if action == "resume":
        return [codex_bin, *codex_common_options(root), "resume", *(rest or ["--last"])]
    raise NoxframeError(f"unsupported codex bridge action: {action}")


def handle_codex_command(root: Path, args: argparse.Namespace, parts: list[str]) -> None:
    action = parts[1].lower() if len(parts) > 1 else "status"
    rest = parts[2:]
    if action == "status":
        print(codex_bridge_status_text(root, args), end="")
        return
    if action == "handoff":
        print(codex_handoff_text(root), end="")
        return
    if action not in {"version", "doctor", "start", "exec", "resume"}:
        print(codex_bridge_usage())
        return
    if not getattr(args, "allow_codex", False):
        print("codex: bridge disabled")
        print("restart NOXFRAME with --allow-codex to launch a host Codex process")
        print("use: codex status | codex handoff")
        return
    try:
        command = codex_bridge_command(root, args, action, rest)
    except NoxframeError as exc:
        print(str(exc))
        return
    print("codex: launching explicit host bridge")
    print(f"cwd: {root}")
    print("boundary: Codex uses host/API configuration; NOXFRAME is not runtime containment")
    print(f"argv: {shlex.join(command)}")
    sys.stdout.flush()
    try:
        result = subprocess.run(command, cwd=root, check=False)
    except FileNotFoundError:
        print(f"codex: executable not found: {getattr(args, 'codex_bin', DEFAULT_CODEX_BIN)}")
        return
    print(f"codex-result: {result.returncode}")


def record_console_event(session: ConsoleSession, line: str) -> None:
    event = f"{utc_now()} command={line}"
    session.audit.append(event)
    if len(session.audit) > 128:
        del session.audit[:-128]


def vfs_normalize(cwd: str, target: str | None) -> str:
    value = target or cwd
    if value.startswith("/"):
        path = value
    else:
        path = f"{cwd.rstrip('/')}/{value}" if cwd != "/" else f"/{value}"
    normalized = os.path.normpath(path)
    if normalized in {".", ""}:
        return "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def vfs_static_dirs() -> dict[str, tuple[str, ...]]:
    cell_dirs = {f"/{cell_id}": ("status", "role") for cell_id, _, _ in SUBSTRATE_CELLS}
    dirs: dict[str, tuple[str, ...]] = {
        "/": (
            "README",
            "root/",
            "wuci-ji/",
            "daylight/",
            "gate/",
            "witness/",
            "ledger/",
            "cage/",
            "qcage/",
            "install/",
            "codex/",
            "dev/",
            "proc/",
            "var/",
            "docs/",
        ),
        "/dev": ("codex",),
        "/proc": ("version", "route", "cells", "processes"),
        "/var": ("log/",),
        "/var/log": ("audit",),
        "/docs": ("contract.json", "status.json", "state.json", "seal.json", "launch-report.md"),
    }
    dirs.update(cell_dirs)
    return dirs


def vfs_is_dir(path: str) -> bool:
    return path in vfs_static_dirs()


def vfs_all_paths() -> list[str]:
    paths: set[str] = set(vfs_static_dirs())
    for base, entries in vfs_static_dirs().items():
        for entry in entries:
            clean = entry.rstrip("/")
            child = f"{base.rstrip('/')}/{clean}" if base != "/" else f"/{clean}"
            paths.add(child)
    return sorted(paths)


def vfs_list(path: str) -> tuple[bool, list[str]]:
    dirs = vfs_static_dirs()
    if path in dirs:
        return True, sorted(dirs[path])
    if path in vfs_all_paths():
        return False, [path.rsplit("/", 1)[-1]]
    raise NoxframeError(f"no such virtual path: {path}")


def cell_for_path(path: str) -> tuple[str, str, tuple[str, ...]] | None:
    parts = path.strip("/").split("/")
    if len(parts) != 2 or parts[1] not in {"status", "role"}:
        return None
    for cell_id, role, actions in SUBSTRATE_CELLS:
        if parts[0] == cell_id:
            return cell_id, role, actions
    return None


def virtual_status_payload(root: Path, args: argparse.Namespace) -> dict[str, object]:
    state_path, seal_path = substrate_paths(root, args)
    if not state_path.exists() or not seal_path.exists():
        return {
            "schema": "wuci-noxframe-status-v1",
            "status": "uninitialized",
            "state": str(state_path),
            "seal": str(seal_path),
        }
    ok, problems = verify_substrate_seal(root, state_path=state_path, seal_path=seal_path)
    state = safe_read_json_file(state_path, "NOXFRAME state")
    return {
        "schema": "wuci-noxframe-status-v1",
        "status": "sealed" if ok else "drifted",
        "state": str(state_path),
        "seal": str(seal_path),
        "active_context": state.get("active_context"),
        "route": state.get("route"),
        "cell_count": len(state.get("cells", [])) if isinstance(state.get("cells"), list) else 0,
        "problems": problems,
    }


def virtual_file_text(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
    path: str,
) -> str:
    state_path, seal_path = substrate_paths(root, args)
    cell = cell_for_path(path)
    if cell is not None:
        cell_id, role, actions = cell
        if path.endswith("/role"):
            return f"{cell_id}: {role}\n"
        return f"{cell_id}: sealed-metadata-ready actions={','.join(actions)}\n"
    if path == "/README":
        return "\n".join(
            [
                "WUCI-NOXFRAME virtual substrate",
                "root route: /proc /docs /dev /var/log and Wuci-Ji proof cells",
                "try: help --compact, sysinfo, ls /proc, cat /proc/cells, cat /dev/codex",
                "",
            ]
        )
    if path == "/proc/version":
        return f"{TOOL_NAME} substrate console\nschema={SUBSTRATE_STATE_SCHEMA}\n"
    if path == "/proc/route":
        return "root > wuci-ji > daylight\n"
    if path == "/proc/cells":
        return "".join(
            f"{cell_id:<10} {role} actions={','.join(actions)}\n"
            for cell_id, role, actions in SUBSTRATE_CELLS
        )
    if path == "/proc/processes":
        return console_process_table()
    if path == "/dev/codex":
        return codex_bridge_status_text(root, args)
    if path == "/var/log/audit":
        return "\n".join(session.audit[-40:]) + ("\n" if session.audit else "audit log empty\n")
    if path == "/docs/contract.json":
        return json.dumps(substrate_contract(), indent=2, sort_keys=True) + "\n"
    if path == "/docs/status.json":
        return json.dumps(virtual_status_payload(root, args), indent=2, sort_keys=True) + "\n"
    if path == "/docs/state.json":
        if not state_path.exists():
            return "state not initialized\n"
        return json.dumps(safe_read_json_file(state_path, "NOXFRAME state"), indent=2, sort_keys=True) + "\n"
    if path == "/docs/seal.json":
        if not seal_path.exists():
            return "substrate seal not initialized\n"
        return json.dumps(safe_read_json_file(seal_path, "NOXFRAME substrate seal"), indent=2, sort_keys=True) + "\n"
    if path == "/docs/launch-report.md":
        report_path = repo_path(root, args.report)
        if not report_path.exists():
            return "launch report not written\n"
        return report_path.read_text(encoding="utf-8")
    raise NoxframeError(f"not a virtual file: {path}")


def console_process_table() -> str:
    return "\n".join(
        [
            "PID  STATE   NAME",
            "1    ready   noxframe-console",
            "2    ready   substrate-seal",
            "3    idle    daylight-anchor",
            "4    idle    codex-bridge",
            "",
        ]
    )


def print_vfs_tree(start: str) -> None:
    dirs = vfs_static_dirs()
    if start not in dirs:
        print(start)
        return
    print(start)
    for path in vfs_all_paths():
        if path == start or not path.startswith(start.rstrip("/") + "/"):
            continue
        rel = path[len(start.rstrip("/")) + 1 :] if start != "/" else path[1:]
        depth = rel.count("/")
        if depth > 2:
            continue
        marker = "/" if path in dirs else ""
        print(f"{'  ' * depth}{rel.rsplit('/', 1)[-1]}{marker}")


def console_text_files(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
    files: list[str],
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for value in files:
        path = vfs_normalize(session.cwd, value)
        out.append((path, virtual_file_text(root, args, session, path)))
    return out


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


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def digest_vector_json(value: object) -> dict[str, str]:
    return digest_vector(canonical_json_bytes(value))


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
        "role": ANCHOR_ROLES.get(relative_path, "public anchor"),
        "bytes": len(data),
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "digest_vector": digest_vector(data),
    }


def safe_read_json_file(path: Path, label: str) -> dict[str, object]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise NoxframeError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise NoxframeError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise NoxframeError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise NoxframeError(f"{label} must not be hardlinked: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise NoxframeError(f"could not open {label}: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise NoxframeError(f"{label} changed type while opening: {path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise NoxframeError(f"{label} changed while opening: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NoxframeError(f"{label} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise NoxframeError(f"{label} must be a JSON object: {path}")
    return dict(value)


def substrate_contract() -> dict[str, object]:
    return {
        "schema": SUBSTRATE_SPEC_SCHEMA,
        "name": TOOL_NAME,
        "working_title_alias": LEGACY_TOOL_NAME,
        "purpose": (
            "minimal metadata system that binds Wuci-Ji and Daylight public "
            "evidence into a local operator-owned state and seal"
        ),
        "phase1_continuation": {
            "source_repository": "https://github.com/Bryforge/phase1",
            "ideas_carried_forward": [
                "operator console",
                "virtual system model",
                "command metadata",
                "guarded host access",
                "local status and audit surfaces",
                "metadata-only nesting",
                "conservative OS-track claims",
            ],
            "ideas_not_imported": [
                "Phase1 code",
                "host shell passthrough",
                "network command surface",
                "simulated kernel claims as enforcement",
            ],
        },
        "project_lineage": [
            "Wuci-Ji proof lanes",
            "Daylight evidence boundary",
            "Latticra-style receipt portability discipline",
            "Fyr-style small language and command-surface lessons",
        ],
        "cells": [
            {
                "id": cell_id,
                "role": role,
                "allowed_actions": list(actions),
                "host_effect": "metadata-only",
            }
            for cell_id, role, actions in SUBSTRATE_CELLS
        ],
        "anchor_paths": list(ANCHOR_PATHS),
        "rules": {
            "stdlib_only": True,
            "network": "unused",
            "shell": "disabled",
            "writes": "state and seal files only unless launch profile is explicitly run",
            "host_access": "public repository files through symlink and hardlink rejecting reads",
        },
        "non_claims": list(NON_CLAIMS),
    }


def build_substrate_state(root: Path, *, now_utc: str) -> dict[str, object]:
    return {
        "schema": SUBSTRATE_STATE_SCHEMA,
        "name": TOOL_NAME,
        "created_utc": now_utc,
        "updated_utc": now_utc,
        "active_context": "root",
        "route": ["root", "wuci-ji", "daylight"],
        "status": "initialized",
        "git": {
            "branch": git_value(root, "branch", "--show-current"),
            "commit": git_value(root, "rev-parse", "HEAD"),
        },
        "cells": [
            {
                "id": cell_id,
                "role": role,
                "state": "sealed-metadata-ready",
                "allowed_actions": list(actions),
            }
            for cell_id, role, actions in SUBSTRATE_CELLS
        ],
        "guards": {
            "network": "unused",
            "shell": "disabled",
            "host_mutation": "state-and-seal-files-only",
            "artifact_release": "requires existing Gate proof lanes",
        },
        "non_claims": list(NON_CLAIMS),
    }


def build_substrate_seal(root: Path, state: dict[str, object], *, now_utc: str) -> dict[str, object]:
    contract = substrate_contract()
    anchors = [anchor_record(root, relative_path) for relative_path in ANCHOR_PATHS]
    seal_material = {
        "contract_digest_vector": digest_vector_json(contract),
        "state_digest_vector": digest_vector_json(state),
        "anchors": anchors,
    }
    return {
        "schema": SUBSTRATE_SEAL_SCHEMA,
        "name": TOOL_NAME,
        "sealed_utc": now_utc,
        "status": "sealed",
        "contract": contract,
        "contract_digest_vector": seal_material["contract_digest_vector"],
        "state_schema": state.get("schema"),
        "state_digest_vector": seal_material["state_digest_vector"],
        "anchors": anchors,
        "substrate_digest_vector": digest_vector_json(seal_material),
        "guards": {
            "network": "unused",
            "shell": "disabled",
            "host_effect": "public-read plus local state/seal write",
        },
        "non_claims": list(NON_CLAIMS),
    }


def verify_substrate_seal(
    root: Path,
    *,
    state_path: Path,
    seal_path: Path,
) -> tuple[bool, list[str]]:
    problems: list[str] = []
    try:
        state = safe_read_json_file(state_path, "NOXFRAME state")
        seal = safe_read_json_file(seal_path, "NOXFRAME substrate seal")
    except NoxframeError as exc:
        return False, [str(exc)]

    if seal.get("schema") != SUBSTRATE_SEAL_SCHEMA:
        problems.append("seal schema mismatch")
    if state.get("schema") != SUBSTRATE_STATE_SCHEMA:
        problems.append("state schema mismatch")
    if seal.get("contract_digest_vector") != digest_vector_json(substrate_contract()):
        problems.append("contract digest mismatch")
    if seal.get("state_digest_vector") != digest_vector_json(state):
        problems.append("state digest mismatch")

    current_anchors = [anchor_record(root, relative_path) for relative_path in ANCHOR_PATHS]
    sealed_anchors = seal.get("anchors")
    if sealed_anchors != current_anchors:
        problems.append("anchor digest mismatch")

    expected_material = {
        "contract_digest_vector": digest_vector_json(substrate_contract()),
        "state_digest_vector": digest_vector_json(state),
        "anchors": current_anchors,
    }
    if seal.get("substrate_digest_vector") != digest_vector_json(expected_material):
        problems.append("substrate digest mismatch")
    return not problems, problems


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
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(info.st_mode):
            raise NoxframeError(f"refusing to replace symlink JSON path: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise NoxframeError(f"refusing to replace non-regular JSON path: {path}")
        if info.st_nlink != 1:
            raise NoxframeError(f"refusing to replace hardlinked JSON path: {path}")
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp_name, path)


def repo_path(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return root / path


def substrate_paths(root: Path, args: argparse.Namespace) -> tuple[Path, Path]:
    return (
        repo_path(root, args.substrate_state),
        repo_path(root, args.substrate_seal),
    )


def init_substrate(
    root: Path,
    *,
    state_path: Path,
    seal_path: Path,
    force: bool,
    now_utc: str,
) -> tuple[dict[str, object], dict[str, object], bool]:
    created = False
    if state_path.exists() and not force:
        state = safe_read_json_file(state_path, "NOXFRAME state")
        if state.get("schema") != SUBSTRATE_STATE_SCHEMA:
            raise NoxframeError(f"existing NOXFRAME state schema mismatch: {state_path}")
    else:
        state = build_substrate_state(root, now_utc=now_utc)
        write_json_atomic(state_path, state)
        created = True
    seal = build_substrate_seal(root, state, now_utc=now_utc)
    write_json_atomic(seal_path, seal)
    return state, seal, created


def ensure_substrate(root: Path, *, state_path: Path, seal_path: Path) -> None:
    if state_path.exists() and seal_path.exists():
        return
    init_substrate(
        root,
        state_path=state_path,
        seal_path=seal_path,
        force=False,
        now_utc=utc_now(),
    )


def boot_answer_allows(value: str) -> bool:
    return value.strip().lower() in {"y", "yes"}


def boot_animation_active(args: argparse.Namespace) -> bool:
    if args.yes or args.no_boot_prompt or getattr(args, "no_boot_animation", False):
        return False
    return sys.stdin.isatty() and sys.stderr.isatty()


def prompt_boot_plain(prompt: str, palette: Palette) -> bool:
    sys.stderr.write(palette.paint(prompt, palette.red))
    sys.stderr.flush()
    answer = sys.stdin.readline()
    return boot_answer_allows(answer)


def prompt_boot_animated(prompt: str, palette: Palette) -> bool:
    try:
        fd = sys.stdin.fileno()
        old_attrs = termios.tcgetattr(fd)
    except (OSError, termios.error):
        return prompt_boot_plain(prompt, palette)

    new_attrs = old_attrs[:]
    new_attrs[6] = old_attrs[6][:]
    new_attrs[3] = new_attrs[3] & ~(termios.ICANON | termios.ECHO)
    new_attrs[6][termios.VMIN] = 0
    new_attrs[6][termios.VTIME] = 0
    answer = ""
    frame = 0
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, new_attrs)
    except termios.error:
        return prompt_boot_plain(prompt, palette)
    sys.stderr.write("\033[?25l")
    sys.stderr.flush()
    try:
        while True:
            print_banner(
                palette,
                frame=frame,
                full_screen=True,
                prompt=prompt,
                answer=answer,
            )
            ready, _, _ = select.select([sys.stdin], [], [], 0.14)
            if ready:
                chunk = os.read(fd, 32).decode("utf-8", errors="ignore")
                for char in chunk:
                    if char in {"\r", "\n"}:
                        return boot_answer_allows(answer)
                    if char == "\x03":
                        raise KeyboardInterrupt
                    if char == "\x04":
                        return False
                    if char in {"\x7f", "\b"}:
                        answer = answer[:-1]
                    elif char.isprintable() and len(answer) < 12:
                        answer += char
            frame += 1
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
        sys.stderr.write("\033[?25h")
        sys.stderr.flush()


def confirm_boot(args: argparse.Namespace, palette: Palette) -> bool:
    if args.yes or args.no_boot_prompt:
        return True
    if not args.force_boot_prompt and (not sys.stdin.isatty() or not sys.stderr.isatty()):
        return True
    prompt = "Would you like to boot the Wuci-Ji substrate? [y/N] "
    if boot_animation_active(args):
        return prompt_boot_animated(prompt, palette)
    return prompt_boot_plain(prompt, palette)


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


def banner_inner_width(columns: int | None = None, *, full_width: bool = False) -> int:
    columns = terminal_columns() if columns is None else max(40, columns)
    usable = max(MIN_BANNER_INNER_WIDTH, columns - 2)
    if full_width:
        return usable
    return min(MAX_BANNER_INNER_WIDTH, usable)


def print_banner(
    palette: Palette,
    *,
    frame: int = 0,
    full_screen: bool = False,
    prompt: str | None = None,
    answer: str = "",
) -> None:
    inner_width = banner_inner_width(full_width=full_screen)

    def frame_line(text: str = "", *, align: str = "center", width: int = inner_width) -> str:
        if align == "left":
            preferred_left = min(3, max(1, width))
            text = fit_display(text, max(0, width - preferred_left))
        else:
            preferred_left = 0
            text = fit_display(text, width)
        text_width = display_width(text)
        if align == "left":
            left = min(preferred_left, max(0, width - text_width))
        else:
            left = (width - text_width) // 2
        right = width - text_width - left
        return f"|{' ' * left}{text}{' ' * right}|"

    def space_line(seed: int, *, drift: int = 1, width: int = inner_width) -> str:
        marks = {3: ".", 11: "'", 19: "*", 31: ".", 43: "+", 59: ".", 71: "*", 83: "'"}
        chars = [" "] * width
        for index, mark in marks.items():
            chars[(index + seed + (frame * drift)) % width] = mark
        return "|" + "".join(chars) + "|"

    def orbit_line(text: str, *, width: int = inner_width) -> str:
        text = fit_display(text, max(1, width - 8))
        text_width = display_width(text)
        if width < 58:
            left_marks = " . "
            right_marks = " . "
        else:
            left_marks = " .  *    .     '   "
            right_marks = "   '     .    *  . "
        fixed_width = display_width(left_marks) + display_width(right_marks) + text_width
        if fixed_width > width:
            return frame_line(text, width=width)
        spacer = width - fixed_width
        wobble = (frame % 5) - 2 if full_screen else 0
        left_pad = max(0, min(spacer, (spacer // 2) + wobble))
        right_pad = spacer - left_pad
        return f"|{' ' * left_pad}{left_marks}{text}{right_marks}{' ' * right_pad}|"

    def sky_line(seed: int, width: int = inner_width) -> str:
        marks = (".", "'", "*", "+", ".", "*")
        chars = [" "] * width
        for offset, mark in enumerate(marks):
            pos = (seed + frame * (offset + 1) * 3 + offset * 17) % width
            chars[pos] = mark
        return "|" + "".join(chars) + "|"

    block_logo = [
        "██╗    ██╗ ██╗   ██╗  ██████╗ ██╗              ██╗ ██╗",
        "██║    ██║ ██║   ██║ ██╔════╝ ██║              ██║ ██║",
        "██║ █╗ ██║ ██║   ██║ ██║      ██║ █████╗       ██║ ██║",
        "██║███╗██║ ██║   ██║ ██║      ██║ ╚════╝  ██   ██║ ██║",
        "╚███╔███╔╝ ╚██████╔╝ ╚██████╗ ██║         ╚█████╔╝ ██║",
        " ╚══╝╚══╝   ╚═════╝   ╚═════╝ ╚═╝          ╚════╝  ╚═╝",
    ]
    compact_logo = [
        "╔════════════════════╗",
        "║      WUCI-JI       ║",
        "╚════════════════════╝",
    ]
    logo = block_logo if max(display_width(line) for line in block_logo) <= inner_width else compact_logo
    detail_rows = (
        [
            (frame_line("NOXFRAME / DAYLIGHT / GATE", align="left"), palette.cyan),
            (
                frame_line(
                    "public anchors only  |  receipt-bound release  |  local proof substrate",
                    align="left",
                ),
                palette.dim,
            ),
            (
                frame_line(
                    "sealed locally  |  clear record  |  standard quick boot between full cycles",
                    align="left",
                ),
                palette.dim,
            ),
        ]
        if inner_width >= 78
        else [
            (frame_line("NOXFRAME / DAYLIGHT / GATE", align="left"), palette.cyan),
            (frame_line("local proof substrate  |  quick boot / full cycle", align="left"), palette.dim),
        ]
    )
    edge = "+" + "-" * inner_width + "+"
    pulse = FRAMES[frame % len(FRAMES)]
    lines = [
        (edge, palette.dim),
        (space_line(0, drift=1), palette.dim),
        (space_line(9, drift=2), palette.dim),
        *[(frame_line(line), palette.red) for line in logo],
        (space_line(17, drift=3), palette.dim),
        (orbit_line("无   此   机   系   统"), palette.yellow),
        (frame_line("wu   ci   ji   xi   tong"), palette.cyan),
        (frame_line("Wuci-Ji Systems"), palette.cyan),
        (space_line(26, drift=2), palette.dim),
        *detail_rows,
        *(
            [
                (
                    frame_line(
                        f"{pulse} awaiting operator boot decision  |  enter y to boot, enter for no",
                        align="left",
                    ),
                    palette.green,
                )
            ]
            if full_screen
            else []
        ),
        (space_line(34, drift=3), palette.dim),
        (frame_line("无此机  ::  无授权  ::  无许可"), palette.yellow),
        (space_line(43, drift=1), palette.dim),
        (edge, palette.dim),
    ]
    if full_screen:
        footer = [
            (frame_line("WUCI-JI + Daylight defensive proof launch", align="left"), palette.dim),
            (frame_line(f"legacy alias: {LEGACY_TOOL_NAME}", align="left"), palette.dim),
        ]
        prompt_rows = []
        if prompt is not None:
            prompt_rows.append((frame_line(f"{prompt}{answer}", align="left"), palette.yellow))
        body = [*lines, *footer, *prompt_rows]
        extra_rows = max(0, terminal_lines() - len(body))
        top_rows = extra_rows // 3
        bottom_rows = extra_rows - top_rows
        full_lines = (
            [(sky_line(101 + index * 11), palette.dim) for index in range(top_rows)]
            + body
            + [(sky_line(211 + index * 13), palette.dim) for index in range(bottom_rows)]
        )
        sys.stderr.write("\033[2J\033[H")
        for line, color in full_lines:
            sys.stderr.write(palette.paint(line, color) + "\n")
        sys.stderr.flush()
        return

    for line, color in lines:
        sys.stderr.write(palette.paint(line, color) + "\n")
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


def print_json(value: object) -> None:
    json.dump(value, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def command_contract() -> int:
    print_json(substrate_contract())
    return 0


def command_init(root: Path, args: argparse.Namespace) -> int:
    state_path, seal_path = substrate_paths(root, args)
    state, seal, created = init_substrate(
        root,
        state_path=state_path,
        seal_path=seal_path,
        force=args.force,
        now_utc=utc_now(),
    )
    if args.json:
        print_json(
            {
                "schema": "wuci-noxframe-init-result-v1",
                "created": created,
                "state": str(state_path),
                "seal": str(seal_path),
                "state_digest_vector": digest_vector_json(state),
                "substrate_digest_vector": seal["substrate_digest_vector"],
            }
        )
    else:
        action = "initialized" if created else "refreshed"
        print(f"noxframe: {action}")
        print(f"state: {state_path}")
        print(f"seal: {seal_path}")
    return 0


def command_status(root: Path, args: argparse.Namespace) -> int:
    state_path, seal_path = substrate_paths(root, args)
    if not state_path.exists() or not seal_path.exists():
        payload = {
            "schema": "wuci-noxframe-status-v1",
            "status": "uninitialized",
            "state": str(state_path),
            "seal": str(seal_path),
        }
        if args.json:
            print_json(payload)
        else:
            print("noxframe: uninitialized")
            print(f"state: {state_path}")
            print(f"seal: {seal_path}")
        return 2

    ok, problems = verify_substrate_seal(root, state_path=state_path, seal_path=seal_path)
    state = safe_read_json_file(state_path, "NOXFRAME state")
    payload = {
        "schema": "wuci-noxframe-status-v1",
        "status": "sealed" if ok else "drifted",
        "state": str(state_path),
        "seal": str(seal_path),
        "active_context": state.get("active_context"),
        "route": state.get("route"),
        "cell_count": len(state.get("cells", [])) if isinstance(state.get("cells"), list) else 0,
        "problems": problems,
    }
    if args.json:
        print_json(payload)
    else:
        print(f"noxframe: {payload['status']}")
        print(f"active-context: {payload['active_context']}")
        print(f"route: {' > '.join(str(part) for part in payload['route']) if isinstance(payload['route'], list) else 'unknown'}")
        print(f"state: {state_path}")
        print(f"seal: {seal_path}")
        for problem in problems:
            print(f"problem: {problem}")
    return 0 if ok else 1


def command_seal(root: Path, args: argparse.Namespace) -> int:
    state_path, seal_path = substrate_paths(root, args)
    ensure_substrate(root, state_path=state_path, seal_path=seal_path)
    state = safe_read_json_file(state_path, "NOXFRAME state")
    state["updated_utc"] = utc_now()
    write_json_atomic(state_path, state)
    seal = build_substrate_seal(root, state, now_utc=utc_now())
    write_json_atomic(seal_path, seal)
    if args.json:
        print_json(
            {
                "schema": "wuci-noxframe-seal-result-v1",
                "status": "sealed",
                "state": str(state_path),
                "seal": str(seal_path),
                "substrate_digest_vector": seal["substrate_digest_vector"],
            }
        )
    else:
        print("noxframe: sealed")
        print(f"state: {state_path}")
        print(f"seal: {seal_path}")
    return 0


def command_verify(root: Path, args: argparse.Namespace) -> int:
    state_path, seal_path = substrate_paths(root, args)
    ok, problems = verify_substrate_seal(root, state_path=state_path, seal_path=seal_path)
    payload = {
        "schema": "wuci-noxframe-verify-result-v1",
        "status": "pass" if ok else "fail",
        "state": str(state_path),
        "seal": str(seal_path),
        "problems": problems,
    }
    if args.json:
        print_json(payload)
    else:
        print(f"noxframe verify: {payload['status']}")
        for problem in problems:
            print(f"problem: {problem}")
    return 0 if ok else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wuci-noxframe",
        description="NOXFRAME launcher for Wuci-Ji and Daylight proof lanes.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("launch", "contract", "init", "status", "seal", "verify"),
        default="launch",
        help="command to run; default is launch",
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
    parser.add_argument(
        "--substrate-state",
        default=DEFAULT_STATE,
        help="NOXFRAME substrate state path, relative to the repository root unless absolute",
    )
    parser.add_argument(
        "--substrate-seal",
        default=DEFAULT_SUBSTRATE_SEAL,
        help="NOXFRAME substrate seal path, relative to the repository root unless absolute",
    )
    parser.add_argument("--force", action="store_true", help="replace existing substrate state during init")
    parser.add_argument("--json", action="store_true", help="emit command result as JSON")
    parser.add_argument("-y", "--yes", action="store_true", help="answer yes to the interactive boot prompt")
    parser.add_argument(
        "--no-boot-prompt",
        action="store_true",
        help="skip the interactive Wuci-Ji substrate boot prompt",
    )
    parser.add_argument(
        "--force-boot-prompt",
        action="store_true",
        help="ask the boot prompt even when stdio is not a TTY",
    )
    parser.add_argument(
        "--no-boot-animation",
        action="store_true",
        help="disable the TTY-only animated full-screen boot prompt",
    )
    parser.add_argument(
        "--console",
        action="store_true",
        help="enter the NOXFRAME operator console after boot",
    )
    parser.add_argument(
        "--no-console",
        action="store_true",
        help="run the launch matrix directly instead of entering the operator console",
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
    parser.add_argument(
        "--allow-codex",
        action="store_true",
        help="allow the NOXFRAME console codex command to launch a host Codex process",
    )
    parser.add_argument(
        "--codex-bin",
        default=DEFAULT_CODEX_BIN,
        help="Codex executable for the opt-in console bridge",
    )
    return parser.parse_args()


def run_launch_matrix(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    *,
    report_path: Path,
    seal_path: Path,
    clock_path: Path,
) -> int:
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


def clear_screen() -> None:
    sys.stderr.write("\033[2J\033[H")
    sys.stderr.flush()


def display_repo_path(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def print_console_line(text: str, *, color: str | None = None, palette: Palette | None = None) -> None:
    width = max(20, terminal_columns() - 1)
    rendered = fit_display(text, width)
    if color is not None and palette is not None:
        rendered = palette.paint(rendered, color)
    print(rendered)


def print_console_header(root: Path, args: argparse.Namespace, palette: Palette) -> None:
    clock_path = repo_path(root, args.clock)
    state_path, seal_path = substrate_paths(root, args)
    clock_state = read_clock_state(clock_path)
    decision = resolve_profile(
        args.profile,
        clock_path=clock_path,
        state=clock_state,
        now=dt.datetime.now(dt.UTC),
    )
    print_console_line("WUCI-JI SYSTEMS / NOXFRAME CONSOLE", color=palette.red, palette=palette)
    print_console_line("bounded metadata console")
    print_console_line("route: root > wuci-ji > daylight")
    print_console_line(
        f"profile: requested={decision.requested_profile} effective={decision.effective_profile}"
    )
    print_console_line(f"state: {display_repo_path(root, state_path)}")
    print_console_line(f"seal: {display_repo_path(root, seal_path)}")
    if terminal_columns() >= 88:
        print_console_line(
            "commands: help --compact, man <cmd>, complete <prefix>, status, launch, clear, exit"
        )
    else:
        print_console_line("commands: help --compact, man <cmd>, complete")
        print_console_line("          status, launch, clear, exit")


def print_goodbye(palette: Palette) -> None:
    print(palette.paint("再见，黑客。", palette.yellow))
    print(palette.paint("Goodbye, Hacker.", palette.cyan))


def print_unavailable(spec: ConsoleCommandSpec) -> None:
    print(f"{spec.name}: route unavailable in NOXFRAME console")
    print("scope: command is discoverable for compatibility; no host passthrough is opened here")


def handle_launch_command(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    parts: list[str],
) -> None:
    old_profile = args.profile
    old_no_countdown = args.no_countdown
    if len(parts) > 1:
        requested = parts[1].lower()
        if requested not in {"auto", "smoke", "full"}:
            print("usage: launch [auto|smoke|full]")
            return
        args.profile = requested
    args.no_countdown = True
    rc = run_launch_matrix(
        root,
        args,
        palette,
        report_path=repo_path(root, args.report),
        seal_path=repo_path(root, args.seal),
        clock_path=repo_path(root, args.clock),
    )
    args.profile = old_profile
    args.no_countdown = old_no_countdown
    print(f"launch-result: {rc}")


def handle_vfs_command(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
    command: str,
    parts: list[str],
) -> None:
    if command == "pwd":
        print(session.cwd)
        return
    if command == "ls":
        path = vfs_normalize(session.cwd, parts[1] if len(parts) > 1 else None)
        is_dir, entries = vfs_list(path)
        if is_dir:
            print("\n".join(entries))
        else:
            print(entries[0])
        return
    if command == "cd":
        path = vfs_normalize(session.cwd, parts[1] if len(parts) > 1 else "/")
        if not vfs_is_dir(path):
            print(f"cd: not a virtual directory: {path}")
            return
        session.cwd = path
        return
    if command == "cat":
        if len(parts) < 2:
            print("usage: cat <file>")
            return
        for file_arg in parts[1:]:
            path = vfs_normalize(session.cwd, file_arg)
            print(virtual_file_text(root, args, session, path), end="")
        return
    if command == "tree":
        path = vfs_normalize(session.cwd, parts[1] if len(parts) > 1 else None)
        print_vfs_tree(path)
        return
    if command == "echo":
        if ">" in parts or ">>" in parts:
            print("echo: redirect writes are not available in the NOXFRAME VFS")
            return
        print(" ".join(parts[1:]))
        return
    print(f"{command}: virtual filesystem mutation is unavailable")


def parse_count_option(parts: list[str], default: int = 10) -> tuple[int, list[str]]:
    count = default
    rest = parts[:]
    if len(rest) >= 2 and rest[0] in {"-n", "--lines"}:
        try:
            count = max(0, int(rest[1]))
        except ValueError:
            count = default
        rest = rest[2:]
    elif rest and rest[0].startswith("-") and rest[0][1:].isdigit():
        count = int(rest[0][1:])
        rest = rest[1:]
    return count, rest


def handle_text_command(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
    command: str,
    parts: list[str],
) -> None:
    if command == "pipeline":
        print("pipeline: grep/head/tail/wc/find are available as direct virtual-file commands")
        return
    if command == "find":
        start = vfs_normalize(session.cwd, parts[1] if len(parts) > 1 and not parts[1].startswith("-") else None)
        needle = ""
        if "-name" in parts:
            index = parts.index("-name")
            if index + 1 < len(parts):
                needle = parts[index + 1].strip("*")
        for path in vfs_all_paths():
            if not path.startswith(start.rstrip("/") + "/") and path != start:
                continue
            if needle and needle not in path.rsplit("/", 1)[-1]:
                continue
            print(path)
        return
    if command == "grep":
        if len(parts) < 3:
            print("usage: grep <pattern> <file>...")
            return
        pattern = parts[1]
        for path, text in console_text_files(root, args, session, parts[2:]):
            for line_no, line in enumerate(text.splitlines(), start=1):
                if pattern in line:
                    print(f"{path}:{line_no}:{line}")
        return
    if command == "wc":
        if len(parts) < 2:
            print("usage: wc <file>...")
            return
        for path, text in console_text_files(root, args, session, parts[1:]):
            lines = len(text.splitlines())
            words = len(text.split())
            chars = len(text.encode("utf-8"))
            print(f"{lines:5d} {words:5d} {chars:6d} {path}")
        return
    if command in {"head", "tail"}:
        count, files = parse_count_option(parts[1:])
        if not files:
            print(f"usage: {command} [-n count] <file>")
            return
        for path, text in console_text_files(root, args, session, files):
            lines = text.splitlines()
            selected = lines[:count] if command == "head" else lines[-count:]
            if len(files) > 1:
                print(f"==> {path} <==")
            print("\n".join(selected))
        return


def handle_proc_command(command: str) -> None:
    if command == "ps":
        print(console_process_table(), end="")
    elif command == "top":
        print("tasks: 3 total, 2 ready, 1 idle")
        print("load: metadata-only  memory: virtual")
    elif command == "jobs":
        print("jobs: no console background jobs")
    else:
        print(f"{command}: simulated process mutation is unavailable")


def handle_sys_command(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
    command: str,
    parts: list[str],
) -> None:
    if command == "sysinfo":
        status = virtual_status_payload(root, args)
        print(f"name: {TOOL_NAME}")
        print("route: root > wuci-ji > daylight")
        print(f"status: {status.get('status')}")
        print(f"cells: {len(SUBSTRATE_CELLS)}")
        print(f"columns: {terminal_columns()}")
        return
    if command == "dash":
        status = virtual_status_payload(root, args)
        print(f"[substrate] {status.get('status')}  [profile] {args.profile}  [route] root>wuci-ji>daylight")
        return
    if command == "free":
        print("              total        used        free")
        print(f"substrate      {len(SUBSTRATE_CELLS)} cells    3 active    {len(SUBSTRATE_CELLS) - 3} sealed")
        return
    if command == "df":
        print("Filesystem        Files  Mounted")
        print(f"noxframe-vfs      {len(vfs_all_paths())}     /")
        print("noxframe-docs      5     /docs")
        return
    if command == "dmesg":
        print("noxframe: responsive Wuci-Ji Systems banner initialized")
        print("noxframe: substrate state/seal paths loaded")
        print("noxframe: Phase1 command registry mapped into bounded console")
        return
    if command == "vmstat":
        print("cells active sealed drift")
        print(f"{len(SUBSTRATE_CELLS):5d} {3:6d} {len(SUBSTRATE_CELLS):6d} {0:5d}")
        return
    if command == "uname":
        print("WUCI-NOXFRAME metadata-console substrate-v1")
        return
    if command == "date":
        print(utc_now())
        return
    if command == "uptime":
        elapsed = int(time.monotonic() - session.started_monotonic)
        print(f"up {elapsed}s")
        return
    if command == "hostname":
        print("wuci-ji-substrate")
        return
    if command == "audit":
        print(virtual_file_text(root, args, session, "/var/log/audit"), end="")
        return
    if command == "opslog":
        sub = parts[1].lower() if len(parts) > 1 else "status"
        if sub == "tail":
            print(virtual_file_text(root, args, session, "/var/log/audit"), end="")
        else:
            print(f"opslog: {len(session.audit)} console events")
        return
    if command in {"lspci", "pcie"}:
        print("00:00.0 Wuci-Ji substrate bridge")
        print("00:01.0 Daylight evidence adapter")
        return
    if command == "cr3":
        print("cr3: 0x0000000000002000 (virtual)")
        return
    if command == "cr4":
        print("cr4: pcide=off pae=on pse=on (virtual)")
        return
    print(f"{command}: virtual hardware mutation is unavailable")


def handle_user_command(session: ConsoleSession, command: str, parts: list[str]) -> None:
    if command == "env":
        for key in sorted(session.env):
            print(f"{key}={session.env[key]}")
        return
    if command == "export":
        if len(parts) != 2 or "=" not in parts[1]:
            print("usage: export KEY=value")
            return
        key, value = parts[1].split("=", 1)
        if not key or not key.replace("_", "").isalnum():
            print("export: invalid key")
            return
        session.env[key] = value
        return
    if command == "unset":
        if len(parts) != 2:
            print("usage: unset KEY")
            return
        session.env.pop(parts[1], None)
        return
    if command == "whoami":
        print(session.env.get("USER", "operator"))
        return
    if command == "id":
        print("uid=1000(operator) gid=1000(wuci) groups=1000(wuci)")
        return
    if command == "accounts":
        print("operator   uid=1000   role=local-console")
        print("system     uid=0      role=substrate-metadata")
        return
    if command == "history":
        for index, item in enumerate(session.history[-50:], start=max(1, len(session.history) - 49)):
            print(f"{index:4d}  {item}")
        return
    if command == "security":
        print("console: bounded command registry")
        print("host: no passthrough commands")
        print("network: no fetch or scan commands")
        print("writes: substrate state/seal and launch evidence only")
        return
    if command == "theme":
        if len(parts) > 1 and parts[1] == "list":
            print("crimson ice amber mono")
        else:
            print("theme: crimson")
        return
    if command == "banner":
        print("banner: responsive Wuci-Ji Systems starfield")
        print(f"inner-width: {banner_inner_width()}")
        return
    if command == "tips":
        print("try: help --compact")
        print("try: ls /proc && cat /proc/cells")
        print("try: status && verify")
        return


def handle_dev_or_host_command(
    root: Path,
    args: argparse.Namespace,
    command: str,
    parts: list[str],
) -> None:
    if command == "codex":
        handle_codex_command(root, args, parts)
        return
    if command == "update":
        print("update: use repository proof lanes outside the console")
        print("protocol: plan, validate, commit, push")
        return
    if command == "repo":
        print("repo: main line with NOXFRAME as Wuci-Ji substrate surface")
        print("channels: main, proof lanes, generated build evidence")
        return
    if command == "fyr":
        print("fyr: lineage carried as small-language and command-surface discipline")
        print("runtime: not embedded in NOXFRAME")
        return
    if command == "lang":
        print("lang: host language runtimes are not executed from this console")
        print("support: metadata only")
        return
    spec = console_lookup(command)
    if spec is not None:
        print_unavailable(spec)


def handle_misc_command(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
    command: str,
    parts: list[str],
) -> bool:
    if command == "help":
        print(console_help_text(parts[1:]))
        return True
    if command == "man":
        if len(parts) < 2:
            print("usage: man <command>")
            return True
        manual = console_man_text(parts[1])
        print(manual if manual is not None else f"no manual entry for {parts[1]}")
        return True
    if command == "complete":
        prefix = parts[1] if len(parts) > 1 else ""
        matches = console_completions(prefix)
        print("\n".join(matches) if matches else f"complete: no matches for {prefix!r}")
        return True
    if command == "capabilities":
        print(console_capabilities_text())
        return True
    if command == "matrix":
        print("matrix: use the responsive boot starfield; animation is not run inside tests")
        return True
    if command == "bootcfg":
        print(f"profile: {args.profile}")
        print(f"clock: {repo_path(root, args.clock)}")
        return True
    if command == "version":
        print(f"{TOOL_NAME} substrate-contract={SUBSTRATE_SPEC_SCHEMA}")
        print(f"git: {git_value(root, 'rev-parse', 'HEAD')}")
        return True
    if command == "roadmap":
        print("1. substrate command registry")
        print("2. responsive console UX")
        print("3. proof-lane launch matrix")
        print("4. future native boundaries stay explicit")
        return True
    if command == "sandbox":
        print("boundary: metadata console with no host shell route")
        print("proof: public anchors plus local state/seal verification")
        return True
    if command == "nest":
        print("nest: root > wuci-ji > daylight")
        print("stack: single active NOXFRAME session")
        return True
    if command == "exit":
        return False
    return True


def dispatch_console_command(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    session: ConsoleSession,
    parts: list[str],
) -> bool:
    spec = console_lookup(parts[0])
    if spec is None:
        print(f"unknown command: {parts[0]}")
        print("try: help --compact")
        return True
    command = spec.name
    if command == "clear":
        clear_screen()
        print_console_header(root, args, palette)
        return True
    if command == "exit":
        print_goodbye(palette)
        return False
    if command in {"status", "seal", "verify", "contract", "launch"}:
        if command == "status":
            command_status(root, args)
        elif command == "seal":
            command_seal(root, args)
        elif command == "verify":
            command_verify(root, args)
        elif command == "contract":
            command_contract()
        else:
            handle_launch_command(root, args, palette, parts)
        return True
    if spec.guard == "unavailable":
        print_unavailable(spec)
        return True
    if spec.category == "fs":
        handle_vfs_command(root, args, session, command, parts)
    elif spec.category == "text":
        handle_text_command(root, args, session, command, parts)
    elif spec.category == "proc":
        handle_proc_command(command)
    elif spec.category == "sys":
        handle_sys_command(root, args, session, command, parts)
    elif spec.category == "user":
        handle_user_command(session, command, parts)
    elif spec.category in {"host", "dev", "net"}:
        handle_dev_or_host_command(root, args, command, parts)
    elif spec.category == "misc":
        return handle_misc_command(root, args, session, command, parts)
    return True


def run_operator_console(root: Path, args: argparse.Namespace, palette: Palette) -> int:
    state_path, seal_path = substrate_paths(root, args)
    ensure_substrate(root, state_path=state_path, seal_path=seal_path)
    session = ConsoleSession()
    clear_screen()
    print_console_header(root, args, palette)
    while True:
        try:
            line = input(palette.paint("noxframe> ", palette.red))
        except EOFError:
            print()
            print_goodbye(palette)
            return 0
        raw = line.strip()
        if not raw:
            continue
        session.history.append(raw)
        if len(session.history) > 512:
            del session.history[:-512]
        record_console_event(session, raw)
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            print(f"parse error: {exc}")
            continue
        if not parts:
            continue
        try:
            keep_running = dispatch_console_command(root, args, palette, session, parts)
        except NoxframeError as exc:
            print(str(exc))
            continue
        if not keep_running:
            return 0


def main() -> int:
    args = parse_args()
    root = repo_root()
    report_path = repo_path(root, args.report)
    seal_path = repo_path(root, args.seal)
    clock_path = repo_path(root, args.clock)
    palette = Palette(args.color)

    if args.command == "contract":
        return command_contract()
    if args.command == "init":
        return command_init(root, args)
    if args.command == "status":
        return command_status(root, args)
    if args.command == "seal":
        return command_seal(root, args)
    if args.command == "verify":
        return command_verify(root, args)

    if not boot_animation_active(args):
        print_banner(palette)
    if not confirm_boot(args, palette):
        sys.stderr.write(palette.paint("WUCI-JI substrate boot declined\n", palette.red))
        return 130
    state_path, substrate_seal_path = substrate_paths(root, args)
    ensure_substrate(root, state_path=state_path, seal_path=substrate_seal_path)
    interactive_console = args.console or (
        not args.no_console and sys.stdin.isatty() and sys.stdout.isatty()
    )
    if interactive_console:
        return run_operator_console(root, args, palette)

    if not args.no_countdown:
        countdown(max(args.countdown, 0), palette)
    return run_launch_matrix(
        root,
        args,
        palette,
        report_path=report_path,
        seal_path=seal_path,
        clock_path=clock_path,
    )


if __name__ == "__main__":
    raise SystemExit(main())
