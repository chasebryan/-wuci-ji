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
import fcntl
import struct
import tempfile
import termios
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path

try:
    import readline
except ImportError:  # pragma: no cover - platform fallback
    readline = None

import wuci_kaiju


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
class ConsoleXFrameState:
    frame_id: int
    cwd: str = "/"
    started_monotonic: float = field(default_factory=time.monotonic)
    history: list[str] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    vfs_dirs: set[str] = field(default_factory=set)
    vfs_files: dict[str, str] = field(default_factory=dict)
    jobs: dict[int, dict[str, str]] = field(default_factory=dict)
    next_pid: int = 100
    env: dict[str, str] = field(default_factory=lambda: default_console_env())


@dataclass
class ConsoleSession:
    cwd: str = "/"
    started_monotonic: float = field(default_factory=time.monotonic)
    history: list[str] = field(default_factory=list)
    audit: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    vfs_dirs: set[str] = field(default_factory=set)
    vfs_files: dict[str, str] = field(default_factory=dict)
    jobs: dict[int, dict[str, str]] = field(default_factory=dict)
    next_pid: int = 100
    env: dict[str, str] = field(default_factory=lambda: default_console_env())
    xframe_count: int = 1
    active_xframe: int = 1
    xframes: dict[int, ConsoleXFrameState] = field(default_factory=dict)


@dataclass(frozen=True)
class BootTerminalProfile:
    name: str
    rich_animation: bool
    reduced_motion: bool
    frame_delay: float


@dataclass(frozen=True)
class ConsoleDepthTheme:
    name: str
    prompt_color: str
    header_color: str
    accent_color: str
    rail: str


TERMINAL_HANDOFF_ENV = "NOXFRAME_TERMINAL_HANDOFF"
MECHANICS_TERMINAL_NAMES = ("kitty", "wezterm", "ghostty", "iterm")
MECHANICS_TERMINAL_HINT = "kitty, WezTerm, Ghostty, or iTerm2"
DEPTH_THEMES = (
    ConsoleDepthTheme("root-red-lattice", "31", "31", "35", "◇─◇─◇"),
    ConsoleDepthTheme("amber-gate-lattice", "33", "33", "31", "◆═◆═◆"),
    ConsoleDepthTheme("green-witness-lattice", "32", "32", "36", "✦─✦─✦"),
    ConsoleDepthTheme("cyan-ledger-lattice", "36", "36", "34", "▣═▣═▣"),
    ConsoleDepthTheme("blue-cage-lattice", "34", "34", "35", "◈─◈─◈"),
    ConsoleDepthTheme("magenta-qcage-lattice", "35", "35", "33", "⬢═⬢═⬢"),
)


TOOL_NAME = "WUCI-NOXFRAME"
LEGACY_TOOL_NAME = "WUCI-BLACK-ICE"
REPORT_SCHEMA = "wuci-noxframe-launch-report-v1"
SEAL_SCHEMA = "wuci-noxframe-seal-v1"
SUBSTRATE_SPEC_SCHEMA = "wuci-noxframe-substrate-contract-v1"
SUBSTRATE_STATE_SCHEMA = "wuci-noxframe-state-v1"
SUBSTRATE_SEAL_SCHEMA = "wuci-noxframe-substrate-seal-v1"
DAYLIGHT_WRAP_SCHEMA = "wuci-noxframe-daylight-wrap-v1"
DAYLIGHT_WRAP_BUNDLE_SCHEMA = "wuci-noxframe-daylight-wrap-bundle-v1"
SUBSTRATE_MEMORY_SCHEMA = "wuci-noxframe-substrate-memory-v1"
SUBSTRATE_LOCK_POLICY_SCHEMA = "wuci-noxframe-substrate-lock-policy-v1"
DEFAULT_REPORT = "docs/noxframe/WUCI_NOXFRAME_LAUNCH_REPORT.md"
DEFAULT_SEAL = "docs/noxframe/WUCI_NOXFRAME_SELF_SEAL.json"
DEFAULT_CLOCK = "build/noxframe/WUCI_NOXFRAME_CLOCK.json"
DEFAULT_STATE = "build/noxframe/WUCI_NOXFRAME_STATE.json"
DEFAULT_SUBSTRATE_SEAL = "build/noxframe/WUCI_NOXFRAME_SUBSTRATE_SEAL.json"
DEFAULT_DAYLIGHT_WRAP_DIR = "build/noxframe/daylight-wrap"
DEFAULT_SUBSTRATE_MEMORY_ROOT = "build/noxframe/substrate-memory"
DEFAULT_SUBSTRATE_LOCK_DEPTH = 9
KAIJU_MANIFEST_PATH = "docs/noxframe/wuci_kaiju_manifest.json"
DEFAULT_DEMO_ROOT = "build/wuci-noxframe-runs"
XFRAME_MAX = 4
XFRAME_SWITCH_INPUTS = ("\x1b[Z", "\x1b\x1b[Z", "\x1b[17~")
XFRAME_SWITCH_HINT = "Shift+Tab/F6"
NOXFRAME_SELF_RELEASE_DEMO_DIR = "build/noxframe/self-release"
NOXFRAME_SELF_RELEASE_ATTESTATION = f"{NOXFRAME_SELF_RELEASE_DEMO_DIR}/attestation.json"
NOXFRAME_WITNESS_BUNDLE_DIR = "build/noxframe/self-release-witness"
NOXFRAME_WITNESS_WORK_DIR = f"{NOXFRAME_WITNESS_BUNDLE_DIR}.work"
NOXFRAME_LEDGER_DIR = "build/noxframe/self-release-ledger"
NOXFRAME_LEDGER_INCLUSION_PROOF = f"{NOXFRAME_LEDGER_DIR}/inclusion-proof.txt"
NOXFRAME_LEDGER_CONSISTENCY_PROOF = f"{NOXFRAME_LEDGER_DIR}/consistency-proof.txt"
DEFAULT_CODEX_BIN = "codex"
DEFAULT_WUCI_BIN = "build/wuci-ji"
GATE_DEMO_DIRNAME = "gate-demo"
WEEK_SECONDS = 7 * 24 * 60 * 60
ANCHOR_PATHS = (
    "docs/SECURITY_BOUNDARY.md",
    "docs/wuci_gate_boundary.json",
    "docs/wuci_cage_policy.json",
    "docs/wuci_qcage_policy.json",
    "docs/wuci_high_attestation_profile.json",
    KAIJU_MANIFEST_PATH,
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
    KAIJU_MANIFEST_PATH: "WUCI-KAIJU Kali purpose catalog",
    "daylight-equation/SCORECARD.v1.json": "Daylight score boundary",
    "daylight-equation/specs/daylight-minimal-core-v0.4.md": "Daylight core spec",
    "daylight-equation/rust/daylight-crypto/src/wuci_daylight.rs": "Daylight bridge source",
}
DAYLIGHT_ANCHOR_PATHS = tuple(
    path for path in ANCHOR_PATHS if path.startswith("daylight-equation/")
)
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
    ("kaiju", "defensive Kali ISO and tool purpose-catalog context", ("status", "iso", "disk", "boot", "verify")),
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
    "phase",
    "fs",
    "text",
    "proc",
    "sys",
    "user",
    "learn",
    "net",
    "host",
    "dev",
    "plugin",
    "misc",
)
BOOT_LINES = (
    "SYSTEMS BOOTING...",
    "ENTROPY LATTICE WARMING...",
    "GATE MATRIX LOCKING...",
    "PRISM TICKERS ARMED...",
    "WUCI-JI SYSTEM INITIALIZED...",
)
BOOT_VOICE_TEXT = (
    "Welcome to the Wuci-Ji system substrate, hacker. "
    "Would you like to enter your system?"
)
BOOT_PROMPT = f"{BOOT_VOICE_TEXT} [y/N] "
BOOT_IDEOGRAPH_TEXT = "无此机系统"
FRAMES = ("[////]", "[////]", "[\\\\\\\\]", "[||||]", "[====]", "[####]")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
DEFAULT_TERMINAL_COLUMNS = 96
MIN_BANNER_INNER_WIDTH = 38
MAX_BANNER_INNER_WIDTH = 112
UNAVAILABLE_COMMAND_PREFIX = "'/"
VFS_COMPLETION_COMMANDS = {"cat", "find", "grep", "head", "ls", "tail", "tree", "wc"}
VFS_DIRECTORY_COMPLETION_COMMANDS = {"cd"}
PHASE1_FEATURES = (
    ("terminal", "operator console, help, completion, history, audit"),
    ("vfs", "virtual filesystem and read-only text tools"),
    ("proc", "process and system metadata views"),
    ("optics", "Phase Compass whereami/path/map surfaces"),
    ("nest", "metadata-only nested contexts"),
    ("learn", "session-local learning notes"),
    ("fyr", "Fyr lineage metadata"),
    ("wasi", "plugin/WASI catalog without execution"),
    ("base1", "guarded B1/B2 workflow metadata"),
    ("quality", "selftest, doctor, and scorecard gates"),
)
PLUGIN_CATALOG = (
    ("codex", "explicit opt-in host bridge", "metadata by default; host launch requires --allow-codex"),
    ("wasi-lite", "Phase1-compatible plugin lane", "catalog only; module execution unavailable"),
    ("prism", "Wuci-Prism proof inspector", "available through launch matrix, not as host shell"),
    ("noxframe-self-release", "self-release evidence lane", "explicit self-release run writes under build/noxframe"),
    ("wuci-kaiju", "Kali purpose catalog for future substrates", "metadata only; host Kali tools unavailable"),
)
WIKI_TOPICS = {
    "phase1": (
        "Phase1 carried forward: terminal UX, VFS, proc/sys views, Optics/Compass, "
        "nests, local learning, plugins, and quality gates. NOXFRAME imports ideas, not code."
    ),
    "noxframe": (
        "NOXFRAME is a bounded Wuci-Ji metadata substrate and proof launcher. "
        "It is not a kernel, host shell, runtime sandbox, or production authority."
    ),
    "gate": "Gate remains the release/open decision boundary; plaintext is not produced before Gate approval.",
    "cage": "CAGE verifies artifact legitimacy around public evidence; it is not OS containment.",
    "qcage": "QCAGE labels quantum risk and digest evidence; classical signatures are not quantum-safe.",
    "install": "INSTALL is noninteractive and signed; it requires a local copied root key.",
    "kaiju": "WUCI-KAIJU maps Kali tool purposes into a verified metadata catalog; it does not run Kali tools.",
}


def default_console_env() -> dict[str, str]:
    return {
        "USER": "operator",
        "HOME": "/wuci",
        "SHELL": "noxframe",
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "PATH": "/bin:/usr/bin:/wuci/bin:/noxframe/bin",
        "PWD": "/",
        "NOXFRAME": TOOL_NAME,
        "NOXFRAME_CONTEXT": "root",
        "NOXFRAME_GUARD": "bounded-command-registry",
        "NOXFRAME_HOST_ROUTES": "metadata-only-by-default",
        "NOXFRAME_MODE": "metadata-console",
        "NOXFRAME_PROFILE": "auto",
        "NOXFRAME_ROUTE": "root>wuci-ji>daylight",
        "NOXFRAME_DEPTH": "0",
        "NOXFRAME_LATTICE": DEPTH_THEMES[0].name,
        "NOXFRAME_SELF_RELEASE": "ready",
        "NOXFRAME_SELF_RELEASE_ROOT": "/wuci/self-release",
        "NOXFRAME_DAYLIGHT_WRAP_ROOT": "/wuci/daylight-wrap",
        "NOXFRAME_SUBSTRATE_MEMORY_ROOT": DEFAULT_SUBSTRATE_MEMORY_ROOT,
        "NOXFRAME_SUBSTRATE_LOCK_FROM_DEPTH": str(DEFAULT_SUBSTRATE_LOCK_DEPTH),
        "NOXFRAME_CR3": "0x0000000000002000",
        "NOXFRAME_PCIDE": "off",
    }


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


def command_is_unavailable(spec: ConsoleCommandSpec) -> bool:
    return spec.guard == "unavailable"


def command_display_token(spec: ConsoleCommandSpec, token: str) -> str:
    if command_is_unavailable(spec):
        return f"{UNAVAILABLE_COMMAND_PREFIX}{token}"
    return token


def command_display_name(spec: ConsoleCommandSpec) -> str:
    return command_display_token(spec, spec.name)


def command_display_usage(spec: ConsoleCommandSpec) -> str:
    if not command_is_unavailable(spec):
        return spec.usage
    if spec.usage == spec.name:
        return command_display_name(spec)
    prefix = f"{spec.name} "
    if spec.usage.startswith(prefix):
        return f"{command_display_name(spec)} {spec.usage[len(prefix):]}"
    return spec.usage


CONSOLE_COMMANDS = (
    console_cmd("status", (), "substrate", "status", "Show substrate state and seal status.", "substrate.read", "local"),
    console_cmd("seal", (), "substrate", "seal", "Refresh the NOXFRAME substrate seal.", "substrate.write", "local"),
    console_cmd("verify", (), "substrate", "verify", "Verify current substrate state and seal.", "substrate.read", "local"),
    console_cmd("contract", (), "substrate", "contract", "Print the canonical substrate contract.", "substrate.read", "local"),
    console_cmd("launch", (), "substrate", "launch [auto|smoke|full]", "Run the Wuci-Ji launch matrix.", "proof.run", "explicit"),
    console_cmd("self-release", ("selfrelease", "release"), "substrate", "self-release [plan|status|run|shell]", "Build and inspect NOXFRAME-scoped Wuci-Ji self-release evidence.", "proof.run", "explicit"),
    console_cmd("phase", ("whereami", "compass", "optics"), "phase", "phase [whereami|compass|path|map|features|help]", "Show Phase1-style Optics and Phase Compass state.", "phase.read", "metadata-only"),
    console_cmd("pwd", (), "fs", "pwd", "Print the current virtual substrate path.", "fs.read", "metadata-only"),
    console_cmd("ls", (), "fs", "ls [path]", "List virtual substrate files and directories.", "fs.read", "metadata-only"),
    console_cmd("cd", (), "fs", "cd [dir]", "Change virtual substrate directory.", "fs.read", "metadata-only"),
    console_cmd("cat", (), "fs", "cat <file>", "Read a virtual substrate file.", "fs.read", "metadata-only"),
    console_cmd("tree", (), "fs", "tree [path]", "Show a virtual substrate tree.", "fs.read", "metadata-only"),
    console_cmd("echo", (), "fs", "echo <text>", "Print text in the console.", "none", "local"),
    console_cmd("mkdir", (), "fs", "mkdir <dir>", "Create a session-local virtual directory.", "fs.write", "local"),
    console_cmd("touch", (), "fs", "touch <file>", "Create or update a session-local virtual file.", "fs.write", "local"),
    console_cmd("rm", (), "fs", "rm <path>", "Remove a session-local virtual file or empty directory.", "fs.write", "local"),
    console_cmd("cp", (), "fs", "cp <src> <dst>", "Copy virtual file text into a session-local destination.", "fs.write", "local"),
    console_cmd("mv", (), "fs", "mv <src> <dst>", "Move a session-local virtual file or directory.", "fs.write", "local"),
    console_cmd("grep", (), "text", "grep <pattern> <file>...", "Search virtual file text.", "fs.read", "metadata-only"),
    console_cmd("wc", (), "text", "wc <file>...", "Count lines, words, and bytes in virtual files.", "fs.read", "metadata-only"),
    console_cmd("head", (), "text", "head [-n count] <file>", "Show first lines from a virtual file.", "fs.read", "metadata-only"),
    console_cmd("tail", (), "text", "tail [-n count] <file>", "Show last lines from a virtual file.", "fs.read", "metadata-only"),
    console_cmd("find", (), "text", "find [path] [-name text]", "Search virtual substrate paths.", "fs.read", "metadata-only"),
    console_cmd("pipeline", ("pipes",), "text", "pipeline", "Show supported text-command composition.", "none", "metadata-only"),
    console_cmd("wiki", ("quickref",), "text", "wiki [topic]", "Read local quick-reference topics without network access.", "fs.read", "metadata-only"),
    console_cmd("ps", (), "proc", "ps", "Show simulated substrate processes.", "proc.read", "metadata-only"),
    console_cmd("top", (), "proc", "top", "Show a compact simulated process summary.", "proc.read", "metadata-only"),
    console_cmd("jobs", (), "proc", "jobs", "List console-local background jobs.", "proc.read", "metadata-only"),
    console_cmd("spawn", (), "proc", "spawn <name>", "Create a simulated session-local process record.", "proc.spawn", "local"),
    console_cmd("fg", (), "proc", "fg <pid>", "Mark a simulated process foreground.", "proc.manage", "local"),
    console_cmd("bg", (), "proc", "bg <pid>", "Mark a simulated process background.", "proc.manage", "local"),
    console_cmd("kill", (), "proc", "kill <pid>", "Terminate a simulated process record.", "proc.kill", "local"),
    console_cmd("nice", (), "proc", "nice <pid> <priority>", "Set simulated process priority.", "proc.manage", "local"),
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
    console_cmd("doctor", ("health",), "sys", "doctor", "Run bounded NOXFRAME health checks without host mutation.", "sys.read", "metadata-only"),
    console_cmd("selftest", ("check",), "sys", "selftest", "Run internal command-surface invariants.", "sys.read", "metadata-only"),
    console_cmd("quality", ("scorecard",), "sys", "quality", "Show command-surface quality and guard coverage.", "sys.read", "metadata-only"),
    console_cmd("audit", (), "sys", "audit", "Show console audit events.", "sys.audit", "local"),
    console_cmd("opslog", (), "sys", "opslog [status|tail]", "Show local operator log status or tail.", "sys.audit", "local"),
    console_cmd("env", (), "user", "env", "Print console-local environment.", "user.read", "local"),
    console_cmd("set", (), "user", "set [KEY=value|-o]", "Inspect or set console-local environment options.", "user.env", "local"),
    console_cmd("export", (), "user", "export KEY=value", "Set a console-local environment value.", "user.env", "local"),
    console_cmd("unset", (), "user", "unset KEY", "Remove a console-local environment value.", "user.env", "local"),
    console_cmd("alias", (), "user", "alias [NAME=COMMAND]", "List or set console-local command aliases.", "user.env", "local"),
    console_cmd("unalias", (), "user", "unalias NAME", "Remove a console-local command alias.", "user.env", "local"),
    console_cmd("which", (), "user", "which <command>", "Show registry metadata for a command.", "user.read", "metadata-only"),
    console_cmd("profile", ("session",), "user", "profile", "Show the active NOXFRAME session profile.", "user.read", "metadata-only"),
    console_cmd("whoami", (), "user", "whoami", "Show the simulated operator identity.", "user.read", "metadata-only"),
    console_cmd("id", (), "user", "id", "Show simulated operator uid/gid.", "user.read", "metadata-only"),
    console_cmd("accounts", ("users",), "user", "accounts", "Show privacy-safe account model.", "user.read", "metadata-only"),
    console_cmd("history", (), "user", "history", "Show console command history.", "user.read", "local"),
    console_cmd("security", ("sec", "policy"), "user", "security", "Show NOXFRAME command-surface posture.", "user.read", "metadata-only"),
    console_cmd("theme", ("style",), "user", "theme [show|list]", "Inspect available console palettes.", "user.env", "metadata-only"),
    console_cmd("banner", ("splash",), "user", "banner", "Describe the active responsive boot banner.", "user.read", "metadata-only"),
    console_cmd("tips", ("hint", "hints"), "user", "tips", "Show concise operator tips.", "user.read", "metadata-only"),
    console_cmd("xframe-split", ("xsplit",), "user", "xframe-split <2|3|4>", "Split one NOXFRAME launch into up to four session-local xframes.", "user.frame", "local"),
    console_cmd("xframe-next", ("xnext", "xframe-cycle"), "user", "xframe-next", "Switch to the next open xframe; bound to Shift+Tab and F6 in interactive readline.", "user.frame", "local"),
    console_cmd("xframe-drop", ("xdrop",), "user", "xframe-drop <1|all>", "Drop the last xframe slot or collapse back to the original frame.", "user.frame", "local"),
    console_cmd("learn", ("memory", "notes"), "learn", "learn [status|list|show|add <text>|clear]", "Maintain session-local learning notes.", "learn.local", "local"),
    console_cmd("ifconfig", (), "net", "ifconfig", "Show virtual network interface policy.", "net.read", "metadata-only"),
    console_cmd("iwconfig", (), "net", "iwconfig", "Show virtual wireless policy.", "net.read", "metadata-only"),
    console_cmd("wifi-scan", (), "net", "wifi-scan", "Show deterministic no-scan Wi-Fi status.", "net.read", "metadata-only"),
    console_cmd("wifi-connect", (), "net", "wifi-connect <ssid>", "Record a denied virtual Wi-Fi connection decision.", "net.admin", "metadata-only"),
    console_cmd("ping", (), "net", "ping <host>", "Show a metadata-deny ping decision without sending packets.", "net.read", "metadata-only"),
    console_cmd("nmcli", (), "net", "nmcli", "Show virtual NetworkManager policy.", "net.read", "metadata-only"),
    console_cmd("browser", (), "host", "browser <url|about>", "Show browser route metadata without fetching URLs.", "host.net", "metadata-only"),
    console_cmd("git", (), "host", "git <args...>", "Show repository metadata without host git passthrough.", "host.exec", "metadata-only"),
    console_cmd("gh", ("github",), "host", "gh <args...>", "Show GitHub route metadata without host CLI passthrough.", "host.exec", "metadata-only"),
    console_cmd("cargo", (), "host", "cargo <args...>", "Show Cargo route metadata without executing cargo.", "host.exec", "metadata-only"),
    console_cmd("rustc", (), "host", "rustc <args...>", "Show Rust compiler route metadata without executing rustc.", "host.exec", "metadata-only"),
    console_cmd("python3", (), "host", "python3 <args...>", "Show Python route metadata without executing Python.", "host.exec", "metadata-only"),
    console_cmd("go", ("golang",), "host", "go <args...>", "Show Go route metadata without executing go.", "host.exec", "metadata-only"),
    console_cmd("python", ("py",), "host", "python <file.py>", "Show Python route metadata without executing Python.", "host.exec", "metadata-only"),
    console_cmd("gcc", ("cc",), "host", "gcc <file.c>", "Show C compiler route metadata without executing gcc.", "host.exec", "metadata-only"),
    console_cmd("plugins", ("plugin",), "plugin", "plugins [list|status|policy]", "Show metadata-only plugin catalog.", "plugin.read", "metadata-only"),
    console_cmd("wasm", ("wasi",), "plugin", "wasm [list|inspect|policy|run]", "Show WASI-lite plugin catalog while keeping execution unavailable.", "wasm.read", "metadata-only"),
    console_cmd("kaiju", ("wuci-kaiju",), "plugin", "kaiju [status|...|clean|boot [--boot-disk] [--allow-network] [--share-repo]]", "WUCI-KAIJU catalog + boot bridge (clean for fresh recording; supports nesting noxframe in guest Kali).", "kaiju.read", "metadata-only"),
    console_cmd("update", ("upgrade",), "host", "update [plan|protocol]", "Update route retained as read-only guidance.", "host.exec", "metadata-only"),
    console_cmd("codex", ("agent",), "dev", "codex [status|handoff|version|doctor|start|exec|resume]", "Use the opt-in Codex bridge pinned to this Wuci-Ji checkout.", "host.exec", "explicit-opt-in"),
    console_cmd("avim", ("vim", "edit"), "dev", "avim <file>", "Open a virtual read-only editor preview.", "fs.read", "metadata-only"),
    console_cmd("dev", ("dock", "selfdev"), "dev", "dev [status]", "Show self-development lane metadata.", "host.exec", "metadata-only"),
    console_cmd("repo", ("channels", "branches", "doctrine"), "dev", "repo [status]", "Show repository channel metadata.", "none", "metadata-only"),
    console_cmd("fyr", ("phase1lang", "forge"), "dev", "fyr [status]", "Show Fyr lineage metadata.", "none", "metadata-only"),
    console_cmd("base1", ("b1", "b2"), "dev", "base1 [status|b1|b2|dry-run]", "Show guarded Base1/B1/B2 workflow metadata.", "none", "metadata-only"),
    console_cmd("lang", ("language", "runlang"), "dev", "lang [support|security]", "Language runtime route retained as non-executing metadata.", "host.exec", "metadata-only"),
    console_cmd("lspci", (), "sys", "lspci", "Show virtual hardware anchors.", "hw.read", "metadata-only"),
    console_cmd("pcie", (), "sys", "pcie", "Show virtual PCIe model.", "hw.read", "metadata-only"),
    console_cmd("cr3", (), "sys", "cr3", "Show virtual CR3 value.", "hw.read", "metadata-only"),
    console_cmd("loadcr3", (), "sys", "loadcr3 <value>", "Set the session-local virtual CR3 value.", "hw.write", "local"),
    console_cmd("cr4", (), "sys", "cr4", "Show virtual CR4 flags.", "hw.read", "metadata-only"),
    console_cmd("pcide", (), "sys", "pcide on|off", "Set the session-local virtual PCIDE flag.", "hw.write", "local"),
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
    console_cmd("nest", ("nests",), "misc", "nest [status|list|enter|inspect|tree|memory|lock-policy|info]", "Show or move through metadata-only nested contexts.", "none", "metadata-only"),
    console_cmd("multi", ("batch", "script"), "misc", "multi <cmd> ; <cmd> ...", "Run multiple NOXFRAME commands from one console line.", "none", "local"),
    console_cmd("exit", ("quit", "shutdown", "poweroff"), "misc", "exit [all]", "Leave the current NOXFRAME level, or all levels with exit all.", "none", "open"),
)


@dataclass(frozen=True)
class Step:
    signal: str
    label: str
    command: tuple[str, ...]
    note: str
    requires_python_modules: tuple[str, ...] = ()


@dataclass(frozen=True)
class SelfReleaseLane:
    name: str
    label: str
    target: str
    make_args: tuple[str, ...]
    outputs: tuple[str, ...]


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


@dataclass(frozen=True)
class ConsoleCompletionPlan:
    matches: tuple[str, ...]
    append_space: bool


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


def console_depth(session: ConsoleSession) -> int:
    try:
        return max(0, int(session.env.get("NOXFRAME_DEPTH", "0")))
    except ValueError:
        return 0


def depth_theme(depth: int) -> ConsoleDepthTheme:
    return DEPTH_THEMES[max(0, depth) % len(DEPTH_THEMES)]


def sync_session_lattice(session: ConsoleSession) -> ConsoleDepthTheme:
    theme = depth_theme(console_depth(session))
    session.env["NOXFRAME_LATTICE"] = theme.name
    return theme


def set_session_depth(session: ConsoleSession, depth: int) -> None:
    session.env["NOXFRAME_DEPTH"] = str(max(0, depth))
    sync_session_lattice(session)


def depth_label(session: ConsoleSession) -> str:
    depth = console_depth(session)
    context = session.env.get("NOXFRAME_CONTEXT", "root")
    return f"L{depth}/{context}"


def display_pad(text: str, width: int) -> str:
    fitted = fit_display(text, width)
    return fitted + (" " * max(0, width - display_width(fitted)))


def xframe_layout_name(count: int) -> str:
    return {
        1: "single",
        2: "left-right",
        3: "top-two-bottom",
        4: "quadrant",
    }.get(count, "single")


def xframe_slot_label(count: int, frame_id: int) -> str:
    labels = {
        1: {1: "full"},
        2: {1: "left", 2: "right"},
        3: {1: "top-left", 2: "top-right", 3: "bottom"},
        4: {1: "top-left", 2: "top-right", 3: "bottom-left", 4: "bottom-right"},
    }
    return labels.get(count, labels[1]).get(frame_id, f"slot-{frame_id}")


def xframe_env_mark(env: dict[str, str], frame_id: int, count: int) -> None:
    env["NOXFRAME_XFRAME_ID"] = str(frame_id)
    env["NOXFRAME_XFRAME_COUNT"] = str(count)
    env["NOXFRAME_XFRAME_LAYOUT"] = xframe_layout_name(count)


def xframe_snapshot(session: ConsoleSession, frame_id: int) -> ConsoleXFrameState:
    env = dict(session.env)
    env["PWD"] = session.cwd
    xframe_env_mark(env, frame_id, session.xframe_count)
    return ConsoleXFrameState(
        frame_id=frame_id,
        cwd=session.cwd,
        started_monotonic=session.started_monotonic,
        history=list(session.history),
        audit=list(session.audit),
        aliases=dict(session.aliases),
        notes=list(session.notes),
        vfs_dirs=set(session.vfs_dirs),
        vfs_files=dict(session.vfs_files),
        jobs={pid: dict(job) for pid, job in session.jobs.items()},
        next_pid=session.next_pid,
        env=env,
    )


def xframe_new_state(frame_id: int, count: int, env_template: dict[str, str]) -> ConsoleXFrameState:
    env = dict(env_template)
    env["PWD"] = "/"
    xframe_env_mark(env, frame_id, count)
    return ConsoleXFrameState(frame_id=frame_id, env=env)


def xframe_apply_state(session: ConsoleSession, state: ConsoleXFrameState) -> None:
    session.cwd = state.cwd
    session.started_monotonic = state.started_monotonic
    session.history = list(state.history)
    session.audit = list(state.audit)
    session.aliases = dict(state.aliases)
    session.notes = list(state.notes)
    session.vfs_dirs = set(state.vfs_dirs)
    session.vfs_files = dict(state.vfs_files)
    session.jobs = {pid: dict(job) for pid, job in state.jobs.items()}
    session.next_pid = state.next_pid
    session.env = dict(state.env)
    session.env["PWD"] = session.cwd
    xframe_env_mark(session.env, session.active_xframe, session.xframe_count)


def xframe_save_active(session: ConsoleSession) -> None:
    session.active_xframe = max(1, min(session.active_xframe, max(1, session.xframe_count)))
    session.xframes[session.active_xframe] = xframe_snapshot(session, session.active_xframe)


def xframe_ensure_deck(session: ConsoleSession) -> None:
    session.xframe_count = max(1, min(XFRAME_MAX, session.xframe_count))
    session.active_xframe = max(1, min(session.active_xframe, session.xframe_count))
    if not session.xframes:
        session.xframes[session.active_xframe] = xframe_snapshot(session, session.active_xframe)
    for frame_id in range(1, session.xframe_count + 1):
        if frame_id not in session.xframes:
            session.xframes[frame_id] = xframe_new_state(frame_id, session.xframe_count, session.env)


def xframe_resize(session: ConsoleSession, count: int) -> list[int]:
    if not 1 <= count <= XFRAME_MAX:
        raise NoxframeError(f"xframe-split: frame count must be between 1 and {XFRAME_MAX}")
    xframe_ensure_deck(session)
    xframe_save_active(session)
    old_count = session.xframe_count
    env_template = dict(session.env)
    dropped = [frame_id for frame_id in range(count + 1, old_count + 1)]
    session.xframe_count = count
    for frame_id in range(1, count + 1):
        if frame_id not in session.xframes:
            session.xframes[frame_id] = xframe_new_state(frame_id, count, env_template)
        xframe_env_mark(session.xframes[frame_id].env, frame_id, count)
    for frame_id in dropped:
        session.xframes.pop(frame_id, None)
    if count == 1:
        session.active_xframe = 1
    elif session.active_xframe > count:
        session.active_xframe = count
    xframe_apply_state(session, session.xframes[session.active_xframe])
    return dropped


def xframe_switch(session: ConsoleSession, frame_id: int) -> None:
    xframe_ensure_deck(session)
    if not 1 <= frame_id <= session.xframe_count:
        raise NoxframeError(f"xframe: no open frame {frame_id}")
    xframe_save_active(session)
    session.active_xframe = frame_id
    xframe_apply_state(session, session.xframes[frame_id])


def xframe_next(session: ConsoleSession) -> None:
    target = 1 if session.active_xframe >= session.xframe_count else session.active_xframe + 1
    xframe_switch(session, target)


def xframe_drop(session: ConsoleSession, value: str) -> list[int]:
    xframe_ensure_deck(session)
    xframe_save_active(session)
    if value.lower() in {"all", "--all", "-a"}:
        target_count = 1
    else:
        try:
            drop_count = int(value, 10)
        except ValueError as exc:
            raise NoxframeError("xframe-drop: use a positive count or all") from exc
        if drop_count < 1:
            raise NoxframeError("xframe-drop: count must be positive")
        target_count = max(1, session.xframe_count - drop_count)
    return xframe_resize(session, target_count)


def xframe_state_depth(state: ConsoleXFrameState) -> int:
    try:
        return max(0, int(state.env.get("NOXFRAME_DEPTH", "0")))
    except ValueError:
        return 0


def xframe_box_lines(
    state: ConsoleXFrameState,
    *,
    active: bool,
    slot_label: str,
    width: int,
) -> list[str]:
    inner = max(10, width - 2)
    theme = depth_theme(xframe_state_depth(state))
    title = f"{'*' if active else ' '} xframe {state.frame_id} {slot_label}"
    return [
        "┌" + display_pad(title, inner) + "┐",
        "│" + display_pad(f"cwd={state.cwd}", inner) + "│",
        "│" + display_pad(f"hist={len(state.history)} jobs={len(state.jobs)} notes={len(state.notes)}", inner) + "│",
        "│" + display_pad(theme.name, inner) + "│",
        "└" + ("─" * inner) + "┘",
    ]


def xframe_join_boxes(left: list[str], right: list[str]) -> list[str]:
    return [f"{a}  {b}" for a, b in zip(left, right)]


def xframe_layout_lines(session: ConsoleSession) -> list[str]:
    xframe_save_active(session)
    width = max(42, terminal_columns() - 1)
    count = session.xframe_count
    gap = 2
    pair_width = max(24, min(42, (width - gap) // 2))
    wide_width = min(width, pair_width * 2 + gap)

    def box(frame_id: int, box_width: int) -> list[str]:
        state = session.xframes[frame_id]
        return xframe_box_lines(
            state,
            active=frame_id == session.active_xframe,
            slot_label=xframe_slot_label(count, frame_id),
            width=box_width,
        )

    if count == 1:
        return box(1, wide_width)
    if count == 2:
        return xframe_join_boxes(box(1, pair_width), box(2, pair_width))
    if count == 3:
        return [
            *xframe_join_boxes(box(1, pair_width), box(2, pair_width)),
            *box(3, wide_width),
        ]
    return [
        *xframe_join_boxes(box(1, pair_width), box(2, pair_width)),
        *xframe_join_boxes(box(3, pair_width), box(4, pair_width)),
    ]


def xframe_status_line(session: ConsoleSession) -> str:
    return (
        f"xframe: active={session.active_xframe}/{session.xframe_count} "
        f"layout={xframe_layout_name(session.xframe_count)} switch={XFRAME_SWITCH_HINT}"
    )


def xframe_status_text(
    session: ConsoleSession,
    *,
    action: str = "status",
    dropped: list[int] | None = None,
) -> str:
    xframe_save_active(session)
    rows = [
        "schema: wuci-noxframe-xframe-v1",
        f"action: {action}",
        f"frames: {session.xframe_count}",
        f"active: {session.active_xframe}",
        f"layout: {xframe_layout_name(session.xframe_count)}",
        f"switch: {XFRAME_SWITCH_HINT}",
    ]
    if dropped is not None:
        rows.append("dropped: " + (" ".join(str(frame_id) for frame_id in dropped) if dropped else "none"))
    rows.append("slots:")
    for frame_id in range(1, session.xframe_count + 1):
        state = session.xframes[frame_id]
        marker = "*" if frame_id == session.active_xframe else "-"
        rows.append(
            f"{marker} {frame_id}: {xframe_slot_label(session.xframe_count, frame_id)} "
            f"cwd={state.cwd} history={len(state.history)} jobs={len(state.jobs)}"
        )
    rows.append("")
    rows.extend(xframe_layout_lines(session))
    rows.append("")
    return "\n".join(rows)


def normalize_xframe_switch_input(raw: str) -> str:
    return "xframe-next" if raw in XFRAME_SWITCH_INPUTS else raw


def prompt_for_session(session: ConsoleSession) -> str:
    if session.xframe_count > 1:
        return f"noxframe:{depth_label(session)}[x{session.active_xframe}/{session.xframe_count}]> "
    return f"noxframe:{depth_label(session)}> "


def lattice_status_line(session: ConsoleSession) -> str:
    depth = console_depth(session)
    theme = sync_session_lattice(session)
    return f"substratisphere: depth={depth} lattice={theme.name} rail={theme.rail}"


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


def self_release_lanes() -> tuple[SelfReleaseLane, ...]:
    return (
        SelfReleaseLane(
            name="bundle",
            label="NOXFRAME self-release bundle",
            target="self-release-bundle",
            make_args=(
                f"SELF_RELEASE_DEMO_DIR={NOXFRAME_SELF_RELEASE_DEMO_DIR}",
                f"SELF_RELEASE_ATTESTATION={NOXFRAME_SELF_RELEASE_ATTESTATION}",
            ),
            outputs=(
                f"{NOXFRAME_SELF_RELEASE_DEMO_DIR}/wuci-ji.self.wj",
                NOXFRAME_SELF_RELEASE_ATTESTATION,
            ),
        ),
        SelfReleaseLane(
            name="witness",
            label="NOXFRAME self-release witness bundle",
            target="self-release-witness-bundle",
            make_args=(
                f"WITNESS_BUNDLE_DIR={NOXFRAME_WITNESS_BUNDLE_DIR}",
                f"WITNESS_WORK_DIR={NOXFRAME_WITNESS_WORK_DIR}",
            ),
            outputs=(
                f"{NOXFRAME_WITNESS_BUNDLE_DIR}/wuci-ji.self.wj",
                f"{NOXFRAME_WITNESS_BUNDLE_DIR}/publish-index.txt",
                f"{NOXFRAME_WITNESS_BUNDLE_DIR}/attestation.json",
            ),
        ),
        SelfReleaseLane(
            name="ledger",
            label="NOXFRAME self-release ledger bundle",
            target="self-release-ledger-bundle",
            make_args=(
                f"WITNESS_BUNDLE_DIR={NOXFRAME_WITNESS_BUNDLE_DIR}",
                f"WITNESS_WORK_DIR={NOXFRAME_WITNESS_WORK_DIR}",
                f"LEDGER_DIR={NOXFRAME_LEDGER_DIR}",
                f"LEDGER_INCLUSION_PROOF={NOXFRAME_LEDGER_INCLUSION_PROOF}",
                f"LEDGER_CONSISTENCY_PROOF={NOXFRAME_LEDGER_CONSISTENCY_PROOF}",
            ),
            outputs=(
                f"{NOXFRAME_LEDGER_DIR}/ledger-entry.txt",
                f"{NOXFRAME_LEDGER_DIR}/ledger-head.txt",
                NOXFRAME_LEDGER_INCLUSION_PROOF,
                NOXFRAME_LEDGER_CONSISTENCY_PROOF,
            ),
        ),
    )


def self_release_lane_map() -> dict[str, SelfReleaseLane]:
    return {lane.name: lane for lane in self_release_lanes()}


def self_release_lane_command(lane: SelfReleaseLane) -> tuple[str, ...]:
    return ("make", lane.target, *lane.make_args)


def self_release_lane_selection(value: str) -> tuple[SelfReleaseLane, ...] | None:
    lanes = self_release_lanes()
    if value == "all":
        return lanes
    lane = self_release_lane_map().get(value)
    if lane is None:
        return None
    return (lane,)


def path_state(root: Path, relative_path: str) -> str:
    path = repo_path(root, relative_path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"error:{exc.__class__.__name__}"
    if stat.S_ISLNK(info.st_mode):
        return "symlink-refused"
    if stat.S_ISDIR(info.st_mode):
        return "dir"
    if stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1:
            return "hardlink-refused"
        return f"file:{info.st_size}"
    return "unsupported"


def self_release_plan_text() -> str:
    rows = [
        "schema: wuci-noxframe-self-release-plan-v1",
        "scope: NOXFRAME-scoped Wuci-Ji self-release evidence",
        "execution: explicit run only; subprocess argv with shell=False",
        "non_claim: not a host shell, not OS runtime containment, not production authority",
        "",
        "lanes:",
    ]
    for lane in self_release_lanes():
        rows.append(f"- {lane.name}: {command_text(self_release_lane_command(lane))}")
    rows.extend(
        [
            "",
            "commands:",
            "  self-release plan",
            "  self-release status",
            "  self-release run bundle|witness|ledger|all",
            "  self-release shell",
            "",
        ]
    )
    return "\n".join(rows)


def self_release_status_text(root: Path) -> str:
    rows = [
        "schema: wuci-noxframe-self-release-status-v1",
        "scope: NOXFRAME-scoped Wuci-Ji self-release evidence",
        "root: build/noxframe",
        "",
    ]
    for lane in self_release_lanes():
        rows.append(f"[{lane.name}]")
        rows.append(f"target: {lane.target}")
        rows.append(f"command: {command_text(self_release_lane_command(lane))}")
        for output in lane.outputs:
            rows.append(f"{output}: {path_state(root, output)}")
        rows.append("")
    return "\n".join(rows)


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
    lowered = normalize_console_lookup_name(name)
    return next(
        (
            spec
            for spec in CONSOLE_COMMANDS
            if spec.name == lowered or lowered in spec.aliases
        ),
        None,
    )


def normalize_console_lookup_name(name: str) -> str:
    lowered = name.lower()
    marker_prefixes = (UNAVAILABLE_COMMAND_PREFIX, UNAVAILABLE_COMMAND_PREFIX[1:])
    for marker in marker_prefixes:
        if lowered.startswith(marker):
            candidate = lowered[len(marker) :]
            if any(
                command_is_unavailable(spec)
                and (spec.name == candidate or candidate in spec.aliases)
                for spec in CONSOLE_COMMANDS
            ):
                return candidate
    return lowered


def console_canonical_name(name: str) -> str | None:
    spec = console_lookup(name)
    return spec.name if spec else None


def console_command_names(category: str) -> str:
    return " ".join(
        command_display_name(spec) for spec in CONSOLE_COMMANDS if spec.category == category
    )


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
                rows.append(
                    f"{command_display_name(spec):<14} "
                    f"{command_display_usage(spec):<29} {spec.description}"
                )
        return "\n".join(rows)
    if topic:
        manual = console_man_text(topic)
        if manual is not None:
            return f"noxframe help // {topic}\n\n{manual}"
        return f"noxframe help // no match\n\nunknown topic: {topic}\ntry: help --compact"

    rows = [
        "noxframe help // operator console",
        "",
        *(f"{category:<9}: {console_command_names(category)}" for category in CONSOLE_CATEGORIES),
        "",
        "Phase1-compatible host, network, dev, and hardware routes are discoverable through help",
        "and capabilities. They resolve to bounded local or metadata-only handlers.",
        "Host passthrough and network execution are not enabled by default.",
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
    aliases = ", ".join(command_display_token(spec, alias) for alias in spec.aliases) if spec.aliases else "none"
    return "\n".join(
        [
            command_display_name(spec),
            "",
            f"usage      : {command_display_usage(spec)}",
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
            matches.append(command_display_name(spec))
        display_name = command_display_name(spec)
        slash_display_name = display_name.removeprefix("'")
        if display_name.startswith(lowered) or (
            command_is_unavailable(spec) and slash_display_name.startswith(lowered)
        ):
            matches.append(display_name)
        for alias in spec.aliases:
            if alias.startswith(lowered):
                matches.append(command_display_token(spec, alias))
            display_alias = command_display_token(spec, alias)
            slash_display_alias = display_alias.removeprefix("'")
            if display_alias.startswith(lowered) or (
                command_is_unavailable(spec) and slash_display_alias.startswith(lowered)
            ):
                matches.append(display_alias)
    return sorted(set(matches))


def console_capabilities_text() -> str:
    rows = ["noxframe capabilities", "", "command        category   capability       guard"]
    for spec in CONSOLE_COMMANDS:
        rows.append(
            f"{command_display_name(spec):<14} {spec.category:<10} "
            f"{spec.capability:<16} {spec.guard}"
        )
    return "\n".join(rows)


def valid_env_key(key: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key) is not None


def parse_assignment(tokens: list[str]) -> tuple[str, str] | None:
    if not tokens:
        return None
    text = " ".join(tokens)
    if "=" not in text:
        return None
    key, value = text.split("=", 1)
    if not valid_env_key(key):
        return None
    return key, value


def set_session_env(session: ConsoleSession, key: str, value: str) -> None:
    session.env[key] = value
    if key == "PWD":
        normalized = vfs_normalize("/", value)
        if vfs_is_dir(normalized, session):
            session.cwd = normalized


def sync_session_env(session: ConsoleSession, args: argparse.Namespace) -> None:
    session.env["PWD"] = session.cwd
    session.env["NOXFRAME_PROFILE"] = getattr(args, "profile", "auto")
    sync_session_lattice(session)


def console_env_text(session: ConsoleSession) -> str:
    return "\n".join(f"{key}={session.env[key]}" for key in sorted(session.env)) + "\n"


def console_option_text() -> str:
    rows = [
        "set -o no_host_passthrough=on",
        "set -o shell_exec=off",
        "set -o network_routes=metadata-deny",
        "set -o runtime_containment_claim=off",
        "set -o quantum_safe_claim=off",
        "set -o alias_expansion=session-local",
    ]
    return "\n".join(rows) + "\n"


def built_in_alias_rows() -> list[str]:
    rows: list[str] = []
    for spec in CONSOLE_COMMANDS:
        for alias in spec.aliases:
            rows.append(f"{command_display_token(spec, alias)} -> {command_display_name(spec)}")
    return sorted(rows)


def console_alias_text(session: ConsoleSession) -> str:
    rows = ["session aliases:"]
    if session.aliases:
        rows.extend(f"{name}='{value}'" for name, value in sorted(session.aliases.items()))
    else:
        rows.append("(none)")
    rows.extend(["", "built-in aliases:"])
    rows.extend(built_in_alias_rows() or ["(none)"])
    return "\n".join(rows) + "\n"


def valid_alias_name(name: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", name) is not None


def set_session_alias(session: ConsoleSession, assignment: str) -> str | None:
    if "=" not in assignment:
        return "usage: alias NAME=COMMAND"
    name, target = assignment.split("=", 1)
    target = target.strip()
    if not valid_alias_name(name):
        return "alias: invalid name"
    if console_lookup(name) is not None:
        return "alias: refusing to shadow registry command"
    if not target:
        return "alias: empty target"
    try:
        target_parts = shlex.split(normalize_console_input_markers(target))
    except ValueError as exc:
        return f"alias: parse error: {exc}"
    if not target_parts:
        return "alias: empty target"
    if console_lookup(target_parts[0]) is None:
        return "alias: target must start with a known NOXFRAME command"
    session.aliases[name] = target
    return None


def expand_session_alias(session: ConsoleSession, parts: list[str]) -> list[str]:
    target = session.aliases.get(parts[0])
    if target is None:
        return parts
    try:
        target_parts = shlex.split(normalize_console_input_markers(target))
    except ValueError:
        return parts
    if not target_parts:
        return parts
    return [*target_parts, *parts[1:]]


def command_which_text(name: str) -> str:
    spec = console_lookup(name)
    if spec is None:
        return f"which: no NOXFRAME command named {name}\n"
    aliases = ", ".join(command_display_token(spec, alias) for alias in spec.aliases) if spec.aliases else "none"
    return "\n".join(
        [
            f"which: {command_display_name(spec)}",
            f"canonical: {spec.name}",
            f"usage: {command_display_usage(spec)}",
            f"category: {spec.category}",
            f"aliases: {aliases}",
            f"capability: {spec.capability}",
            f"guard: {spec.guard}",
            "",
        ]
    )


def console_profile_text(session: ConsoleSession, args: argparse.Namespace) -> str:
    sync_session_env(session, args)
    return "\n".join(
        [
            "schema: wuci-noxframe-session-profile-v1",
            f"user: {session.env.get('USER', 'operator')}",
            f"cwd: {session.cwd}",
            f"profile: {session.env.get('NOXFRAME_PROFILE', 'auto')}",
            f"route: {session.env.get('NOXFRAME_ROUTE', 'root>wuci-ji>daylight')}",
            f"mode: {session.env.get('NOXFRAME_MODE', 'metadata-console')}",
            f"depth: {console_depth(session)}",
            f"lattice: {session.env.get('NOXFRAME_LATTICE', depth_theme(0).name)}",
            f"env: {len(session.env)} variable(s)",
            f"aliases: {len(session.aliases)} session-local alias(es)",
            f"notes: {len(session.notes)} session-local note(s)",
            f"history: {len(session.history)} command(s)",
            f"audit: {len(session.audit)} event(s)",
            f"xframes: active={session.active_xframe}/{session.xframe_count} layout={xframe_layout_name(session.xframe_count)}",
            "boundary: metadata console; no host shell or runtime-containment claim",
            "",
        ]
    )


def phase_feature_text() -> str:
    rows = ["schema: wuci-noxframe-phase1-feature-map-v1", "features:"]
    rows.extend(f"- {name}: {description}" for name, description in PHASE1_FEATURES)
    rows.extend(
        [
            "",
            "boundary: Phase1 ideas are mapped into WUCI-native metadata surfaces; no Phase1 code is imported.",
            "",
        ]
    )
    return "\n".join(rows)


def phase_text(session: ConsoleSession, args: argparse.Namespace, action: str) -> str:
    sync_session_env(session, args)
    route = session.env.get("NOXFRAME_ROUTE", "root>wuci-ji>daylight")
    context = session.env.get("NOXFRAME_CONTEXT", "root")
    depth = console_depth(session)
    theme = sync_session_lattice(session)
    if action in {"whereami", "status"}:
        return "\n".join(
            [
                "schema: wuci-noxframe-phase-whereami-v1",
                f"context: {context}",
                f"cwd: {session.cwd}",
                f"route: {route}",
                f"profile: {session.env.get('NOXFRAME_PROFILE', 'auto')}",
                f"substratisphere_depth: {depth}",
                f"lattice: {theme.name}",
                "mode: metadata-only Optics rail",
                "",
            ]
        )
    if action == "path":
        return "\n".join(
            [
                "schema: wuci-noxframe-phase-path-v1",
                *(f"{index}: {cell_id}" for index, cell_id in enumerate(route.split(">"), start=1)),
                "",
            ]
        )
    if action == "map":
        rows = ["schema: wuci-noxframe-phase-map-v1"]
        for cell_id, role, actions in SUBSTRATE_CELLS:
            marker = "*" if cell_id == context else "-"
            rows.append(f"{marker} {cell_id:<10} {role} actions={','.join(actions)}")
        rows.append("")
        return "\n".join(rows)
    if action in {"features", "feature", "capabilities"}:
        return phase_feature_text()
    if action in {"help", "compass", "optics"}:
        return "\n".join(
            [
                "schema: wuci-noxframe-phase-compass-v1",
                "commands: phase whereami | phase path | phase map | phase features",
                "aliases: whereami, compass, optics",
                "rails: terminal, vfs, proc, optics, nest, learn, plugin, quality",
                f"substratisphere_depth: {depth}",
                f"lattice: {theme.name} {theme.rail}",
                "non_claim: not a kernel, not host shell, not runtime containment",
                "",
            ]
        )
    return "usage: phase [whereami|compass|path|map|features|help]\n"


def learn_status_text(session: ConsoleSession) -> str:
    return "\n".join(
        [
            "schema: wuci-noxframe-learn-status-v1",
            "scope: session-local operator notes",
            f"notes: {len(session.notes)}",
            "persistence: none",
            "network: unused",
            "",
        ]
    )


def learn_notes_text(session: ConsoleSession) -> str:
    if not session.notes:
        return "learn: no session notes\n"
    return "\n".join(f"{index}. {note}" for index, note in enumerate(session.notes, start=1)) + "\n"


def context_ids() -> tuple[str, ...]:
    return tuple(cell_id for cell_id, _, _ in SUBSTRATE_CELLS)


def context_record(context: str) -> tuple[str, str, tuple[str, ...]] | None:
    for cell in SUBSTRATE_CELLS:
        if cell[0] == context:
            return cell
    return None


def substrate_memory_path(context: str, depth: int) -> str:
    return f"{DEFAULT_SUBSTRATE_MEMORY_ROOT}/depth-{depth:02d}/{context}/memory.wj"


def substrate_memory_manifest_path(context: str, depth: int) -> str:
    return f"{DEFAULT_SUBSTRATE_MEMORY_ROOT}/depth-{depth:02d}/{context}/manifest.json"


def substrate_lock_policy() -> dict[str, object]:
    return {
        "schema": SUBSTRATE_LOCK_POLICY_SCHEMA,
        "default_lock_from_depth": DEFAULT_SUBSTRATE_LOCK_DEPTH,
        "warning_required_before_lock": True,
        "lock_gate": {
            "mode": "operator-keyfile-or-reviewed-password-gate",
            "password_storage": "plaintext password must never be stored",
            "recovery": "unavailable by design; destroy the locked substrate depth and recreate it",
            "destroy_scope": "the locked depth and descendants, not unrelated substrate depths",
        },
        "non_claims": [
            "not host-proof isolation",
            "not runtime containment",
            "not quantum-safe unless a real pinned PQ verifier lane is added",
        ],
    }


def substrate_memory_contract(active_context: str = "root", depth: int = 0) -> dict[str, object]:
    if context_record(active_context) is None:
        active_context = "root"
    depth = max(0, depth)
    contexts = []
    for cell_id, role, actions in SUBSTRATE_CELLS:
        record = {
            "context": cell_id,
            "role": role,
            "depth": depth,
            "store_path": substrate_memory_path(cell_id, depth),
            "manifest_path": substrate_memory_manifest_path(cell_id, depth),
            "allowed_actions": list(actions),
            "envelope": "WJSEAL-v2 via NOXFRAME daylight-wrap",
        }
        record["digest_vector"] = digest_vector_json(record)
        contexts.append(record)
    return {
        "schema": SUBSTRATE_MEMORY_SCHEMA,
        "active_context": active_context,
        "active_depth": depth,
        "memory_root": DEFAULT_SUBSTRATE_MEMORY_ROOT,
        "store_template": f"{DEFAULT_SUBSTRATE_MEMORY_ROOT}/depth-{{depth:02d}}/{{context}}/memory.wj",
        "manifest_template": f"{DEFAULT_SUBSTRATE_MEMORY_ROOT}/depth-{{depth:02d}}/{{context}}/manifest.json",
        "active_store_path": substrate_memory_path(active_context, depth),
        "active_manifest_path": substrate_memory_manifest_path(active_context, depth),
        "persistence": {
            "mechanism": "sealed local artifacts bound by Daylight/WJSEAL evidence",
            "plain_session_memory": "session-local only until explicitly sealed",
            "reboot_behavior": "re-entering a depth points at the same sealed memory path",
        },
        "lock_policy": substrate_lock_policy(),
        "network_policy": {
            "default": "metadata-deny in the console registry",
            "future_bridge": "must be explicit opt-in, allowlisted, transcripted, and non-scanning by default",
        },
        "host_boundary": {
            "protects": "at-rest confidentiality/integrity only after a real sealed artifact is written",
            "does_not_protect": "a running substrate from a compromised host kernel, root account, debugger, or disk deletion",
            "required_for_host_compromise_resistance": "separate host, VM/hypervisor boundary, kernel sandbox, TEE, or hardware-backed key release",
        },
        "contexts": contexts,
        "non_claims": list(NON_CLAIMS),
    }


def substrate_memory_text(session: ConsoleSession) -> str:
    context = session.env.get("NOXFRAME_CONTEXT", "root")
    depth = console_depth(session)
    memory = substrate_memory_contract(context, depth)
    lock_policy = memory["lock_policy"]
    assert isinstance(lock_policy, dict)
    return "\n".join(
        [
            f"schema: {memory['schema']}",
            f"active_context: {memory['active_context']}",
            f"active_depth: {memory['active_depth']}",
            f"memory_root: {memory['memory_root']}",
            f"active_store: {memory['active_store_path']}",
            f"active_manifest: {memory['active_manifest_path']}",
            f"default_lock_from_depth: {lock_policy['default_lock_from_depth']}",
            "envelope: WJSEAL-v2 via NOXFRAME daylight-wrap",
            "recovery: password/key loss requires destroying that locked depth and descendants",
            "host_boundary: encrypted-at-rest policy only; not host-compromise containment",
            "network: default metadata-deny; explicit future bridge must be allowlisted and transcripted",
            "",
        ]
    )


def substrate_lock_policy_text() -> str:
    policy = substrate_lock_policy()
    gate = policy["lock_gate"]
    assert isinstance(gate, dict)
    return "\n".join(
        [
            f"schema: {policy['schema']}",
            f"default_lock_from_depth: {policy['default_lock_from_depth']}",
            f"warning_required_before_lock: {policy['warning_required_before_lock']}",
            f"mode: {gate['mode']}",
            f"password_storage: {gate['password_storage']}",
            f"recovery: {gate['recovery']}",
            f"destroy_scope: {gate['destroy_scope']}",
            "non_claim: not host-proof isolation",
            "",
        ]
    )


def nest_status_text(session: ConsoleSession) -> str:
    context = session.env.get("NOXFRAME_CONTEXT", "root")
    depth = console_depth(session)
    theme = sync_session_lattice(session)
    return "\n".join(
        [
            "schema: wuci-noxframe-nest-status-v1",
            f"active: {context}",
            f"cwd: {session.cwd}",
            f"substratisphere_depth: {depth}",
            f"lattice: {theme.name}",
            f"memory_store: {substrate_memory_path(context, depth)}",
            "mode: single-session metadata nesting",
            "commands: nest list | nest enter <context> | nest inspect <context> | nest tree | nest memory | nest lock-policy",
            "mutation: spawn/destroy remain blocked for fixed metadata cells",
            "",
        ]
    )


def nest_list_text() -> str:
    return "\n".join(context_ids()) + "\n"


def nest_inspect_text(context: str) -> str:
    cell = context_record(context)
    if cell is None:
        return f"nest: unknown context: {context}\n"
    cell_id, role, actions = cell
    return "\n".join(
        [
            f"context: {cell_id}",
            f"role: {role}",
            f"actions: {','.join(actions)}",
            "host_effect: metadata-only",
            "",
        ]
    )


def nest_tree_text(session: ConsoleSession | None = None) -> str:
    depth = console_depth(session) if session is not None else 0
    rows = ["root"]
    for cell_id in context_ids():
        rows.append(f"  {cell_id}/ memory={substrate_memory_path(cell_id, depth)}")
    return "\n".join(rows) + "\n"


def plugin_catalog_text() -> str:
    rows = ["schema: wuci-noxframe-plugin-catalog-v1", "plugins:"]
    rows.extend(f"- {name}: {purpose}; guard={guard}" for name, purpose, guard in PLUGIN_CATALOG)
    rows.extend(
        [
            "",
            "execution: unavailable through the console except explicit Codex bridge with --allow-codex",
            "network: unused",
            "",
        ]
    )
    return "\n".join(rows)


def plugin_policy_text() -> str:
    return "\n".join(
        [
            "schema: wuci-noxframe-plugin-policy-v1",
            "host_shell: disabled",
            "wasm_run: unavailable",
            "network_fetch: unavailable",
            "codex_launch: explicit --allow-codex only",
            "writes: session metadata or existing proof-lane artifacts only",
            "",
        ]
    )


def kaiju_catalog(root: Path) -> dict[str, object]:
    try:
        return wuci_kaiju.load_manifest(wuci_kaiju.default_manifest_path(root))
    except wuci_kaiju.KaijuError as exc:
        raise NoxframeError(str(exc)) from exc


def kaiju_verify_text(root: Path) -> str:
    try:
        result = wuci_kaiju.verify_manifest(wuci_kaiju.default_manifest_path(root))
    except wuci_kaiju.KaijuError as exc:
        raise NoxframeError(str(exc)) from exc
    rows = [
        "schema: wuci-kaiju-verification-v1",
        f"status: {result['status']}",
        f"manifest: {display_repo_path(root, Path(str(result['manifest'])))}",
        f"purposes: {result['purpose_count']}",
        f"selected_tools: {result['selected_tool_count']}",
    ]
    problems = result.get("problems", [])
    if isinstance(problems, list) and problems:
        rows.extend(f"problem: {problem}" for problem in problems)
    rows.append("")
    return "\n".join(rows)


def kaiju_iso_root(root: Path, args: argparse.Namespace) -> Path:
    return repo_path(root, getattr(args, "kaiju_iso_root", str(wuci_kaiju.DEFAULT_ISO_ROOT)))


def kaiju_disk_root(root: Path, args: argparse.Namespace) -> Path:
    return repo_path(root, getattr(args, "kaiju_disk_root", str(wuci_kaiju.DEFAULT_DISK_ROOT)))


def has_console_flag(parts: list[str], flag: str) -> bool:
    return flag in parts


def console_option_value(parts: list[str], option: str) -> str | None:
    if option not in parts:
        return None
    index = parts.index(option)
    if index + 1 >= len(parts):
        raise NoxframeError(f"{option} requires a value")
    return parts[index + 1]


def console_int_option(parts: list[str], option: str, default: int) -> int:
    value = console_option_value(parts, option)
    if value is None:
        return default
    try:
        return int(value, 10)
    except ValueError as exc:
        raise NoxframeError(f"{option} must be an integer") from exc


def kaiju_boot_plan_text(root: Path, args: argparse.Namespace, parts: list[str]) -> str:
    plan = wuci_kaiju.boot_plan(
        iso_root=kaiju_iso_root(root, args),
        disk_root=kaiju_disk_root(root, args),
        qemu_bin=getattr(args, "kaiju_qemu_bin", wuci_kaiju.DEFAULT_QEMU_BIN),
        memory_mib=console_int_option(parts, "--memory-mib", wuci_kaiju.DEFAULT_MEMORY_MIB),
        cpus=console_int_option(parts, "--cpus", wuci_kaiju.DEFAULT_CPUS),
        network=has_console_flag(parts, "--allow-network"),
        boot_disk=has_console_flag(parts, "--boot-disk") or has_console_flag(parts, "--from-disk"),
        share_repo=root if (has_console_flag(parts, "--share-repo") or has_console_flag(parts, "--allow-share")) else None,
    )
    return json.dumps(plan, indent=2, sort_keys=True) + "\n"


def handle_kaiju_iso_command(root: Path, args: argparse.Namespace, parts: list[str]) -> None:
    action = parts[2].lower() if len(parts) > 2 else "status"
    iso_root = kaiju_iso_root(root, args)
    if action == "status":
        print(wuci_kaiju.iso_status_text(iso_root), end="")
        return
    if action == "verify":
        result = wuci_kaiju.verify_iso_install(iso_root)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if action == "install":
        if len(parts) < 4:
            print("usage: kaiju iso install <local-iso> [--name kali.iso] [--force]")
            return
        source = Path(parts[3])
        name = console_option_value(parts, "--name")
        force = has_console_flag(parts, "--force")
        manifest = wuci_kaiju.install_iso(source, iso_root=iso_root, name=name, force=force)
        print(f"kaiju iso: installed {manifest['image_path']}")
        print(f"bytes: {manifest['image_bytes']}")
        print(f"sha256: {manifest['digest_vector']['sha256']}")
        return
    print("usage: kaiju iso [status|verify|install <local-iso>]")


def handle_kaiju_disk_command(root: Path, args: argparse.Namespace, parts: list[str]) -> None:
    action = parts[2].lower() if len(parts) > 2 else "status"
    disk_root = kaiju_disk_root(root, args)
    if action == "status":
        print(wuci_kaiju.disk_status_text(disk_root), end="")
        return
    if action == "verify":
        result = wuci_kaiju.verify_disk(disk_root)
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if action == "create":
        size_mib = console_int_option(parts, "--size-mib", 32768)
        name = console_option_value(parts, "--name") or "kali.raw"
        manifest = wuci_kaiju.create_disk(
            disk_root=disk_root,
            size_mib=size_mib,
            name=name,
            force=has_console_flag(parts, "--force"),
        )
        print(f"kaiju disk: created {manifest['disk_path']}")
        print(f"size-mib: {manifest['size_mib']}")
        return
    print("usage: kaiju disk [status|verify|create --size-mib N]")


def handle_kaiju_boot_command(root: Path, args: argparse.Namespace, parts: list[str]) -> None:
    try:
        plan_text = kaiju_boot_plan_text(root, args, parts)
    except wuci_kaiju.KaijuError as exc:
        raise NoxframeError(str(exc)) from exc
    if has_console_flag(parts, "--dry-run") or has_console_flag(parts, "--json"):
        print(plan_text, end="")
        return
    if not getattr(args, "allow_kaiju_boot", False):
        print("kaiju boot: bridge disabled")
        print("restart NOXFRAME with --allow-kaiju-boot to launch non-graphical QEMU")
        print("use: kaiju boot --dry-run")
        return
    plan = json.loads(plan_text)
    disc = plan.get("qemu_discovered")
    if not disc or disc == "not found on PATH":
        print(f"kaiju boot: QEMU executable not found: {getattr(args, 'kaiju_qemu_bin', wuci_kaiju.DEFAULT_QEMU_BIN)}")
        print(wuci_kaiju.QEMU_INSTALL_HINT)
        return
    if plan.get("status") != "ready":
        print(f"kaiju boot: boot plan {plan.get('status')}")
        if plan.get("share_problem"):
            print("problem: " + str(plan["share_problem"]))
        for problem in plan.get("installed_boot", {}).get("problems", []):
            print("problem: " + str(problem))
        return
    try:
        argv = wuci_kaiju.build_live_boot_argv(plan)
    except Exception as exc:
        print(f"kaiju boot: live argv error: {exc}")
        return
    print("kaiju boot: launching non-graphical QEMU")
    print("network: " + str(plan.get("network", "none")))
    print("graphics: none")
    print("boot_disk: " + str(plan.get("boot_disk", False)))
    print("launch_mode: " + str(plan.get("launch_mode", "cdrom")))
    if plan.get("share"):
        print("share_repo: " + str(plan.get("share_path")))
        print("guest: " + str(plan.get("guest_mount_hint")))
    print("argv: " + shlex.join(str(part) for part in argv))
    if plan.get("boot_disk"):
        print("note: this boots installed Kali by direct kernel/initrd serial path; GRUB is bypassed.")
    if plan.get("share"):
        print("note: inside the guest you can access the outer tree and start another noxframe: cd /mnt/wuci && python3 tools/wuci-noxframe")
    print("      (use Ctrl-a x to exit qemu from serial; git clone works if --allow-network was given)")

    # Full terminal takeover for smooth operation:
    # - Use alternate screen buffer so the QEMU serial session (Kali) occupies the
    #   entire real terminal (no "tiny box" inside noxframe lattice/xframes).
    # - Save/restore termios attributes so QEMU's raw mode / monitor keys / size
    #   changes don't leave graphical glitches (bad echo, colors, cursor, input)
    #   when we return to the noxframe console.
    # - Reset attributes + cursor on exit for a clean hand-back.
    is_tty = sys.stdout.isatty() and sys.stdin.isatty()
    old_attrs = None
    fd = None
    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")
    if is_tty:
        fd = sys.stdin.fileno()
        try:
            old_attrs = termios.tcgetattr(fd)
        except (OSError, termios.error):
            old_attrs = None
        # Enter alt screen + clear + hide cursor
        sys.stdout.write("\033[?1049h\033[H\033[2J\033[?25l")
        sys.stdout.flush()

        # Explicitly set the real terminal size via ioctl so the guest (Kali
        # serial console / installer TUI) starts with full correct dimensions.
        # This helps avoid graphical glitches from wrong winsize.
        try:
            size = shutil.get_terminal_size(fallback=(80, 24))
            rows, cols = size.lines, size.columns
            winsz = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)
        except Exception:
            pass

    try:
        result = subprocess.run([str(part) for part in argv], cwd=root, check=False, shell=False, env=env)
    finally:
        if is_tty:
            # Pop alt screen, show cursor, reset SGR colors/attrs
            sys.stdout.write("\033[?1049l\033[?25h\033[0m")
            sys.stdout.flush()
            if old_attrs is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
                except (OSError, termios.error):
                    pass
            # Extra line reset to eat any leftover sequences or partial lines
            sys.stdout.write("\033[0m\r\n")
            sys.stdout.flush()
        # Always force full sane reset on exit from the guest. This ensures
        # the noxframe console (lattice, prompts, input) returns without
        # graphical glitches. The initial boot splash is protected because
        # reset_terminal_to_sane() is called at noxframe startup.
        reset_terminal_to_sane()

    print(f"kaiju-boot-result: {result.returncode}")
    try:
        wuci_kaiju._cleanup_boot_artifacts(plan.get("iso", {}).get("image_path", ""))
        wuci_kaiju._cleanup_installed_boot_artifacts(plan.get("disk", {}).get("disk_root", wuci_kaiju.default_disk_root(root)))
    except Exception:
        pass

    # Note: we intentionally do *not* force a clear or re-draw of the noxframe
    # chrome / lattice / header here. The alt-screen restore + termios restore
    # should pop back to the exact previous display state. Explicit redraws
    # were messing with the intended boot splash / console aesthetics.


def handle_kaiju_command(root: Path, args: argparse.Namespace, parts: list[str]) -> None:
    action = parts[1].lower() if len(parts) > 1 else "status"
    if action in {"run", "exec", "scan"}:
        print(f"kaiju {action}: unavailable in NOXFRAME")
        print("scope: WUCI-KAIJU is a read-only Kali purpose catalog")
        return
    if action == "iso":
        handle_kaiju_iso_command(root, args, parts)
        return
    if action == "disk":
        handle_kaiju_disk_command(root, args, parts)
        return
    if action == "clean":
        res = wuci_kaiju.clean(
            iso_root=kaiju_iso_root(root, args),
            disk_root=kaiju_disk_root(root, args),
        )
        print("kaiju clean:", res.get("status", "done"))
        for p in res.get("removed", []):
            print("  removed:", p)
        return
    if action == "boot":
        handle_kaiju_boot_command(root, args, parts)
        return
    manifest = None if action == "verify" else kaiju_catalog(root)
    if action == "status":
        assert manifest is not None
        print(wuci_kaiju.manifest_status_text(manifest), end="")
        return
    if action in {"list", "ls"}:
        assert manifest is not None
        print(wuci_kaiju.manifest_list_text(manifest), end="")
        return
    if action == "purpose":
        if len(parts) < 3:
            print("usage: kaiju purpose <purpose-id>")
            return
        assert manifest is not None
        print(wuci_kaiju.manifest_list_text(manifest, parts[2]), end="")
        return
    if action == "policy":
        assert manifest is not None
        print(wuci_kaiju.manifest_policy_text(manifest), end="")
        return
    if action == "verify":
        print(kaiju_verify_text(root), end="")
        return
    if action == "manifest":
        assert manifest is not None
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return
    print("usage: kaiju [status|list|...|iso|disk|clean|boot]")
    print("  kaiju clean   : wipe iso/disk state for clean from-scratch flow (good for recordings)")
    print("  boot options: --dry-run | --boot-disk | --allow-network | --share-repo")


def wiki_text(topic: str | None) -> str:
    if not topic:
        return "wiki topics: " + " ".join(sorted(WIKI_TOPICS)) + "\n"
    key = topic.lower()
    value = WIKI_TOPICS.get(key)
    if value is None:
        return f"wiki: no local topic named {topic}\n"
    return f"{key}: {value}\n"


def guard_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in CONSOLE_COMMANDS:
        counts[spec.guard] = counts.get(spec.guard, 0) + 1
    return counts


def quality_text() -> str:
    counts = guard_counts()
    return "\n".join(
        [
            "schema: wuci-noxframe-quality-scorecard-v1",
            f"commands: {len(CONSOLE_COMMANDS)}",
            f"categories: {len(CONSOLE_CATEGORIES)}",
            f"local: {counts.get('local', 0)}",
            f"metadata-only: {counts.get('metadata-only', 0)}",
            f"explicit-opt-in: {counts.get('explicit-opt-in', 0)}",
            f"unavailable: {counts.get('unavailable', 0)}",
            f"public-anchors: {len(ANCHOR_PATHS)}",
            "claims: conservative",
            "",
        ]
    )


def selftest_text(session: ConsoleSession) -> str:
    names = [spec.name for spec in CONSOLE_COMMANDS]
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    missing_categories = sorted({spec.category for spec in CONSOLE_COMMANDS} - set(CONSOLE_CATEGORIES))
    unavailable_without_marker = [
        spec.name
        for spec in CONSOLE_COMMANDS
        if spec.guard == "unavailable" and not command_display_name(spec).startswith(UNAVAILABLE_COMMAND_PREFIX)
    ]
    status = "pass" if not duplicate_names and not missing_categories and not unavailable_without_marker else "fail"
    return "\n".join(
        [
            "schema: wuci-noxframe-selftest-v1",
            f"status: {status}",
            f"commands: {len(CONSOLE_COMMANDS)}",
            f"history: {len(session.history)}",
            f"duplicates: {','.join(duplicate_names) if duplicate_names else 'none'}",
            f"missing_categories: {','.join(missing_categories) if missing_categories else 'none'}",
            f"marker_errors: {','.join(unavailable_without_marker) if unavailable_without_marker else 'none'}",
            "",
        ]
    )


def doctor_text(root: Path, args: argparse.Namespace, session: ConsoleSession) -> str:
    state_path, seal_path = substrate_paths(root, args)
    ok, problems = verify_substrate_seal(root, state_path=state_path, seal_path=seal_path)
    return "\n".join(
        [
            "schema: wuci-noxframe-doctor-v1",
            f"substrate: {'sealed' if ok else 'needs-seal'}",
            f"state: {display_repo_path(root, state_path)}",
            f"seal: {display_repo_path(root, seal_path)}",
            f"commands: {len(CONSOLE_COMMANDS)}",
            f"notes: {len(session.notes)}",
            f"problems: {len(problems)}",
            *(f"problem: {problem}" for problem in problems),
            "boundary: no host shell, metadata-deny network route, no runtime-containment claim",
            "",
        ]
    )


def base1_text(action: str) -> str:
    if action in {"b1", "b2", "dry-run"}:
        return "\n".join(
            [
                "schema: wuci-noxframe-base1-dry-run-v1",
                f"lane: {action}",
                "status: report-only",
                "host_exec: unavailable",
                "assembly_preview: existing Wuci-Ji proof lanes only",
                "boundary: no generated host commands are executed inside NOXFRAME",
                "",
            ]
        )
    return "\n".join(
        [
            "schema: wuci-noxframe-base1-status-v1",
            "b1: metadata-only",
            "b2: metadata-only",
            "dry_run: available",
            "execution: unavailable inside the console",
            "",
        ]
    )


def normalize_console_input_markers(raw: str) -> str:
    return re.sub(r"(^|\s)'/", r"\1/", raw)


def split_console_multicommands(raw: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == ";":
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            continue
        current.append(char)

    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments


def completion_context(line: str, cursor: int) -> tuple[list[str], str]:
    before = line[:cursor]
    starts_new_token = not before or before[-1].isspace()
    words = before.split()
    if starts_new_token:
        return words, ""
    if not words:
        return [], before
    return words[:-1], words[-1]


def completion_plan(matches: list[str], *, append_space: bool = True) -> ConsoleCompletionPlan:
    ordered = tuple(sorted(set(matches)))
    should_append = append_space and len(ordered) == 1 and not ordered[0].endswith("/")
    return ConsoleCompletionPlan(ordered, should_append)


def completion_choice_matches(choice: str, token: str) -> bool:
    if choice.startswith(token):
        return True
    if choice.startswith(UNAVAILABLE_COMMAND_PREFIX):
        return choice.removeprefix("'").startswith(token) or choice.removeprefix(
            UNAVAILABLE_COMMAND_PREFIX
        ).startswith(token)
    return False


def command_argument_completion_plan(
    session: ConsoleSession,
    command: str,
    token: str,
) -> ConsoleCompletionPlan:
    choices: tuple[str, ...]
    if command == "help":
        matches = [category for category in CONSOLE_CATEGORIES if category.startswith(token)]
        matches.extend(console_completions(token))
        return completion_plan(matches)
    if command in {"man", "complete", "which"}:
        return completion_plan(console_completions(token))
    elif command == "phase":
        choices = ("whereami", "compass", "path", "map", "features", "help")
    elif command == "launch":
        choices = ("auto", "smoke", "full")
    elif command == "self-release":
        choices = ("plan", "status", "run", "bundle", "witness", "ledger", "all", "shell")
    elif command == "learn":
        choices = ("status", "list", "show", "add", "clear")
    elif command == "codex":
        choices = ("status", "handoff", "version", "doctor", "start", "exec", "resume")
    elif command == "kaiju":
        choices = (
            "status",
            "list",
            "purpose",
            "policy",
            "verify",
            "manifest",
            "iso",
            "disk",
            "clean",
            "boot",
        )
    elif command in {"plugins", "wasm"}:
        choices = ("list", "status", "inspect", "policy", "run")
    elif command == "wiki":
        choices = tuple(sorted(WIKI_TOPICS))
    elif command == "theme":
        choices = ("show", "list")
    elif command == "xframe-split":
        choices = ("2", "3", "4")
    elif command == "xframe-drop":
        choices = ("1", "all")
    elif command == "set":
        if token.startswith("-"):
            choices = ("-o",)
        else:
            choices = tuple(f"{key}=" for key in sorted(session.env))
    elif command == "export":
        choices = tuple(f"{key}=" for key in sorted(session.env))
    elif command == "unset":
        choices = tuple(sorted(session.env))
    elif command == "unalias":
        choices = tuple(sorted(session.aliases))
    elif command == "opslog":
        choices = ("status", "tail")
    elif command == "bootcfg":
        choices = ("show", "path")
    elif command == "nest":
        choices = (
            "status",
            "list",
            "enter",
            "inspect",
            "tree",
            "memory",
            "lock-policy",
            "info",
            *context_ids(),
        )
    elif command == "repo":
        choices = ("status",)
    elif command == "fyr":
        choices = ("status",)
    elif command == "base1":
        choices = ("status", "b1", "b2", "dry-run")
    elif command == "lang":
        choices = ("support", "security")
    elif command == "update":
        choices = ("plan", "protocol")
    elif command == "version":
        choices = ("--compare",)
    else:
        choices = ()
    return completion_plan([choice for choice in choices if completion_choice_matches(choice, token)])


def vfs_completion_plan(session: ConsoleSession, token: str, *, dirs_only: bool) -> ConsoleCompletionPlan:
    if "/" in token:
        base_token, fragment = token.rsplit("/", 1)
        base_path = vfs_normalize(session.cwd, base_token or "/")
        if base_token == "":
            display_prefix = "/"
        else:
            display_prefix = f"{base_token.rstrip('/')}/"
    else:
        base_path = session.cwd
        fragment = token
        display_prefix = ""
    try:
        is_dir, entries = vfs_list(base_path, session)
    except NoxframeError:
        return ConsoleCompletionPlan((), False)
    if not is_dir:
        return ConsoleCompletionPlan((), False)
    matches: list[str] = []
    for entry in entries:
        name = entry.rstrip("/")
        is_entry_dir = entry.endswith("/")
        if not name.startswith(fragment):
            continue
        if dirs_only and not is_entry_dir:
            continue
        matches.append(f"{display_prefix}{name}{'/' if is_entry_dir else ''}")
    return completion_plan(matches, append_space=True)


def console_completion_plan(
    session: ConsoleSession,
    line: str,
    cursor: int | None = None,
) -> ConsoleCompletionPlan:
    if cursor is None:
        cursor = len(line)
    words, token = completion_context(line, cursor)
    normalized_words = [normalize_console_lookup_name(word) for word in words]
    if not normalized_words:
        alias_matches = [name for name in session.aliases if name.startswith(token)]
        return completion_plan([*console_completions(token), *alias_matches], append_space=True)

    command = console_canonical_name(normalized_words[0])
    if command is None:
        return ConsoleCompletionPlan((), False)
    if command == "unalias":
        return completion_plan([name for name in session.aliases if name.startswith(token)])
    if command == "unset":
        return completion_plan([key for key in session.env if key.startswith(token)])
    if command in VFS_DIRECTORY_COMPLETION_COMMANDS:
        return vfs_completion_plan(session, token, dirs_only=True)
    if command in VFS_COMPLETION_COMMANDS:
        if command == "find" and len(normalized_words) > 1 and normalized_words[-1] == "-name":
            return ConsoleCompletionPlan((), False)
        if command in {"head", "tail"} and token.startswith("-"):
            return completion_plan([choice for choice in ("-n", "--lines") if choice.startswith(token)])
        return vfs_completion_plan(session, token, dirs_only=False)
    return command_argument_completion_plan(session, command, token)


def readline_prompt(text: str, color: str, palette: Palette) -> str:
    if not palette.enabled or readline is None or not sys.stdin.isatty():
        return palette.paint(text, color)
    return f"\001\x1b[{color}m\002{text}\001\x1b[0m\002"


def install_console_readline(session: ConsoleSession) -> tuple[object, str] | None:
    if readline is None or not sys.stdin.isatty():
        return None
    old_completer = readline.get_completer()
    old_delims = readline.get_completer_delims()
    cache: dict[str, object] = {"key": None, "matches": (), "append_space": False}

    def completer(text: str, state: int) -> str | None:
        buffer = readline.get_line_buffer()
        cursor = readline.get_endidx()
        key = (buffer, cursor, text)
        if state == 0 or cache.get("key") != key:
            plan = console_completion_plan(session, buffer, cursor)
            cache["key"] = key
            cache["matches"] = plan.matches
            cache["append_space"] = plan.append_space
            if hasattr(readline, "set_completion_append_character"):
                readline.set_completion_append_character(" " if plan.append_space else "")
        matches = cache.get("matches", ())
        if isinstance(matches, tuple) and state < len(matches):
            return matches[state]
        return None

    readline.set_completer(completer)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")
    for binding in (
        '"\\e[Z": "xframe-next\\n"',
        '"\\e\\e[Z": "xframe-next\\n"',
        '"\\e[17~": "xframe-next\\n"',
    ):
        try:
            readline.parse_and_bind(binding)
        except (ValueError, OSError):
            pass
    return old_completer, old_delims


def restore_console_readline(state: tuple[object, str] | None) -> None:
    if state is None or readline is None:
        return
    old_completer, old_delims = state
    readline.set_completer(old_completer)
    readline.set_completer_delims(old_delims)
    if hasattr(readline, "set_completion_append_character"):
        readline.set_completion_append_character(" ")


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
            "kaiju/",
            "codex/",
            "dev/",
            "phase/",
            "env/",
            "learn/",
            "nests/",
            "proc/",
            "var/",
            "docs/",
        ),
        "/dev": ("codex", "kaiju", "plugins", "wasi"),
        "/env": ("aliases", "profile", "security", "self-release", "variables"),
        "/kaiju": ("boot-plan", "disk", "iso", "manifest", "policy", "purposes", "status", "verify"),
        "/phase": ("compass", "features", "map", "path", "whereami"),
        "/learn": ("notes", "status"),
        "/nests": ("contexts", "lock-policy", "memory-map", "stack", "tree"),
        "/proc": ("version", "route", "cells", "processes"),
        "/var": ("log/",),
        "/var/log": ("audit",),
        "/docs": (
            "contract.json",
            "status.json",
            "state.json",
            "seal.json",
            "launch-report.md",
            "wuci-kaiju.json",
            "wiki",
        ),
    }
    dirs.update(cell_dirs)
    return dirs


def vfs_is_dir(path: str, session: ConsoleSession | None = None) -> bool:
    return path in vfs_static_dirs() or (session is not None and path in session.vfs_dirs)


def vfs_all_paths(session: ConsoleSession | None = None) -> list[str]:
    paths: set[str] = set(vfs_static_dirs())
    for base, entries in vfs_static_dirs().items():
        for entry in entries:
            clean = entry.rstrip("/")
            child = f"{base.rstrip('/')}/{clean}" if base != "/" else f"/{clean}"
            paths.add(child)
    if session is not None:
        paths.update(session.vfs_dirs)
        paths.update(session.vfs_files)
    return sorted(paths)


def vfs_parent(path: str) -> str:
    parent = os.path.dirname(path.rstrip("/"))
    return parent or "/"


def vfs_name(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


def vfs_static_path(path: str) -> bool:
    return path in vfs_all_paths(None)


def vfs_existing_path(path: str, session: ConsoleSession) -> bool:
    return vfs_static_path(path) or path in session.vfs_dirs or path in session.vfs_files


def vfs_list(path: str, session: ConsoleSession | None = None) -> tuple[bool, list[str]]:
    dirs = vfs_static_dirs()
    if path in dirs:
        entries = set(dirs[path])
        if session is not None:
            prefix = "/" if path == "/" else f"{path.rstrip('/')}/"
            for candidate in [*session.vfs_dirs, *session.vfs_files]:
                if not candidate.startswith(prefix) or candidate == path:
                    continue
                rel = candidate[len(prefix) :]
                if "/" in rel:
                    entries.add(rel.split("/", 1)[0] + "/")
                elif candidate in session.vfs_dirs:
                    entries.add(rel + "/")
                else:
                    entries.add(rel)
        return True, sorted(entries)
    if session is not None and path in session.vfs_dirs:
        prefix = f"{path.rstrip('/')}/"
        entries = set()
        for candidate in [*session.vfs_dirs, *session.vfs_files]:
            if not candidate.startswith(prefix) or candidate == path:
                continue
            rel = candidate[len(prefix) :]
            if "/" in rel:
                entries.add(rel.split("/", 1)[0] + "/")
            elif candidate in session.vfs_dirs:
                entries.add(rel + "/")
            else:
                entries.add(rel)
        return True, sorted(entries)
    if session is not None and path in session.vfs_files:
        return False, [path.rsplit("/", 1)[-1]]
    if path in vfs_all_paths(None):
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
    if path in session.vfs_files:
        return session.vfs_files[path]
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
                "root route: /proc /docs /phase /env /learn /nests /dev /var/log and Wuci-Ji proof cells",
                "try: help --compact, phase map, ls /phase, cat /env/profile, cat /dev/codex",
                "",
            ]
        )
    if path == "/phase/whereami":
        return phase_text(session, args, "whereami")
    if path == "/phase/compass":
        return phase_text(session, args, "compass")
    if path == "/phase/path":
        return phase_text(session, args, "path")
    if path == "/phase/map":
        return phase_text(session, args, "map")
    if path == "/phase/features":
        return phase_feature_text()
    if path == "/env/profile":
        return console_profile_text(session, args)
    if path == "/env/variables":
        sync_session_env(session, args)
        return console_env_text(session)
    if path == "/env/aliases":
        return console_alias_text(session)
    if path == "/env/security":
        return "\n".join(
            [
                "schema: wuci-noxframe-environment-security-v1",
                "scope: console-local metadata environment",
                "host_shell: disabled through the console registry",
                "host_routes: metadata-only unless an explicit bridge opts in",
                "network_routes: metadata-deny in the NOXFRAME console",
                "writes: substrate state/seal, launch evidence, and session-local env only",
                "non_claim: not OS runtime containment",
                "",
            ]
        )
    if path == "/env/self-release":
        return self_release_status_text(root)
    if path == "/kaiju/status":
        return wuci_kaiju.manifest_status_text(kaiju_catalog(root))
    if path == "/kaiju/policy":
        return wuci_kaiju.manifest_policy_text(kaiju_catalog(root))
    if path == "/kaiju/purposes":
        return wuci_kaiju.manifest_list_text(kaiju_catalog(root))
    if path == "/kaiju/verify":
        return kaiju_verify_text(root)
    if path == "/kaiju/iso":
        return wuci_kaiju.iso_status_text(kaiju_iso_root(root, args))
    if path == "/kaiju/disk":
        return wuci_kaiju.disk_status_text(kaiju_disk_root(root, args))
    if path == "/kaiju/boot-plan":
        try:
            return kaiju_boot_plan_text(root, args, ["kaiju", "boot", "--dry-run"])
        except wuci_kaiju.KaijuError as exc:
            return f"kaiju boot-plan: unavailable: {exc}\n"
    if path == "/kaiju/manifest":
        return json.dumps(kaiju_catalog(root), indent=2, sort_keys=True) + "\n"
    if path == "/learn/status":
        return learn_status_text(session)
    if path == "/learn/notes":
        return learn_notes_text(session)
    if path == "/nests/contexts":
        return nest_list_text()
    if path == "/nests/memory-map":
        return (
            json.dumps(
                substrate_memory_contract(
                    session.env.get("NOXFRAME_CONTEXT", "root"),
                    console_depth(session),
                ),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    if path == "/nests/lock-policy":
        return substrate_lock_policy_text()
    if path == "/nests/stack":
        return nest_status_text(session)
    if path == "/nests/tree":
        return nest_tree_text(session)
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
        return console_process_table(session)
    if path == "/dev/codex":
        return codex_bridge_status_text(root, args)
    if path == "/dev/kaiju":
        return wuci_kaiju.manifest_status_text(kaiju_catalog(root))
    if path == "/dev/plugins":
        return plugin_catalog_text()
    if path == "/dev/wasi":
        return plugin_policy_text()
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
    if path == "/docs/wuci-kaiju.json":
        return json.dumps(kaiju_catalog(root), indent=2, sort_keys=True) + "\n"
    if path == "/docs/wiki":
        return wiki_text(None)
    raise NoxframeError(f"not a virtual file: {path}")


def console_process_rows(session: ConsoleSession | None = None) -> list[tuple[int, str, str, str]]:
    rows = [
        (1, "ready", "0", "noxframe-console"),
        (2, "ready", "0", "substrate-seal"),
        (3, "idle", "0", "daylight-anchor"),
        (4, "idle", "0", "codex-bridge"),
    ]
    if session is not None:
        for pid in sorted(session.jobs):
            job = session.jobs[pid]
            rows.append(
                (
                    pid,
                    job.get("state", "ready"),
                    job.get("priority", "0"),
                    job.get("name", "job"),
                )
            )
    return rows


def console_process_table(session: ConsoleSession | None = None) -> str:
    lines = ["PID  STATE       PRI  NAME"]
    for pid, state, priority, name in console_process_rows(session):
        lines.append(f"{pid:<4} {state:<11} {priority:<4} {name}")
    lines.append("")
    return "\n".join(lines)


def print_vfs_tree(start: str, session: ConsoleSession) -> None:
    dirs = vfs_static_dirs()
    all_paths = vfs_all_paths(session)
    if start not in dirs and start not in session.vfs_dirs:
        print(start)
        return
    print(start)
    for path in all_paths:
        if path == start or not path.startswith(start.rstrip("/") + "/"):
            continue
        rel = path[len(start.rstrip("/")) + 1 :] if start != "/" else path[1:]
        depth = rel.count("/")
        if depth > 2:
            continue
        marker = "/" if path in dirs or path in session.vfs_dirs else ""
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
                "Phase Compass and Optics rails",
                "metadata-only nesting",
                "sealed depth memory path map",
                "session-local learning notes",
                "plugin and WASI-lite catalogs without execution",
                "Base1/B1/B2 dry-run metadata",
                "quality gates and selftest surfaces",
                "conservative OS-track claims",
            ],
            "ideas_not_imported": [
                "Phase1 code",
                "host shell passthrough",
                "network command surface",
                "plugin execution",
                "persistent learning database",
                "host-proof substrate isolation",
                "password recovery backdoor",
                "simulated kernel claims as enforcement",
            ],
        },
        "phase1_feature_map": [
            {"id": name, "mapping": description, "host_effect": "metadata-only"}
            for name, description in PHASE1_FEATURES
        ],
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
        "substrate_memory": substrate_memory_contract(),
        "daylight_wrap": {
            "schema": DAYLIGHT_WRAP_SCHEMA,
            "artifact_envelope": "WJSEAL-v2 via seal-file-keyfile-v2",
            "key_source": "operator-supplied local keyfile; password-derived gates require a reviewed implementation",
            "scope": "NOXFRAME substrate state, seal, cells, substrate memory map, virtual dimensions, and Daylight anchors",
            "non_claim": "local artifact sealing only; not runtime containment or whole-system PQ safety",
        },
        "network_bridge": {
            "default": "metadata-deny in the NOXFRAME console",
            "future_opt_in": "explicit allowlisted bridge with transcripted egress; no scanning by default",
        },
        "rules": {
            "stdlib_only": True,
            "network": "metadata-deny unless a future explicit bridge is added",
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
            "network": "metadata-deny unless a future explicit bridge is added",
            "shell": "disabled",
            "host_mutation": "state-and-seal-files-only",
            "artifact_release": "requires existing Gate proof lanes",
            "plugin_execution": "unavailable",
            "learning": "session-local only",
        },
        "substrate_memory": substrate_memory_contract(),
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
            "network": "metadata-deny in the console registry",
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


def validate_regular_local_file(path: Path, label: str, *, executable: bool = False) -> None:
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
    if executable and not os.access(path, os.X_OK):
        raise NoxframeError(f"{label} must be executable: {path}")


def read_regular_local_bytes(path: Path, label: str) -> bytes:
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
        if opened.st_nlink != 1:
            raise NoxframeError(f"{label} must not be hardlinked: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def ensure_local_output_dir(path: Path, label: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise NoxframeError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise NoxframeError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise NoxframeError(f"{label} must be a directory: {path}")


def require_new_output_path(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise NoxframeError(f"refusing to replace symlink {label}: {path}")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise NoxframeError(f"refusing to replace hardlinked {label}: {path}")
    raise NoxframeError(f"refusing to overwrite existing {label}: {path}")


def noxframe_inner_dimension_records(state: dict[str, object]) -> list[dict[str, object]]:
    state_cells = state.get("cells")
    cell_by_id: dict[str, dict[str, object]] = {}
    if isinstance(state_cells, list):
        for cell in state_cells:
            if isinstance(cell, dict) and isinstance(cell.get("id"), str):
                cell_by_id[str(cell["id"])] = dict(cell)
    records: list[dict[str, object]] = []
    for cell_id, role, actions in SUBSTRATE_CELLS:
        state_cell = cell_by_id.get(cell_id, {})
        record = {
            "id": cell_id,
            "role": role,
            "allowed_actions": list(actions),
            "state": state_cell.get("state", "sealed-metadata-ready"),
            "memory_store_path": substrate_memory_path(cell_id, 0),
            "wrap_surface": "substrate-cell",
        }
        record["digest_vector"] = digest_vector_json(record)
        records.append(record)
    return records


def noxframe_virtual_dimension_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path, entries in sorted(vfs_static_dirs().items()):
        record = {
            "path": path,
            "entries": [entry.rstrip("/") for entry in entries],
            "wrap_surface": "virtual-filesystem",
        }
        record["digest_vector"] = digest_vector_json(record)
        records.append(record)
    return records


def build_daylight_wrap_bundle(
    root: Path,
    *,
    state: dict[str, object],
    seal: dict[str, object],
    now_utc: str,
) -> dict[str, object]:
    dimensions = noxframe_inner_dimension_records(state)
    virtual_dimensions = noxframe_virtual_dimension_records()
    daylight_anchors = [
        anchor_record(root, relative_path) for relative_path in DAYLIGHT_ANCHOR_PATHS
    ]
    public_anchors = [anchor_record(root, relative_path) for relative_path in ANCHOR_PATHS]
    bundle = {
        "schema": DAYLIGHT_WRAP_BUNDLE_SCHEMA,
        "name": TOOL_NAME,
        "created_utc": now_utc,
        "route": ["root", "wuci-ji", "daylight"],
        "wrap_scheme": {
            "artifact_envelope": "WJSEAL-v2 via seal-file-keyfile-v2",
            "daylight_binding": "Daylight public anchors and WUCI-Daylight bridge source digests",
            "key_source": "operator-supplied local keyfile",
            "plaintext_persistence": "temporary bundle only; depth memory is represented by sealed path records",
        },
        "contract": substrate_contract(),
        "state": state,
        "substrate_seal": seal,
        "substrate_memory": substrate_memory_contract(),
        "inner_dimensions": dimensions,
        "virtual_dimensions": virtual_dimensions,
        "daylight_anchors": daylight_anchors,
        "public_anchors": public_anchors,
        "dimension_digest_vector": digest_vector_json(
            {
                "inner_dimensions": dimensions,
                "virtual_dimensions": virtual_dimensions,
                "substrate_memory": substrate_memory_contract(),
            }
        ),
        "non_claims": list(NON_CLAIMS),
    }
    bundle["bundle_digest_vector"] = digest_vector_json(bundle)
    return bundle


def daylight_wrap_key_id(bundle: dict[str, object]) -> str:
    material = {
        "schema": DAYLIGHT_WRAP_SCHEMA,
        "bundle_digest_vector": bundle["bundle_digest_vector"],
        "domain": "wuci-noxframe-daylight-wrap-key-id-v1",
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()[:32]


def command_daylight_wrap(root: Path, args: argparse.Namespace) -> int:
    if not args.daylight_wrap_keyfile:
        sys.stderr.write("daylight-wrap: --daylight-wrap-keyfile is required\n")
        return 2

    state_path, seal_path = substrate_paths(root, args)
    ensure_substrate(root, state_path=state_path, seal_path=seal_path)
    ok, problems = verify_substrate_seal(root, state_path=state_path, seal_path=seal_path)
    if not ok:
        sys.stderr.write("daylight-wrap: refusing to wrap drifted NOXFRAME substrate\n")
        for problem in problems:
            sys.stderr.write(f"problem: {problem}\n")
        return 1

    out_dir = repo_path(root, args.daylight_wrap_out)
    ensure_local_output_dir(out_dir, "NOXFRAME Daylight wrap output directory")
    bundle_path = out_dir / "noxframe-inner-dimensions.bundle.json"
    sealed_path = out_dir / "noxframe-inner-dimensions.wj"
    manifest_path = out_dir / "manifest.json"
    require_new_output_path(sealed_path, "NOXFRAME Daylight wrap artifact")

    bin_path = repo_path(root, args.bin)
    keyfile_path = repo_path(root, args.daylight_wrap_keyfile)
    validate_regular_local_file(bin_path, "wuci-ji binary", executable=True)
    keyfile_bytes = read_regular_local_bytes(keyfile_path, "NOXFRAME Daylight wrap keyfile")

    state = safe_read_json_file(state_path, "NOXFRAME state")
    seal = safe_read_json_file(seal_path, "NOXFRAME substrate seal")
    bundle = build_daylight_wrap_bundle(root, state=state, seal=seal, now_utc=utc_now())
    key_id = daylight_wrap_key_id(bundle)
    bundle_bytes = canonical_json_bytes(bundle)
    bundle_file_bytes = bundle_bytes + b"\n"

    key_fd, key_tmp_name = tempfile.mkstemp(
        prefix=".daylight-wrap-key.", dir=str(out_dir), text=False
    )
    try:
        with os.fdopen(key_fd, "wb") as handle:
            handle.write(keyfile_bytes)
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{bundle_path.name}.", dir=str(out_dir), text=False
        )
        try:
            with os.fdopen(tmp_fd, "wb") as handle:
                handle.write(bundle_file_bytes)
            try:
                result = subprocess.run(
                    [
                        str(bin_path),
                        "seal-file-keyfile-v2",
                        key_tmp_name,
                        key_id,
                        tmp_name,
                        str(sealed_path),
                    ],
                    cwd=root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
            except OSError as exc:
                sys.stderr.write(f"daylight-wrap: could not run seal-file-keyfile-v2: {exc}\n")
                return 1
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
    finally:
        try:
            os.unlink(key_tmp_name)
        except FileNotFoundError:
            pass

    if result.returncode != 0:
        try:
            os.unlink(sealed_path)
        except FileNotFoundError:
            pass
        sys.stderr.write(result.stderr or "daylight-wrap: seal-file-keyfile-v2 failed\n")
        return result.returncode

    sealed_bytes = read_regular_local_bytes(sealed_path, "NOXFRAME Daylight wrap artifact")
    manifest = {
        "schema": DAYLIGHT_WRAP_SCHEMA,
        "name": TOOL_NAME,
        "status": "sealed",
        "created_utc": utc_now(),
        "wrap_scheme": bundle["wrap_scheme"],
        "key_id": key_id,
        "key_source": "operator-supplied local keyfile; key material is not embedded",
        "bundle_digest_vector": digest_vector(bundle_file_bytes),
        "dimension_digest_vector": bundle["dimension_digest_vector"],
        "substrate_memory_digest_vector": digest_vector_json(bundle["substrate_memory"]),
        "state_digest_vector": digest_vector_json(state),
        "substrate_seal_digest_vector": digest_vector_json(seal),
        "sealed_artifact": {
            "path": str(sealed_path),
            "bytes": len(sealed_bytes),
            "digest_vector": digest_vector(sealed_bytes),
        },
        "manifest": str(manifest_path),
        "inner_dimensions": [
            {
                "id": record["id"],
                "role": record["role"],
                "digest_vector": record["digest_vector"],
            }
            for record in bundle["inner_dimensions"]
            if isinstance(record, dict)
        ],
        "virtual_dimension_count": len(bundle["virtual_dimensions"]),
        "daylight_anchors": bundle["daylight_anchors"],
        "guards": {
            "network": "metadata-deny in the console registry",
            "shell": "disabled; subprocess invoked with shell=False",
            "keyfile": (
                "operator keyfile read through no-follow regular-file check; "
                "temporary key copy removed after sealing"
            ),
            "plaintext_bundle": "temporary file removed after seal-file-keyfile-v2 returns",
        },
        "non_claims": list(NON_CLAIMS),
    }
    write_json_atomic(manifest_path, manifest)

    if args.json:
        print_json(manifest)
    else:
        print("noxframe daylight-wrap: sealed")
        print(f"artifact: {sealed_path}")
        print(f"manifest: {manifest_path}")
        print(f"key-id: {key_id}")
    return 0


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


def detect_boot_terminal(env: dict[str, str] | None = None) -> BootTerminalProfile:
    env = os.environ if env is None else env
    term = env.get("TERM", "").lower()
    term_program = env.get("TERM_PROGRAM", "").lower()
    colorterm = env.get("COLORTERM", "").lower()
    in_tmux = bool(env.get("TMUX")) or term.startswith("screen")
    remote = bool(env.get("SSH_CONNECTION") or env.get("SSH_TTY"))

    if term in {"", "dumb"}:
        return BootTerminalProfile("dumb", False, True, 0.0)
    if env.get("KITTY_WINDOW_ID") or "kitty" in term:
        return BootTerminalProfile("kitty", True, False, 0.14)
    if env.get("WEZTERM_PANE") or "wezterm" in term_program:
        return BootTerminalProfile("wezterm", True, False, 0.15)
    if env.get("GHOSTTY_RESOURCES_DIR") or "ghostty" in term_program or "ghostty" in term:
        return BootTerminalProfile("ghostty", True, False, 0.15)
    if "iterm" in term_program:
        return BootTerminalProfile("iterm", True, False, 0.16)
    if "vscode" in term_program or "vscode" in term:
        return BootTerminalProfile("vscode", False, True, 0.0)
    if in_tmux:
        return BootTerminalProfile("tmux", False, True, 0.0)
    if remote:
        return BootTerminalProfile("remote", False, True, 0.0)
    if "truecolor" in colorterm and any(token in term for token in ("xterm", "alacritty", "ghostty")):
        return BootTerminalProfile("truecolor", False, True, 0.0)
    return BootTerminalProfile(term or "generic", False, True, 0.0)


def terminal_graphics_available(env: dict[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    if sys.platform == "darwin":
        return True
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def interactive_terminal_launch(
    args: argparse.Namespace,
    *,
    stdin_tty: bool | None = None,
    stdout_tty: bool | None = None,
    stderr_tty: bool | None = None,
) -> bool:
    stdin_tty = sys.stdin.isatty() if stdin_tty is None else stdin_tty
    stdout_tty = sys.stdout.isatty() if stdout_tty is None else stdout_tty
    stderr_tty = sys.stderr.isatty() if stderr_tty is None else stderr_tty
    return (
        getattr(args, "command", "launch") == "launch"
        and not getattr(args, "no_console", False)
        and stdin_tty
        and stdout_tty
        and stderr_tty
    )


def should_handoff_to_mechanics_terminal(
    args: argparse.Namespace,
    *,
    env: dict[str, str] | None = None,
    stdin_tty: bool | None = None,
    stdout_tty: bool | None = None,
    stderr_tty: bool | None = None,
) -> bool:
    env = os.environ if env is None else env
    if getattr(args, "no_terminal_handoff", False):
        return False
    if env.get(TERMINAL_HANDOFF_ENV):
        return False
    if getattr(args, "boot_renderer", "auto") != "auto":
        return False
    if not interactive_terminal_launch(
        args,
        stdin_tty=stdin_tty,
        stdout_tty=stdout_tty,
        stderr_tty=stderr_tty,
    ):
        return False
    if not terminal_graphics_available(env):
        return False
    profile = detect_boot_terminal(env)
    if profile.name in {"dumb", "remote", "tmux"}:
        return False
    return not profile.rich_animation


def resolve_command_path(
    name: str,
    command_paths: dict[str, str | None] | None = None,
) -> str | None:
    if command_paths is not None:
        return command_paths.get(name)
    return shutil.which(name)


def noxframe_relaunch_argv(root: Path, argv: tuple[str, ...] | None = None) -> tuple[str, ...]:
    raw = tuple(sys.argv if argv is None else argv)
    suffix = raw[1:] if raw else ()
    if raw:
        launcher = Path(raw[0])
        if not launcher.is_absolute():
            launcher = (Path.cwd() / launcher).resolve()
        if launcher.exists():
            return (str(launcher), *suffix)
    return (str(root / "tools" / "wuci-noxframe"), *suffix)


def mechanics_terminal_handoff_command(
    root: Path,
    args: argparse.Namespace,
    *,
    env: dict[str, str] | None = None,
    command_paths: dict[str, str | None] | None = None,
    argv: tuple[str, ...] | None = None,
    stdin_tty: bool | None = None,
    stdout_tty: bool | None = None,
    stderr_tty: bool | None = None,
) -> tuple[str, ...] | None:
    if not should_handoff_to_mechanics_terminal(
        args,
        env=env,
        stdin_tty=stdin_tty,
        stdout_tty=stdout_tty,
        stderr_tty=stderr_tty,
    ):
        return None
    kitty = resolve_command_path("kitty", command_paths)
    if not kitty:
        return None
    return (
        kitty,
        "--title",
        "WUCI-NOXFRAME",
        "--working-directory",
        str(root),
        *noxframe_relaunch_argv(root, argv),
    )


def maybe_open_mechanics_terminal(root: Path, args: argparse.Namespace, palette: Palette) -> bool:
    env = os.environ.copy()
    command = mechanics_terminal_handoff_command(root, args, env=env)
    if command is None:
        if should_handoff_to_mechanics_terminal(args, env=env):
            sys.stderr.write(
                palette.paint(
                    "NOXFRAME mechanics terminal not found; install kitty "
                    f"or use {MECHANICS_TERMINAL_HINT}. "
                    "Using the reduced terminal profile.\n",
                    palette.yellow,
                )
            )
            sys.stderr.flush()
        return False
    env[TERMINAL_HANDOFF_ENV] = "1"
    env["NOXFRAME_PARENT_TERMINAL"] = detect_boot_terminal(env).name
    try:
        subprocess.Popen(
            list(command),
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError as exc:
        sys.stderr.write(
            palette.paint(
                f"NOXFRAME could not open kitty ({exc}); using the reduced terminal profile.\n",
                palette.yellow,
            )
        )
        sys.stderr.flush()
        return False
    sys.stderr.write(
        palette.paint(
            "NOXFRAME opening kitty mechanics terminal for the full boot surface.\n",
            palette.cyan,
        )
    )
    sys.stderr.flush()
    return True


def boot_animation_active(args: argparse.Namespace) -> bool:
    if args.yes or args.no_boot_prompt or getattr(args, "no_boot_animation", False):
        return False
    return (
        sys.stdin.isatty()
        and sys.stderr.isatty()
        and getattr(args, "boot_renderer", "auto") != "gui"
        and detect_boot_terminal().rich_animation
    )


def boot_voice_active(args: argparse.Namespace) -> bool:
    if args.yes or args.no_boot_prompt or getattr(args, "no_boot_voice", False):
        return False
    return sys.stdin.isatty() and sys.stderr.isatty()


def boot_voice_command(
    text: str,
    command_paths: dict[str, str | None] | None = None,
) -> tuple[str, ...] | None:
    def resolved(name: str) -> str | None:
        if command_paths is not None:
            return command_paths.get(name)
        return shutil.which(name)

    candidates = (
        ("spd-say", ("-t", "female1", "-r", "-20", text)),
        ("espeak-ng", ("-v", "en+f3", "-s", "145", text)),
        ("espeak", ("-v", "en+f3", "-s", "145", text)),
        ("say", ("-v", "Samantha", "-r", "145", text)),
    )
    for name, args in candidates:
        path = resolved(name)
        if path:
            return (path, *args)
    return None


def speak_boot_prompt_once(text: str = BOOT_VOICE_TEXT) -> bool:
    command = boot_voice_command(text)
    if command is None:
        return False
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError:
        return False
    return True


def prompt_boot_plain(prompt: str, palette: Palette) -> bool:
    sys.stderr.write(palette.paint(prompt, palette.red))
    sys.stderr.flush()
    answer = sys.stdin.readline()
    return boot_answer_allows(answer)


def prompt_boot_animated(prompt: str, palette: Palette) -> bool:
    terminal_profile = detect_boot_terminal()
    if not terminal_profile.rich_animation:
        return prompt_boot_plain(prompt, palette)
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
                clear_screen=frame == 0,
            )
            ready, _, _ = select.select([sys.stdin], [], [], terminal_profile.frame_delay)
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


def boot_gui_candidate(args: argparse.Namespace) -> bool:
    renderer = getattr(args, "boot_renderer", "auto")
    if args.yes or args.no_boot_prompt or getattr(args, "no_boot_animation", False):
        return False
    return renderer == "gui" and sys.stdin.isatty()


def prompt_boot_graphical(prompt: str) -> bool | None:
    try:
        import tkinter as tk
        from tkinter import font as tkfont
    except Exception:
        return None

    try:
        root = tk.Tk()
    except Exception:
        return None

    decision: dict[str, bool | None] = {"value": None}
    frame_state = {"frame": 0, "after": None}
    def finish(value: bool) -> None:
        decision["value"] = value
        after_id = frame_state.get("after")
        if after_id is not None:
            try:
                root.after_cancel(after_id)
            except tk.TclError:
                pass
        root.destroy()

    def on_key(event: object) -> None:
        keysym = getattr(event, "keysym", "")
        char = getattr(event, "char", "")
        lowered = char.lower()
        if keysym in {"Return", "KP_Enter", "space"} or lowered in {"y"}:
            finish(True)
        elif keysym in {"Escape"} or lowered in {"n", "q"}:
            finish(False)

    def on_close() -> None:
        finish(False)

    def hex_color(rgb: tuple[int, int, int]) -> str:
        return "#{:02x}{:02x}{:02x}".format(*rgb)

    def mix(a: tuple[int, int, int], b: tuple[int, int, int], amount: float) -> tuple[int, int, int]:
        amount = max(0.0, min(1.0, amount))
        return (
            int(a[0] + (b[0] - a[0]) * amount),
            int(a[1] + (b[1] - a[1]) * amount),
            int(a[2] + (b[2] - a[2]) * amount),
        )

    def draw_gradient(canvas: object, width: int, height: int) -> None:
        bands = 72
        for index in range(bands):
            t0 = index / bands
            t1 = (index + 1) / bands
            base = mix((3, 1, 4), (23, 2, 8), t0)
            crimson = mix(base, (101, 4, 21), max(0.0, 1.0 - abs(t0 - 0.58) * 3.2))
            violet = mix(crimson, (42, 11, 61), max(0.0, t0 - 0.74) * 0.9)
            ember = mix(violet, (139, 10, 34), max(0.0, 1.0 - abs(t0 - 0.86) * 5.0) * 0.22)
            canvas.create_rectangle(
                0,
                int(height * t0),
                width,
                int(height * t1) + 1,
                fill=hex_color(ember),
                outline="",
                tags="frame",
            )

    def draw_static_scene(canvas: object, width: int, height: int, frame: int) -> None:
        draw_gradient(canvas, width, height)
        grid_color = "#3c0711"
        grid_step = max(34, min(72, width // 22))
        for x in range(0, width + grid_step, grid_step):
            canvas.create_line(x, 0, x, height, fill=grid_color, width=1, tags="frame")
        for y in range(0, height + grid_step, grid_step):
            canvas.create_line(0, y, width, y, fill=grid_color, width=1, tags="frame")

        panel_x = width * 0.58
        panel_y = height * 0.18
        panel_w = width * 0.36
        panel_h = height * 0.58
        cols = 8
        grid_rows = 6
        cell_w = panel_w / cols
        cell_h = panel_h / grid_rows
        canvas.create_rectangle(
            panel_x,
            panel_y,
            panel_x + panel_w,
            panel_y + panel_h,
            outline="#e3345d",
            width=max(1, width // 480),
            tags="frame",
        )
        for col in range(1, cols):
            x = panel_x + col * cell_w
            canvas.create_line(x, panel_y, x, panel_y + panel_h, fill="#651123", width=1, tags="frame")
        for row in range(1, grid_rows):
            y = panel_y + row * cell_h
            canvas.create_line(panel_x, y, panel_x + panel_w, y, fill="#651123", width=1, tags="frame")

        matrix_font = tkfont.Font(family="Courier", size=max(10, width // 108), weight="bold")
        small_font = tkfont.Font(family="Courier", size=max(8, width // 150))
        canvas.create_text(panel_x + 18, panel_y - 22, anchor=tk.W, text="[2 1; 1 1]", fill="#ff7b9a", font=small_font, tags="frame")
        canvas.create_text(panel_x + panel_w - 18, panel_y - 22, anchor=tk.E, text=BOOT_IDEOGRAPH_TEXT, fill="#b875ff", font=small_font, tags="frame")

        active_cells: set[tuple[int, int]] = set()
        for seed in range(18):
            u = (seed * 3 + frame // 5) % cols
            v = (seed * 5 + frame // 8) % grid_rows
            x_cell = (2 * u + v + frame // 11) % cols
            y_cell = (u + v + frame // 13) % grid_rows
            active_cells.add((x_cell, y_cell))

        for row in range(grid_rows):
            for col in range(cols):
                x0 = panel_x + col * cell_w
                y0 = panel_y + row * cell_h
                token = ((col * 7 + row * 11 + frame // 4) % 16)
                if (col, row) in active_cells:
                    canvas.create_rectangle(
                        x0 + 3,
                        y0 + 3,
                        x0 + cell_w - 3,
                        y0 + cell_h - 3,
                        fill="#2a020b",
                        outline="#ff4d73",
                        width=2,
                        tags="frame",
                    )
                    canvas.create_text(
                        x0 + cell_w / 2,
                        y0 + cell_h / 2,
                        text=f"{token:X}",
                        fill="#ffe9f1",
                        font=matrix_font,
                        tags="frame",
                    )
                elif (col + row + frame // 10) % 5 == 0:
                    canvas.create_text(
                        x0 + cell_w / 2,
                        y0 + cell_h / 2,
                        text=f"{token:X}",
                        fill="#9c2444",
                        font=small_font,
                        tags="frame",
                    )

        for index in range(5):
            rail_y = panel_y + panel_h + 24 + index * max(10, height * 0.018)
            canvas.create_line(panel_x, rail_y, panel_x + panel_w, rail_y, fill="#6b1530", width=1, tags="frame")
            packet_x = panel_x + ((frame * (1.2 + index * 0.25) + index * 61) % panel_w)
            canvas.create_rectangle(packet_x, rail_y - 2, packet_x + cell_w * 0.62, rail_y + 2, fill="#ff4f84", outline="", tags="frame")

    def draw_text(canvas: object, width: int, height: int) -> None:
        title_size = max(44, min(112, width // 13))
        subtitle_size = max(16, min(30, width // 48))
        prompt_size = max(15, min(24, width // 62))
        center_x = int(width * (0.42 if width >= 900 else 0.50))
        title_y = int(height * 0.46)
        title_font = tkfont.Font(family="Helvetica", size=title_size, weight="bold")
        subtitle_font = tkfont.Font(family="Helvetica", size=subtitle_size)
        prompt_font = tkfont.Font(family="Helvetica", size=prompt_size)
        canvas.create_text(
            center_x + 3,
            title_y + 4,
            text="WUCI-JI",
            fill="#4d0010",
            font=title_font,
            tags="frame",
        )
        canvas.create_text(center_x, title_y, text="WUCI-JI", fill="#fff0f5", font=title_font, tags="frame")
        canvas.create_text(
            center_x,
            title_y + title_size * 0.82,
            text="Wuci-Ji Systems Substrate",
            fill="#ff6b8f",
            font=subtitle_font,
            tags="frame",
        )
        canvas.create_text(
            center_x,
            title_y + title_size * 1.12,
            text=BOOT_IDEOGRAPH_TEXT,
            fill="#b875ff",
            font=tkfont.Font(family="Helvetica", size=max(18, min(36, width // 42)), weight="bold"),
            tags="frame",
        )
        question = BOOT_VOICE_TEXT if prompt == BOOT_PROMPT else prompt.strip()
        wrap = min(int(width * 0.54), 720)
        canvas.create_text(
            center_x,
            int(height * 0.72),
            text=question,
            fill="#ffd7e2",
            font=prompt_font,
            width=wrap,
            justify=tk.CENTER,
            tags="frame",
        )
        canvas.create_text(
            center_x,
            int(height * 0.82),
            text="[ Enter / Y ]",
            fill="#ff4f74",
            font=tkfont.Font(family="Helvetica", size=max(13, prompt_size - 2), weight="bold"),
            tags="frame",
        )
        canvas.create_text(
            center_x,
            int(height * 0.875),
            text="N / Esc declines",
            fill="#b875ff",
            font=tkfont.Font(family="Helvetica", size=max(10, prompt_size - 7)),
            tags="frame",
        )

    root.title("WUCI-JI Systems Substrate")
    root.configure(bg="#030104")
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.bind("<Key>", on_key)
    root.bind("<Button-1>", lambda _event: finish(True))
    try:
        root.attributes("-fullscreen", True)
    except tk.TclError:
        root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}+0+0")
    canvas = tk.Canvas(root, highlightthickness=0, bd=0, bg="#030104")
    canvas.pack(fill=tk.BOTH, expand=True)
    width = max(800, root.winfo_screenwidth())
    height = max(480, root.winfo_screenheight())

    def render() -> None:
        try:
            current_width = max(640, canvas.winfo_width() or width)
            current_height = max(420, canvas.winfo_height() or height)
            canvas.delete("frame")
            frame = frame_state["frame"]
            draw_static_scene(canvas, current_width, current_height, frame)
            draw_text(canvas, current_width, current_height)
            frame_state["frame"] = frame + 1
            frame_state["after"] = root.after(33, render)
        except tk.TclError:
            return

    try:
        root.after(0, render)
        root.mainloop()
    except Exception:
        try:
            root.destroy()
        except tk.TclError:
            pass
        return None
    return bool(decision["value"])


def confirm_boot(args: argparse.Namespace, palette: Palette) -> bool:
    if args.yes or args.no_boot_prompt:
        return True
    if not args.force_boot_prompt and (not sys.stdin.isatty() or not sys.stderr.isatty()):
        return True
    prompt = BOOT_PROMPT
    if boot_voice_active(args):
        speak_boot_prompt_once()
    if boot_gui_candidate(args):
        graphical_answer = prompt_boot_graphical(prompt)
        if graphical_answer is not None:
            return graphical_answer
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
    clear_screen: bool = True,
) -> None:
    width = max(
        MIN_BANNER_INNER_WIDTH,
        terminal_columns() - 1 if full_screen else banner_inner_width(full_width=False),
    )
    rows = (
        max(14, terminal_lines() - 1)
        if full_screen
        else (24 if width >= 82 else 20)
    )
    if not full_screen:
        rows = min(rows, 26)

    Cell = tuple[str, tuple[int, int, int] | None, tuple[int, int, int] | None, bool]

    def blend(a: tuple[int, int, int], b: tuple[int, int, int], amount: float) -> tuple[int, int, int]:
        amount = max(0.0, min(1.0, amount))
        return (
            int(a[0] + (b[0] - a[0]) * amount),
            int(a[1] + (b[1] - a[1]) * amount),
            int(a[2] + (b[2] - a[2]) * amount),
        )

    def bg_at(x: int, y: int) -> tuple[int, int, int]:
        x_t = x / max(1, width - 1)
        y_t = y / max(1, rows - 1)
        void = blend((3, 1, 4), (17, 1, 7), y_t)
        crimson = blend(void, (74, 4, 17), max(0.0, 1.0 - abs(y_t - 0.58) * 3.6))
        lower = blend(crimson, (18, 0, 6), max(0.0, y_t - 0.72) * 1.5)
        red_haze = max(0.0, x_t - 0.56) * max(0.0, 0.88 - y_t) * 0.62
        purple_haze = max(0.0, 0.50 - x_t) * max(0.0, y_t - 0.18) * 0.22
        return blend(blend(lower, (132, 6, 31), red_haze), (66, 18, 91), purple_haze)

    canvas: list[list[Cell]] = [
        [(" ", None, bg_at(x, y), False) for x in range(width)]
        for y in range(rows)
    ]

    def ansi_prefix(
        fg: tuple[int, int, int] | None,
        bg: tuple[int, int, int] | None,
        bold: bool,
    ) -> str:
        if not palette.enabled:
            return ""
        codes = []
        if bold:
            codes.append("1")
        if fg is not None:
            codes.append(f"38;2;{fg[0]};{fg[1]};{fg[2]}")
        if bg is not None:
            codes.append(f"48;2;{bg[0]};{bg[1]};{bg[2]}")
        return f"\x1b[{';'.join(codes)}m" if codes else ""

    def put(
        x: int,
        y: int,
        char: str,
        *,
        fg: tuple[int, int, int] | None = None,
        bg: tuple[int, int, int] | None = None,
        bold: bool = False,
    ) -> None:
        if 0 <= x < width and 0 <= y < rows and display_width(char) == 1:
            old = canvas[y][x]
            canvas[y][x] = (char, fg, bg if bg is not None else old[2], bold)

    def put_text(
        text: str,
        x: int,
        y: int,
        *,
        fg: tuple[int, int, int],
        bold: bool = False,
        max_width: int | None = None,
    ) -> None:
        if not 0 <= y < rows:
            return
        limit = max(0, min(width - x, max_width if max_width is not None else width - x))
        rendered = fit_display(text, limit)
        cursor = x
        for char in rendered:
            char_width = display_width(char)
            if char_width == 1:
                put(cursor, y, char, fg=fg, bold=bold)
            elif char_width == 2 and cursor + 1 < width:
                old = canvas[y][cursor]
                canvas[y][cursor] = (char, fg, old[2], bold)
                canvas[y][cursor + 1] = ("", fg, old[2], bold)
            cursor += max(char_width, 1)
            if cursor >= width:
                break

    def clear_span(x: int, y: int, span: int) -> None:
        if not 0 <= y < rows:
            return
        for xx in range(max(0, x), min(width, x + span)):
            canvas[y][xx] = (" ", None, blend(bg_at(xx, y), (44, 2, 13), 0.18), False)

    def centered_x(text: str, center: int, padding: int = 2) -> int:
        text_width = display_width(text)
        return max(padding, min(width - text_width - padding, center - text_width // 2))

    def wrap_words(text: str, limit: int) -> list[str]:
        words = text.split()
        lines: list[str] = []
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if display_width(candidate) <= limit:
                current = candidate
                continue
            if current:
                lines.append(current)
            current = word
        if current:
            lines.append(current)
        return lines or [""]

    def draw_line(
        x0: int,
        y0: int,
        x1: int,
        y1: int,
        *,
        fg: tuple[int, int, int],
        char: str | None = None,
        bold: bool = False,
    ) -> None:
        steps = max(abs(x1 - x0), abs(y1 - y0), 1)
        for step in range(steps + 1):
            t = step / steps
            x = round(x0 + (x1 - x0) * t)
            y = round(y0 + (y1 - y0) * t)
            if char is None:
                mark = "╲" if (x1 - x0) * (y1 - y0) >= 0 else "╱"
            else:
                mark = char
            put(x, y, mark, fg=fg, bold=bold)

    grid_left = int(width * (0.61 if width >= 74 else 0.54))
    grid_top = max(1, int(rows * 0.18))
    grid_width = max(18, width - grid_left - 2)
    grid_rows = max(4, min(6, (rows - grid_top - 5) // 2))
    grid_cols = max(4, min(8, grid_width // 6))
    cell_w = max(4, grid_width // grid_cols)
    cell_h = 2
    grid_right = min(width - 2, grid_left + grid_cols * cell_w)
    grid_bottom = min(rows - 2, grid_top + grid_rows * cell_h)
    grid_color = (214, 42, 76)
    hot_color = (255, 80, 122)
    dim_grid = (101, 18, 42)

    for row in range(grid_rows + 1):
        y = grid_top + row * cell_h
        if y > grid_bottom:
            continue
        for x in range(grid_left, grid_right + 1):
            if x == grid_left:
                char = "├" if 0 < row < grid_rows else ("┌" if row == 0 else "└")
            elif x == grid_right:
                char = "┤" if 0 < row < grid_rows else ("┐" if row == 0 else "┘")
            elif (x - grid_left) % cell_w == 0:
                char = "┼" if 0 < row < grid_rows else ("┬" if row == 0 else "┴")
            else:
                char = "─"
            put(x, y, char, fg=grid_color if row in {0, grid_rows} else dim_grid)

    for col in range(grid_cols + 1):
        x = grid_left + col * cell_w
        if x > grid_right:
            continue
        for y in range(grid_top + 1, grid_bottom):
            if (y - grid_top) % cell_h == 0:
                continue
            put(x, y, "│", fg=dim_grid)

    if width >= 74:
        put_text("[2 1; 1 1]", grid_left, max(0, grid_top - 1), fg=(255, 126, 154), max_width=16)
        put_text(BOOT_IDEOGRAPH_TEXT, max(grid_left + 16, grid_right - 12), max(0, grid_top - 1), fg=(184, 117, 255), max_width=12)

    active_cells: set[tuple[int, int]] = set()
    for seed in range(14):
        u = (seed * 3 + frame // 5) % grid_cols
        v = (seed * 5 + frame // 8) % grid_rows
        active_cells.add(((2 * u + v + frame // 11) % grid_cols, (u + v + frame // 13) % grid_rows))

    for row in range(grid_rows):
        for col in range(grid_cols):
            x0 = grid_left + col * cell_w + 1
            y0 = grid_top + row * cell_h + 1
            token = f"{(col * 7 + row * 11 + frame // 4) % 16:X}"
            if (col, row) in active_cells:
                put(x0, y0, "■", fg=hot_color, bold=True)
                if x0 + 1 < grid_right:
                    put(x0 + 1, y0, token, fg=(255, 232, 238), bold=True)
            elif (col + row + frame // 10) % 5 == 0:
                put(x0, y0, token, fg=(158, 36, 68))

    rail_start = min(rows - 2, grid_bottom + 2)
    for index in range(3):
        y = rail_start + index
        if y >= rows:
            continue
        for x in range(grid_left, grid_right + 1):
            mark = "─" if (x + index) % 2 == 0 else " "
            if mark != " ":
                put(x, y, mark, fg=dim_grid)
        packet = grid_left + int((frame * (0.2 + index * 0.07) + index * 5) % max(1, grid_right - grid_left))
        for x in range(packet, min(grid_right, packet + max(2, cell_w // 2))):
            put(x, y, "━", fg=hot_color, bold=True)

    title_center = int(width * (0.38 if width >= 74 else 0.50))
    title_y = max(2, int(rows * 0.44))
    title = "WUCI-JI"
    title_x = centered_x(title, title_center)
    clear_span(title_x - 3, title_y, display_width(title) + 6)
    put_text(title, title_x, title_y, fg=(255, 238, 245), bold=True)
    subtitle = "Wuci-Ji Systems Substrate"
    subtitle_x = centered_x(subtitle, title_center)
    clear_span(subtitle_x - 3, min(rows - 1, title_y + 2), display_width(subtitle) + 6)
    put_text(subtitle, subtitle_x, min(rows - 1, title_y + 2), fg=(255, 111, 143))

    if width >= 74:
        mode = f"NOXFRAME // {BOOT_IDEOGRAPH_TEXT}"
        mode_x = centered_x(mode, title_center)
        clear_span(mode_x - 2, min(rows - 1, title_y + 4), display_width(mode) + 4)
        put_text(mode, mode_x, min(rows - 1, title_y + 4), fg=(184, 117, 255), bold=True)
    else:
        ideograph_x = centered_x(BOOT_IDEOGRAPH_TEXT, title_center)
        clear_span(ideograph_x - 2, min(rows - 1, title_y + 4), display_width(BOOT_IDEOGRAPH_TEXT) + 4)
        put_text(BOOT_IDEOGRAPH_TEXT, ideograph_x, min(rows - 1, title_y + 4), fg=(184, 117, 255), bold=True)

    if prompt is not None:
        question = BOOT_VOICE_TEXT if prompt == BOOT_PROMPT else prompt.strip()
        prompt_field = int(width * 0.70) if width >= 74 else width
        prompt_width = min(prompt_field - 6, 56)
        prompt_lines = wrap_words(question, prompt_width)
        prompt_start = min(rows - len(prompt_lines) - 2, max(title_y + 6, int(rows * 0.70)))
        for index, line in enumerate(prompt_lines):
            line_x = centered_x(line, title_center)
            clear_span(line_x - 2, prompt_start + index, display_width(line) + 4)
            put_text(
                line,
                line_x,
                prompt_start + index,
                fg=(255, 215, 226),
            )
        input_text = f"[y/N] {answer}"
        input_x = centered_x(input_text, title_center)
        clear_span(input_x - 2, prompt_start + len(prompt_lines) + 1, display_width(input_text) + 4)
        put_text(
            input_text,
            input_x,
            prompt_start + len(prompt_lines) + 1,
            fg=(255, 80, 122),
            bold=True,
        )

    def render_line(row: list[Cell]) -> str:
        rendered: list[str] = []
        active: tuple[tuple[int, int, int] | None, tuple[int, int, int] | None, bool] | None = None
        for char, fg, bg, bold in row:
            style = (fg, bg, bold)
            if palette.enabled and style != active:
                if active is not None:
                    rendered.append("\x1b[0m")
                rendered.append(ansi_prefix(fg, bg, bold))
                active = style
            rendered.append(char)
        if palette.enabled and active is not None:
            rendered.append("\x1b[0m")
        return "".join(rendered)

    lines = [render_line(row) for row in canvas]

    if full_screen:
        sys.stderr.write("\033[2J\033[H" if clear_screen else "\033[H")
        for line in lines:
            sys.stderr.write(line + "\n")
        sys.stderr.flush()
        return

    for line in lines:
        sys.stderr.write(line + "\n")
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
        choices=("launch", "contract", "init", "status", "seal", "verify", "daylight-wrap"),
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
    parser.add_argument(
        "--daylight-wrap-out",
        default=DEFAULT_DAYLIGHT_WRAP_DIR,
        help="NOXFRAME Daylight wrap output directory, relative to the repository root unless absolute",
    )
    parser.add_argument(
        "--daylight-wrap-keyfile",
        help="local WJSEAL keyfile used by daylight-wrap; symlinks and hardlinks are rejected",
    )
    parser.add_argument(
        "--bin",
        default=os.environ.get("WUCI_JI_BIN", DEFAULT_WUCI_BIN),
        help="path to the wuci-ji binary for daylight-wrap; defaults to WUCI_JI_BIN or build/wuci-ji",
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
        "--boot-renderer",
        choices=("auto", "gui", "terminal"),
        default="auto",
        help="boot prompt renderer; auto selects a terminal profile, gui opens the local graphical canvas",
    )
    parser.add_argument(
        "--no-terminal-handoff",
        action="store_true",
        help="do not auto-open kitty from a generic interactive terminal",
    )
    parser.add_argument(
        "--no-boot-voice",
        action="store_true",
        help="disable the one-shot local voice prompt during interactive boot",
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
    parser.add_argument(
        "--allow-kaiju-boot",
        action="store_true",
        help="allow the NOXFRAME console kaiju boot command to launch non-graphical QEMU",
    )
    parser.add_argument(
        "--kaiju-qemu-bin",
        default=wuci_kaiju.DEFAULT_QEMU_BIN,
        help="QEMU executable for the opt-in WUCI-KAIJU non-graphical boot bridge",
    )
    parser.add_argument(
        "--kaiju-iso-root",
        default=str(wuci_kaiju.DEFAULT_ISO_ROOT),
        help="WUCI-KAIJU ISO workspace, relative to repository root unless absolute",
    )
    parser.add_argument(
        "--kaiju-disk-root",
        default=str(wuci_kaiju.DEFAULT_DISK_ROOT),
        help="WUCI-KAIJU disk workspace, relative to repository root unless absolute",
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


def reset_terminal_to_sane() -> None:
    """Force the terminal back to a sane state.
    This protects the boot splash aesthetic and console lattice from
    leftover modes, alt screens, hidden cursor, or raw mode left by
    takeovers like kaiju boot. Call early and on returns from full-screen
    guests.
    Does nothing (no output) if not attached to a tty.
    """
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        return
    sys.stdout.write("\033[?1049l\033[?25h\033[0m\033[?7h\033[r")
    sys.stdout.flush()
    try:
        fd = sys.stdin.fileno()
        attrs = termios.tcgetattr(fd)
        # Force canonical input + echo (sane for readline and our UI)
        attrs[3] |= (termios.ICANON | termios.ECHO)
        # Make sure ISIG is on for ctrl-c etc.
        attrs[3] |= termios.ISIG
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    except (OSError, termios.error):
        pass


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


def print_console_header(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    session: ConsoleSession | None = None,
) -> None:
    clock_path = repo_path(root, args.clock)
    state_path, seal_path = substrate_paths(root, args)
    clock_state = read_clock_state(clock_path)
    decision = resolve_profile(
        args.profile,
        clock_path=clock_path,
        state=clock_state,
        now=dt.datetime.now(dt.UTC),
    )
    theme = sync_session_lattice(session) if session is not None else depth_theme(0)
    print_console_line("WUCI-JI SYSTEMS / NOXFRAME CONSOLE", color=theme.header_color, palette=palette)
    print_console_line("bounded metadata console")
    print_console_line("route: root > wuci-ji > daylight")
    if session is not None:
        print_console_line(lattice_status_line(session), color=theme.accent_color, palette=palette)
        if session.xframe_count > 1:
            print_console_line(xframe_status_line(session), color=theme.accent_color, palette=palette)
    print_console_line(
        f"profile: requested={decision.requested_profile} effective={decision.effective_profile}"
    )
    print_console_line(f"state: {display_repo_path(root, state_path)}")
    print_console_line(f"seal: {display_repo_path(root, seal_path)}")
    if terminal_columns() >= 88:
        print_console_line(
            "commands: help --compact, man <cmd>, complete <prefix>, status, launch, self-release, clear, exit"
        )
    else:
        print_console_line("commands: help --compact, man <cmd>, complete")
        print_console_line("          status, launch, self-release, clear, exit")


def print_goodbye(palette: Palette) -> None:
    print(palette.paint("再见，黑客。", palette.yellow))
    print(palette.paint("Goodbye, Hacker.", palette.cyan))


def print_unavailable(spec: ConsoleCommandSpec) -> None:
    print(f"{command_display_name(spec)}: route disabled in NOXFRAME console")
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


def print_self_release_shell_header(session: ConsoleSession, palette: Palette) -> None:
    theme = sync_session_lattice(session)
    print(palette.paint("WUCI-JI / NOXFRAME self-release shell", theme.header_color))
    print("context: wuci-ji/self-release")
    print(f"cwd: {session.cwd}")
    print(palette.paint(lattice_status_line(session), theme.accent_color))
    print("commands: self-release plan, self-release status, self-release run all, exit")
    print("boundary: nested metadata console; no host shell route")


def run_self_release_shell(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    parent: ConsoleSession,
) -> bool:
    nested = ConsoleSession(cwd="/wuci-ji")
    nested.env.update(parent.env)
    nested.env["NOXFRAME_PARENT_CONTEXT"] = parent.env.get("NOXFRAME_CONTEXT", "root")
    nested.env["NOXFRAME_CONTEXT"] = "wuci-ji/self-release"
    nested.env["NOXFRAME_MODE"] = "self-release-metadata-console"
    nested.env["SHELL"] = "noxframe:self-release"
    nested.env["PWD"] = nested.cwd
    set_session_depth(nested, console_depth(parent) + 1)
    nested.aliases.update(parent.aliases)
    readline_state = install_console_readline(nested)
    print_self_release_shell_header(nested, palette)
    try:
        while True:
            try:
                theme = sync_session_lattice(nested)
                line = input(readline_prompt(prompt_for_session(nested), theme.prompt_color, palette))
            except EOFError:
                print()
                print("self-release shell: return to parent")
                return False
            raw = line.strip()
            if not raw:
                continue
            nested.history.append(raw)
            if len(nested.history) > 512:
                del nested.history[:-512]
            record_console_event(nested, raw)
            keep_running = dispatch_console_line(root, args, palette, nested, raw)
            if not keep_running:
                if nested.env.get("NOXFRAME_EXIT_ALL") == "1":
                    print("self-release shell: exit all requested")
                    return True
                print("self-release shell: return to parent")
                return False
    finally:
        restore_console_readline(readline_state)


def handle_self_release_command(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    session: ConsoleSession,
    parts: list[str],
) -> None:
    subcommand = parts[1].lower() if len(parts) > 1 else "plan"
    if subcommand == "plan":
        print(self_release_plan_text(), end="")
        return
    if subcommand == "status":
        print(self_release_status_text(root), end="")
        return
    if subcommand == "shell":
        old_context = session.env.get("NOXFRAME_CONTEXT", "root")
        old_self_release = session.env.get("NOXFRAME_SELF_RELEASE", "ready")
        old_cwd = session.cwd
        session.env["NOXFRAME_SELF_RELEASE"] = "shell"
        exit_all = run_self_release_shell(root, args, palette, session)
        session.env["NOXFRAME_CONTEXT"] = old_context
        session.env["NOXFRAME_SELF_RELEASE"] = old_self_release
        session.cwd = old_cwd
        session.env["PWD"] = session.cwd
        sync_session_lattice(session)
        if exit_all:
            session.env["NOXFRAME_EXIT_ALL"] = "1"
        return
    if subcommand in {"bundle", "witness", "ledger", "all"}:
        selection_name = subcommand
    elif subcommand == "run":
        selection_name = parts[2].lower() if len(parts) > 2 else "all"
    else:
        print("usage: self-release [plan|status|run bundle|run witness|run ledger|run all|shell]")
        return

    selected = self_release_lane_selection(selection_name)
    if selected is None:
        print("usage: self-release run bundle|witness|ledger|all")
        return

    session.env["NOXFRAME_CONTEXT"] = "wuci-ji/self-release"
    session.env["NOXFRAME_SELF_RELEASE"] = "running"
    results: list[StepResult] = []
    for lane in selected:
        step = Step(
            signal="SELF RELEASE...",
            label=lane.label,
            command=self_release_lane_command(lane),
            note="Run the existing Wuci-Ji self-release proof lane in the NOXFRAME workspace.",
        )
        result = run_step(step, root, palette)
        results.append(result)
        if result.returncode != 0:
            break

    ok = bool(results) and all(result.returncode == 0 for result in results)
    session.env["NOXFRAME_SELF_RELEASE"] = "pass" if ok else "fail"
    print(f"self-release-result: {0 if ok else 1}")
    print(self_release_status_text(root), end="")


def handle_phase_command(
    session: ConsoleSession,
    args: argparse.Namespace,
    parts: list[str],
) -> None:
    invoked = parts[0].lower()
    if invoked in {"whereami", "compass", "optics"} and len(parts) == 1:
        action = {"whereami": "whereami", "compass": "compass", "optics": "compass"}[invoked]
    else:
        action = parts[1].lower() if len(parts) > 1 else "whereami"
    print(phase_text(session, args, action), end="")


def handle_learn_command(session: ConsoleSession, parts: list[str]) -> None:
    action = parts[1].lower() if len(parts) > 1 else "status"
    if action == "status":
        print(learn_status_text(session), end="")
        return
    if action in {"list", "show"}:
        print(learn_notes_text(session), end="")
        return
    if action == "add":
        note = " ".join(parts[2:]).strip()
        if not note:
            print("usage: learn add <text>")
            return
        session.notes.append(fit_display(note, 240))
        if len(session.notes) > 64:
            del session.notes[:-64]
        print(f"learn: stored session note {len(session.notes)}")
        return
    if action == "clear":
        session.notes.clear()
        print("learn: cleared session notes")
        return
    print("usage: learn [status|list|show|add <text>|clear]")


def handle_plugin_command(command: str, parts: list[str]) -> None:
    action = parts[1].lower() if len(parts) > 1 else "list"
    if action in {"list", "status", "inspect"}:
        print(plugin_catalog_text(), end="")
        return
    if action == "policy":
        print(plugin_policy_text(), end="")
        return
    if action == "run":
        print(f"{command}: plugin execution is unavailable in NOXFRAME console")
        print("scope: catalog and policy metadata only; no host module runtime is opened")
        return
    print(f"usage: {command} [list|status|inspect|policy|run]")


def handle_nest_command(session: ConsoleSession, parts: list[str]) -> None:
    action = parts[1].lower() if len(parts) > 1 else "status"
    if action in {"status", "info"}:
        print(nest_status_text(session), end="")
        return
    if action == "list":
        print(nest_list_text(), end="")
        return
    if action == "tree":
        print(nest_tree_text(session), end="")
        return
    if action in {"memory", "memory-map"}:
        print(substrate_memory_text(session), end="")
        return
    if action in {"lock-policy", "locks"}:
        print(substrate_lock_policy_text(), end="")
        return
    if action == "inspect":
        context = parts[2].lower() if len(parts) > 2 else session.env.get("NOXFRAME_CONTEXT", "root")
        print(nest_inspect_text(context), end="")
        return
    if action == "enter":
        if len(parts) < 3:
            print("usage: nest enter <context>")
            return
        context = parts[2].lower()
        if context_record(context) is None:
            print(f"nest: unknown context: {context}")
            return
        session.env["NOXFRAME_CONTEXT"] = context
        session.cwd = f"/{context}"
        session.env["PWD"] = session.cwd
        print(f"nest: entered {context}")
        return
    if action in {"spawn", "destroy"}:
        print(f"nest {action}: unavailable in NOXFRAME console")
        print("scope: nested contexts are fixed metadata cells")
        return
    print("usage: nest [status|list|enter <context>|inspect <context>|tree|memory|lock-policy|info]")


def vfs_mutation_target(session: ConsoleSession, cwd: str, value: str) -> str:
    path = vfs_normalize(cwd, value)
    if path == "/":
        raise NoxframeError("vfs: refusing to mutate root")
    if path.endswith("/"):
        path = path.rstrip("/")
    if vfs_static_path(path):
        raise NoxframeError(f"vfs: refusing to mutate static path: {path}")
    parent = vfs_parent(path)
    if not vfs_is_dir(parent, session):
        raise NoxframeError(f"vfs: parent is not a virtual directory: {parent}")
    return path


def vfs_destination_path(session: ConsoleSession, cwd: str, source: str, dest: str) -> str:
    dest_path = vfs_normalize(cwd, dest)
    if vfs_is_dir(dest_path, session):
        dest_path = f"{dest_path.rstrip('/')}/{vfs_name(source)}"
    return vfs_mutation_target(session, "/", dest_path)


def vfs_rm_session_path(session: ConsoleSession, path: str) -> None:
    if vfs_static_path(path):
        raise NoxframeError(f"rm: refusing static virtual path: {path}")
    if path in session.vfs_files:
        del session.vfs_files[path]
        print(f"rm: removed {path}")
        return
    if path in session.vfs_dirs:
        prefix = f"{path.rstrip('/')}/"
        if any(candidate.startswith(prefix) for candidate in session.vfs_dirs | set(session.vfs_files)):
            raise NoxframeError(f"rm: virtual directory not empty: {path}")
        session.vfs_dirs.remove(path)
        print(f"rm: removed {path}/")
        return
    raise NoxframeError(f"rm: no session-local virtual path: {path}")


def vfs_move_session_path(session: ConsoleSession, source: str, dest: str) -> None:
    if vfs_static_path(source):
        raise NoxframeError(f"mv: refusing static virtual source: {source}")
    if vfs_static_path(dest) or dest in session.vfs_files or dest in session.vfs_dirs:
        raise NoxframeError(f"mv: refusing to overwrite existing virtual path: {dest}")
    if source in session.vfs_files:
        session.vfs_files[dest] = session.vfs_files.pop(source)
        print(f"mv: {source} -> {dest}")
        return
    if source in session.vfs_dirs:
        if dest.startswith(f"{source.rstrip('/')}/"):
            raise NoxframeError("mv: refusing to move a directory into itself")
        moved_dirs: dict[str, str] = {}
        moved_files: dict[str, tuple[str, str]] = {}
        prefix = f"{source.rstrip('/')}/"
        for directory in sorted(session.vfs_dirs):
            if directory == source or directory.startswith(prefix):
                moved_dirs[directory] = dest + directory[len(source) :]
        for file_path, text in list(session.vfs_files.items()):
            if file_path.startswith(prefix):
                moved_files[file_path] = (dest + file_path[len(source) :], text)
        for old in moved_dirs:
            session.vfs_dirs.remove(old)
        for old in moved_files:
            del session.vfs_files[old]
        session.vfs_dirs.update(moved_dirs.values())
        for new, text in moved_files.values():
            session.vfs_files[new] = text
        print(f"mv: {source}/ -> {dest}/")
        return
    raise NoxframeError(f"mv: no session-local virtual path: {source}")


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
        is_dir, entries = vfs_list(path, session)
        if is_dir:
            print("\n".join(entries))
        else:
            print(entries[0])
        return
    if command == "cd":
        path = vfs_normalize(session.cwd, parts[1] if len(parts) > 1 else "/")
        if not vfs_is_dir(path, session):
            print(f"cd: not a virtual directory: {path}")
            return
        session.cwd = path
        session.env["PWD"] = path
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
        print_vfs_tree(path, session)
        return
    if command == "echo":
        if ">" in parts or ">>" in parts:
            print("echo: redirect writes are not available in the NOXFRAME VFS")
            return
        print(" ".join(parts[1:]))
        return
    if command == "mkdir":
        if len(parts) != 2:
            print("usage: mkdir <dir>")
            return
        path = vfs_mutation_target(session, session.cwd, parts[1])
        if path in session.vfs_files:
            print(f"mkdir: virtual file exists: {path}")
            return
        session.vfs_dirs.add(path)
        print(f"mkdir: created {path}/")
        return
    if command == "touch":
        if len(parts) != 2:
            print("usage: touch <file>")
            return
        path = vfs_mutation_target(session, session.cwd, parts[1])
        if path in session.vfs_dirs:
            print(f"touch: virtual directory exists: {path}")
            return
        session.vfs_files.setdefault(path, "")
        print(f"touch: {path}")
        return
    if command == "rm":
        if len(parts) != 2:
            print("usage: rm <path>")
            return
        path = vfs_normalize(session.cwd, parts[1])
        vfs_rm_session_path(session, path)
        return
    if command == "cp":
        if len(parts) != 3:
            print("usage: cp <src> <dst>")
            return
        src = vfs_normalize(session.cwd, parts[1])
        if vfs_is_dir(src, session):
            print(f"cp: refusing directory source: {src}")
            return
        text = virtual_file_text(root, args, session, src)
        dest = vfs_destination_path(session, session.cwd, src, parts[2])
        if dest in session.vfs_dirs:
            print(f"cp: destination is a directory: {dest}")
            return
        session.vfs_files[dest] = text
        print(f"cp: {src} -> {dest}")
        return
    if command == "mv":
        if len(parts) != 3:
            print("usage: mv <src> <dst>")
            return
        src = vfs_normalize(session.cwd, parts[1])
        dest = vfs_destination_path(session, session.cwd, src, parts[2])
        vfs_move_session_path(session, src, dest)
        return


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
    if command == "wiki":
        print(wiki_text(parts[1] if len(parts) > 1 else None), end="")
        return
    if command == "find":
        start = vfs_normalize(session.cwd, parts[1] if len(parts) > 1 and not parts[1].startswith("-") else None)
        needle = ""
        if "-name" in parts:
            index = parts.index("-name")
            if index + 1 < len(parts):
                needle = parts[index + 1].strip("*")
        for path in vfs_all_paths(session):
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


def parse_virtual_pid(value: str) -> int | None:
    try:
        pid = int(value, 10)
    except ValueError:
        return None
    return pid if pid > 0 else None


def handle_proc_command(session: ConsoleSession, command: str, parts: list[str]) -> None:
    if command == "ps":
        print(console_process_table(session), end="")
    elif command == "top":
        rows = console_process_rows(session)
        ready = sum(1 for _, state, _, _ in rows if state in {"ready", "foreground", "background"})
        idle = sum(1 for _, state, _, _ in rows if state == "idle")
        print(f"tasks: {len(rows)} total, {ready} ready, {idle} idle")
        print("load: metadata-only  memory: virtual")
    elif command == "jobs":
        if not session.jobs:
            print("jobs: no console background jobs")
            return
        for pid in sorted(session.jobs):
            job = session.jobs[pid]
            print(f"{pid:<4} {job.get('state', 'ready'):<11} {job.get('name', 'job')}")
    elif command == "spawn":
        name = fit_display(" ".join(parts[1:]).strip() or "job", 64)
        if not re.fullmatch(r"[A-Za-z0-9_.:@/+ -]{1,64}", name):
            print("spawn: invalid virtual process name")
            return
        pid = session.next_pid
        session.next_pid += 1
        session.jobs[pid] = {"state": "ready", "name": name, "priority": "0"}
        print(f"spawn: pid={pid} name={name}")
    elif command in {"fg", "bg", "kill"}:
        if len(parts) != 2:
            print(f"usage: {command} <pid>")
            return
        pid = parse_virtual_pid(parts[1])
        if pid is None or pid not in session.jobs:
            print(f"{command}: no session-local process: {parts[1]}")
            return
        state = {"fg": "foreground", "bg": "background", "kill": "terminated"}[command]
        session.jobs[pid]["state"] = state
        print(f"{command}: pid={pid} state={state}")
    elif command == "nice":
        if len(parts) != 3:
            print("usage: nice <pid> <priority>")
            return
        pid = parse_virtual_pid(parts[1])
        try:
            priority = int(parts[2], 10)
        except ValueError:
            print("nice: priority must be an integer")
            return
        if pid is None or pid not in session.jobs:
            print(f"nice: no session-local process: {parts[1]}")
            return
        priority = max(-20, min(19, priority))
        session.jobs[pid]["priority"] = str(priority)
        print(f"nice: pid={pid} priority={priority}")


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
        print(f"noxframe-vfs      {len(vfs_all_paths(session))}     /")
        print("noxframe-docs      6     /docs")
        print("noxframe-env       5     /env")
        print("noxframe-phase     5     /phase")
        print("noxframe-learn     2     /learn")
        print("noxframe-nests     3     /nests")
        return
    if command == "dmesg":
        print("noxframe: responsive Wuci-Ji Systems banner initialized")
        print("noxframe: substrate state/seal paths loaded")
        print("noxframe: Phase1 command registry mapped into bounded console")
        print("noxframe: Optics, nests, learn, plugins, and quality rails loaded")
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
    if command == "doctor":
        print(doctor_text(root, args, session), end="")
        return
    if command == "selftest":
        print(selftest_text(session), end="")
        return
    if command == "quality":
        print(quality_text(), end="")
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
        print(f"cr3: {session.env.get('NOXFRAME_CR3', '0x0000000000002000')} (virtual)")
        return
    if command == "loadcr3":
        if len(parts) != 2:
            print("usage: loadcr3 <value>")
            return
        value = parts[1].lower()
        if value.startswith("0x"):
            digits = value[2:]
        else:
            digits = value
            value = f"0x{value}"
        if not digits or not re.fullmatch(r"[0-9a-f]+", digits):
            print("loadcr3: value must be hexadecimal")
            return
        session.env["NOXFRAME_CR3"] = value
        print(f"loadcr3: {value}")
        return
    if command == "cr4":
        pcide = session.env.get("NOXFRAME_PCIDE", "off")
        print(f"cr4: pcide={pcide} pae=on pse=on (virtual)")
        return
    if command == "pcide":
        if len(parts) != 2 or parts[1].lower() not in {"on", "off"}:
            print("usage: pcide on|off")
            return
        session.env["NOXFRAME_PCIDE"] = parts[1].lower()
        print(f"pcide: {parts[1].lower()}")
        return
    print(f"{command}: virtual hardware mutation is unavailable")


def handle_xframe_command(session: ConsoleSession, command: str, parts: list[str]) -> None:
    if command == "xframe-split":
        if len(parts) == 1:
            print(xframe_status_text(session), end="")
            return
        try:
            count = int(parts[1], 10)
        except ValueError:
            print("usage: xframe-split <2|3|4>")
            return
        if count == 1:
            dropped = xframe_resize(session, 1)
            print(xframe_status_text(session, action="split", dropped=dropped), end="")
            return
        if not 2 <= count <= XFRAME_MAX:
            print(f"xframe-split: count must be 2, 3, or {XFRAME_MAX}")
            return
        xframe_resize(session, count)
        print(xframe_status_text(session, action="split"), end="")
        return
    if command == "xframe-next":
        xframe_next(session)
        print(xframe_status_text(session, action="switch"), end="")
        return
    if command == "xframe-drop":
        dropped = xframe_drop(session, parts[1] if len(parts) > 1 else "1")
        print(xframe_status_text(session, action="drop", dropped=dropped), end="")
        return


def handle_user_command(
    session: ConsoleSession,
    args: argparse.Namespace,
    command: str,
    parts: list[str],
) -> None:
    if command in {"xframe-split", "xframe-next", "xframe-drop"}:
        handle_xframe_command(session, command, parts)
        return
    if command == "env":
        sync_session_env(session, args)
        print(console_env_text(session), end="")
        return
    if command == "set":
        if len(parts) == 1:
            sync_session_env(session, args)
            print(console_env_text(session), end="")
            return
        if parts[1] == "-o":
            print(console_option_text(), end="")
            return
        assignment = parse_assignment(parts[1:])
        if assignment is None:
            print("usage: set [KEY=value|-o]")
            return
        key, value = assignment
        set_session_env(session, key, value)
        return
    if command == "export":
        assignment = parse_assignment(parts[1:])
        if assignment is None:
            print("usage: export KEY=value")
            return
        key, value = assignment
        set_session_env(session, key, value)
        return
    if command == "unset":
        if len(parts) != 2:
            print("usage: unset KEY")
            return
        if not valid_env_key(parts[1]):
            print("unset: invalid key")
            return
        session.env.pop(parts[1], None)
        return
    if command == "alias":
        if len(parts) == 1:
            print(console_alias_text(session), end="")
            return
        error = set_session_alias(session, " ".join(parts[1:]))
        if error is not None:
            print(error)
        return
    if command == "unalias":
        if len(parts) != 2:
            print("usage: unalias NAME")
            return
        session.aliases.pop(parts[1], None)
        return
    if command == "which":
        if len(parts) != 2:
            print("usage: which <command>")
            return
        print(command_which_text(parts[1]), end="")
        return
    if command == "profile":
        print(console_profile_text(session, args), end="")
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
        print("banner: responsive Wuci-Ji lattice boot frame")
        print(f"inner-width: {banner_inner_width()}")
        return
    if command == "tips":
        print("try: help --compact")
        print("try: ls /proc && cat /proc/cells")
        print("try: status && verify")
        return


def handle_network_command(command: str, parts: list[str]) -> None:
    if command == "ifconfig":
        print("ifconfig: nox0 flags=UP,LOOPBACK,METADATA mtu 65536")
        print("        inet 127.0.0.1  netmask 255.0.0.0")
        print("        policy metadata-deny; no host network interface is opened by this command")
        return
    if command == "iwconfig":
        print("iwconfig: no wireless extensions in NOXFRAME metadata console")
        return
    if command == "wifi-scan":
        print("wifi-scan: skipped; no host radio access")
        return
    if command == "wifi-connect":
        ssid = " ".join(parts[1:]).strip() or "(missing)"
        if ssid == "(missing)":
            print("usage: wifi-connect <ssid>")
            return
        print(f"wifi-connect: denied by NOXFRAME policy; ssid={fit_display(ssid, 80)}")
        return
    if command == "ping":
        host = parts[1] if len(parts) > 1 else "(missing)"
        if host == "(missing)":
            print("usage: ping <host>")
            return
        print(f"ping: no packets sent; host={fit_display(host, 120)}; policy=metadata-deny")
        return
    if command == "nmcli":
        print("nmcli: virtual NetworkManager state disconnected")
        print("policy: metadata-only; no host network mutation by this command")
        return


def host_dry_run_text(root: Path, command: str, parts: list[str]) -> str:
    argv = " ".join(shlex.quote(part) for part in parts[1:]) or "(none)"
    if command == "git":
        return "\n".join(
            [
                "git: metadata-only; host git argv not executed",
                f"repo: {root}",
                f"branch: {git_value(root, 'branch', '--show-current')}",
                f"commit: {git_value(root, 'rev-parse', '--short', 'HEAD')}",
                f"requested-args: {argv}",
                "",
            ]
        )
    if command == "gh":
        return "\n".join(
            [
                "gh: metadata-only; GitHub CLI argv not executed",
                "network: no API request made",
                f"requested-args: {argv}",
                "",
            ]
        )
    recommendations = {
        "cargo": "use repository Rust/Daylight make targets outside NOXFRAME when needed",
        "rustc": "use make targets or cargo outside NOXFRAME when needed",
        "python3": "use make noxframe-launch-test or python3 from the host shell outside NOXFRAME",
        "python": "use make noxframe-launch-test or python3 from the host shell outside NOXFRAME",
        "go": "use host Go tooling outside NOXFRAME when a reviewed lane needs it",
        "gcc": "use existing assembly/C build lanes outside NOXFRAME when needed",
    }
    return "\n".join(
        [
            f"{command}: dry-run route; host executable not launched",
            f"requested-args: {argv}",
            f"guidance: {recommendations.get(command, 'run from the host shell outside NOXFRAME when needed')}",
            "",
        ]
    )


def handle_dev_or_host_command(
    root: Path,
    args: argparse.Namespace,
    session: ConsoleSession,
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
    if command == "browser":
        target = parts[1] if len(parts) > 1 else "about"
        if target == "about":
            print("browser: metadata-only local route")
            print("home: /docs/wiki")
            print("network: no URL fetch")
        else:
            print(f"browser: metadata-only URL route target={fit_display(target, 160)}")
            print("network: fetch skipped by NOXFRAME policy")
        return
    if command in {"git", "gh", "cargo", "rustc", "python3", "go", "python", "gcc"}:
        print(host_dry_run_text(root, command, parts), end="")
        return
    if command == "avim":
        if len(parts) != 2:
            print("usage: avim <file>")
            return
        path = vfs_normalize(session.cwd, parts[1])
        try:
            text = virtual_file_text(root, args, session, path)
        except NoxframeError as exc:
            print(f"avim: {exc}")
            return
        print(f"avim: read-only virtual preview {path}")
        for line_no, line in enumerate(text.splitlines()[:20], start=1):
            print(f"{line_no:4d}  {line}")
        if len(text.splitlines()) > 20:
            print("... truncated")
        return
    if command == "dev":
        print("dev: self-development lane metadata")
        print(f"workspace: {root}")
        print("host_exec: disabled; use explicit proof lanes or Codex bridge")
        return
    if command == "repo":
        print("repo: main line with NOXFRAME as Wuci-Ji substrate surface")
        print("channels: main, proof lanes, generated build evidence")
        return
    if command == "fyr":
        print("fyr: lineage carried as small-language and command-surface discipline")
        print("runtime: not embedded in NOXFRAME")
        return
    if command == "base1":
        action = parts[1].lower() if len(parts) > 1 else "status"
        print(base1_text(action), end="")
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
        print("matrix: use the responsive lattice boot frame; animation is not run inside tests")
        return True
    if command == "bootcfg":
        print(f"profile: {args.profile}")
        print(f"clock: {repo_path(root, args.clock)}")
        return True
    if command == "version":
        if len(parts) > 1 and parts[1] == "--compare":
            print(f"{TOOL_NAME} substrate-contract={SUBSTRATE_SPEC_SCHEMA}")
            print("phase1-source: https://github.com/Bryforge/phase1")
            print("phase1-code-import: no")
            print("implemented-ideas: " + ", ".join(name for name, _ in PHASE1_FEATURES))
            print("boundary: WUCI-native metadata substrate, not Phase1 kernel code")
            return True
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
        handle_nest_command(session, parts)
        return True
    if command == "multi":
        print("usage: multi <command> ; <command> ...")
        print("example: multi phase compass ; nest tree ; nest enter gate ; phase whereami")
        print("separator: semicolon outside quotes; commands remain NOXFRAME registry commands")
        return True
    if command == "exit":
        return False
    return True


def dispatch_console_line(
    root: Path,
    args: argparse.Namespace,
    palette: Palette,
    session: ConsoleSession,
    raw: str,
) -> bool:
    normalized_raw = normalize_console_input_markers(normalize_xframe_switch_input(raw))
    for segment in split_console_multicommands(normalized_raw):
        try:
            parts = shlex.split(segment)
        except ValueError as exc:
            print(f"parse error: {exc}")
            continue
        if not parts:
            continue
        parts = expand_session_alias(session, parts)
        if parts and parts[0] in {"multi", "batch", "script"} and len(parts) > 1:
            parts = parts[1:]
        try:
            keep_running = dispatch_console_command(root, args, palette, session, parts)
        except NoxframeError as exc:
            print(str(exc))
            continue
        if not keep_running:
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
        print_console_header(root, args, palette, session)
        return True
    if command == "exit":
        if len(parts) > 1 and parts[1].lower() in {"all", "--all", "-a"}:
            session.env["NOXFRAME_EXIT_ALL"] = "1"
            print("exit: all NOXFRAME levels requested")
        print_goodbye(palette)
        return False
    if command in {"status", "seal", "verify", "contract", "launch", "self-release"}:
        if command == "status":
            command_status(root, args)
        elif command == "seal":
            command_seal(root, args)
        elif command == "verify":
            command_verify(root, args)
        elif command == "contract":
            command_contract()
        elif command == "launch":
            handle_launch_command(root, args, palette, parts)
        else:
            handle_self_release_command(root, args, palette, session, parts)
            if session.env.get("NOXFRAME_EXIT_ALL") == "1":
                return False
        return True
    if spec.category == "phase":
        handle_phase_command(session, args, parts)
        return True
    if spec.guard == "unavailable":
        print_unavailable(spec)
        return True
    if spec.category == "fs":
        handle_vfs_command(root, args, session, command, parts)
    elif spec.category == "text":
        handle_text_command(root, args, session, command, parts)
    elif spec.category == "proc":
        handle_proc_command(session, command, parts)
    elif spec.category == "sys":
        handle_sys_command(root, args, session, command, parts)
    elif spec.category == "user":
        handle_user_command(session, args, command, parts)
    elif spec.category == "learn":
        handle_learn_command(session, parts)
    elif spec.category == "plugin":
        if command == "kaiju":
            handle_kaiju_command(root, args, parts)
        else:
            handle_plugin_command(command, parts)
    elif spec.category == "net":
        handle_network_command(command, parts)
    elif spec.category in {"host", "dev"}:
        handle_dev_or_host_command(root, args, session, command, parts)
    elif spec.category == "misc":
        return handle_misc_command(root, args, session, command, parts)
    return True


def run_operator_console(root: Path, args: argparse.Namespace, palette: Palette) -> int:
    state_path, seal_path = substrate_paths(root, args)
    ensure_substrate(root, state_path=state_path, seal_path=seal_path)
    session = ConsoleSession()
    sync_session_env(session, args)
    readline_state = install_console_readline(session)
    # Extra reset on entering the console to guarantee clean state for
    # the lattice, prompts, and any re-entries after guest sessions.
    # Does not affect the initial boot splash (which happens before this).
    reset_terminal_to_sane()
    clear_screen()
    print_console_header(root, args, palette, session)
    try:
        while True:
            try:
                theme = sync_session_lattice(session)
                line = input(readline_prompt(prompt_for_session(session), theme.prompt_color, palette))
            except EOFError:
                print()
                print_goodbye(palette)
                return 0
            raw = normalize_xframe_switch_input(line.strip())
            if not raw:
                continue
            session.history.append(raw)
            if len(session.history) > 512:
                del session.history[:-512]
            record_console_event(session, raw)
            keep_running = dispatch_console_line(root, args, palette, session, raw)
            if not keep_running:
                return 0
    finally:
        restore_console_readline(readline_state)


def main() -> int:
    args = parse_args()
    root = repo_root()
    report_path = repo_path(root, args.report)
    seal_path = repo_path(root, args.seal)
    clock_path = repo_path(root, args.clock)
    palette = Palette(args.color)

    # Always reset terminal state at the very start. This ensures the
    # beloved boot splash (animation, lattice, voice, banners, cursor, modes)
    # always looks pristine, even if a previous kaiju guest session or
    # other takeover left the tty in a weird state.
    reset_terminal_to_sane()

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
    if args.command == "daylight-wrap":
        try:
            return command_daylight_wrap(root, args)
        except NoxframeError as exc:
            sys.stderr.write(f"{exc}\n")
            return 1

    if maybe_open_mechanics_terminal(root, args, palette):
        return 0

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
