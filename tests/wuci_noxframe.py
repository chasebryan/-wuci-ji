#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_LAUNCHER = REPO / "tools" / "wuci-noxframe"
sys.path.insert(0, str(REPO / "tools"))
import wuci_black_ice  # noqa: E402


def display_width(text: str) -> int:
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return width


def strip_ansi(text: str) -> str:
    return wuci_black_ice.ANSI_RE.sub("", text)


def assert_public_anchor_rejections(tmp: Path) -> None:
    regular = tmp / "regular.txt"
    regular.write_text("anchor\n", encoding="utf-8")
    record = wuci_black_ice.anchor_record(tmp, "regular.txt")
    assert record["path"] == "regular.txt"
    assert record["digest_vector"]["sha256"]
    assert record["digest_vector"]["sha384"]
    assert record["digest_vector"]["sha512"]

    if hasattr(os, "symlink"):
        link = tmp / "anchor-link.txt"
        link.symlink_to(regular)
        try:
            wuci_black_ice.anchor_record(tmp, "anchor-link.txt")
        except wuci_black_ice.NoxframeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink anchor was accepted")

    if hasattr(os, "link"):
        hard_source = tmp / "hard-source.txt"
        hard_link = tmp / "hard-link.txt"
        hard_source.write_text("hard anchor\n", encoding="utf-8")
        try:
            os.link(hard_source, hard_link)
        except OSError:
            return
        try:
            wuci_black_ice.anchor_record(tmp, "hard-source.txt")
        except wuci_black_ice.NoxframeError as exc:
            assert "hardlinked" in str(exc)
        else:
            raise AssertionError("hardlinked anchor was accepted")


def assert_optional_dependency_preflight() -> None:
    step = wuci_black_ice.Step(
        "OPTIONAL...",
        "optional dependency fixture",
        ("make", "optional-target"),
        "Synthetic optional dependency check.",
        ("wuci_noxframe_missing_optional_module",),
    )
    assert wuci_black_ice.missing_python_modules(step) == (
        "wuci_noxframe_missing_optional_module",
    )


def assert_boot_voice_selection() -> None:
    text = wuci_black_ice.BOOT_VOICE_TEXT
    assert wuci_black_ice.boot_voice_command(text, {}) is None
    assert wuci_black_ice.boot_voice_command(
        text,
        {"espeak-ng": "/usr/bin/espeak-ng"},
    ) == ("/usr/bin/espeak-ng", "-v", "en+f3", "-s", "145", text)
    assert wuci_black_ice.boot_voice_command(
        text,
        {"spd-say": "/usr/bin/spd-say", "espeak-ng": "/usr/bin/espeak-ng"},
    ) == ("/usr/bin/spd-say", "-t", "female1", "-r", "-20", text)
    no_voice = argparse.Namespace(yes=False, no_boot_prompt=False, no_boot_voice=True)
    assert not wuci_black_ice.boot_voice_active(no_voice)
    terminal_renderer = argparse.Namespace(
        yes=False,
        no_boot_prompt=False,
        no_boot_animation=False,
        boot_renderer="terminal",
    )
    assert not wuci_black_ice.boot_gui_candidate(terminal_renderer)
    gui_renderer = argparse.Namespace(
        yes=False,
        no_boot_prompt=False,
        no_boot_animation=False,
        boot_renderer="gui",
    )
    assert wuci_black_ice.boot_gui_candidate(gui_renderer) == sys.stdin.isatty()

    kitty = wuci_black_ice.detect_boot_terminal({"TERM": "xterm-kitty", "KITTY_WINDOW_ID": "1"})
    assert kitty.name == "kitty"
    assert kitty.rich_animation
    tmux = wuci_black_ice.detect_boot_terminal({"TERM": "screen-256color", "TMUX": "/tmp/tmux"})
    assert tmux.name == "tmux"
    assert tmux.reduced_motion
    remote = wuci_black_ice.detect_boot_terminal({"TERM": "xterm-256color", "SSH_CONNECTION": "1"})
    assert remote.name == "remote"
    assert remote.reduced_motion
    dumb = wuci_black_ice.detect_boot_terminal({"TERM": "dumb"})
    assert dumb.name == "dumb"
    assert dumb.reduced_motion


def noxframe_args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "command": "launch",
        "no_console": False,
        "boot_renderer": "auto",
        "no_terminal_handoff": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def assert_mechanics_terminal_handoff() -> None:
    generic_env = {"TERM": "xterm-256color", "DISPLAY": ":0"}
    kitty_env = {"TERM": "xterm-kitty", "KITTY_WINDOW_ID": "1", "DISPLAY": ":0"}
    ghostty = wuci_black_ice.detect_boot_terminal(
        {"TERM": "xterm-256color", "TERM_PROGRAM": "ghostty", "DISPLAY": ":0"}
    )
    assert ghostty.name == "ghostty"
    assert ghostty.rich_animation

    assert wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env=generic_env,
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env=kitty_env,
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(boot_renderer="terminal"),
        env=generic_env,
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(no_console=True),
        env=generic_env,
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env=generic_env,
        stdin_tty=False,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env={"TERM": "xterm-256color"},
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env={"TERM": "screen-256color", "TMUX": "/tmp/tmux", "DISPLAY": ":0"},
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env={"TERM": "xterm-256color", "SSH_CONNECTION": "1", "DISPLAY": ":0"},
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert not wuci_black_ice.should_handoff_to_mechanics_terminal(
        noxframe_args(),
        env={**generic_env, wuci_black_ice.TERMINAL_HANDOFF_ENV: "1"},
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )

    argv = (str(DEFAULT_LAUNCHER), "--console")
    command = wuci_black_ice.mechanics_terminal_handoff_command(
        REPO,
        noxframe_args(),
        env=generic_env,
        command_paths={"kitty": "/usr/bin/kitty"},
        argv=argv,
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    )
    assert command == (
        "/usr/bin/kitty",
        "--title",
        "WUCI-NOXFRAME",
        "--working-directory",
        str(REPO),
        str(DEFAULT_LAUNCHER),
        "--console",
    )
    assert wuci_black_ice.mechanics_terminal_handoff_command(
        REPO,
        noxframe_args(),
        env=generic_env,
        command_paths={"kitty": None},
        argv=argv,
        stdin_tty=True,
        stdout_tty=True,
        stderr_tty=True,
    ) is None


def assert_console_multicommand_logic() -> None:
    assert wuci_black_ice.split_console_multicommands(
        "phase compass ; nest tree ; nest enter gate"
    ) == ["phase compass", "nest tree", "nest enter gate"]
    assert wuci_black_ice.split_console_multicommands(
        "echo 'a; b' ; phase whereami"
    ) == ["echo 'a; b'", "phase whereami"]


def assert_clock_decisions(tmp: Path) -> None:
    clock = tmp / "clock.json"
    now = dt.datetime(2026, 6, 29, 12, 0, 0, tzinfo=dt.UTC)

    fresh = wuci_black_ice.resolve_profile(
        "auto",
        clock_path=clock,
        state={},
        now=now,
    )
    assert fresh.effective_profile == "smoke"
    assert fresh.seconds_until_full == 7 * 24 * 60 * 60
    assert "clock initialized" in fresh.reason

    recent_anchor = now - dt.timedelta(days=2)
    recent = wuci_black_ice.resolve_profile(
        "auto",
        clock_path=clock,
        state={"schema": "wuci-noxframe-clock-v1", "full_due_anchor_utc": wuci_black_ice.format_utc(recent_anchor)},
        now=now,
    )
    assert recent.effective_profile == "smoke"
    assert recent.seconds_until_full == 5 * 24 * 60 * 60
    assert "quick mode" in recent.reason

    old_anchor = now - dt.timedelta(days=8)
    overdue = wuci_black_ice.resolve_profile(
        "auto",
        clock_path=clock,
        state={"schema": "wuci-noxframe-clock-v1", "full_due_anchor_utc": wuci_black_ice.format_utc(old_anchor)},
        now=now,
    )
    assert overdue.effective_profile == "full"
    assert overdue.seconds_until_full == 0
    assert "7-day" in overdue.reason

    explicit = wuci_black_ice.resolve_profile(
        "full",
        clock_path=clock,
        state={"schema": "wuci-noxframe-clock-v1", "full_due_anchor_utc": wuci_black_ice.format_utc(recent_anchor)},
        now=now,
    )
    assert explicit.effective_profile == "full"
    assert "explicit full" in explicit.reason

    wuci_black_ice.update_clock_state(
        fresh,
        ended_utc=wuci_black_ice.format_utc(now + dt.timedelta(seconds=10)),
        launch_complete=True,
    )
    state = json.loads(clock.read_text(encoding="utf-8"))
    assert state["schema"] == "wuci-noxframe-clock-v1"
    assert state["last_effective_profile"] == "smoke"
    assert state["full_due_anchor_utc"] == fresh.anchor_utc
    assert state["next_full_due_utc"] == fresh.next_full_due_utc

    full_clock = tmp / "full-clock.json"
    full = wuci_black_ice.resolve_profile(
        "full",
        clock_path=full_clock,
        state={},
        now=now,
    )
    wuci_black_ice.update_clock_state(
        full,
        ended_utc=wuci_black_ice.format_utc(now + dt.timedelta(seconds=20)),
        launch_complete=True,
    )
    full_state = json.loads(full_clock.read_text(encoding="utf-8"))
    assert full_state["last_effective_profile"] == "full"
    assert full_state["last_full_launch_utc"] == wuci_black_ice.format_utc(
        now + dt.timedelta(seconds=20)
    )


def assert_substrate_commands(launcher: Path, tmp: Path) -> None:
    state = tmp / "state.json"
    substrate_seal = tmp / "substrate-seal.json"
    common = [
        "--substrate-state",
        str(state),
        "--substrate-seal",
        str(substrate_seal),
        "--json",
    ]

    contract = subprocess.run(
        [str(launcher), "contract"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert contract.returncode == 0, contract.stderr + contract.stdout
    contract_payload = json.loads(contract.stdout)
    assert contract_payload["schema"] == "wuci-noxframe-substrate-contract-v1"
    assert contract_payload["phase1_continuation"]["source_repository"] == "https://github.com/Bryforge/phase1"
    assert "Phase1 code" in contract_payload["phase1_continuation"]["ideas_not_imported"]
    feature_ids = {item["id"] for item in contract_payload["phase1_feature_map"]}
    assert {"optics", "nest", "learn", "wasi", "base1", "quality"} <= feature_ids
    memory_contract = contract_payload["substrate_memory"]
    assert memory_contract["schema"] == "wuci-noxframe-substrate-memory-v1"
    assert memory_contract["memory_root"] == "build/noxframe/substrate-memory"
    assert memory_contract["lock_policy"]["default_lock_from_depth"] == 9
    assert "host kernel" in memory_contract["host_boundary"]["does_not_protect"]

    init = subprocess.run(
        [str(launcher), "init", *common],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert init.returncode == 0, init.stderr + init.stdout
    init_payload = json.loads(init.stdout)
    assert init_payload["schema"] == "wuci-noxframe-init-result-v1"
    assert init_payload["created"] is True
    assert state.exists()
    assert substrate_seal.exists()
    state_payload = json.loads(state.read_text(encoding="utf-8"))
    assert state_payload["substrate_memory"]["active_store_path"] == (
        "build/noxframe/substrate-memory/depth-00/root/memory.wj"
    )

    status = subprocess.run(
        [str(launcher), "status", *common],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert status.returncode == 0, status.stderr + status.stdout
    status_payload = json.loads(status.stdout)
    assert status_payload["schema"] == "wuci-noxframe-status-v1"
    assert status_payload["status"] == "sealed"
    assert status_payload["route"] == ["root", "wuci-ji", "daylight"]

    reseal = subprocess.run(
        [str(launcher), "seal", *common],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert reseal.returncode == 0, reseal.stderr + reseal.stdout
    reseal_payload = json.loads(reseal.stdout)
    assert reseal_payload["schema"] == "wuci-noxframe-seal-result-v1"
    assert reseal_payload["status"] == "sealed"

    verify = subprocess.run(
        [str(launcher), "verify", *common],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr + verify.stdout
    verify_payload = json.loads(verify.stdout)
    assert verify_payload["schema"] == "wuci-noxframe-verify-result-v1"
    assert verify_payload["status"] == "pass"


def assert_daylight_wrap(launcher: Path, tmp: Path) -> None:
    bin_path = REPO / "build" / "wuci-ji"
    assert bin_path.exists()
    keyfile = tmp / "daylight-wrap.key"
    keyfile.write_text(("11" * 32) + "\n", encoding="ascii")
    state = tmp / "wrap-state.json"
    substrate_seal = tmp / "wrap-substrate-seal.json"
    out_dir = tmp / "daylight-wrap"
    wrap = subprocess.run(
        [
            str(launcher),
            "daylight-wrap",
            "--bin",
            str(bin_path),
            "--substrate-state",
            str(state),
            "--substrate-seal",
            str(substrate_seal),
            "--daylight-wrap-keyfile",
            str(keyfile),
            "--daylight-wrap-out",
            str(out_dir),
            "--json",
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert wrap.returncode == 0, wrap.stderr + wrap.stdout
    manifest = json.loads(wrap.stdout)
    assert manifest["schema"] == "wuci-noxframe-daylight-wrap-v1"
    assert manifest["status"] == "sealed"
    assert manifest["wrap_scheme"]["artifact_envelope"] == "WJSEAL-v2 via seal-file-keyfile-v2"
    assert manifest["guards"]["shell"] == "disabled; subprocess invoked with shell=False"
    assert manifest["guards"]["network"] == "metadata-deny in the console registry"
    assert len(manifest["key_id"]) == 32
    assert manifest["substrate_memory_digest_vector"]["sha384"]
    assert "not OS runtime containment" in manifest["non_claims"]
    assert "not whole-system post-quantum safety" in manifest["non_claims"]
    dimension_ids = {record["id"] for record in manifest["inner_dimensions"]}
    assert {"root", "wuci-ji", "daylight", "cage", "qcage", "install", "codex"} <= dimension_ids
    daylight_anchor_paths = {record["path"] for record in manifest["daylight_anchors"]}
    assert "daylight-equation/SCORECARD.v1.json" in daylight_anchor_paths
    assert "daylight-equation/rust/daylight-crypto/src/wuci_daylight.rs" in daylight_anchor_paths

    artifact = Path(manifest["sealed_artifact"]["path"])
    assert artifact.exists()
    assert artifact.read_bytes()
    opened = tmp / "daylight-wrap-opened.json"
    opened_proc = subprocess.run(
        [
            str(bin_path),
            "open-file-keyfile",
            str(keyfile),
            str(artifact),
            str(opened),
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert opened_proc.returncode == 0, opened_proc.stderr + opened_proc.stdout
    opened_bytes = opened.read_bytes()
    assert wuci_black_ice.digest_vector(opened_bytes) == manifest["bundle_digest_vector"]
    bundle = json.loads(opened_bytes.decode("utf-8"))
    assert bundle["schema"] == "wuci-noxframe-daylight-wrap-bundle-v1"
    assert bundle["dimension_digest_vector"] == manifest["dimension_digest_vector"]
    assert bundle["substrate_memory"]["active_store_path"] == (
        "build/noxframe/substrate-memory/depth-00/root/memory.wj"
    )
    assert bundle["substrate_memory"]["lock_policy"]["default_lock_from_depth"] == 9
    assert not (out_dir / "noxframe-inner-dimensions.bundle.json").exists()

    if hasattr(os, "symlink"):
        link_key = tmp / "daylight-wrap-link.key"
        link_key.symlink_to(keyfile)
        link_proc = subprocess.run(
            [
                str(launcher),
                "daylight-wrap",
                "--bin",
                str(bin_path),
                "--substrate-state",
                str(state),
                "--substrate-seal",
                str(substrate_seal),
                "--daylight-wrap-keyfile",
                str(link_key),
                "--daylight-wrap-out",
                str(tmp / "daylight-wrap-link"),
            ],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert link_proc.returncode != 0
        assert "symlink" in link_proc.stderr

    if hasattr(os, "link"):
        hard_source = tmp / "daylight-wrap-hard-source.key"
        hard_key = tmp / "daylight-wrap-hard.key"
        hard_source.write_text(("22" * 32) + "\n", encoding="ascii")
        try:
            os.link(hard_source, hard_key)
        except OSError:
            pass
        else:
            hard_proc = subprocess.run(
                [
                    str(launcher),
                    "daylight-wrap",
                    "--bin",
                    str(bin_path),
                    "--substrate-state",
                    str(state),
                    "--substrate-seal",
                    str(substrate_seal),
                    "--daylight-wrap-keyfile",
                    str(hard_source),
                    "--daylight-wrap-out",
                    str(tmp / "daylight-wrap-hard"),
                ],
                cwd=REPO,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            assert hard_proc.returncode != 0
            assert "hardlinked" in hard_proc.stderr

    second = subprocess.run(
        [
            str(launcher),
            "daylight-wrap",
            "--bin",
            str(bin_path),
            "--substrate-state",
            str(state),
            "--substrate-seal",
            str(substrate_seal),
            "--daylight-wrap-keyfile",
            str(keyfile),
            "--daylight-wrap-out",
            str(out_dir),
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert second.returncode != 0
    assert "overwrite" in second.stderr


def assert_boot_prompt_and_banner(launcher: Path, tmp: Path) -> None:
    declined = subprocess.run(
        [
            str(launcher),
            "--force-boot-prompt",
            "--color",
            "always",
            "--substrate-state",
            str(tmp / "decline-state.json"),
            "--substrate-seal",
            str(tmp / "decline-substrate-seal.json"),
        ],
        cwd=REPO,
        input="n\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert declined.returncode == 130
    assert wuci_black_ice.BOOT_VOICE_TEXT in declined.stderr
    assert "\x1b[31m" in declined.stderr
    assert "WUCI-JI" in declined.stderr
    assert "WUCI-I JI" not in declined.stderr
    assert "proof trace" not in declined.stderr
    assert "operator gate" not in declined.stderr
    assert "no production authority" not in declined.stderr
    plain = strip_ansi(declined.stderr)
    assert "Wuci-Ji Systems Substrate" in plain
    assert "NOXFRAME" in plain
    assert wuci_black_ice.BOOT_IDEOGRAPH_TEXT in plain
    scene = [line for line in plain.splitlines() if line and not line.startswith(wuci_black_ice.BOOT_VOICE_TEXT)]
    assert scene
    assert len({display_width(line) for line in scene[:-1]}) <= 2

    env = dict(os.environ)
    env["COLUMNS"] = "46"
    narrow = subprocess.run(
        [
            str(launcher),
            "--force-boot-prompt",
            "--color",
            "never",
            "--substrate-state",
            str(tmp / "narrow-state.json"),
            "--substrate-seal",
            str(tmp / "narrow-substrate-seal.json"),
        ],
        cwd=REPO,
        env=env,
        input="n\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert narrow.returncode == 130
    narrow_scene = [
        line for line in narrow.stderr.splitlines()
        if line and "Welcome to the Wuci-Ji" not in line
    ]
    assert narrow_scene
    assert max(display_width(line) for line in narrow_scene[:-1]) <= 46
    assert "WUCI-JI" in narrow.stderr


def assert_boot_animation_frame() -> None:
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        wuci_black_ice.print_banner(
            wuci_black_ice.Palette("never"),
            frame=3,
            full_screen=True,
            prompt=wuci_black_ice.BOOT_PROMPT,
            answer="y",
    )
    text = buffer.getvalue()
    assert text.startswith("\033[2J\033[H")
    assert "Welcome to the Wuci-Ji system substrate" in text
    assert "enter your system" in text
    assert "[y/N] y" in text
    assert "awaiting operator boot decision" not in text
    assert "operator gate" not in text
    assert "proof trace" not in text
    assert "WUCI-JI" in text
    assert "WUCI-I JI" not in text
    assert "Wuci-Ji Systems Substrate" in text
    assert "NOXFRAME" in text
    assert wuci_black_ice.BOOT_IDEOGRAPH_TEXT in text
    assert "[2 1; 1 1]" in text
    assert "┌" in text
    assert "┼" in text
    assert "·" not in text
    assert "∙" not in text
    assert "✦" not in text
    assert "✧" not in text
    assert "SEAL" not in text
    assert "BUS" not in text
    plain = strip_ansi(text.replace("\033[2J\033[H", ""))
    scene = [line for line in plain.splitlines() if line]
    assert scene
    assert len({display_width(line) for line in scene}) == 1


def assert_terminal_color_depth() -> None:
    depth = wuci_black_ice.terminal_color_depth
    # 24-bit terminals advertise truecolor or a known rich TERM.
    assert depth({"TERM": "xterm-256color", "COLORTERM": "truecolor"}, is_tty=True) == "truecolor"
    assert depth({"TERM": "xterm-kitty", "KITTY_WINDOW_ID": "1"}, is_tty=True) == "truecolor"
    # macOS Terminal.app and similar are 256-color only, not truecolor.
    assert depth({"TERM": "xterm-256color", "TERM_PROGRAM": "Apple_Terminal"}, is_tty=True) == "256"
    # Plain xterm / linux console / serial fall back to the 16 base colors.
    assert depth({"TERM": "xterm"}, is_tty=True) == "basic"
    assert depth({"TERM": "linux"}, is_tty=True) == "basic"
    # No color surfaces: dumb terminals, non-ttys, and the NO_COLOR convention.
    assert depth({"TERM": "dumb"}, is_tty=True) == "none"
    assert depth({"TERM": "xterm-256color", "COLORTERM": "truecolor"}, is_tty=False) == "none"
    assert depth({"TERM": "xterm-256color", "COLORTERM": "truecolor", "NO_COLOR": "1"}, is_tty=True) == "none"
    # Operators can force a depth for any terminal.
    assert depth({"TERM": "dumb", "NOXFRAME_COLOR_DEPTH": "256"}, is_tty=True) == "256"

    # Quantizers stay inside their palette ranges and keep pure colors distinct.
    assert 16 <= wuci_black_ice.rgb_to_xterm256(132, 6, 31) <= 255
    assert wuci_black_ice.rgb_to_xterm256(0, 0, 0) == 16
    assert 0 <= wuci_black_ice.rgb_to_ansi16(255, 80, 122) <= 15
    assert wuci_black_ice.rgb_to_ansi16(0, 0, 0) == 0

    def banner(color_depth: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            wuci_black_ice.print_banner(
                wuci_black_ice.Palette("always"),
                full_screen=True,
                prompt=wuci_black_ice.BOOT_PROMPT,
                color_depth=color_depth,
            )
        return buffer.getvalue()

    # 256-color rendering emits indexed color and never raw 24-bit escapes.
    scene_256 = banner("256")
    assert "38;5;" in scene_256 and "48;5;" in scene_256
    assert "38;2;" not in scene_256 and "48;2;" not in scene_256
    assert "WUCI-JI" in scene_256
    # Basic rendering drops the per-cell gradient background but keeps color.
    scene_basic = banner("basic")
    assert "48;5;" not in scene_basic and "48;2;" not in scene_basic
    assert "\x1b[" in scene_basic
    assert "WUCI-JI" in scene_basic
    # A none depth is monochrome even with color "always".
    scene_none = banner("none")
    assert "\x1b[3" not in scene_none and "\x1b[4" not in scene_none
    assert "WUCI-JI" in scene_none


def assert_boot_wordmark_hero() -> None:
    # The block-letter font spells the wordmark exactly.
    word = wuci_black_ice.boot_block_word("WUCI-JI")
    assert len(word) == wuci_black_ice._BOOT_BLOCK_HEIGHT
    assert len({len(line) for line in word}) == 1  # every row is the same width
    assert any("█" in line for line in word)

    def render(columns: int, lines: int) -> str:
        saved = {k: os.environ.get(k) for k in ("COLUMNS", "LINES")}
        os.environ["COLUMNS"] = str(columns)
        os.environ["LINES"] = str(lines)
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stderr(buffer):
                wuci_black_ice.print_banner(
                    wuci_black_ice.Palette("never"),
                    frame=1,
                    full_screen=True,
                    prompt=wuci_black_ice.BOOT_PROMPT,
                )
            return buffer.getvalue()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    # A wide terminal renders the block-art hero and the station header.
    wide = render(100, 30)
    assert "█" in wide
    assert "WUCI-JI // NOXFRAME SUBSTRATE" in wide
    assert "Wuci-Ji Systems Substrate" in wide
    wide_scene = [line for line in strip_ansi(wide.replace("\033[2J\033[H", "")).splitlines() if line]
    assert len({display_width(line) for line in wide_scene}) == 1

    # A narrow terminal falls back to the plain wordmark without block glyphs.
    narrow = render(58, 26)
    assert "█" not in narrow
    assert "WUCI-JI" in narrow
    narrow_scene = [line for line in strip_ansi(narrow.replace("\033[2J\033[H", "")).splitlines() if line]
    assert len({display_width(line) for line in narrow_scene}) == 1


def assert_static_fullscreen_boot_gate() -> None:
    def args(**over: object) -> argparse.Namespace:
        base: dict[str, object] = {
            "yes": False,
            "no_boot_prompt": False,
            "no_boot_animation": False,
            "boot_renderer": "auto",
        }
        base.update(over)
        return argparse.Namespace(**base)

    generic = {"TERM": "xterm-256color"}
    kitty = {"TERM": "xterm-kitty", "KITTY_WINDOW_ID": "1"}
    tmux = {"TERM": "screen-256color", "TMUX": "/tmp/tmux"}

    # A generic interactive terminal gets the one-shot full-screen splash.
    assert wuci_black_ice.boot_static_fullscreen_active(
        args(), env=generic, stdin_tty=True, stderr_tty=True
    )
    # tmux/SSH (reduced-motion) also qualifies -- painted once, no flicker.
    assert wuci_black_ice.boot_static_fullscreen_active(
        args(), env=tmux, stdin_tty=True, stderr_tty=True
    )
    # Rich terminals animate instead of using the static splash.
    assert not wuci_black_ice.boot_static_fullscreen_active(
        args(), env=kitty, stdin_tty=True, stderr_tty=True
    )
    # Non-ttys, GUI renderer, and opt-outs fall back to other paths.
    assert not wuci_black_ice.boot_static_fullscreen_active(
        args(), env=generic, stdin_tty=False, stderr_tty=True
    )
    assert not wuci_black_ice.boot_static_fullscreen_active(
        args(boot_renderer="gui"), env=generic, stdin_tty=True, stderr_tty=True
    )
    assert not wuci_black_ice.boot_static_fullscreen_active(
        args(no_boot_animation=True), env=generic, stdin_tty=True, stderr_tty=True
    )
    assert not wuci_black_ice.boot_static_fullscreen_active(
        args(yes=True), env=generic, stdin_tty=True, stderr_tty=True
    )


def assert_console_ux_polish() -> None:
    # A themed rail is exactly the requested width and never appends an ellipsis.
    rail = wuci_black_ice.themed_rail("◇─◇─◇", 40)
    assert display_width(rail) == 40
    assert "…" not in rail and "..." not in rail

    # Help decks carry a rule under the title but keep their locked contract.
    compact = wuci_black_ice.console_help_text(["--compact"])
    assert "noxframe help // compact" in compact
    assert "─" in compact
    fs_help = wuci_black_ice.console_help_text(["fs"])
    assert "mkdir <dir>" in fs_help

    # The countdown draws a progress bar and still prints the init line.
    countdown_buffer = io.StringIO()
    with contextlib.redirect_stderr(countdown_buffer):
        wuci_black_ice.countdown(1, wuci_black_ice.Palette("never"))
    countdown_text = countdown_buffer.getvalue()
    assert "WUCI-JI SYSTEM INITIALIZED..." in countdown_text
    assert "100%" in countdown_text
    assert "█" in countdown_text

    # The sign-off keeps the bilingual farewell inside a lattice frame.
    goodbye_buffer = io.StringIO()
    with contextlib.redirect_stdout(goodbye_buffer):
        wuci_black_ice.print_goodbye(wuci_black_ice.Palette("never"))
    goodbye_text = goodbye_buffer.getvalue()
    assert "再见，黑客。" in goodbye_text
    assert "Goodbye, Hacker." in goodbye_text
    assert wuci_black_ice.BOOT_IDEOGRAPH_TEXT in goodbye_text
    assert "◇" in goodbye_text


def assert_console_exit(launcher: Path, tmp: Path) -> None:
    kaiju_iso_source = tmp / "kali-noxframe.iso"
    kaiju_iso_source.write_bytes(b"KAIJU NOXFRAME ISO\n")
    kaiju_iso_root = tmp / "kaiju-iso"
    kaiju_disk_root = tmp / "kaiju-disk"
    wuci_black_ice.wuci_kaiju.install_iso(
        kaiju_iso_source,
        iso_root=kaiju_iso_root,
        name="kali-noxframe.iso",
    )
    wuci_black_ice.wuci_kaiju.create_disk(disk_root=kaiju_disk_root, size_mib=1)
    proc = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "never",
            "--clock",
            str(tmp / "console-clock.json"),
            "--substrate-state",
            str(tmp / "console-state.json"),
            "--substrate-seal",
            str(tmp / "console-seal.json"),
            "--kaiju-iso-root",
            str(kaiju_iso_root),
            "--kaiju-disk-root",
            str(kaiju_disk_root),
            "--kaiju-qemu-bin",
            "/bin/true",
        ],
        cwd=REPO,
        input=(
            "help --compact\n"
            "man sysinfo\n"
            "complete se\n"
            "pwd\n"
            "ls /proc\n"
            "cat /proc/cells\n"
            "cat /dev/codex\n"
            "cat /dev/wuci-os\n"
            "cat /dev/plugins\n"
            "cat /kaiju/iso\n"
            "cat /kaiju/disk\n"
            "cat /kaiju/boot-plan\n"
            "cat /wuci-os/status\n"
            "cat /wuci-os/boundary\n"
            "cat /wuci-os/boot\n"
            "cat /docs/wuci-os.md\n"
            "cat /phase/features\n"
            "cat /nests/contexts\n"
            "cat /nests/memory-map\n"
            "cat /nests/lock-policy\n"
            "cat /learn/status\n"
            "cat /env/profile\n"
            "cat /env/variables\n"
            "cat /env/self-release\n"
            "phase map\n"
            "whereami\n"
            "nest list\n"
            "nest inspect daylight\n"
            "nest memory\n"
            "nest lock-policy\n"
            "nest enter gate\n"
            "phase whereami\n"
            "learn add Gate notes stay local\n"
            "learn list\n"
            "plugins list\n"
            "wasm policy\n"
            "kaiju iso status\n"
            "kaiju disk status\n"
            "kaiju boot --dry-run --memory-mib 512 --cpus 1\n"
            "kaiju boot --memory-mib 512 --cpus 1\n"
            "wuci-os status\n"
            "wuci-os boot\n"
            "wuci-os run\n"
            "wiki qcage\n"
            "base1 b1\n"
            "doctor\n"
            "selftest\n"
            "quality\n"
            "version --compare\n"
            "sysinfo\n"
            "ps\n"
            "self-release plan\n"
            "self-release status\n"
            "self-release shell\n"
            "profile\n"
            "exit\n"
            "man codex\n"
            "codex status\n"
            "codex version\n"
            "profile\n"
            "set -o\n"
            "set FRAME=ready\n"
            "env\n"
            "which browser\n"
            "alias ep='cat /env/profile'\n"
            "alias\n"
            "ep\n"
            "unalias ep\n"
            "mkdir /tmp\n"
            "touch /tmp/a\n"
            "ls /tmp\n"
            "cp /proc/version /tmp/version\n"
            "cat /tmp/version\n"
            "mv /tmp/version /tmp/version2\n"
            "rm /tmp/version2\n"
            "spawn worker\n"
            "jobs\n"
            "bg 100\n"
            "fg 100\n"
            "nice 100 5\n"
            "kill 100\n"
            "ps\n"
            "ifconfig\n"
            "iwconfig\n"
            "wifi-scan\n"
            "wifi-connect lab\n"
            "ping example.invalid\n"
            "nmcli\n"
            "browser about\n"
            "git status\n"
            "gh status\n"
            "cargo build\n"
            "rustc --version\n"
            "python3 --version\n"
            "go version\n"
            "python --version\n"
            "gcc --version\n"
            "avim /proc/version\n"
            "dev status\n"
            "loadcr3 0x3000\n"
            "pcide on\n"
            "cr3\n"
            "cr4\n"
            "history\n"
            "exit\n"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "noxframe help // compact" in proc.stdout
    assert "substrate: status seal verify contract launch self-release" in proc.stdout
    assert "usage      : sysinfo" in proc.stdout
    assert "usage      : codex" in proc.stdout
    assert "guard      : explicit-opt-in" in proc.stdout
    assert "security" in proc.stdout
    assert "selfdev" in proc.stdout
    assert "codex" in proc.stdout
    assert "/proc" in proc.stdout or "cells" in proc.stdout
    assert "NOXFRAME root context" in proc.stdout
    assert "opt-in Codex host bridge context" in proc.stdout
    assert "musl image evidence and boot-planning context" in proc.stdout
    assert "codex bridge: disabled" in proc.stdout
    assert "restart NOXFRAME with --allow-codex" in proc.stdout
    assert "codex-bridge" in proc.stdout
    assert "schema: wuci-noxframe-phase-map-v1" in proc.stdout
    assert "schema: wuci-noxframe-phase-whereami-v1" in proc.stdout
    assert "schema: wuci-noxframe-plugin-catalog-v1" in proc.stdout
    assert "schema: wuci-noxframe-plugin-policy-v1" in proc.stdout
    assert "schema: wuci-kaiju-iso-status-v1" in proc.stdout
    assert "schema: wuci-kaiju-disk-status-v1" in proc.stdout
    assert "schema\": \"wuci-kaiju-boot-plan-v1" in proc.stdout
    assert "schema: wuci-noxframe-wuci-os-status-v1" in proc.stdout
    assert "schema: wuci-noxframe-wuci-os-boundary-v1" in proc.stdout
    assert "schema: wuci-noxframe-wuci-os-command-plan-v1" in proc.stdout
    assert "command: tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo" in proc.stdout
    assert "wuci-os run: unavailable in NOXFRAME" in proc.stdout
    assert "scope: metadata adapter only; use tools/wuci-os from the host shell" in proc.stdout
    assert "-nographic" in proc.stdout
    assert "\"network\": \"none\"" in proc.stdout
    assert "kaiju boot: bridge disabled" in proc.stdout
    assert "restart NOXFRAME with --allow-kaiju-boot" in proc.stdout
    assert "schema: wuci-noxframe-learn-status-v1" in proc.stdout
    assert "wuci-noxframe-substrate-memory-v1" in proc.stdout
    assert "schema: wuci-noxframe-substrate-lock-policy-v1" in proc.stdout
    assert "active_store: build/noxframe/substrate-memory/depth-00/root/memory.wj" in proc.stdout
    assert "recovery: password/key loss requires destroying that locked depth and descendants" in proc.stdout
    assert "schema: wuci-noxframe-base1-dry-run-v1" in proc.stdout
    assert "schema: wuci-noxframe-doctor-v1" in proc.stdout
    assert "schema: wuci-noxframe-selftest-v1" in proc.stdout
    assert "schema: wuci-noxframe-quality-scorecard-v1" in proc.stdout
    assert "implemented-ideas: terminal, vfs, proc, optics, nest, learn, fyr, wasi, base1, quality" in proc.stdout
    assert "context: gate" in proc.stdout
    assert "learn: stored session note 1" in proc.stdout
    assert "1. Gate notes stay local" in proc.stdout
    assert "qcage: QCAGE labels quantum risk" in proc.stdout
    assert "schema: wuci-noxframe-session-profile-v1" in proc.stdout
    assert "schema: wuci-noxframe-self-release-plan-v1" in proc.stdout
    assert "schema: wuci-noxframe-self-release-status-v1" in proc.stdout
    assert "WUCI-JI / NOXFRAME self-release shell" in proc.stdout
    assert "context: wuci-ji/self-release" in proc.stdout
    assert "NOXFRAME_PROFILE=auto" in proc.stdout
    assert "FRAME=ready" in proc.stdout
    assert "set -o no_host_passthrough=on" in proc.stdout
    assert "which: browser" in proc.stdout
    assert "ep='cat /env/profile'" in proc.stdout
    assert "mkdir: created /tmp/" in proc.stdout
    assert "touch: /tmp/a" in proc.stdout
    assert "cp: /proc/version -> /tmp/version" in proc.stdout
    assert "WUCI-NOXFRAME substrate console" in proc.stdout
    assert "mv: /tmp/version -> /tmp/version2" in proc.stdout
    assert "rm: removed /tmp/version2" in proc.stdout
    assert "spawn: pid=100 name=worker" in proc.stdout
    assert "bg: pid=100 state=background" in proc.stdout
    assert "fg: pid=100 state=foreground" in proc.stdout
    assert "nice: pid=100 priority=5" in proc.stdout
    assert "kill: pid=100 state=terminated" in proc.stdout
    assert "PID  STATE       PRI  NAME" in proc.stdout
    assert "worker" in proc.stdout
    assert "ifconfig: nox0" in proc.stdout
    assert "iwconfig: no wireless extensions" in proc.stdout
    assert "wifi-scan: skipped" in proc.stdout
    assert "wifi-connect: denied by NOXFRAME policy; ssid=lab" in proc.stdout
    assert "ping: no packets sent; host=example.invalid; policy=metadata-deny" in proc.stdout
    assert "nmcli: virtual NetworkManager state disconnected" in proc.stdout
    assert "browser: metadata-only local route" in proc.stdout
    assert "git: metadata-only; host git argv not executed" in proc.stdout
    assert "gh: metadata-only; GitHub CLI argv not executed" in proc.stdout
    assert "cargo: dry-run route; host executable not launched" in proc.stdout
    assert "rustc: dry-run route; host executable not launched" in proc.stdout
    assert "python3: dry-run route; host executable not launched" in proc.stdout
    assert "go: dry-run route; host executable not launched" in proc.stdout
    assert "python: dry-run route; host executable not launched" in proc.stdout
    assert "gcc: dry-run route; host executable not launched" in proc.stdout
    assert "avim: read-only virtual preview /proc/version" in proc.stdout
    assert "dev: self-development lane metadata" in proc.stdout
    assert "loadcr3: 0x3000" in proc.stdout
    assert "pcide: on" in proc.stdout
    assert "cr3: 0x3000 (virtual)" in proc.stdout
    assert "cr4: pcide=on pae=on pse=on (virtual)" in proc.stdout
    assert "history" in proc.stdout
    assert "再见，黑客。" in proc.stdout
    assert "Goodbye, Hacker." in proc.stdout
    assert not wuci_black_ice.boot_answer_allows("no")


def assert_console_multicommand_depth_exit_all(launcher: Path, tmp: Path) -> None:
    proc = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "always",
            "--clock",
            str(tmp / "multi-depth-clock.json"),
            "--substrate-state",
            str(tmp / "multi-depth-state.json"),
            "--substrate-seal",
            str(tmp / "multi-depth-seal.json"),
        ],
        cwd=REPO,
        input=(
            "multi phase compass ; nest enter gate ; phase whereami\n"
            "self-release shell\n"
            "multi nest enter witness ; phase whereami ; self-release shell\n"
            "multi nest enter ledger ; phase whereami ; exit all\n"
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    combined = proc.stderr + proc.stdout
    assert proc.returncode == 0, combined
    assert "substratisphere: depth=0 lattice=root-red-lattice" in combined
    assert "substratisphere_depth: 0" in combined
    assert "substratisphere_depth: 1" in combined
    assert "substratisphere_depth: 2" in combined
    assert "lattice: amber-gate-lattice" in combined
    assert "lattice: green-witness-lattice" in combined
    assert "context: gate" in combined
    assert "context: witness" in combined
    assert "context: ledger" in combined
    assert "exit: all NOXFRAME levels requested" in combined
    assert "self-release shell: exit all requested" in combined
    assert "\x1b[31m" in combined
    assert "\x1b[33m" in combined
    assert "\x1b[32m" in combined


def assert_codex_bridge_process(launcher: Path, tmp: Path) -> None:
    proc = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "never",
            "--allow-codex",
            "--codex-bin",
            sys.executable,
            "--clock",
            str(tmp / "codex-console-clock.json"),
            "--substrate-state",
            str(tmp / "codex-console-state.json"),
            "--substrate-seal",
            str(tmp / "codex-console-seal.json"),
        ],
        cwd=REPO,
        input="codex version\nexit\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "codex: launching explicit host bridge" in proc.stdout
    assert "boundary: Codex uses host/API configuration" in proc.stdout
    assert "argv:" in proc.stdout
    assert "--version" in proc.stdout
    assert "codex-result: 0" in proc.stdout


def assert_kaiju_boot_bridge_process(launcher: Path, tmp: Path) -> None:
    kaiju_iso_source = tmp / "kali-boot.iso"
    kaiju_iso_source.write_bytes(b"KAIJU BOOT ISO\n")
    kaiju_iso_root = tmp / "kaiju-boot-iso"
    kaiju_disk_root = tmp / "kaiju-boot-disk"
    wuci_black_ice.wuci_kaiju.install_iso(
        kaiju_iso_source,
        iso_root=kaiju_iso_root,
        name="kali-boot.iso",
    )
    wuci_black_ice.wuci_kaiju.create_disk(disk_root=kaiju_disk_root, size_mib=1)
    proc = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "never",
            "--allow-kaiju-boot",
            "--kaiju-qemu-bin",
            "/bin/true",
            "--kaiju-iso-root",
            str(kaiju_iso_root),
            "--kaiju-disk-root",
            str(kaiju_disk_root),
            "--clock",
            str(tmp / "kaiju-console-clock.json"),
            "--substrate-state",
            str(tmp / "kaiju-console-state.json"),
            "--substrate-seal",
            str(tmp / "kaiju-console-seal.json"),
        ],
        cwd=REPO,
        input="kaiju boot --memory-mib 512 --cpus 1\nexit\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "kaiju boot: launching non-graphical QEMU" in proc.stdout
    assert "graphics: none" in proc.stdout
    assert "network: none" in proc.stdout
    assert "argv: /bin/true" in proc.stdout
    assert "-nographic" in proc.stdout
    assert "-net none" in proc.stdout
    assert "kaiju-boot-result: 0" in proc.stdout
    missing = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "never",
            "--allow-kaiju-boot",
            "--kaiju-qemu-bin",
            str(tmp / "missing-qemu"),
            "--kaiju-iso-root",
            str(kaiju_iso_root),
            "--kaiju-disk-root",
            str(kaiju_disk_root),
            "--clock",
            str(tmp / "kaiju-missing-console-clock.json"),
            "--substrate-state",
            str(tmp / "kaiju-missing-console-state.json"),
            "--substrate-seal",
            str(tmp / "kaiju-missing-console-seal.json"),
        ],
        cwd=REPO,
        input="kaiju boot --memory-mib 512 --cpus 1\nexit\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert missing.returncode == 0, missing.stderr + missing.stdout
    assert "kaiju boot: QEMU executable not found:" in missing.stdout
    assert "install qemu-kvm-core on RHEL" in missing.stdout


def console_command_matrix() -> dict[str, str]:
    samples = {
        "status": "status",
        "seal": "seal",
        "verify": "verify",
        "contract": "contract",
        "launch": "launch smoke",
        "self-release": "self-release status",
        "phase": "phase whereami",
        "pwd": "pwd",
        "ls": "ls /",
        "cd": "cd /docs",
        "cat": "cat /proc/version",
        "tree": "tree /",
        "echo": "echo noxframe command matrix",
        "mkdir": "mkdir /tmp",
        "touch": "touch /tmp/matrix",
        "rm": "rm /tmp/matrix",
        "cp": "cp /proc/version /tmp/version",
        "mv": "mv /tmp/version /tmp/version2",
        "grep": "grep NOXFRAME /proc/version",
        "wc": "wc /proc/version",
        "head": "head -n 1 /proc/version",
        "tail": "tail -n 1 /proc/version",
        "find": "find / -name status",
        "pipeline": "pipeline",
        "wiki": "wiki phase1",
        "ps": "ps",
        "top": "top",
        "jobs": "jobs",
        "spawn": "spawn worker",
        "fg": "fg 100",
        "bg": "bg 100",
        "kill": "kill 100",
        "nice": "nice 100 5",
        "sysinfo": "sysinfo",
        "dash": "dash",
        "free": "free",
        "df": "df",
        "dmesg": "dmesg",
        "vmstat": "vmstat",
        "uname": "uname",
        "date": "date",
        "uptime": "uptime",
        "hostname": "hostname",
        "doctor": "doctor",
        "selftest": "selftest",
        "quality": "quality",
        "audit": "audit",
        "opslog": "opslog tail",
        "env": "env",
        "set": "set -o",
        "export": "export MATRIX=pass",
        "unset": "unset MATRIX",
        "alias": "alias st=status",
        "unalias": "unalias st",
        "which": "which status",
        "profile": "profile",
        "whoami": "whoami",
        "id": "id",
        "accounts": "accounts",
        "history": "history",
        "security": "security",
        "theme": "theme list",
        "banner": "banner",
        "tips": "tips",
        "xframe-split": "xframe-split 2",
        "xframe-next": "xframe-next",
        "xframe-drop": "xframe-drop all",
        "learn": "learn status",
        "ifconfig": "ifconfig",
        "iwconfig": "iwconfig",
        "wifi-scan": "wifi-scan",
        "wifi-connect": "wifi-connect lab",
        "ping": "ping example.invalid",
        "nmcli": "nmcli",
        "browser": "browser about",
        "git": "git status",
        "gh": "gh status",
        "cargo": "cargo build",
        "rustc": "rustc --version",
        "python3": "python3 --version",
        "go": "go version",
        "python": "python --version",
        "gcc": "gcc --version",
        "update": "update plan",
        "plugins": "plugins status",
        "wasm": "wasm list",
        "kaiju": "kaiju status",
        "wuci-os": "wuci-os status",
        "codex": "codex status",
        "avim": "avim /proc/version",
        "dev": "dev status",
        "repo": "repo status",
        "fyr": "fyr status",
        "base1": "base1 status",
        "lang": "lang support",
        "lspci": "lspci",
        "pcie": "pcie",
        "cr3": "cr3",
        "loadcr3": "loadcr3 0x4000",
        "cr4": "cr4",
        "pcide": "pcide on",
        "help": "help --compact",
        "man": "man status",
        "complete": "complete se",
        "capabilities": "capabilities",
        "matrix": "matrix",
        "bootcfg": "bootcfg show",
        "clear": "clear",
        "version": "version --compare",
        "roadmap": "roadmap",
        "sandbox": "sandbox",
        "nest": "nest tree",
        "multi": "multi phase compass ; nest status",
        "exit": "exit",
    }
    missing = sorted(spec.name for spec in wuci_black_ice.CONSOLE_COMMANDS if spec.name not in samples)
    assert not missing, f"missing NOXFRAME console matrix sample(s): {missing}"
    return samples


def assert_no_unavailable_command_markers() -> None:
    marker = wuci_black_ice.UNAVAILABLE_COMMAND_PREFIX
    unavailable = [
        spec for spec in wuci_black_ice.CONSOLE_COMMANDS if spec.guard == "unavailable"
    ]
    assert not unavailable, [spec.name for spec in unavailable]

    for spec in wuci_black_ice.CONSOLE_COMMANDS:
        display_name = wuci_black_ice.command_display_name(spec)
        display_usage = wuci_black_ice.command_display_usage(spec)
        assert not display_name.startswith(marker), spec.name
        assert not display_usage.startswith(marker), spec.name
        assert wuci_black_ice.console_lookup(f"/{spec.name}") is None

    compact = wuci_black_ice.console_help_text(["--compact"])
    assert marker not in compact

    fs_help = wuci_black_ice.console_help_text(["fs"])
    assert marker not in fs_help
    assert "mkdir <dir>" in fs_help

    manual = wuci_black_ice.console_man_text("mkdir")
    assert manual is not None
    assert manual.startswith("mkdir\n")
    assert "usage      : mkdir <dir>" in manual

    completions = wuci_black_ice.console_completions("/")
    assert not completions

    capabilities = wuci_black_ice.console_capabilities_text()
    assert marker not in capabilities


def assert_console_completion_logic() -> None:
    session = wuci_black_ice.ConsoleSession()

    status = wuci_black_ice.console_completion_plan(session, "sta")
    assert status.matches == ("status",)
    assert status.append_space is True

    browser = wuci_black_ice.console_completion_plan(session, "bro")
    assert browser.matches == ("browser",)
    assert browser.append_space is True

    slash_browser = wuci_black_ice.console_completion_plan(session, "/bro")
    assert slash_browser.matches == ()
    assert slash_browser.append_space is False

    root_path = wuci_black_ice.console_completion_plan(session, "cat /pr")
    assert root_path.matches == ("/proc/",)
    assert root_path.append_space is False

    proc_file = wuci_black_ice.console_completion_plan(session, "cat /proc/ce")
    assert proc_file.matches == ("/proc/cells",)
    assert proc_file.append_space is True

    session.cwd = "/docs"
    docs_file = wuci_black_ice.console_completion_plan(session, "cat st")
    assert docs_file.matches == ("state.json", "status.json")
    assert docs_file.append_space is False

    docs_dir = wuci_black_ice.console_completion_plan(session, "cd /do")
    assert docs_dir.matches == ("/docs/",)
    assert docs_dir.append_space is False

    launch = wuci_black_ice.console_completion_plan(session, "launch f")
    assert launch.matches == ("full",)
    assert launch.append_space is True

    phase = wuci_black_ice.console_completion_plan(session, "phase fea")
    assert phase.matches == ("features",)
    assert phase.append_space is True

    self_release = wuci_black_ice.console_completion_plan(session, "self-release sta")
    assert self_release.matches == ("status",)
    assert self_release.append_space is True

    man_reserved = wuci_black_ice.console_completion_plan(session, "man /mk")
    assert man_reserved.matches == ()
    assert man_reserved.append_space is False

    which_alias = wuci_black_ice.console_completion_plan(session, "which git")
    assert which_alias.matches == ("git", "github")

    session.env["NOXFRAME_EXTRA"] = "1"
    unset_env = wuci_black_ice.console_completion_plan(session, "unset NOXF")
    assert "NOXFRAME" in unset_env.matches
    assert "NOXFRAME_EXTRA" in unset_env.matches

    export_env = wuci_black_ice.console_completion_plan(session, "export NOXFRAME_M")
    assert export_env.matches == ("NOXFRAME_MODE=",)

    session.aliases["st"] = "status"
    unalias = wuci_black_ice.console_completion_plan(session, "unalias s")
    assert unalias.matches == ("st",)
    assert unalias.append_space is True

    nest = wuci_black_ice.console_completion_plan(session, "nest enter ga")
    assert nest.matches == ("gate",)
    assert nest.append_space is True

    nest_memory = wuci_black_ice.console_completion_plan(session, "nest mem")
    assert nest_memory.matches == ("memory",)
    assert nest_memory.append_space is True

    wiki = wuci_black_ice.console_completion_plan(session, "wiki q")
    assert wiki.matches == ("qcage",)
    assert wiki.append_space is True

    plugins = wuci_black_ice.console_completion_plan(session, "plugins po")
    assert plugins.matches == ("policy",)
    assert plugins.append_space is True

    split = wuci_black_ice.console_completion_plan(session, "xframe-split ")
    assert split.matches == ("2", "3", "4")
    assert split.append_space is False

    drop = wuci_black_ice.console_completion_plan(session, "xframe-drop ")
    assert drop.matches == ("1", "all")
    assert drop.append_space is False


def assert_xframe_split_drop_logic() -> None:
    session = wuci_black_ice.ConsoleSession()
    args = noxframe_args(profile="smoke")
    palette = wuci_black_ice.Palette("never")

    def run(*lines: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            for line in lines:
                keep_running = wuci_black_ice.dispatch_console_line(REPO, args, palette, session, line)
                assert keep_running
        return buffer.getvalue()

    split = run("xframe-split 2")
    assert "schema: wuci-noxframe-xframe-v1" in split
    assert "action: split" in split
    assert "frames: 2" in split
    assert "layout: left-right" in split
    assert "switch: Shift+Tab/F6" in split
    assert "1: left cwd=/" in split
    assert "2: right cwd=/" in split
    assert session.xframe_count == 2
    assert session.active_xframe == 1
    assert wuci_black_ice.prompt_for_session(session) == "noxframe:L0/root[x1/2]> "
    assert wuci_black_ice.normalize_xframe_switch_input("\x1b[Z") == "xframe-next"
    assert wuci_black_ice.normalize_xframe_switch_input("\x1b\x1b[Z") == "xframe-next"
    assert wuci_black_ice.normalize_xframe_switch_input("\x1b[17~") == "xframe-next"

    run("cd /env")
    assert session.cwd == "/env"
    switched = run("\x1b[Z")
    assert "action: switch" in switched
    assert "active: 2" in switched
    assert session.active_xframe == 2
    assert session.cwd == "/"
    assert session.env["PWD"] == "/"

    run("mkdir /tmp", "touch /tmp/frame2")
    assert "/tmp/frame2" in session.vfs_files
    back = run("\x1b[17~")
    assert "active: 1" in back
    assert session.cwd == "/env"
    assert session.env["PWD"] == "/env"
    assert "/tmp/frame2" not in session.vfs_files

    quad = run("xframe-split 4")
    assert "frames: 4" in quad
    assert "layout: quadrant" in quad
    assert "4: bottom-right" in quad
    dropped_one = run("xframe-drop 1")
    assert "action: drop" in dropped_one
    assert "dropped: 4" in dropped_one
    assert "frames: 3" in dropped_one
    assert "3: bottom" in dropped_one
    assert session.xframe_count == 3

    collapsed = run("xframe-drop all")
    assert "dropped: 2 3" in collapsed
    assert "frames: 1" in collapsed
    assert "layout: single" in collapsed
    assert session.xframe_count == 1
    assert session.active_xframe == 1
    assert wuci_black_ice.prompt_for_session(session) == "noxframe:L0/root> "


def assert_console_command_matrix(launcher: Path, tmp: Path) -> None:
    samples = console_command_matrix()
    commands = [
        samples[spec.name]
        for spec in wuci_black_ice.CONSOLE_COMMANDS
        if spec.name != "exit"
    ]
    commands.append(samples["exit"])
    proc = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "never",
            "--profile",
            "smoke",
            "--no-countdown",
            "--report",
            str(tmp / "matrix-report.md"),
            "--seal",
            str(tmp / "matrix-seal.json"),
            "--clock",
            str(tmp / "matrix-clock.json"),
            "--substrate-state",
            str(tmp / "matrix-state.json"),
            "--substrate-seal",
            str(tmp / "matrix-substrate-seal.json"),
        ],
        cwd=REPO,
        input="\n".join(commands) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    combined = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == 0, combined
    assert "unknown command:" not in combined
    assert "parse error:" not in combined
    assert "Traceback" not in combined
    assert "launch-result: 0" in proc.stdout
    assert "root/" in proc.stdout
    assert "noxframe help // compact" in proc.stdout
    assert "mkdir: created /tmp/" in proc.stdout
    assert "touch: /tmp/matrix" in proc.stdout
    assert "rm: removed /tmp/matrix" in proc.stdout
    assert "cp: /proc/version -> /tmp/version" in proc.stdout
    assert "mv: /tmp/version -> /tmp/version2" in proc.stdout
    assert "spawn: pid=100 name=worker" in proc.stdout
    assert "fg: pid=100 state=foreground" in proc.stdout
    assert "bg: pid=100 state=background" in proc.stdout
    assert "kill: pid=100 state=terminated" in proc.stdout
    assert "nice: pid=100 priority=5" in proc.stdout
    assert "ifconfig: nox0" in proc.stdout
    assert "wifi-scan: skipped" in proc.stdout
    assert "browser: metadata-only local route" in proc.stdout
    assert "git: metadata-only; host git argv not executed" in proc.stdout
    assert "gh: metadata-only; GitHub CLI argv not executed" in proc.stdout
    assert "cargo: dry-run route; host executable not launched" in proc.stdout
    assert "schema: wuci-noxframe-wuci-os-status-v1" in proc.stdout
    assert "avim: read-only virtual preview /proc/version" in proc.stdout
    assert "dev: self-development lane metadata" in proc.stdout
    assert "loadcr3: 0x4000" in proc.stdout
    assert "pcide: on" in proc.stdout
    assert "schema: wuci-noxframe-xframe-v1" in proc.stdout
    assert "action: split" in proc.stdout
    assert "action: switch" in proc.stdout
    assert "action: drop" in proc.stdout
    assert (tmp / "matrix-report.md").exists()
    assert (tmp / "matrix-seal.json").exists()


def assert_console_alias_matrix(launcher: Path, tmp: Path) -> None:
    samples = console_command_matrix()
    alias_commands = []
    exit_aliases = []
    for spec in wuci_black_ice.CONSOLE_COMMANDS:
        for alias in spec.aliases:
            if spec.name == "exit":
                exit_aliases.append(alias)
                continue
            sample = samples[spec.name]
            parts = sample.split(maxsplit=1)
            alias_commands.append(alias if len(parts) == 1 else f"{alias} {parts[1]}")
    assert alias_commands
    proc = subprocess.run(
        [
            str(launcher),
            "--console",
            "--yes",
            "--color",
            "never",
            "--clock",
            str(tmp / "alias-clock.json"),
            "--substrate-state",
            str(tmp / "alias-state.json"),
            "--substrate-seal",
            str(tmp / "alias-substrate-seal.json"),
        ],
        cwd=REPO,
        input="\n".join(alias_commands + ["exit"]) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    combined = proc.stdout + "\n" + proc.stderr
    assert proc.returncode == 0, combined
    assert "unknown command:" not in combined
    assert "parse error:" not in combined
    assert "Traceback" not in combined
    assert "codex bridge: disabled" in proc.stdout
    assert "gh: metadata-only; GitHub CLI argv not executed" in proc.stdout

    for index, alias in enumerate(exit_aliases):
        exit_proc = subprocess.run(
            [
                str(launcher),
                "--console",
                "--yes",
                "--color",
                "never",
                "--clock",
                str(tmp / f"exit-alias-{index}-clock.json"),
                "--substrate-state",
                str(tmp / f"exit-alias-{index}-state.json"),
                "--substrate-seal",
                str(tmp / f"exit-alias-{index}-seal.json"),
            ],
            cwd=REPO,
            input=f"{alias}\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert exit_proc.returncode == 0, exit_proc.stderr + exit_proc.stdout
        assert "Goodbye, Hacker." in exit_proc.stdout


def assert_launcher(launcher: Path) -> None:
    assert launcher.exists()
    assert os.access(launcher, os.X_OK)
    with tempfile.TemporaryDirectory(prefix="wuci-noxframe-") as tmp_name:
        tmp = Path(tmp_name)
        report = tmp / "report.md"
        seal = tmp / "seal.json"
        clock = tmp / "clock.json"
        assert_public_anchor_rejections(tmp)
        assert_optional_dependency_preflight()
        assert_boot_voice_selection()
        assert_mechanics_terminal_handoff()
        assert_console_multicommand_logic()
        assert_clock_decisions(tmp)
        assert_no_unavailable_command_markers()
        assert_console_completion_logic()
        assert_xframe_split_drop_logic()
        assert_substrate_commands(launcher, tmp)
        assert_boot_prompt_and_banner(launcher, tmp)
        assert_boot_animation_frame()
        assert_boot_wordmark_hero()
        assert_terminal_color_depth()
        assert_static_fullscreen_boot_gate()
        assert_console_ux_polish()
        assert_console_exit(launcher, tmp)
        assert_console_multicommand_depth_exit_all(launcher, tmp)
        assert_codex_bridge_process(launcher, tmp)
        assert_kaiju_boot_bridge_process(launcher, tmp)
        assert_console_command_matrix(launcher, tmp)
        assert_console_alias_matrix(launcher, tmp)
        proc = subprocess.run(
            [
                str(launcher),
                "--profile",
                "smoke",
                "--no-countdown",
                "--color",
                "never",
                "--report",
                str(report),
                "--seal",
                str(seal),
                "--clock",
                str(clock),
            ],
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
        text = report.read_text(encoding="utf-8")
        assert "# WUCI-NOXFRAME Launch Report" in text
        assert "Schema: `wuci-noxframe-launch-report-v1`" in text
        assert "Working-title alias: `WUCI-BLACK-ICE`" in text
        assert "SYSTEMS BOOTING..." in text
        assert "WUCI-JI SYSTEM INITIALIZED..." in text
        assert "Wuci-Prism live inspector" in text
        assert "Status: `PASS`" in text
        assert "production-authority-verify" in text
        assert "Skipped And Report-Only Lanes" in text

        payload = json.loads(seal.read_text(encoding="utf-8"))
        assert payload["schema"] == "wuci-noxframe-seal-v1"
        assert payload["name"] == "WUCI-NOXFRAME"
        assert payload["working_title_alias"] == "WUCI-BLACK-ICE"
        assert payload["profile"] == "smoke"
        assert payload["requested_profile"] == "smoke"
        assert payload["clock"]["path"] == str(clock)
        assert payload["lineage"]["adaptation"] == "WUCI-native defensive proof substrate; no Phase1 code import"
        assert payload["host_effects"]["network"] == "unused"
        assert payload["host_effects"]["shell"] == "disabled; subprocesses are invoked with shell=False"
        assert "skipped_and_report_only_lanes" in payload
        assert "not OS runtime containment" in payload["non_claims"]
        assert "not whole-system post-quantum safety" in payload["non_claims"]
        anchor_paths = {entry["path"] for entry in payload["anchors"]}
        assert "docs/SECURITY_BOUNDARY.md" in anchor_paths
        assert "docs/wuci_gate_boundary.json" in anchor_paths
        assert "daylight-equation/SCORECARD.v1.json" in anchor_paths
        assert "daylight-equation/rust/daylight-crypto/src/wuci_daylight.rs" in anchor_paths
        for anchor in payload["anchors"]:
            vector = anchor["digest_vector"]
            assert vector["sha256"]
            assert vector["sha384"]
            assert vector["sha512"]
        clock_state = json.loads(clock.read_text(encoding="utf-8"))
        assert clock_state["last_effective_profile"] == "smoke"
        assert clock_state["last_requested_profile"] == "smoke"
        assert_daylight_wrap(launcher, tmp)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-NOXFRAME launcher.")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--launcher", default=str(DEFAULT_LAUNCHER))
    args = parser.parse_args()
    assert_launcher(Path(args.launcher))
    if not args.quiet:
        print("wuci noxframe: PASS")


if __name__ == "__main__":
    main()
