#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
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
    assert "Would you like to boot the Wuci-Ji substrate?" in declined.stderr
    assert "\x1b[31m" in declined.stderr
    assert "WUCI-JI" in declined.stderr
    assert "无   此   机   系   统" in declined.stderr
    assert "wu   ci   ji   xi   tong" in declined.stderr
    assert "Wuci-Ji Systems" in declined.stderr
    assert "no production authority" not in declined.stderr
    plain = strip_ansi(declined.stderr)
    framed = [line for line in plain.splitlines() if line.startswith("|")]
    assert framed
    assert len({display_width(line) for line in framed}) == 1

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
    narrow_framed = [line for line in narrow.stderr.splitlines() if line.startswith("|")]
    assert narrow_framed
    assert max(display_width(line) for line in narrow_framed) <= 46
    assert "WUCI-JI" in narrow.stderr


def assert_console_exit(launcher: Path, tmp: Path) -> None:
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
        ],
        cwd=REPO,
        input=(
            "help --compact\n"
            "man sysinfo\n"
            "complete se\n"
            "pwd\n"
            "ls /proc\n"
            "cat /proc/cells\n"
            "sysinfo\n"
            "ps\n"
            "browser about\n"
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
    assert "substrate: status seal verify contract launch" in proc.stdout
    assert "usage      : sysinfo" in proc.stdout
    assert "security" in proc.stdout
    assert "selfdev" in proc.stdout
    assert "/proc" in proc.stdout or "cells" in proc.stdout
    assert "NOXFRAME root context" in proc.stdout
    assert "PID  STATE   NAME" in proc.stdout
    assert "browser: route unavailable in NOXFRAME console" in proc.stdout
    assert "history" in proc.stdout
    assert "再见，黑客。" in proc.stdout
    assert "Goodbye, Hacker." in proc.stdout
    assert not wuci_black_ice.boot_answer_allows("no")


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
        assert_clock_decisions(tmp)
        assert_substrate_commands(launcher, tmp)
        assert_boot_prompt_and_banner(launcher, tmp)
        assert_console_exit(launcher, tmp)
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
