#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
DEFAULT_LAUNCHER = REPO / "tools" / "wuci-noxframe"
sys.path.insert(0, str(REPO / "tools"))
import wuci_black_ice  # noqa: E402


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
