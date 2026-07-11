#!/usr/bin/env python3
"""Deploy the exact validated site tree from a clean, current main checkout."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools import site_dist


CANONICAL_REPOSITORY = "https://github.com/chasebryan/-wuci-ji"
CANONICAL_BRANCH = "main"
CANONICAL_PROJECT = "wuci-ji"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(
    r"^(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$"
)


class DeploySourceError(ValueError):
    """The checkout or staged artifact cannot be deployed safely."""


def normalize_git_repository_url(value: str) -> str | None:
    match = REPOSITORY_PATTERN.fullmatch(value.strip())
    if match is None:
        return None
    return f"https://github.com/{match.group(1)}/{match.group(2)}"


def validate_source_state(
    *,
    head: str,
    origin_main: str,
    branch: str,
    tree_status: str,
    repository: str | None,
    github_sha: str | None = None,
) -> None:
    if not COMMIT_PATTERN.fullmatch(head):
        raise DeploySourceError("site deploy HEAD must be a full Git commit")
    if origin_main != head:
        raise DeploySourceError("site deploy HEAD must equal the freshly fetched origin/main")
    if branch != CANONICAL_BRANCH:
        raise DeploySourceError("site deploy checkout must be on the main branch")
    if tree_status != "":
        raise DeploySourceError("site deploy checkout must have a clean tracked and untracked tree")
    if repository != CANONICAL_REPOSITORY:
        raise DeploySourceError("site deploy origin must be the canonical Wuci-Ji repository")
    if github_sha is not None and github_sha != head:
        raise DeploySourceError("site deploy HEAD must match GITHUB_SHA when supplied")


def validate_staged_site() -> dict[str, bytes]:
    staged = site_dist.collect_regular_tree(site_dist.OUTPUT_ROOT)
    raw_inventory = staged.get(site_dist.INVENTORY_NAME)
    if raw_inventory is None:
        raise DeploySourceError("site deploy tree is missing its generated inventory")
    try:
        inventory = json.loads(raw_inventory)
        site_dist.validate_inventory(inventory, staged)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DeploySourceError(f"site deploy tree failed exact inventory validation: {error}") from error
    return staged


def build_deploy_command(
    commit: str,
    commit_message: str,
    upload_directory: str,
) -> list[str]:
    if not COMMIT_PATTERN.fullmatch(commit):
        raise DeploySourceError("site deploy metadata commit must be a full Git commit")
    if (
        not commit_message
        or len(commit_message.encode("utf-8")) > 256
        or any(character in commit_message for character in "\x00\r\n")
    ):
        raise DeploySourceError("site deploy commit subject must be one bounded line")
    if not upload_directory or "\x00" in upload_directory:
        raise DeploySourceError("site deploy upload directory is invalid")
    return [
        "npx",
        "--no-install",
        "wrangler",
        "pages",
        "deploy",
        upload_directory,
        "--project-name",
        CANONICAL_PROJECT,
        "--branch",
        CANONICAL_BRANCH,
        "--commit-hash",
        commit,
        "--commit-message",
        commit_message,
        "--commit-dirty=false",
    ]


def write_private_snapshot(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir(mode=0o700)
    directories: set[Path] = {root}
    for relative, content in sorted(files.items()):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        directories.update([destination.parent, *destination.parent.parents])
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        destination.chmod(0o400)
    contained_directories = sorted(
        (path for path in directories if path == root or root in path.parents),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in contained_directories:
        directory.chmod(0o500)


def restore_snapshot_permissions(root: Path) -> None:
    try:
        root_metadata = root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            return
        root.chmod(0o700)
    except FileNotFoundError:
        return
    paths = list(root.rglob("*"))
    directories = [path for path in paths if stat.S_ISDIR(path.lstat().st_mode)]
    for directory in sorted(directories, key=lambda path: len(path.parts)):
        directory.chmod(0o700)
    for path in paths:
        if stat.S_ISREG(path.lstat().st_mode):
            path.chmod(0o600)


def run_git(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DeploySourceError(f"git {' '.join(arguments)} failed") from error
    return result.stdout.strip()


def main() -> int:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "WRANGLER_SEND_METRICS": "false",
            "WRANGLER_WRITE_LOGS": "false",
        }
    )
    try:
        subprocess.run(
            ["git", "fetch", "--quiet", "origin", CANONICAL_BRANCH],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=True,
            timeout=60,
        )
        head = run_git(["rev-parse", "HEAD"])
        validate_source_state(
            head=head,
            origin_main=run_git(["rev-parse", "refs/remotes/origin/main"]),
            branch=run_git(["branch", "--show-current"]),
            tree_status=run_git(["status", "--porcelain=v1", "--untracked-files=all"]),
            repository=normalize_git_repository_url(run_git(["remote", "get-url", "origin"])),
            github_sha=environment.get("GITHUB_SHA"),
        )
        staged = validate_staged_site()
        with tempfile.TemporaryDirectory(prefix="wuci-site-reviewed-") as temporary:
            snapshot = Path(temporary) / "site"
            write_private_snapshot(snapshot, staged)
            try:
                snapshot_files = site_dist.collect_regular_tree(snapshot)
                inventory = json.loads(snapshot_files[site_dist.INVENTORY_NAME])
                site_dist.validate_inventory(inventory, snapshot_files)
                if snapshot_files != staged:
                    raise DeploySourceError("private site deploy snapshot changed during creation")
                command = build_deploy_command(
                    head,
                    run_git(["show", "-s", "--format=%s", "HEAD"]),
                    str(snapshot),
                )
                subprocess.run(
                    command,
                    cwd=REPOSITORY_ROOT,
                    env=environment,
                    check=True,
                    timeout=300,
                )
                if site_dist.collect_regular_tree(snapshot) != staged:
                    raise DeploySourceError("private site deploy snapshot changed during upload")
            finally:
                restore_snapshot_permissions(snapshot)
    except (DeploySourceError, OSError, subprocess.SubprocessError) as error:
        print(f"site-deploy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
