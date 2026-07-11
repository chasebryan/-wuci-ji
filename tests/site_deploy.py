#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools import site_deploy, site_dist


HEAD = "a" * 40


def assert_rejected(**overrides: object) -> None:
    values: dict[str, object] = {
        "head": HEAD,
        "origin_main": HEAD,
        "branch": "main",
        "tree_status": "",
        "repository": site_deploy.CANONICAL_REPOSITORY,
        "github_sha": None,
    }
    values.update(overrides)
    try:
        site_deploy.validate_source_state(**values)  # type: ignore[arg-type]
    except site_deploy.DeploySourceError:
        return
    raise AssertionError(f"unsafe deploy source state was accepted: {overrides}")


def main() -> None:
    site_deploy.validate_source_state(
        head=HEAD,
        origin_main=HEAD,
        branch="main",
        tree_status="",
        repository=site_deploy.CANONICAL_REPOSITORY,
    )
    site_deploy.validate_source_state(
        head=HEAD,
        origin_main=HEAD,
        branch="main",
        tree_status="",
        repository=site_deploy.CANONICAL_REPOSITORY,
        github_sha=HEAD,
    )

    assert_rejected(head="short")
    assert_rejected(origin_main="b" * 40)
    assert_rejected(branch="agent/deploy")
    assert_rejected(branch="")
    assert_rejected(tree_status=" M site/index.html")
    assert_rejected(repository="https://github.com/example/-wuci-ji")
    assert_rejected(repository=None)
    assert_rejected(github_sha="b" * 40)

    for source in [
        "https://github.com/chasebryan/-wuci-ji",
        "https://github.com/chasebryan/-wuci-ji.git",
        "git@github.com:chasebryan/-wuci-ji.git",
        "ssh://git@github.com/chasebryan/-wuci-ji.git",
    ]:
        assert site_deploy.normalize_git_repository_url(source) == site_deploy.CANONICAL_REPOSITORY
    for source in [
        "http://github.com/chasebryan/-wuci-ji",
        "https://example.com/chasebryan/-wuci-ji",
        "file:///tmp/-wuci-ji",
        "https://github.com/chasebryan/-wuci-ji/extra",
    ]:
        assert site_deploy.normalize_git_repository_url(source) is None

    command = site_deploy.build_deploy_command(
        HEAD,
        "Deploy exact reviewed site",
        "/tmp/reviewed-site",
    )
    assert command == [
        "npx",
        "--no-install",
        "wrangler",
        "pages",
        "deploy",
        "/tmp/reviewed-site",
        "--project-name",
        "wuci-ji",
        "--branch",
        "main",
        "--commit-hash",
        HEAD,
        "--commit-message",
        "Deploy exact reviewed site",
        "--commit-dirty=false",
    ]
    for commit, message in [
        ("short", "valid"),
        (HEAD, ""),
        (HEAD, "two\nlines"),
        (HEAD, "x" * 257),
    ]:
        try:
            site_deploy.build_deploy_command(commit, message, "/tmp/reviewed-site")
        except site_deploy.DeploySourceError:
            pass
        else:
            raise AssertionError("unsafe deploy metadata was accepted")

    staged = site_deploy.validate_staged_site()
    with tempfile.TemporaryDirectory(prefix="site-deploy-test-") as temporary:
        snapshot = Path(temporary) / "site"
        site_deploy.write_private_snapshot(snapshot, staged)
        try:
            assert site_dist.collect_regular_tree(snapshot) == staged
            assert snapshot.stat().st_mode & 0o777 == 0o500
            assert all(path.stat().st_mode & 0o777 == 0o400 for path in snapshot.rglob("*") if path.is_file())
        finally:
            site_deploy.restore_snapshot_permissions(snapshot)
    print("site deploy policy: PASS")


if __name__ == "__main__":
    main()
