#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import daylight_public_evidence_firewall as firewall
from tools import live_integrity_check as live_integrity
from tools import site_dist


def read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def main() -> None:
    for retired_path in [".github/workflows/pages.yml", "CNAME", "site/CNAME"]:
        assert not (REPO_ROOT / retired_path).exists(), f"retired Pages path remains: {retired_path}"

    hosting = json.loads(read("site/hosting-requirements.json"))
    assert hosting["schema"] == "wuci-site-hosting-requirements-v2"
    assert hosting["production_host"] == "Cloudflare Pages"
    assert hosting["secondary_publishers"] == []
    assert any(
        item.get("host") == "GitHub Pages"
        and item.get("repository_status") == "retired"
        and item.get("account_follow_up") == "disable-pages-publishing"
        for item in hosting["retired_publishers"]
    )
    assert sorted(hosting["forbidden_response_headers"]) == ["nel", "report-to"]
    assert {
        "static.cloudflareinsights.com",
        "data-cf-beacon",
        "/cdn-cgi/rum",
    }.issubset(hosting["forbidden_html_markers"])

    inventory = site_dist.build_site_dist()
    staged_site = site_dist.collect_regular_tree(site_dist.OUTPUT_ROOT)
    site_dist.validate_inventory(inventory, staged_site)
    assert set(site_dist.EXCLUDED_SOURCE_FILES).isdisjoint(staged_site)
    local_site = live_integrity.load_local_site_build()
    assert {artifact.path for artifact in local_site.artifacts} == (
        set(staged_site) - set(site_dist.CONFIG_FILES)
    ), "every staged public site file must be byte-bound by the live checker"
    root_package = json.loads(read("package.json"))
    assert "python3 tools/site_dist.py" in root_package["scripts"]["build"]
    assert root_package["scripts"]["deploy:pages"] == (
        "npm ci && npm run build && python3 tools/site_deploy.py"
    )
    assert "npx --no-install wrangler" in root_package["scripts"]["cloudflare:login"]
    assert "npx --no-install wrangler" in root_package["scripts"]["cloudflare:whoami"]
    wrangler_config = read("wrangler.toml")
    assert 'pages_build_output_dir = "./build/site-dist"' in wrangler_config
    site_live_check = read("tools/site_live_check.py")
    assert "Source review is open. The ISO is not published." not in site_live_check
    assert "00171c4cbd377f7c3c200c8a2493ad42c90a1207" not in site_live_check
    for marker in [
        "Source review is published. The ISO is not.",
        "4783ebc530bc8c28cdeed2f06e79c233cee13b08",
    ]:
        assert marker in site_live_check, f"legacy live checker is missing current Noether marker: {marker}"
    deploy_source = read("tools/site_deploy.py")
    for marker in [
        '"git", "fetch", "--quiet", "origin", CANONICAL_BRANCH',
        'origin_main=run_git(["rev-parse", "refs/remotes/origin/main"])',
        'branch=run_git(["branch", "--show-current"])',
        'tree_status=run_git(["status", "--porcelain=v1", "--untracked-files=all"])',
        '"--commit-hash"',
        '"--commit-message"',
        '"--commit-dirty=false"',
    ]:
        assert marker in deploy_source, f"site deploy source gate is missing {marker}"

    bottle_deploy_source = read("apps/bottle/scripts/validate-production-config.mjs")
    assert 'execFileSync("git", ["fetch", "--quiet", "origin", "main"]' in bottle_deploy_source
    assert 'GIT_TERMINAL_PROMPT: "0"' in bottle_deploy_source
    bottle_package = json.loads(read("apps/bottle/package.json"))
    assert bottle_package["scripts"]["deploy"] == (
        "npm ci && npm run check && node scripts/deploy-reviewed-worker.mjs"
    )
    reviewed_worker_deploy = read("apps/bottle/scripts/deploy-reviewed-worker-lib.mjs")
    for marker in ['"--no-bundle"', '"--strict"', '"--tag"', "workerBundleTag"]:
        assert marker in reviewed_worker_deploy, f"reviewed Worker deploy is missing {marker}"
    assert '[version_metadata]\nbinding = "CF_VERSION_METADATA"' in read(
        "apps/bottle/wrangler.toml"
    )

    dependabot = read(".github/dependabot.yml")
    for marker in [
        "package-ecosystem: npm\n    directory: /\n",
        "package-ecosystem: npm\n    directory: /apps/bottle\n",
        "package-ecosystem: github-actions\n    directory: /\n",
        "package-ecosystem: cargo\n    directory: /daylight-equation/rust/daylight-crypto\n",
        "package-ecosystem: cargo\n    directory: /penumbra\n",
        "package-ecosystem: cargo\n    directory: /tools/wuci-pq-fips204-verify\n",
    ]:
        assert marker in dependabot, f"Dependabot is missing {marker!r}"
    for forbidden in [
        "directory: /third_party",
        "directory: /daylight-equation/fixtures",
        "directory: /tools/wuciji-zp1-bridge",
    ]:
        assert forbidden not in dependabot, f"Dependabot must exclude {forbidden}"

    codeql_workflow = read(".github/workflows/codeql.yml")
    assert "javascript-typescript" in codeql_workflow
    assert re.search(r"(?m)^\s*- python$", codeql_workflow)
    assert "security-events: write" in codeql_workflow
    assert "actions/upload-artifact" not in codeql_workflow
    action_references = re.findall(r"uses: (?:actions/checkout|github/codeql-action/(?:init|analyze))@([^\s]+)", codeql_workflow)
    assert len(action_references) == 3
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_references)

    codeql_config = read(".github/codeql/codeql-config.yml")
    for ignored_path in ["third_party/**", "daylight-equation/fixtures/**", '"**/node_modules/**"']:
        assert ignored_path in codeql_config, f"CodeQL config must ignore {ignored_path}"

    live_integrity_workflow = read(".github/workflows/live-integrity.yml")
    assert "workflow_dispatch:" in live_integrity_workflow
    assert "if: github.ref == 'refs/heads/main'" in live_integrity_workflow
    assert re.search(r"(?m)^\s+ref: main$", live_integrity_workflow)
    assert 'test "$(git branch --show-current)" = main' in live_integrity_workflow
    assert "NODE_VERSION: 22.23.1" in live_integrity_workflow
    assert "NPM_VERSION: 11.8.0" in live_integrity_workflow
    assert (
        "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e"
        in live_integrity_workflow
    )
    for command in [
        "npm install --global npm@${NPM_VERSION}",
        "npm ci",
        "npm run check",
        "npm run validate:release-source",
    ]:
        assert command in live_integrity_workflow
    assert "Build the exact Cloudflare Pages upload tree" in live_integrity_workflow
    assert live_integrity_workflow.index("npm run check") < live_integrity_workflow.index(
        "make live-integrity-check"
    )

    for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        report = firewall.check_workflow(workflow)
        assert report["ok"], report

    print("repository maintenance policy: PASS")


if __name__ == "__main__":
    main()
