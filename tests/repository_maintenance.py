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

    bound_site_paths = {
        item.repository_path for item in live_integrity.SITE_SURFACES
    }
    assert {"site/index.html", "site/wucios.html", "site/app.js", "site/styles.css"}.issubset(
        bound_site_paths
    )
    assert {
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "site").glob("*.json")
    } == {
        path for path in bound_site_paths if path.endswith(".json")
    }, "every top-level public site JSON surface must be byte-bound by the live checker"

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
        "npm run build",
        "npm run verify:bundle",
        "npm run validate:release-source",
    ]:
        assert command in live_integrity_workflow
    assert live_integrity_workflow.index("npm run build") < live_integrity_workflow.index(
        "make live-integrity-check"
    )

    for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        report = firewall.check_workflow(workflow)
        assert report["ok"], report

    print("repository maintenance policy: PASS")


if __name__ == "__main__":
    main()
