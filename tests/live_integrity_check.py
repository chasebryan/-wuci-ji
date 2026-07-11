#!/usr/bin/env python3
from __future__ import annotations

import base64
import gzip
import json
import os
import subprocess
import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import live_integrity_check as live
from tools import site_dist


EXPECTED_COMMIT = "0123456789abcdef0123456789abcdef01234567"
KEYRING_BYTES = (
    b'{\n'
    b'  "schema": "nsm.daylight-bottle.keyring.v1",\n'
    b'  "updatedAt": "2026-07-07T00:00:00.000Z",\n'
    b'  "keys": []\n'
    b'}\n'
)
INDEX_BYTES = b"<!doctype html><title>Daylight Bottle</title>"
APP_BYTES = b"export const daylightBottle = true;\n"
_LOCAL_SITE: live.LocalSiteBuild | None = None


def build_manifest(artifacts_by_path: dict[str, bytes]) -> dict[str, object]:
    artifacts = [
        {"path": path, "bytes": len(content), "sha256": live.sha256(content)}
        for path, content in sorted(artifacts_by_path.items())
    ]
    runtime = [
        content
        for path, content in artifacts_by_path.items()
        if Path(path).suffix in live.RUNTIME_EXTENSIONS
    ]
    subject: dict[str, object] = {
        "source": {
            "repository": live.CANONICAL_REPOSITORY,
            "commit": EXPECTED_COMMIT,
            "treeState": "clean",
        },
        "build": {
            "appVersion": "0.1.0",
            "nodeVersion": "v22.23.1",
            "packageManager": "npm@11.8.0",
            "command": "npm run build",
        },
        "inputs": live.expected_manifest_inputs(),
        "bundleBudget": {
            "schema": "nsm.daylight-bottle.bundle-budget.v1",
            "runtimeBytes": sum(len(content) for content in runtime),
            # The production value is emitted by the pinned Node/zlib
            # toolchain. A different standards-compliant gzip implementation
            # need not produce the same compressed byte count.
            "runtimeGzipBytes": sum(
                len(gzip.compress(content, compresslevel=9, mtime=0)) for content in runtime
            )
            + 7,
            "maxRuntimeBytes": live.MAX_RUNTIME_BYTES,
            "maxRuntimeGzipBytes": live.MAX_RUNTIME_GZIP_BYTES,
        },
        "artifacts": artifacts,
    }
    return {
        "schema": "nsm.daylight-bottle.release-manifest.v1",
        "subjectSha256": f"sha256:{live.sha256(live.canonical_json_bytes(subject))}",
        **subject,
    }


def refresh_manifest_subject(manifest: dict[str, object]) -> None:
    subject = {
        "source": manifest["source"],
        "build": manifest["build"],
        "inputs": manifest["inputs"],
        "bundleBudget": manifest["bundleBudget"],
        "artifacts": manifest["artifacts"],
    }
    manifest["subjectSha256"] = f"sha256:{live.sha256(live.canonical_json_bytes(subject))}"


def replace_manifest(
    responses: dict[str, live.Response], manifest: dict[str, object]
) -> None:
    responses["bottle_manifest"] = replace(
        responses["bottle_manifest"],
        body=json.dumps(manifest).encode("utf-8"),
    )


def canonical_artifacts() -> dict[str, bytes]:
    return {
        "_headers": (REPO_ROOT / "apps/bottle/public/_headers").read_bytes(),
        "assets/app.js": APP_BYTES,
        "index.html": INDEX_BYTES,
        "keyring.json": KEYRING_BYTES,
    }


def canonical_local_build() -> live.LocalBottleBuild:
    artifacts = canonical_artifacts()
    manifest = build_manifest(artifacts)
    return live.LocalBottleBuild(
        manifest=manifest,
        manifest_bytes=(json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
        artifacts=artifacts,
        worker_bundle_sha256="a" * 64,
    )


def canonical_local_site_build() -> live.LocalSiteBuild:
    global _LOCAL_SITE
    if _LOCAL_SITE is None:
        site_dist.build_site_dist()
        _LOCAL_SITE = live.load_local_site_build()
    return _LOCAL_SITE


def bottle_headers(content_type: str) -> dict[str, str]:
    return {
        **live.REQUIRED_BOTTLE_HEADERS,
        "content-type": content_type,
        "cache-control": "no-store, no-transform",
    }


def response(
    status: int,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> live.Response:
    return live.Response(status=status, headers=headers or {}, body=body, url=url)


def passing_responses() -> dict[str, live.Response]:
    local_build = canonical_local_build()
    local_site = canonical_local_site_build()
    artifacts = dict(local_build.artifacts)
    manifest = dict(local_build.manifest)
    api = {"schema": "nsm.daylight-bottle.list.response.v1", "bottles": []}
    responses = {
        "site_secondary": response(410, live.SITE_SECONDARY),
        "bottle_root": response(
            200,
            f"{live.BOTTLE_ORIGIN}/",
            headers=bottle_headers("text/html; charset=utf-8"),
            body=INDEX_BYTES,
        ),
        "bottle_deployment": response(
            200,
            f"{live.BOTTLE_ORIGIN}/api/deployment",
            headers=bottle_headers("application/json; charset=utf-8"),
            body=json.dumps(
                {
                    "schema": "nsm.daylight-bottle.deployment.v1",
                    "workerVersionId": "01234567-89ab-4cde-8f01-23456789abcd",
                    "workerVersionTag": f"sha256-{'a' * 64}",
                    "versionCreatedAt": "2026-07-11T03:30:00.000Z",
                }
            ).encode("utf-8"),
        ),
        "bottle_manifest": response(
            200,
            f"{live.BOTTLE_ORIGIN}/release-manifest.json",
            headers=bottle_headers("application/json; charset=utf-8"),
            body=local_build.manifest_bytes,
        ),
        "bottle_api": response(
            200,
            f"{live.BOTTLE_ORIGIN}/api/bottles?recipientFingerprint={live.ZERO_FINGERPRINT}",
            headers=bottle_headers("application/json; charset=utf-8"),
            body=json.dumps(api, sort_keys=True).encode("utf-8"),
        ),
        "bottle_keyring": response(
            200,
            f"{live.BOTTLE_ORIGIN}/keyring.json",
            headers=bottle_headers("application/json; charset=utf-8"),
            body=KEYRING_BYTES,
        ),
    }
    global_headers = live.site_global_headers(local_site.configs["_headers"])
    cache_rules = live.site_cache_control_rules(local_site.configs["_headers"])
    for artifact in local_site.artifacts:
        headers = {
            **global_headers,
            "content-type": f"{artifact.media_type}; charset=utf-8",
        }
        expected_cache = live.expected_site_cache_control(cache_rules, artifact.url)
        if expected_cache is None:
            headers.pop("cache-control", None)
        elif artifact.status == 404:
            headers["cache-control"] = "no-store"
        else:
            headers["cache-control"] = expected_cache
        responses[artifact.response_name] = response(
            artifact.status,
            artifact.url,
            headers=headers,
            body=artifact.content,
        )
    for redirect in local_site.redirects:
        responses[redirect.response_name] = response(
            redirect.status,
            redirect.url,
            headers={"location": redirect.location},
        )
    for path, content in artifacts.items():
        if path == "_headers":
            continue
        responses[live.artifact_response_name(path)] = response(
            200,
            live.artifact_url(path),
            headers={
                **live.REQUIRED_BOTTLE_HEADERS,
                "content-type": f"{sorted(live.artifact_media_types(path))[0]}; charset=utf-8",
                "cache-control": (
                    "no-store, no-transform"
                    if path in {"index.html", "keyring.json"}
                    else "public, max-age=31536000, immutable, no-transform"
                ),
            },
            body=content,
        )
    return responses


def assert_passes(
    responses: dict[str, live.Response],
    *,
    local_build: live.LocalBottleBuild | None = None,
) -> None:
    checks = live.evaluate(
        responses,
        EXPECTED_COMMIT,
        local_build or canonical_local_build(),
        canonical_local_site_build(),
    )
    failures = [check for check in checks if not check.ok]
    assert not failures, failures
    assert len({check.name for check in checks}) == len(checks), "check names must be unique"


def assert_rejects(
    responses: dict[str, live.Response],
    expected_name: str,
    *,
    expected_commit: str = EXPECTED_COMMIT,
    local_build: live.LocalBottleBuild | None = None,
) -> None:
    checks = live.evaluate(
        responses,
        expected_commit,
        local_build or canonical_local_build(),
        canonical_local_site_build(),
    )
    failures = {check.name for check in checks if not check.ok}
    assert expected_name in failures, failures


def assert_value_error(function, expected: str) -> None:
    try:
        function()
    except ValueError as error:
        assert expected in str(error), error
        return
    raise AssertionError(f"expected ValueError containing {expected!r}")


def main() -> None:
    module_help = subprocess.run(
        [sys.executable, "-m", "tools.live_integrity_check", "--help"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert module_help.returncode == 0, module_help.stderr
    assert "--live" in module_help.stdout

    js_subject_vector = {
        "source": {
            "repository": live.CANONICAL_REPOSITORY,
            "commit": EXPECTED_COMMIT,
            "treeState": "clean",
        },
        "build": {
            "appVersion": "0.1.0",
            "nodeVersion": "v22.23.1",
            "packageManager": "npm@11.8.0",
            "command": "npm run build",
        },
        "inputs": {"packageJsonSha256": "a" * 64},
        "bundleBudget": {
            "schema": "nsm.daylight-bottle.bundle-budget.v1",
            "runtimeBytes": 42,
            "runtimeGzipBytes": 21,
            "maxRuntimeBytes": live.MAX_RUNTIME_BYTES,
            "maxRuntimeGzipBytes": live.MAX_RUNTIME_GZIP_BYTES,
        },
        "artifacts": [{"path": "index.html", "bytes": 42, "sha256": "b" * 64}],
    }
    assert live.sha256(live.canonical_json_bytes(js_subject_vector)) == (
        "ea57471a380127d5b227a03029e4a75da31170a9cf9e2150b58c05cf442406c7"
    )
    assert len(gzip.compress(INDEX_BYTES, compresslevel=9, mtime=0)) == 59
    assert len(gzip.compress(APP_BYTES, compresslevel=9, mtime=0)) == 56
    local_site = canonical_local_site_build()
    global_headers_bytes = local_site.configs["_headers"]
    assert "nel" not in live.site_global_headers(global_headers_bytes)
    for required_removal in (b"  ! NEL\n", b"  ! Report-To\n"):
        assert_value_error(
            lambda required_removal=required_removal: live.site_global_headers(
                global_headers_bytes.replace(required_removal, b"", 1)
            ),
            "global rule removals are not exact",
        )
    cache_rules = live.site_cache_control_rules(local_site.configs["_headers"])
    assert live.expected_site_cache_control(
        cache_rules, f"{live.SITE_ORIGIN}/app.js"
    ) == "no-store"
    assert live.expected_site_cache_control(
        cache_rules, f"{live.SITE_ORIGIN}/assets/wuci-ji-systems-hero.jpg"
    ) == "public, max-age=31536000, immutable"
    assert "no-transform" in (
        live.expected_site_cache_control(cache_rules, live.SITE_APEX) or ""
    )
    assert all(
        redirect.url.startswith(
            (
                live.SITE_ORIGIN,
                "http://nosuchmachine.net/",
                "http://www.nosuchmachine.net/",
                "https://www.nosuchmachine.net/",
            )
        )
        for redirect in local_site.redirects
    )
    canonical_redirect_names = set(live.CANONICAL_ABSOLUTE_REDIRECT_SOURCES.values())
    canonical_redirects = [
        redirect
        for redirect in local_site.redirects
        if redirect.response_name in canonical_redirect_names
    ]
    assert len(canonical_redirects) == 3
    assert all(
        redirect.url.endswith(f"/{live.CANONICAL_REDIRECT_PROBE_PATH}")
        and redirect.location
        == f"{live.SITE_ORIGIN}/{live.CANONICAL_REDIRECT_PROBE_PATH}"
        for redirect in canonical_redirects
    )
    for invalid_redirect, expected_error in [
        (
            b"http://127.0.0.1:8788/* https://nosuchmachine.net/:splat 301\n",
            "absolute source",
        ),
        (
            b"http://169.254.169.254/latest https://nosuchmachine.net/ 302\n",
            "absolute source",
        ),
        (
            b"/assets/* / 302\n",
            "safe canonical path",
        ),
        (
            b"//127.0.0.1/internal / 302\n",
            "safe canonical path",
        ),
        (
            b"http://nosuchmachine.net/* http://127.0.0.1/:splat 301\n"
            b"http://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
            b"https://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n",
            "wildcard line",
        ),
        (
            b"http://nosuchmachine.net/* https://nosuchmachine.net/:splat 302\n"
            b"http://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
            b"https://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n",
            "wildcard line",
        ),
        (
            b"# http://nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
            b"# http://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
            b"# https://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
            b"/repo https://github.com/chasebryan/-wuci-ji 302\n",
            "wildcard set is not exact",
        ),
    ]:
        assert_value_error(
            lambda content=invalid_redirect: live.parse_site_redirects(content),
            expected_error,
        )
    redirect_overflow = (
        b"http://nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
        b"http://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
        b"https://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301\n"
        + b"".join(
            f"/overflow-{index} / 302\n".encode("ascii") for index in range(30)
        )
    )
    assert_value_error(
        lambda: live.parse_site_redirects(redirect_overflow),
        "redirect-count budget",
    )
    assert_passes(passing_responses())
    assert all(not spec.follow_redirects for spec in live.REQUEST_PLAN)
    assert all(
        spec.user_agent == live.BROWSER_USER_AGENT
        for spec in live.REQUEST_PLAN
        if spec.name.startswith("bottle_")
    )
    assert all(
        not live.RequestSpec(
            redirect.response_name,
            redirect.url,
            method="HEAD",
        ).follow_redirects
        for redirect in local_site.redirects
    )
    assert not live.RequestSpec("artifact", live.artifact_url("index.html")).follow_redirects
    assert live.artifact_url("index.html") == f"{live.BOTTLE_ORIGIN}/"
    assert not live.valid_artifact_path("api/bottles")
    assert not live.valid_artifact_path("https://example.invalid/payload.js")

    original_urlopen = live.urllib.request.urlopen
    slow_started = threading.Event()
    slow_release = threading.Event()
    slow_finished = threading.Event()

    class SlowResponse:
        status = 200
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit: int) -> bytes:
            slow_started.set()
            slow_release.wait(2.0)
            slow_finished.set()
            return b"slow"

        def geturl(self) -> str:
            return "https://example.invalid/slow"

    def slow_urlopen(_request, *, timeout: float):
        assert timeout == 0.05
        return SlowResponse()

    live.urllib.request.urlopen = slow_urlopen
    started_at = live.time.monotonic()
    try:
        slow = live.fetch(
            live.RequestSpec(
                "slow-drip",
                "https://example.invalid/slow",
                follow_redirects=True,
            ),
            timeout=0.05,
            max_body_bytes=16,
        )
        elapsed = live.time.monotonic() - started_at
        assert slow_started.wait(0.2)
        assert slow.status == 0
        assert elapsed < 0.25, elapsed
    finally:
        slow_release.set()
        slow_finished.wait(0.5)
        live.urllib.request.urlopen = original_urlopen

    capture_calls: list[tuple[live.RequestSpec, float, int]] = []
    original_fetch = live.fetch

    def fake_fetch(
        spec: live.RequestSpec,
        *,
        timeout: float = 12.0,
        max_body_bytes: int = live.MAX_RESPONSE_BYTES,
    ) -> live.Response:
        capture_calls.append((spec, timeout, max_body_bytes))
        body = (
            b'{"artifacts":[{"path":"assets/remote-only.js","bytes":1,"sha256":"'
            + b"0" * 64
            + b'"}]}'
            if spec.name == "bottle_manifest"
            else b""
        )
        return response(200, spec.url, body=body[:max_body_bytes])

    live.fetch = fake_fetch
    try:
        live.capture_live(canonical_local_build(), local_site)
    finally:
        live.fetch = original_fetch
    artifact_calls = {
        call_spec.name.removeprefix("bottle_artifact:"): (call_timeout, call_limit)
        for call_spec, call_timeout, call_limit in capture_calls
        if call_spec.name.startswith("bottle_artifact:")
    }
    expected_capture = {
        path: content
        for path, content in canonical_artifacts().items()
        if path not in {"_headers", "index.html"}
    }
    assert set(artifact_calls) == set(expected_capture)
    assert all(
        timeout <= live.MAX_ARTIFACT_REQUEST_SECONDS
        and limit == len(expected_capture[path])
        for path, (timeout, limit) in artifact_calls.items()
    )
    assert sum(limit for _, limit in artifact_calls.values()) == sum(
        len(content) for content in expected_capture.values()
    )
    root_calls = [
        (timeout, limit)
        for spec, timeout, limit in capture_calls
        if spec.name == "bottle_root"
    ]
    assert len(root_calls) == 1
    assert root_calls[0][0] <= live.MAX_ARTIFACT_REQUEST_SECONDS
    assert root_calls[0][1] == len(canonical_artifacts()["index.html"])
    root_specs = [
        spec for spec, _, _ in capture_calls if spec.name == "bottle_root"
    ]
    assert len(root_specs) == 1
    assert root_specs[0].accept == live.BROWSER_NAVIGATION_ACCEPT
    assert all(
        spec.user_agent == live.BROWSER_USER_AGENT
        for spec, _, _ in capture_calls
        if spec.name == "bottle_root" or spec.name.startswith("bottle_artifact:")
    )

    artifact_deadline_fetches: list[tuple[str, float]] = []
    original_fetch = live.fetch
    original_monotonic = live.time.monotonic
    artifact_paths = {
        path
        for path in canonical_artifacts()
        if path not in {"_headers", "index.html"}
    }
    artifact_clock = iter(
        [0.0, 0.0]
        + [live.MAX_ARTIFACT_CAPTURE_SECONDS + 1.0] * len(artifact_paths)
    )

    def artifact_deadline_fetch(
        spec: live.RequestSpec,
        *,
        timeout: float = 12.0,
        max_body_bytes: int = live.MAX_RESPONSE_BYTES,
    ) -> live.Response:
        artifact_deadline_fetches.append((spec.name, timeout))
        return response(200, spec.url, body=INDEX_BYTES[:max_body_bytes])

    live.fetch = artifact_deadline_fetch
    live.time.monotonic = lambda: next(artifact_clock)
    try:
        artifact_deadline_responses = live.capture_bottle_artifacts(
            canonical_local_build()
        )
    finally:
        live.fetch = original_fetch
        live.time.monotonic = original_monotonic
    assert artifact_deadline_fetches == [
        ("bottle_root", live.MAX_ARTIFACT_REQUEST_SECONDS)
    ]
    assert (
        artifact_deadline_responses[live.artifact_response_name("index.html")]
        is artifact_deadline_responses["bottle_root"]
    )
    assert all(
        artifact_deadline_responses[live.artifact_response_name(path)].status == 0
        for path in artifact_paths
    )

    site_calls = {
        call_spec.name: (call_timeout, call_limit)
        for call_spec, call_timeout, call_limit in capture_calls
        if call_spec.name in {artifact.response_name for artifact in local_site.artifacts}
    }
    assert set(site_calls) == {
        artifact.response_name for artifact in local_site.artifacts
    }
    assert all(
        timeout <= live.MAX_SITE_REQUEST_SECONDS
        and limit == len(artifact.content)
        for artifact in local_site.artifacts
        for timeout, limit in [site_calls[artifact.response_name]]
    )
    assert sum(limit for _, limit in site_calls.values()) == sum(
        len(artifact.content) for artifact in local_site.artifacts
    )
    redirect_names = {redirect.response_name for redirect in local_site.redirects}
    redirect_calls = [
        (timeout, limit)
        for spec, timeout, limit in capture_calls
        if spec.name in redirect_names
    ]
    assert len(redirect_calls) == len(local_site.redirects)
    assert all(
        timeout <= live.MAX_REDIRECT_REQUEST_SECONDS and limit == 4096
        for timeout, limit in redirect_calls
    )

    deadline_fetches: list[str] = []
    original_fetch = live.fetch
    original_monotonic = live.time.monotonic
    clock = iter(
        [0.0, 0.0]
        + [live.MAX_REDIRECT_CAPTURE_SECONDS + 1.0] * len(local_site.redirects)
    )

    def deadline_fetch(
        spec: live.RequestSpec,
        *,
        timeout: float = 12.0,
        max_body_bytes: int = live.MAX_RESPONSE_BYTES,
    ) -> live.Response:
        deadline_fetches.append(spec.name)
        return response(200, spec.url)

    live.fetch = deadline_fetch
    live.time.monotonic = lambda: next(clock)
    try:
        deadline_responses = live.capture_redirects(local_site)
    finally:
        live.fetch = original_fetch
        live.time.monotonic = original_monotonic
    assert deadline_fetches == [local_site.redirects[0].response_name]
    assert all(
        deadline_responses[redirect.response_name].status == 0
        for redirect in local_site.redirects[1:]
    )

    original_total_plan = live.MAX_TOTAL_RESPONSE_PLAN
    try:
        live.MAX_TOTAL_RESPONSE_PLAN = 1
        assert_value_error(
            lambda: live.expected_snapshot_response_limits(
                canonical_local_build(),
                local_site,
            ),
            "total-count budget",
        )
    finally:
        live.MAX_TOTAL_RESPONSE_PLAN = original_total_plan

    case = passing_responses()
    case["bottle_api"] = replace(
        case["bottle_api"],
        headers={**case["bottle_api"].headers, "nel": '{"report_to":"cf-nel"}'},
    )
    assert_rejects(case, "bottle-api-no-nel")

    case = passing_responses()
    case["bottle_root"] = replace(
        case["bottle_root"],
        headers={**case["bottle_root"].headers, "cache-control": "no-store"},
    )
    case[live.artifact_response_name("index.html")] = case["bottle_root"]
    assert_rejects(case, "bottle-root-no-transform")

    for lookalike in (
        "x-no-transform",
        "no-transform-disabled",
        'no-transform="true"',
        "no-transform=1",
    ):
        case = passing_responses()
        case["bottle_root"] = replace(
            case["bottle_root"],
            headers={
                **case["bottle_root"].headers,
                "cache-control": f"no-store, {lookalike}",
            },
        )
        case[live.artifact_response_name("index.html")] = case["bottle_root"]
        assert_rejects(case, "bottle-root-no-transform")

    case = passing_responses()
    case["bottle_api"] = replace(
        case["bottle_api"],
        headers={
            **case["bottle_api"].headers,
            "cache-control": "x-no-store, no-transform",
        },
    )
    assert_rejects(case, "bottle-api-no-store")

    case = passing_responses()
    bottle_script_name = live.artifact_response_name("assets/app.js")
    case[bottle_script_name] = replace(
        case[bottle_script_name],
        headers={
            **case[bottle_script_name].headers,
            "cache-control": "public, max-age=31536000, immutable",
        },
    )
    assert_rejects(case, "bottle-artifact-assets/app.js-no-transform")

    case = passing_responses()
    injected_root = replace(
        case["bottle_root"],
        body=(
            case["bottle_root"].body
            + b'<script src="https://static.cloudflareinsights.com/beacon.js"></script>'
        ),
    )
    case["bottle_root"] = injected_root
    case[live.artifact_response_name("index.html")] = injected_root
    assert_rejects(case, "bottle-root-no-analytics-injection")

    case = passing_responses()
    case["site_https_root"] = replace(
        case["site_https_root"],
        headers={**case["site_https_root"].headers, "report-to": '{"group":"cf-nel"}'},
    )
    assert_rejects(case, "site-root-no-report-to")

    case = passing_responses()
    redirect_name = canonical_local_site_build().redirects[0].response_name
    case[redirect_name] = replace(
        case[redirect_name],
        headers={**case[redirect_name].headers, "nel": '{"report_to":"cf-nel"}'},
    )
    assert_rejects(case, f"{redirect_name.replace(':', '-').replace('/', '-')}-no-nel")

    case = passing_responses()
    case["site_browser_wucios"] = replace(
        case["site_browser_wucios"],
        body=case["site_browser_wucios"].body + b'<script src="https://static.cloudflareinsights.com/beacon.js"></script>',
    )
    assert_rejects(case, "site-browser-no-analytics-injection")

    case = passing_responses()
    case["site_https_root"] = replace(case["site_https_root"], body=b"unrelated deployment")
    assert_rejects(case, "site-root-exact-bytes")

    for lookalike in (
        "x-no-transform",
        "no-transform-disabled",
        'no-transform="true"',
        "no-transform=1",
    ):
        case = passing_responses()
        case["site_https_root"] = replace(
            case["site_https_root"],
            headers={
                **case["site_https_root"].headers,
                "cache-control": f"public, max-age=0, must-revalidate, {lookalike}",
            },
        )
        assert_rejects(case, "site-html-no-transform")

    case = passing_responses()
    case["site_browser_wucios"] = replace(
        case["site_browser_wucios"], body=b"unrelated deployment"
    )
    assert_rejects(case, "site-browser-wucios-exact-bytes")

    case = passing_responses()
    ai_name = live.site_response_name("ai-scoring-integrity.html")
    case[ai_name] = replace(case[ai_name], body=b"substituted audit page")
    assert_rejects(case, "site-artifact-ai-scoring-integrity.html-exact-bytes")

    case = passing_responses()
    media_path = "assets/wuci-ji-systems-hero.jpg"
    media_name = live.site_response_name(media_path)
    case[media_name] = replace(case[media_name], body=b"substituted media")
    assert_rejects(
        case,
        "site-artifact-assets/wuci-ji-systems-hero.jpg-exact-bytes",
    )

    case = passing_responses()
    case[media_name] = replace(
        case[media_name],
        headers={
            **case[media_name].headers,
            "cache-control": "public, max-age=0, must-revalidate, no-transform",
        },
    )
    assert_rejects(
        case,
        "site-artifact-assets/wuci-ji-systems-hero.jpg-cache-control-policy",
    )

    case = passing_responses()
    not_found_name = live.site_response_name("404.html")
    case[not_found_name] = replace(
        case[not_found_name],
        headers={
            **case[not_found_name].headers,
            "cache-control": "public, max-age=86400",
        },
    )
    assert_rejects(case, "site-artifact-404.html-cache-control-policy")

    case = passing_responses()
    case["site_app_js"] = replace(
        case["site_app_js"],
        headers={
            **case["site_app_js"].headers,
            "cache-control": "public, max-age=0, must-revalidate, no-transform",
        },
    )
    assert_rejects(case, "site-app-js-cache-control-policy")

    case = passing_responses()
    case["site_bottle_status"] = replace(
        case["site_bottle_status"],
        headers={
            **case["site_bottle_status"].headers,
            "cache-control": "public, max-age=86400",
        },
    )
    assert_rejects(case, "site-bottle-status-cache-control-policy")

    inventory_name = live.site_response_name(site_dist.INVENTORY_NAME)
    case = passing_responses()
    inventory = json.loads(case[inventory_name].body)
    inventory["publicFiles"] = inventory["publicFiles"][:-1]
    inventory["publicFileCount"] -= 1
    case[inventory_name] = replace(
        case[inventory_name],
        body=(json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    assert_rejects(case, "site-artifact-site-inventory.json-exact-bytes")

    case = passing_responses()
    inventory = json.loads(case[inventory_name].body)
    inventory["publicFiles"].append(
        {
            "path": "extra.txt",
            "urlPath": "/extra.txt",
            "status": 200,
            "mediaType": "text/plain",
            "bytes": 1,
            "sha256": "0" * 64,
        }
    )
    inventory["publicFileCount"] += 1
    case[inventory_name] = replace(
        case[inventory_name],
        body=(json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    assert_rejects(case, "site-artifact-site-inventory.json-exact-bytes")

    assert_rejects(passing_responses(), "bottle-manifest-source-commit", expected_commit="f" * 40)

    case = passing_responses()
    manifest = json.loads(case["bottle_manifest"].body)
    manifest["subjectSha256"] = f"sha256:{'0' * 64}"
    replace_manifest(case, manifest)
    assert_rejects(case, "bottle-manifest-subject-digest")

    case = passing_responses()
    manifest = json.loads(case["bottle_manifest"].body)
    manifest["unexpected"] = True
    replace_manifest(case, manifest)
    assert_rejects(case, "bottle-manifest-exact-fields")

    for field, value in [
        ("nodeVersion", "v24.0.0"),
        ("packageManager", "npm@11.9.0"),
    ]:
        case = passing_responses()
        manifest = json.loads(case["bottle_manifest"].body)
        manifest["build"][field] = value
        refresh_manifest_subject(manifest)
        replace_manifest(case, manifest)
        assert_rejects(case, "bottle-manifest-build-contract")

    for response_name, invalid_body, expected_check in [
        (
            "bottle_manifest",
            b'{"schema":"nsm.daylight-bottle.release-manifest.v1","schema":"duplicate"}',
            "bottle-manifest-json",
        ),
        (
            "bottle_manifest",
            b'{"schema":NaN}',
            "bottle-manifest-json",
        ),
        (
            "bottle_api",
            b'{"schema":"nsm.daylight-bottle.list.response.v1","schema":"duplicate","bottles":[]}',
            "bottle-api-exact-fields",
        ),
        (
            "bottle_api",
            b'{"schema":"nsm.daylight-bottle.list.response.v1","bottles":NaN}',
            "bottle-api-exact-fields",
        ),
        (
            "bottle_keyring",
            b'{"schema":"nsm.daylight-bottle.keyring.v1","schema":"duplicate","updatedAt":"2026-07-07T00:00:00.000Z","keys":[]}',
            "bottle-keyring-schema-and-records",
        ),
        (
            "bottle_keyring",
            b'{"schema":"nsm.daylight-bottle.keyring.v1","updatedAt":"2026-07-07T00:00:00.000Z","keys":NaN}',
            "bottle-keyring-schema-and-records",
        ),
    ]:
        case = passing_responses()
        case[response_name] = replace(case[response_name], body=invalid_body)
        assert_rejects(case, expected_check)

    case = passing_responses()
    manifest = json.loads(case["bottle_manifest"].body)
    manifest["inputs"]["packageJsonSha256"] = "f" * 64
    refresh_manifest_subject(manifest)
    replace_manifest(case, manifest)
    assert_rejects(case, "bottle-manifest-inputs-match-checkout")

    for invalid_gzip_bytes in (0, live.MAX_RUNTIME_GZIP_BYTES + 1):
        case = passing_responses()
        manifest = json.loads(case["bottle_manifest"].body)
        manifest["bundleBudget"]["runtimeGzipBytes"] = invalid_gzip_bytes
        refresh_manifest_subject(manifest)
        replace_manifest(case, manifest)
        local_build = replace(
            canonical_local_build(),
            manifest=manifest,
            manifest_bytes=(json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
        )
        assert_rejects(
            case,
            "bottle-manifest-bundle-budget",
            local_build=local_build,
        )

    case = passing_responses()
    manifest = json.loads(case["bottle_manifest"].body)
    manifest["bundleBudget"]["runtimeBytes"] += 1
    refresh_manifest_subject(manifest)
    replace_manifest(case, manifest)
    local_build = replace(
        canonical_local_build(),
        manifest=manifest,
        manifest_bytes=(json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
    )
    assert_rejects(
        case,
        "bottle-manifest-bundle-budget",
        local_build=local_build,
    )

    case = passing_responses()
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(case[artifact_name], body=case[artifact_name].body + b"tamper")
    assert_rejects(case, "bottle-artifact-assets/app.js-local-byte-binding")

    # A forged deployment cannot make a substituted script legitimate by
    # rewriting its remote manifest record and canonical subject together.
    case = passing_responses()
    forged_js = b"export const daylightBottle = false;\n"
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(case[artifact_name], body=forged_js)
    manifest = json.loads(case["bottle_manifest"].body)
    app_record = next(
        record for record in manifest["artifacts"] if record["path"] == "assets/app.js"
    )
    app_record["bytes"] = len(forged_js)
    app_record["sha256"] = live.sha256(forged_js)
    runtime = [
        forged_js if path == "assets/app.js" else content
        for path, content in canonical_artifacts().items()
        if Path(path).suffix in live.RUNTIME_EXTENSIONS
    ]
    manifest["bundleBudget"]["runtimeBytes"] = sum(len(content) for content in runtime)
    manifest["bundleBudget"]["runtimeGzipBytes"] = sum(
        len(gzip.compress(content, compresslevel=9, mtime=0)) for content in runtime
    )
    refresh_manifest_subject(manifest)
    replace_manifest(case, manifest)
    assert_rejects(case, "bottle-manifest-matches-local-build")
    assert_rejects(case, "bottle-artifact-assets/app.js-local-byte-binding")

    # The Bottle artifact accepts its browser-safe text/javascript response;
    # the staged site keeps its exact application/javascript header contract.
    case = passing_responses()
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(
        case[artifact_name],
        headers={**case[artifact_name].headers, "content-type": "text/javascript"},
    )
    assert_passes(case)

    case = passing_responses()
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(
        case[artifact_name],
        headers={**case[artifact_name].headers, "content-type": "application/octet-stream"},
    )
    assert_rejects(case, "bottle-artifact-assets/app.js-content-type")

    case = passing_responses()
    case["site_app_js"] = replace(
        case["site_app_js"],
        headers={**case["site_app_js"].headers, "content-type": "application/octet-stream"},
    )
    assert_rejects(case, "site-app-js-content-type")

    case = passing_responses()
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(case[artifact_name], url="https://example.invalid/app.js")
    assert_rejects(case, "bottle-artifact-assets/app.js-final-url")

    for name, expected_check in [
        ("bottle_deployment", "bottle-deployment-final-url"),
        ("bottle_manifest", "bottle-manifest-final-url"),
        ("bottle_api", "bottle-api-final-url"),
        ("bottle_keyring", "bottle-keyring-final-url"),
        ("site_bottle_status", "site-bottle-status-final-url"),
        ("site_bottle_observation", "site-bottle-observation-final-url"),
    ]:
        case = passing_responses()
        case[name] = replace(case[name], url="https://example.invalid/redirected")
        assert_rejects(case, expected_check)

    case = passing_responses()
    deployment = json.loads(case["bottle_deployment"].body)
    deployment["workerVersionTag"] = f"sha256-{'b' * 64}"
    case["bottle_deployment"] = replace(
        case["bottle_deployment"],
        body=json.dumps(deployment).encode("utf-8"),
    )
    assert_rejects(case, "bottle-deployment-reviewed-worker-tag")

    case = passing_responses()
    manifest = json.loads(case["bottle_manifest"].body)
    manifest["artifacts"][0]["path"] = "../_headers"
    refresh_manifest_subject(manifest)
    replace_manifest(case, manifest)
    assert_rejects(case, "bottle-manifest-artifact-contract")

    invalid_updated_at = json.loads(KEYRING_BYTES)
    invalid_updated_at["updatedAt"] = "not-a-time"
    assert not live.valid_keyring(invalid_updated_at)[0]
    recipient = "age1" + "q" * 58
    keyname = "daylight/test"
    fingerprint = f"sha256:{live.sha256(f'nsm.daylight-bottle.key.v1\n{keyname}\n{recipient}'.encode())}"
    invalid_created_at = {
        "schema": "nsm.daylight-bottle.keyring.v1",
        "updatedAt": "2026-07-10T00:00:00.000Z",
        "keys": [
            {
                "schema": "nsm.daylight-bottle.key.v1",
                "keyname": keyname,
                "publicRecipient": recipient,
                "fingerprint": fingerprint,
                "createdAt": "2026-02-30T00:00:00.000Z",
                "status": "active",
            }
        ],
    }
    assert not live.valid_keyring(invalid_created_at)[0]
    invalid_created_at["keys"][0]["createdAt"] = "2026-02-28T00:00:00.000Z"
    assert live.valid_keyring(invalid_created_at)[0]

    case = passing_responses()
    api = json.loads(case["bottle_api"].body)
    api["schema"] = "nsm.daylight-bottle.list.response.v0"
    case["bottle_api"] = replace(case["bottle_api"], body=json.dumps(api).encode("utf-8"))
    assert_rejects(case, "bottle-api-schema")

    case = passing_responses()
    status = json.loads(case["site_bottle_status"].body)
    status["keyringSha256"] = f"sha256:{'f' * 64}"
    case["site_bottle_status"] = replace(
        case["site_bottle_status"],
        body=json.dumps(status).encode("utf-8"),
    )
    assert_rejects(case, "site-bottle-status-keyring-digest")

    case = passing_responses()
    case["site_secondary"] = response(
        301,
        live.SITE_SECONDARY,
        headers={"location": "http://nosuchmachine.net/"},
    )
    assert_rejects(case, "site-secondary-retired-or-canonical-https")

    case = passing_responses()
    case["bottle_manifest"] = response(
        404,
        f"{live.BOTTLE_ORIGIN}/release-manifest.json",
        headers=bottle_headers("application/json; charset=utf-8"),
        body=b'{"error":"Not found."}',
    )
    assert_rejects(case, "bottle-manifest-status")

    with tempfile.TemporaryDirectory() as tmp:
        snapshot_path = Path(tmp) / "snapshot.json"
        snapshot = {
            "schema": live.SCHEMA,
            "expectedCommit": EXPECTED_COMMIT,
            "responses": {
                name: {
                    "status": item.status,
                    "headers": dict(item.headers),
                    "bodyBase64": base64.b64encode(item.body).decode("ascii"),
                    "url": item.url,
                    "truncated": item.truncated,
                }
                for name, item in passing_responses().items()
            },
        }
        snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
        snapshot_commit, snapshot_responses = live.load_snapshot(
            snapshot_path,
            canonical_local_build(),
            local_site,
        )
        assert snapshot_commit == EXPECTED_COMMIT
        assert_passes(snapshot_responses)

        missing = {**snapshot, "responses": dict(snapshot["responses"])}
        missing["responses"].pop(next(iter(missing["responses"])))
        snapshot_path.write_text(json.dumps(missing), encoding="utf-8")
        assert_value_error(
            lambda: live.load_snapshot(snapshot_path, canonical_local_build(), local_site),
            "response names are not exact",
        )

        example = next(iter(snapshot["responses"].values()))
        too_many = {
            "schema": live.SCHEMA,
            "expectedCommit": EXPECTED_COMMIT,
            "responses": {
                f"unexpected-{index}": example for index in range(10_000)
            },
        }
        snapshot_path.write_text(json.dumps(too_many), encoding="utf-8")
        assert_value_error(
            lambda: live.load_snapshot(snapshot_path, canonical_local_build(), local_site),
            "response count",
        )

        oversized_body = {**snapshot, "responses": dict(snapshot["responses"])}
        oversized_body["responses"]["site_secondary"] = {
            **snapshot["responses"]["site_secondary"],
            "bodyBase64": base64.b64encode(b"x" * 4097).decode("ascii"),
        }
        snapshot_path.write_text(json.dumps(oversized_body), encoding="utf-8")
        assert_value_error(
            lambda: live.load_snapshot(snapshot_path, canonical_local_build(), local_site),
            "local body cap",
        )

        duplicate_path = Path(tmp) / "duplicate.json"
        duplicate_path.write_text(
            '{"schema":"wuci-live-integrity-snapshot-v2",'
            '"schema":"duplicate","expectedCommit":"'
            + EXPECTED_COMMIT
            + '","responses":{}}',
            encoding="utf-8",
        )
        assert_value_error(
            lambda: live.load_snapshot(duplicate_path, canonical_local_build(), local_site),
            "canonical finite JSON",
        )

        nonfinite_path = Path(tmp) / "nonfinite.json"
        nonfinite_path.write_text(
            '{"schema":NaN,"expectedCommit":"'
            + EXPECTED_COMMIT
            + '","responses":{}}',
            encoding="utf-8",
        )
        assert_value_error(
            lambda: live.load_snapshot(nonfinite_path, canonical_local_build(), local_site),
            "canonical finite JSON",
        )

        snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
        original_fstat = live.os.fstat
        fstat_calls = 0

        def changing_fstat(descriptor: int):
            nonlocal fstat_calls
            metadata = original_fstat(descriptor)
            fstat_calls += 1
            if fstat_calls != 2:
                return metadata
            return SimpleNamespace(
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_mode=metadata.st_mode,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_ctime_ns=metadata.st_ctime_ns + 1,
            )

        live.os.fstat = changing_fstat
        try:
            assert_value_error(
                lambda: live.load_snapshot(
                    snapshot_path,
                    canonical_local_build(),
                    local_site,
                ),
                "changed during the bounded read",
            )
        finally:
            live.os.fstat = original_fstat

        symlink_path = Path(tmp) / "snapshot-link.json"
        symlink_path.symlink_to(snapshot_path)
        assert_value_error(
            lambda: live.load_snapshot(symlink_path, canonical_local_build(), local_site),
            "single-link regular file",
        )
        hardlink_path = Path(tmp) / "snapshot-hardlink.json"
        os.link(snapshot_path, hardlink_path)
        assert_value_error(
            lambda: live.load_snapshot(hardlink_path, canonical_local_build(), local_site),
            "single-link regular file",
        )
        hardlink_path.unlink()

        small_path = Path(tmp) / "oversized.json"
        small_path.write_bytes(b"x" * 65)
        original_file_budget = live.SNAPSHOT_MAX_FILE_BYTES
        try:
            live.SNAPSHOT_MAX_FILE_BYTES = 64
            assert_value_error(
                lambda: live.load_snapshot(small_path, canonical_local_build(), local_site),
                "file-size budget",
            )
        finally:
            live.SNAPSHOT_MAX_FILE_BYTES = original_file_budget

        original_decoded_budget = live.SNAPSHOT_MAX_DECODED_BYTES
        try:
            live.SNAPSHOT_MAX_DECODED_BYTES = 1
            assert_value_error(
                lambda: live.load_snapshot(snapshot_path, canonical_local_build(), local_site),
                "aggregate body budget",
            )
        finally:
            live.SNAPSHOT_MAX_DECODED_BYTES = original_decoded_budget

    print("live integrity check: PASS")


if __name__ == "__main__":
    main()
