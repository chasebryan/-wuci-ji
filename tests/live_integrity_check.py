#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import live_integrity_check as live


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
            "runtimeGzipBytes": sum(
                len(gzip.compress(content, compresslevel=9, mtime=0)) for content in runtime
            ),
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


def bottle_headers(content_type: str) -> dict[str, str]:
    return {
        **live.REQUIRED_BOTTLE_HEADERS,
        "content-type": content_type,
        "cache-control": "no-store",
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
    keyring_sha = hashlib.sha256(KEYRING_BYTES).hexdigest()
    artifacts = canonical_artifacts()
    manifest = build_manifest(artifacts)
    api = {"schema": "nsm.daylight-bottle.list.response.v1", "bottles": []}
    status = {
        "schema": "nsm.daylight-bottle.public-status.v1",
        "origin": live.BOTTLE_ORIGIN,
        "keyringUrl": f"{live.BOTTLE_ORIGIN}/keyring.json",
        "observedAt": "2026-07-10T04:21:51Z",
        "observationMethod": "https-live-readback",
        "observationPath": "daylight-bottle-keyring-observation.json",
        "keyringSchema": "nsm.daylight-bottle.keyring.v1",
        "keyringUpdatedAt": "2026-07-07T00:00:00.000Z",
        "keyringSha256": f"sha256:{keyring_sha}",
        "activeRecipientCount": 0,
        "recipientActivation": "pending",
        "claimBoundary": "Point-in-time public readback.",
    }
    responses = {
        "site_https_root": response(
            200,
            live.SITE_APEX,
            headers={
                "content-type": "text/html; charset=utf-8",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "cache-control": "public, max-age=0, must-revalidate, no-transform",
            },
            body=(REPO_ROOT / "site/index.html").read_bytes(),
        ),
        "site_http_root": response(
            308,
            live.SITE_HTTP_APEX,
            headers={"location": live.SITE_APEX},
        ),
        "site_www_root": response(
            301,
            live.SITE_WWW,
            headers={"location": live.SITE_APEX},
        ),
        "site_secondary": response(410, live.SITE_SECONDARY),
        "site_browser_wucios": response(
            200,
            f"{live.SITE_ORIGIN}/wucios",
            headers={"content-type": "text/html; charset=utf-8"},
            body=(REPO_ROOT / "site/wucios.html").read_bytes(),
        ),
        "bottle_root": response(
            200,
            f"{live.BOTTLE_ORIGIN}/",
            headers=bottle_headers("text/html; charset=utf-8"),
            body=INDEX_BYTES,
        ),
        "bottle_manifest": response(
            200,
            f"{live.BOTTLE_ORIGIN}/release-manifest.json",
            headers=bottle_headers("application/json; charset=utf-8"),
            body=json.dumps(manifest).encode("utf-8"),
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
        "site_bottle_status": response(
            200,
            f"{live.SITE_ORIGIN}/daylight-bottle-status.json",
            headers={"content-type": "application/json; charset=utf-8", "cache-control": "no-store"},
            body=json.dumps(status, sort_keys=True).encode("utf-8"),
        ),
        "site_bottle_observation": response(
            200,
            f"{live.SITE_ORIGIN}/daylight-bottle-keyring-observation.json",
            headers={"content-type": "application/json; charset=utf-8", "cache-control": "no-store"},
            body=KEYRING_BYTES,
        ),
    }
    for path, content in artifacts.items():
        if path == "_headers":
            continue
        responses[live.artifact_response_name(path)] = response(
            200,
            live.artifact_url(path),
            headers={
                **live.REQUIRED_BOTTLE_HEADERS,
                "content-type": "application/octet-stream",
                "cache-control": (
                    "no-store"
                    if path in {"index.html", "keyring.json"}
                    else "public, max-age=31536000, immutable"
                ),
            },
            body=content,
        )
    return responses


def assert_passes(responses: dict[str, live.Response]) -> None:
    checks = live.evaluate(responses, EXPECTED_COMMIT)
    failures = [check for check in checks if not check.ok]
    assert not failures, failures
    assert len({check.name for check in checks}) == len(checks), "check names must be unique"


def assert_rejects(
    responses: dict[str, live.Response],
    expected_name: str,
    *,
    expected_commit: str = EXPECTED_COMMIT,
) -> None:
    checks = live.evaluate(responses, expected_commit)
    failures = {check.name for check in checks if not check.ok}
    assert expected_name in failures, failures


def main() -> None:
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
    assert_passes(passing_responses())
    assert all(not spec.follow_redirects for spec in live.REQUEST_PLAN)
    assert not live.RequestSpec("artifact", live.artifact_url("index.html")).follow_redirects
    assert not live.valid_artifact_path("api/bottles")
    assert not live.valid_artifact_path("https://example.invalid/payload.js")

    case = passing_responses()
    case["bottle_api"] = replace(
        case["bottle_api"],
        headers={**case["bottle_api"].headers, "nel": '{"report_to":"cf-nel"}'},
    )
    assert_rejects(case, "bottle-api-no-nel")

    case = passing_responses()
    case["site_https_root"] = replace(
        case["site_https_root"],
        headers={**case["site_https_root"].headers, "report-to": '{"group":"cf-nel"}'},
    )
    assert_rejects(case, "site-root-no-report-to")

    case = passing_responses()
    case["site_browser_wucios"] = replace(
        case["site_browser_wucios"],
        body=case["site_browser_wucios"].body + b'<script src="https://static.cloudflareinsights.com/beacon.js"></script>',
    )
    assert_rejects(case, "site-browser-no-analytics-injection")

    case = passing_responses()
    case["site_https_root"] = replace(case["site_https_root"], body=b"unrelated deployment")
    assert_rejects(case, "site-root-exact-bytes")

    case = passing_responses()
    case["site_browser_wucios"] = replace(
        case["site_browser_wucios"], body=b"unrelated deployment"
    )
    assert_rejects(case, "site-browser-wucios-exact-bytes")

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

    case = passing_responses()
    manifest = json.loads(case["bottle_manifest"].body)
    manifest["inputs"]["packageJsonSha256"] = "f" * 64
    refresh_manifest_subject(manifest)
    replace_manifest(case, manifest)
    assert_rejects(case, "bottle-manifest-inputs-match-checkout")

    case = passing_responses()
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(case[artifact_name], body=case[artifact_name].body + b"tamper")
    assert_rejects(case, "bottle-artifact-assets/app.js-bytes-and-sha256")

    case = passing_responses()
    artifact_name = live.artifact_response_name("assets/app.js")
    case[artifact_name] = replace(case[artifact_name], url="https://example.invalid/app.js")
    assert_rejects(case, "bottle-artifact-assets/app.js-final-url")

    for name, expected_check in [
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
                    "body": item.body.decode("utf-8"),
                    "url": item.url,
                    "truncated": item.truncated,
                }
                for name, item in passing_responses().items()
            },
        }
        snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
        snapshot_commit, snapshot_responses = live.load_snapshot(snapshot_path)
        assert snapshot_commit == EXPECTED_COMMIT
        assert_passes(snapshot_responses)

    print("live integrity check: PASS")


if __name__ == "__main__":
    main()
