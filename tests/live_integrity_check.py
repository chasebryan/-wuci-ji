#!/usr/bin/env python3
from __future__ import annotations

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
    manifest = {
        "schema": "nsm.daylight-bottle.release-manifest.v1",
        "subjectSha256": f"sha256:{'a' * 64}",
        "source": {
            "repository": live.CANONICAL_REPOSITORY,
            "commit": EXPECTED_COMMIT,
            "treeState": "clean",
        },
        "inputs": {"keyringSha256": keyring_sha},
    }
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
    return {
        "site_https_root": response(
            200,
            live.SITE_APEX,
            headers={
                "content-type": "text/html; charset=utf-8",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "cache-control": "public, max-age=0, must-revalidate, no-transform",
            },
            body=b"<!doctype html><title>Wuci-Ji v2</title>",
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
            body=b"<!doctype html><title>Noether Forge</title>",
        ),
        "bottle_root": response(
            200,
            f"{live.BOTTLE_ORIGIN}/",
            headers=bottle_headers("text/html; charset=utf-8"),
            body=b"<!doctype html><title>Daylight Bottle</title>",
        ),
        "bottle_manifest": response(
            200,
            f"{live.BOTTLE_ORIGIN}/release-manifest.json",
            headers=bottle_headers("application/json; charset=utf-8"),
            body=json.dumps(manifest, sort_keys=True).encode("utf-8"),
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
    assert_passes(passing_responses())

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

    assert_rejects(passing_responses(), "bottle-manifest-source-commit", expected_commit="f" * 40)

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
