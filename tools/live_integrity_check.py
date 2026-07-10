#!/usr/bin/env python3
"""Evaluate public deployment drift without sending credentials or user data.

The default mode reads an explicit JSON snapshot and performs no network I/O.
Pass ``--live`` to issue the fixed, read-only request plan documented below.
Response bodies are bounded and never printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "wuci-live-integrity-snapshot-v1"
SITE_ORIGIN = "https://nosuchmachine.net"
SITE_APEX = f"{SITE_ORIGIN}/"
SITE_HTTP_APEX = "http://nosuchmachine.net/"
SITE_WWW = "https://www.nosuchmachine.net/"
SITE_SECONDARY = "https://chasebryan.github.io/-wuci-ji/"
BOTTLE_ORIGIN = "https://bottle.nosuchmachine.net"
CANONICAL_REPOSITORY = "https://github.com/chasebryan/-wuci-ji"
ZERO_FINGERPRINT = f"sha256:{'0' * 64}"
MAX_RESPONSE_BYTES = 1_048_576
BROWSER_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0"

REQUIRED_BOTTLE_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; connect-src 'self'; "
        "img-src 'self'; style-src 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; object-src 'none'"
    ),
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}
FORBIDDEN_RESPONSE_HEADERS = ("nel", "report-to")
ANALYTICS_MARKERS = (
    b"static.cloudflareinsights.com",
    b"data-cf-beacon",
    b"/cdn-cgi/rum",
)
KEYNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/-]{2,63}$")
FINGERPRINT_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
AGE_RECIPIENT_PATTERN = re.compile(r"^age1[a-z0-9]{20,511}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirect)


@dataclass(frozen=True)
class RequestSpec:
    name: str
    url: str
    method: str = "GET"
    follow_redirects: bool = True
    user_agent: str = "wuci-live-integrity-check/1"


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str
    truncated: bool = False


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


REQUEST_PLAN = (
    RequestSpec("site_https_root", SITE_APEX),
    RequestSpec("site_http_root", SITE_HTTP_APEX, method="HEAD", follow_redirects=False),
    RequestSpec("site_www_root", SITE_WWW, method="HEAD", follow_redirects=False),
    RequestSpec("site_secondary", SITE_SECONDARY, method="HEAD", follow_redirects=False),
    RequestSpec("site_browser_wucios", f"{SITE_ORIGIN}/wucios", user_agent=BROWSER_USER_AGENT),
    RequestSpec("bottle_root", f"{BOTTLE_ORIGIN}/"),
    RequestSpec("bottle_manifest", f"{BOTTLE_ORIGIN}/release-manifest.json"),
    RequestSpec(
        "bottle_api",
        f"{BOTTLE_ORIGIN}/api/bottles?recipientFingerprint={ZERO_FINGERPRINT}",
    ),
    RequestSpec("bottle_keyring", f"{BOTTLE_ORIGIN}/keyring.json"),
    RequestSpec("site_bottle_status", f"{SITE_ORIGIN}/daylight-bottle-status.json"),
    RequestSpec(
        "site_bottle_observation",
        f"{SITE_ORIGIN}/daylight-bottle-keyring-observation.json",
    ),
)


def fetch(spec: RequestSpec, *, timeout: float = 12.0) -> Response:
    request = urllib.request.Request(
        spec.url,
        method=spec.method,
        headers={"User-Agent": spec.user_agent, "Accept": "*/*"},
    )
    opener = urllib.request.urlopen if spec.follow_redirects else NO_REDIRECT_OPENER.open
    try:
        with opener(request, timeout=timeout) as handle:
            body = handle.read(MAX_RESPONSE_BYTES + 1)
            return Response(
                status=handle.status,
                headers={key.lower(): value for key, value in handle.headers.items()},
                body=body[:MAX_RESPONSE_BYTES],
                url=handle.geturl(),
                truncated=len(body) > MAX_RESPONSE_BYTES,
            )
    except urllib.error.HTTPError as error:
        body = error.read(MAX_RESPONSE_BYTES + 1)
        return Response(
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=body[:MAX_RESPONSE_BYTES],
            url=spec.url,
            truncated=len(body) > MAX_RESPONSE_BYTES,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return Response(status=0, headers={}, body=b"", url=spec.url)


def capture_live() -> dict[str, Response]:
    return {spec.name: fetch(spec) for spec in REQUEST_PLAN}


def load_snapshot(path: Path) -> tuple[str, dict[str, Response]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ValueError(f"snapshot schema must be {SCHEMA}")
    expected_commit = payload.get("expectedCommit")
    if not isinstance(expected_commit, str):
        raise ValueError("snapshot expectedCommit must be a string")
    raw_responses = payload.get("responses")
    if not isinstance(raw_responses, dict):
        raise ValueError("snapshot responses must be an object")
    responses: dict[str, Response] = {}
    for name, value in raw_responses.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise ValueError("snapshot response entries must be objects")
        status = value.get("status")
        headers = value.get("headers")
        body = value.get("body", "")
        url = value.get("url")
        truncated = value.get("truncated", False)
        if (
            not isinstance(status, int)
            or not isinstance(headers, dict)
            or not all(isinstance(key, str) and isinstance(item, str) for key, item in headers.items())
            or not isinstance(body, str)
            or not isinstance(url, str)
            or not isinstance(truncated, bool)
        ):
            raise ValueError(f"snapshot response {name} has an invalid shape")
        responses[name] = Response(
            status=status,
            headers={key.lower(): item for key, item in headers.items()},
            body=body.encode("utf-8"),
            url=url,
            truncated=truncated,
        )
    return expected_commit, responses


def response_or_missing(responses: Mapping[str, Response], name: str) -> Response:
    return responses.get(name, Response(status=0, headers={}, body=b"", url="<missing>"))


def json_body(response: Response) -> Any | None:
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def has_forbidden_analytics(body: bytes) -> bool:
    lowered = body.lower()
    return any(marker.lower() in lowered for marker in ANALYTICS_MARKERS)


def add_common_response_checks(checks: list[Check], label: str, response: Response) -> None:
    checks.append(
        Check(
            f"{label}-bounded-body",
            not response.truncated,
            f"body-bytes={len(response.body)} limit={MAX_RESPONSE_BYTES}",
        )
    )
    for header in FORBIDDEN_RESPONSE_HEADERS:
        checks.append(
            Check(
                f"{label}-no-{header}",
                header not in response.headers,
                "absent" if header not in response.headers else "present",
            )
        )


def add_bottle_header_checks(checks: list[Check], label: str, response: Response) -> None:
    add_common_response_checks(checks, label, response)
    for header, expected in REQUIRED_BOTTLE_HEADERS.items():
        observed = response.headers.get(header, "")
        checks.append(
            Check(
                f"{label}-{header}",
                observed == expected,
                "exact" if observed == expected else f"expected={expected!r} observed={observed!r}",
            )
        )
    cache_control = response.headers.get("cache-control", "")
    checks.append(
        Check(
            f"{label}-no-store",
            "no-store" in cache_control.lower(),
            cache_control or "<missing>",
        )
    )


def valid_keyring(payload: Any) -> tuple[bool, str, int]:
    if not isinstance(payload, dict) or set(payload) != {"schema", "updatedAt", "keys"}:
        return False, "keyring fields are not exact", 0
    if payload.get("schema") != "nsm.daylight-bottle.keyring.v1":
        return False, "unsupported keyring schema", 0
    if not isinstance(payload.get("updatedAt"), str) or not isinstance(payload.get("keys"), list):
        return False, "invalid keyring updatedAt or keys", 0
    active_keynames: set[str] = set()
    fingerprints: set[str] = set()
    active_count = 0
    for candidate in payload["keys"]:
        fields = {"schema", "keyname", "publicRecipient", "fingerprint", "createdAt", "status"}
        if not isinstance(candidate, dict) or set(candidate) != fields:
            return False, "key record fields are not exact", 0
        keyname = candidate.get("keyname")
        recipient = candidate.get("publicRecipient")
        fingerprint = candidate.get("fingerprint")
        status = candidate.get("status")
        if (
            candidate.get("schema") != "nsm.daylight-bottle.key.v1"
            or not isinstance(keyname, str)
            or not KEYNAME_PATTERN.fullmatch(keyname)
            or ".." in keyname
            or "//" in keyname
            or keyname.startswith("/")
            or keyname.endswith("/")
            or not isinstance(recipient, str)
            or not AGE_RECIPIENT_PATTERN.fullmatch(recipient)
            or not isinstance(fingerprint, str)
            or not FINGERPRINT_PATTERN.fullmatch(fingerprint)
            or status not in {"active", "revoked"}
        ):
            return False, "invalid key record", 0
        canonical = f"nsm.daylight-bottle.key.v1\n{keyname}\n{recipient}".encode("utf-8")
        expected = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        if fingerprint != expected or fingerprint in fingerprints:
            return False, "keyring fingerprint mismatch or duplicate", 0
        fingerprints.add(fingerprint)
        if status == "active":
            if keyname in active_keynames:
                return False, "duplicate active keyname", 0
            active_keynames.add(keyname)
            active_count += 1
    return True, "canonical keyring", active_count


def evaluate(responses: Mapping[str, Response], expected_commit: str) -> list[Check]:
    checks: list[Check] = []
    checks.append(
        Check(
            "expected-commit-format",
            bool(COMMIT_PATTERN.fullmatch(expected_commit)),
            expected_commit,
        )
    )

    site_root = response_or_missing(responses, "site_https_root")
    checks.extend(
        [
            Check("site-https-status", site_root.status == 200, f"status={site_root.status}"),
            Check("site-https-final-url", site_root.url == SITE_APEX, site_root.url),
            Check(
                "site-hsts",
                "max-age=" in site_root.headers.get("strict-transport-security", "").lower(),
                site_root.headers.get("strict-transport-security", "<missing>"),
            ),
            Check(
                "site-html-no-transform",
                "no-transform" in site_root.headers.get("cache-control", "").lower(),
                site_root.headers.get("cache-control", "<missing>"),
            ),
            Check(
                "site-root-no-analytics-injection",
                not has_forbidden_analytics(site_root.body),
                "analytics markers absent",
            ),
        ]
    )
    add_common_response_checks(checks, "site-root", site_root)

    http_root = response_or_missing(responses, "site_http_root")
    http_location = http_root.headers.get("location", "")
    checks.append(
        Check(
            "site-http-upgrades-to-canonical-https",
            http_root.status in {301, 308} and http_location.startswith(SITE_APEX),
            f"status={http_root.status} location={http_location or '<missing>'}",
        )
    )
    add_common_response_checks(checks, "site-http", http_root)
    www_root = response_or_missing(responses, "site_www_root")
    www_location = www_root.headers.get("location", "")
    checks.append(
        Check(
            "site-www-redirects-to-canonical-https",
            www_root.status in {301, 308} and www_location.startswith(SITE_APEX),
            f"status={www_root.status} location={www_location or '<missing>'}",
        )
    )
    add_common_response_checks(checks, "site-www", www_root)

    secondary = response_or_missing(responses, "site_secondary")
    secondary_location = secondary.headers.get("location", "")
    secondary_retired = secondary.status in {404, 410}
    secondary_safe_redirect = (
        secondary.status in {301, 302, 307, 308}
        and secondary_location.startswith(SITE_APEX)
    )
    checks.append(
        Check(
            "site-secondary-retired-or-canonical-https",
            secondary_retired or secondary_safe_redirect,
            f"status={secondary.status} location={secondary_location or '<missing>'}",
        )
    )
    add_common_response_checks(checks, "site-secondary", secondary)

    browser_page = response_or_missing(responses, "site_browser_wucios")
    checks.extend(
        [
            Check("site-browser-wucios-status", browser_page.status == 200, f"status={browser_page.status}"),
            Check(
                "site-browser-wucios-https",
                browser_page.url.startswith(f"{SITE_ORIGIN}/"),
                browser_page.url,
            ),
            Check(
                "site-browser-no-analytics-injection",
                not has_forbidden_analytics(browser_page.body),
                "analytics markers absent",
            ),
        ]
    )
    add_common_response_checks(checks, "site-browser", browser_page)

    bottle_root = response_or_missing(responses, "bottle_root")
    checks.extend(
        [
            Check("bottle-root-status", bottle_root.status == 200, f"status={bottle_root.status}"),
            Check("bottle-root-https", bottle_root.url == f"{BOTTLE_ORIGIN}/", bottle_root.url),
            Check(
                "bottle-root-content-type",
                "text/html" in bottle_root.headers.get("content-type", "").lower(),
                bottle_root.headers.get("content-type", "<missing>"),
            ),
            Check(
                "bottle-root-no-analytics-injection",
                not has_forbidden_analytics(bottle_root.body),
                "analytics markers absent",
            ),
        ]
    )
    add_bottle_header_checks(checks, "bottle-root", bottle_root)

    manifest_response = response_or_missing(responses, "bottle_manifest")
    add_bottle_header_checks(checks, "bottle-manifest", manifest_response)
    manifest = json_body(manifest_response)
    checks.extend(
        [
            Check("bottle-manifest-status", manifest_response.status == 200, f"status={manifest_response.status}"),
            Check("bottle-manifest-json", isinstance(manifest, dict), "valid object" if isinstance(manifest, dict) else "invalid JSON"),
        ]
    )
    manifest_source = manifest.get("source") if isinstance(manifest, dict) else None
    manifest_inputs = manifest.get("inputs") if isinstance(manifest, dict) else None
    manifest_subject = manifest.get("subjectSha256") if isinstance(manifest, dict) else None
    checks.extend(
        [
            Check(
                "bottle-manifest-schema",
                isinstance(manifest, dict) and manifest.get("schema") == "nsm.daylight-bottle.release-manifest.v1",
                str(manifest.get("schema")) if isinstance(manifest, dict) else "<invalid>",
            ),
            Check(
                "bottle-manifest-source-repository",
                isinstance(manifest_source, dict) and manifest_source.get("repository") == CANONICAL_REPOSITORY,
                str(manifest_source.get("repository")) if isinstance(manifest_source, dict) else "<invalid>",
            ),
            Check(
                "bottle-manifest-source-commit",
                isinstance(manifest_source, dict) and manifest_source.get("commit") == expected_commit,
                str(manifest_source.get("commit")) if isinstance(manifest_source, dict) else "<invalid>",
            ),
            Check(
                "bottle-manifest-clean-tree",
                isinstance(manifest_source, dict) and manifest_source.get("treeState") == "clean",
                str(manifest_source.get("treeState")) if isinstance(manifest_source, dict) else "<invalid>",
            ),
            Check(
                "bottle-manifest-subject-digest",
                isinstance(manifest_subject, str) and bool(FINGERPRINT_PATTERN.fullmatch(manifest_subject)),
                str(manifest_subject),
            ),
        ]
    )

    api_response = response_or_missing(responses, "bottle_api")
    add_bottle_header_checks(checks, "bottle-api", api_response)
    api_payload = json_body(api_response)
    api_exact = isinstance(api_payload, dict) and set(api_payload) == {"schema", "bottles"}
    api_bottles = api_payload.get("bottles") if isinstance(api_payload, dict) else None
    checks.extend(
        [
            Check("bottle-api-status", api_response.status == 200, f"status={api_response.status}"),
            Check("bottle-api-exact-fields", api_exact, "schema,bottles"),
            Check(
                "bottle-api-schema",
                isinstance(api_payload, dict) and api_payload.get("schema") == "nsm.daylight-bottle.list.response.v1",
                str(api_payload.get("schema")) if isinstance(api_payload, dict) else "<invalid>",
            ),
            Check(
                "bottle-api-zero-probe-empty",
                api_bottles == [],
                f"candidate-count={len(api_bottles) if isinstance(api_bottles, list) else '<invalid>'}",
            ),
        ]
    )

    keyring_response = response_or_missing(responses, "bottle_keyring")
    add_bottle_header_checks(checks, "bottle-keyring", keyring_response)
    keyring = json_body(keyring_response)
    keyring_ok, keyring_detail, active_count = valid_keyring(keyring)
    keyring_sha256 = f"sha256:{hashlib.sha256(keyring_response.body).hexdigest()}"
    checks.extend(
        [
            Check("bottle-keyring-status", keyring_response.status == 200, f"status={keyring_response.status}"),
            Check("bottle-keyring-schema-and-records", keyring_ok, keyring_detail),
            Check(
                "bottle-manifest-keyring-digest",
                isinstance(manifest_inputs, dict)
                and manifest_inputs.get("keyringSha256") == keyring_sha256.removeprefix("sha256:"),
                f"live={keyring_sha256}",
            ),
        ]
    )

    status_response = response_or_missing(responses, "site_bottle_status")
    add_common_response_checks(checks, "site-bottle-status", status_response)
    status = json_body(status_response)
    expected_activation = "pending" if active_count == 0 else "active"
    checks.extend(
        [
            Check("site-bottle-status-http", status_response.status == 200, f"status={status_response.status}"),
            Check(
                "site-bottle-status-schema",
                isinstance(status, dict) and status.get("schema") == "nsm.daylight-bottle.public-status.v1",
                str(status.get("schema")) if isinstance(status, dict) else "<invalid>",
            ),
            Check(
                "site-bottle-status-origin",
                isinstance(status, dict)
                and status.get("origin") == BOTTLE_ORIGIN
                and status.get("keyringUrl") == f"{BOTTLE_ORIGIN}/keyring.json",
                "canonical Bottle origin",
            ),
            Check(
                "site-bottle-status-keyring-schema",
                isinstance(status, dict)
                and isinstance(keyring, dict)
                and status.get("keyringSchema") == keyring.get("schema"),
                "status matches live keyring schema",
            ),
            Check(
                "site-bottle-status-keyring-updated-at",
                isinstance(status, dict)
                and isinstance(keyring, dict)
                and status.get("keyringUpdatedAt") == keyring.get("updatedAt"),
                "status matches live keyring updatedAt",
            ),
            Check(
                "site-bottle-status-keyring-digest",
                isinstance(status, dict) and status.get("keyringSha256") == keyring_sha256,
                f"live={keyring_sha256}",
            ),
            Check(
                "site-bottle-status-active-count",
                isinstance(status, dict) and status.get("activeRecipientCount") == active_count,
                f"live={active_count}",
            ),
            Check(
                "site-bottle-status-activation",
                isinstance(status, dict) and status.get("recipientActivation") == expected_activation,
                f"expected={expected_activation}",
            ),
        ]
    )

    observation_response = response_or_missing(responses, "site_bottle_observation")
    add_common_response_checks(checks, "site-bottle-observation", observation_response)
    observation = json_body(observation_response)
    checks.extend(
        [
            Check(
                "site-bottle-observation-http",
                observation_response.status == 200,
                f"status={observation_response.status}",
            ),
            Check(
                "site-bottle-observation-bytes",
                observation_response.body == keyring_response.body,
                (
                    f"keyring-sha256={hashlib.sha256(keyring_response.body).hexdigest()} "
                    f"observation-sha256={hashlib.sha256(observation_response.body).hexdigest()}"
                ),
            ),
            Check(
                "site-bottle-observation-json",
                observation == keyring,
                "observation matches live keyring",
            ),
            Check(
                "site-bottle-observation-path",
                isinstance(status, dict)
                and status.get("observationMethod") == "https-live-readback"
                and status.get("observationPath") == "daylight-bottle-keyring-observation.json",
                "status identifies bounded live readback",
            ),
        ]
    )
    return checks


def emit(checks: list[Check], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps([check.__dict__ for check in checks], indent=2, sort_keys=True))
        return
    width = max(len(check.name) for check in checks)
    for check in checks:
        print(f"{'PASS' if check.ok else 'FAIL'} {check.name:<{width}} {check.detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", type=Path, help="evaluate a local JSON snapshot without network I/O")
    mode.add_argument("--live", action="store_true", help="perform the fixed public, read-only network request plan")
    parser.add_argument("--expected-commit", help="40-character commit expected in the Bottle manifest")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)

    try:
        if args.snapshot:
            snapshot_commit, responses = load_snapshot(args.snapshot)
            expected_commit = args.expected_commit or snapshot_commit
        else:
            if not args.expected_commit:
                parser.error("--live requires --expected-commit")
            expected_commit = args.expected_commit
            responses = capture_live()
        checks = evaluate(responses, expected_commit)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"live-integrity-check: {error}", file=sys.stderr)
        return 2

    emit(checks, as_json=args.json)
    failures = [check for check in checks if not check.ok]
    if failures:
        print(f"live-integrity-check: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("live-integrity-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
