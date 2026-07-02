#!/usr/bin/env python3
"""Check the deployed Wuci-Ji website host, not just the static artifact."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass


APEX = "https://nosuchmachine.net/"
HTTP_APEX = "http://nosuchmachine.net/"
WWW = "https://www.nosuchmachine.net/"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirect)


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def fetch(url: str, *, method: str = "GET", follow_redirects: bool = True, timeout: float = 12.0) -> Response:
    request = urllib.request.Request(url, method=method, headers={"User-Agent": "wuci-site-live-check/1"})
    opener = urllib.request.urlopen if follow_redirects else NO_REDIRECT_OPENER.open
    try:
        with opener(request, timeout=timeout) as handle:
            return Response(
                status=handle.status,
                headers={key.lower(): value for key, value in handle.headers.items()},
                body=handle.read(),
                url=handle.geturl(),
            )
    except urllib.error.HTTPError as error:
        return Response(
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=error.read(),
            url=url,
        )
    except urllib.error.URLError as error:
        return Response(status=0, headers={}, body=str(error).encode("utf-8"), url=url)


def contains(body: bytes, needle: str) -> bool:
    return needle.encode("utf-8") in body


def check_https_root() -> list[Check]:
    response = fetch(APEX)
    checks = [
        Check("https-root-status", response.status == 200, f"{APEX} -> {response.status}"),
        Check(
            "https-root-content-type",
            "text/html" in response.headers.get("content-type", ""),
            response.headers.get("content-type", "<missing>"),
        ),
        Check("https-root-wuci-marker", contains(response.body, "Wuci-Ji v2"), "homepage contains Wuci-Ji v2"),
        Check(
            "https-root-emblem-marker",
            contains(response.body, "assets/wuci-ji-official-emblem.jpg"),
            "homepage references official emblem",
        ),
    ]
    hsts = response.headers.get("strict-transport-security", "")
    checks.append(Check("hsts", bool(hsts and "max-age=" in hsts.lower()), hsts or "<missing>"))
    return checks


def check_redirects() -> list[Check]:
    http_response = fetch(HTTP_APEX, method="HEAD", follow_redirects=False)
    http_location = http_response.headers.get("location", "")
    www_response = fetch(WWW, method="HEAD", follow_redirects=False)
    www_location = www_response.headers.get("location", "")
    return [
        Check(
            "http-to-https-redirect",
            http_response.status in {301, 308} and http_location.startswith(APEX),
            f"{HTTP_APEX} -> {http_response.status} {http_location or '<no location>'}",
        ),
        Check(
            "www-to-apex-redirect",
            www_response.status in {301, 308} and www_location.startswith(APEX),
            f"{WWW} -> {www_response.status} {www_location or '<no location>'}",
        ),
    ]


def check_text_asset(path: str, markers: list[str]) -> list[Check]:
    url = APEX + path
    response = fetch(url)
    checks = [Check(f"{path}-status", response.status == 200, f"{url} -> {response.status}")]
    for marker in markers:
        checks.append(Check(f"{path}-marker", contains(response.body, marker), marker))
    return checks


def check_readonly_meridian_surface() -> list[Check]:
    homepage = fetch(APEX)
    app = fetch(APEX + "app.js")
    homepage_forbidden = [
        "data-meridian-file",
        "data-meridian-open-file",
        "data-meridian-open-key",
        "data-meridian-encrypt",
        "data-meridian-open",
        "data-meridian-copy-key",
        "Download opened file",
        "Download private key",
    ]
    app_forbidden = [
        "crypto.subtle.encrypt",
        "crypto.subtle.decrypt",
        "deriveKey(",
        "importKey(",
        "getRandomValues(",
        "AES-GCM",
        "privateKey",
    ]
    checks = [
        Check(
            "readonly-meridian-marker",
            contains(homepage.body, "Evidence is reviewable; browser cryptography is not shipped."),
            "homepage declares read-only Meridian posture",
        ),
        Check(
            "readonly-meridian-browser-posture",
            contains(homepage.body, "No public browser encryptor, private-key handler, or file opener is shipped."),
            "homepage declares no public browser opener",
        ),
    ]
    for marker in homepage_forbidden:
        checks.append(
            Check(
                "readonly-meridian-no-control",
                not contains(homepage.body, marker),
                f"homepage absent: {marker}",
            )
        )
    for marker in app_forbidden:
        checks.append(
            Check(
                "readonly-meridian-no-js-crypto",
                not contains(app.body, marker),
                f"app.js absent: {marker}",
            )
        )
    return checks


def check_json_asset(path: str, required_keys: set[str]) -> list[Check]:
    url = APEX + path
    response = fetch(url)
    checks = [Check(f"{path}-status", response.status == 200, f"{url} -> {response.status}")]
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        checks.append(Check(f"{path}-json", False, str(error)))
        return checks
    missing = sorted(required_keys.difference(payload))
    checks.append(Check(f"{path}-keys", not missing, f"missing={missing}" if missing else "required keys present"))
    return checks


def check_binary_asset(path: str, expected_content_type: str) -> list[Check]:
    url = APEX + path
    response = fetch(url, method="HEAD")
    content_type = response.headers.get("content-type", "")
    content_length = response.headers.get("content-length", "")
    try:
        length_ok = int(content_length) > 0
    except ValueError:
        length_ok = False
    return [
        Check(f"{path}-status", response.status == 200, f"{url} -> {response.status}"),
        Check(f"{path}-content-type", expected_content_type in content_type, content_type or "<missing>"),
        Check(f"{path}-content-length", length_ok, content_length or "<missing>"),
    ]


def run_checks() -> list[Check]:
    checks: list[Check] = []
    checks.extend(check_https_root())
    checks.extend(check_redirects())
    checks.extend(check_text_asset(".well-known/security.txt", ["Contact:", "Policy:", "Canonical:"]))
    checks.extend(check_text_asset("llms.txt", ["Wuci-Ji v2", "not production cryptography"]))
    checks.extend(check_text_asset("citation.cff", ["Wuci-Ji v2", "not production cryptography", "repository-code:"]))
    checks.extend(
        check_text_asset(
            "sitemap.xml",
            [
                "https://nosuchmachine.net/",
                "wuci-ji-official-emblem.jpg",
                "daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp",
                "daylight-v20-gate-fixture-score-surface.webp",
                "daylight-v20-gate-aes-256-gcm-comparison-surface.webp",
            ],
        )
    )
    checks.extend(check_text_asset("app.js", ["enforceCanonicalHttps", "https://nosuchmachine.net"]))
    checks.extend(check_readonly_meridian_surface())
    checks.extend(
        check_json_asset(
            "codemeta.json",
            {"@context", "@type", "name", "codeRepository", "license", "additionalProperty"},
        )
    )
    checks.extend(
        check_json_asset(
            "hosting-requirements.json",
            {"schema", "canonical_url", "required_redirects", "required_https_headers", "required_public_paths"},
        )
    )
    checks.extend(
        check_json_asset(
            "claim-evidence.json",
            {"schema", "surface", "claims", "primary_validation", "non_claims"},
        )
    )
    checks.extend(
        check_json_asset(
            "aperture-status.json",
            {"schema", "project", "layer", "release_tag", "capsule_digest", "non_claims"},
        )
    )
    checks.extend(check_json_asset("daylight-status.json", {"score_AM_plus", "unit", "scorecard_digest", "source"}))
    checks.extend(
        check_json_asset(
            "daylight-v20-aperture-singularity-status.json",
            {"schema", "capsule_digest", "score_AM_plus", "declared", "non_claims"},
        )
    )
    checks.extend(check_binary_asset("assets/wuci-ji-official-emblem.jpg", "image/jpeg"))
    checks.extend(check_binary_asset("assets/wuci-ji-v2-aperture-bastion.jpeg", "image/jpeg"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp", "image/webp"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.png", "image/png"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-fixture-score-surface.webp", "image/webp"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-fixture-score-surface.png", "image/png"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-aes-256-gcm-comparison-surface.webp", "image/webp"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-aes-256-gcm-comparison-surface.png", "image/png"))
    return checks


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable check results")
    args = parser.parse_args(argv)

    checks = run_checks()
    if args.json:
        print(json.dumps([check.__dict__ for check in checks], indent=2, sort_keys=True))
    else:
        width = max(len(check.name) for check in checks)
        for check in checks:
            status = "PASS" if check.ok else "FAIL"
            print(f"{status} {check.name:<{width}} {check.detail}")

    failures = [check for check in checks if not check.ok]
    if failures:
        print(f"site-live-check: {len(failures)} failure(s)", file=sys.stderr)
        return 1
    print("site-live-check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
