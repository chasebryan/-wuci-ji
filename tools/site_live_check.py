#!/usr/bin/env python3
"""Check the deployed Wuci-Ji website host, not just the static artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


APEX = "https://nosuchmachine.net/"
HTTP_APEX = "http://nosuchmachine.net/"
WWW = "https://www.nosuchmachine.net/"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


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
            contains(response.body, "assets/no-such-machine-official-emblem.svg"),
            "homepage references transparent official emblem",
        ),
        Check(
            "https-root-v20-challenge-marker",
            contains(response.body, "assets/daylight-v20-public-challenge-780thc.jpg")
            and contains(response.body, "Review evidence, reproduce the lane")
            and contains(response.body, "Endorsement is not implied."),
            "homepage references Daylight v20 public challenge",
        ),
        Check(
            "https-root-noether-forge-marker",
            contains(response.body, "Source review is open. The ISO is not published.")
            and contains(response.body, "Noether Forge · source-only review"),
            "homepage publishes Noether Forge as source-only review",
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
    legacy_wucios = fetch(APEX + "docs/wuci-os", method="HEAD", follow_redirects=False)
    legacy_wucios_location = legacy_wucios.headers.get("location", "")
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
        Check(
            "legacy-wucios-to-current",
            legacy_wucios.status == 302
            and legacy_wucios_location in {"/wucios.html", APEX + "wucios.html"},
            f"{APEX}docs/wuci-os -> {legacy_wucios.status} {legacy_wucios_location or '<no location>'}",
        ),
    ]


def check_text_asset(path: str, markers: list[str]) -> list[Check]:
    url = APEX + path
    response = fetch(url)
    checks = [Check(f"{path}-status", response.status == 200, f"{url} -> {response.status}")]
    for marker in markers:
        checks.append(Check(f"{path}-marker", contains(response.body, marker), marker))
    return checks


def check_no_browser_crypto_surface() -> list[Check]:
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
    checks: list[Check] = []
    for marker in homepage_forbidden:
        checks.append(
            Check(
                "no-browser-crypto-control",
                not contains(homepage.body, marker),
                f"homepage absent: {marker}",
            )
        )
    for marker in app_forbidden:
        checks.append(
            Check(
                "no-browser-crypto-js",
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


def check_exact_local_asset(path: str) -> list[Check]:
    url = APEX + path
    response = fetch(url)
    local_path = REPOSITORY_ROOT / "site" / path
    try:
        expected = local_path.read_bytes()
    except OSError as error:
        return [Check(f"{path}-local-source", False, str(error))]
    expected_digest = hashlib.sha256(expected).hexdigest()
    observed_digest = hashlib.sha256(response.body).hexdigest()
    return [
        Check(f"{path}-exact-status", response.status == 200, f"{url} -> {response.status}"),
        Check(
            f"{path}-content-type",
            "application/json" in response.headers.get("content-type", ""),
            response.headers.get("content-type", "<missing>"),
        ),
        Check(
            f"{path}-cache-control",
            "no-store" in response.headers.get("cache-control", "").lower(),
            response.headers.get("cache-control", "<missing>"),
        ),
        Check(
            f"{path}-exact-bytes",
            response.body == expected,
            f"expected-sha256={expected_digest} observed-sha256={observed_digest}",
        ),
    ]


def check_binary_asset(path: str, expected_content_type: str) -> list[Check]:
    url = APEX + path
    response = fetch(url, method="HEAD")
    content_type = response.headers.get("content-type", "")
    content_length = response.headers.get("content-length", "")
    content_length_detail = content_length or "<missing>"
    try:
        length_ok = int(content_length) > 0
    except ValueError:
        get_response = fetch(url)
        length_ok = get_response.status == 200 and len(get_response.body) > 0
        if length_ok:
            content_length_detail = f"body-bytes={len(get_response.body)}"
    return [
        Check(f"{path}-status", response.status == 200, f"{url} -> {response.status}"),
        Check(f"{path}-content-type", expected_content_type in content_type, content_type or "<missing>"),
        Check(f"{path}-content-length", length_ok, content_length_detail),
    ]


def run_checks() -> list[Check]:
    checks: list[Check] = []
    checks.extend(check_https_root())
    checks.extend(check_redirects())
    checks.extend(check_text_asset(".well-known/security.txt", ["Contact:", "Policy:", "Canonical:"]))
    checks.extend(
        check_text_asset(
            "llms.txt",
            [
                "Wuci-Ji v2",
                "WuciOS 2.4.0 Noether Forge source-only external review candidate",
                "00171c4cbd377f7c3c200c8a2493ad42c90a1207",
                "not production cryptography",
                "Daylight v20 public challenge poster",
                "declaration_allowed = false",
            ],
        )
    )
    checks.extend(
        check_text_asset(
            "wucios.html",
            [
                "WuciOS 2.4.0 · Source-only external review",
                "Noether Forge",
                "We do not distribute the ISO or upstream binary payloads.",
                "00171c4cbd377f7c3c200c8a2493ad42c90a1207",
                "Why there is no ISO download",
                "A sanitized video may supplement review.",
            ],
        )
    )
    checks.extend(check_text_asset("citation.cff", ["Wuci-Ji v2", "not production cryptography", "repository-code:"]))
    checks.extend(
        check_text_asset(
            "sitemap.xml",
            [
                "https://nosuchmachine.net/",
                "audits/daylight/score-integrity/",
                "no-such-machine-official-banner.jpg",
                "no-such-machine-official-emblem.svg",
                "no-such-machine-official-emblem.jpg",
                "daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp",
                "daylight-v20-public-challenge-780thc.jpg",
                "https://nosuchmachine.net/wucios.html",
                "https://nosuchmachine.net/noether-forge-status.json",
                "daylight-v20-gate-fixture-score-surface.webp",
                "daylight-v20-gate-aes-256-gcm-comparison-surface.webp",
            ],
        )
    )
    checks.extend(check_text_asset("app.js", ["enforceCanonicalHttps", "https://nosuchmachine.net"]))
    checks.extend(
        check_text_asset(
            "audits/daylight/score-integrity/",
            [
                "Daylight Audit Portal v1",
                "PASS_SCORE_INTEGRITY",
                "999,801,305 AM+",
                "Codex: PASS",
                "Fable5: PASS",
                "Recompute the Daylight v20 score.",
                "Daylight External Verifier Intake v1",
                "does not certify security",
            ],
        )
    )
    checks.extend(check_no_browser_crypto_surface())
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
            "noether-forge-status.json",
            {
                "schema",
                "releaseId",
                "reviewStatus",
                "distributionMode",
                "officialRelease",
                "publicReleaseAuthorized",
                "binaryAssetsPublished",
                "externalValidationReceived",
                "reviewedCommit",
                "substrate",
                "validationAtReviewedCommit",
                "publicationHolds",
                "nonClaims",
            },
        )
    )
    checks.extend(check_exact_local_asset("noether-forge-status.json"))
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
    checks.extend(check_binary_asset("assets/no-such-machine-official-emblem.svg", "image/svg+xml"))
    checks.extend(check_binary_asset("assets/no-such-machine-official-emblem.jpg", "image/jpeg"))
    checks.extend(check_binary_asset("assets/no-such-machine-official-banner.jpg", "image/jpeg"))
    checks.extend(check_binary_asset("assets/wuci-ji-v2-aperture-bastion.jpeg", "image/jpeg"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp", "image/webp"))
    checks.extend(check_binary_asset("assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.png", "image/png"))
    checks.extend(check_binary_asset("assets/daylight-v20-public-challenge-780thc.jpg", "image/jpeg"))
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
