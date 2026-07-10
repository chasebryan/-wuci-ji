#!/usr/bin/env python3
"""Evaluate public deployment drift without sending credentials or user data.

The default mode reads an explicit JSON snapshot and performs no network I/O.
Pass ``--live`` to issue the bounded, same-origin, read-only request plan after
rebuilding Daylight Bottle locally. The local ``dist/`` tree defines every
Bottle artifact request, expected byte string, and response cap; the remote
manifest cannot expand the request plan. Response bodies are bounded and never
printed.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from tools import site_dist


SCHEMA = "wuci-live-integrity-snapshot-v2"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SITE_ORIGIN = "https://nosuchmachine.net"
SITE_APEX = f"{SITE_ORIGIN}/"
SITE_HTTP_APEX = "http://nosuchmachine.net/"
SITE_WWW = "https://www.nosuchmachine.net/"
SITE_SECONDARY = "https://chasebryan.github.io/-wuci-ji/"
BOTTLE_ORIGIN = "https://bottle.nosuchmachine.net"
CANONICAL_REPOSITORY = "https://github.com/chasebryan/-wuci-ji"
ZERO_FINGERPRINT = f"sha256:{'0' * 64}"
MAX_RESPONSE_BYTES = 1_048_576
MAX_MANIFEST_ARTIFACTS = 32
MAX_MANIFEST_ARTIFACT_BYTES = 2_097_152
MAX_ARTIFACT_CAPTURE_SECONDS = 20.0
MAX_ARTIFACT_REQUEST_SECONDS = 5.0
MAX_SITE_CAPTURE_SECONDS = 120.0
MAX_SITE_REQUEST_SECONDS = 15.0
MAX_SITE_WORKERS = 8
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:152.0) Gecko/20100101 Firefox/152.0"
)

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
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ISO_TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$"
)
ARTIFACT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
NODE_VERSION_PATTERN = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
RUNTIME_EXTENSIONS = {".html", ".js", ".mjs", ".css"}
PUBLIC_ROOT_ARTIFACTS = {"_headers", "favicon.svg", "index.html", "keyring.json"}
PUBLIC_ASSET_EXTENSIONS = {
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".mjs",
    ".png",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
}
MAX_RUNTIME_BYTES = 220 * 1024
MAX_RUNTIME_GZIP_BYTES = 80 * 1024
WORKER_SOURCE_PATHS = (
    "public/keyring.json",
    "src/crypto/fingerprint.ts",
    "src/domain/types.ts",
    "src/domain/validation.ts",
    "worker/index.ts",
)
MANIFEST_INPUT_PATHS = {
    "packageJsonSha256": "package.json",
    "packageLockSha256": "package-lock.json",
    "keyringSha256": "public/keyring.json",
    "securityHeadersSha256": "public/_headers",
    "wranglerConfigSha256": "wrangler.toml",
}

ARTIFACT_MEDIA_TYPES = {
    ".css": {"text/css"},
    ".gif": {"image/gif"},
    ".html": {"text/html"},
    ".ico": {"image/vnd.microsoft.icon", "image/x-icon"},
    ".jpeg": {"image/jpeg"},
    ".jpg": {"image/jpeg"},
    ".js": {"application/javascript", "text/javascript"},
    ".json": {"application/json"},
    ".mjs": {"application/javascript", "text/javascript"},
    ".png": {"image/png"},
    ".svg": {"image/svg+xml"},
    ".webp": {"image/webp"},
    ".woff": {"font/woff"},
    ".woff2": {"font/woff2"},
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirect)


@dataclass(frozen=True)
class RequestSpec:
    name: str
    url: str
    method: str = "GET"
    follow_redirects: bool = False
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


@dataclass(frozen=True)
class LocalBottleBuild:
    manifest: Mapping[str, Any]
    manifest_bytes: bytes
    artifacts: Mapping[str, bytes]


@dataclass(frozen=True)
class SiteArtifact:
    path: str
    response_name: str
    url: str
    status: int
    media_type: str
    content: bytes
    user_agent: str = "wuci-live-integrity-check/1"


@dataclass(frozen=True)
class RedirectExpectation:
    response_name: str
    url: str
    status: int
    location: str


@dataclass(frozen=True)
class LocalSiteBuild:
    inventory: Mapping[str, Any]
    inventory_bytes: bytes
    configs: Mapping[str, bytes]
    artifacts: tuple[SiteArtifact, ...]
    redirects: tuple[RedirectExpectation, ...]


SITE_RESPONSE_NAMES = {
    "index.html": "site_https_root",
    "wucios.html": "site_browser_wucios",
    "app.js": "site_app_js",
    "styles.css": "site_styles_css",
    "daylight-bottle-status.json": "site_bottle_status",
    "daylight-bottle-keyring-observation.json": "site_bottle_observation",
}


REQUEST_PLAN = (
    RequestSpec("site_secondary", SITE_SECONDARY, method="HEAD", follow_redirects=False),
    RequestSpec("bottle_root", f"{BOTTLE_ORIGIN}/"),
    RequestSpec("bottle_manifest", f"{BOTTLE_ORIGIN}/release-manifest.json"),
    RequestSpec(
        "bottle_api",
        f"{BOTTLE_ORIGIN}/api/bottles?recipientFingerprint={ZERO_FINGERPRINT}",
    ),
    RequestSpec("bottle_keyring", f"{BOTTLE_ORIGIN}/keyring.json"),
)


def canonical_json_bytes(value: Any) -> bytes:
    """Match JSON.stringify for the ASCII/integer release-manifest contract."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def read_regular_repo_file(relative_path: str) -> bytes:
    path = REPOSITORY_ROOT / relative_path
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
        raise ValueError(f"repository input must be a single-link regular file: {relative_path}")
    return path.read_bytes()


def bottle_file(relative_path: str) -> bytes:
    return read_regular_repo_file(f"apps/bottle/{relative_path}")


def site_response_name(path: str) -> str:
    return SITE_RESPONSE_NAMES.get(path, f"site_artifact:{path}")


def site_check_label(path: str) -> str:
    labels = {
        "index.html": "site-root",
        "wucios.html": "site-browser-wucios",
        "app.js": "site-app-js",
        "styles.css": "site-styles-css",
        "daylight-bottle-status.json": "site-bottle-status",
        "daylight-bottle-keyring-observation.json": "site-bottle-observation",
    }
    return labels.get(path, f"site-artifact-{path}")


def parse_site_redirects(content: bytes) -> tuple[RedirectExpectation, ...]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("staged _redirects must be UTF-8") from error
    redirects: list[RedirectExpectation] = []
    used_names: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3 or parts[2] not in {"301", "302", "307", "308"}:
            raise ValueError(f"staged _redirects line {line_number} is invalid")
        source, target, raw_status = parts
        if "*" in source:
            if not source.endswith("/*") or target.count(":splat") != 1:
                raise ValueError(f"staged _redirects wildcard line {line_number} is invalid")
            url = source.removesuffix("*")
            location = target.replace(":splat", "")
        else:
            if ":" in source and not source.startswith(("http://", "https://")):
                raise ValueError(f"staged _redirects source line {line_number} is invalid")
            url = source if source.startswith(("http://", "https://")) else f"{SITE_ORIGIN}{source}"
            location = target
        names = {
            "http://nosuchmachine.net/*": "site_http_root",
            "http://www.nosuchmachine.net/*": "site_http_www_root",
            "https://www.nosuchmachine.net/*": "site_www_root",
        }
        name = names.get(source, f"site_redirect:{source}")
        if name in used_names:
            raise ValueError(f"staged _redirects contains a duplicate source: {source}")
        used_names.add(name)
        redirects.append(
            RedirectExpectation(
                response_name=name,
                url=url,
                status=int(raw_status),
                location=location,
            )
        )
    if not redirects:
        raise ValueError("staged _redirects contains no redirect rules")
    return tuple(redirects)


def site_global_headers(content: bytes) -> dict[str, str]:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("staged _headers must be UTF-8") from error
    try:
        start = next(index for index, line in enumerate(lines) if line.strip() == "/*")
    except StopIteration as error:
        raise ValueError("staged _headers is missing the global rule") from error
    headers: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if line and not line[0].isspace():
            break
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("!") or ":" not in stripped:
            raise ValueError("staged _headers global rule is invalid")
        name, value = stripped.split(":", 1)
        normalized = name.strip().lower()
        if not normalized or normalized in headers:
            raise ValueError("staged _headers global rule contains a duplicate header")
        headers[normalized] = value.strip()
    required = {
        "content-security-policy",
        "strict-transport-security",
        "referrer-policy",
        "x-content-type-options",
        "x-frame-options",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
        "cache-control",
    }
    if set(headers) != required:
        raise ValueError("staged _headers global rule fields are not exact")
    return headers


def load_local_site_build() -> LocalSiteBuild:
    staged = site_dist.collect_regular_tree(site_dist.OUTPUT_ROOT)
    inventory_content = staged.get(site_dist.INVENTORY_NAME)
    if inventory_content is None:
        raise ValueError("staged site tree is missing site-inventory.json")
    try:
        inventory = json.loads(
            inventory_content.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("staged site inventory is invalid JSON") from error
    site_dist.validate_inventory(inventory, staged)

    configs = {path: staged[path] for path in site_dist.CONFIG_FILES}
    site_global_headers(configs["_headers"])
    redirects = parse_site_redirects(configs["_redirects"])
    records = list(inventory["publicFiles"])
    records.append(site_dist.public_file_record(site_dist.INVENTORY_NAME, inventory_content))
    artifacts = tuple(
        SiteArtifact(
            path=record["path"],
            response_name=site_response_name(record["path"]),
            url=f"{SITE_ORIGIN}{record['urlPath']}",
            status=record["status"],
            media_type=record["mediaType"],
            content=staged[record["path"]],
            user_agent=(
                BROWSER_USER_AGENT
                if record["mediaType"] in {"text/html", "application/javascript"}
                else "wuci-live-integrity-check/1"
            ),
        )
        for record in sorted(records, key=lambda item: item["path"])
    )
    if len(artifacts) + len(configs) > site_dist.MAX_SITE_FILES:
        raise ValueError("staged site capture exceeds the fixed file-count budget")
    if sum(len(artifact.content) for artifact in artifacts) > site_dist.MAX_SITE_TOTAL_BYTES:
        raise ValueError("staged site capture exceeds the fixed aggregate byte budget")
    if len({artifact.response_name for artifact in artifacts}) != len(artifacts):
        raise ValueError("staged site capture response names are not unique")
    return LocalSiteBuild(
        inventory=inventory,
        inventory_bytes=inventory_content,
        configs=configs,
        artifacts=artifacts,
        redirects=redirects,
    )


def collect_regular_tree(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"artifact root must be a real directory: {root}")

    files: dict[str, bytes] = {}

    def visit(directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda candidate: candidate.name):
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise ValueError(f"artifact entry must not be a symlink: {relative}")
            if path.is_dir():
                visit(path)
                continue
            if not path.is_file() or metadata.st_nlink != 1:
                raise ValueError(
                    f"artifact entry must be a single-link regular file: {relative}"
                )
            files[relative] = path.read_bytes()

    visit(root)
    return files


def load_local_bottle_build() -> LocalBottleBuild:
    dist = REPOSITORY_ROOT / "apps" / "bottle" / "dist"
    files = collect_regular_tree(dist)
    manifest_bytes = files.pop("release-manifest.json", None)
    if manifest_bytes is None:
        raise ValueError("local Bottle build is missing dist/release-manifest.json")
    try:
        manifest = json.loads(
            manifest_bytes.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("local Bottle release manifest is invalid JSON") from error
    if not isinstance(manifest, dict):
        raise ValueError("local Bottle release manifest must be an object")
    if not files:
        raise ValueError("local Bottle build contains no public artifacts")
    if len(files) > MAX_MANIFEST_ARTIFACTS:
        raise ValueError("local Bottle build exceeds the artifact-count budget")
    if sum(len(content) for content in files.values()) > MAX_MANIFEST_ARTIFACT_BYTES:
        raise ValueError("local Bottle build exceeds the aggregate artifact-byte budget")
    if not all(valid_artifact_path(path) for path in files):
        raise ValueError("local Bottle build contains a path outside the public artifact contract")

    records = [
        {"path": path, "bytes": len(content), "sha256": sha256(content)}
        for path, content in sorted(files.items())
    ]
    if manifest.get("artifacts") != records:
        raise ValueError("local Bottle manifest does not describe the rebuilt dist bytes")
    return LocalBottleBuild(
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        artifacts=files,
    )


def build_worker_source_closure() -> dict[str, Any]:
    files = []
    for path in sorted(WORKER_SOURCE_PATHS):
        content = bottle_file(path)
        files.append({"path": path, "bytes": len(content), "sha256": sha256(content)})
    return {
        "schema": "nsm.daylight-bottle.worker-source-closure.v1",
        "sha256": sha256(canonical_json_bytes(files)),
        "files": files,
    }


def expected_manifest_inputs() -> dict[str, Any]:
    inputs: dict[str, Any] = {
        field: sha256(bottle_file(path)) for field, path in MANIFEST_INPUT_PATHS.items()
    }
    inputs["workerSourceClosure"] = build_worker_source_closure()
    # Preserve the exact key order emitted by generate-release-manifest.mjs.
    return {
        "packageJsonSha256": inputs["packageJsonSha256"],
        "packageLockSha256": inputs["packageLockSha256"],
        "keyringSha256": inputs["keyringSha256"],
        "securityHeadersSha256": inputs["securityHeadersSha256"],
        "workerSourceClosure": inputs["workerSourceClosure"],
        "wranglerConfigSha256": inputs["wranglerConfigSha256"],
    }


def valid_canonical_timestamp(value: Any) -> bool:
    """Faithfully implement the JS regex/Date/toISOString timestamp contract."""
    if not isinstance(value, str):
        return False
    match = ISO_TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second, _millisecond = map(int, match.groups())
    if month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59:
        return False
    month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        month_days[1] = 29
    return 1 <= day <= month_days[month - 1]


def valid_artifact_path(path: Any) -> bool:
    structurally_safe = (
        isinstance(path, str)
        and bool(ARTIFACT_PATH_PATTERN.fullmatch(path))
        and not path.startswith("/")
        and not path.endswith("/")
        and ".." not in path
        and "//" not in path
    )
    if not structurally_safe:
        return False
    return path in PUBLIC_ROOT_ARTIFACTS or (
        path.startswith("assets/")
        and path.count("/") == 1
        and Path(path).suffix in PUBLIC_ASSET_EXTENSIONS
    )


def artifact_response_name(path: str) -> str:
    return f"bottle_artifact:{path}"


def artifact_url(path: str) -> str:
    return f"{BOTTLE_ORIGIN}/{path}"


def manifest_artifact_paths(payload: Any) -> list[str]:
    if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
        return []
    artifacts = payload["artifacts"]
    if not 0 < len(artifacts) <= MAX_MANIFEST_ARTIFACTS:
        return []
    paths: list[str] = []
    total_bytes = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "bytes", "sha256"}:
            return []
        path = artifact.get("path")
        size = artifact.get("bytes")
        digest = artifact.get("sha256")
        if (
            not valid_artifact_path(path)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_RESPONSE_BYTES
            or not isinstance(digest, str)
            or not SHA256_PATTERN.fullmatch(digest)
        ):
            return []
        total_bytes += size
        paths.append(path)
    if total_bytes > MAX_MANIFEST_ARTIFACT_BYTES or paths != sorted(set(paths)):
        return []
    return paths


def fetch(
    spec: RequestSpec,
    *,
    timeout: float = 12.0,
    max_body_bytes: int = MAX_RESPONSE_BYTES,
) -> Response:
    absolute_limit = max(MAX_RESPONSE_BYTES, site_dist.MAX_SITE_FILE_BYTES)
    if max_body_bytes < 0 or max_body_bytes > absolute_limit:
        raise ValueError("response body limit is outside the fixed checker budget")
    request = urllib.request.Request(
        spec.url,
        method=spec.method,
        headers={"User-Agent": spec.user_agent, "Accept": "*/*"},
    )
    opener = urllib.request.urlopen if spec.follow_redirects else NO_REDIRECT_OPENER.open
    try:
        with opener(request, timeout=timeout) as handle:
            body = handle.read(max_body_bytes + 1)
            return Response(
                status=handle.status,
                headers={key.lower(): value for key, value in handle.headers.items()},
                body=body[:max_body_bytes],
                url=handle.geturl(),
                truncated=len(body) > max_body_bytes,
            )
    except urllib.error.HTTPError as error:
        body = error.read(max_body_bytes + 1)
        return Response(
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=body[:max_body_bytes],
            url=spec.url,
            truncated=len(body) > max_body_bytes,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return Response(status=0, headers={}, body=b"", url=spec.url)


def capture_site_artifacts(local_site: LocalSiteBuild) -> dict[str, Response]:
    deadline = time.monotonic() + MAX_SITE_CAPTURE_SECONDS

    def capture(artifact: SiteArtifact) -> tuple[str, Response]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return artifact.response_name, Response(
                status=0,
                headers={},
                body=b"",
                url=artifact.url,
            )
        response = fetch(
            RequestSpec(
                artifact.response_name,
                artifact.url,
                user_agent=artifact.user_agent,
            ),
            timeout=min(MAX_SITE_REQUEST_SECONDS, remaining),
            max_body_bytes=len(artifact.content),
        )
        return artifact.response_name, response

    responses: dict[str, Response] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SITE_WORKERS) as executor:
        futures = [executor.submit(capture, artifact) for artifact in local_site.artifacts]
        for future in concurrent.futures.as_completed(futures):
            name, response = future.result()
            responses[name] = response
    return responses


def capture_live(
    local_build: LocalBottleBuild,
    local_site: LocalSiteBuild,
) -> dict[str, Response]:
    base_limits = {
        "site_secondary": 4096,
        "bottle_root": len(local_build.artifacts.get("index.html", b"")),
        "bottle_manifest": len(local_build.manifest_bytes),
        "bottle_api": 64 * 1024,
        "bottle_keyring": len(local_build.artifacts.get("keyring.json", b"")),
    }
    responses = {
        spec.name: fetch(spec, max_body_bytes=base_limits[spec.name])
        for spec in REQUEST_PLAN
    }
    for redirect in local_site.redirects:
        responses[redirect.response_name] = fetch(
            RequestSpec(
                redirect.response_name,
                redirect.url,
                method="HEAD",
                follow_redirects=False,
            ),
            max_body_bytes=4096,
        )
    responses.update(capture_site_artifacts(local_site))

    expected_total = sum(
        len(content)
        for path, content in local_build.artifacts.items()
        if path != "_headers"
    )
    if expected_total > MAX_MANIFEST_ARTIFACT_BYTES:
        raise ValueError("local Bottle artifact capture exceeds its aggregate byte budget")

    deadline = time.monotonic() + MAX_ARTIFACT_CAPTURE_SECONDS
    for path, expected_content in sorted(local_build.artifacts.items()):
        # Cloudflare consumes _headers as deployment configuration. Bind it to
        # the checkout and verify its resulting headers instead of requesting
        # a path that is intentionally not public.
        if path == "_headers":
            continue
        name = artifact_response_name(path)
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            responses[name] = Response(status=0, headers={}, body=b"", url=artifact_url(path))
            continue
        responses[name] = fetch(
            RequestSpec(name, artifact_url(path)),
            timeout=min(MAX_ARTIFACT_REQUEST_SECONDS, remaining_seconds),
            max_body_bytes=len(expected_content),
        )
    return responses


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
        body_base64 = value.get("bodyBase64", "")
        url = value.get("url")
        truncated = value.get("truncated", False)
        if (
            not isinstance(status, int)
            or not isinstance(headers, dict)
            or not all(isinstance(key, str) and isinstance(item, str) for key, item in headers.items())
            or not isinstance(body_base64, str)
            or not isinstance(url, str)
            or not isinstance(truncated, bool)
        ):
            raise ValueError(f"snapshot response {name} has an invalid shape")
        try:
            body = base64.b64decode(body_base64, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError(f"snapshot response {name} bodyBase64 is invalid") from error
        if len(body) > max(MAX_RESPONSE_BYTES, site_dist.MAX_SITE_FILE_BYTES):
            raise ValueError(f"snapshot response {name} exceeds the fixed body budget")
        responses[name] = Response(
            status=status,
            headers={key.lower(): item for key, item in headers.items()},
            body=body,
            url=url,
            truncated=truncated,
        )
    return expected_commit, responses


def response_or_missing(responses: Mapping[str, Response], name: str) -> Response:
    return responses.get(name, Response(status=0, headers={}, body=b"", url="<missing>"))


def json_body(response: Response) -> Any | None:
    try:
        return json.loads(
            response.body.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def response_media_type(response: Response) -> str:
    return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def artifact_media_types(path: str) -> frozenset[str]:
    return frozenset(ARTIFACT_MEDIA_TYPES.get(Path(path).suffix.lower(), set()))


def add_media_type_check(
    checks: list[Check],
    label: str,
    response: Response,
    allowed: frozenset[str] | set[str],
) -> None:
    observed = response_media_type(response)
    checks.append(
        Check(
            f"{label}-content-type",
            bool(allowed) and observed in allowed,
            f"expected={','.join(sorted(allowed)) or '<none>'} observed={observed or '<missing>'}",
        )
    )


def has_forbidden_analytics(body: bytes) -> bool:
    lowered = body.lower()
    return any(marker.lower() in lowered for marker in ANALYTICS_MARKERS)


def add_exact_url_check(
    checks: list[Check], label: str, response: Response, expected_url: str
) -> None:
    checks.append(Check(f"{label}-final-url", response.url == expected_url, response.url))


def byte_match_detail(expected: bytes, observed: bytes) -> str:
    return f"expected-sha256={sha256(expected)} observed-sha256={sha256(observed)}"


def add_common_response_checks(checks: list[Check], label: str, response: Response) -> None:
    checks.append(
        Check(
            f"{label}-bounded-body",
            not response.truncated,
            f"body-bytes={len(response.body)} truncated={response.truncated}",
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


def add_site_global_header_checks(
    checks: list[Check],
    label: str,
    response: Response,
    expected_headers: Mapping[str, str],
) -> None:
    for header, expected in expected_headers.items():
        if header == "cache-control":
            continue
        observed = response.headers.get(header, "")
        checks.append(
            Check(
                f"{label}-{header}",
                observed == expected,
                "exact"
                if observed == expected
                else f"expected={expected!r} observed={observed!r}",
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
    if not valid_canonical_timestamp(payload.get("updatedAt")) or not isinstance(payload.get("keys"), list):
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
        created_at = candidate.get("createdAt")
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
            or not valid_canonical_timestamp(created_at)
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


def exact_fields(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def valid_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def release_manifest_checks(
    manifest: Any,
    responses: Mapping[str, Response],
    expected_commit: str,
    bottle_root: Response,
    keyring_response: Response,
    local_build: LocalBottleBuild,
) -> list[Check]:
    checks: list[Check] = []
    top_fields = {"schema", "subjectSha256", "source", "build", "inputs", "bundleBudget", "artifacts"}
    top_exact = exact_fields(manifest, top_fields)
    checks.append(Check("bottle-manifest-exact-fields", top_exact, ",".join(sorted(top_fields))))

    source = manifest.get("source") if isinstance(manifest, dict) else None
    source_exact = exact_fields(source, {"repository", "commit", "treeState"})
    checks.extend(
        [
            Check("bottle-manifest-source-exact-fields", source_exact, "repository,commit,treeState"),
            Check(
                "bottle-manifest-source-repository",
                source_exact and source.get("repository") == CANONICAL_REPOSITORY,
                str(source.get("repository")) if isinstance(source, dict) else "<invalid>",
            ),
            Check(
                "bottle-manifest-source-commit",
                source_exact and source.get("commit") == expected_commit,
                str(source.get("commit")) if isinstance(source, dict) else "<invalid>",
            ),
            Check(
                "bottle-manifest-clean-tree",
                source_exact and source.get("treeState") == "clean",
                str(source.get("treeState")) if isinstance(source, dict) else "<invalid>",
            ),
        ]
    )

    build = manifest.get("build") if isinstance(manifest, dict) else None
    build_fields = {"appVersion", "nodeVersion", "packageManager", "command"}
    build_exact = exact_fields(build, build_fields)
    package = json.loads(bottle_file("package.json"))
    build_matches = (
        build_exact
        and build.get("appVersion") == package.get("version")
        and build.get("packageManager") == package.get("packageManager")
        and build.get("command") == "npm run build"
        and isinstance(build.get("nodeVersion"), str)
        and bool(NODE_VERSION_PATTERN.fullmatch(build["nodeVersion"]))
    )
    checks.extend(
        [
            Check("bottle-manifest-build-exact-fields", build_exact, ",".join(sorted(build_fields))),
            Check("bottle-manifest-build-contract", build_matches, "checked-out package metadata and npm run build"),
        ]
    )

    inputs = manifest.get("inputs") if isinstance(manifest, dict) else None
    local_inputs = expected_manifest_inputs()
    checks.append(
        Check(
            "bottle-manifest-inputs-match-checkout",
            inputs == local_inputs,
            "canonical package, keyring, headers, Worker closure, and Wrangler input digests",
        )
    )
    checks.append(
        Check(
            "bottle-manifest-matches-local-build",
            manifest == local_build.manifest,
            "live manifest must equal the locally rebuilt dist manifest",
        )
    )

    artifact_paths = manifest_artifact_paths(manifest)
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    required_artifacts = {"_headers", "index.html", "keyring.json"}
    expected_paths = sorted(local_build.artifacts)
    artifacts_contract = (
        bool(artifact_paths)
        and artifact_paths == expected_paths
        and required_artifacts.issubset(artifact_paths)
    )
    checks.append(
        Check(
            "bottle-manifest-artifact-contract",
            artifacts_contract,
            "artifact paths exactly match the locally rebuilt dist tree",
        )
    )

    artifact_contents: dict[str, bytes] = {}
    artifact_records: dict[str, Mapping[str, Any]] = {}
    if isinstance(artifacts, list):
        artifact_records = {
            record["path"]: record
            for record in artifacts
            if isinstance(record, dict) and isinstance(record.get("path"), str)
        }
    artifact_responses: list[Response] = []
    for path, expected_content in sorted(local_build.artifacts.items()):
        record = artifact_records.get(path)
        record_matches_local = (
            isinstance(record, dict)
            and set(record) == {"path", "bytes", "sha256"}
            and record.get("bytes") == len(expected_content)
            and record.get("sha256") == sha256(expected_content)
        )
        checks.append(
            Check(
                f"bottle-artifact-{path}-manifest-local-binding",
                record_matches_local,
                byte_match_detail(expected_content, expected_content)
                if record_matches_local
                else "manifest record differs from locally rebuilt dist artifact",
            )
        )
        if path == "_headers":
            checkout_content = bottle_file("public/_headers")
            artifact_contents[path] = expected_content
            matches = expected_content == checkout_content
            checks.append(
                Check(
                    "bottle-artifact-_headers-checkout-binding",
                    matches,
                    byte_match_detail(checkout_content, expected_content),
                )
            )
            continue

        response = response_or_missing(responses, artifact_response_name(path))
        artifact_responses.append(response)
        if path in {"index.html", "keyring.json"}:
            add_bottle_header_checks(checks, f"bottle-artifact-{path}", response)
        else:
            add_common_response_checks(checks, f"bottle-artifact-{path}", response)
        add_media_type_check(
            checks,
            f"bottle-artifact-{path}",
            response,
            artifact_media_types(path),
        )
        checks.extend(
            [
                Check(
                    f"bottle-artifact-{path}-status",
                    response.status == 200,
                    f"status={response.status}",
                ),
                Check(
                    f"bottle-artifact-{path}-final-url",
                    response.url == artifact_url(path),
                    response.url,
                ),
                Check(
                    f"bottle-artifact-{path}-local-byte-binding",
                    response.body == expected_content,
                    byte_match_detail(expected_content, response.body),
                ),
            ]
        )
        artifact_contents[path] = response.body

    observed_artifact_bytes = sum(len(response.body) for response in artifact_responses)
    expected_artifact_bytes = sum(
        len(content)
        for path, content in local_build.artifacts.items()
        if path != "_headers"
    )
    checks.append(
        Check(
            "bottle-artifact-aggregate-body-budget",
            observed_artifact_bytes <= expected_artifact_bytes
            and expected_artifact_bytes <= MAX_MANIFEST_ARTIFACT_BYTES,
            f"observed={observed_artifact_bytes} expected-cap={expected_artifact_bytes}",
        )
    )

    checks.extend(
        [
            Check(
                "bottle-root-matches-manifest-index",
                artifact_contents.get("index.html") == bottle_root.body,
                byte_match_detail(artifact_contents.get("index.html", b""), bottle_root.body),
            ),
            Check(
                "bottle-keyring-matches-manifest-artifact",
                artifact_contents.get("keyring.json") == keyring_response.body,
                byte_match_detail(artifact_contents.get("keyring.json", b""), keyring_response.body),
            ),
        ]
    )

    budget = manifest.get("bundleBudget") if isinstance(manifest, dict) else None
    budget_fields = {"schema", "runtimeBytes", "runtimeGzipBytes", "maxRuntimeBytes", "maxRuntimeGzipBytes"}
    budget_exact = exact_fields(budget, budget_fields)
    runtime_contents = [
        content
        for path, content in artifact_contents.items()
        if Path(path).suffix in RUNTIME_EXTENSIONS
    ]
    runtime_bytes = sum(len(content) for content in runtime_contents)
    runtime_gzip_bytes = sum(len(gzip.compress(content, compresslevel=9, mtime=0)) for content in runtime_contents)
    budget_matches = (
        budget_exact
        and budget.get("schema") == "nsm.daylight-bottle.bundle-budget.v1"
        and all(valid_nonnegative_integer(budget.get(field)) for field in budget_fields - {"schema"})
        and budget.get("runtimeBytes") == runtime_bytes
        and budget.get("runtimeGzipBytes") == runtime_gzip_bytes
        and budget.get("maxRuntimeBytes") == MAX_RUNTIME_BYTES
        and budget.get("maxRuntimeGzipBytes") == MAX_RUNTIME_GZIP_BYTES
        and runtime_bytes <= MAX_RUNTIME_BYTES
        and runtime_gzip_bytes <= MAX_RUNTIME_GZIP_BYTES
    )
    checks.append(
        Check(
            "bottle-manifest-bundle-budget",
            budget_matches,
            f"runtime={runtime_bytes}/{MAX_RUNTIME_BYTES} gzip={runtime_gzip_bytes}/{MAX_RUNTIME_GZIP_BYTES}",
        )
    )

    subject = None
    if isinstance(manifest, dict):
        subject = {
            "source": manifest.get("source"),
            "build": manifest.get("build"),
            "inputs": manifest.get("inputs"),
            "bundleBudget": manifest.get("bundleBudget"),
            "artifacts": manifest.get("artifacts"),
        }
    expected_subject = f"sha256:{sha256(canonical_json_bytes(subject))}" if subject is not None else "<invalid>"
    observed_subject = manifest.get("subjectSha256") if isinstance(manifest, dict) else None
    checks.append(
        Check(
            "bottle-manifest-subject-digest",
            top_exact and observed_subject == expected_subject,
            f"expected={expected_subject} observed={observed_subject}",
        )
    )
    return checks


def evaluate(
    responses: Mapping[str, Response],
    expected_commit: str,
    local_build: LocalBottleBuild | None = None,
    local_site: LocalSiteBuild | None = None,
) -> list[Check]:
    checks: list[Check] = []
    if local_build is None:
        local_build = load_local_bottle_build()
    if local_site is None:
        local_site = load_local_site_build()
    global_site_headers = site_global_headers(local_site.configs["_headers"])
    checks.append(
        Check(
            "expected-commit-format",
            bool(COMMIT_PATTERN.fullmatch(expected_commit)),
            expected_commit,
        )
    )

    config_records = {
        record["path"]: record for record in local_site.inventory["configFiles"]
    }
    for path, content in local_site.configs.items():
        record = config_records.get(path)
        expected_record = site_dist.file_record(path, content)
        checks.append(
            Check(
                f"site-config-{path}-inventory-binding",
                record == expected_record,
                f"sha256={sha256(content)}",
            )
        )

    site_responses: list[Response] = []
    for artifact in local_site.artifacts:
        observed = response_or_missing(responses, artifact.response_name)
        site_responses.append(observed)
        label = site_check_label(artifact.path)
        status_name = (
            "site-https-status" if artifact.path == "index.html" else f"{label}-status"
        )
        url_name = (
            "site-https-final-url"
            if artifact.path == "index.html"
            else "site-browser-wucios-https"
            if artifact.path == "wucios.html"
            else f"{label}-final-url"
        )
        analytics_name = (
            "site-browser-no-analytics-injection"
            if artifact.path == "wucios.html"
            else f"{label}-no-analytics-injection"
        )
        checks.extend(
            [
                Check(
                    status_name,
                    observed.status == artifact.status,
                    f"expected={artifact.status} observed={observed.status}",
                ),
                Check(url_name, observed.url == artifact.url, observed.url),
                Check(
                    f"{label}-exact-bytes",
                    observed.body == artifact.content,
                    byte_match_detail(artifact.content, observed.body),
                ),
            ]
        )
        if artifact.media_type in {"text/html", "application/javascript", "text/javascript"}:
            checks.append(
                Check(
                    analytics_name,
                    not has_forbidden_analytics(observed.body),
                    "analytics markers absent",
                )
            )
        add_media_type_check(
            checks,
            label,
            observed,
            {artifact.media_type},
        )
        add_common_response_checks(checks, label, observed)
        add_site_global_header_checks(
            checks,
            label,
            observed,
            global_site_headers,
        )

    observed_site_bytes = sum(len(response.body) for response in site_responses)
    expected_site_bytes = sum(len(artifact.content) for artifact in local_site.artifacts)
    checks.extend(
        [
            Check(
                "site-artifact-count-budget",
                len(local_site.artifacts) + len(local_site.configs)
                <= site_dist.MAX_SITE_FILES,
                f"artifacts={len(local_site.artifacts)} configs={len(local_site.configs)}",
            ),
            Check(
                "site-artifact-aggregate-body-budget",
                observed_site_bytes <= expected_site_bytes
                and expected_site_bytes <= site_dist.MAX_SITE_TOTAL_BYTES,
                f"observed={observed_site_bytes} expected-cap={expected_site_bytes}",
            ),
        ]
    )

    site_root = response_or_missing(responses, "site_https_root")
    checks.extend(
        [
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
        ]
    )

    for redirect in local_site.redirects:
        observed = response_or_missing(responses, redirect.response_name)
        label = redirect.response_name.replace(":", "-").replace("/", "-")
        checks.extend(
            [
                Check(
                    f"{label}-status-location",
                    observed.status == redirect.status
                    and observed.headers.get("location") == redirect.location,
                    (
                        f"expected={redirect.status} location={redirect.location!r} "
                        f"observed={observed.status} "
                        f"location={observed.headers.get('location', '<missing>')!r}"
                    ),
                ),
                Check(
                    f"{label}-final-url",
                    observed.url == redirect.url,
                    observed.url,
                ),
            ]
        )
        add_common_response_checks(checks, label, observed)
        add_site_global_header_checks(
            checks,
            label,
            observed,
            global_site_headers,
        )

    secondary = response_or_missing(responses, "site_secondary")
    secondary_location = secondary.headers.get("location", "")
    secondary_retired = secondary.status in {404, 410}
    secondary_safe_redirect = (
        secondary.status in {301, 302, 307, 308}
        and secondary_location == SITE_APEX
    )
    checks.append(
        Check(
            "site-secondary-retired-or-canonical-https",
            secondary_retired or secondary_safe_redirect,
            f"status={secondary.status} location={secondary_location or '<missing>'}",
        )
    )
    add_common_response_checks(checks, "site-secondary", secondary)

    bottle_root = response_or_missing(responses, "bottle_root")
    checks.extend(
        [
            Check("bottle-root-status", bottle_root.status == 200, f"status={bottle_root.status}"),
            Check("bottle-root-https", bottle_root.url == f"{BOTTLE_ORIGIN}/", bottle_root.url),
            Check(
                "bottle-root-no-analytics-injection",
                not has_forbidden_analytics(bottle_root.body),
                "analytics markers absent",
            ),
        ]
    )
    add_media_type_check(checks, "bottle-root", bottle_root, {"text/html"})
    add_bottle_header_checks(checks, "bottle-root", bottle_root)

    manifest_response = response_or_missing(responses, "bottle_manifest")
    add_bottle_header_checks(checks, "bottle-manifest", manifest_response)
    add_media_type_check(
        checks,
        "bottle-manifest",
        manifest_response,
        {"application/json"},
    )
    add_exact_url_check(
        checks,
        "bottle-manifest",
        manifest_response,
        f"{BOTTLE_ORIGIN}/release-manifest.json",
    )
    manifest = json_body(manifest_response)
    checks.extend(
        [
            Check("bottle-manifest-status", manifest_response.status == 200, f"status={manifest_response.status}"),
            Check(
                "bottle-manifest-exact-local-bytes",
                manifest_response.body == local_build.manifest_bytes,
                byte_match_detail(local_build.manifest_bytes, manifest_response.body),
            ),
            Check(
                "bottle-manifest-json",
                isinstance(manifest, dict),
                "valid object" if isinstance(manifest, dict) else "invalid JSON",
            ),
        ]
    )
    manifest_inputs = manifest.get("inputs") if isinstance(manifest, dict) else None
    checks.append(
        Check(
            "bottle-manifest-schema",
            isinstance(manifest, dict) and manifest.get("schema") == "nsm.daylight-bottle.release-manifest.v1",
            str(manifest.get("schema")) if isinstance(manifest, dict) else "<invalid>",
        )
    )

    api_response = response_or_missing(responses, "bottle_api")
    add_bottle_header_checks(checks, "bottle-api", api_response)
    add_media_type_check(checks, "bottle-api", api_response, {"application/json"})
    add_exact_url_check(
        checks,
        "bottle-api",
        api_response,
        f"{BOTTLE_ORIGIN}/api/bottles?recipientFingerprint={ZERO_FINGERPRINT}",
    )
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
    add_media_type_check(
        checks,
        "bottle-keyring",
        keyring_response,
        {"application/json"},
    )
    add_exact_url_check(
        checks,
        "bottle-keyring",
        keyring_response,
        f"{BOTTLE_ORIGIN}/keyring.json",
    )
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
    checks.extend(
        release_manifest_checks(
            manifest,
            responses,
            expected_commit,
            bottle_root,
            keyring_response,
            local_build,
        )
    )

    status_response = response_or_missing(responses, "site_bottle_status")
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
    mode.add_argument(
        "--live",
        action="store_true",
        help="perform the bounded canonical-origin, read-only network request plan",
    )
    parser.add_argument("--expected-commit", help="40-character commit expected in the Bottle manifest")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)

    try:
        local_build = load_local_bottle_build()
        local_site = load_local_site_build()
        if args.snapshot:
            snapshot_commit, responses = load_snapshot(args.snapshot)
            expected_commit = args.expected_commit or snapshot_commit
        else:
            if not args.expected_commit:
                parser.error("--live requires --expected-commit")
            expected_commit = args.expected_commit
            responses = capture_live(local_build, local_site)
        checks = evaluate(responses, expected_commit, local_build, local_site)
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
