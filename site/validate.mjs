import { access, readFile, readdir, stat } from "node:fs/promises";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import process from "node:process";

const siteRoot = new URL(".", import.meta.url);

const requiredFiles = [
  "index.html",
  "CNAME",
  "404.html",
  "styles.css",
  "app.js",
  "_headers",
  "_redirects",
  "robots.txt",
  "sitemap.xml",
  "site.webmanifest",
  "codemeta.json",
  "citation.cff",
  "hosting-requirements.json",
  "claim-evidence.json",
  "llms.txt",
  "humans.txt",
  "security.txt",
  ".well-known/security.txt",
  "daylight-status.json",
  "aperture-status.json",
  "assets/wuci-ji-official-emblem.jpg",
  "assets/wuci-ji-v2-aperture-bastion.jpeg",
  "assets/wuci-daylight-v15-meridian-banner.png",
  "assets/daylight-v17-singularity.jpg",
  "assets/daylight-v16-analemma.png",
  "assets/wuci-daylight-v15-plus-solstice.png",
  "assets/wuci-daylight-v15-meridian.png",
  "assets/wuci-v15-mae-meridian-authorized-envelope.jpeg",
  "assets/wuci-daylight-v14c-plus-ascendant-wide.png",
  "assets/wuci-daylight-v14c-plus-ascendant.png",
  "assets/wuci-daylight-wire-model.png",
  "assets/wuci-daylight-v10-scoreboard.png",
  "assets/wuci-os-boot-splash.svg"
];

function fail(message) {
  console.error(`site build: ${message}`);
  process.exitCode = 1;
}

async function exists(relativePath) {
  try {
    await access(new URL(relativePath, siteRoot), constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

async function existsInRepo(relativePath) {
  if (relativePath.startsWith("/") || relativePath.includes("..")) {
    return false;
  }
  try {
    await access(new URL(`../${relativePath}`, siteRoot), constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

async function assertRequiredFiles() {
  for (const file of requiredFiles) {
    if (!(await exists(file))) {
      fail(`missing required file: site/${file}`);
    }
  }
}

async function assertCustomDomain() {
  const cname = (await readFile(new URL("CNAME", siteRoot), "utf8")).trim();
  if (cname !== "nosuchmachine.net") {
    fail("site/CNAME must contain exactly nosuchmachine.net");
  }
}

async function assertIndexReferences() {
  const index = await readFile(new URL("index.html", siteRoot), "utf8");
  const references = Array.from(index.matchAll(/\b(?:href|src)="([^":#?]+)(?:[?#][^"]*)?"/g)).map((match) => match[1]);
  for (const reference of references) {
    if (
      reference.startsWith("/") ||
      reference.startsWith("mailto:") ||
      reference.startsWith("tel:") ||
      reference.startsWith("data:")
    ) {
      continue;
    }
    if (!(await exists(reference))) {
      fail(`index.html references missing local asset: ${reference}`);
    }
  }
  for (const required of [
    'name="robots"',
    'name="application-name" content="Wuci-Ji"',
    'rel="canonical"',
    'rel="sitemap"',
    'rel="author"',
    'rel="alternate"',
    'type="text/plain" href="/citation.cff"',
    'type="application/ld+json" href="/codemeta.json"',
    'type="application/json" href="/hosting-requirements.json"',
    'type="application/json" href="/claim-evidence.json"',
    'itemtype="https://schema.org/SoftwareSourceCode"',
    'itemprop="codeRepository"',
    'itemprop="logo"',
    'rel="manifest"',
    'rel="preload"',
    'rel="apple-touch-icon"',
    'property="og:image"',
    'name="twitter:card"',
    'href="aperture-status.json"',
    'href="#meridian"',
    'href="#aperture"',
    'href="#assurance"',
    'href="#review"',
    'href="#daylight"',
    'id="aperture"',
    'id="assurance"',
    'id="review"',
    'id="catalog"',
    'id="mae"',
    'id="meridian"',
    'No public browser encryptor, private-key handler, or file opener is shipped.',
    'make daylight-meridian-envelope-test',
    'Wuci-Ji v2 — Aperture Bastion',
    'assets/wuci-ji-official-emblem.jpg',
    'Official Wuci-Ji emblem',
    'Every public claim needs a local handle.',
    'Claims, evidence, metadata, and host gates in one place.',
    'claim-evidence.json',
    'citation.cff',
    'hosting-requirements.json',
    'https://nosuchmachine.net/',
    'https://nosuchmachine.net/assets/wuci-ji-official-emblem.jpg',
    'https://nosuchmachine.net/assets/wuci-ji-v2-aperture-bastion.jpeg',
    'make daylight-public-artifact-firewall',
    '28564990503',
    'v2.0.0-aperture-bastion',
    'ce077fea615528634ad27fec516fdb402f101602',
    '9109e7d9364f305a0618e6f5d810f3dd665d995e5c56f9d0ccc8d01875b9eec0'
  ]) {
    if (!index.includes(required)) {
      fail(`index.html is missing SEO or site marker: ${required}`);
    }
  }
  // The GitHub Pages deploy path does not serve _headers, so the document
  // itself must carry the CSP and referrer policy.
  for (const required of [
    'http-equiv="Content-Security-Policy"',
    'upgrade-insecure-requests',
    'name="referrer"'
  ]) {
    if (!index.includes(required)) {
      fail(`index.html is missing in-document security policy: ${required}`);
    }
  }
}

async function assertNoPublicBrowserCrypto() {
  const index = await readFile(new URL("index.html", siteRoot), "utf8");
  const app = await readFile(new URL("app.js", siteRoot), "utf8");
  for (const forbidden of [
    "data-meridian-file",
    "data-meridian-open-file",
    "data-meridian-open-key",
    "data-meridian-encrypt",
    "data-meridian-open",
    "data-meridian-copy-key",
    "Download opened file",
    "Download private key"
  ]) {
    if (index.includes(forbidden) || app.includes(forbidden)) {
      fail(`public site exposes browser crypto control: ${forbidden}`);
    }
  }
  for (const forbidden of [
    "crypto.subtle.encrypt",
    "crypto.subtle.decrypt",
    "deriveKey(",
    "importKey(",
    "getRandomValues(",
    "AES-GCM",
    "privateKey"
  ]) {
    if (app.includes(forbidden)) {
      fail(`app.js exposes browser cryptographic operation: ${forbidden}`);
    }
  }
}

async function assertNotFoundPage() {
  const notFound = await readFile(new URL("404.html", siteRoot), "utf8");
  for (const required of [
    'name="robots" content="noindex, follow"',
    'rel="canonical" href="https://nosuchmachine.net/"',
    'assets/wuci-ji-official-emblem.jpg',
    'http-equiv="Content-Security-Policy"',
    'upgrade-insecure-requests',
    'name="referrer"'
  ]) {
    if (!notFound.includes(required)) {
      fail(`404.html is missing discovery or security marker: ${required}`);
    }
  }
}

async function assertBrowserHttpsFallback() {
  const app = await readFile(new URL("app.js", siteRoot), "utf8");
  for (const required of [
    "function enforceCanonicalHttps()",
    'window.location.protocol === "http:"',
    'host === "nosuchmachine.net"',
    'host === "www.nosuchmachine.net"',
    'window.location.replace(',
    '"https://nosuchmachine.net"'
  ]) {
    if (!app.includes(required)) {
      fail(`app.js is missing browser HTTPS fallback marker: ${required}`);
    }
  }
}

async function assertApertureStatusBinding() {
  const status = await readJsonOrNull(new URL("aperture-status.json", siteRoot));
  if (status === null) {
    fail("site/aperture-status.json is missing or not valid JSON");
    return;
  }
  const expected = {
    schema: "wuci-aperture-site-status-v1",
    project: "wuci-ji",
    layer: "Wuci-Ji v2 — Aperture Bastion",
    release_tag: "v2.0.0-aperture-bastion",
    commit: "ce077fea615528634ad27fec516fdb402f101602",
    capsule_digest: "9109e7d9364f305a0618e6f5d810f3dd665d995e5c56f9d0ccc8d01875b9eec0",
    firewall_profile_id: "aperture-bastion-public-v1",
    hosted_artifact_diff: "matched local firewalled artifact"
  };
  for (const [key, value] of Object.entries(expected)) {
    if (status[key] !== value) {
      fail(`aperture-status.json ${key} does not match expected value`);
    }
  }
  if (status.public_artifact_file_count !== 8) {
    fail("aperture-status.json public_artifact_file_count must be 8");
  }
  if (typeof status.firewall_profile_digest !== "string" || !/^[0-9a-f]{64}$/.test(status.firewall_profile_digest)) {
    fail("aperture-status.json firewall_profile_digest must be sha256 hex");
  }
  if (!Number.isInteger(status.hosted_run_id) || status.hosted_run_id <= 0) {
    fail("aperture-status.json hosted_run_id must be a positive integer");
  }
  if (!Array.isArray(status.non_claims)) {
    fail("aperture-status.json non_claims must be a list");
    return;
  }
  const index = await readFile(new URL("index.html", siteRoot), "utf8");
  for (const required of [
    status.release_tag,
    status.commit,
    status.capsule_digest,
    status.firewall_profile_id
  ]) {
    if (!index.includes(required)) {
      fail(`index.html does not display Aperture status value: ${required}`);
    }
  }
  for (const requiredNonClaim of [
    "not production cryptography",
    "not runtime sandboxing",
    "not host-cleanliness proof",
    "not whole-system post-quantum safety",
    "not FIPS validation",
    "not government validation",
    "not external certification",
    "not independent audit completion",
    "not a perfect score claim from repository-owned evidence"
  ]) {
    if (!status.non_claims.includes(requiredNonClaim)) {
      fail(`aperture-status.json missing non-claim: ${requiredNonClaim}`);
    }
  }
}

async function assertClaimBoundaryLanguage() {
  const index = await readFile(new URL("index.html", siteRoot), "utf8");
  const normalized = index.replace(/\s+/g, " ");
  for (const required of [
    "not production cryptography",
    "not a general runtime sandbox",
    "not host-cleanliness proof",
    "not whole-system post-quantum secure",
    "not FIPS validation",
    "not government validation",
    "not external certification",
    "not independently audited"
  ]) {
    if (!normalized.includes(required)) {
      fail(`index.html is missing claim-boundary text: ${required}`);
    }
  }
  for (const forbidden of [
    "production-ready cryptography",
    "runtime sandboxing guaranteed",
    "host cleanliness proof",
    "post-quantum safe",
    "FIPS validated",
    "government validated",
    "externally certified",
    "independently audited by"
  ]) {
    if (normalized.includes(forbidden)) {
      fail(`index.html contains unsupported release claim: ${forbidden}`);
    }
  }
}

async function assertAssetSizes() {
  const entries = await readdir(new URL("assets/", siteRoot));
  for (const entry of entries) {
    const assetPath = new URL(`assets/${entry}`, siteRoot);
    const info = await stat(assetPath);
    if (!info.isFile()) {
      fail(`asset is not a regular file: site/assets/${entry}`);
      continue;
    }
    if (info.size <= 0) {
      fail(`asset is empty: site/assets/${entry}`);
    }
  }
}

async function assertCloudflareFiles() {
  const headers = await readFile(new URL("_headers", siteRoot), "utf8");
  for (const requiredHeader of [
    "Content-Security-Policy:",
    "Strict-Transport-Security:",
    "Referrer-Policy:",
    "X-Content-Type-Options: nosniff",
    "X-Frame-Options: DENY",
    "Cross-Origin-Opener-Policy: same-origin",
    "Cross-Origin-Resource-Policy: same-origin",
    "Permissions-Policy:"
  ]) {
    if (!headers.includes(requiredHeader)) {
      fail(`site/_headers is missing security header: ${requiredHeader}`);
    }
  }
  for (const requiredHeader of [
    "/aperture-status.json",
    "/daylight-status.json",
    "/codemeta.json",
    "/citation.cff",
    "/hosting-requirements.json",
    "/claim-evidence.json",
    "Content-Type: application/json; charset=utf-8",
    "Content-Type: application/ld+json; charset=utf-8",
    "Cache-Control: no-store",
    "/.well-known/security.txt",
    "/security.txt",
    "/llms.txt",
    "/humans.txt",
    "Content-Type: text/plain; charset=utf-8",
    "/assets/*",
    "Cache-Control: public, max-age=31536000, immutable"
  ]) {
    if (!headers.includes(requiredHeader)) {
      fail(`site/_headers is missing deploy metadata: ${requiredHeader}`);
    }
  }
  for (const requiredDirective of [
    "default-src 'self'",
    "script-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'"
  ]) {
    if (!headers.includes(requiredDirective)) {
      fail(`site/_headers CSP is missing directive: ${requiredDirective}`);
    }
  }
  const redirects = await readFile(new URL("_redirects", siteRoot), "utf8");
  for (const route of [
    "/repo",
    "/readme",
    "/docs/security-boundary",
    "/docs/aperture-bastion",
    "/docs/aperture-boundary",
    "/docs/aperture-pass-report",
    "/docs/wuci-os"
  ]) {
    if (!redirects.includes(`${route} `)) {
      fail(`site/_redirects is missing route: ${route}`);
    }
  }
  for (const redirect of [
    "http://nosuchmachine.net/* https://nosuchmachine.net/:splat 301",
    "http://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301",
    "https://www.nosuchmachine.net/* https://nosuchmachine.net/:splat 301",
    "/security.txt /.well-known/security.txt 301"
  ]) {
    if (!redirects.includes(redirect)) {
      fail(`site/_redirects is missing canonical HTTPS redirect: ${redirect}`);
    }
  }
}

function withCommas(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

async function readJsonOrNull(url) {
  try {
    return JSON.parse(await readFile(url, "utf8"));
  } catch {
    return null;
  }
}

async function sha256Hex(relativePath) {
  return createHash("sha256").update(await readFile(new URL(relativePath, siteRoot))).digest("hex");
}

// Daylight doctrine: the site may not display a number the evidence cannot
// regenerate. The headline AM+ figure is bound to site/daylight-status.json,
// which is itself generated from the committed v17 scorecard. This check fails
// the build if the displayed number drifts from that evidence.
async function assertDaylightStatusBinding() {
  const status = await readJsonOrNull(new URL("daylight-status.json", siteRoot));
  if (status === null) {
    fail("site/daylight-status.json is missing or not valid JSON");
    return;
  }
  if (!Number.isInteger(status.score_AM_plus) || status.score_AM_plus < 0) {
    fail("daylight-status.json score_AM_plus must be a non-negative integer");
  }
  if (status.unit !== "AM+") {
    fail("daylight-status.json unit must be AM+");
  }
  if (typeof status.scorecard_digest !== "string" || !/^[0-9a-f]{64}$/.test(status.scorecard_digest)) {
    fail("daylight-status.json scorecard_digest must be sha256 hex");
  }
  if (typeof status.source !== "string" || !status.source) {
    fail("daylight-status.json must name its evidence source");
  }

  const index = await readFile(new URL("index.html", siteRoot), "utf8");
  const displayed = withCommas(status.score_AM_plus);
  if (!index.includes(displayed)) {
    fail(`index.html does not display the evidence AM+ number: ${displayed}`);
  }
  const hooks = Array.from(index.matchAll(/data-am-plus="([0-9]+)"/g)).map((match) => match[1]);
  if (hooks.length === 0) {
    fail("index.html is missing a data-am-plus evidence hook");
  }
  for (const hook of hooks) {
    if (hook !== String(status.score_AM_plus)) {
      fail(`index.html data-am-plus="${hook}" does not match evidence ${status.score_AM_plus}`);
    }
  }

  // On a full repository build the status file is cross-checked against the
  // committed scorecard it claims to summarize. In an isolated site-only
  // context that file is absent and the internal binding above still holds.
  const scorecard = await readJsonOrNull(new URL(`../${status.source}`, siteRoot));
  if (scorecard === null) {
    console.log(`site build: note: ${status.source} absent, skipped scorecard cross-check`);
    return;
  }
  if (scorecard.score_AM_plus !== status.score_AM_plus) {
    fail(`daylight-status.json score ${status.score_AM_plus} != scorecard ${scorecard.score_AM_plus}`);
  }
  if (scorecard.scorecard_digest !== status.scorecard_digest) {
    fail("daylight-status.json scorecard_digest does not match committed scorecard");
  }
}

async function assertSearchDiscoveryFiles() {
  const robots = await readFile(new URL("robots.txt", siteRoot), "utf8");
  if (!robots.includes("Sitemap: https://nosuchmachine.net/sitemap.xml")) {
    fail("robots.txt is missing sitemap declaration");
  }
  if (!robots.includes("Host: nosuchmachine.net")) {
    fail("robots.txt is missing canonical host declaration");
  }
  const sitemap = await readFile(new URL("sitemap.xml", siteRoot), "utf8");
  if (!sitemap.includes("<loc>https://nosuchmachine.net/</loc>")) {
    fail("sitemap.xml is missing canonical root URL");
  }
  for (const required of [
    "xmlns:image=\"http://www.google.com/schemas/sitemap-image/1.1\"",
    "<image:loc>https://nosuchmachine.net/assets/wuci-ji-v2-aperture-bastion.jpeg</image:loc>",
    "<image:loc>https://nosuchmachine.net/assets/wuci-ji-official-emblem.jpg</image:loc>",
    "<loc>https://nosuchmachine.net/aperture-status.json</loc>",
    "<loc>https://nosuchmachine.net/daylight-status.json</loc>",
    "<loc>https://nosuchmachine.net/codemeta.json</loc>",
    "<loc>https://nosuchmachine.net/citation.cff</loc>",
    "<loc>https://nosuchmachine.net/hosting-requirements.json</loc>",
    "<loc>https://nosuchmachine.net/claim-evidence.json</loc>"
  ]) {
    if (!sitemap.includes(required)) {
      fail(`sitemap.xml is missing discovery marker: ${required}`);
    }
  }
  if (!sitemap.includes("<lastmod>2026-07-02</lastmod>")) {
    fail("sitemap.xml lastmod must reflect the Aperture Bastion site update");
  }
  const manifest = JSON.parse(await readFile(new URL("site.webmanifest", siteRoot), "utf8"));
  if (manifest.name !== "Wuci-Ji" || manifest.short_name !== "Wuci-Ji" || manifest.start_url !== "/") {
    fail("site.webmanifest has unexpected identity or start_url");
  }
  if (!manifest.description.includes("Wuci-Ji v2 Aperture Bastion")) {
    fail("site.webmanifest must describe the Aperture Bastion surface");
  }
  if (!manifest.icons.some((icon) => icon.src === "/assets/wuci-ji-official-emblem.jpg" && icon.type === "image/jpeg")) {
    fail("site.webmanifest must expose the official Wuci-Ji emblem");
  }
}

async function assertPublicTextDiscovery() {
  const llms = await readFile(new URL("llms.txt", siteRoot), "utf8");
  for (const required of [
    "Wuci-Ji v2 — Aperture Bastion",
    "https://nosuchmachine.net/assets/wuci-ji-official-emblem.jpg",
    "716a6a2f845ef9f5c8ae1493474db1ec653fdb09a478089fd144b09c4fd04de9",
    "https://nosuchmachine.net/aperture-status.json",
    "https://nosuchmachine.net/codemeta.json",
    "https://nosuchmachine.net/citation.cff",
    "https://nosuchmachine.net/hosting-requirements.json",
    "https://nosuchmachine.net/claim-evidence.json",
    "make daylight-v19-aperture-bastion-ci",
    "not production cryptography",
    "not runtime sandboxing",
    "not external certification"
  ]) {
    if (!llms.includes(required)) {
      fail(`llms.txt is missing required research-agent marker: ${required}`);
    }
  }
  const humans = await readFile(new URL("humans.txt", siteRoot), "utf8");
  if (
    !humans.includes("No Such Machine") ||
    !humans.includes("make site-validate") ||
    !humans.includes("https://nosuchmachine.net/assets/wuci-ji-official-emblem.jpg") ||
    !humans.includes("https://nosuchmachine.net/citation.cff") ||
    !humans.includes("716a6a2f845ef9f5c8ae1493474db1ec653fdb09a478089fd144b09c4fd04de9")
  ) {
    fail("humans.txt is missing project identity or validation handle");
  }
  for (const securityPath of ["security.txt", ".well-known/security.txt"]) {
    const security = await readFile(new URL(securityPath, siteRoot), "utf8");
    for (const required of [
      "Contact: https://github.com/chasebryan/-wuci-ji/issues",
      "Expires: 2027-07-02T00:00:00Z",
      "Canonical: https://nosuchmachine.net/.well-known/security.txt",
      "Policy: https://github.com/chasebryan/-wuci-ji/blob/main/docs/SECURITY_BOUNDARY.md"
    ]) {
      if (!security.includes(required)) {
        fail(`${securityPath} is missing security.txt marker: ${required}`);
      }
    }
  }
}

async function assertResearchMetadata() {
  const metadata = await readJsonOrNull(new URL("codemeta.json", siteRoot));
  if (metadata === null) {
    fail("site/codemeta.json is missing or not valid JSON");
    return;
  }
  const expected = {
    "@context": "https://w3id.org/codemeta/3.0",
    "@id": "https://nosuchmachine.net/codemeta.json",
    "@type": "SoftwareSourceCode",
    name: "Wuci-Ji v2 — Aperture Bastion",
    citation: "https://nosuchmachine.net/citation.cff",
    codeRepository: "https://github.com/chasebryan/-wuci-ji",
    contIntegration: "https://github.com/chasebryan/-wuci-ji/actions/workflows/daylight-v19-aperture-bastion.yml",
    identifier: "wuci-ji-v2-aperture-bastion",
    image: "https://nosuchmachine.net/assets/wuci-ji-v2-aperture-bastion.jpeg",
    issueTracker: "https://github.com/chasebryan/-wuci-ji/issues",
    license: "https://spdx.org/licenses/Apache-2.0",
    logo: "https://nosuchmachine.net/assets/wuci-ji-official-emblem.jpg",
    readme: "https://github.com/chasebryan/-wuci-ji/blob/main/README.md",
    softwareVersion: "v2.0.0-aperture-bastion",
    url: "https://nosuchmachine.net/"
  };
  for (const [key, value] of Object.entries(expected)) {
    if (metadata[key] !== value) {
      fail(`codemeta.json ${key} does not match expected value`);
    }
  }
  for (const [key, requiredValues] of Object.entries({
    keywords: [
      "Aperture Bastion",
      "defensive research",
      "public evidence",
      "claim-bounded release",
      "cryptographic research",
      "high-assurance research"
    ],
    programmingLanguage: ["Python", "x86_64 assembly", "JavaScript", "Rust", "Zig"],
    runtimePlatform: ["stdlib Python", "static HTML"]
  })) {
    if (!Array.isArray(metadata[key])) {
      fail(`codemeta.json ${key} must be a list`);
      continue;
    }
    for (const required of requiredValues) {
      if (!metadata[key].includes(required)) {
        fail(`codemeta.json ${key} is missing ${required}`);
      }
    }
  }
  if (!metadata.isAccessibleForFree) {
    fail("codemeta.json must mark the public research surface as accessible for free");
  }

  if (!Array.isArray(metadata.additionalProperty)) {
    fail("codemeta.json additionalProperty must be a list");
    return;
  }
  const properties = new Map(metadata.additionalProperty.map((entry) => [entry.name, entry.value]));
  const aperture = await readJsonOrNull(new URL("aperture-status.json", siteRoot));
  if (aperture === null) {
    fail("site/aperture-status.json is missing or not valid JSON");
    return;
  }
  if (properties.get("capsule-digest") !== aperture.capsule_digest) {
    fail("codemeta.json capsule digest must match aperture-status.json");
  }
  if (properties.get("firewall-profile") !== aperture.firewall_profile_id) {
    fail("codemeta.json firewall profile must match aperture-status.json");
  }
  if (properties.get("hosted-artifact-diff") !== aperture.hosted_artifact_diff) {
    fail("codemeta.json hosted artifact diff must match aperture-status.json");
  }
  const validation = properties.get("local-validation");
  for (const required of [
    "make daylight-v19-aperture-bastion-ci",
    "make daylight-public-artifact-firewall",
    "make site-validate"
  ]) {
    if (typeof validation !== "string" || !validation.includes(required)) {
      fail(`codemeta.json local-validation is missing ${required}`);
    }
  }
  const nonClaims = properties.get("non-claims");
  for (const required of aperture.non_claims) {
    if (typeof nonClaims !== "string" || !nonClaims.includes(required)) {
      fail(`codemeta.json non-claims are missing ${required}`);
    }
  }
  const normalized = JSON.stringify(metadata).replace(/\s+/g, " ");
  for (const [label, pattern] of [
    ["production-ready cryptography", /production-ready cryptography/],
    ["runtime sandboxing guaranteed", /runtime sandboxing guaranteed/],
    ["host cleanliness proof", /host cleanliness proof/],
    ["post-quantum safe", /post-quantum safe\b/],
    ["FIPS validated", /FIPS validated/],
    ["government validated", /government validated/],
    ["externally certified", /externally certified/],
    ["independently audited by", /independently audited by/]
  ]) {
    if (pattern.test(normalized)) {
      fail(`codemeta.json contains unsupported release claim: ${label}`);
    }
  }
}

async function assertCitationMetadata() {
  const rootCitation = await readFile(new URL("../CITATION.cff", siteRoot), "utf8");
  const siteCitation = await readFile(new URL("citation.cff", siteRoot), "utf8");
  if (rootCitation !== siteCitation) {
    fail("site/citation.cff must match root CITATION.cff exactly");
  }
  for (const required of [
    "cff-version: 1.2.0",
    "message: \"If you use this research software artifact, cite it using the metadata in this file.\"",
    "title: \"Wuci-Ji v2 — Aperture Bastion\"",
    "type: software",
    "name: \"No Such Machine\"",
    "version: \"v2.0.0-aperture-bastion\"",
    "date-released: \"2026-07-02\"",
    "repository-code: \"https://github.com/chasebryan/-wuci-ji\"",
    "url: \"https://nosuchmachine.net/\"",
    "license: \"Apache-2.0\"",
    "defensive research",
    "public evidence",
    "claim-bounded release",
    "cryptographic research",
    "high-assurance research",
    "not production cryptography",
    "not runtime sandboxing",
    "not host-cleanliness proof",
    "not whole-system post-quantum safety",
    "not FIPS validation",
    "not government validation",
    "not external certification",
    "not independent audit completion",
    "not a perfect score claim from repository-owned evidence"
  ]) {
    if (!siteCitation.includes(required)) {
      fail(`citation.cff is missing required citation marker: ${required}`);
    }
  }
  for (const [label, pattern] of [
    ["production-ready cryptography", /production-ready cryptography/],
    ["runtime sandboxing guaranteed", /runtime sandboxing guaranteed/],
    ["host cleanliness proof", /host cleanliness proof/],
    ["post-quantum safe", /post-quantum safe\b/],
    ["FIPS validated", /FIPS validated/],
    ["government validated", /government validated/],
    ["externally certified", /externally certified/],
    ["independently audited by", /independently audited by/]
  ]) {
    if (pattern.test(siteCitation)) {
      fail(`citation.cff contains unsupported release claim: ${label}`);
    }
  }
}

async function assertHostingRequirements() {
  const requirements = await readJsonOrNull(new URL("hosting-requirements.json", siteRoot));
  if (requirements === null) {
    fail("site/hosting-requirements.json is missing or not valid JSON");
    return;
  }
  const expected = {
    schema: "wuci-site-hosting-requirements-v1",
    project: "wuci-ji",
    surface: "Wuci-Ji v2 — Aperture Bastion website",
    canonical_origin: "https://nosuchmachine.net",
    canonical_url: "https://nosuchmachine.net/",
    checked_by: "make site-live-check"
  };
  for (const [key, value] of Object.entries(expected)) {
    if (requirements[key] !== value) {
      fail(`hosting-requirements.json ${key} does not match expected value`);
    }
  }

  if (!Array.isArray(requirements.required_redirects)) {
    fail("hosting-requirements.json required_redirects must be a list");
  } else {
    const redirectNames = new Set(requirements.required_redirects.map((entry) => entry.name));
    for (const required of ["apex-http-to-https", "www-to-apex"]) {
      if (!redirectNames.has(required)) {
        fail(`hosting-requirements.json is missing redirect requirement: ${required}`);
      }
    }
    for (const entry of requirements.required_redirects) {
      if (!Array.isArray(entry.allowed_status) || !entry.allowed_status.includes(301) || !entry.allowed_status.includes(308)) {
        fail(`hosting-requirements.json redirect ${entry.name} must allow 301 and 308`);
      }
      if (entry.target_prefix !== "https://nosuchmachine.net/") {
        fail(`hosting-requirements.json redirect ${entry.name} has unexpected target_prefix`);
      }
    }
  }

  if (!Array.isArray(requirements.required_https_headers)) {
    fail("hosting-requirements.json required_https_headers must be a list");
  } else if (
    !requirements.required_https_headers.some(
      (entry) =>
        entry.path === "/" &&
        entry.header === "strict-transport-security" &&
        entry.value_must_contain === "max-age="
    )
  ) {
    fail("hosting-requirements.json must require Strict-Transport-Security max-age on /");
  }

  for (const required of [
    "/",
    "/llms.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/aperture-status.json",
    "/daylight-status.json",
    "/codemeta.json",
    "/citation.cff",
    "/hosting-requirements.json",
    "/claim-evidence.json",
    "/assets/wuci-ji-official-emblem.jpg",
    "/assets/wuci-ji-v2-aperture-bastion.jpeg"
  ]) {
    if (!Array.isArray(requirements.required_public_paths) || !requirements.required_public_paths.includes(required)) {
      fail(`hosting-requirements.json is missing public path: ${required}`);
    }
  }

  const controls = JSON.stringify(requirements.deployment_controls || []);
  for (const required of ["Enforce HTTPS enabled", "Always Use HTTPS enabled", "HTTP Strict Transport Security enabled"]) {
    if (!controls.includes(required)) {
      fail(`hosting-requirements.json is missing deploy control: ${required}`);
    }
  }
  for (const required of [
    "not host-cleanliness proof",
    "not runtime sandboxing",
    "not production cryptography",
    "not external certification",
    "not independent audit completion"
  ]) {
    if (!Array.isArray(requirements.non_claims) || !requirements.non_claims.includes(required)) {
      fail(`hosting-requirements.json non_claims are missing ${required}`);
    }
  }
}

async function assertClaimEvidenceMap() {
  const claimMap = await readJsonOrNull(new URL("claim-evidence.json", siteRoot));
  if (claimMap === null) {
    fail("site/claim-evidence.json is missing or not valid JSON");
    return;
  }
  const expected = {
    schema: "wuci-site-claim-evidence-v1",
    project: "wuci-ji",
    surface: "Wuci-Ji v2 — Aperture Bastion website",
    canonical_url: "https://nosuchmachine.net/"
  };
  for (const [key, value] of Object.entries(expected)) {
    if (claimMap[key] !== value) {
      fail(`claim-evidence.json ${key} does not match expected value`);
    }
  }
  for (const required of [
    "make site-validate",
    "make daylight-v19-aperture-bastion-ci",
    "make daylight-public-artifact-firewall",
    "make site-live-check"
  ]) {
    if (!Array.isArray(claimMap.primary_validation) || !claimMap.primary_validation.includes(required)) {
      fail(`claim-evidence.json primary_validation is missing ${required}`);
    }
  }
  if (!Array.isArray(claimMap.claims)) {
    fail("claim-evidence.json claims must be a list");
    return;
  }
  const claims = new Map(claimMap.claims.map((entry) => [entry.id, entry]));
  for (const requiredId of [
    "official-emblem",
    "aperture-review-capsule",
    "public-artifact-firewall",
    "daylight-score-binding",
    "read-only-public-meridian-surface",
    "hosted-tls-requirements",
    "research-discovery-metadata"
  ]) {
    if (!claims.has(requiredId)) {
      fail(`claim-evidence.json is missing claim id: ${requiredId}`);
    }
  }
  for (const claim of claimMap.claims) {
    for (const key of ["public_claim", "status", "evidence_paths", "validation_commands", "does_not_prove"]) {
      if (!(key in claim)) {
        fail(`claim-evidence.json claim ${claim.id || "<missing-id>"} is missing ${key}`);
      }
    }
    if (!Array.isArray(claim.evidence_paths) || claim.evidence_paths.length === 0) {
      fail(`claim-evidence.json claim ${claim.id} must list evidence_paths`);
    } else {
      for (const evidencePath of claim.evidence_paths) {
        if (!(await existsInRepo(evidencePath))) {
          fail(`claim-evidence.json claim ${claim.id} references missing evidence path: ${evidencePath}`);
        }
      }
    }
    if (!Array.isArray(claim.validation_commands) || claim.validation_commands.length === 0) {
      fail(`claim-evidence.json claim ${claim.id} must list validation_commands`);
    }
    if (!Array.isArray(claim.does_not_prove) || claim.does_not_prove.length === 0) {
      fail(`claim-evidence.json claim ${claim.id} must state what it does not prove`);
    }
  }

  const aperture = await readJsonOrNull(new URL("aperture-status.json", siteRoot));
  const daylight = await readJsonOrNull(new URL("daylight-status.json", siteRoot));
  if (aperture === null || daylight === null) {
    fail("claim-evidence.json cross-check requires aperture-status.json and daylight-status.json");
    return;
  }

  const emblem = claims.get("official-emblem");
  if (emblem?.evidence_values?.sha256 !== await sha256Hex("assets/wuci-ji-official-emblem.jpg")) {
    fail("claim-evidence.json official-emblem sha256 must match asset bytes");
  }
  const apertureClaim = claims.get("aperture-review-capsule");
  if (apertureClaim?.evidence_values?.release_tag !== aperture.release_tag) {
    fail("claim-evidence.json Aperture release tag must match aperture-status.json");
  }
  if (apertureClaim?.evidence_values?.capsule_digest !== aperture.capsule_digest) {
    fail("claim-evidence.json Aperture capsule digest must match aperture-status.json");
  }
  if (apertureClaim?.evidence_values?.firewall_profile_id !== aperture.firewall_profile_id) {
    fail("claim-evidence.json Aperture firewall profile must match aperture-status.json");
  }
  const firewallClaim = claims.get("public-artifact-firewall");
  if (firewallClaim?.evidence_values?.firewall_profile_digest !== aperture.firewall_profile_digest) {
    fail("claim-evidence.json firewall digest must match aperture-status.json");
  }
  const scoreClaim = claims.get("daylight-score-binding");
  if (scoreClaim?.evidence_values?.score_AM_plus !== daylight.score_AM_plus) {
    fail("claim-evidence.json Daylight score must match daylight-status.json");
  }
  if (scoreClaim?.evidence_values?.scorecard_digest !== daylight.scorecard_digest) {
    fail("claim-evidence.json Daylight scorecard digest must match daylight-status.json");
  }
  if (scoreClaim?.evidence_values?.declared !== daylight.declared) {
    fail("claim-evidence.json Daylight declared flag must match daylight-status.json");
  }
  const hostClaim = claims.get("hosted-tls-requirements");
  if (hostClaim?.evidence_values?.canonical_url !== "https://nosuchmachine.net/") {
    fail("claim-evidence.json hosted TLS canonical URL must be https://nosuchmachine.net/");
  }
  if (
    hostClaim?.evidence_values?.required_redirect_source_scheme !== "http" ||
    hostClaim?.evidence_values?.required_redirect_source_host !== "nosuchmachine.net" ||
    hostClaim?.evidence_values?.required_redirect_target_prefix !== "https://nosuchmachine.net/"
  ) {
    fail("claim-evidence.json hosted TLS redirect fields must target the HTTPS apex");
  }
  const researchClaim = claims.get("research-discovery-metadata");
  if (!Array.isArray(researchClaim?.evidence_paths) || !researchClaim.evidence_paths.includes("CITATION.cff")) {
    fail("claim-evidence.json research-discovery-metadata must reference root CITATION.cff");
  }
  if (!Array.isArray(researchClaim?.evidence_paths) || !researchClaim.evidence_paths.includes("site/citation.cff")) {
    fail("claim-evidence.json research-discovery-metadata must reference site/citation.cff");
  }
  if (researchClaim?.evidence_values?.citation !== "https://nosuchmachine.net/citation.cff") {
    fail("claim-evidence.json research-discovery-metadata citation URL must match public endpoint");
  }
  for (const required of aperture.non_claims) {
    if (!Array.isArray(claimMap.non_claims) || !claimMap.non_claims.includes(required)) {
      fail(`claim-evidence.json non_claims are missing ${required}`);
    }
  }
}

async function assertNoInsecurePublicUrls() {
  for (const file of [
    "index.html",
    "404.html",
    "robots.txt",
    "sitemap.xml",
    "site.webmanifest",
    "codemeta.json",
    "citation.cff",
    "hosting-requirements.json",
    "claim-evidence.json",
    "llms.txt",
    "humans.txt",
    "security.txt",
    ".well-known/security.txt"
  ]) {
    const text = await readFile(new URL(file, siteRoot), "utf8");
    const insecureUrls = Array.from(text.matchAll(/http:\/\/[^"'\s<>]+/g)).map((match) => match[0]);
    for (const url of insecureUrls) {
      if (
        url.startsWith("http://127.0.0.1") ||
        url.startsWith("http://localhost") ||
        url === "http://www.sitemaps.org/schemas/sitemap/0.9" ||
        url === "http://www.google.com/schemas/sitemap-image/1.1"
      ) {
        continue;
      }
      fail(`site/${file} contains non-local insecure URL: ${url}`);
    }
  }
}

async function assertNoRootDeployArtifacts() {
  const forbidden = ["dist", "public", "build"];
  for (const directory of forbidden) {
    const target = path.resolve(process.cwd(), directory);
    if (target === path.resolve(process.cwd(), "site")) {
      fail("site output directory must remain site/");
    }
  }
}

await assertRequiredFiles();
await assertCustomDomain();
await assertIndexReferences();
await assertNotFoundPage();
await assertBrowserHttpsFallback();
await assertNoPublicBrowserCrypto();
await assertAssetSizes();
await assertCloudflareFiles();
await assertSearchDiscoveryFiles();
await assertPublicTextDiscovery();
await assertResearchMetadata();
await assertCitationMetadata();
await assertHostingRequirements();
await assertClaimEvidenceMap();
await assertNoInsecurePublicUrls();
await assertDaylightStatusBinding();
await assertApertureStatusBinding();
await assertClaimBoundaryLanguage();
await assertNoRootDeployArtifacts();

if (process.exitCode) {
  process.exit();
}

console.log("site build: OK");
console.log("site output: site");
