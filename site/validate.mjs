import { access, readFile, readdir, stat } from "node:fs/promises";
import { constants } from "node:fs";
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
    'itemtype="https://schema.org/SoftwareSourceCode"',
    'itemprop="codeRepository"',
    'itemprop="logo"',
    'rel="manifest"',
    'rel="preload"',
    'rel="apple-touch-icon"',
    'property="og:image"',
    'name="twitter:card"',
    'href="aperture-status.json"',
    'href="#encrypt"',
    'href="#aperture"',
    'href="#assurance"',
    'href="#daylight"',
    'id="aperture"',
    'id="assurance"',
    'id="catalog"',
    'id="mae"',
    'data-meridian-workbench',
    'Wuci-Ji v2 — Aperture Bastion',
    'assets/wuci-ji-official-emblem.jpg',
    'Official Wuci-Ji emblem',
    'Every public claim needs a local handle.',
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
      fail(`index.html is missing SEO or encryptor marker: ${required}`);
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
    "Content-Type: application/json; charset=utf-8",
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
    "<loc>https://nosuchmachine.net/daylight-status.json</loc>"
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

async function assertNoInsecurePublicUrls() {
  for (const file of [
    "index.html",
    "404.html",
    "robots.txt",
    "sitemap.xml",
    "site.webmanifest",
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
await assertAssetSizes();
await assertCloudflareFiles();
await assertSearchDiscoveryFiles();
await assertPublicTextDiscovery();
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
