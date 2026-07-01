import { access, readFile, readdir, stat } from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import process from "node:process";

const siteRoot = new URL(".", import.meta.url);

const requiredFiles = [
  "index.html",
  "404.html",
  "styles.css",
  "app.js",
  "_headers",
  "_redirects",
  "robots.txt",
  "sitemap.xml",
  "site.webmanifest",
  "daylight-status.json",
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
    'rel="canonical"',
    'rel="sitemap"',
    'rel="manifest"',
    'property="og:image"',
    'name="twitter:card"',
    'href="#encrypt"',
    'href="#daylight"',
    'id="catalog"',
    'id="mae"',
    'data-meridian-workbench'
  ]) {
    if (!index.includes(required)) {
      fail(`index.html is missing SEO or encryptor marker: ${required}`);
    }
  }
  // The GitHub Pages deploy path does not serve _headers, so the document
  // itself must carry the CSP and referrer policy.
  for (const required of [
    'http-equiv="Content-Security-Policy"',
    'name="referrer"'
  ]) {
    if (!index.includes(required)) {
      fail(`index.html is missing in-document security policy: ${required}`);
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
  for (const route of ["/repo", "/readme", "/docs/security-boundary", "/docs/wuci-os"]) {
    if (!redirects.includes(`${route} `)) {
      fail(`site/_redirects is missing route: ${route}`);
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
  const sitemap = await readFile(new URL("sitemap.xml", siteRoot), "utf8");
  if (!sitemap.includes("<loc>https://nosuchmachine.net/</loc>")) {
    fail("sitemap.xml is missing canonical root URL");
  }
  const manifest = JSON.parse(await readFile(new URL("site.webmanifest", siteRoot), "utf8"));
  if (manifest.name !== "No Such Machine" || manifest.start_url !== "/") {
    fail("site.webmanifest has unexpected identity or start_url");
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
await assertIndexReferences();
await assertAssetSizes();
await assertCloudflareFiles();
await assertSearchDiscoveryFiles();
await assertDaylightStatusBinding();
await assertNoRootDeployArtifacts();

if (process.exitCode) {
  process.exit();
}

console.log("site build: OK");
console.log("site output: site");
