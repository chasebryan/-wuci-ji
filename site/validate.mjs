import { access, readFile, readdir, stat } from "node:fs/promises";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import process from "node:process";

const siteRoot = new URL(".", import.meta.url);

const requiredFiles = [
  "index.html",
  "product-boundary.html",
  "wucios.html",
  "ai-scoring-integrity.html",
  "daylight-grok-audit.html",
  "audits/daylight/score-integrity/index.html",
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
  "daylight-v20-aperture-singularity-status.json",
  "assets/wuci-ji-white-brick-banner.jpg",
  "assets/wuci-ji-black-brick-banner.jpg",
  "assets/wuci-ji-official-emblem.jpg",
  "assets/no-such-machine-official-emblem.jpg",
  "assets/no-such-machine-official-emblem.svg",
  "assets/no-such-machine-official-banner.jpg",
  "assets/wuci-ji-v2-aperture-bastion.jpeg",
  "assets/wuci-daylight-v15-meridian-banner.png",
  "assets/daylight-v17-singularity.jpg",
  "assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp",
  "assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.png",
  "assets/daylight-v20-public-challenge-780thc.jpg",
  "assets/daylight-v20-gate-fixture-score-surface.webp",
  "assets/daylight-v20-gate-fixture-score-surface.png",
  "assets/daylight-v20-gate-aes-256-gcm-comparison-surface.webp",
  "assets/daylight-v20-gate-aes-256-gcm-comparison-surface.png",
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
    'name="application-name" content="No Such Machine"',
    'rel="canonical"',
    'rel="author"',
    'rel="alternate"',
    'rel="manifest"',
    'rel="apple-touch-icon"',
    'property="og:image"',
    'https://nosuchmachine.net/assets/no-such-machine-official-banner.jpg',
    'name="twitter:card"',
    'No Such Machine — Wuci-Ji Public Evidence Surface',
    '<section class="nsm-hero"',
    'assets/no-such-machine-official-emblem.svg',
    'assets/no-such-machine-official-banner.jpg',
    'Official No Such Machine emblem: circular aperture compass with central bastion mark',
    'href="#evidence"',
    'href="#daylight"',
    'href="#wucios"',
    'href="#catalog"',
    'href="product-boundary.html"',
    'id="review"',
    'id="evidence"',
    'id="daylight"',
    'id="meridian"',
    'id="wucios"',
    'id="catalog"',
    'id="boundary"',
    'Not production cryptography',
    'Not runtime sandboxing',
    'Not external certification',
    'Browser cryptography is not shipped',
    'Evidence-bound public review',
    'NoEvidence(x) -&gt; NoClaim(x)',
    'NoProof(x) -&gt; NoRelease(x)',
    'ManualScore(x) -&gt; Reject(x)',
    'claim-evidence.json',
    'aperture-status.json',
    'citation.cff',
    'codemeta.json',
    'hosting-requirements.json',
    'daylight-v20-aperture-singularity-status.json',
    'https://nosuchmachine.net/',
    'assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp',
    'Daylight v20 repo-owned ceiling score surface',
    '999,801,305 AM+',
    'assets/daylight-v20-public-challenge-780thc.jpg',
    'Daylight v20 public challenge',
    'repo_owned_code_gap_count = 0',
    'repo_owned_ceiling_reached = true',
    'singularity_possible_without_external_validation = false',
    'declaration_allowed = false',
    'Technical review requested',
    'No endorsement is requested or implied',
    'assets/daylight-v20-gate-fixture-score-surface.webp',
    'Fixture score surface, not claim-usable external evidence.',
    'make daylight-public-artifact-firewall',
    '28564990503',
    'v2.2.0-aperture-bastion',
    'ce077fea615528634ad27fec516fdb402f101602',
    '9109e7d9364f305a0618e6f5d810f3dd665d995e5c56f9d0ccc8d01875b9eec0',
    'WuciOS v2.4 Reduction Gate',
    'make wucios-validate',
    'make wucios-review'
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

async function assertInteractiveAccessibility() {
  const app = await readFile(new URL("app.js", siteRoot), "utf8");
  const styles = await readFile(new URL("styles.css", siteRoot), "utf8");
  for (const required of [
    'lightbox.setAttribute("role", "dialog")',
    'lightbox.setAttribute("aria-modal", "true")',
    'lightbox.setAttribute("aria-hidden", "true")',
    'lightbox.setAttribute("aria-label", "Image preview")',
    'closeBtn.setAttribute("tabindex", "-1")',
    "function setPageHidden(hidden)",
    'region.setAttribute("inert", "")',
    'figure.setAttribute("aria-label", "Open larger view: " + label.trim())',
    'lightbox.setAttribute("aria-hidden", "false")',
    "closeBtn.focus({ preventScroll: true })",
    "window.requestAnimationFrame(function ()",
    "lastActiveElement.focus()",
    'e.key === "Tab" && lightbox.classList.contains("is-active")'
  ]) {
    if (!app.includes(required)) {
      fail(`app.js is missing interactive accessibility marker: ${required}`);
    }
  }
  for (const required of [
    ".lightbox-close:focus-visible",
    "main figure:focus-visible",
    "transition: opacity 300ms ease, backdrop-filter 300ms ease;",
    "transition: background 200ms ease, border-color 200ms ease, color 200ms ease;",
    ".lightbox.is-active .lightbox-close"
  ]) {
    if (!styles.includes(required)) {
      fail(`styles.css is missing interactive focus marker: ${required}`);
    }
  }
}

async function assertNoBroadCssTransitions() {
  const styles = await readFile(new URL("styles.css", siteRoot), "utf8");
  if (/transition\s*:\s*all\b/.test(styles)) {
    fail("styles.css must not use transition: all; transition only the properties that change");
  }
}

async function assertNotFoundPage() {
  const notFound = await readFile(new URL("404.html", siteRoot), "utf8");
  for (const required of [
    'name="robots" content="noindex, follow"',
    'rel="canonical" href="https://nosuchmachine.net/"',
    'assets/no-such-machine-official-emblem.svg',
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
    layer: "Wuci-Ji v2.2 — Aperture Bastion",
    release_tag: "v2.2.0-aperture-bastion",
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
  const normalized = index.replace(/\s+/g, " ").toLowerCase();
  for (const required of [
    "not production cryptography",
    "not a general runtime sandbox",
    "not host-cleanliness proof",
    "not whole-system post-quantum secure",
    "not fips validation",
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
    "proves host cleanliness",
    "post-quantum safe",
    "is fips validated",
    "is government validated",
    "is externally certified",
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

async function assertDaylightV20ApertureSingularityStatusBinding() {
  const status = await readJsonOrNull(new URL("daylight-v20-aperture-singularity-status.json", siteRoot));
  if (status === null) {
    fail("site/daylight-v20-aperture-singularity-status.json is missing or not valid JSON");
    return;
  }
  if (status.schema !== "wuci-daylight-v20-aperture-singularity-site-status-v1") {
    fail("daylight-v20-aperture-singularity-status.json schema is unsupported");
  }
  if (status.layer !== "Daylight v20 - Aperture Singularity Gate") {
    fail("daylight-v20-aperture-singularity-status.json layer is unsupported");
  }
  if (!Number.isInteger(status.score_AM_plus) || status.score_AM_plus < 0) {
    fail("daylight-v20-aperture-singularity-status.json score_AM_plus must be a non-negative integer");
  }
  if (status.unit !== "AM+") {
    fail("daylight-v20-aperture-singularity-status.json unit must be AM+");
  }
  if (typeof status.capsule_digest !== "string" || !/^[0-9a-f]{64}$/.test(status.capsule_digest)) {
    fail("daylight-v20-aperture-singularity-status.json capsule_digest must be sha256 hex");
  }
  if (status.declared !== false || status.declaration !== "refused") {
    fail("daylight-v20-aperture-singularity-status.json must remain declaration-refused");
  }
  if (status.fixture !== true || status.claim_usable !== false) {
    fail("daylight-v20-aperture-singularity-status.json must keep fixture=true and claim_usable=false");
  }
  if (status.repo_owned_code_gap_count !== 0 || status.external_evidence_required_count !== 4) {
    fail("daylight-v20-aperture-singularity-status.json evidence gap counts changed unexpectedly");
  }
  if (
    status.repo_owned_ceiling_reached !== true
    || status.singularity_possible_without_external_validation !== false
    || status.highest_truthful_no_external_score_AM_plus !== status.score_AM_plus
  ) {
    fail("daylight-v20-aperture-singularity-status.json no-external ceiling fields are inconsistent");
  }

  const index = await readFile(new URL("index.html", siteRoot), "utf8");
  const displayed = withCommas(status.score_AM_plus);
  if (!index.includes(displayed)) {
    fail(`index.html does not display the v20 Aperture Singularity AM+ number: ${displayed}`);
  }
  const hooks = Array.from(index.matchAll(/data-v20-am-plus="([0-9]+)"/g)).map((match) => match[1]);
  if (hooks.length === 0) {
    fail("index.html is missing a data-v20-am-plus evidence hook");
  }
  for (const hook of hooks) {
    if (hook !== String(status.score_AM_plus)) {
      fail(`index.html data-v20-am-plus="${hook}" does not match v20 evidence ${status.score_AM_plus}`);
    }
  }

  const capsule = await readJsonOrNull(new URL(`../${status.source}`, siteRoot));
  if (capsule === null) {
    console.log(`site build: note: ${status.source} absent, skipped v20 capsule cross-check`);
    return;
  }
  const comparisons = {
    capsule_digest: capsule.capsule_digest,
    score_AM_plus: capsule.score_AM_plus,
    omega_eff: capsule.omega_eff,
    release_tag: capsule.release_tag,
    declared: capsule.declaration_allowed,
    fixture: capsule.fixture,
    claim_usable: capsule.claim_usable
  };
  for (const [key, expected] of Object.entries(comparisons)) {
    if (status[key] !== expected) {
      fail(`daylight-v20-aperture-singularity-status.json ${key} does not match committed capsule`);
    }
  }
  if (!Array.isArray(status.blockers) || JSON.stringify(status.blockers) !== JSON.stringify(capsule.blockers)) {
    fail("daylight-v20-aperture-singularity-status.json blockers do not match committed capsule");
  }
  if (!Array.isArray(status.non_claims) || JSON.stringify(status.non_claims) !== JSON.stringify(capsule.non_claims)) {
    fail("daylight-v20-aperture-singularity-status.json non_claims do not match committed capsule");
  }
}

function dataAttribute(html, name) {
  const match = html.match(new RegExp(`\\bdata-${name}="([^"]*)"`, "i"));
  return match ? match[1] : null;
}

async function assertDaylightScoreIntegrityAuditPortal() {
  const pagePath = "audits/daylight/score-integrity/index.html";
  const page = await readFile(new URL(pagePath, siteRoot), "utf8");
  const normalized = page.replace(/\s+/g, " ");
  const visibleText = normalized.replace(/<[^>]*>/g, " ");
  const lowerVisibleText = visibleText.toLowerCase();
  const auditBase = "audits/daylight/score-integrity";
  const repoBlobBase = "https://github.com/chasebryan/-wuci-ji/blob/main";

  const auditIndex = await readJsonOrNull(new URL(`../${auditBase}/index.json`, siteRoot));
  if (auditIndex === null) {
    fail(`${auditBase}/index.json is missing or not valid JSON`);
    return;
  }
  const latestRunId = auditIndex.latest_run;
  const latestRun = Array.isArray(auditIndex.runs)
    ? auditIndex.runs.find((entry) => entry.id === latestRunId)
    : null;
  if (!latestRun) {
    fail("score-integrity index.json latest_run does not name a listed run");
    return;
  }
  if (dataAttribute(page, "audit-run") !== latestRunId) {
    fail("audit portal page run id does not match index.json latest_run");
  }

  const manifestPath = `${auditBase}/${latestRun.manifest}`;
  const reportPath = `${auditBase}/${latestRun.report}`;
  const manifest = await readJsonOrNull(new URL(`../${manifestPath}`, siteRoot));
  const report = await readJsonOrNull(new URL(`../${reportPath}`, siteRoot));
  const claims = await readJsonOrNull(new URL(`../${auditBase}/runs/${latestRunId}/reports/daylight-score-claims.json`, siteRoot));
  const ratioAudit = await readJsonOrNull(new URL(`../${auditBase}/runs/${latestRunId}/reports/ratio-percent-audit.json`, siteRoot));
  const surfaceDiff = await readJsonOrNull(new URL(`../${auditBase}/runs/${latestRunId}/reports/public-surface-score-diff.json`, siteRoot));
  if (manifest === null || report === null || claims === null || ratioAudit === null || surfaceDiff === null) {
    fail("score-integrity audit portal cross-check requires manifest, final report, claim ledger, ratio audit, and public-surface diff JSON");
    return;
  }

  if (manifest.audit_id !== latestRunId) {
    fail("score-integrity manifest audit_id does not match index.json latest_run");
  }
  if (latestRun.commit !== manifest.audited_commit) {
    fail("score-integrity index.json commit does not match manifest audited_commit");
  }
  if (report.commit !== manifest.audited_commit || claims.commit !== manifest.audited_commit || ratioAudit.commit !== manifest.audited_commit || surfaceDiff.commit !== manifest.audited_commit) {
    fail("score-integrity report commits do not match manifest audited_commit");
  }
  if (dataAttribute(page, "audited-commit") !== manifest.audited_commit) {
    fail("audit portal page commit does not match manifest audited_commit");
  }
  if (dataAttribute(page, "audit-result") !== manifest.result || dataAttribute(page, "audit-result") !== latestRun.result) {
    fail("audit portal page result does not match index.json and manifest result");
  }
  if (dataAttribute(page, "report-result") !== report.result) {
    fail("audit portal page report result does not match final report result");
  }
  if (manifest.result !== "PASS_SCORE_INTEGRITY" || report.result !== "pass") {
    fail("score-integrity audit files do not carry the expected pass result pair");
  }

  const v20Claim = Array.isArray(claims.claims)
    ? claims.claims.find((entry) => entry.id === "v20.repo_owned_ceiling")
    : null;
  const quorumClaim = Array.isArray(claims.claims)
    ? claims.claims.find((entry) => entry.id === "v20_3.verifier_quorum")
    : null;
  if (!v20Claim || !quorumClaim) {
    fail("score-integrity claim ledger is missing v20 or v20.3 claim records");
    return;
  }
  const displayedScore = `${withCommas(v20Claim.numerator)} AM+`;
  if (v20Claim.value_raw !== displayedScore || dataAttribute(page, "displayed-score") !== displayedScore) {
    fail("audit portal displayed score does not match score-claim ledger value");
  }
  if (dataAttribute(page, "score-am-plus") !== String(v20Claim.numerator)) {
    fail("audit portal data score does not match score-claim ledger numerator");
  }
  if (!page.includes(displayedScore)) {
    fail(`audit portal page does not display report score: ${displayedScore}`);
  }
  const scoreHooks = Array.from(page.matchAll(/data-v20-am-plus="([0-9]+)"/g)).map((match) => match[1]);
  if (scoreHooks.length === 0 || scoreHooks.some((hook) => hook !== String(v20Claim.numerator))) {
    fail("audit portal data-v20-am-plus hooks do not match score-claim ledger numerator");
  }
  if (v20Claim.audit_status !== "PASS_RECOMPUTED" || quorumClaim.audit_status !== "PASS_EVIDENCE_MATCH") {
    fail("score-integrity v20 and v20.3 claim statuses changed unexpectedly");
  }

  const caveat = report.non_claim_caveat.replace(/\s+/g, " ");
  if (!normalized.includes(caveat)) {
    fail("audit portal page is missing final report non-claim caveat");
  }
  for (const required of [
    "Latest audit run",
    "Audited commit",
    "PASS_SCORE_INTEGRITY result",
    "Displayed score",
    "Codex: PASS",
    "Fable5: PASS",
    "Report file links",
    "Manifest link",
    "SHA256SUMS link",
    "Score-claim ledger link",
    "Ratio/percentage audit link",
    "Public-surface diff link",
    "Methodology",
    "Non-claim boundary",
    "Recompute the Daylight v20 score.",
    "Check the claim ledger.",
    "Check the ratio math.",
    "Check the v20.3 quorum boundary.",
    "Find a mismatch.",
    "If you find one, file it.",
    "Daylight External Verifier Intake v1"
  ]) {
    if (!normalized.includes(required)) {
      fail(`audit portal page is missing required marker: ${required}`);
    }
  }
  if (dataAttribute(page, "codex-result") !== "PASS" || dataAttribute(page, "fable5-result") !== "PASS") {
    fail("audit portal Codex/Fable5 display results must remain PASS");
  }

  for (const requiredPath of [
    `${auditBase}/index.json`,
    manifestPath,
    `${auditBase}/runs/${latestRunId}/SHA256SUMS.txt`,
    reportPath,
    `${auditBase}/runs/${latestRunId}/reports/daylight-score-claims.json`,
    `${auditBase}/runs/${latestRunId}/reports/ratio-percent-audit.json`,
    `${auditBase}/runs/${latestRunId}/reports/public-surface-score-diff.json`,
    `${auditBase}/METHODOLOGY.md`,
    `${auditBase}/NON_CLAIMS.md`
  ]) {
    const expectedLink = `${repoBlobBase}/${requiredPath}`;
    if (!page.includes(expectedLink)) {
      fail(`audit portal page is missing evidence link: ${expectedLink}`);
    }
  }

  for (const [label, pattern] of [
    ["certified", /\bcertified\b/],
    ["officially audited", /\bofficially audited\b/],
    ["production ready", /\bproduction ready\b/]
  ]) {
    if (pattern.test(lowerVisibleText)) {
      fail(`audit portal page contains forbidden unsupported claim: ${label}`);
    }
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
    "<image:loc>https://nosuchmachine.net/assets/no-such-machine-official-banner.jpg</image:loc>",
    "<image:loc>https://nosuchmachine.net/assets/no-such-machine-official-emblem.svg</image:loc>",
    "<image:loc>https://nosuchmachine.net/assets/no-such-machine-official-emblem.jpg</image:loc>",
    "<image:title>No Such Machine official banner</image:title>",
    "<image:title>No Such Machine official transparent emblem</image:title>",
    "<image:title>No Such Machine official emblem</image:title>",
    "<image:loc>https://nosuchmachine.net/assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp</image:loc>",
    "<image:title>Daylight v20 Gate repo-owned score surface</image:title>",
    "<image:loc>https://nosuchmachine.net/assets/daylight-v20-public-challenge-780thc.jpg</image:loc>",
    "<image:title>Daylight v20 public challenge</image:title>",
    "<image:loc>https://nosuchmachine.net/assets/daylight-v20-gate-fixture-score-surface.webp</image:loc>",
    "<image:title>Daylight v20 Gate fixture surface</image:title>",
    "<image:loc>https://nosuchmachine.net/assets/daylight-v20-gate-aes-256-gcm-comparison-surface.webp</image:loc>",
    "<image:title>Daylight v20 Gate heuristic comparison</image:title>",
    "<loc>https://nosuchmachine.net/aperture-status.json</loc>",
    "<loc>https://nosuchmachine.net/daylight-status.json</loc>",
    "<loc>https://nosuchmachine.net/daylight-v20-aperture-singularity-status.json</loc>",
    "<loc>https://nosuchmachine.net/ai-scoring-integrity.html</loc>",
    "<loc>https://nosuchmachine.net/daylight-grok-audit.html</loc>",
    "<loc>https://nosuchmachine.net/audits/daylight/score-integrity/</loc>",
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
  if (manifest.name !== "No Such Machine" || manifest.short_name !== "NSM" || manifest.start_url !== "/") {
    fail("site.webmanifest has unexpected identity or start_url");
  }
  if (!manifest.description.includes("No Such Machine public evidence surface")) {
    fail("site.webmanifest must describe the No Such Machine public evidence surface");
  }
  if (!manifest.icons.some((icon) => icon.src === "/assets/no-such-machine-official-emblem.jpg" && icon.type === "image/jpeg")) {
    fail("site.webmanifest must expose the official No Such Machine emblem");
  }
}

async function assertPublicTextDiscovery() {
  const llms = await readFile(new URL("llms.txt", siteRoot), "utf8");
  for (const required of [
    "No Such Machine / Wuci-Ji",
    "https://nosuchmachine.net/assets/no-such-machine-official-emblem.svg",
    "https://nosuchmachine.net/assets/no-such-machine-official-emblem.jpg",
    "https://nosuchmachine.net/assets/no-such-machine-official-banner.jpg",
    "WuciOS v2.4 Reduction Gate",
    "Noether Core",
    "Birkhoff Bastion",
    "Tarski Review Appliance",
    "Euclid Substrate Trial",
    "make wucios-validate",
    "make wucios-review",
    "make site-validate",
    "not production cryptography",
    "not runtime sandboxing",
    "not host-cleanliness proof",
    "not whole-system post-quantum safety",
    "not FIPS validation",
    "not government validation",
    "not external certification",
    "not independent audit completion"
  ]) {
    if (!llms.includes(required)) {
      fail(`llms.txt is missing required research-agent marker: ${required}`);
    }
  }
  const humans = await readFile(new URL("humans.txt", siteRoot), "utf8");
  if (
    !humans.includes("No Such Machine") ||
    !humans.includes("make site-validate") ||
    !humans.includes("https://nosuchmachine.net/assets/no-such-machine-official-emblem.svg") ||
    !humans.includes("890d4c6ccc6af97a4d4f3de4b53fe4c6384b03456053bbe66a7a3b06f739b6c4") ||
    !humans.includes("0790f9fae750460099c38e217800deee0d97043a591918a2e478b594a18b4c8f") ||
    !humans.includes("https://nosuchmachine.net/citation.cff") ||
    !humans.includes("https://nosuchmachine.net/claim-evidence.json")
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
    name: "Wuci-Ji v2.2 — Aperture Bastion",
    citation: "https://nosuchmachine.net/citation.cff",
    codeRepository: "https://github.com/chasebryan/-wuci-ji",
    contIntegration: "https://github.com/chasebryan/-wuci-ji/actions/workflows/daylight-v19-aperture-bastion.yml",
    identifier: "wuci-ji-v2-aperture-bastion",
    image: "https://nosuchmachine.net/assets/wuci-ji-v2-aperture-bastion.jpeg",
    issueTracker: "https://github.com/chasebryan/-wuci-ji/issues",
    license: "https://spdx.org/licenses/Apache-2.0",
    logo: "https://nosuchmachine.net/assets/wuci-ji-official-emblem.jpg",
    readme: "https://github.com/chasebryan/-wuci-ji/blob/main/README.md",
    softwareVersion: "v2.2.0-aperture-bastion",
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
    "title: \"Wuci-Ji v2.2 — Aperture Bastion\"",
    "type: software",
    "name: \"No Such Machine\"",
    "version: \"v2.2.0-aperture-bastion\"",
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
    surface: "Wuci-Ji v2.2 — Aperture Bastion website",
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
    "/ai-scoring-integrity.html",
    "/daylight-grok-audit.html",
    "/audits/daylight/score-integrity/",
    "/aperture-status.json",
    "/daylight-status.json",
    "/daylight-v20-aperture-singularity-status.json",
    "/codemeta.json",
    "/citation.cff",
    "/hosting-requirements.json",
    "/claim-evidence.json",
    "/assets/wuci-ji-official-emblem.jpg",
    "/assets/wuci-ji-v2-aperture-bastion.jpeg",
    "/assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.webp",
    "/assets/daylight-v20-gate-repo-owned-ceiling-score-surface-999801305.png",
    "/assets/daylight-v20-public-challenge-780thc.jpg",
    "/assets/daylight-v20-gate-fixture-score-surface.webp",
    "/assets/daylight-v20-gate-fixture-score-surface.png",
    "/assets/daylight-v20-gate-aes-256-gcm-comparison-surface.webp",
    "/assets/daylight-v20-gate-aes-256-gcm-comparison-surface.png"
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
    surface: "Wuci-Ji v2.2 — Aperture Bastion website",
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
    "daylight-v20-aperture-singularity-score-surface",
    "daylight-v20-public-challenge",
    "ai-scoring-integrity-audit",
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
  const daylightV20 = await readJsonOrNull(new URL("daylight-v20-aperture-singularity-status.json", siteRoot));
  if (aperture === null || daylight === null || daylightV20 === null) {
    fail("claim-evidence.json cross-check requires aperture-status.json, daylight-status.json, and daylight-v20-aperture-singularity-status.json");
    return;
  }

  const emblem = claims.get("official-emblem");
  if (emblem?.evidence_values?.emblem_sha256 !== await sha256Hex("assets/no-such-machine-official-emblem.jpg")) {
    fail("claim-evidence.json official-emblem emblem_sha256 must match asset bytes");
  }
  if (emblem?.evidence_values?.emblem_svg_sha256 !== await sha256Hex("assets/no-such-machine-official-emblem.svg")) {
    fail("claim-evidence.json official-emblem emblem_svg_sha256 must match asset bytes");
  }
  if (emblem?.evidence_values?.banner_sha256 !== await sha256Hex("assets/no-such-machine-official-banner.jpg")) {
    fail("claim-evidence.json official-emblem banner_sha256 must match asset bytes");
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
  const v20ScoreClaim = claims.get("daylight-v20-aperture-singularity-score-surface");
  if (v20ScoreClaim?.evidence_values?.score_AM_plus !== daylightV20.score_AM_plus) {
    fail("claim-evidence.json v20 score must match daylight-v20-aperture-singularity-status.json");
  }
  if (v20ScoreClaim?.evidence_values?.capsule_digest !== daylightV20.capsule_digest) {
    fail("claim-evidence.json v20 capsule digest must match daylight-v20-aperture-singularity-status.json");
  }
  if (v20ScoreClaim?.evidence_values?.declared !== daylightV20.declared) {
    fail("claim-evidence.json v20 declared flag must match daylight-v20-aperture-singularity-status.json");
  }
  if (v20ScoreClaim?.evidence_values?.fixture !== daylightV20.fixture || v20ScoreClaim?.evidence_values?.claim_usable !== daylightV20.claim_usable) {
    fail("claim-evidence.json v20 fixture and claim_usable values must match daylight-v20-aperture-singularity-status.json");
  }
  if (v20ScoreClaim?.evidence_values?.repo_owned_code_gap_count !== daylightV20.repo_owned_code_gap_count) {
    fail("claim-evidence.json v20 repo_owned_code_gap_count must match daylight-v20-aperture-singularity-status.json");
  }
  for (const key of [
    "repo_owned_ceiling_reached",
    "singularity_possible_without_external_validation",
    "highest_truthful_no_external_score_AM_plus"
  ]) {
    if (v20ScoreClaim?.evidence_values?.[key] !== daylightV20[key]) {
      fail(`claim-evidence.json v20 ${key} must match daylight-v20-aperture-singularity-status.json`);
    }
  }
  const v20ChallengeClaim = claims.get("daylight-v20-public-challenge");
  if (v20ChallengeClaim?.evidence_values?.poster_sha256 !== await sha256Hex("assets/daylight-v20-public-challenge-780thc.jpg")) {
    fail("claim-evidence.json v20 public challenge poster_sha256 must match asset bytes");
  }
  for (const [claimKey, statusKey] of [
    ["score_AM_plus", "score_AM_plus"],
    ["repo_owned_code_gap_count", "repo_owned_code_gap_count"],
    ["repo_owned_ceiling_reached", "repo_owned_ceiling_reached"],
    ["singularity_possible_without_external_validation", "singularity_possible_without_external_validation"],
    ["declaration_allowed", "declared"]
  ]) {
    if (v20ChallengeClaim?.evidence_values?.[claimKey] !== daylightV20[statusKey]) {
      fail(`claim-evidence.json v20 public challenge ${claimKey} must match daylight-v20-aperture-singularity-status.json`);
    }
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
    "ai-scoring-integrity.html",
    "daylight-grok-audit.html",
    "audits/daylight/score-integrity/index.html",
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

async function assertAiScoringAuditPages() {
  const integrity = await readFile(new URL("ai-scoring-integrity.html", siteRoot), "utf8");
  const grokAudit = await readFile(new URL("daylight-grok-audit.html", siteRoot), "utf8");
  const combined = `${integrity}\n${grokAudit}`;
  for (const required of [
    "AI Scoring Integrity — Daylight",
    "Daylight / Grok Scoring Audit",
    "scoring-integrity concern",
    "provenance failure",
    "capability-disclosure inconsistency",
    "unsupported validation language",
    "false precision risk",
    "national defense AI assurance concern",
    "standards-level review concern",
    "NoEvidence(x) → NoScore(x)",
    "NoProvenance(x) → NoAuthority(x)",
    "NoExecution(x) → NoRuntimeScore(x)",
    "Public file inspection is not runtime verification. Reading a repository is not executing a gate. A model-confidence score is not cryptographic evidence.",
    "Gate execution",
    "not executed",
    "Public artifact generation",
    "Public artifact verification",
    "Sealed-chain verification",
    "Cryptographic attestation verification",
    "Runtime score",
    "none",
    "Prior provenance access",
    "unavailable",
    "does not claim a federal crime occurred",
    "does not claim intent",
    "does not claim any federal agency has adopted, reviewed, or endorsed Daylight",
    "does not claim Daylight is production-ready",
    "does not claim all Grok outputs are invalid",
    "docs/GROK_SCORE_INFLATION_AUDIT.md",
    "docs/DAYLIGHT_AI_SCORING_ASSURANCE_LEDGER.md",
    "docs/DAYLIGHT_AI_ASSURANCE_STANDARD.md",
    "docs/DAYLIGHT_GROK_AUDIT_EXHIBITS.md",
    "data/daylight/grok-scoring-audit/ledger.json",
    "data/daylight/grok-scoring-audit/exhibits.json"
  ]) {
    if (!combined.includes(required)) {
      fail(`AI scoring audit pages are missing required marker: ${required}`);
    }
  }
  for (const forbidden of [
    "Grok is criminal",
    "xAI committed fraud",
    "Grok lied"
  ]) {
    if (combined.includes(forbidden)) {
      fail(`AI scoring audit pages contain forbidden accusation: ${forbidden}`);
    }
  }

  const ledger = await readJsonOrNull(new URL("../data/daylight/grok-scoring-audit/ledger.json", siteRoot));
  const exhibits = await readJsonOrNull(new URL("../data/daylight/grok-scoring-audit/exhibits.json", siteRoot));
  if (ledger === null) {
    fail("data/daylight/grok-scoring-audit/ledger.json is missing or not valid JSON");
    return;
  }
  if (exhibits === null) {
    fail("data/daylight/grok-scoring-audit/exhibits.json is missing or not valid JSON");
    return;
  }
  if (ledger.audit !== "daylight-grok-scoring-integrity" || ledger.status !== "public-ledger") {
    fail("ledger.json has unexpected audit identity or status");
  }
  for (const required of [
    "no_criminal_conclusion",
    "no_intent_claim",
    "no_federal_agency_endorsement_claim",
    "no_daylight_production_claim",
    "no_claim_all_grok_outputs_invalid"
  ]) {
    if (!Array.isArray(ledger.non_claims) || !ledger.non_claims.includes(required)) {
      fail(`ledger.json non_claims are missing ${required}`);
    }
  }
  const ruleExpressions = new Set((ledger.rules || []).map((rule) => rule.expression));
  for (const required of [
    "NoEvidence(x) -> NoScore(x)",
    "NoProvenance(x) -> NoAuthority(x)",
    "NoExecution(x) -> NoRuntimeScore(x)"
  ]) {
    if (!ruleExpressions.has(required)) {
      fail(`ledger.json rules are missing ${required}`);
    }
  }
  const entryIds = new Set((ledger.entries || []).map((entry) => entry.id));
  for (const required of ["G-001", "G-002", "G-003", "G-004"]) {
    if (!entryIds.has(required)) {
      fail(`ledger.json entries are missing ${required}`);
    }
  }
  const exhibitIds = new Set((exhibits.exhibits || []).map((entry) => entry.id));
  for (const required of ["G-01", "G-02", "G-03", "G-04"]) {
    if (!exhibitIds.has(required)) {
      fail(`exhibits.json exhibits are missing ${required}`);
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
await assertInteractiveAccessibility();
await assertNoBroadCssTransitions();
await assertAssetSizes();
await assertCloudflareFiles();
await assertSearchDiscoveryFiles();
await assertPublicTextDiscovery();
await assertResearchMetadata();
await assertCitationMetadata();
await assertHostingRequirements();
await assertClaimEvidenceMap();
await assertAiScoringAuditPages();
await assertDaylightScoreIntegrityAuditPortal();
await assertNoInsecurePublicUrls();
await assertDaylightStatusBinding();
await assertDaylightV20ApertureSingularityStatusBinding();
await assertApertureStatusBinding();
await assertClaimBoundaryLanguage();
await assertNoRootDeployArtifacts();

if (process.exitCode) {
  process.exit();
}

console.log("site build: OK");
console.log("site output: site");
