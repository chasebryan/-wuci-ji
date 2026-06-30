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
  "assets/wuci-daylight-v15-meridian-banner.png",
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
    'href="#mae"',
    'data-meridian-workbench'
  ]) {
    if (!index.includes(required)) {
      fail(`index.html is missing SEO or encryptor marker: ${required}`);
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
  if (!headers.includes("Content-Security-Policy:")) {
    fail("site/_headers is missing Content-Security-Policy");
  }
  const redirects = await readFile(new URL("_redirects", siteRoot), "utf8");
  for (const route of ["/repo", "/readme", "/docs/security-boundary", "/docs/wuci-os"]) {
    if (!redirects.includes(`${route} `)) {
      fail(`site/_redirects is missing route: ${route}`);
    }
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
await assertNoRootDeployArtifacts();

if (process.exitCode) {
  process.exit();
}

console.log("site build: OK");
console.log("site output: site");
