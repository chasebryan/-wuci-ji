import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import process from "node:process";

const siteRoot = new URL(".", import.meta.url);

const requiredFiles = [
  "index.html",
  "wucios.html",
  "styles.css",
  "app.js",
  "favicon.png",
  "site.webmanifest",
  "assets/wuci-ji-official-emblem.jpg",
  "assets/wuci-ji-v2-aperture-bastion.jpeg"
];

const requiredIndexMarkers = [
  "WuciOS v2.4 Reduction Gate",
  "Noether Core",
  "Euclid Trial",
  "Gödel Boundary",
  "make wucios-validate",
  "make wucios-fluff-audit",
  "make wucios-substrate-matrix",
  "make wucios-euclid-trial-phase-1",
  "make wucios-euclid-trial-phase-2",
  "make wucios-review",
  "Void is no longer treated as the",
  "selected base",
  "Xfce is non-authoritative"
];

const requiredWuciosMarkers = [
  "WuciOS v2.4",
  "Reduction Gate",
  "Noether Core",
  "Birkhoff Bastion",
  "Tarski Review Appliance",
  "Euclid Substrate Trial",
  "Gödel Boundary",
  "NO_SUBSTRATE_SELECTED",
  "INVALID_WITHOUT_ARTIFACT",
  "NOT_MEASURED",
  "make wucios-validate",
  "make wucios-fluff-audit",
  "make wucios-substrate-matrix",
  "make wucios-euclid-trial-phase-1",
  "make wucios-euclid-trial-phase-2",
  "SAFE_DETECT_ONLY",
  "not a WuciOS substrate score",
  "make wucios-review"
];

const forbiddenClaims = [
  "military approved",
  "NSA approved",
  "DoD approved",
  "Department of War approved",
  "production certified",
  "production authorized",
  "unbreakable",
  "cannot be hacked",
  "perfect security",
  "999,999",
  "998,900M",
  "1000000M"
];

function fail(message) {
  console.error(`site validate: ${message}`);
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

function isAllowedNonClaim(text, phrase) {
  const lower = text.toLowerCase();
  if (phrase === "cannot be hacked") {
    return lower.includes("not a claim that it cannot be hacked");
  }
  if (phrase === "perfect security") {
    return lower.includes("not perfect security") || lower.includes("not a claim of perfect security");
  }
  if (phrase === "production authorized") {
    return lower.includes("not production authorized");
  }
  return false;
}

async function assertRequiredFiles() {
  for (const file of requiredFiles) {
    if (!(await exists(file))) {
      fail(`missing required file: site/${file}`);
    }
  }
}

async function assertLocalReferences(file) {
  const html = await readFile(new URL(file, siteRoot), "utf8");
  const references = Array.from(html.matchAll(/\b(?:href|src)="([^":#?]+)(?:[?#][^"]*)?"/g)).map((match) => match[1]);
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
      fail(`${file} references missing local asset: ${reference}`);
    }
  }
}

async function assertMarkers(file, markers) {
  const text = await readFile(new URL(file, siteRoot), "utf8");
  for (const marker of markers) {
    if (!text.includes(marker)) {
      fail(`${file} missing marker: ${marker}`);
    }
  }
}

async function assertForbiddenClaims(file) {
  const text = await readFile(new URL(file, siteRoot), "utf8");
  const lower = text.toLowerCase();
  for (const phrase of forbiddenClaims) {
    if (lower.includes(phrase.toLowerCase()) && !isAllowedNonClaim(text, phrase)) {
      fail(`${file} contains unsupported claim phrase: ${phrase}`);
    }
  }
}

await assertRequiredFiles();
await assertLocalReferences("index.html");
await assertLocalReferences("wucios.html");
await assertMarkers("index.html", requiredIndexMarkers);
await assertMarkers("wucios.html", requiredWuciosMarkers);
await assertForbiddenClaims("index.html");
await assertForbiddenClaims("wucios.html");

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log("site validate: ok");
