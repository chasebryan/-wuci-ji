import { execFileSync } from "node:child_process";
import { extname, relative, sep } from "node:path";
import { gzipSync } from "node:zlib";
import {
  WORKER_SOURCE_PATHS,
  assertBundleSourceMetadata,
  assertReleaseBuildToolchain,
  assertSameBytes,
  assertValidKeyring,
  buildSourceClosure,
  collectRegularFiles,
  readRegularFile,
  sha256
} from "./release-manifest-lib.mjs";

const root = new URL("../", import.meta.url);
const dist = new URL("dist/", root);
const requiredFiles = ["index.html", "keyring.json", "_headers", "release-manifest.json"];
const runtimeExtensions = new Set([".html", ".js", ".mjs", ".css"]);
const expectedMaxRuntimeBytes = 220 * 1024;
const expectedMaxRuntimeGzipBytes = 80 * 1024;

assertReleaseBuildToolchain(process.version, `npm@${currentNpmVersion()}`);

for (const file of requiredFiles) {
  await readRegularFile(new URL(file, dist), `Required built file ${file}`);
}

for (const file of await runtimeFiles(dist)) {
  const label = relative(dist.pathname, file.pathname);
  const content = (await readRegularFile(file, `Runtime file ${label}`)).toString("utf8");
  if (/(?:https?|wss?):\/\//i.test(content)) {
    throw new Error(`${label} contains an external runtime URL.`);
  }
}

const html = (await readRegularFile(new URL("index.html", dist), "Built index.html")).toString("utf8");
if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(html) || /<style\b/i.test(html) || /\sstyle=/i.test(html)) {
  throw new Error("Built HTML contains inline script or style that violates the production CSP.");
}

const headers = (await readRegularFile(new URL("_headers", dist), "Built security headers")).toString("utf8");
for (const required of [
  "default-src 'self'",
  "script-src 'self'",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "Referrer-Policy: no-referrer",
  "Permissions-Policy: geolocation=(), microphone=(), camera=()",
  "Cross-Origin-Opener-Policy: same-origin",
  "Cross-Origin-Resource-Policy: same-origin",
  "X-Frame-Options: DENY",
  "X-Content-Type-Options: nosniff"
]) {
  if (!headers.includes(required)) {
    throw new Error(`Built _headers is missing required policy: ${required}`);
  }
}
if (!/(?:^|\n)\/release-manifest\.json\n {2}Cache-Control: no-store, no-transform(?:\n|$)/.test(headers)) {
  throw new Error(
    "Built _headers must serve release-manifest.json with Cache-Control: no-store, no-transform."
  );
}

await verifyKeyring();
const budget = await verifyReleaseManifest();
console.log(
  `Verified same-origin bundle, CSP-compatible HTML, keyring fingerprints, release manifest, security headers, and bundle budget (${budget.runtimeBytes} raw / ${budget.runtimeGzipBytes} gzip bytes).`
);

async function verifyKeyring() {
  const source = (await readRegularFile(new URL("keyring.json", dist), "Built public keyring")).toString("utf8");
  assertValidKeyring(JSON.parse(source));
}

async function verifyReleaseManifest() {
  const manifest = expectRecord(
    JSON.parse(
      (
        await readRegularFile(
          new URL("release-manifest.json", dist),
          "Built release manifest"
        )
      ).toString("utf8")
    ),
    "release manifest"
  );
  assertExactFields(
    manifest,
    ["schema", "subjectSha256", "source", "build", "inputs", "bundleBudget", "artifacts"],
    "release manifest"
  );
  if (manifest.schema !== "nsm.daylight-bottle.release-manifest.v1") {
    throw new Error("Built release manifest has an unsupported schema.");
  }
  if (!Array.isArray(manifest.artifacts)) {
    throw new Error("Built release manifest artifacts must be an array.");
  }
  const source = expectRecord(manifest.source, "release manifest source");
  assertExactFields(source, ["repository", "commit", "treeState"], "release manifest source");
  assertBundleSourceMetadata(source);
  const build = expectRecord(manifest.build, "release manifest build");
  assertExactFields(
    build,
    ["appVersion", "nodeVersion", "packageManager", "command"],
    "release manifest build"
  );
  for (const field of ["appVersion", "nodeVersion", "packageManager", "command"]) {
    expectString(build[field], `release manifest build ${field}`);
  }
  if (build.command !== "npm run build") {
    throw new Error("Built release manifest has an unexpected build command.");
  }
  assertReleaseBuildToolchain(build.nodeVersion, build.packageManager);

  const actualFiles = (await collectRegularFiles(dist, "Built release artifact"))
    .filter((file) => !file.pathname.endsWith("/release-manifest.json"))
    .sort(compareUrlPathnames);
  const actualArtifacts = [];
  let runtimeBytes = 0;
  let runtimeGzipBytes = 0;
  for (const file of actualFiles) {
    const path = relative(dist.pathname, file.pathname).split(sep).join("/");
    const content = await readRegularFile(file, `Built release artifact ${path}`);
    actualArtifacts.push({ path, bytes: content.byteLength, sha256: sha256(content) });
    if (runtimeExtensions.has(extname(path))) {
      runtimeBytes += content.byteLength;
      runtimeGzipBytes += gzipSync(content, { level: 9 }).byteLength;
    }
  }
  if (JSON.stringify(manifest.artifacts) !== JSON.stringify(actualArtifacts)) {
    throw new Error("Built release manifest artifact hashes or sizes do not match dist.");
  }

  const budget = expectRecord(manifest.bundleBudget, "bundle budget");
  assertExactFields(
    budget,
    ["schema", "runtimeBytes", "runtimeGzipBytes", "maxRuntimeBytes", "maxRuntimeGzipBytes"],
    "bundle budget"
  );
  if (budget.schema !== "nsm.daylight-bottle.bundle-budget.v1") {
    throw new Error("Built release manifest has an unsupported bundle budget schema.");
  }
  const maxRuntimeBytes = expectPositiveInteger(budget.maxRuntimeBytes, "maxRuntimeBytes");
  const maxRuntimeGzipBytes = expectPositiveInteger(budget.maxRuntimeGzipBytes, "maxRuntimeGzipBytes");
  if (
    maxRuntimeBytes !== expectedMaxRuntimeBytes ||
    maxRuntimeGzipBytes !== expectedMaxRuntimeGzipBytes
  ) {
    throw new Error("Built release manifest changes the enforced runtime bundle budget.");
  }
  if (budget.runtimeBytes !== runtimeBytes || budget.runtimeGzipBytes !== runtimeGzipBytes) {
    throw new Error("Built release manifest bundle measurements do not match dist.");
  }
  if (runtimeBytes > maxRuntimeBytes || runtimeGzipBytes > maxRuntimeGzipBytes) {
    throw new Error("Built runtime assets exceed the recorded release budget.");
  }

  const subject = {
    source: manifest.source,
    build: manifest.build,
    inputs: manifest.inputs,
    bundleBudget: manifest.bundleBudget,
    artifacts: manifest.artifacts
  };
  const expectedSubjectSha256 = `sha256:${sha256(Buffer.from(JSON.stringify(subject)))}`;
  if (manifest.subjectSha256 !== expectedSubjectSha256) {
    throw new Error("Built release manifest subject digest does not verify.");
  }

  const inputs = expectRecord(manifest.inputs, "release manifest inputs");
  assertExactFields(
    inputs,
    [
      "packageJsonSha256",
      "packageLockSha256",
      "keyringSha256",
      "securityHeadersSha256",
      "workerSourceClosure",
      "wranglerConfigSha256"
    ],
    "release manifest inputs"
  );
  const sourceInputs = [
    ["packageJsonSha256", new URL("package.json", root), "Package manifest"],
    ["packageLockSha256", new URL("package-lock.json", root), "Package lock"],
    ["keyringSha256", new URL("public/keyring.json", root), "Source public keyring"],
    ["securityHeadersSha256", new URL("public/_headers", root), "Static security headers"],
    ["wranglerConfigSha256", new URL("wrangler.toml", root), "Wrangler configuration"]
  ];
  for (const [name, url, label] of sourceInputs) {
    const expected = sha256(await readRegularFile(url, label));
    if (inputs[name] !== expected) {
      throw new Error(`Built release manifest input digest does not match ${name}.`);
    }
  }

  const expectedWorkerSourceClosure = await buildSourceClosure(root, WORKER_SOURCE_PATHS);
  if (JSON.stringify(inputs.workerSourceClosure) !== JSON.stringify(expectedWorkerSourceClosure)) {
    throw new Error("Built release manifest Worker source closure does not match current sources.");
  }

  const sourceKeyring = await readRegularFile(
    new URL("public/keyring.json", root),
    "Source public keyring"
  );
  const builtKeyring = await readRegularFile(new URL("keyring.json", dist), "Built public keyring");
  assertSameBytes(sourceKeyring, builtKeyring, "Source and built public keyrings");

  return { runtimeBytes, runtimeGzipBytes };
}

async function runtimeFiles(directory) {
  return (await collectRegularFiles(directory, "Built runtime artifact")).filter((file) =>
    runtimeExtensions.has(extname(file.pathname))
  );
}

function expectRecord(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value;
}

function expectString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string.`);
  }
  return value;
}

function expectPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function currentNpmVersion() {
  const userAgentMatch = process.env["npm_config_user_agent"]?.match(/\bnpm\/([^\s]+)/);
  if (userAgentMatch?.[1]) {
    return userAgentMatch[1];
  }
  try {
    return execFileSync("npm", ["--version"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    throw new Error("Unable to determine the npm version for bundle verification.");
  }
}

function assertExactFields(record, fields, label) {
  const expected = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) {
      throw new Error(`${label} contains unexpected field ${key}.`);
    }
  }
  for (const field of expected) {
    if (!Object.hasOwn(record, field)) {
      throw new Error(`${label} is missing field ${field}.`);
    }
  }
}

function compareUrlPathnames(left, right) {
  return left.pathname < right.pathname ? -1 : left.pathname > right.pathname ? 1 : 0;
}
