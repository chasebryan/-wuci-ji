import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { extname, relative, sep } from "node:path";
import { gzipSync } from "node:zlib";
import {
  assertSameBytes,
  buildSourceClosure,
  collectRegularFiles,
  normalizeGitRepositoryUrl,
  readRegularFile,
  sha256,
  WORKER_SOURCE_PATHS
} from "./release-manifest-lib.mjs";

const appRoot = new URL("../", import.meta.url);
const repositoryRoot = new URL("../../", appRoot);
const dist = new URL("dist/", appRoot);
const manifestUrl = new URL("release-manifest.json", dist);
const runtimeExtensions = new Set([".html", ".js", ".mjs", ".css"]);
const maxRuntimeBytes = 220 * 1024;
const maxRuntimeGzipBytes = 80 * 1024;

const files = (await collectRegularFiles(dist, "Built release artifact"))
  .filter((file) => file.pathname !== manifestUrl.pathname)
  .sort(compareUrlPathnames);
const artifacts = [];
let runtimeBytes = 0;
let runtimeGzipBytes = 0;

for (const file of files) {
  const path = relative(dist.pathname, file.pathname).split(sep).join("/");
  const content = await readRegularFile(file, `Built release artifact ${path}`);
  artifacts.push({ path, bytes: content.byteLength, sha256: sha256(content) });
  if (runtimeExtensions.has(extname(path))) {
    runtimeBytes += content.byteLength;
    runtimeGzipBytes += gzipSync(content, { level: 9 }).byteLength;
  }
}

assertWithinBudget("raw runtime assets", runtimeBytes, maxRuntimeBytes);
assertWithinBudget("gzip runtime assets", runtimeGzipBytes, maxRuntimeGzipBytes);

const sourceKeyring = await readRegularFile(
  new URL("public/keyring.json", appRoot),
  "Source public keyring"
);
const builtKeyring = await readRegularFile(new URL("keyring.json", dist), "Built public keyring");
assertSameBytes(sourceKeyring, builtKeyring, "Source and built public keyrings");

const packageJsonBytes = await readRegularFile(
  new URL("package.json", appRoot),
  "Package manifest"
);
const packageJson = JSON.parse(packageJsonBytes.toString("utf8"));
const treeStatus = gitOutput(["status", "--porcelain=v1", "--untracked-files=all"]);
const repository = normalizeGitRepositoryUrl(gitOutput(["remote", "get-url", "origin"])) ?? "unknown";
const subject = {
  source: {
    repository,
    commit: gitOutput(["rev-parse", "HEAD"]) ?? "unknown",
    treeState: treeStatus === undefined ? "unknown" : treeStatus === "" ? "clean" : "dirty"
  },
  build: {
    appVersion: expectString(packageJson.version, "package version"),
    nodeVersion: process.version,
    packageManager: `npm@${currentNpmVersion()}`,
    command: "npm run build"
  },
  inputs: {
    packageJsonSha256: sha256(packageJsonBytes),
    packageLockSha256: await sha256File(new URL("package-lock.json", appRoot), "Package lock"),
    keyringSha256: sha256(sourceKeyring),
    securityHeadersSha256: await sha256File(
      new URL("public/_headers", appRoot),
      "Static security headers"
    ),
    workerSourceClosure: await buildSourceClosure(appRoot, WORKER_SOURCE_PATHS),
    wranglerConfigSha256: await sha256File(
      new URL("wrangler.toml", appRoot),
      "Wrangler configuration"
    )
  },
  bundleBudget: {
    schema: "nsm.daylight-bottle.bundle-budget.v1",
    runtimeBytes,
    runtimeGzipBytes,
    maxRuntimeBytes,
    maxRuntimeGzipBytes
  },
  artifacts
};
const subjectSha256 = sha256(Buffer.from(JSON.stringify(subject)));
const manifest = {
  schema: "nsm.daylight-bottle.release-manifest.v1",
  subjectSha256: `sha256:${subjectSha256}`,
  ...subject
};

await writeFile(manifestUrl, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(
  `Generated release-manifest.json: ${runtimeBytes}/${maxRuntimeBytes} raw bytes, ${runtimeGzipBytes}/${maxRuntimeGzipBytes} gzip bytes.`
);

function gitOutput(args) {
  return commandOutput("git", args, repositoryRoot);
}

function commandOutput(command, args, cwd = appRoot) {
  try {
    return execFileSync(command, args, {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return undefined;
  }
}

function currentNpmVersion() {
  const userAgentMatch = process.env["npm_config_user_agent"]?.match(/\bnpm\/([^\s]+)/);
  if (userAgentMatch?.[1]) {
    return userAgentMatch[1];
  }
  return expectString(commandOutput("npm", ["--version"]), "npm version");
}

async function sha256File(url, label) {
  return sha256(await readRegularFile(url, label));
}

function assertWithinBudget(label, actual, maximum) {
  if (actual > maximum) {
    throw new Error(`${label} exceed the release budget: ${actual} > ${maximum} bytes.`);
  }
}

function expectString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Missing ${label}.`);
  }
  return value;
}

function compareUrlPathnames(left, right) {
  return left.pathname < right.pathname ? -1 : left.pathname > right.pathname ? 1 : 0;
}
