import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  assertCurrentCleanSource,
  assertReleaseBuildToolchain,
  assertSameBytes,
  normalizeGitRepositoryUrl,
  readRegularFile
} from "./release-manifest-lib.mjs";
import { assertProductionConfig } from "./production-config-lib.mjs";
import {
  assertDeploymentEvidence,
  buildReviewedWorkerDeployArguments
} from "./deploy-reviewed-worker-lib.mjs";

const appRoot = new URL("../", import.meta.url);
const repositoryRoot = new URL("../../", appRoot);
const productionConfigPath = fileURLToPath(new URL("wrangler.toml", appRoot));
const environment = {
  ...process.env,
  GIT_TERMINAL_PROMPT: "0",
  WRANGLER_SEND_METRICS: "false",
  WRANGLER_WRITE_LOGS: "false"
};

run("git", ["fetch", "--quiet", "origin", "main"], repositoryRoot, 60_000);
const manifest = JSON.parse(
  (await readRegularFile(new URL("dist/release-manifest.json", appRoot), "Release manifest"))
    .toString("utf8")
);
const config = (
  await readRegularFile(new URL("wrangler.toml", appRoot), "Production Wrangler configuration")
).toString("utf8");
assertProductionConfig(config);

const head = gitOutput(["rev-parse", "HEAD"]);
assertCurrentCleanSource(
  manifest,
  head,
  gitOutput(["status", "--porcelain=v1", "--untracked-files=all"]),
  normalizeGitRepositoryUrl(gitOutput(["remote", "get-url", "origin"])),
  gitOutput(["rev-parse", "refs/remotes/origin/main"])
);
assertReleaseBuildToolchain(process.version, `npm@${commandOutput("npm", ["--version"])}`);
assertReleaseBuildToolchain(manifest.build?.nodeVersion, manifest.build?.packageManager);
await import("./verify-bundle.mjs");

const temporary = await mkdtemp(join(tmpdir(), "daylight-bottle-reviewed-worker-"));
try {
  run("wrangler", ["deploy", "--dry-run", "--outdir", temporary], appRoot, 120_000);
  const freshPath = join(temporary, "index.js");
  const fresh = await readRegularFile(pathToFileURL(freshPath), "Fresh reviewed Worker bundle");
  const retained = await readRegularFile(
    new URL("../.wrangler/dry-run/index.js", import.meta.url),
    "Retained CI-shape Worker bundle"
  );
  assertSameBytes(retained, fresh, "Retained and fresh reviewed Worker bundles");
  const deployment = buildReviewedWorkerDeployArguments(
    freshPath,
    productionConfigPath,
    head,
    fresh
  );
  run("wrangler", deployment.args, appRoot, 300_000);
  const liveEvidence = await verifyLiveDeployment(deployment.tag);
  console.log(
    `Verified active Worker version ${liveEvidence.workerVersionId} for source ${head} and ${deployment.tag}.`
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function verifyLiveDeployment(expectedTag) {
  let lastError;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      const response = await fetch("https://bottle.nosuchmachine.net/api/deployment", {
        headers: { Accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(5_000)
      });
      const contentLength = response.headers.get("content-length");
      if (contentLength !== null && Number(contentLength) > 4096) {
        throw new Error("Live Worker deployment evidence exceeds its byte budget.");
      }
      const body = await readBoundedBody(response, 4096);
      if (
        response.status !== 200
        || response.url !== "https://bottle.nosuchmachine.net/api/deployment"
        || !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")
        || !response.headers.get("cache-control")?.toLowerCase().includes("no-store")
      ) {
        throw new Error("Live Worker deployment evidence response is invalid.");
      }
      return assertDeploymentEvidence(JSON.parse(body.toString("utf8")), expectedTag);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
  }
  throw new Error(
    `The exact Worker bundle was uploaded but its active version tag was not confirmed: ${
      lastError instanceof Error ? lastError.message : "unknown error"
    }`
  );
}

async function readBoundedBody(response, limit) {
  if (!response.body) {
    return Buffer.alloc(0);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel("Deployment evidence exceeds its byte budget.");
        throw new Error("Live Worker deployment evidence exceeds its byte budget.");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

function gitOutput(args) {
  return commandOutput("git", args, repositoryRoot);
}

function commandOutput(command, args, cwd = appRoot) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    env: environment,
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 30_000
  }).trim();
}

function run(command, args, cwd, timeout) {
  execFileSync(command, args, {
    cwd,
    env: environment,
    stdio: "inherit",
    timeout
  });
}
