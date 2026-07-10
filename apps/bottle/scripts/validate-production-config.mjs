import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import {
  assertCurrentCleanSource,
  normalizeGitRepositoryUrl
} from "./release-manifest-lib.mjs";
import { assertProductionConfig } from "./production-config-lib.mjs";

const appRoot = new URL("../", import.meta.url);
const repositoryRoot = new URL("../../", appRoot);
const config = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
const releaseManifest = JSON.parse(
  await readFile(new URL("../dist/release-manifest.json", import.meta.url), "utf8")
);

try {
  await import("./verify-bundle.mjs");
} catch (error) {
  refuse(
    `Refusing live deployment: bundle verification failed: ${error instanceof Error ? error.message : "unknown error"}`
  );
}

try {
  assertProductionConfig(config);
} catch (error) {
  refuse(
    `Refusing live deployment: ${error instanceof Error ? error.message : "production Wrangler configuration is invalid"}`
  );
}

const currentCommit = gitOutput(["rev-parse", "HEAD"]);
const currentTreeStatus = gitOutput(["status", "--porcelain=v1", "--untracked-files=all"]);
const currentRepository = normalizeGitRepositoryUrl(gitOutput(["remote", "get-url", "origin"]));
const approvedMainCommit = gitOutput(["rev-parse", "refs/remotes/origin/main"]);
try {
  assertCurrentCleanSource(
    releaseManifest,
    currentCommit,
    currentTreeStatus,
    currentRepository,
    approvedMainCommit
  );
} catch (error) {
  refuse(
    `Refusing live deployment: ${error instanceof Error ? error.message : "source binding is invalid"}`
  );
}

console.log(
  "Verified clean release manifest, production custom domain, assets route, and BOTTLES_KV namespace id."
);

function refuse(message) {
  console.error(message);
  process.exit(1);
}

function gitOutput(args) {
  try {
    return execFileSync("git", args, {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return undefined;
  }
}
