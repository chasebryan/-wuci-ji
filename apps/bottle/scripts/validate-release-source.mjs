import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import {
  assertCleanSourceSnapshot,
  normalizeGitRepositoryUrl
} from "./release-manifest-lib.mjs";

const appRoot = new URL("../", import.meta.url);
const repositoryRoot = new URL("../../", appRoot);
const releaseManifest = JSON.parse(
  await readFile(new URL("../dist/release-manifest.json", import.meta.url), "utf8")
);
const currentCommit = gitOutput(["rev-parse", "HEAD"]);

assertCleanSourceSnapshot(
  releaseManifest,
  currentCommit,
  gitOutput(["status", "--porcelain=v1", "--untracked-files=all"]),
  normalizeGitRepositoryUrl(gitOutput(["remote", "get-url", "origin"]))
);

const ciCommit = process.env["GITHUB_SHA"];
if (ciCommit !== undefined && ciCommit !== currentCommit) {
  throw new Error("The release manifest checkout does not match GITHUB_SHA.");
}

console.log("Verified release manifest against the current clean source checkout.");

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
