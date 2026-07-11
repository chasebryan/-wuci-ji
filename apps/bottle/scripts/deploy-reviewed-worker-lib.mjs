import { sha256 } from "./release-manifest-lib.mjs";

const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const TAG_PATTERN = /^sha256-[0-9a-f]{64}$/;

export function workerBundleTag(bundleBytes) {
  return `sha256-${sha256(bundleBytes)}`;
}

export function buildReviewedWorkerDeployArguments(bundlePath, commit, bundleBytes) {
  if (
    typeof bundlePath !== "string"
    || bundlePath.length === 0
    || bundlePath.includes("\0")
    || !COMMIT_PATTERN.test(commit)
  ) {
    throw new Error("Reviewed Worker deploy metadata is invalid.");
  }
  const tag = workerBundleTag(bundleBytes);
  if (!TAG_PATTERN.test(tag)) {
    throw new Error("Reviewed Worker bundle tag is invalid.");
  }
  return {
    tag,
    args: [
      "deploy",
      bundlePath,
      "--no-bundle",
      "--strict",
      "--tag",
      tag,
      "--message",
      `source=${commit} worker-${tag}`
    ]
  };
}

export function assertDeploymentEvidence(payload, expectedTag) {
  if (
    typeof payload !== "object"
    || payload === null
    || Array.isArray(payload)
    || Object.keys(payload).sort().join(",")
      !== "schema,versionCreatedAt,workerVersionId,workerVersionTag"
    || payload.schema !== "nsm.daylight-bottle.deployment.v1"
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      payload.workerVersionId
    )
    || payload.workerVersionTag !== expectedTag
    || !TAG_PATTERN.test(payload.workerVersionTag)
    || typeof payload.versionCreatedAt !== "string"
    || new Date(payload.versionCreatedAt).toISOString() !== payload.versionCreatedAt
  ) {
    throw new Error("Live Worker deployment evidence does not match the reviewed bundle tag.");
  }
  return payload;
}
