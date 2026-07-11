import { describe, expect, it } from "vitest";
import {
  assertDeploymentEvidence,
  buildReviewedWorkerDeployArguments,
  workerBundleTag
} from "./deploy-reviewed-worker-lib.mjs";

describe("reviewed Worker deployment", () => {
  it("deploys the exact prebuilt bytes with the reviewed production config", () => {
    const bytes = Buffer.from("export default { fetch() { return new Response(); } };\n");
    const commit = "a".repeat(40);
    const tag = workerBundleTag(bytes);
    const built = buildReviewedWorkerDeployArguments(
      "/tmp/reviewed/index.js",
      "/repo/apps/bottle/wrangler.toml",
      commit,
      bytes
    );
    expect(tag).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(built).toEqual({
      tag,
      args: [
        "deploy",
        "/tmp/reviewed/index.js",
        "--config",
        "/repo/apps/bottle/wrangler.toml",
        "--name",
        "daylight-bottle",
        "--no-bundle",
        "--strict",
        "--tag",
        tag,
        "--message",
        `source=${commit} worker-${tag}`
      ]
    });
  });

  it("rejects unsafe source metadata and mismatched live evidence", () => {
    expect(() =>
      buildReviewedWorkerDeployArguments("", "/repo/wrangler.toml", "a".repeat(40), Buffer.from("x"))
    ).toThrow();
    expect(() =>
      buildReviewedWorkerDeployArguments("/tmp/index.js", "", "a".repeat(40), Buffer.from("x"))
    ).toThrow();
    expect(() =>
      buildReviewedWorkerDeployArguments(
        "/tmp/index.js",
        "/repo/wrangler.toml",
        "short",
        Buffer.from("x")
      )
    ).toThrow();
    const expectedTag = `sha256-${"b".repeat(64)}`;
    const evidence = {
      schema: "nsm.daylight-bottle.deployment.v1",
      workerVersionId: "01234567-89ab-4cde-8f01-23456789abcd",
      workerVersionTag: expectedTag,
      versionCreatedAt: "2026-07-11T03:30:00.000Z"
    };
    expect(assertDeploymentEvidence(evidence, expectedTag)).toBe(evidence);
    expect(() =>
      assertDeploymentEvidence(
        { ...evidence, workerVersionTag: `sha256-${"c".repeat(64)}` },
        expectedTag
      )
    ).toThrow(/reviewed bundle tag/);
  });
});
