import { describe, expect, it } from "vitest";
import { formatFingerprint } from "./dom";

describe("UI formatting", () => {
  it("groups the full fingerprint for comparison without changing its characters", () => {
    const fingerprint = `sha256:${"01234567".repeat(8)}`;
    const formatted = formatFingerprint(fingerprint);

    expect(formatted).toBe(`sha256:${Array(8).fill("01234567").join(" ")}`);
    expect(formatted.replaceAll(" ", "")).toBe(fingerprint);
  });
});
