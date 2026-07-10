import { describe, expect, it } from "vitest";
import { fingerprintKeyRecordInput } from "./fingerprint";

describe("fingerprintKeyRecordInput", () => {
  it("is deterministic and uses the required canonical string", async () => {
    const input = {
      keyname: "Daylight/Chase",
      publicRecipient: "age1examplepublicrecipient"
    };
    const expectedDigest = "621e81a78fa9dbb2c30e71e70ca8f16893353f122db26fd8eb1a61f52bfb9d41";

    await expect(fingerprintKeyRecordInput(input)).resolves.toBe(`sha256:${expectedDigest}`);
    await expect(fingerprintKeyRecordInput(input)).resolves.toBe(`sha256:${expectedDigest}`);
  });
});
