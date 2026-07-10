import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fingerprintKeyRecordInput } from "../crypto/fingerprint";
import { parseKeyring } from "../domain/validation";

describe("published static keyring", () => {
  it("contains only exact public records with verified fingerprints", async () => {
    const source = await readFile(join(process.cwd(), "public/keyring.json"), "utf8");
    const keyring = parseKeyring(JSON.parse(source));

    for (const key of keyring.keys) {
      await expect(
        fingerprintKeyRecordInput({
          keyname: key.keyname,
          publicRecipient: key.publicRecipient
        })
      ).resolves.toBe(key.fingerprint);
    }
  });
});
