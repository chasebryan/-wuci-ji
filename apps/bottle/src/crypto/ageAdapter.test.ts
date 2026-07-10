import { describe, expect, it } from "vitest";
import * as age from "age-encryption";
import {
  decryptBottlePayload,
  decryptBottlePayloadForRecipient,
  encryptBottlePayload,
  fingerprintKeyRecordInput,
  generateIdentity,
  verifyPrivateIdentityMatchesKeyRecord
} from "./ageAdapter";
import { SCHEMAS, type PlainBottlePayload } from "../domain/types";

describe("ageAdapter", () => {
  it("encrypts and decrypts a bottle payload round trip", async () => {
    const identity = await generateIdentity();
    const recipientFingerprint = await fingerprintKeyRecordInput({
      keyname: "daylight/chase",
      publicRecipient: identity.publicRecipient
    });
    const payload: PlainBottlePayload = {
      schema: SCHEMAS.payload,
      keyname: "daylight/chase",
      recipientFingerprint,
      message: "The tide turns at first light.",
      createdAt: "2026-07-07T00:00:00.000Z"
    };

    const ciphertext = await encryptBottlePayload({
      payload,
      publicRecipient: identity.publicRecipient
    });

    expect(ciphertext).toContain("-----BEGIN AGE ENCRYPTED FILE-----");
    expect(ciphertext).not.toContain(payload.message);
    await expect(
      decryptBottlePayload({
        ciphertext,
        privateIdentity: identity.privateIdentity
      })
    ).resolves.toEqual(payload);
  });

  it("rejects decrypted plaintext with a malformed payload schema", async () => {
    const identity = await generateIdentity();
    const encrypter = new age.Encrypter();
    encrypter.addRecipient(identity.publicRecipient);
    const ciphertext = age.armor.encode(
      await encrypter.encrypt(JSON.stringify({ schema: "not-daylight", message: "bad" }))
    );

    await expect(
      decryptBottlePayload({
        ciphertext,
        privateIdentity: identity.privateIdentity
      })
    ).rejects.toThrow(/schema/);
  });

  it("rejects decrypted payloads whose recipient fingerprint does not match metadata", async () => {
    const identity = await generateIdentity();
    const payload: PlainBottlePayload = {
      schema: SCHEMAS.payload,
      keyname: "daylight/chase",
      recipientFingerprint: `sha256:${"a".repeat(64)}`,
      message: "Fingerprint mismatch should fail after decrypt.",
      createdAt: "2026-07-07T00:00:00.000Z"
    };
    const ciphertext = await encryptBottlePayload({
      payload,
      publicRecipient: identity.publicRecipient
    });

    await expect(
      decryptBottlePayloadForRecipient({
        ciphertext,
        privateIdentity: identity.privateIdentity,
        expectedKeyname: "daylight/chase",
        expectedRecipientFingerprint: `sha256:${"b".repeat(64)}`
      })
    ).rejects.toThrow(/recipient fingerprint/);
  });

  it("rejects decrypted payloads whose keyname does not match selected metadata", async () => {
    const identity = await generateIdentity();
    const recipientFingerprint = await fingerprintKeyRecordInput({
      keyname: "daylight/chase",
      publicRecipient: identity.publicRecipient
    });
    const payload: PlainBottlePayload = {
      schema: SCHEMAS.payload,
      keyname: "daylight/chase",
      recipientFingerprint,
      message: "Keyname mismatch should fail after decrypt.",
      createdAt: "2026-07-07T00:00:00.000Z"
    };
    const ciphertext = await encryptBottlePayload({
      payload,
      publicRecipient: identity.publicRecipient
    });

    await expect(
      decryptBottlePayloadForRecipient({
        ciphertext,
        privateIdentity: identity.privateIdentity,
        expectedKeyname: "aperture/alice",
        expectedRecipientFingerprint: recipientFingerprint
      })
    ).rejects.toThrow(/keyname/);
  });

  it("verifies that a private identity matches the full selected key record", async () => {
    const identity = await generateIdentity();
    const fingerprint = await fingerprintKeyRecordInput({
      keyname: "daylight/chase",
      publicRecipient: identity.publicRecipient
    });

    await expect(
      verifyPrivateIdentityMatchesKeyRecord({
        privateIdentity: identity.privateIdentity,
        keyname: "daylight/chase",
        expectedPublicRecipient: identity.publicRecipient,
        expectedFingerprint: fingerprint
      })
    ).resolves.toBeUndefined();

    const otherIdentity = await generateIdentity();
    await expect(
      verifyPrivateIdentityMatchesKeyRecord({
        privateIdentity: otherIdentity.privateIdentity,
        keyname: "daylight/chase",
        expectedPublicRecipient: identity.publicRecipient,
        expectedFingerprint: fingerprint
      })
    ).rejects.toThrow(/does not match/);
  });
});
