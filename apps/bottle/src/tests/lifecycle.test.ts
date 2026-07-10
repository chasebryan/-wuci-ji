import { describe, expect, it } from "vitest";
import { dropBottle, listBottles } from "../api/client";
import {
  decryptBottlePayloadForRecipient,
  encryptBottlePayload,
  fingerprintKeyRecordInput,
  generateIdentity,
  verifyPrivateIdentityMatchesKeyRecord
} from "../crypto/ageAdapter";
import { SCHEMAS, type DropBottleRequest, type PlainBottlePayload } from "../domain/types";
import {
  MAX_SERIALIZED_PAYLOAD_BYTES,
  messageMeterPresentation,
  serializedPayloadByteLength
} from "../ui/DropBottle";
import { createMemoryBottleStorage, handleRequest, type BottleWorkerEnv } from "../../worker/index";

describe("complete ciphertext-only bottle lifecycle", () => {
  it("warns before encryption overhead approaches the request limit", () => {
    const small = messageMeterPresentation(1024);
    expect(small.warning).toBe(false);
    expect(small.text).toContain("encryption adds overhead");

    const large = messageMeterPresentation(180 * 1024);
    expect(large.warning).toBe(true);
    expect(large.text).toContain("may exceed the 256 KiB request limit");

    const escapedPayload: PlainBottlePayload = {
      schema: SCHEMAS.payload,
      keyname: "daylight/chase",
      recipientFingerprint: `sha256:${"a".repeat(64)}`,
      message: "\u0000".repeat(30 * 1024),
      createdAt: "2026-07-07T00:00:00.000Z"
    };
    expect(serializedPayloadByteLength(escapedPayload)).toBeGreaterThan(
      MAX_SERIALIZED_PAYLOAD_BYTES
    );
  });

  it("creates, drops, retrieves, and locally opens a short message", async () => {
    const identity = await generateIdentity();
    const keyname = "daylight/chase";
    const recipientFingerprint = await fingerprintKeyRecordInput({
      keyname,
      publicRecipient: identity.publicRecipient
    });
    const payload: PlainBottlePayload = {
      schema: SCHEMAS.payload,
      keyname,
      recipientFingerprint,
      message: "a",
      createdAt: "2026-07-07T00:00:00.000Z"
    };
    const ciphertext = await encryptBottlePayload({
      payload,
      publicRecipient: identity.publicRecipient
    });
    const request: DropBottleRequest = {
      schema: SCHEMAS.drop,
      keyname,
      recipientFingerprint,
      ciphertext,
      createdAtClient: payload.createdAt
    };
    const serializedRequest = JSON.parse(JSON.stringify(request)) as Record<string, unknown>;
    expect(Object.hasOwn(serializedRequest, "message")).toBe(false);
    expect(Object.hasOwn(serializedRequest, "privateIdentity")).toBe(false);

    const store = createMemoryBottleStorage();
    const env: BottleWorkerEnv = {
      __TEST_STORE__: store,
      __TEST_KEYRING__: {
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: [
          {
            schema: SCHEMAS.key,
            keyname,
            publicRecipient: identity.publicRecipient,
            fingerprint: recipientFingerprint,
            createdAt: "2026-07-07T00:00:00.000Z",
            status: "active"
          }
        ]
      }
    };
    const fetcher = workerFetcher(env);
    const dropped = await dropBottle(request, fetcher);
    const storedJson = JSON.stringify(store.entries());
    expect(storedJson).not.toContain("\"message\"");
    expect(storedJson).not.toContain("privateIdentity");

    await verifyPrivateIdentityMatchesKeyRecord({
      privateIdentity: identity.privateIdentity,
      keyname,
      expectedPublicRecipient: identity.publicRecipient,
      expectedFingerprint: recipientFingerprint
    });
    const listed = await listBottles(recipientFingerprint, fetcher);
    expect(listed.bottles.map((bottle) => bottle.bottleId)).toEqual([dropped.bottleId]);

    const opened = await decryptBottlePayloadForRecipient({
      ciphertext: listed.bottles[0]?.ciphertext ?? "",
      privateIdentity: identity.privateIdentity,
      expectedKeyname: keyname,
      expectedRecipientFingerprint: recipientFingerprint
    });
    expect(opened).toEqual(payload);
  });

  it("accepts registered metadata for opaque unrelated ciphertext that fails local decryption", async () => {
    const registeredIdentity = await generateIdentity();
    const unrelatedIdentity = await generateIdentity();
    const keyname = "daylight/chase";
    const recipientFingerprint = await fingerprintKeyRecordInput({
      keyname,
      publicRecipient: registeredIdentity.publicRecipient
    });
    const payload: PlainBottlePayload = {
      schema: SCHEMAS.payload,
      keyname,
      recipientFingerprint,
      message: "The server cannot inspect an age ciphertext recipient.",
      createdAt: "2026-07-07T00:00:00.000Z"
    };
    const ciphertext = await encryptBottlePayload({
      payload,
      publicRecipient: unrelatedIdentity.publicRecipient
    });
    const request: DropBottleRequest = {
      schema: SCHEMAS.drop,
      keyname,
      recipientFingerprint,
      ciphertext,
      createdAtClient: payload.createdAt
    };
    const env: BottleWorkerEnv = {
      __TEST_STORE__: createMemoryBottleStorage(),
      __TEST_KEYRING__: {
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: [
          {
            schema: SCHEMAS.key,
            keyname,
            publicRecipient: registeredIdentity.publicRecipient,
            fingerprint: recipientFingerprint,
            createdAt: "2026-07-07T00:00:00.000Z",
            status: "active"
          }
        ]
      }
    };
    const fetcher = workerFetcher(env);

    const dropped = await dropBottle(request, fetcher);
    const listed = await listBottles(recipientFingerprint, fetcher);
    expect(listed.bottles.map((bottle) => bottle.bottleId)).toEqual([dropped.bottleId]);
    await expect(
      decryptBottlePayloadForRecipient({
        ciphertext: listed.bottles[0]?.ciphertext ?? "",
        privateIdentity: registeredIdentity.privateIdentity,
        expectedKeyname: keyname,
        expectedRecipientFingerprint: recipientFingerprint
      })
    ).rejects.toThrow();
  });
});

function workerFetcher(env: BottleWorkerEnv): typeof fetch {
  return async (input, init) => {
    const inputUrl = input instanceof Request ? input.url : String(input);
    const url = new URL(inputUrl, "https://bottle.nosuchmachine.net");
    const request = input instanceof Request
      ? new Request(url, input)
      : new Request(url, init);
    return handleRequest(request, env, new Date("2026-07-07T12:00:00.000Z"));
  };
}
