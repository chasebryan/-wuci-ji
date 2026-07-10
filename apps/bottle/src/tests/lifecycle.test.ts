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
import { createMemoryBottleStorage, handleRequest, type BottleWorkerEnv } from "../../worker/index";

describe("complete ciphertext-only bottle lifecycle", () => {
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
    const env: BottleWorkerEnv = { __TEST_STORE__: store };
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
