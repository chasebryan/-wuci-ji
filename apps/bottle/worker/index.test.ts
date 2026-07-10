import { describe, expect, it } from "vitest";
import { fingerprintKeyRecordInput, sha256Hex } from "../src/crypto/fingerprint";
import { MAX_DROP_BODY_BYTES } from "../src/domain/validation";
import {
  SCHEMAS,
  type DropBottleRequest,
  type Keyring,
  type StoredBottle
} from "../src/domain/types";
import {
  BOTTLE_LIST_CURSOR_HEADER,
  BOTTLE_LIST_PAGE_SIZE,
  BOTTLE_LIST_RESPONSE_MAX_BYTES,
  BOTTLE_RECIPIENT_CAPACITY,
  SECURITY_HEADERS,
  createMemoryBottleStorage,
  handleRequest,
  type BottleKVNamespace,
  type BottleRateLimiter,
  type BottleWorkerEnv
} from "./index";

const recipientPublic = `age1${"q".repeat(58)}`;
const recipientFingerprint = await fingerprintKeyRecordInput({
  keyname: "daylight/chase",
  publicRecipient: recipientPublic
});
const bulkCiphertext = "bounded-bulk-ciphertext";
const bulkCiphertextSha256 = await sha256Hex(bulkCiphertext);
const now = new Date("2026-07-07T12:00:00.000Z");
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const textEncoder = new TextEncoder();

describe("bottle worker API", () => {
  it("rejects plaintext fields in bottle requests", async () => {
    const response = await postBottle(
      {
        ...validDropRequest(),
        message: "plaintext must not be accepted"
      },
      testEnv()
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: expect.stringContaining("message") });
    expectSecurityHeaders(response);
  });

  it("accepts application/json case-insensitively with parameters", async () => {
    const response = await postRaw(JSON.stringify(validDropRequest()), testEnv(), {
      "Content-Type": "Application/JSON; charset=utf-8"
    });

    expect(response.status).toBe(201);
    expectSecurityHeaders(response);
  });

  it.each([undefined, "text/plain", "text/application/json", "application/jsonp"])(
    "rejects non-JSON content type %s",
    async (contentType) => {
      const headers: Record<string, string> = {};
      if (contentType) {
        headers["Content-Type"] = contentType;
      }
      const response = await postRaw(JSON.stringify(validDropRequest()), testEnv(), headers);

      expect(response.status).toBe(415);
      expectSecurityHeaders(response);
    }
  );

  it("rejects an advertised oversized request before parsing", async () => {
    const response = await postRaw(JSON.stringify(validDropRequest()), testEnv(), {
      "Content-Type": "application/json",
      "Content-Length": String(MAX_DROP_BODY_BYTES + 1)
    });

    expect(response.status).toBe(413);
    expectSecurityHeaders(response);
  });

  it("accepts a request at the exact byte limit", async () => {
    const body = exactSizeDropBody(MAX_DROP_BODY_BYTES);
    expect(textEncoder.encode(body)).toHaveLength(MAX_DROP_BODY_BYTES);

    const response = await postRaw(body, testEnv());

    expect(response.status).toBe(201);
    expectSecurityHeaders(response);
  });

  it("cancels a streamed request as soon as it exceeds the byte limit", async () => {
    let pullCount = 0;
    let canceled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pullCount += 1;
        if (pullCount === 1) {
          controller.enqueue(new Uint8Array(MAX_DROP_BODY_BYTES));
        } else if (pullCount === 2) {
          controller.enqueue(new Uint8Array(1));
        } else {
          controller.close();
        }
      },
      cancel() {
        canceled = true;
      }
    });

    const response = await postRaw(body, testEnv());

    expect(response.status).toBe(413);
    expect(canceled).toBe(true);
    expectSecurityHeaders(response);
  });

  it("rejects malformed JSON", async () => {
    const response = await postRaw("{not json", testEnv());

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: "Malformed JSON request." });
    expectSecurityHeaders(response);
  });

  it("returns a controlled 400 for pathologically deep JSON", async () => {
    let nested: unknown = "ciphertext";
    for (let depth = 0; depth < 40; depth += 1) {
      nested = { wrapper: nested };
    }

    const response = await postRaw(JSON.stringify(nested), testEnv());

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "Drop request structure exceeds the validation complexity limit."
    });
    expectSecurityHeaders(response);
  });

  it("rejects invalid UTF-8 instead of replacing bytes before JSON parsing", async () => {
    const response = await postRaw(new Uint8Array([0xff]), testEnv());

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "Bottle request body must be valid UTF-8 JSON."
    });
    expectSecurityHeaders(response);
  });

  it("stores ciphertext and metadata only", async () => {
    const store = createMemoryBottleStorage();
    const response = await postBottle(validDropRequest(), { __TEST_STORE__: store });

    expect(response.status).toBe(201);
    const stored = store.entries()[0];
    expect(stored).toBeDefined();
    expect(stored?.ciphertext).toBe("armored-ciphertext-only");
    expect(JSON.stringify(stored)).not.toContain("server must not receive this");
    expect(Object.keys(stored ?? {})).not.toContain("message");
    expect(Object.keys(stored ?? {})).not.toContain("privateIdentity");
    expectSecurityHeaders(response);
  });

  it("rejects an unregistered recipient before performing any storage write", async () => {
    const store = createMemoryBottleStorage();
    let rateLimitCalls = 0;
    const response = await postBottle(validDropRequest(), {
      __TEST_STORE__: store,
      DROP_RATE_LIMITER: {
        async limit() {
          rateLimitCalls += 1;
          return { success: true };
        }
      },
      __TEST_KEYRING__: {
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: []
      }
    });

    expect(response.status).toBe(403);
    expect(store.entries()).toHaveLength(0);
    expect(rateLimitCalls).toBe(0);
    await expect(response.json()).resolves.toEqual({
      error: "Recipient is not registered as an active public key."
    });
    expectSecurityHeaders(response);
  });

  it("rejects a revoked recipient before performing any storage write", async () => {
    const store = createMemoryBottleStorage();
    const revokedKeyring = registeredKeyring();
    const key = revokedKeyring.keys[0];
    if (!key) {
      throw new Error("Missing registered key fixture.");
    }
    key.status = "revoked";

    const response = await postBottle(validDropRequest(), {
      __TEST_STORE__: store,
      __TEST_KEYRING__: revokedKeyring
    });

    expect(response.status).toBe(403);
    expect(store.entries()).toHaveLength(0);
    expectSecurityHeaders(response);
  });

  it("fails closed when a registered fingerprint does not bind its public recipient", async () => {
    const store = createMemoryBottleStorage();
    const invalidKeyring = registeredKeyring();
    const key = invalidKeyring.keys[0];
    if (!key) {
      throw new Error("Missing registered key fixture.");
    }
    key.publicRecipient = `age1${"r".repeat(58)}`;

    const response = await postBottle(validDropRequest(), {
      __TEST_STORE__: store,
      __TEST_KEYRING__: invalidKeyring
    });

    expect(response.status).toBe(503);
    expect(store.entries()).toHaveLength(0);
    await expect(response.json()).resolves.toEqual({
      error: "The published recipient key record is invalid."
    });
    expectSecurityHeaders(response);
  });

  it("rate-limits repeated drops before hashing or storage", async () => {
    const store = createMemoryBottleStorage();
    const rateKeys: string[] = [];
    let calls = 0;
    const limiter: BottleRateLimiter = {
      async limit({ key }) {
        rateKeys.push(key);
        calls += 1;
        return { success: calls === 1 };
      }
    };
    const env = { __TEST_STORE__: store, DROP_RATE_LIMITER: limiter };
    const headers = {
      "Content-Type": "application/json",
      "CF-Connecting-IP": "203.0.113.42"
    };

    const accepted = await postRaw(JSON.stringify(validDropRequest()), env, headers);
    const limited = await postRaw(JSON.stringify(validDropRequest()), env, headers);

    expect(accepted.status).toBe(201);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("60");
    await expect(limited.json()).resolves.toEqual({
      error: "Too many bottle drops for this network and recipient. Try again in one minute."
    });
    expect(store.entries()).toHaveLength(1);
    expect(rateKeys).toHaveLength(2);
    expect(rateKeys[0]).toBe(rateKeys[1]);
    expect(rateKeys[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(rateKeys[0]).not.toContain("203.0.113.42");
    expect(rateKeys[0]).not.toContain(recipientFingerprint);
    expectSecurityHeaders(limited);
  });

  it("fails closed when production storage has no drop limiter binding", async () => {
    const kv = new FakeBottleKv();
    const request = new Request("https://bottle.nosuchmachine.net/api/bottles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(validDropRequest())
    });

    const response = await handleRequest(
      request,
      { BOTTLES_KV: kv, __TEST_KEYRING__: registeredKeyring() },
      now
    );

    expect(response.status).toBe(503);
    expect(kv.putCalls).toHaveLength(0);
    await expect(response.json()).resolves.toEqual({
      error: "Bottle drop protection is unavailable."
    });
    expectSecurityHeaders(response);
  });

  it("rate-limits repeated bounded reads without exposing the network address in the key", async () => {
    const store = createMemoryBottleStorage();
    await postBottle(validDropRequest(), { __TEST_STORE__: store });
    const rateKeys: string[] = [];
    let calls = 0;
    const limiter: BottleRateLimiter = {
      async limit({ key }) {
        rateKeys.push(key);
        calls += 1;
        return { success: calls === 1 };
      }
    };
    const env = { __TEST_STORE__: store, READ_RATE_LIMITER: limiter };

    const accepted = await listBottles(env, now, undefined, "203.0.113.84");
    const limited = await listBottles(env, now, undefined, "203.0.113.84");

    expect(accepted.status).toBe(200);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBe("60");
    expect(rateKeys[0]).toBe(rateKeys[1]);
    expect(rateKeys[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(rateKeys[0]).not.toContain("203.0.113.84");
    await expect(limited.json()).resolves.toEqual({
      error: "Too many bottle lookups for this network and recipient. Try again in one minute."
    });
    expectSecurityHeaders(limited);
  });

  it("fails closed when production storage has no read limiter binding", async () => {
    const kv = new FakeBottleKv();
    const response = await handleRequest(
      new Request(
        `https://bottle.nosuchmachine.net/api/bottles?recipientFingerprint=${recipientFingerprint}`
      ),
      { BOTTLES_KV: kv },
      now
    );

    expect(response.status).toBe(503);
    expect(kv.listCalls).toBe(0);
    await expect(response.json()).resolves.toEqual({
      error: "Bottle read protection is unavailable."
    });
    expectSecurityHeaders(response);
  });

  it("returns only unexpired candidate ciphertexts by recipient fingerprint", async () => {
    const store = createMemoryBottleStorage();
    await postBottle(validDropRequest(), { __TEST_STORE__: store });

    const beforeExpiry = await listBottles({ __TEST_STORE__: store }, now);
    const beforeExpiryBody = await beforeExpiry.json();
    expect(beforeExpiry.status).toBe(200);
    expect(beforeExpiryBody).toMatchObject({
      schema: SCHEMAS.listResponse,
      bottles: [
        {
          schema: SCHEMAS.publicBottle,
          keyname: "daylight/chase",
          recipientFingerprint,
          ciphertext: "armored-ciphertext-only"
        }
      ]
    });

    const atExpiry = await listBottles(
      { __TEST_STORE__: store },
      new Date(now.getTime() + THIRTY_DAYS_MS)
    );
    await expect(atExpiry.json()).resolves.toEqual({
      schema: SCHEMAS.listResponse,
      bottles: []
    });
    expectSecurityHeaders(beforeExpiry);
    expectSecurityHeaders(atExpiry);
  });

  it("returns evidence before expiry and rejects it at expiry", async () => {
    const store = createMemoryBottleStorage();
    const dropResponse = await postBottle(validDropRequest(), { __TEST_STORE__: store });
    const dropBody = await dropResponse.json();

    expect(dropBody.evidence).toMatchObject({
      schema: SCHEMAS.evidence,
      event: "bottle.accepted",
      bottleId: dropBody.bottleId,
      keyname: "daylight/chase",
      recipientFingerprint,
      ciphertextSha256: await sha256Hex("armored-ciphertext-only"),
      serverOrigin: "bottle.nosuchmachine.net",
      storagePolicy: "ciphertext-only",
      plaintextSeenByServer: false
    });

    const evidenceResponse = await getEvidence(dropBody.bottleId, { __TEST_STORE__: store }, now);
    await expect(evidenceResponse.json()).resolves.toEqual(dropBody.evidence);
    expect(evidenceResponse.status).toBe(200);

    const expiredResponse = await getEvidence(
      dropBody.bottleId,
      { __TEST_STORE__: store },
      new Date(now.getTime() + THIRTY_DAYS_MS)
    );
    expect(expiredResponse.status).toBe(404);
    await expect(expiredResponse.json()).resolves.toEqual({ error: "Bottle not found." });
    expectSecurityHeaders(evidenceResponse);
    expectSecurityHeaders(expiredResponse);
  });

  it("returns 405 with Allow and security headers for known routes", async () => {
    const collectionResponse = await handleRequest(
      new Request("https://bottle.nosuchmachine.net/api/bottles", { method: "PUT" }),
      testEnv(),
      now
    );
    const evidenceResponse = await handleRequest(
      new Request("https://bottle.nosuchmachine.net/api/bottles/bottle123/evidence", {
        method: "POST"
      }),
      testEnv(),
      now
    );

    expect(collectionResponse.status).toBe(405);
    expect(collectionResponse.headers.get("Allow")).toBe("GET, POST");
    expect(evidenceResponse.status).toBe(405);
    expect(evidenceResponse.headers.get("Allow")).toBe("GET");
    expectSecurityHeaders(collectionResponse);
    expectSecurityHeaders(evidenceResponse);
  });

  it.each([
    `recipientFingerprint=${recipientFingerprint}&recipientFingerprint=${recipientFingerprint}`,
    `recipientFingerprint=${recipientFingerprint}&cursor=first&cursor=second`,
    `recipientFingerprint=${recipientFingerprint}&unexpected=value`
  ])("rejects ambiguous or unknown list query parameters: %s", async (query) => {
    let limiterCalls = 0;
    const response = await handleRequest(
      new Request(`https://bottle.nosuchmachine.net/api/bottles?${query}`),
      {
        __TEST_STORE__: createMemoryBottleStorage(),
        READ_RATE_LIMITER: {
          async limit() {
            limiterCalls += 1;
            return { success: true };
          }
        }
      },
      now
    );

    expect(response.status).toBe(400);
    expect(limiterCalls).toBe(0);
    expectSecurityHeaders(response);
  });
});

describe("Cloudflare KV bottle storage", () => {
  it("writes both required keys with the same absolute expiration", async () => {
    const kv = new FakeBottleKv();
    const response = await postBottle(validDropRequest(), { BOTTLES_KV: kv });
    const body = await response.json();
    const expectedExpiration = Math.ceil((now.getTime() + THIRTY_DAYS_MS) / 1000);

    expect(response.status).toBe(201);
    expect(kv.putCalls).toHaveLength(2);
    expect(kv.putCalls.map((call) => call.key)).toEqual([
      `bottle-id:${body.bottleId}`,
      `bottle:${recipientFingerprint}:${now.getTime()}:${body.bottleId}`
    ]);
    for (const call of kv.putCalls) {
      expect(call.options).toEqual({ expiration: expectedExpiration });
      expect(JSON.parse(call.value)).toMatchObject({
        schema: SCHEMAS.stored,
        bottleId: body.bottleId,
        ciphertext: "armored-ciphertext-only",
        expiresAt: new Date(now.getTime() + THIRTY_DAYS_MS).toISOString()
      });
    }
  });

  it("best-effort deletes both keys when the second write fails", async () => {
    const kv = new FakeBottleKv();
    kv.failPutCall = 2;

    const response = await postBottle(validDropRequest(), { BOTTLES_KV: kv });

    expect(response.status).toBe(500);
    expect(kv.deleteCalls).toHaveLength(2);
    expect(kv.values.size).toBe(0);
    expectSecurityHeaders(response);
  });

  it("keeps a failed second write out of the recipient index even if rollback fails", async () => {
    const kv = new FakeBottleKv();
    kv.failPutCall = 2;
    kv.failDeletes = true;

    const response = await postBottle(validDropRequest(), { BOTTLES_KV: kv });
    const listed = await listBottles({ BOTTLES_KV: kv }, now);
    const listedBody = await listed.json();

    expect(response.status).toBe(500);
    expect(kv.deleteCalls).toHaveLength(2);
    expect([...kv.values.keys()].filter((key) => key.startsWith("bottle:"))).toEqual([]);
    expect([...kv.values.keys()].filter((key) => key.startsWith("bottle-id:"))).toHaveLength(1);
    expect(listedBody).toEqual({ schema: SCHEMAS.listResponse, bottles: [] });
    expectSecurityHeaders(response);
    expectSecurityHeaders(listed);
  });

  it("refuses new writes when the recipient admission ceiling is reached", async () => {
    const kv = new FakeBottleKv();
    for (let index = 0; index < BOTTLE_RECIPIENT_CAPACITY; index += 1) {
      kv.values.set(
        `bottle:${recipientFingerprint}:${String(index).padStart(13, "0")}:capacity-${index}`,
        "capacity-marker"
      );
    }

    const response = await postBottle(validDropRequest(), { BOTTLES_KV: kv });

    expect(response.status).toBe(409);
    expect(kv.putCalls).toHaveLength(0);
    expect(kv.listOptions.at(-1)?.limit).toBe(BOTTLE_RECIPIENT_CAPACITY);
    await expect(response.json()).resolves.toEqual({
      error: "This recipient inbox has reached its 30-day bottle capacity. Try again after older bottles expire."
    });
    expectSecurityHeaders(response);
  });

  it("bounds each KV list request and returns an opaque continuation cursor", async () => {
    const kv = new FakeBottleKv();
    kv.pageSize = 1;
    await postBottle(validDropRequest(), { BOTTLES_KV: kv });
    await postBottle(
      { ...validDropRequest(), ciphertext: "second-armored-ciphertext" },
      { BOTTLES_KV: kv }
    );

    const response = await listBottles({ BOTTLES_KV: kv }, now);
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.bottles).toHaveLength(1);
    expect(body).not.toHaveProperty("nextCursor");
    expect(response.headers.get(BOTTLE_LIST_CURSOR_HEADER)).toBe("1");
    expect(kv.listOptions.filter((options) => options.limit === BOTTLE_LIST_PAGE_SIZE)).toHaveLength(1);

    const nextResponse = await listBottles(
      { BOTTLES_KV: kv },
      now,
      response.headers.get(BOTTLE_LIST_CURSOR_HEADER) ?? undefined
    );
    const nextBody = await nextResponse.json();
    expect(nextBody.bottles).toHaveLength(1);
    expect(nextBody).not.toHaveProperty("nextCursor");
    expect(nextResponse.headers.get(BOTTLE_LIST_CURSOR_HEADER)).toBeNull();
    expect(kv.listOptions.filter((options) => options.limit === BOTTLE_LIST_PAGE_SIZE)).toHaveLength(2);
  });

  it("keeps a thousand-entry legacy backlog to one bounded read page and byte budget", async () => {
    const kv = new FakeBottleKv();
    for (let index = 0; index < 1_200; index += 1) {
      const stored = storedBottleFixture(index);
      kv.values.set(
        `bottle:${recipientFingerprint}:${Date.parse(stored.storedAt)}:${stored.bottleId}`,
        JSON.stringify(stored)
      );
    }

    const response = await listBottles({ BOTTLES_KV: kv }, now);
    const responseText = await response.text();
    const body = JSON.parse(responseText);

    expect(response.status).toBe(200);
    expect(body.bottles).toHaveLength(BOTTLE_LIST_PAGE_SIZE);
    expect(response.headers.get(BOTTLE_LIST_CURSOR_HEADER)).not.toBeNull();
    expect(kv.getCalls).toBe(1);
    expect(kv.bulkGetKeyCounts).toEqual([BOTTLE_LIST_PAGE_SIZE]);
    expect(kv.listOptions.filter((options) => options.limit === BOTTLE_LIST_PAGE_SIZE)).toHaveLength(1);
    expect(textEncoder.encode(responseText).byteLength).toBeLessThanOrEqual(
      BOTTLE_LIST_RESPONSE_MAX_BYTES
    );
  });

  it("rejects persisted ciphertext whose digest no longer matches", async () => {
    const kv = new FakeBottleKv();
    const dropResponse = await postBottle(validDropRequest(), { BOTTLES_KV: kv });
    const dropBody = await dropResponse.json();
    const idKey = `bottle-id:${dropBody.bottleId}`;
    const stored = JSON.parse(kv.values.get(idKey) ?? "null");
    stored.ciphertext = `${stored.ciphertext}-changed`;
    kv.values.set(idKey, JSON.stringify(stored));

    const response = await getEvidence(dropBody.bottleId, { BOTTLES_KV: kv }, now);

    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({ error: "Internal server error." });
    expectSecurityHeaders(response);
  });

  it("rejects persisted evidence that disagrees with stored metadata", async () => {
    const kv = new FakeBottleKv();
    const dropResponse = await postBottle(validDropRequest(), { BOTTLES_KV: kv });
    const dropBody = await dropResponse.json();
    const idKey = `bottle-id:${dropBody.bottleId}`;
    const stored = JSON.parse(kv.values.get(idKey) ?? "null");
    stored.evidence.keyname = "aperture.alice";
    kv.values.set(idKey, JSON.stringify(stored));

    const response = await getEvidence(dropBody.bottleId, { BOTTLES_KV: kv }, now);

    expect(response.status).toBe(500);
    expectSecurityHeaders(response);
  });
});

function testEnv(): BottleWorkerEnv {
  return { __TEST_STORE__: createMemoryBottleStorage() };
}

function validDropRequest(): DropBottleRequest {
  return {
    schema: SCHEMAS.drop,
    keyname: "daylight/chase",
    recipientFingerprint,
    ciphertext: "armored-ciphertext-only",
    createdAtClient: "2026-07-07T00:00:00.000Z"
  };
}

function exactSizeDropBody(size: number): string {
  const emptyCiphertextBody = JSON.stringify({ ...validDropRequest(), ciphertext: "" });
  const fixedBytes = textEncoder.encode(emptyCiphertextBody).byteLength;
  return JSON.stringify({
    ...validDropRequest(),
    ciphertext: "x".repeat(size - fixedBytes)
  });
}

function postBottle(
  body: DropBottleRequest | (DropBottleRequest & Record<string, unknown>),
  env: BottleWorkerEnv
): Promise<Response> {
  return postRaw(JSON.stringify(body), env);
}

function postRaw(
  body: BodyInit,
  env: BottleWorkerEnv,
  headers: HeadersInit = { "Content-Type": "application/json" }
): Promise<Response> {
  const init: RequestInit & { duplex?: "half" } = {
    method: "POST",
    headers,
    body
  };
  if (body instanceof ReadableStream) {
    init.duplex = "half";
  }
  return handleRequest(
    new Request("https://bottle.nosuchmachine.net/api/bottles", init),
    withRegisteredRecipient(env),
    now
  );
}

function withRegisteredRecipient(env: BottleWorkerEnv): BottleWorkerEnv {
  return {
    __TEST_KEYRING__: registeredKeyring(),
    DROP_RATE_LIMITER: allowRateLimiter,
    ...env
  };
}

const allowRateLimiter: BottleRateLimiter = {
  async limit() {
    return { success: true };
  }
};

function registeredKeyring(): Keyring {
  return {
    schema: SCHEMAS.keyring,
    updatedAt: "2026-07-07T00:00:00.000Z",
    keys: [
      {
        schema: SCHEMAS.key,
        keyname: "daylight/chase",
        publicRecipient: recipientPublic,
        fingerprint: recipientFingerprint,
        createdAt: "2026-07-07T00:00:00.000Z",
        status: "active"
      }
    ]
  };
}

function storedBottleFixture(index: number): StoredBottle {
  const storedAtDate = new Date(now.getTime() + index);
  const storedAt = storedAtDate.toISOString();
  const expiresAt = new Date(storedAtDate.getTime() + THIRTY_DAYS_MS).toISOString();
  const bottleId = `bottle_${String(index).padStart(8, "0")}`;
  return {
    schema: SCHEMAS.stored,
    bottleId,
    keyname: "daylight/chase",
    recipientFingerprint,
    ciphertext: bulkCiphertext,
    ciphertextSha256: bulkCiphertextSha256,
    storedAt,
    expiresAt,
    evidence: {
      schema: SCHEMAS.evidence,
      event: "bottle.accepted",
      bottleId,
      keyname: "daylight/chase",
      recipientFingerprint,
      ciphertextSha256: bulkCiphertextSha256,
      storedAt,
      expiresAt,
      serverOrigin: "bottle.nosuchmachine.net",
      storagePolicy: "ciphertext-only",
      plaintextSeenByServer: false
    }
  };
}

function listBottles(
  env: BottleWorkerEnv,
  at: Date,
  cursor?: string,
  clientAddress?: string
): Promise<Response> {
  const cursorQuery = cursor === undefined ? "" : `&cursor=${encodeURIComponent(cursor)}`;
  const init: RequestInit =
    clientAddress === undefined ? {} : { headers: { "CF-Connecting-IP": clientAddress } };
  return handleRequest(
    new Request(
      `https://bottle.nosuchmachine.net/api/bottles?recipientFingerprint=${recipientFingerprint}${cursorQuery}`,
      init
    ),
    { READ_RATE_LIMITER: allowRateLimiter, ...env },
    at
  );
}

function getEvidence(bottleId: string, env: BottleWorkerEnv, at: Date): Promise<Response> {
  return handleRequest(
    new Request(`https://bottle.nosuchmachine.net/api/bottles/${bottleId}/evidence`),
    env,
    at
  );
}

function expectSecurityHeaders(response: Response): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    expect(response.headers.get(name), name).toBe(value);
  }
}

class FakeBottleKv implements BottleKVNamespace {
  readonly values = new Map<string, string>();
  readonly putCalls: Array<{
    key: string;
    value: string;
    options: { expiration?: number } | undefined;
  }> = [];
  readonly deleteCalls: string[] = [];
  getCalls = 0;
  readonly bulkGetKeyCounts: number[] = [];
  failPutCall: number | undefined;
  failDeletes = false;
  pageSize = Number.POSITIVE_INFINITY;
  listCalls = 0;
  readonly listOptions: Array<{ prefix?: string; cursor?: string; limit?: number }> = [];

  async get(key: string): Promise<string | null>;
  async get(keys: string[]): Promise<Map<string, string | null>>;
  async get(keyOrKeys: string | string[]): Promise<string | null | Map<string, string | null>> {
    this.getCalls += 1;
    if (Array.isArray(keyOrKeys)) {
      this.bulkGetKeyCounts.push(keyOrKeys.length);
      return new Map(keyOrKeys.map((key) => [key, this.values.get(key) ?? null]));
    }
    return this.values.get(keyOrKeys) ?? null;
  }

  async put(key: string, value: string, options?: { expiration?: number }): Promise<void> {
    this.putCalls.push({ key, value, options: options ? { ...options } : undefined });
    if (this.putCalls.length === this.failPutCall) {
      throw new Error("Injected KV put failure.");
    }
    this.values.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.deleteCalls.push(key);
    if (this.failDeletes) {
      throw new Error("Injected KV delete failure.");
    }
    this.values.delete(key);
  }

  async list(options: { prefix?: string; cursor?: string; limit?: number }): Promise<{
    keys: Array<{ name: string }>;
    list_complete: boolean;
    cursor?: string;
  }> {
    this.listCalls += 1;
    this.listOptions.push({ ...options });
    const keys = [...this.values.keys()]
      .filter((key) => key.startsWith(options.prefix ?? ""))
      .sort();
    const offset = options.cursor ? Number(options.cursor) : 0;
    const end = Math.min(offset + this.pageSize, offset + (options.limit ?? keys.length), keys.length);
    const page = keys.slice(offset, end).map((name) => ({ name }));
    if (end < keys.length) {
      return { keys: page, list_complete: false, cursor: String(end) };
    }
    return { keys: page, list_complete: true };
  }
}
