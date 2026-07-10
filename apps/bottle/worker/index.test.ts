import { describe, expect, it } from "vitest";
import { sha256Hex } from "../src/crypto/fingerprint";
import { MAX_DROP_BODY_BYTES } from "../src/domain/validation";
import { SCHEMAS, type DropBottleRequest } from "../src/domain/types";
import {
  SECURITY_HEADERS,
  createMemoryBottleStorage,
  handleRequest,
  type BottleKVNamespace,
  type BottleWorkerEnv
} from "./index";

const recipientFingerprint = `sha256:${"a".repeat(64)}`;
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
      `bottle:${recipientFingerprint}:${now.getTime()}:${body.bottleId}`,
      `bottle-id:${body.bottleId}`
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

  it("reads every KV list page and validates stored records", async () => {
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
    expect(body.bottles).toHaveLength(2);
    expect(kv.listCalls).toBe(2);
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
    env,
    now
  );
}

function listBottles(env: BottleWorkerEnv, at: Date): Promise<Response> {
  return handleRequest(
    new Request(`https://bottle.nosuchmachine.net/api/bottles?recipientFingerprint=${recipientFingerprint}`),
    env,
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
  failPutCall: number | undefined;
  pageSize = Number.POSITIVE_INFINITY;
  listCalls = 0;

  async get(key: string): Promise<string | null> {
    return this.values.get(key) ?? null;
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
    this.values.delete(key);
  }

  async list(options: { prefix?: string; cursor?: string }): Promise<{
    keys: Array<{ name: string }>;
    list_complete: boolean;
    cursor?: string;
  }> {
    this.listCalls += 1;
    const keys = [...this.values.keys()]
      .filter((key) => key.startsWith(options.prefix ?? ""))
      .sort();
    const offset = options.cursor ? Number(options.cursor) : 0;
    const end = Math.min(offset + this.pageSize, keys.length);
    const page = keys.slice(offset, end).map((name) => ({ name }));
    if (end < keys.length) {
      return { keys: page, list_complete: false, cursor: String(end) };
    }
    return { keys: page, list_complete: true };
  }
}
