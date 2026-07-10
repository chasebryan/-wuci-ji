import { sha256Hex } from "../src/crypto/fingerprint";
import {
  SCHEMAS,
  type DaylightBottleEvidence,
  type DropBottleResponse,
  type ListBottlesResponse,
  type StoredBottle,
  type StoredBottlePublic
} from "../src/domain/types";
import {
  MAX_DROP_BODY_BYTES,
  assertBottleId,
  assertFingerprint,
  assertStoredBottle,
  parseDropBottleRequest,
  toStoredBottlePublic
} from "../src/domain/validation";

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const SERVER_ORIGIN = "bottle.nosuchmachine.net" as const;

export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff"
};

export type BottleWorkerEnv = {
  BOTTLES_KV?: BottleKVNamespace;
  __TEST_STORE__?: BottleStorage;
};

export type BottleKVNamespace = {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expiration?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: { prefix?: string; cursor?: string }): Promise<{
    keys: Array<{ name: string }>;
    list_complete: boolean;
    cursor?: string;
  }>;
};

export type BottleStorage = {
  put(stored: StoredBottle, storedAtEpochMs: number): Promise<void>;
  getByBottleId(bottleId: string): Promise<StoredBottle | null>;
  listByRecipientFingerprint(recipientFingerprint: string): Promise<StoredBottle[]>;
};

type WorkerModule = {
  fetch(request: Request, env: BottleWorkerEnv): Promise<Response>;
};

const worker: WorkerModule = {
  fetch: handleRequest
};

export default worker;

export async function handleRequest(
  request: Request,
  env: BottleWorkerEnv,
  now: Date = new Date()
): Promise<Response> {
  try {
    const url = new URL(request.url);

    if (url.pathname === "/api/bottles") {
      if (request.method === "POST") {
        return withSecurityHeaders(await handleDropBottle(request, env, now));
      }
      if (request.method === "GET") {
        return withSecurityHeaders(await handleListBottles(url, env, now));
      }
      return withSecurityHeaders(methodNotAllowed(["GET", "POST"]));
    }

    const evidenceMatch = url.pathname.match(/^\/api\/bottles\/([^/]+)\/evidence$/);
    if (evidenceMatch) {
      if (request.method !== "GET") {
        return withSecurityHeaders(methodNotAllowed(["GET"]));
      }
      return withSecurityHeaders(
        await handleEvidence(decodeBottleId(evidenceMatch[1] ?? ""), env, now)
      );
    }

    return withSecurityHeaders(json({ error: "Not found." }, 404));
  } catch (error) {
    if (error instanceof HttpError) {
      return withSecurityHeaders(json({ error: error.message }, error.status));
    }
    return withSecurityHeaders(json({ error: "Internal server error." }, 500));
  }
}

export function createMemoryBottleStorage(): BottleStorage & { entries(): StoredBottle[] } {
  const byId = new Map<string, StoredBottle>();
  const byRecipient = new Map<string, StoredBottle[]>();

  return {
    async put(stored: StoredBottle): Promise<void> {
      byId.set(stored.bottleId, stored);
      const existing = byRecipient.get(stored.recipientFingerprint) ?? [];
      existing.push(stored);
      byRecipient.set(stored.recipientFingerprint, existing);
    },
    async getByBottleId(bottleId: string): Promise<StoredBottle | null> {
      return byId.get(bottleId) ?? null;
    },
    async listByRecipientFingerprint(recipientFingerprint: string): Promise<StoredBottle[]> {
      return [...(byRecipient.get(recipientFingerprint) ?? [])];
    },
    entries(): StoredBottle[] {
      return [...byId.values()];
    }
  };
}

export function createKvBottleStorage(kv: BottleKVNamespace): BottleStorage {
  return {
    async put(stored: StoredBottle, storedAtEpochMs: number): Promise<void> {
      const value = JSON.stringify(stored);
      const recipientKey = bottleKey(stored.recipientFingerprint, storedAtEpochMs, stored.bottleId);
      const idKey = bottleIdKey(stored.bottleId);
      const expiration = Math.ceil(Date.parse(stored.expiresAt) / 1000);
      const options = { expiration };

      await kv.put(recipientKey, value, options);
      try {
        await kv.put(idKey, value, options);
      } catch (error) {
        await bestEffortDelete(kv, [recipientKey, idKey]);
        throw error;
      }
    },
    async getByBottleId(bottleId: string): Promise<StoredBottle | null> {
      const value = await kv.get(bottleIdKey(bottleId));
      if (!value) {
        return null;
      }

      const stored = await parseAndVerifyStoredBottle(value);
      if (stored.bottleId !== bottleId) {
        throw new Error("Stored bottle id does not match its lookup key.");
      }
      return stored;
    },
    async listByRecipientFingerprint(recipientFingerprint: string): Promise<StoredBottle[]> {
      const prefix = `bottle:${recipientFingerprint}:`;
      const bottles: StoredBottle[] = [];
      let cursor: string | undefined;

      do {
        const listResult = await kv.list(cursor ? { prefix, cursor } : { prefix });
        for (const key of listResult.keys) {
          const value = await kv.get(key.name);
          if (value) {
            const stored = await parseAndVerifyStoredBottle(value);
            const storedAtEpochMs = Date.parse(stored.storedAt);
            const expectedKey = bottleKey(
              stored.recipientFingerprint,
              storedAtEpochMs,
              stored.bottleId
            );
            if (stored.recipientFingerprint !== recipientFingerprint || key.name !== expectedKey) {
              throw new Error("Stored bottle metadata does not match its recipient index key.");
            }
            bottles.push(stored);
          }
        }
        cursor = listResult.cursor;
        if (listResult.list_complete) {
          break;
        }
      } while (cursor);

      return bottles;
    }
  };
}

async function handleDropBottle(request: Request, env: BottleWorkerEnv, now: Date): Promise<Response> {
  const body = await readJsonRequest(request);
  const drop = parseClientInput(() => parseDropBottleRequest(body));
  const storedAt = now.toISOString();
  const storedAtEpochMs = now.getTime();
  const expiresAt = new Date(storedAtEpochMs + THIRTY_DAYS_MS).toISOString();
  const bottleId = crypto.randomUUID();
  const ciphertextSha256 = await sha256Hex(drop.ciphertext);
  const evidence: DaylightBottleEvidence = {
    schema: SCHEMAS.evidence,
    event: "bottle.accepted",
    bottleId,
    keyname: drop.keyname,
    recipientFingerprint: drop.recipientFingerprint,
    ciphertextSha256,
    storedAt,
    expiresAt,
    serverOrigin: SERVER_ORIGIN,
    storagePolicy: "ciphertext-only",
    plaintextSeenByServer: false
  };
  const stored: StoredBottle = {
    schema: SCHEMAS.stored,
    bottleId,
    keyname: drop.keyname,
    recipientFingerprint: drop.recipientFingerprint,
    ciphertext: drop.ciphertext,
    ciphertextSha256,
    storedAt,
    expiresAt,
    evidence
  };

  await getStorage(env).put(stored, storedAtEpochMs);

  const response: DropBottleResponse = {
    schema: SCHEMAS.dropResponse,
    bottleId,
    storedAt,
    expiresAt,
    evidence
  };
  return json(response, 201);
}

async function handleListBottles(url: URL, env: BottleWorkerEnv, now: Date): Promise<Response> {
  const recipientFingerprint = parseClientInput(() =>
    assertFingerprint(url.searchParams.get("recipientFingerprint") ?? "")
  );
  const bottles = await getStorage(env).listByRecipientFingerprint(recipientFingerprint);
  const publicBottles: StoredBottlePublic[] = bottles
    .filter((bottle) => Date.parse(bottle.expiresAt) > now.getTime())
    .sort((left, right) => Date.parse(left.storedAt) - Date.parse(right.storedAt))
    .map(toStoredBottlePublic);
  const response: ListBottlesResponse = {
    schema: SCHEMAS.listResponse,
    bottles: publicBottles
  };
  return json(response);
}

async function handleEvidence(bottleId: string, env: BottleWorkerEnv, now: Date): Promise<Response> {
  if (bottleId.length === 0) {
    throw new HttpError(404, "Bottle not found.");
  }

  const bottle = await getStorage(env).getByBottleId(bottleId);
  if (!bottle) {
    throw new HttpError(404, "Bottle not found.");
  }
  if (Date.parse(bottle.expiresAt) <= now.getTime()) {
    throw new HttpError(404, "Bottle not found.");
  }

  return json(bottle.evidence);
}

function getStorage(env: BottleWorkerEnv): BottleStorage {
  if (env.__TEST_STORE__) {
    return env.__TEST_STORE__;
  }
  if (env.BOTTLES_KV) {
    return createKvBottleStorage(env.BOTTLES_KV);
  }
  throw new HttpError(500, "BOTTLES_KV binding is not configured.");
}

async function readJsonRequest(request: Request): Promise<unknown> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!isApplicationJsonContentType(contentType)) {
    throw new HttpError(415, "Expected application/json request.");
  }

  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const normalizedLength = contentLength.trim();
    if (!/^\d+$/.test(normalizedLength)) {
      throw new HttpError(400, "Invalid Content-Length header.");
    }
    const advertisedLength = Number(normalizedLength);
    if (!Number.isSafeInteger(advertisedLength) || advertisedLength > MAX_DROP_BODY_BYTES) {
      throw new HttpError(413, "Bottle request body is too large.");
    }
  }

  const text = await readRequestText(request);

  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "Malformed JSON request.");
  }
}

async function readRequestText(request: Request): Promise<string> {
  if (!request.body) {
    return "";
  }

  const reader = request.body.getReader();
  const bytes = new Uint8Array(MAX_DROP_BODY_BYTES);
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      const chunkStart = totalBytes;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_DROP_BODY_BYTES) {
        try {
          await reader.cancel("Bottle request body is too large.");
        } catch {
          // The size rejection remains authoritative even if cancellation fails.
        }
        throw new HttpError(413, "Bottle request body is too large.");
      }
      bytes.set(value, chunkStart);
    }
    try {
      return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
        bytes.subarray(0, totalBytes)
      );
    } catch {
      throw new HttpError(400, "Bottle request body must be valid UTF-8 JSON.");
    }
  } finally {
    reader.releaseLock();
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function withSecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(name, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function methodNotAllowed(allowedMethods: string[]): Response {
  const response = json({ error: "Method not allowed." }, 405);
  response.headers.set("Allow", allowedMethods.join(", "));
  return response;
}

function decodeBottleId(value: string): string {
  try {
    return assertBottleId(decodeURIComponent(value));
  } catch {
    throw new HttpError(404, "Bottle not found.");
  }
}

function isApplicationJsonContentType(value: string): boolean {
  const [mediaType] = value.split(";", 1);
  return mediaType?.trim().toLowerCase() === "application/json";
}

async function parseAndVerifyStoredBottle(value: string): Promise<StoredBottle> {
  const stored = assertStoredBottle(JSON.parse(value));
  const ciphertextSha256 = await sha256Hex(stored.ciphertext);
  if (ciphertextSha256 !== stored.ciphertextSha256) {
    throw new Error("Stored bottle ciphertext digest does not match its ciphertext.");
  }
  return stored;
}

async function bestEffortDelete(kv: BottleKVNamespace, keys: string[]): Promise<void> {
  await Promise.all(
    keys.map(async (key) => {
      try {
        await kv.delete(key);
      } catch {
        // Preserve the original write failure; rollback is best effort for KV.
      }
    })
  );
}

function bottleKey(recipientFingerprint: string, storedAtEpochMs: number, bottleId: string): string {
  return `bottle:${recipientFingerprint}:${storedAtEpochMs}:${bottleId}`;
}

function bottleIdKey(bottleId: string): string {
  return `bottle-id:${bottleId}`;
}

function parseClientInput<T>(parser: () => T): T {
  try {
    return parser();
  } catch (error) {
    throw new HttpError(400, error instanceof Error ? error.message : "Invalid request.");
  }
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}
