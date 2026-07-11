import { fingerprintKeyRecordInput, sha256Hex } from "../src/crypto/fingerprint";
import publishedKeyringJson from "../public/keyring.json";
import {
  SCHEMAS,
  type BottleDeploymentEvidence,
  type DaylightBottleEvidence,
  type DropBottleResponse,
  type DropBottleRequest,
  type Keyring,
  type ListBottlesResponse,
  type StoredBottle,
  type StoredBottlePublic
} from "../src/domain/types";
import {
  MAX_DROP_BODY_BYTES,
  assertBottleId,
  assertFingerprint,
  assertListCursor,
  assertStoredBottle,
  parseKeyring,
  parseDropBottleRequest,
  toStoredBottlePublic,
  utf8ByteLength
} from "../src/domain/validation";

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
export const BOTTLE_LIST_PAGE_SIZE = 8;
export const BOTTLE_RECIPIENT_CAPACITY = 500;
export const BOTTLE_LIST_RESPONSE_MAX_BYTES =
  BOTTLE_LIST_PAGE_SIZE * MAX_DROP_BODY_BYTES + 64 * 1024;
export const BOTTLE_LIST_CURSOR_HEADER = "X-Daylight-Next-Cursor";
const SERVER_ORIGIN = "bottle.nosuchmachine.net" as const;
const WORKER_VERSION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const WORKER_VERSION_TAG_PATTERN = /^sha256-[0-9a-f]{64}$/;
const PUBLISHED_KEYRING = parseKeyring(publishedKeyringJson);

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
  CF_VERSION_METADATA?: BottleWorkerVersionMetadata;
  DROP_RATE_LIMITER?: BottleRateLimiter;
  READ_RATE_LIMITER?: BottleRateLimiter;
  __TEST_STORE__?: BottleStorage;
  __TEST_KEYRING__?: Keyring;
};

export type BottleWorkerVersionMetadata = {
  id: string;
  tag: string;
  timestamp: string;
};

export type BottleRateLimiter = {
  limit(options: { key: string }): Promise<{ success: boolean }>;
};

export type BottleKVNamespace = {
  get(key: string): Promise<string | null>;
  get(keys: string[]): Promise<Map<string, string | null>>;
  put(key: string, value: string, options?: { expiration?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(options: { prefix?: string; cursor?: string; limit?: number }): Promise<{
    keys: Array<{ name: string }>;
    list_complete: boolean;
    cursor?: string;
  }>;
};

export type BottleStorage = {
  put(stored: StoredBottle, storedAtEpochMs: number): Promise<void>;
  getByBottleId(bottleId: string): Promise<StoredBottle | null>;
  hasRecipientCapacity(recipientFingerprint: string): Promise<boolean>;
  listByRecipientFingerprint(
    recipientFingerprint: string,
    cursor?: string
  ): Promise<{ bottles: StoredBottle[]; nextCursor?: string }>;
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

    if (url.pathname === "/api/deployment") {
      if (request.method !== "GET") {
        return withSecurityHeaders(methodNotAllowed(["GET"]));
      }
      if (url.search !== "") {
        throw new HttpError(400, "Deployment evidence does not accept query parameters.");
      }
      return withSecurityHeaders(handleDeploymentEvidence(env));
    }

    if (url.pathname === "/api/bottles") {
      if (request.method === "POST") {
        return withSecurityHeaders(await handleDropBottle(request, env, now));
      }
      if (request.method === "GET") {
        return withSecurityHeaders(await handleListBottles(request, url, env, now));
      }
      return withSecurityHeaders(methodNotAllowed(["GET", "POST"]));
    }

    const evidenceMatch = url.pathname.match(/^\/api\/bottles\/([^/]+)\/evidence$/);
    if (evidenceMatch) {
      if (request.method !== "GET") {
        return withSecurityHeaders(methodNotAllowed(["GET"]));
      }
      await enforceReadRateLimit(request, env);
      return withSecurityHeaders(
        await handleEvidence(decodeBottleId(evidenceMatch[1] ?? ""), env, now)
      );
    }

    return withSecurityHeaders(json({ error: "Not found." }, 404));
  } catch (error) {
    if (error instanceof HttpError) {
      const response = json({ error: error.message }, error.status);
      for (const [name, value] of Object.entries(error.headers)) {
        response.headers.set(name, value);
      }
      return withSecurityHeaders(response);
    }
    return withSecurityHeaders(json({ error: "Internal server error." }, 500));
  }
}

function handleDeploymentEvidence(env: BottleWorkerEnv): Response {
  const metadata = env.CF_VERSION_METADATA;
  if (
    !metadata
    || !WORKER_VERSION_ID_PATTERN.test(metadata.id)
    || !WORKER_VERSION_TAG_PATTERN.test(metadata.tag)
  ) {
    throw new HttpError(503, "Worker deployment evidence is unavailable.");
  }
  const created = new Date(metadata.timestamp);
  if (Number.isNaN(created.getTime())) {
    throw new HttpError(503, "Worker deployment evidence is unavailable.");
  }
  const evidence: BottleDeploymentEvidence = {
    schema: SCHEMAS.deployment,
    workerVersionId: metadata.id.toLowerCase(),
    workerVersionTag: metadata.tag,
    versionCreatedAt: created.toISOString()
  };
  return json(evidence);
}

export function createMemoryBottleStorage(
  pageSize = BOTTLE_LIST_PAGE_SIZE
): BottleStorage & { entries(): StoredBottle[] } {
  const byId = new Map<string, StoredBottle>();
  const byRecipient = new Map<string, StoredBottle[]>();

  return {
    async put(stored: StoredBottle): Promise<void> {
      const existing = byRecipient.get(stored.recipientFingerprint) ?? [];
      if (existing.length >= BOTTLE_RECIPIENT_CAPACITY) {
        throw new Error("Recipient bottle capacity was reached before storage.");
      }
      byId.set(stored.bottleId, stored);
      existing.push(stored);
      byRecipient.set(stored.recipientFingerprint, existing);
    },
    async getByBottleId(bottleId: string): Promise<StoredBottle | null> {
      return byId.get(bottleId) ?? null;
    },
    async hasRecipientCapacity(recipientFingerprint: string): Promise<boolean> {
      return (byRecipient.get(recipientFingerprint)?.length ?? 0) < BOTTLE_RECIPIENT_CAPACITY;
    },
    async listByRecipientFingerprint(
      recipientFingerprint: string,
      cursor?: string
    ): Promise<{ bottles: StoredBottle[]; nextCursor?: string }> {
      const offset = cursor === undefined ? 0 : Number(cursor);
      if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new Error("Memory bottle list cursor is invalid.");
      }
      const matching = byRecipient.get(recipientFingerprint) ?? [];
      const end = Math.min(offset + pageSize, matching.length);
      return {
        bottles: matching.slice(offset, end),
        ...(end < matching.length ? { nextCursor: String(end) } : {})
      };
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

      await kv.put(idKey, value, options);
      try {
        await kv.put(recipientKey, value, options);
      } catch (error) {
        await bestEffortDelete(kv, [idKey, recipientKey]);
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
    async hasRecipientCapacity(recipientFingerprint: string): Promise<boolean> {
      const result = await kv.list({
        prefix: `bottle:${recipientFingerprint}:`,
        limit: BOTTLE_RECIPIENT_CAPACITY
      });
      return result.list_complete && result.keys.length < BOTTLE_RECIPIENT_CAPACITY;
    },
    async listByRecipientFingerprint(
      recipientFingerprint: string,
      cursor?: string
    ): Promise<{ bottles: StoredBottle[]; nextCursor?: string }> {
      const prefix = `bottle:${recipientFingerprint}:`;
      const bottles: StoredBottle[] = [];
      const listResult = await kv.list({
        prefix,
        limit: BOTTLE_LIST_PAGE_SIZE,
        ...(cursor === undefined ? {} : { cursor })
      });
      const keyNames = listResult.keys.map((key) => key.name);
      const values =
        keyNames.length === 0
          ? new Map<string, string | null>()
          : await kv.get(keyNames);
      for (const key of listResult.keys) {
        const value = values.get(key.name) ?? null;
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
      if (!listResult.list_complete && !listResult.cursor) {
        throw new Error("KV bottle list page omitted its continuation cursor.");
      }

      return {
        bottles,
        ...(!listResult.list_complete && listResult.cursor
          ? { nextCursor: assertListCursor(listResult.cursor) }
          : {})
      };
    }
  };
}

async function handleDropBottle(request: Request, env: BottleWorkerEnv, now: Date): Promise<Response> {
  const body = await readJsonRequest(request);
  const drop = parseClientInput(() => parseDropBottleRequest(body));
  await assertActiveKeyringRecipient(drop, env);
  await enforceDropRateLimit(request, drop, env);
  const storage = getStorage(env);
  if (!(await storage.hasRecipientCapacity(drop.recipientFingerprint))) {
    throw new HttpError(
      409,
      "This recipient inbox has reached its 30-day bottle capacity. Try again after older bottles expire."
    );
  }
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

  await storage.put(stored, storedAtEpochMs);

  const response: DropBottleResponse = {
    schema: SCHEMAS.dropResponse,
    bottleId,
    storedAt,
    expiresAt,
    evidence
  };
  return json(response, 201);
}

async function enforceDropRateLimit(
  request: Request,
  drop: DropBottleRequest,
  env: BottleWorkerEnv
): Promise<void> {
  const limiter = env.DROP_RATE_LIMITER;
  if (!limiter) {
    if (env.BOTTLES_KV) {
      throw new HttpError(503, "Bottle drop protection is unavailable.");
    }
    return;
  }

  const clientAddress = request.headers.get("CF-Connecting-IP")?.trim() || "unavailable";
  const key = await sha256Hex(
    `nsm.daylight-bottle.drop-rate.v1\n${clientAddress}\n${drop.recipientFingerprint}`
  );
  const result = await limiter.limit({ key });
  if (!result.success) {
    throw new HttpError(
      429,
      "Too many bottle drops for this network and recipient. Try again in one minute.",
      { "Retry-After": "60" }
    );
  }
}

async function assertActiveKeyringRecipient(
  drop: DropBottleRequest,
  env: BottleWorkerEnv
): Promise<void> {
  const keyring = env.__TEST_KEYRING__ ?? PUBLISHED_KEYRING;
  const registered = keyring.keys.find(
    (key) =>
      key.status === "active" &&
      key.keyname === drop.keyname &&
      key.fingerprint === drop.recipientFingerprint
  );
  if (!registered) {
    throw new HttpError(403, "Recipient is not registered as an active public key.");
  }
  const derivedFingerprint = await fingerprintKeyRecordInput({
    keyname: registered.keyname,
    publicRecipient: registered.publicRecipient
  });
  if (derivedFingerprint !== registered.fingerprint) {
    throw new HttpError(503, "The published recipient key record is invalid.");
  }
}

async function handleListBottles(
  request: Request,
  url: URL,
  env: BottleWorkerEnv,
  now: Date
): Promise<Response> {
  const { recipientFingerprint, cursor } = parseClientInput(() => parseListQuery(url));
  await enforceReadRateLimit(request, env);
  const page = await getStorage(env).listByRecipientFingerprint(recipientFingerprint, cursor);
  const publicBottles: StoredBottlePublic[] = page.bottles
    .filter((bottle) => Date.parse(bottle.expiresAt) > now.getTime())
    .sort((left, right) => Date.parse(left.storedAt) - Date.parse(right.storedAt))
    .map(toStoredBottlePublic);
  const response: ListBottlesResponse = {
    schema: SCHEMAS.listResponse,
    bottles: publicBottles
  };
  if (utf8ByteLength(JSON.stringify(response, null, 2)) > BOTTLE_LIST_RESPONSE_MAX_BYTES) {
    throw new Error("Bottle list response exceeds its byte budget.");
  }
  const result = json(response);
  if (page.nextCursor !== undefined) {
    result.headers.set(BOTTLE_LIST_CURSOR_HEADER, page.nextCursor);
  }
  return result;
}

function parseListQuery(url: URL): { recipientFingerprint: string; cursor?: string } {
  const allowed = new Set(["recipientFingerprint", "cursor"]);
  url.searchParams.forEach((_value, key) => {
    if (!allowed.has(key)) {
      throw new Error(`Unexpected bottle list query parameter: ${key}`);
    }
  });
  const fingerprintValues = url.searchParams.getAll("recipientFingerprint");
  const cursorValues = url.searchParams.getAll("cursor");
  if (fingerprintValues.length !== 1 || cursorValues.length > 1) {
    throw new Error("Bottle list query parameters must occur exactly once.");
  }
  const recipientFingerprint = assertFingerprint(fingerprintValues[0] ?? "");
  return {
    recipientFingerprint,
    ...(cursorValues.length === 0 ? {} : { cursor: assertListCursor(cursorValues[0] ?? "") })
  };
}

async function enforceReadRateLimit(
  request: Request,
  env: BottleWorkerEnv
): Promise<void> {
  const limiter = env.READ_RATE_LIMITER;
  if (!limiter) {
    if (env.BOTTLES_KV) {
      throw new HttpError(503, "Bottle read protection is unavailable.");
    }
    return;
  }

  const clientAddress = request.headers.get("CF-Connecting-IP")?.trim() || "unavailable";
  const key = await sha256Hex(`nsm.daylight-bottle.read-rate.v2\n${clientAddress}`);
  const result = await limiter.limit({ key });
  if (!result.success) {
    throw new HttpError(
      429,
      "Too many bottle lookups for this network. Try again in one minute.",
      { "Retry-After": "60" }
    );
  }
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
      "Cache-Control": "no-store, no-transform"
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
    message: string,
    readonly headers: Readonly<Record<string, string>> = {}
  ) {
    super(message);
  }
}
