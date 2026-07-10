import {
  SCHEMAS,
  type DaylightBottleEvidence,
  type DropBottleResponse,
  type DropBottleRequest,
  type KeyRecord,
  type Keyring,
  type ListBottlesResponse,
  type PlainBottlePayload,
  type StoredBottle,
  type StoredBottlePublic
} from "./types";

export const MAX_DROP_BODY_BYTES = 256 * 1024;
export const MAX_PRIVATE_IDENTITY_BYTES = 64 * 1024;

const KEYNAME_PATTERN = /^[a-z0-9][a-z0-9._/-]{2,63}$/;
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/;
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;
const BOTTLE_ID_PATTERN = /^[a-zA-Z0-9_-]{8,128}$/;
const AGE_RECIPIENT_PATTERN = /^age1[a-z0-9]{20,511}$/;
const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/;
const FORBIDDEN_PLAINTEXT_FIELDS = new Set([
  "message",
  "plaintext",
  "privateKey",
  "privateIdentity",
  "passphrase"
]);
const DROP_REQUEST_FIELDS = new Set([
  "schema",
  "keyname",
  "recipientFingerprint",
  "ciphertext",
  "createdAtClient"
]);
const KEY_RECORD_FIELDS = new Set([
  "schema",
  "keyname",
  "publicRecipient",
  "fingerprint",
  "createdAt",
  "status"
]);
const KEYRING_FIELDS = new Set(["schema", "updatedAt", "keys"]);
const PAYLOAD_FIELDS = new Set([
  "schema",
  "keyname",
  "recipientFingerprint",
  "message",
  "createdAt"
]);
const EVIDENCE_FIELDS = new Set([
  "schema",
  "event",
  "bottleId",
  "keyname",
  "recipientFingerprint",
  "ciphertextSha256",
  "storedAt",
  "expiresAt",
  "serverOrigin",
  "storagePolicy",
  "plaintextSeenByServer"
]);
const DROP_RESPONSE_FIELDS = new Set([
  "schema",
  "bottleId",
  "storedAt",
  "expiresAt",
  "evidence"
]);
const STORED_BOTTLE_FIELDS = new Set([
  "schema",
  "bottleId",
  "keyname",
  "recipientFingerprint",
  "ciphertext",
  "ciphertextSha256",
  "storedAt",
  "expiresAt",
  "evidence"
]);
const PUBLIC_BOTTLE_FIELDS = new Set([
  "schema",
  "bottleId",
  "keyname",
  "recipientFingerprint",
  "ciphertext",
  "ciphertextSha256",
  "storedAt",
  "expiresAt"
]);
const LIST_RESPONSE_FIELDS = new Set(["schema", "bottles"]);

export function normalizeKeyname(input: string): string {
  if (typeof input !== "string") {
    throw new Error("Keyname must be a string.");
  }

  const normalized = input.trim().toLowerCase();
  if (!isNormalizedKeyname(normalized)) {
    throw new Error("Keyname must be 3-64 lowercase characters using letters, digits, '.', '_', '/', or '-'.");
  }

  return normalized;
}

export function isValidKeyname(input: string): boolean {
  try {
    normalizeKeyname(input);
    return true;
  } catch {
    return false;
  }
}

export function isValidFingerprint(input: string): boolean {
  return FINGERPRINT_PATTERN.test(input);
}

export function assertFingerprint(input: string): string {
  if (typeof input !== "string" || !isValidFingerprint(input)) {
    throw new Error("Recipient fingerprint must be sha256: followed by 64 lowercase hex characters.");
  }
  return input;
}

export function assertSha256Hex(input: string): string {
  if (typeof input !== "string" || !SHA256_HEX_PATTERN.test(input)) {
    throw new Error("SHA-256 digest must be 64 lowercase hex characters.");
  }
  return input;
}

export function assertBottleId(input: string): string {
  if (typeof input !== "string" || !BOTTLE_ID_PATTERN.test(input)) {
    throw new Error("Bottle id has an invalid format.");
  }
  return input;
}

export function assertPublicRecipient(input: string): string {
  if (typeof input !== "string" || !AGE_RECIPIENT_PATTERN.test(input)) {
    throw new Error("Public recipient must be a supported age recipient string.");
  }
  return input;
}

export function safeKeynameForFilename(keyname: string): string {
  return normalizeKeyname(keyname).replace(/[^a-z0-9._-]/g, "-");
}

export function parseKeyRecord(input: unknown): KeyRecord {
  const record = expectRecord(input, "Key record");
  if (record["schema"] !== SCHEMAS.key) {
    throw new Error("Unsupported key record schema.");
  }
  assertExactFields(record, KEY_RECORD_FIELDS, "Key record");

  const keyname = normalizeKeyname(expectString(record["keyname"], "keyname"));
  const publicRecipient = assertPublicRecipient(expectString(record["publicRecipient"], "publicRecipient"));
  const fingerprint = assertFingerprint(expectString(record["fingerprint"], "fingerprint"));
  const createdAt = expectIsoTimestamp(record["createdAt"], "createdAt");
  const status = record["status"];
  if (status !== "active" && status !== "revoked") {
    throw new Error("Key record status must be active or revoked.");
  }

  return {
    schema: SCHEMAS.key,
    keyname,
    publicRecipient,
    fingerprint,
    createdAt,
    status
  };
}

export function parseKeyring(input: unknown): Keyring {
  const record = expectRecord(input, "Keyring");
  if (record["schema"] !== SCHEMAS.keyring) {
    throw new Error("Unsupported keyring schema.");
  }
  assertExactFields(record, KEYRING_FIELDS, "Keyring");

  const keys = record["keys"];
  if (!Array.isArray(keys)) {
    throw new Error("Keyring keys must be an array.");
  }

  const parsedKeys = keys.map(parseKeyRecord);
  const fingerprints = new Set<string>();
  const activeKeynames = new Set<string>();
  for (const key of parsedKeys) {
    if (fingerprints.has(key.fingerprint)) {
      throw new Error(`Duplicate key fingerprint in keyring: ${key.fingerprint}`);
    }
    fingerprints.add(key.fingerprint);
    if (key.status === "active") {
      if (activeKeynames.has(key.keyname)) {
        throw new Error(`Multiple active records exist for keyname: ${key.keyname}`);
      }
      activeKeynames.add(key.keyname);
    }
  }

  return {
    schema: SCHEMAS.keyring,
    updatedAt: expectIsoTimestamp(record["updatedAt"], "updatedAt"),
    keys: parsedKeys
  };
}

export function parsePlainBottlePayload(input: unknown): PlainBottlePayload {
  const record = expectRecord(input, "Plain bottle payload");
  if (record["schema"] !== SCHEMAS.payload) {
    throw new Error("Unsupported bottle payload schema.");
  }
  assertExactFields(record, PAYLOAD_FIELDS, "Plain bottle payload");

  return {
    schema: SCHEMAS.payload,
    keyname: normalizeKeyname(expectString(record["keyname"], "keyname")),
    recipientFingerprint: assertFingerprint(expectString(record["recipientFingerprint"], "recipientFingerprint")),
    message: expectString(record["message"], "message"),
    createdAt: expectIsoTimestamp(record["createdAt"], "createdAt")
  };
}

export function parseDropBottleRequest(input: unknown): DropBottleRequest {
  assertNoForbiddenPlaintextFields(input);
  const record = expectRecord(input, "Drop bottle request");
  if (record["schema"] !== SCHEMAS.drop) {
    throw new Error("Unsupported drop request schema.");
  }
  assertExactFields(record, DROP_REQUEST_FIELDS, "Drop bottle request");

  return {
    schema: SCHEMAS.drop,
    keyname: normalizeKeyname(expectString(record["keyname"], "keyname")),
    recipientFingerprint: assertFingerprint(expectString(record["recipientFingerprint"], "recipientFingerprint")),
    ciphertext: expectNonEmptyString(record["ciphertext"], "ciphertext"),
    createdAtClient: expectIsoTimestamp(record["createdAtClient"], "createdAtClient")
  };
}

export function parseDaylightBottleEvidence(input: unknown): DaylightBottleEvidence {
  const record = expectRecord(input, "Daylight evidence");
  if (record["schema"] !== SCHEMAS.evidence) {
    throw new Error("Unsupported Daylight evidence schema.");
  }
  assertExactFields(record, EVIDENCE_FIELDS, "Daylight evidence");
  if (record["event"] !== "bottle.accepted") {
    throw new Error("Unsupported Daylight evidence event.");
  }
  if (record["serverOrigin"] !== "bottle.nosuchmachine.net") {
    throw new Error("Unexpected Daylight evidence server origin.");
  }
  if (record["storagePolicy"] !== "ciphertext-only") {
    throw new Error("Unexpected Daylight evidence storage policy.");
  }
  if (record["plaintextSeenByServer"] !== false) {
    throw new Error("Daylight evidence must identify the ciphertext-only design claim.");
  }

  const evidence: DaylightBottleEvidence = {
    schema: SCHEMAS.evidence,
    event: "bottle.accepted",
    bottleId: assertBottleId(expectString(record["bottleId"], "bottleId")),
    keyname: normalizeKeyname(expectString(record["keyname"], "keyname")),
    recipientFingerprint: assertFingerprint(expectString(record["recipientFingerprint"], "recipientFingerprint")),
    ciphertextSha256: assertSha256Hex(expectString(record["ciphertextSha256"], "ciphertextSha256")),
    storedAt: expectIsoTimestamp(record["storedAt"], "storedAt"),
    expiresAt: expectIsoTimestamp(record["expiresAt"], "expiresAt"),
    serverOrigin: "bottle.nosuchmachine.net",
    storagePolicy: "ciphertext-only",
    plaintextSeenByServer: false
  };
  assertExpiryAfterStoredAt(evidence.storedAt, evidence.expiresAt);
  return evidence;
}

export function parseDropBottleResponse(input: unknown): DropBottleResponse {
  const record = expectRecord(input, "Drop bottle response");
  if (record["schema"] !== SCHEMAS.dropResponse) {
    throw new Error("Unsupported drop response schema.");
  }
  assertExactFields(record, DROP_RESPONSE_FIELDS, "Drop bottle response");

  const response: DropBottleResponse = {
    schema: SCHEMAS.dropResponse,
    bottleId: assertBottleId(expectString(record["bottleId"], "bottleId")),
    storedAt: expectIsoTimestamp(record["storedAt"], "storedAt"),
    expiresAt: expectIsoTimestamp(record["expiresAt"], "expiresAt"),
    evidence: parseDaylightBottleEvidence(record["evidence"])
  };
  assertExpiryAfterStoredAt(response.storedAt, response.expiresAt);
  assertEvidenceMatchesMetadata(response.evidence, response);
  return response;
}

export function assertStoredBottle(input: unknown): StoredBottle {
  const record = expectRecord(input, "Stored bottle");
  if (record["schema"] !== SCHEMAS.stored) {
    throw new Error("Unsupported stored bottle schema.");
  }
  assertExactFields(record, STORED_BOTTLE_FIELDS, "Stored bottle");

  const stored: StoredBottle = {
    schema: SCHEMAS.stored,
    bottleId: assertBottleId(expectString(record["bottleId"], "bottleId")),
    keyname: normalizeKeyname(expectString(record["keyname"], "keyname")),
    recipientFingerprint: assertFingerprint(expectString(record["recipientFingerprint"], "recipientFingerprint")),
    ciphertext: expectNonEmptyString(record["ciphertext"], "ciphertext"),
    ciphertextSha256: assertSha256Hex(expectString(record["ciphertextSha256"], "ciphertextSha256")),
    storedAt: expectIsoTimestamp(record["storedAt"], "storedAt"),
    expiresAt: expectIsoTimestamp(record["expiresAt"], "expiresAt"),
    evidence: parseDaylightBottleEvidence(record["evidence"])
  };
  assertExpiryAfterStoredAt(stored.storedAt, stored.expiresAt);
  assertEvidenceMatchesMetadata(stored.evidence, stored);
  return stored;
}

export function parseStoredBottlePublic(input: unknown): StoredBottlePublic {
  const record = expectRecord(input, "Public bottle");
  if (record["schema"] !== SCHEMAS.publicBottle) {
    throw new Error("Unsupported public bottle schema.");
  }
  assertExactFields(record, PUBLIC_BOTTLE_FIELDS, "Public bottle");

  const bottle: StoredBottlePublic = {
    schema: SCHEMAS.publicBottle,
    bottleId: assertBottleId(expectString(record["bottleId"], "bottleId")),
    keyname: normalizeKeyname(expectString(record["keyname"], "keyname")),
    recipientFingerprint: assertFingerprint(expectString(record["recipientFingerprint"], "recipientFingerprint")),
    ciphertext: expectNonEmptyString(record["ciphertext"], "ciphertext"),
    ciphertextSha256: assertSha256Hex(expectString(record["ciphertextSha256"], "ciphertextSha256")),
    storedAt: expectIsoTimestamp(record["storedAt"], "storedAt"),
    expiresAt: expectIsoTimestamp(record["expiresAt"], "expiresAt")
  };
  assertExpiryAfterStoredAt(bottle.storedAt, bottle.expiresAt);
  return bottle;
}

export function parseListBottlesResponse(input: unknown): ListBottlesResponse {
  const record = expectRecord(input, "List bottles response");
  if (record["schema"] !== SCHEMAS.listResponse) {
    throw new Error("Unsupported list response schema.");
  }
  assertExactFields(record, LIST_RESPONSE_FIELDS, "List bottles response");
  if (!Array.isArray(record["bottles"])) {
    throw new Error("List response bottles must be an array.");
  }

  const bottles = record["bottles"].map(parseStoredBottlePublic);
  const bottleIds = new Set<string>();
  for (const bottle of bottles) {
    if (bottleIds.has(bottle.bottleId)) {
      throw new Error(`Duplicate bottle id in list response: ${bottle.bottleId}`);
    }
    bottleIds.add(bottle.bottleId);
  }
  return { schema: SCHEMAS.listResponse, bottles };
}

export function toStoredBottlePublic(stored: StoredBottle): StoredBottlePublic {
  return {
    schema: SCHEMAS.publicBottle,
    bottleId: stored.bottleId,
    keyname: stored.keyname,
    recipientFingerprint: stored.recipientFingerprint,
    ciphertext: stored.ciphertext,
    ciphertextSha256: stored.ciphertextSha256,
    storedAt: stored.storedAt,
    expiresAt: stored.expiresAt
  };
}

export function assertPayloadMatchesBottleMetadata(
  payload: PlainBottlePayload,
  metadata: { keyname: string; recipientFingerprint: string }
): void {
  const expectedKeyname = normalizeKeyname(metadata.keyname);
  const expectedFingerprint = assertFingerprint(metadata.recipientFingerprint);

  if (payload.keyname !== expectedKeyname) {
    throw new Error("Decrypted payload keyname does not match bottle metadata.");
  }

  if (payload.recipientFingerprint !== expectedFingerprint) {
    throw new Error("Decrypted payload recipient fingerprint does not match bottle metadata.");
  }
}

export function assertNoForbiddenPlaintextFields(input: unknown): void {
  visitFieldNames(input, (fieldName) => {
    if (FORBIDDEN_PLAINTEXT_FIELDS.has(fieldName)) {
      throw new Error(`Drop request must not include plaintext or private field: ${fieldName}`);
    }
  });
}

export function utf8ByteLength(input: string): number {
  return new TextEncoder().encode(input).byteLength;
}

function isNormalizedKeyname(input: string): boolean {
  if (!KEYNAME_PATTERN.test(input)) {
    return false;
  }
  if (input.includes("..") || input.includes("//")) {
    return false;
  }
  if (input.includes(" ") || CONTROL_CHARACTER_PATTERN.test(input)) {
    return false;
  }
  if (input.startsWith("/") || input.endsWith("/")) {
    return false;
  }
  return true;
}

function visitFieldNames(input: unknown, visitor: (fieldName: string) => void): void {
  if (Array.isArray(input)) {
    for (const item of input) {
      visitFieldNames(item, visitor);
    }
    return;
  }

  if (!isRecord(input)) {
    return;
  }

  for (const [fieldName, value] of Object.entries(input)) {
    visitor(fieldName);
    visitFieldNames(value, visitor);
  }
}

function expectRecord(input: unknown, label: string): Record<string, unknown> {
  if (!isRecord(input)) {
    throw new Error(`${label} must be an object.`);
  }
  return input;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input);
}

function expectString(input: unknown, label: string): string {
  if (typeof input !== "string") {
    throw new Error(`${label} must be a string.`);
  }
  return input;
}

function expectNonEmptyString(input: unknown, label: string): string {
  const value = expectString(input, label);
  if (value.trim().length === 0) {
    throw new Error(`${label} must not be empty.`);
  }
  return value;
}

function expectIsoTimestamp(input: unknown, label: string): string {
  const value = expectString(input, label);
  if (!ISO_TIMESTAMP_PATTERN.test(value)) {
    throw new Error(`${label} must be a canonical UTC ISO timestamp.`);
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.toISOString() !== value) {
    throw new Error(`${label} must be a valid canonical UTC ISO timestamp.`);
  }
  return value;
}

function assertExactFields(
  record: Record<string, unknown>,
  expectedFields: ReadonlySet<string>,
  label: string
): void {
  for (const key of Object.keys(record)) {
    if (!expectedFields.has(key)) {
      throw new Error(`Unexpected field in ${label.toLowerCase()}: ${key}`);
    }
  }
  for (const key of expectedFields) {
    if (!Object.hasOwn(record, key)) {
      throw new Error(`Missing field in ${label.toLowerCase()}: ${key}`);
    }
  }
}

function assertExpiryAfterStoredAt(storedAt: string, expiresAt: string): void {
  if (Date.parse(expiresAt) <= Date.parse(storedAt)) {
    throw new Error("Bottle expiry must be later than its storage time.");
  }
}

function assertEvidenceMatchesMetadata(
  evidence: DaylightBottleEvidence,
  metadata: {
    bottleId: string;
    storedAt: string;
    expiresAt: string;
    keyname?: string;
    recipientFingerprint?: string;
    ciphertextSha256?: string;
  }
): void {
  const comparisons: Array<[string, string | undefined, string]> = [
    ["bottle id", metadata.bottleId, evidence.bottleId],
    ["stored timestamp", metadata.storedAt, evidence.storedAt],
    ["expiry timestamp", metadata.expiresAt, evidence.expiresAt],
    ["keyname", metadata.keyname, evidence.keyname],
    ["recipient fingerprint", metadata.recipientFingerprint, evidence.recipientFingerprint],
    ["ciphertext hash", metadata.ciphertextSha256, evidence.ciphertextSha256]
  ];
  for (const [label, outer, inner] of comparisons) {
    if (outer !== undefined && outer !== inner) {
      throw new Error(`Daylight evidence ${label} does not match enclosing metadata.`);
    }
  }
}
