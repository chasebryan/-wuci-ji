export const SCHEMAS = {
  key: "nsm.daylight-bottle.key.v1",
  keyring: "nsm.daylight-bottle.keyring.v1",
  payload: "nsm.daylight-bottle.payload.v1",
  drop: "nsm.daylight-bottle.drop.v1",
  dropResponse: "nsm.daylight-bottle.drop.response.v1",
  listResponse: "nsm.daylight-bottle.list.response.v1",
  stored: "nsm.daylight-bottle.stored.v1",
  publicBottle: "nsm.daylight-bottle.public.v1",
  evidence: "nsm.daylight-bottle.evidence.v1"
} as const;

export type GeneratedIdentity = {
  privateIdentity: string;
  publicRecipient: string;
};

export type KeyRecord = {
  schema: typeof SCHEMAS.key;
  keyname: string;
  publicRecipient: string;
  fingerprint: string;
  createdAt: string;
  status: "active" | "revoked";
};

export type Keyring = {
  schema: typeof SCHEMAS.keyring;
  updatedAt: string;
  keys: KeyRecord[];
};

export type PlainBottlePayload = {
  schema: typeof SCHEMAS.payload;
  keyname: string;
  recipientFingerprint: string;
  message: string;
  createdAt: string;
};

export type DropBottleRequest = {
  schema: typeof SCHEMAS.drop;
  keyname: string;
  recipientFingerprint: string;
  ciphertext: string;
  createdAtClient: string;
};

export type DaylightBottleEvidence = {
  schema: typeof SCHEMAS.evidence;
  event: "bottle.accepted";
  bottleId: string;
  keyname: string;
  recipientFingerprint: string;
  ciphertextSha256: string;
  storedAt: string;
  expiresAt: string;
  serverOrigin: "bottle.nosuchmachine.net";
  storagePolicy: "ciphertext-only";
  plaintextSeenByServer: false;
};

export type DropBottleResponse = {
  schema: typeof SCHEMAS.dropResponse;
  bottleId: string;
  storedAt: string;
  expiresAt: string;
  evidence: DaylightBottleEvidence;
};

export type StoredBottle = {
  schema: typeof SCHEMAS.stored;
  bottleId: string;
  keyname: string;
  recipientFingerprint: string;
  ciphertext: string;
  ciphertextSha256: string;
  storedAt: string;
  expiresAt: string;
  evidence: DaylightBottleEvidence;
};

export type StoredBottlePublic = {
  schema: typeof SCHEMAS.publicBottle;
  bottleId: string;
  keyname: string;
  recipientFingerprint: string;
  ciphertext: string;
  ciphertextSha256: string;
  storedAt: string;
  expiresAt: string;
};

export type ListBottlesResponse = {
  schema: typeof SCHEMAS.listResponse;
  bottles: StoredBottlePublic[];
};
