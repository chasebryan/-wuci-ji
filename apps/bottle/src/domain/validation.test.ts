import { describe, expect, it } from "vitest";
import {
  isValidKeyname,
  normalizeKeyname,
  parseDaylightBottleEvidence,
  parseDropBottleRequest,
  parseKeyring,
  parsePlainBottlePayload
} from "./validation";
import { SCHEMAS, type DaylightBottleEvidence, type KeyRecord } from "./types";

describe("keyname validation", () => {
  it("normalizes and accepts valid keynames", () => {
    expect(normalizeKeyname("daylight/chase")).toBe("daylight/chase");
    expect(normalizeKeyname(" Aperture.Alice ")).toBe("aperture.alice");
    expect(normalizeKeyname("NSM/operator-7")).toBe("nsm/operator-7");
  });

  it("rejects invalid keynames", () => {
    const invalid = [
      "ab",
      "/abc",
      "abc/",
      "a b c",
      "abc..def",
      "abc//def",
      "abc\u0007def",
      "-abc",
      "abc!",
      "a".repeat(65)
    ];

    for (const keyname of invalid) {
      expect(isValidKeyname(keyname), keyname).toBe(false);
      expect(() => normalizeKeyname(keyname), keyname).toThrow();
    }
  });
});

describe("drop request validation", () => {
  it("rejects plaintext and private material field names", () => {
    const request = {
      schema: SCHEMAS.drop,
      keyname: "daylight/chase",
      recipientFingerprint: `sha256:${"a".repeat(64)}`,
      ciphertext: "ciphertext",
      createdAtClient: "2026-07-07T00:00:00.000Z",
      message: "server must not receive this"
    };

    expect(() => parseDropBottleRequest(request)).toThrow(/message/);
  });

  it("rejects unknown fields and non-canonical timestamps", () => {
    const base = {
      schema: SCHEMAS.drop,
      keyname: "daylight/chase",
      recipientFingerprint: `sha256:${"a".repeat(64)}`,
      ciphertext: "ciphertext",
      createdAtClient: "2026-07-07T00:00:00.000Z"
    };

    expect(() => parseDropBottleRequest({ ...base, harmlessLooking: true })).toThrow(/Unexpected field/);
    expect(() => parseDropBottleRequest({ ...base, createdAtClient: "2026" })).toThrow(/canonical UTC/);
    expect(() => parseDropBottleRequest({ ...base, createdAtClient: "2026-02-31T00:00:00.000Z" })).toThrow(
      /valid canonical/
    );
  });
});

describe("versioned record validation", () => {
  it("rejects accidental secret fields in the public keyring", () => {
    const record = validKeyRecord();
    expect(() =>
      parseKeyring({
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: [{ ...record, privateIdentity: "AGE-SECRET-KEY-1DO-NOT-PUBLISH" }]
      })
    ).toThrow(/privateIdentity/);
  });

  it("allows key rotation history but rejects duplicate fingerprints or active keynames", () => {
    const active = validKeyRecord();
    const revoked: KeyRecord = {
      ...validKeyRecord({
        publicRecipient: `age1${"r".repeat(58)}`,
        fingerprint: `sha256:${"b".repeat(64)}`
      }),
      status: "revoked"
    };
    expect(
      parseKeyring({
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: [revoked, active]
      }).keys
    ).toHaveLength(2);

    expect(() =>
      parseKeyring({
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: [active, { ...revoked, status: "active" }]
      })
    ).toThrow(/Multiple active/);
    expect(() =>
      parseKeyring({
        schema: SCHEMAS.keyring,
        updatedAt: "2026-07-07T00:00:00.000Z",
        keys: [active, { ...revoked, fingerprint: active.fingerprint }]
      })
    ).toThrow(/Duplicate key fingerprint/);
  });

  it("rejects unknown decrypted payload fields", () => {
    expect(() =>
      parsePlainBottlePayload({
        schema: SCHEMAS.payload,
        keyname: "daylight/chase",
        recipientFingerprint: `sha256:${"a".repeat(64)}`,
        message: "hello",
        createdAt: "2026-07-07T00:00:00.000Z",
        executableHint: "not part of this schema"
      })
    ).toThrow(/Unexpected field/);
  });

  it("validates every evidence field and chronological expiry", () => {
    expect(parseDaylightBottleEvidence(validEvidence()).plaintextSeenByServer).toBe(false);
    expect(() => parseDaylightBottleEvidence({ ...validEvidence(), plaintextSeenByServer: true })).toThrow(
      /ciphertext-only design claim/
    );
    expect(() =>
      parseDaylightBottleEvidence({
        ...validEvidence(),
        expiresAt: "2026-07-07T12:00:00.000Z"
      })
    ).toThrow(/expiry/);
  });
});

function validKeyRecord(overrides: Partial<KeyRecord> = {}): KeyRecord {
  return {
    schema: SCHEMAS.key,
    keyname: "daylight/chase",
    publicRecipient: `age1${"q".repeat(58)}`,
    fingerprint: `sha256:${"a".repeat(64)}`,
    createdAt: "2026-07-07T00:00:00.000Z",
    status: "active",
    ...overrides
  };
}

function validEvidence(): DaylightBottleEvidence {
  return {
    schema: SCHEMAS.evidence,
    event: "bottle.accepted",
    bottleId: "bottle_12345678",
    keyname: "daylight/chase",
    recipientFingerprint: `sha256:${"a".repeat(64)}`,
    ciphertextSha256: "b".repeat(64),
    storedAt: "2026-07-07T12:00:00.000Z",
    expiresAt: "2026-08-06T12:00:00.000Z",
    serverOrigin: "bottle.nosuchmachine.net",
    storagePolicy: "ciphertext-only",
    plaintextSeenByServer: false
  };
}
