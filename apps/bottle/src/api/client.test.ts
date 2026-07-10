import { describe, expect, it } from "vitest";
import { sha256Hex } from "../crypto/fingerprint";
import { SCHEMAS, type DaylightBottleEvidence, type DropBottleRequest } from "../domain/types";
import { dropBottle, listBottlePage, listBottles, loadKeyring } from "./client";

const fingerprint = `sha256:${"a".repeat(64)}`;
const storedAt = "2026-07-07T12:00:00.000Z";
const expiresAt = "2026-08-06T12:00:00.000Z";
const bottleId = "bottle_12345678";

describe("API client trust boundary", () => {
  it("captures a ciphertext-only drop body and validates the evidence response", async () => {
    const request = validRequest();
    const ciphertextSha256 = await sha256Hex(request.ciphertext);
    let submitted: unknown;

    const response = await dropBottle(request, async (_input, init) => {
      submitted = JSON.parse(String(init?.body));
      return jsonResponse({
        schema: SCHEMAS.dropResponse,
        bottleId,
        storedAt,
        expiresAt,
        evidence: validEvidence(ciphertextSha256)
      }, 201);
    });

    expect(response.bottleId).toBe(bottleId);
    expect(submitted).toEqual(request);
    expect(JSON.stringify(submitted)).not.toContain("message");
    expect(JSON.stringify(submitted)).not.toContain("privateIdentity");
  });

  it("rejects a drop response whose evidence does not bind the uploaded ciphertext", async () => {
    await expect(
      dropBottle(validRequest(), async () =>
        jsonResponse({
          schema: SCHEMAS.dropResponse,
          bottleId,
          storedAt,
          expiresAt,
          evidence: validEvidence("f".repeat(64))
        }, 201)
      )
    ).rejects.toThrow(/ciphertext hash/);
  });

  it("rejects list entries with a different fingerprint or modified ciphertext", async () => {
    const ciphertext = "armored-ciphertext";
    const validBottle = {
      schema: SCHEMAS.publicBottle,
      bottleId,
      keyname: "daylight/chase",
      recipientFingerprint: fingerprint,
      ciphertext,
      ciphertextSha256: await sha256Hex(ciphertext),
      storedAt,
      expiresAt
    };

    await expect(
      listBottles(fingerprint, async () =>
        jsonResponse({
          schema: SCHEMAS.listResponse,
          bottles: [{ ...validBottle, recipientFingerprint: `sha256:${"b".repeat(64)}` }]
        })
      )
    ).rejects.toThrow(/different recipient fingerprint/);

    await expect(
      listBottles(fingerprint, async () =>
        jsonResponse({
          schema: SCHEMAS.listResponse,
          bottles: [{ ...validBottle, ciphertext: `${ciphertext}-modified` }]
        })
      )
    ).rejects.toThrow(/integrity check/);
  });

  it("rejects a keyring record whose published fingerprint is inconsistent", async () => {
    await expect(
      loadKeyring(async () =>
        jsonResponse({
          schema: SCHEMAS.keyring,
          updatedAt: "2026-07-07T00:00:00.000Z",
          keys: [
            {
              schema: SCHEMAS.key,
              keyname: "daylight/chase",
              publicRecipient: `age1${"q".repeat(58)}`,
              fingerprint,
              createdAt: "2026-07-07T00:00:00.000Z",
              status: "active"
            }
          ]
        })
      )
    ).rejects.toThrow(/fingerprint mismatch/);
  });

  it("requests a validated continuation cursor and rejects a repeated cursor", async () => {
    let requestedUrl = "";
    const fetcher: typeof fetch = async (input) => {
      requestedUrl = String(input);
      return jsonResponse(
        { schema: SCHEMAS.listResponse, bottles: [] },
        200,
        { "X-Daylight-Next-Cursor": "page_3" }
      );
    };

    const page = await listBottlePage(fingerprint, fetcher, "page_2");
    expect(requestedUrl).toContain(`recipientFingerprint=${encodeURIComponent(fingerprint)}`);
    expect(requestedUrl).toContain("cursor=page_2");
    expect(page.response).toEqual({ schema: SCHEMAS.listResponse, bottles: [] });
    expect(page.nextCursor).toBe("page_3");

    await expect(
      listBottlePage(
        fingerprint,
        async () =>
          jsonResponse(
            { schema: SCHEMAS.listResponse, bottles: [] },
            200,
            { "X-Daylight-Next-Cursor": "page_2" }
          ),
        "page_2"
      )
    ).rejects.toThrow(/repeated its pagination cursor/);
  });
});

function validRequest(): DropBottleRequest {
  return {
    schema: SCHEMAS.drop,
    keyname: "daylight/chase",
    recipientFingerprint: fingerprint,
    ciphertext: "-----BEGIN AGE ENCRYPTED FILE-----\nopaque\n-----END AGE ENCRYPTED FILE-----",
    createdAtClient: "2026-07-07T00:00:00.000Z"
  };
}

function validEvidence(ciphertextSha256: string): DaylightBottleEvidence {
  return {
    schema: SCHEMAS.evidence,
    event: "bottle.accepted",
    bottleId,
    keyname: "daylight/chase",
    recipientFingerprint: fingerprint,
    ciphertextSha256,
    storedAt,
    expiresAt,
    serverOrigin: "bottle.nosuchmachine.net",
    storagePolicy: "ciphertext-only",
    plaintextSeenByServer: false
  };
}

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  });
}
