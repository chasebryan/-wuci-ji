import * as age from "age-encryption";
import {
  assertFingerprint,
  assertPayloadMatchesBottleMetadata,
  assertPublicRecipient,
  normalizeKeyname,
  parsePlainBottlePayload
} from "../domain/validation";
import type { GeneratedIdentity, PlainBottlePayload } from "../domain/types";
import { fingerprintKeyRecordInput } from "./fingerprint";

export type { GeneratedIdentity, PlainBottlePayload, KeyRecord } from "../domain/types";
export { fingerprintKeyRecordInput } from "./fingerprint";

export async function generateIdentity(): Promise<GeneratedIdentity> {
  const privateIdentity = await age.generateIdentity();
  const publicRecipient = await age.identityToRecipient(privateIdentity);
  return { privateIdentity, publicRecipient };
}

export async function encryptBottlePayload(input: {
  payload: PlainBottlePayload;
  publicRecipient: string;
}): Promise<string> {
  if (input.publicRecipient.length === 0) {
    throw new Error("Public recipient must not be empty.");
  }

  const payload = parsePlainBottlePayload(input.payload);
  const encrypter = new age.Encrypter();
  encrypter.addRecipient(input.publicRecipient);
  const ciphertext = await encrypter.encrypt(JSON.stringify(payload));
  return age.armor.encode(ciphertext);
}

export async function decryptBottlePayload(input: {
  ciphertext: string;
  privateIdentity: string;
}): Promise<PlainBottlePayload> {
  if (input.privateIdentity.trim().length === 0) {
    throw new Error("Private identity must not be empty.");
  }

  const decrypter = new age.Decrypter();
  decrypter.addIdentity(input.privateIdentity.trim());
  const plaintext = await decrypter.decrypt(age.armor.decode(input.ciphertext.trim()), "text");
  return parsePlainBottlePayload(JSON.parse(plaintext));
}

export async function decryptBottlePayloadForRecipient(input: {
  ciphertext: string;
  privateIdentity: string;
  expectedKeyname: string;
  expectedRecipientFingerprint: string;
}): Promise<PlainBottlePayload> {
  const payload = await decryptBottlePayload(input);
  assertPayloadMatchesBottleMetadata(payload, {
    keyname: input.expectedKeyname,
    recipientFingerprint: input.expectedRecipientFingerprint
  });
  return payload;
}

export async function verifyPrivateIdentityMatchesKeyRecord(input: {
  privateIdentity: string;
  keyname: string;
  expectedPublicRecipient: string;
  expectedFingerprint: string;
}): Promise<void> {
  const privateIdentity = input.privateIdentity.trim();
  if (privateIdentity.length === 0) {
    throw new Error("Private identity must not be empty.");
  }

  const keyname = normalizeKeyname(input.keyname);
  const expectedPublicRecipient = assertPublicRecipient(input.expectedPublicRecipient);
  const expectedFingerprint = assertFingerprint(input.expectedFingerprint);
  const derivedPublicRecipient = await age.identityToRecipient(privateIdentity);
  if (derivedPublicRecipient !== expectedPublicRecipient) {
    throw new Error("The private identity does not match the selected key record.");
  }

  const derivedFingerprint = await fingerprintKeyRecordInput({
    keyname,
    publicRecipient: derivedPublicRecipient
  });
  if (derivedFingerprint !== expectedFingerprint) {
    throw new Error("The private identity fingerprint does not match the selected key record.");
  }
}
