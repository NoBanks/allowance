// The Node side of the verifier: real crypto from node:crypto, rules from core.mjs.
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { makeVerifier, GENESIS_PREV } from "./core.mjs";

const SIGNATURE_HEX_LEN = 128;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export { GENESIS_PREV };

export const sha256Hex = (data) => createHash("sha256").update(data).digest("hex");

export function verifySignature(publicKeyHex, message, signatureHex) {
  if (!/^[0-9a-f]+$/.test(signatureHex) || signatureHex.length !== SIGNATURE_HEX_LEN) return false;
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]),
    format: "der",
    type: "spki",
  });
  return nodeVerify(null, Buffer.from(message), key, Buffer.from(signatureHex, "hex"));
}

export const { replay, receiptPreimage, intentMessage } = makeVerifier({ sha256Hex, verifySignature });