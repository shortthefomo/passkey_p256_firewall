// Reference signer for passkey_p256_firewall_v1.c.
//
// Builds the 53-byte payload the hook hashes, then signs it with ECDSA P-256
// over SHA-256. WebCrypto returns the signature as r || s (64 bytes), which is
// what util_verify_p256 expects.

import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;

export const MAGIC = "xahau.passkey.v1";
export const MEMO_TYPE_HEX = Buffer.from(MAGIC, "ascii").toString("hex").toUpperCase();
export const PAYLOAD_LEN = 53;

export function buildPayload({ direction, sequence, counterparty, drops }) {
  if (direction !== 0 && direction !== 1)
    throw new Error("direction must be 0 (outgoing) or 1 (incoming)");

  const other = Buffer.isBuffer(counterparty)
    ? counterparty
    : Buffer.from(counterparty);
  if (other.length !== 20)
    throw new Error("counterparty must be 20 bytes");

  const payload = Buffer.alloc(PAYLOAD_LEN);
  payload.write(MAGIC, 0, "ascii");
  payload[16] = direction;
  payload.writeUInt32BE(Number(sequence), 21);
  other.copy(payload, 25);
  payload.writeBigUInt64BE(BigInt(drops), 45);
  return payload;
}

export async function generatePasskey() {
  const keyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const raw = Buffer.from(await subtle.exportKey("raw", keyPair.publicKey));
  if (raw.length !== 65 || raw[0] !== 0x04)
    throw new Error("expected uncompressed P-256 public key");
  const pkcs8 = Buffer.from(await subtle.exportKey("pkcs8", keyPair.privateKey));
  return {
    x: raw.subarray(1, 33),
    y: raw.subarray(33, 65),
    raw,
    pkcs8,
  };
}

export async function signPayload(pkcs8, payload) {
  const key = await subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const sig = Buffer.from(
    await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, payload)
  );
  if (sig.length !== 64)
    throw new Error(`expected 64-byte r||s signature, got ${sig.length}`);
  return sig;
}

export async function verifyPayload(rawPublic, payload, sig) {
  const key = await subtle.importKey(
    "raw",
    rawPublic,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, payload);
}

export function memoFromSignature(sig) {
  return {
    Memo: {
      MemoType: MEMO_TYPE_HEX,
      MemoData: Buffer.from(sig).toString("hex").toUpperCase(),
    },
  };
}
