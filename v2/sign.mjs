// Reference signer for passkey_p256_firewall_v2.c.
//
// Builds the 53-byte payment payload the hook uses as the WebAuthn challenge,
// then signs authenticatorData || SHA-256(clientDataJSON) with ECDSA P-256.
// WebCrypto returns r || s. A browser passkey returns DER; derToRaw converts it.

import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;

export const MAGIC = "xahau.passkey.v2";
export const MEMO_TYPE_HEX = Buffer.from(MAGIC, "ascii").toString("hex").toUpperCase();
export const PAYLOAD_LEN = 53;
export const TX_KIND = 2;
export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const DEVICE_FLAGS = FLAG_UP | FLAG_UV;

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

// 53-byte challenge for a gated non-payment. txHash is SHA-256 of the
// serialized transaction with Memos, TxnSignature, and Signers removed.
export function buildTxPayload({ sequence, txHash }) {
  const hash = Buffer.isBuffer(txHash) ? txHash : Buffer.from(txHash);
  if (hash.length !== 32) throw new Error("tx hash must be 32 bytes");
  const seq = Number(sequence);
  if (!Number.isInteger(seq) || seq < 0 || seq > 0xffffffff)
    throw new Error("sequence must be a uint32");
  const payload = Buffer.alloc(PAYLOAD_LEN);
  payload.write(MAGIC, 0, "ascii");
  payload[16] = TX_KIND;
  payload.writeUInt32BE(seq, 17);
  hash.copy(payload, 21);
  return payload;
}

export function base64url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export async function sha256(bytes) {
  return Buffer.from(await subtle.digest("SHA-256", Buffer.from(bytes)));
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

export function clientDataJSON({ payload, origin, type = "webauthn.get", crossOrigin = false }) {
  if (typeof origin !== "string" || origin.includes('"') || origin.includes("\\"))
    throw new Error("origin cannot contain quotes or backslashes");
  if (typeof type !== "string" || type.includes('"') || type.includes("\\"))
    throw new Error("type cannot contain quotes or backslashes");
  const challenge = base64url(payload);
  if (challenge.length !== 71)
    throw new Error(`payload must base64url-encode to 71 characters, got ${challenge.length}`);
  return Buffer.from(
    `{"type":"${type}","challenge":"${challenge}","origin":"${origin}","crossOrigin":${crossOrigin ? "true" : "false"}}`,
    "utf8"
  );
}

export async function authenticatorData({ rpId, flags = DEVICE_FLAGS, signCount = 0 }) {
  const rpIdHash = await sha256(Buffer.from(rpId, "utf8"));
  const auth = Buffer.alloc(37);
  rpIdHash.copy(auth, 0);
  auth[32] = flags & 0xff;
  auth.writeUInt32BE(signCount >>> 0, 33);
  return { auth, rpIdHash };
}

export async function signPayload(pkcs8, message) {
  const key = await subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const sig = Buffer.from(
    await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, message)
  );
  if (sig.length !== 64)
    throw new Error(`expected 64-byte r||s signature, got ${sig.length}`);
  return sig;
}

export async function verifyPayload(rawPublic, message, sig) {
  const key = await subtle.importKey(
    "raw",
    rawPublic,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, message);
}

// WebCrypto hashes `message` itself. Pass authenticatorData || clientDataHash,
// which is what the authenticator signed before its own SHA-256.
export async function signWebAuthn({
  pkcs8,
  payload,
  rpId,
  origin,
  flags = DEVICE_FLAGS,
  signCount = 0,
  type = "webauthn.get",
}) {
  const clientData = clientDataJSON({ payload, origin, type });
  const { auth, rpIdHash } = await authenticatorData({ rpId, flags, signCount });
  const clientDataHash = await sha256(clientData);
  const message = Buffer.concat([auth, clientDataHash]);
  const sig = await signPayload(pkcs8, message);
  return { clientData, auth, rpIdHash, clientDataHash, message, sig };
}

export function memoFromWebAuthn({ auth, clientData, sig }) {
  if (auth.length < 37 || auth.length > 128)
    throw new Error("authenticatorData must be 37 to 128 bytes");
  if (clientData.length < 1 || clientData.length > 220)
    throw new Error("clientDataJSON must be 1 to 220 bytes");
  if (sig.length !== 64)
    throw new Error("signature must be 64-byte r||s");
  const body = Buffer.alloc(2 + auth.length + 2 + clientData.length + 64);
  let offset = 0;
  body.writeUInt16BE(auth.length, offset);
  offset += 2;
  auth.copy(body, offset);
  offset += auth.length;
  body.writeUInt16BE(clientData.length, offset);
  offset += 2;
  clientData.copy(body, offset);
  offset += clientData.length;
  Buffer.from(sig).copy(body, offset);
  return {
    Memo: {
      MemoType: MEMO_TYPE_HEX,
      MemoData: body.toString("hex").toUpperCase(),
    },
  };
}

function derInteger(bytes) {
  let value = Buffer.from(bytes);
  if (value.length === 33) {
    if (value[0] !== 0x00) throw new Error("DER integer is too wide");
    value = value.subarray(1);
  }
  if (value.length === 0 || value.length > 32)
    throw new Error("DER integer does not fit in 32 bytes");
  const out = Buffer.alloc(32);
  value.copy(out, 32 - value.length);
  return out;
}

// WebAuthn assertion signatures are DER SEQUENCE { INTEGER r, INTEGER s }.
export function derToRaw(der) {
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  if (buf.length < 8 || buf[0] !== 0x30)
    throw new Error("DER signature must start with SEQUENCE");
  let i = 2;
  let seqLen = buf[1];
  if (buf[1] & 0x80) {
    const nbytes = buf[1] & 0x7f;
    if (nbytes !== 1) throw new Error("DER length is too wide");
    seqLen = buf[2];
    i = 3;
  }
  if (i + seqLen !== buf.length) throw new Error("DER length mismatch");
  if (buf[i] !== 0x02) throw new Error("DER signature is missing r");
  const rLen = buf[i + 1];
  const r = buf.subarray(i + 2, i + 2 + rLen);
  i += 2 + rLen;
  if (i >= buf.length || buf[i] !== 0x02) throw new Error("DER signature is missing s");
  const sLen = buf[i + 1];
  const s = buf.subarray(i + 2, i + 2 + sLen);
  if (i + 2 + sLen !== buf.length) throw new Error("DER signature has trailing bytes");
  return Buffer.concat([derInteger(r), derInteger(s)]);
}

export function assertSignerFixtures() {
  const r = Buffer.alloc(32, 0x11);
  r[0] = 0x80;
  const s = Buffer.alloc(32, 0x22);
  const der = Buffer.concat([
    Buffer.from([0x30, 0x45, 0x02, 0x21, 0x00]),
    r,
    Buffer.from([0x02, 0x20]),
    s,
  ]);
  const raw = derToRaw(der);
  if (raw.length !== 64 || !raw.subarray(0, 32).equals(r) || !raw.subarray(32).equals(s))
    throw new Error("derToRaw failed on a high-bit r");

  const short = Buffer.concat([
    Buffer.from([0x30, 0x25, 0x02, 0x01, 0x7f, 0x02, 0x20]),
    s,
  ]);
  const shortRaw = derToRaw(short);
  if (shortRaw.length !== 64 || shortRaw[31] !== 0x7f || shortRaw[30] !== 0)
    throw new Error("derToRaw failed on a short r");
}
