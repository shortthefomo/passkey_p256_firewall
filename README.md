# P-256 Passkey Firewall Hook (iPhone / Secure Enclave)

A Xahau Hook that adds a **second, hardware-bound authorization gate** to an account.
On top of the normal Xahau/XRPL transaction signature, any *gated* movement must also
carry a valid **P-256 (secp256r1) ECDSA** signature produced by an iPhone key. The hook
rebuilds a canonical payload from the real transaction fields, hashes it with **SHA-256**,
and verifies the signature with `util_verify_p256`. If it's missing or invalid, the
transaction **rolls back**.

Result: the ledger still needs a normal Xahau/XRPL signature to *submit* the tx, but this
hook adds a second gate tied to Apple hardware so **"only this device can authorize
movement."**

- Hook source: [`passkey_p256_firewall.c`](passkey_p256_firewall.c)
- Reference signer (Node.js): [`sign.mjs`](sign.mjs)

---

## Where it runs

The hook imports two HookAPI functions from
[xahaud PR #511](https://github.com/Xahau/xahaud/pull/511), gated by the `HooksUpdate2`
amendment:

| Import | Purpose |
|--------|---------|
| `util_sha256(write_ptr, write_len, read_ptr, read_len)` | SHA-256 of a buffer → 32-byte digest (returns `32`) |
| `util_verify_p256(h,hl,r,rl,s,sl,x,xl,y,yl)` | Verify a P-256 ECDSA `(r,s)` over 32-byte `h` with pubkey `(x,y)` → `1`/`0`/error |

The Passkey Hook Devnet already has that amendment enabled (network id **21339**):

| | |
|--|--|
| WebSocket | `wss://passkey.xahau-dev.net` |
| JSON-RPC | `https://rpc.passkey.xahau-dev.net` |
| Explorer | `https://explorer.passkey.xahau-dev.net` |
| Faucet | `POST https://faucet.passkey.xahau-dev.net/accounts` with body `{}` |

A stock node without `HooksUpdate2` rejects the install. The hook declares the two imports
itself because they are not in stock `hook/extern.h`.

Transactions on this network must set `NetworkID` to `21339`.

---

## How it works

```
                 ┌──────────────────────────  iPhone (Secure Enclave)  ──────────────────────────┐
                 │  P-256 keypair (private never leaves the device)                              │
                 └───────────────▲──────────────────────────────────────────────────────────────┘
                                 │ signs SHA-256(payload) → (r, s)
                                 │
   tx fields ──────────────┐     │      Memo:  MemoType = "xahau.passkey.v1"
   (direction, seq,        │     │       MemoData = r || s  (64 bytes)
    counterparty, amount)  ▼     │
   ┌───────────────────────────────┘
   │  hook rebuilds the SAME canonical payload (53 bytes) from the tx fields,
   │  hashes it with util_sha256, and calls util_verify_p256(hash, r, s, PX, PY).
   │  valid → accept()      invalid/missing → rollback()
   └───────────────────────────────────────────────────────────────────────────────
```

The hook never trusts a "payload" the sender writes in a memo. It **recomputes** the
payload from authoritative transaction fields (`Sequence`, `Account`/`Destination`,
`Amount`) and only the *signature* comes from the memo. That's what makes it a real gate:
an attacker who can submit a tx with the account's XRPL key still cannot forge the P-256
signature without the iPhone.

### Canonical signed payload (53 bytes)

The exact byte layout the hook hashes — and that your signer must hash:

| Offset | Length | Field | Value |
|--------|--------|-------|-------|
| 0      | 16     | MAGIC | ASCII `xahau.passkey.v1` |
| 16     | 1      | DIRECTION | `0` = outgoing, `1` = incoming |
| 17     | 8      | SEQUENCE | tx `Sequence` as **big-endian**, zero-extended from 4 → 8 bytes |
| 25     | 20     | COUNTERPARTY | the *other* party's account id (20 bytes): `Destination` for outgoing, source `Account` for incoming |
| 45     | 8      | AMOUNT | drop count as **uint64 big-endian**. This is not the XRPL amount encoding (no `0x40` positive flag). |

The signature is carried in a **Memo**:
- `MemoType` = ASCII `xahau.passkey.v1` (16 bytes)
- `MemoData` = `r || s`, each 32 bytes big-endian (64 bytes total)

### Direction & gating (`MODE`)

`direction` is derived by comparing the tx `Account` to the hook account:
- equal → **outgoing** (we are the source), counterparty = `Destination`
- not equal → **incoming** (we are the destination), counterparty = source `Account`

`MODE` (1 byte, state) selects which directions are gated:
- `0` = gate **outgoing** only (default)
- `1` = gate **incoming** only
- `2` = gate **both**

Non-gated directions are accepted without a signature. This is the "firewall incoming /
outgoing / both" behavior from the design.

---

## State (owned by this hook)

| Key | Size | Meaning |
|-----|------|---------|
| `PX` | 32 bytes | P-256 public key **X** coordinate (big-endian). Required. |
| `PY` | 32 bytes | P-256 public key **Y** coordinate (big-endian). Required. |
| `MODE` | 1 byte | `0`/`1`/`2` as above. Optional, defaults to `0`. |

The hook is **fail-closed**: if a direction is gated but `PX`/`PY` aren't set, or the
amount isn't native (v1), it rolls back.

---

## Triggers

| Trigger | Purpose |
|---------|---------|
| `ttPAYMENT` (0) | The firewall — gates native payments per `MODE`. |
| `ttINVOKE` (99) | Owner-only admin: set/rotate `PX`, `PY`, and/or `MODE`. |

Any other transaction type is accepted untouched.

---

## Getting PX / PY from an iPhone P-256 key

A WebAuthn/passkey **P-256 public key is in COSE format: `x (32) || y (32)`** — exactly
what the hook stores as `PX` and `PY`.

- If you already have a passkey's public key (e.g. from a WebAuthn `PublicKey` credential
  creation response, `response.publicKey`), it's the raw COSE key bytes: first 32 = `PX`,
  next 32 = `PY`.
- To generate a fresh P-256 keypair for testing, see [`sign.mjs`](sign.mjs) — it can print
  `PX`/`PY` in hex.

> The **private** key must stay on the iPhone (Secure Enclave). Only `PX`/`PY` go on-chain.

---

## Signing (producing the memo)

The hook verifies a **plain ECDSA P-256 signature over `SHA-256(payload)`**.

### Option A — reference signer (simplest, for testing)
[`sign.mjs`](sign.mjs) builds the exact 53-byte payload from your tx fields, computes
`SHA-256`, signs with a P-256 key (WebCrypto), and returns the `MemoType`/`MemoData` hex to
attach to your payment. [`test-devnet.mjs`](test-devnet.mjs) uses it against the devnet.

### Option B — a real WebAuthn passkey (the "passkey" in the PR title)
A genuine Secure Enclave passkey signs via **WebAuthn**, and a WebAuthn assertion signature
is over `SHA-256(authenticatorData || clientDataHash)` — **not** directly over the
challenge. So to use a true passkey you have two choices:

1. **Extend the hook** so its canonical payload is `authenticatorData || clientDataHash`
   (with the WebAuthn `challenge` set to a value you also control), then verify that digest.
   This is the fully "passkey-native" flow and keeps signing 100% inside WebAuthn.
2. **Use a signing helper** that performs plain ECDSA over `SHA-256(payload)` (Option A).
   This is what **v1 of this hook implements** and matches `util_verify_p256` directly.

Both keep the private key in the Secure Enclave; they differ only in *what digest* is
signed. v1 = Option A (plain ECDSA over the 53-byte payload).

---

## Build and test

`./build.sh` needs an LLVM clang that ships `wasm-ld` (Homebrew `llvm@14` works;
`llvm@22` on this machine does not). It compiles for `wasm32-unknown-unknown` and strips
custom sections. The guard checker rejects those sections, and it also rejects any
function other than the exported `hook`, so the helpers are `always_inline`.

```bash
cd examples/Passkey_P256_Firewall
./build.sh
npm install
node test-devnet.mjs
```

The test funds two faucet accounts, installs the hook, and checks the accept and reject
cases below. Submit and sign with `xrpl-client` and `xrpl-accountlib`. Those libraries
load this network's field definitions (SetHook, Invoke, NetworkID) from the server.

Do not set `HookName`. A named hook runs only when the transaction repeats that name, so
a payment could skip the firewall by leaving the name off.

## Deployment

1. **Compile** with `./build.sh`.
2. **SetHook** on the target account. `HookOn` for Payment and Invoke is
   `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFFFFBFFFFE`
   (active-low, and `ttHOOK_SET` stays off). Leave the hook unnamed. `Flags` `1` is
   `hsfOVERRIDE`. `HookApiVersion` is `0`. Creation fee is wasm byte count × 500 drops,
   plus enough for execution.
3. **Invoke** from the hook owner to configure `PX`, `PY`, and optionally `MODE`.
   Parameter names and values are hex. `PX` is `5058`, `PY` is `5059`, `MODE` is `4D4F4445`.
4. From then on, gated payments must carry a valid passkey memo or they roll back.

Example admin Invoke (owner only, `NetworkID` 21339 on this devnet):
```jsonc
{
  "TransactionType": "Invoke",
  "Account": "<hook-owner>",
  "NetworkID": 21339,
  "HookParameters": [
    { "HookParameter": { "HookParameterName": "5058", "HookParameterValue": "<64 hex chars, X>" } },
    { "HookParameter": { "HookParameterName": "5059", "HookParameterValue": "<64 hex chars, Y>" } },
    { "HookParameter": { "HookParameterName": "4D4F4445", "HookParameterValue": "02" } }
  ]
}
```

Example gated payment (must include the passkey memo):
```jsonc
{
  "TransactionType": "Payment",
  "Account": "<hook-owner>",
  "NetworkID": 21339,
  "Destination": "<counterparty>",
  "Amount": "1000000",
  "Memos": [ { "Memo": {
      "MemoType": "78616861752e706173736b65792e7631",   // "xahau.passkey.v1"
      "MemoData": "<128 hex chars = r||s>"
  } } ]
}
```

---

## What the devnet test checks

`node test-devnet.mjs` covers:

- Install, then owner Invoke setting `PX`, `PY`, and `MODE=0`.
- Outgoing payment with no memo → `tecHOOK_REJECTED` (`no valid passkey memo found`).
- Outgoing payment with a valid signature → `tesSUCCESS` (`signature accepted`).
- Tampered signature, or a signature over a different amount → `invalid P-256 passkey signature`.
- 63-byte `MemoData` → `MemoData must be 64 bytes`.
- Incoming payment while `MODE=0` → accepted (`direction is not gated`).
- Invoke from another account → `only the hook owner can configure`.
- Owner sets `MODE=2`. Incoming with no memo is rejected. Incoming with a valid signature is accepted.
- Native partial payment → `temBAD_SEND_NATIVE_PARTIAL`. This devnet rejects that before hooks run. The hook also refuses `tfPartialPayment` if a partial payment is applied.

---

## Security notes & limitations (v1)

- **Native amounts only.** IOU payments on a gated direction roll back. Extend the payload
  to include the currency/issuer if you need IOU gating later.
- **Replay protection** comes from binding the tx `Sequence` into the payload — a signature
  is only valid for that exact sequence. The ledger also rejects a reused sequence.
- **Key rotation does not ask for the old passkey.** The owner Invoke is authorized by the
  account's Xahau key. Anyone who can sign for the account can replace `PX`/`PY`.
- **No `HookName`.** A named hook is opt-in and would let a payment skip the firewall.
- **Partial payments.** The hook rejects `tfPartialPayment`. On this devnet a native partial
  never reaches the hook (`temBAD_SEND_NATIVE_PARTIAL`).
- **Not signed:** DestinationTag, Fee, and flags other than the partial-payment bit. v1 binds
  direction, sequence, counterparty, and the drop count.
- **Fail-closed** by design: missing key, malformed memo, or IOU on a gated path all roll back.
- **WebAuthn nuance:** v1 verifies plain ECDSA over `SHA-256(payload)`. For a raw WebAuthn
  passkey assertion, see [Signing → Option B](#signing-producing-the-memo).
- **Trust boundary:** the hook only proves *this P-256 key* authorized the movement. It does
  not replace the Xahau account signature; it's a second factor on top of it.

---

## Files

| File | Description |
|------|-------------|
| [`passkey_p256_firewall.c`](passkey_p256_firewall.c) | The hook (C → WASM). |
| [`build.sh`](build.sh) | Compile with wasm32 clang and strip custom sections. |
| [`sign.mjs`](sign.mjs) | Reference signer: builds the 53-byte payload and signs with P-256. |
| [`test-devnet.mjs`](test-devnet.mjs) | Fund, install, and run the accept/reject cases on the devnet. |
