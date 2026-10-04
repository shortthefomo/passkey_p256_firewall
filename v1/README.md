# Passkey firewall v1

Plain P-256 ECDSA over `SHA-256` of a 53-byte payload. The memo carries only `r || s`.
The hook rebuilds the payload from the transaction, so the memo cannot change the amount,
sequence, or counterparty.

This is not a WebAuthn assertion. A call to `navigator.credentials.get` signs
`authenticatorData || clientDataHash`, and this hook will reject that signature. For that
flow, use [v2](../v2/README.md). The two hooks are separate: a v2 memo does not satisfy v1.

- Hook: [`passkey_p256_firewall_v1.c`](passkey_p256_firewall_v1.c)
- Signer: [`sign.mjs`](sign.mjs)
- Devnet test: [`test-devnet.mjs`](test-devnet.mjs)

Shared network details are in the [root README](../README.md). This hook needs
`HooksUpdate2` (`util_sha256`, `util_verify_p256`).

## Canonical payload (53 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 16 | ASCII `xahau.passkey.v1` |
| 16 | 1 | `0` outgoing, `1` incoming |
| 17 | 8 | tx `Sequence` as uint64 big-endian |
| 25 | 20 | the other party: `Destination` when outgoing, source `Account` when incoming |
| 45 | 8 | drop count as uint64 big-endian, not the XRPL amount encoding |

`MemoType` is `xahau.passkey.v1`. `MemoData` is `r || s`, 32 bytes each.

## State

| Key | Size | Meaning |
|-----|------|---------|
| `PX` | 32 | P-256 public key X |
| `PY` | 32 | P-256 public key Y |
| `MODE` | 1 | `0` outgoing (default), `1` incoming, `2` both |

The owner sets these with an Invoke. Parameter names are the ASCII keys. `MODE` `02` gates both directions. A gated native payment without `PX` and `PY`, or without a valid memo, rolls back. Other transaction types pass through. IOUs on a gated path roll back. `tfPartialPayment` rolls back.

## Build and test

From the repo root:

```bash
npm install
./v1/build.sh
node v1/test-devnet.mjs
```

`./v1/build.sh` writes `passkey_p256_firewall_v1.wasm`. The devnet test funds two faucet
accounts, installs the hook unnamed, and checks the accept and reject cases:

- Outgoing with no memo, a tampered signature, a signature over a different amount, or a 63-byte memo is rejected.
- Outgoing with a valid signature is accepted.
- Incoming is allowed while `MODE` is `0`, and rejected in `MODE` `2` unless the signature matches.
- An Invoke from another account is rejected.
- A native partial payment is rejected by the devnet before the hook runs (`temBAD_SEND_NATIVE_PARTIAL`).

Do not set `HookName`. A named hook runs only when the transaction repeats that name.

## Install

`HookOn` for Payment and Invoke, with `ttHOOK_SET` left off:

`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFFFFBFFFFE`

`Flags` `1` is `hsfOVERRIDE`. `HookApiVersion` is `0`. Creation fee is the wasm size in
bytes times 500 drops, plus enough for execution.

Example memo:

```jsonc
"Memos": [{ "Memo": {
  "MemoType": "78616861752E706173736B65792E7631",
  "MemoData": "<128 hex chars, r||s>"
}}]
```

`sign.mjs` builds that memo from the same payload the hook rebuilds.

## Limits

Replay protection is the `Sequence` inside the payload. Key rotation does not ask for the
old P-256 key; anyone who can sign the Invoke can replace `PX` and `PY`. DestinationTag,
Fee, and flags other than the partial-payment bit are not in the payload. The hook proves
this P-256 key authorized the movement. It does not replace the Xahau account signature.
