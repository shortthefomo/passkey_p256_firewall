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

## Payment payload (53 bytes)

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
| `LV` | 1 | `1` payments (default), `2` value and account control, `3` every outgoing transaction |

The owner sets these with an Invoke. Parameter names are the ASCII keys. `MODE` `02` gates both directions. A gated transaction without `PX` and `PY`, or without a valid memo, rolls back. IOUs on a gated payment path roll back. `tfPartialPayment` rolls back.

`LV` unset is level 1: only native payments are gated, and every other type passes. Level 2 also gates outgoing value and account-control transactions, including Invoke, so the configuration cannot be changed without a passkey. `SetHook` still passes at level 2, which is how the account key removes the hook if the passkey is lost. Level 3 gates every outgoing transaction the hook runs on, including `SetHook`. Incoming non-payments pass at every level. A lost passkey at level 3 cannot remove the hook.

Payments keep the payment payload above. Any other gated transaction uses this 53-byte payload instead:

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 16 | ASCII `xahau.passkey.v1` |
| 16 | 1 | `2` |
| 17 | 4 | tx `Sequence` as uint32 big-endian |
| 21 | 32 | SHA-256 of the serialized tx with `Memos`, `TxnSignature`, and `Signers` removed |

`SigningPubKey` stays in that hash. The whole serialized transaction, memos included, must be at most 2048 bytes. At level 1 the owner Invoke is unsigned. At level 2 and 3 the Invoke is signed with this payload, and then `PX`, `PY`, `MODE`, and `LV` are applied.

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
- At level 1 an `AccountSet` passes. At level 2 it rolls back unless the transaction-hash signature matches, and a payment signature does not count.
- At level 2 an unsigned Invoke rolls back and a `SetHook` passes through the hook. A signed Invoke can raise `LV` to 3. At level 3 a `SetHook` that would delete the hook rolls back, and the hook stays installed.

Do not set `HookName`. A named hook runs only when the transaction repeats that name.

## Install

`HookOn` runs the hook for every transaction type except `GenesisMint`, `Amendment`,
`Fee`, `UNLModify`, `EmitFailure`, and `UNLReport`:

`00000000000000000000000000000000000001F1000000000000000000400000`

Bit 22 (`SetHook`) is active-high. The other bits are active-low.

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

Replay protection is the `Sequence` inside the payload. At level 1, anyone who can sign
the Invoke can replace `PX` and `PY`. At level 2 and 3 that Invoke needs the passkey.
DestinationTag, Fee, and flags other than the partial-payment bit are not in the payment
payload. They are covered for every other gated type, because that payload hashes the
canonical transaction. The hook proves this P-256 key authorized the transaction. It does
not replace the Xahau account signature. A transaction larger than 2048 serialized bytes
cannot be authorized and rolls back when its type is gated.
