# Passkey firewall v2

WebAuthn-native P-256 gate. The authenticator signs
`authenticatorData || SHA-256(clientDataJSON)`, and the hook verifies
`SHA-256` of that concatenation with `util_verify_p256`.

The 53-byte payment payload is the WebAuthn **challenge**, not the signed digest. The hook
rebuilds it from the transaction and accepts the assertion only when `clientDataJSON`'s
challenge decodes to those exact bytes. A login assertion, or an assertion for a different
amount or destination, does not authorize this payment.

v1 is a different hook. A v1 memo does not satisfy v2. See [v1](../v1/README.md) and the
[comparison](../README.md).

- Hook: [`passkey_p256_firewall_v2.c`](passkey_p256_firewall_v2.c)
- Challenge and `clientDataJSON` checks: [`passkey_v2.h`](passkey_v2.h)
- Signer: [`sign.mjs`](sign.mjs)
- Devnet test: [`test-devnet.mjs`](test-devnet.mjs)
- Parser checks: [`test-parse.c`](test-parse.c), run by `./build.sh`

Shared network details are in the [root README](../README.md). This hook needs
`HooksUpdate2` (`util_sha256`, `util_verify_p256`).

## What the hook checks

1. Rebuild the 53-byte challenge. Payments use direction, `Sequence`, counterparty, and drops. Every other gated type uses kind byte `2`, `Sequence`, and the transaction hash described below.
2. Read the one `xahau.passkey.v2` memo.
3. `authenticatorData` is 37 to 128 bytes, its first 32 bytes equal state `RP`, and the
   flags include user presence (`0x01`) and user verification (`0x04`).
4. `clientDataJSON` is printable ASCII with no backslashes and no spaces. It contains
   one `"type":"webauthn.get"`, one `"origin":"<OR>"`, and one `"challenge":"<base64url>"`.
   The challenge decodes to the 53-byte payload (71 unpadded base64url characters).
5. Verify `r || s` over `SHA-256(authenticatorData || SHA-256(clientDataJSON))` with `PX` and `PY`.

`signCount` is not checked. Apple passkeys often leave it at 0. The backup-eligible flag
is not rejected, so a synced passkey can pass this gate. The check is that this passkey
signed this payment, not that the key is unable to leave the device.

## Payment challenge (53 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 16 | ASCII `xahau.passkey.v2` |
| 16 | 1 | `0` outgoing, `1` incoming |
| 17 | 8 | tx `Sequence` as uint64 big-endian |
| 25 | 20 | the other party: `Destination` when outgoing, source `Account` when incoming |
| 45 | 8 | drop count as uint64 big-endian, not the XRPL amount encoding |

Pass those 53 raw bytes as the WebAuthn `challenge` (`BufferSource`). The browser
base64url-encodes them into `clientDataJSON`. Do not pass the hex or the base64 text.

## Memo

`MemoType` is `xahau.passkey.v2`.

| Field | Size |
|-------|------|
| authenticatorData length | uint16 big-endian |
| authenticatorData | 37..128 bytes |
| clientDataJSON length | uint16 big-endian |
| clientDataJSON | 1..220 bytes, the browser's exact bytes |
| signature | `r \|\| s`, 32 bytes each |

WebAuthn returns the signature as DER. `derToRaw` in `sign.mjs` turns that into `r || s`
without signing again. `authenticatorData` and `clientDataJSON` are copied unchanged.

## State

| Key | Size | Meaning |
|-----|------|---------|
| `PX` | 32 | P-256 public key X, from the passkey COSE key |
| `PY` | 32 | P-256 public key Y |
| `RP` | 32 | `SHA-256` of the relying party id, for example `passkey.xahau-dev.net` |
| `OR` | 8..64 | exact origin, for example `https://passkey.xahau-dev.net` |
| `MODE` | 1 | `0` outgoing (default), `1` incoming, `2` both |
| `LV` | 1 | `1` payments (default), `2` value and account control, `3` every outgoing transaction |

`OR` is ASCII without quotes, backslashes, or spaces. A gated transaction rolls back until
`PX`, `PY`, `RP`, and `OR` are all set. The owner sets them with an Invoke.

`LV` unset is level 1: only native payments are gated, and every other type passes. Level 2 also gates outgoing value and account-control transactions, including Invoke, so the configuration cannot be changed without a passkey. `SetHook` still passes at level 2, which is how the account key removes the hook if the passkey is lost. Level 3 gates every outgoing transaction the hook runs on, including `SetHook`. Incoming non-payments pass at every level. A lost passkey at level 3 cannot remove the hook.

Payments keep the payment challenge above. Any other gated transaction uses this 53-byte challenge instead. Pass those raw bytes as the WebAuthn `challenge`.

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 16 | ASCII `xahau.passkey.v2` |
| 16 | 1 | `2` |
| 17 | 4 | tx `Sequence` as uint32 big-endian |
| 21 | 32 | SHA-256 of the serialized tx with `Memos`, `TxnSignature`, and `Signers` removed |

`SigningPubKey` stays in that hash. The whole serialized transaction, memos included, must be at most 2048 bytes. At level 1 the owner Invoke is unsigned. At level 2 and 3 the Invoke is signed with this challenge, and then the parameters are applied. The same 220-byte `clientDataJSON` rules apply. Kind byte `2` keeps the challenge at 53 bytes, so the base64url form is still 71 characters.

## Browser

```javascript
const challenge = payload; // 53 raw bytes, Sequence already chosen
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge,
    rpId: "passkey.xahau-dev.net",
    userVerification: "required",
    allowCredentials: [{ type: "public-key", id: credentialId }],
  },
});
// assertion.response.authenticatorData
// assertion.response.clientDataJSON
// derToRaw(assertion.response.signature) → 64-byte r||s
```

`userVerification: "required"` is what sets the UV flag this hook demands.

## Build and test

From the repo root:

```bash
npm install
./v2/build.sh
node v2/test-devnet.mjs
```

`./v2/build.sh` writes `passkey_p256_firewall_v2.wasm` and runs `test-parse.c`. The devnet
test installs the hook unnamed and checks:

- A valid assertion is accepted outgoing, and incoming once `MODE` is `2`.
- No memo, a v1 memo, a truncated v2 memo, a tampered signature, a challenge for a different
  amount, a different rpId, a missing UV flag, and a `webauthn.create` assertion are rejected.
- Incoming is allowed while `MODE` is `0`.
- An Invoke from another account is rejected.
- A native partial payment is rejected by the devnet before the hook runs.
- At level 1 an `AccountSet` passes. At level 2 it rolls back unless the transaction-hash
  challenge matches, and a payment challenge does not count.
- At level 2 an unsigned Invoke rolls back and a `SetHook` passes through the hook. A signed
  Invoke can raise `LV` to 3. At level 3 a `SetHook` that would delete the hook rolls back,
  and the hook stays installed.

Do not set `HookName`. `HookOn` runs the hook for every transaction type except
`GenesisMint`, `Amendment`, `Fee`, `UNLModify`, `EmitFailure`, and `UNLReport`:

`00000000000000000000000000000000000001F1000000000000000000400000`

Bit 22 (`SetHook`) is active-high. The other bits are active-low.

## Limits

Replay protection is the `Sequence` inside the challenge. At level 1, key rotation does not
ask for the old passkey. At level 2 and 3 the Invoke that changes state needs this passkey.
DestinationTag and Fee are not in the payment challenge. They are covered for every other
gated type, because that challenge hashes the canonical transaction. `clientDataJSON` must
be the compact form browsers emit, at most 220 bytes: no escapes, no spaces, and the type,
challenge, and origin tokens written as JSON strings. The hook proves this P-256 key signed
this transaction inside WebAuthn. It does not replace the Xahau account signature. A
transaction larger than 2048 serialized bytes cannot be authorized and rolls back when its
type is gated. A `SetHook` carrying this wasm is larger than that, so at level 3 delete
the hook with a small passkey-signed `SetHook` before installing a replacement.
