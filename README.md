# P-256 passkey firewall

Two separate Xahau hooks. Each one adds a second signature check on top of the normal
account signature. They do not install together and they do not accept each other's memos.

| | [v1](v1/README.md) | [v2](v2/README.md) |
|--|--|--|
| What is signed | `SHA-256` of a 53-byte payload | `SHA-256(authenticatorData \|\| SHA-256(clientDataJSON))` |
| Where the signature is produced | Any P-256 signer, including WebCrypto | Inside WebAuthn (`navigator.credentials.get`) |
| Memo type | `xahau.passkey.v1` | `xahau.passkey.v2` |
| Memo data | `r \|\| s` (64 bytes) | `authenticatorData`, `clientDataJSON`, and `r \|\| s` |
| What the hook rebuilds | A 53-byte payment payload, or a 53-byte transaction-hash payload | The same payload, and requires it to be the WebAuthn challenge |
| Extra state | `PX`, `PY`, `MODE`, `LV` | Those, plus `RP` (rpId hash) and `OR` (origin) |
| User verification | Not represented. The signer just produces ECDSA | Requires the user-present and user-verified flags |

v1 is the plain ECDSA gate. A browser passkey will not satisfy it, because WebAuthn does
not sign the payload directly.

v2 is the passkey-native gate. The authenticator still signs `authenticatorData || clientDataHash`.
The hook sets the WebAuthn challenge to the 53-byte payload, checks that the signed
`clientDataJSON` contains that challenge, then verifies the WebAuthn digest. An old login
assertion cannot authorize a transaction, because its challenge is not this payload.

Both hooks are fail-closed for a gated transaction: missing key material or a bad memo
rolls the transaction back. Install one hook per account. Leave it unnamed, or a
transaction can skip it by omitting the name.

## Modes

`MODE` is one byte of hook state. It selects which native-payment directions need a
passkey. Unset means `0`. The owner sets it with an Invoke parameter named `MODE`.
The value is one byte: `00`, `01`, or `02`. At level 1 that Invoke is unsigned. At
level 2 and 3 the Invoke must carry a passkey before `MODE` is stored. Other
transaction types follow `LV`. Incoming non-payments pass at every mode.

| `MODE` | Payments that need a passkey |
|--------|------------------------------|
| 0 | Outgoing. Incoming payments pass. |
| 1 | Incoming. Outgoing payments pass. |
| 2 | Both directions. |

An IOU on a gated payment path rolls back. `tfPartialPayment` rolls back. A gated
payment without the stored key, or without a valid memo, rolls back. v1 needs `PX`
and `PY`. v2 also needs `RP` and `OR`.

## Levels

`LV` is one byte of hook state. Unset means level 1. The owner sets it with an Invoke
parameter named `LV`. Payments use the payment payload at every level. Other gated
types use the transaction-hash payload.

| `LV` | What needs a passkey |
|------|----------------------|
| 1 | Native payments, in the directions selected by `MODE`. Every other transaction type passes. |
| 2 | Level 1, plus outgoing value and account-control transactions. Invoke is included, so the key, `MODE`, and `LV` cannot be changed without a passkey. `SetHook` still passes, so the account key can remove the hook. |
| 3 | Every outgoing transaction the hook runs on, including `SetHook` and Invoke. A lost passkey cannot remove the hook. Incoming non-payments still pass. |

Level 2 covers escrow, account and regular-key changes, offers, tickets, signer lists,
payment channels, checks, deposit preauth, trust lines, account delete, NFTs, clawback,
AMM, URI tokens, cross-chain bridge transactions, DID, oracles, ledger-state fix,
MPTokens, credentials, permissioned domains, `CronSet`, remarks, remit, import, claim
reward, and Invoke. `Cron` execution itself is level 3, so a schedule can still fire
at level 2. `SetHook` is level 3.

The hook runs for every transaction type except `GenesisMint`, `Amendment`, `Fee`,
`UNLModify`, `EmitFailure`, and `UNLReport`. `SetHook` is the one active-high bit in
`HookOn` (bit 22), and that bit is set so the hook can see `SetHook`. At level 1 the
extra types pass through.

A non-payment payload is 53 bytes: the 16-byte magic, kind byte `2`, the transaction
`Sequence` as uint32 big-endian, and SHA-256 of the serialized transaction after
`Memos`, `TxnSignature`, and `Signers` are removed. `SigningPubKey` stays in the hash.
The whole serialized transaction, memos included, must be at most 2048 bytes or the
hook rolls it back. A `SetHook` that deletes the hook fits. A `SetHook` that installs
this wasm does not, so at level 3 you delete the hook with a passkey and install the
replacement afterward.

## Devnet

Both versions need `util_sha256` and `util_verify_p256` from
[xahaud PR #511](https://github.com/Xahau/xahaud/pull/511), enabled by the `HooksUpdate2`
amendment. The Passkey Hook Devnet (network id **21339**) already has it:

| | |
|--|--|
| WebSocket | `wss://passkey.xahau-dev.net` |
| JSON-RPC | `https://rpc.passkey.xahau-dev.net` |
| Explorer | `https://explorer.passkey.xahau-dev.net` |
| Faucet | `POST https://faucet.passkey.xahau-dev.net/accounts` with body `{}` |

Transactions on this network set `NetworkID` to `21339`.

## Build and test

Install the shared Node dependencies once from this directory, then build and test the
version you want:

```bash
npm install
./v1/build.sh
node v1/test-devnet.mjs
./v2/build.sh
node v2/test-devnet.mjs
```

`./v1/build.sh` and `./v2/build.sh` need an LLVM clang that ships `wasm-ld`. v2's build
also runs the host checks for the `clientDataJSON` parser.
