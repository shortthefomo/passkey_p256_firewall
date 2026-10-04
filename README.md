# P-256 passkey firewall

Two separate Xahau hooks. Each one adds a second signature check on top of the normal
account signature. They do not install together and they do not accept each other's memos.

| | [v1](v1/README.md) | [v2](v2/README.md) |
|--|--|--|
| What is signed | `SHA-256` of a 53-byte payment payload | `SHA-256(authenticatorData \|\| SHA-256(clientDataJSON))` |
| Where the signature is produced | Any P-256 signer, including WebCrypto | Inside WebAuthn (`navigator.credentials.get`) |
| Memo type | `xahau.passkey.v1` | `xahau.passkey.v2` |
| Memo data | `r \|\| s` (64 bytes) | `authenticatorData`, `clientDataJSON`, and `r \|\| s` |
| What the hook rebuilds | The 53-byte payload | The same 53-byte payload, and requires it to be the WebAuthn challenge |
| Extra state | `PX`, `PY`, `MODE` | Those, plus `RP` (rpId hash) and `OR` (origin) |
| User verification | Not represented. The signer just produces ECDSA | Requires the user-present and user-verified flags |

v1 is the plain ECDSA gate. A browser passkey will not satisfy it, because WebAuthn does
not sign the payload directly.

v2 is the passkey-native gate. The authenticator still signs `authenticatorData || clientDataHash`.
The hook sets the WebAuthn challenge to the 53-byte payment payload, checks that the signed
`clientDataJSON` contains that challenge, then verifies the WebAuthn digest. An old login
assertion cannot authorize a payment, because its challenge is not this payment.

Both hooks are fail-closed for a gated native payment: missing key material or a bad memo
rolls the transaction back. Install one hook per account. Leave it unnamed, or a payment
can skip it by omitting the name.

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
