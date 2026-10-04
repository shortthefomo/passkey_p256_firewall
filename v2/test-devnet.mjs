// Deploy passkey_p256_firewall_v2.wasm on the Passkey Hook Devnet and exercise it.
//
//   ws:      wss://passkey.xahau-dev.net
//   rpc:     https://rpc.passkey.xahau-dev.net
//   faucet:  https://faucet.passkey.xahau-dev.net/accounts
//   network: 21339
//
// Server I/O uses xrpl-client. Signing uses xrpl-accountlib, which loads this
// network's definitions (SetHook, Invoke, NetworkID) at runtime.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  binary,
  derive,
  libraries,
  signAndSubmit,
  utils,
  XrplClient,
  XrplDefinitions,
} from "xrpl-accountlib";
import {
  assertSignerFixtures,
  authenticatorData,
  buildPayload,
  buildTxPayload,
  clientDataJSON,
  DEVICE_FLAGS,
  FLAG_UP,
  generatePasskey,
  memoFromWebAuthn,
  sha256,
  signWebAuthn,
  verifyPayload,
} from "./sign.mjs";

const { decodeAccountID } = libraries.rippleAddressCodec;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(HERE, "passkey_p256_firewall_v2.wasm");
const RP_ID = "passkey.xahau-dev.net";
const ORIGIN = "https://passkey.xahau-dev.net";
const WSS = process.env.XAHAU_WSS || "wss://passkey.xahau-dev.net";
const FAUCET = process.env.XAHAU_FAUCET || "https://faucet.passkey.xahau-dev.net/accounts";
const NETWORK_ID = Number(process.env.XAHAU_NETWORK_ID || 21339);
const TX_FEE = "2000000"; // 2 XAH, covers hook execution

const results = [];

function log(...args) {
  process.stdout.write(args.map(String).join(" ") + "\n");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function txResult(res) {
  return (
    res?.result?.meta?.TransactionResult ||
    res?.result?.metadata?.TransactionResult ||
    res?.result?.engine_result ||
    res?.engine_result ||
    "unknown"
  );
}

function hookExecutions(res) {
  const meta = res?.result?.meta || res?.result?.metadata || res?.meta || {};
  const execs = meta.HookExecutions || [];
  return execs.map((entry) => {
    const ex = entry.HookExecution || entry;
    let text = ex.HookReturnString || "";
    if (text && /^[0-9A-Fa-f]+$/.test(text) && text.length % 2 === 0)
      text = Buffer.from(text, "hex").toString("utf8");
    return {
      result: ex.HookResult,
      code: ex.HookReturnCode,
      text: text.replace(/\0+$/, ""),
    };
  });
}

// Every bit except ttHOOK_SET (22) is active-low: 0 runs the hook.
// Bit 22 is active-high: 1 runs the hook on SetHook.
// Network-control types stay off. LV decides which running types roll back.
const HOOK_SKIP = [96, 100, 101, 102, 103, 104];
const HOOK_ON = (() => {
  let mask = 1n << 22n;
  for (const bit of HOOK_SKIP) mask |= 1n << BigInt(bit);
  return mask.toString(16).padStart(64, "0").toUpperCase();
})();

function hookParameters(pairs) {
  const asHex = (value) => {
    const text = String(value);
    if (/^[0-9A-Fa-f]+$/.test(text) && text.length % 2 === 0) return text.toUpperCase();
    return Buffer.from(text, "utf8").toString("hex").toUpperCase();
  };
  return pairs.map(([name, value]) => ({
    HookParameter: {
      HookParameterName: asHex(name),
      HookParameterValue: asHex(value),
    },
  }));
}

async function faucetAccount() {
  for (let attempt = 0; attempt < 6; attempt++) {
    const response = await fetch(FAUCET, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const body = await response.json();
    if (body.account?.secret) {
      const wallet = derive.familySeed(body.account.secret);
      const address = body.account.classicAddress || body.account.address;
      if (wallet.address !== address)
        throw new Error(`seed derived ${wallet.address}, faucet said ${address}`);
      return {
        wallet,
        address,
        secret: body.account.secret,
        balance: body.balance,
      };
    }
    const msg = JSON.stringify(body);
    log("faucet retry", attempt, msg);
    if (/wait|rate/i.test(msg)) {
      await sleep(65000);
      continue;
    }
    throw new Error("faucet failed: " + msg);
  }
  throw new Error("faucet failed after retries");
}

async function preparedTx(client, wallet, tx) {
  const net = await utils.txNetworkAndAccountValues(client, wallet);
  return {
    ...tx,
    Account: wallet.address,
    NetworkID: NETWORK_ID,
    Sequence: tx.Sequence ?? net.txValues.Sequence,
    Fee: tx.Fee || TX_FEE,
    LastLedgerSequence:
      tx.LastLedgerSequence ?? (net.networkInfo.ledgerSequence || 0) + 120,
  };
}

async function submit(client, wallet, tx) {
  const prepared = await preparedTx(client, wallet, tx);
  const submitted = await signAndSubmit(prepared, client, wallet);
  const response = submitted.response || {};
  const prelimResult = response.engine_result || response.error || "unknown";
  const prelimMessage =
    response.engine_result_message || response.error_message || response.error_exception || "";
  log(
    "submit",
    tx.TransactionType,
    "seq",
    prepared.Sequence,
    "fee",
    prepared.Fee,
    "lls",
    prepared.LastLedgerSequence,
    submitted.tx_id
  );
  log("  prelim", prelimResult, prelimMessage);
  const packed = {
    result: response,
    hash: submitted.tx_id,
    sequence: prepared.Sequence,
  };
  // tec* is in the open ledger and consumes Sequence. tem* does not.
  // A validated account_info can still show the old sequence for a moment.
  const applied = /^(tes|tec)/.test(prelimResult);
  const retry = /terQUEUED|terPRE_SEQ|terRETRY/.test(prelimResult);
  if (!applied && !retry) return packed;

  let validated = null;
  for (let i = 0; i < 20; i++) {
    try {
      const txr = await client.send({
        command: "tx",
        transaction: submitted.tx_id,
        binary: false,
      });
      if (txr.validated) {
        validated = txr;
        break;
      }
    } catch {
      // Not in a ledger yet.
    }
    await sleep(1000);
  }
  if (applied) {
    for (let i = 0; i < 20; i++) {
      const info = await client.send({
        command: "account_info",
        account: wallet.address,
        ledger_index: "validated",
      });
      if (info.account_data.Sequence > prepared.Sequence) break;
      await sleep(1000);
    }
  }
  if (validated) {
    const out = { result: validated, hash: submitted.tx_id, sequence: prepared.Sequence };
    log("  ->", txResult(out), hookExecutions(out).map((h) => h.text).join(" | "));
    return out;
  }
  log("  -> not validated", prelimResult);
  return packed;
}

function recordText(name, res, needle) {
  const text = hookExecutions(res).map((h) => h.text).join(" | ");
  const ok = text.includes(needle);
  results.push({
    name,
    ok,
    got: text,
    expected: needle,
    hash: res.hash,
    hooks: hookExecutions(res),
  });
  log(ok ? "PASS" : "FAIL", name, JSON.stringify(text));
  return ok;
}

function record(name, res, expected) {
  const got = txResult(res);
  const hooks = hookExecutions(res);
  const ok = got === expected;
  results.push({ name, ok, got, expected, hash: res.hash, hooks });
  log(ok ? "PASS" : "FAIL", name, "got", got, "expected", expected, res.hash);
  if (!ok) {
    log("  message", res?.result?.engine_result_message || "");
    log("  hooks", JSON.stringify(hooks));
  }
  return ok;
}

async function waitForAccount(client, address) {
  for (let i = 0; i < 30; i++) {
    try {
      const info = await client.send({
        command: "account_info",
        account: address,
        ledger_index: "validated",
      });
      if (info.account_data) return info.account_data;
    } catch {
      // Faucet payment has not validated yet.
    }
    await sleep(2000);
  }
  throw new Error("account was not funded: " + address);
}

async function accountSequence(client, address) {
  // Current ledger, not validated. A hook rejection is already applied here
  // and has consumed Sequence before the validated ledger catches up.
  const info = await client.send({
    command: "account_info",
    account: address,
  });
  return info.account_data.Sequence;
}

async function signedPayment(
  client,
  wallet,
  { destination, drops, direction, counterparty, passkey, amount, payloadDrops, rpId, origin, flags, type }
) {
  const sequence = await accountSequence(client, wallet.address);
  const payload = buildPayload({
    direction,
    sequence,
    counterparty,
    drops: payloadDrops ?? drops,
  });
  const assertion = await signWebAuthn({
    pkcs8: passkey.pkcs8,
    payload,
    rpId: rpId || RP_ID,
    origin: origin || ORIGIN,
    flags: flags ?? DEVICE_FLAGS,
    type: type || "webauthn.get",
  });
  const localOk = await verifyPayload(passkey.raw, assertion.message, assertion.sig);
  if (!localOk) throw new Error("local WebAuthn verify failed before submit");
  return submit(client, wallet, {
    TransactionType: "Payment",
    Account: wallet.address,
    Destination: destination,
    Amount: amount || String(drops),
    Sequence: sequence,
    Fee: TX_FEE,
    Memos: [memoFromWebAuthn(assertion)],
  });
}

async function codecDefinitions(client) {
  const raw = await client.definitions();
  if (raw && typeof raw.FIELDS === "object") return new XrplDefinitions(raw);
  return undefined;
}

function signingPubKey(wallet) {
  const pub = wallet.keypair && wallet.keypair.publicKey;
  if (!pub) throw new Error("wallet is missing keypair.publicKey");
  return pub;
}

function canonicalHex(tx, pub, definitions) {
  const body = { ...tx, SigningPubKey: pub };
  delete body.Memos;
  delete body.TxnSignature;
  delete body.Signers;
  return binary.encode(body, definitions);
}

async function passkeyMemo(prepared, wallet, definitions, passkey) {
  const hex = canonicalHex(prepared, signingPubKey(wallet), definitions);
  const txHash = await sha256(Buffer.from(hex, "hex"));
  const payload = buildTxPayload({ sequence: prepared.Sequence, txHash });
  const assertion = await signWebAuthn({
    pkcs8: passkey.pkcs8,
    payload,
    rpId: RP_ID,
    origin: ORIGIN,
  });
  if (!(await verifyPayload(passkey.raw, assertion.message, assertion.sig)))
    throw new Error("local WebAuthn verify failed before submit");
  return memoFromWebAuthn(assertion);
}

const NAMESPACE =
  "506173736B657930320000000000000000000000000000000000000000000002";

function hookBody(wasmHex) {
  return {
    TransactionType: "SetHook",
    Fee: String((wasmHex.length / 2) * 500 + 2_000_000),
    Hooks: [
      {
        Hook: {
          CreateCode: wasmHex,
          Flags: 1,
          HookApiVersion: 0,
          HookNamespace: NAMESPACE,
          HookOn: HOOK_ON,
        },
      },
    ],
  };
}

function summary() {
  log("---");
  for (const item of results) {
    log(item.ok ? "PASS" : "FAIL", item.name, item.got, item.hash);
  }
  const failed = results.filter((item) => !item.ok).length;
  log(failed ? `${failed} failed` : `${results.length} passed`);
}

async function main() {
  if (!fs.existsSync(WASM_PATH))
    throw new Error("missing wasm; run ./build.sh first");
  const wasmHex = fs.readFileSync(WASM_PATH).toString("hex").toUpperCase();
  log("wasm", fs.statSync(WASM_PATH).size, "bytes");

  assertSignerFixtures();
  const passkey = await generatePasskey();
  const probe = buildPayload({
    direction: 0,
    sequence: 1,
    counterparty: Buffer.alloc(20, 7),
    drops: 1000000n,
  });
  const probeAssertion = await signWebAuthn({
    pkcs8: passkey.pkcs8,
    payload: probe,
    rpId: RP_ID,
    origin: ORIGIN,
  });
  if (!(await verifyPayload(passkey.raw, probeAssertion.message, probeAssertion.sig)))
    throw new Error("signer self-check failed");
  if (probeAssertion.clientData.toString("utf8").indexOf("webauthn.get") < 0)
    throw new Error("clientDataJSON is missing the assertion type");
  log("signer self-check ok");

  if (HOOK_ON !== "00000000000000000000000000000000000001F1000000000000000000400000")
    throw new Error("unexpected HookOn mask " + HOOK_ON);
  log("HookOn", HOOK_ON);

  const client = new XrplClient(WSS);
  try {
    const info = await client.send({ command: "server_info" });
    const server = info.info || info.result?.info;
    log("connected", server.build_version, "network", server.network_id, WSS);
    if (Number(server.network_id) !== NETWORK_ID)
      throw new Error(`unexpected network id ${server.network_id}`);

    const features = await client.send({ command: "feature" });
    const table = features.features || features.result?.features || {};
    const hooksUpdate2 = Object.values(table).find((feature) => feature.name === "HooksUpdate2");
    log("HooksUpdate2", hooksUpdate2?.enabled ? "enabled" : "MISSING");
    if (!hooksUpdate2?.enabled) throw new Error("HooksUpdate2 is not enabled");

    log("funding owner");
    const owner = await faucetAccount();
    log("owner", owner.address, "balance", owner.balance);
    log("funding counterparty");
    const other = await faucetAccount();
    log("counterparty", other.address, "balance", other.balance);
    await waitForAccount(client, owner.address);
    await waitForAccount(client, other.address);
    log("both accounts are in a validated ledger");

    const ownerId = Buffer.from(decodeAccountID(owner.address));
    const otherId = Buffer.from(decodeAccountID(other.address));

    // Leave the hook unnamed. A HookName makes it opt-in, so a transaction
    // can skip the firewall by omitting the name.
    const setHook = await submit(client, owner.wallet, hookBody(wasmHex));
    record("install hook", setHook, "tesSUCCESS");
    if (txResult(setHook) !== "tesSUCCESS") {
      log("install failed, stopping");
      writeWallets(owner, other, passkey);
      summary();
      process.exitCode = 1;
      return;
    }

    const configure = await submit(client, owner.wallet, {
      TransactionType: "Invoke",
      Account: owner.address,
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([
        ["PX", passkey.x.toString("hex")],
        ["PY", passkey.y.toString("hex")],
        ["RP", (await sha256(Buffer.from(RP_ID, "utf8"))).toString("hex")],
        ["OR", ORIGIN],
        ["MODE", "00"],
      ]),
    });
    record("configure PX PY RP OR MODE=0", configure, "tesSUCCESS");

    const bareOut = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Fee: TX_FEE,
    });
    record("outgoing without memo rejected", bareOut, "tecHOOK_REJECTED");

    const goodOut = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
    });
    record("outgoing with valid WebAuthn assertion accepted", goodOut, "tesSUCCESS");

    const sequence = await accountSequence(client, owner.address);
    const badPayload = buildPayload({
      direction: 0,
      sequence,
      counterparty: otherId,
      drops: 1000000n,
    });
    const badAssertion = await signWebAuthn({
      pkcs8: passkey.pkcs8,
      payload: badPayload,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    badAssertion.sig[0] ^= 0xff;
    const tampered = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Sequence: sequence,
      Fee: TX_FEE,
      Memos: [memoFromWebAuthn(badAssertion)],
    });
    record("outgoing with tampered signature rejected", tampered, "tecHOOK_REJECTED");

    const wrongAmount = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 2000000n,
      payloadDrops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
      amount: "2000000",
    });
    record("outgoing signed for a different amount rejected", wrongAmount, "tecHOOK_REJECTED");

    const wrongRp = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
      rpId: "evil.example",
    });
    record("outgoing with a different rpId rejected", wrongRp, "tecHOOK_REJECTED");

    const noUv = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
      flags: FLAG_UP,
    });
    record("outgoing without user verification rejected", noUv, "tecHOOK_REJECTED");

    const wrongType = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
      type: "webauthn.create",
    });
    record("outgoing registration assertion rejected", wrongType, "tecHOOK_REJECTED");

    const v1Memo = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Fee: TX_FEE,
      Memos: [
        {
          Memo: {
            MemoType: Buffer.from("xahau.passkey.v1").toString("hex").toUpperCase(),
            MemoData: "ab".repeat(64),
          },
        },
      ],
    });
    record("v1 memo does not satisfy v2", v1Memo, "tecHOOK_REJECTED");

    const { auth } = await authenticatorData({ rpId: RP_ID });
    const truncated = clientDataJSON({ payload: probe, origin: ORIGIN });
    const shortMemo = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Fee: TX_FEE,
      Memos: [
        {
          Memo: {
            MemoType: Buffer.from("xahau.passkey.v2").toString("hex").toUpperCase(),
            MemoData: Buffer.concat([
              Buffer.from([0x00, 0x25]),
              auth,
              Buffer.from([0x00, truncated.length]),
              truncated,
            ]).toString("hex").toUpperCase(),
          },
        },
      ],
    });
    record("truncated v2 memo rejected", shortMemo, "tecHOOK_REJECTED");

    const incomingOpen = await submit(client, other.wallet, {
      TransactionType: "Payment",
      Account: other.address,
      Destination: owner.address,
      Amount: "1000000",
      Fee: TX_FEE,
    });
    record("incoming allowed while MODE=0", incomingOpen, "tesSUCCESS");

    const stranger = await submit(client, other.wallet, {
      TransactionType: "Invoke",
      Account: other.address,
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([["MODE", "02"]]),
    });
    record("configure from non-owner rejected", stranger, "tecHOOK_REJECTED");

    const both = await submit(client, owner.wallet, {
      TransactionType: "Invoke",
      Account: owner.address,
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([["MODE", "02"]]),
    });
    record("set MODE=2", both, "tesSUCCESS");

    const incomingBlocked = await submit(client, other.wallet, {
      TransactionType: "Payment",
      Account: other.address,
      Destination: owner.address,
      Amount: "1000000",
      Fee: TX_FEE,
    });
    record("incoming without memo rejected in MODE=2", incomingBlocked, "tecHOOK_REJECTED");

    const incomingSigned = await signedPayment(client, other.wallet, {
      destination: owner.address,
      drops: 1000000n,
      direction: 1,
      counterparty: otherId,
      passkey,
    });
    record("incoming with valid WebAuthn assertion accepted", incomingSigned, "tesSUCCESS");

    const partialSeq = await accountSequence(client, owner.address);
    const partialPayload = buildPayload({
      direction: 0,
      sequence: partialSeq,
      counterparty: otherId,
      drops: 1000000n,
    });
    const partialAssertion = await signWebAuthn({
      pkcs8: passkey.pkcs8,
      payload: partialPayload,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    const partial = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Sequence: partialSeq,
      Fee: TX_FEE,
      Flags: 0x00020000,
      Memos: [memoFromWebAuthn(partialAssertion)],
    });
    // This devnet rejects a native partial before hooks run. The hook still
  // refuses tfPartialPayment if a partial payment is applied.
  record("partial payment rejected", partial, "temBAD_SEND_NATIVE_PARTIAL");

    const definitions = await codecDefinitions(client);
    log("definitions", definitions ? "network" : "codec default");

    const openSet = await submit(client, owner.wallet, {
      TransactionType: "AccountSet",
      SetFlag: 8,
      Fee: TX_FEE,
    });
    record("AccountSet allowed at level 1", openSet, "tesSUCCESS");

    const level2 = await submit(client, owner.wallet, {
      TransactionType: "Invoke",
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([["LV", "02"]]),
    });
    record("set LV=2", level2, "tesSUCCESS");

    const blockedSet = await submit(client, owner.wallet, {
      TransactionType: "AccountSet",
      SetFlag: 8,
      Fee: TX_FEE,
    });
    record("AccountSet without memo rejected at level 2", blockedSet, "tecHOOK_REJECTED");

    const payMemoSeq = await accountSequence(client, owner.address);
    const payPayload = buildPayload({
      direction: 0,
      sequence: payMemoSeq,
      counterparty: otherId,
      drops: 1000000n,
    });
    const payAssertion = await signWebAuthn({
      pkcs8: passkey.pkcs8,
      payload: payPayload,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    const payMemo = await submit(client, owner.wallet, {
      TransactionType: "AccountSet",
      SetFlag: 8,
      Sequence: payMemoSeq,
      Fee: TX_FEE,
      Memos: [memoFromWebAuthn(payAssertion)],
    });
    record("payment challenge does not authorize AccountSet", payMemo, "tecHOOK_REJECTED");

    const mismatch = await preparedTx(client, owner.wallet, {
      TransactionType: "AccountSet",
      SetFlag: 8,
      Fee: TX_FEE,
    });
    const mismatchMemo = await passkeyMemo(mismatch, owner.wallet, definitions, passkey);
    mismatch.Domain = "6578616D706C65";
    mismatch.Memos = [mismatchMemo];
    record(
      "AccountSet signed for different fields rejected",
      await submit(client, owner.wallet, mismatch),
      "tecHOOK_REJECTED"
    );

    const goodSet = await preparedTx(client, owner.wallet, {
      TransactionType: "AccountSet",
      SetFlag: 8,
      Fee: TX_FEE,
    });
    goodSet.Memos = [await passkeyMemo(goodSet, owner.wallet, definitions, passkey)];
    record(
      "AccountSet with valid assertion accepted",
      await submit(client, owner.wallet, goodSet),
      "tesSUCCESS"
    );

    const stillPays = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
    });
    record("payment still accepted at level 2", stillPays, "tesSUCCESS");

    const unsignedInvoke = await submit(client, owner.wallet, {
      TransactionType: "Invoke",
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([["LV", "01"]]),
    });
    record("unsigned Invoke rejected at level 2", unsignedInvoke, "tecHOOK_REJECTED");

    const reinstall = await submit(client, owner.wallet, hookBody(wasmHex));
    record("SetHook allowed at level 2", reinstall, "tesSUCCESS");
    recordText("SetHook at level 2 ran and passed through", reinstall, "passthrough");

    const toLevel3 = await preparedTx(client, owner.wallet, {
      TransactionType: "Invoke",
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([["LV", "03"]]),
    });
    toLevel3.Memos = [await passkeyMemo(toLevel3, owner.wallet, definitions, passkey)];
    record(
      "signed Invoke sets LV=3",
      await submit(client, owner.wallet, toLevel3),
      "tesSUCCESS"
    );

    const blockedAt3 = await submit(client, owner.wallet, {
      TransactionType: "AccountSet",
      SetFlag: 8,
      Fee: TX_FEE,
    });
    record("AccountSet without memo rejected at level 3", blockedAt3, "tecHOOK_REJECTED");

    const invokeAt3 = await submit(client, owner.wallet, {
      TransactionType: "Invoke",
      Destination: owner.address,
      Fee: TX_FEE,
      HookParameters: hookParameters([["LV", "01"]]),
    });
    record("unsigned Invoke rejected at level 3", invokeAt3, "tecHOOK_REJECTED");

    const deleteHook = await submit(client, owner.wallet, {
      TransactionType: "SetHook",
      Fee: TX_FEE,
      Hooks: [{ Hook: { CreateCode: "", Flags: 1 } }],
    });
    record("SetHook delete without memo rejected at level 3", deleteHook, "tecHOOK_REJECTED");
    recordText("SetHook at level 3 reached the hook", deleteHook, "passkey:");

    const paysAt3 = await signedPayment(client, owner.wallet, {
      destination: other.address,
      drops: 1000000n,
      direction: 0,
      counterparty: otherId,
      passkey,
    });
    record("payment still accepted at level 3", paysAt3, "tesSUCCESS");

    writeWallets(owner, other, passkey);
    summary();
    const failed = results.filter((item) => !item.ok).length;
    process.exitCode = failed ? 1 : 0;
  } finally {
    client.close();
  }
}

function writeWallets(owner, other, passkey) {
  const walletFile = "/tmp/passkey-v2-devnet-wallets.json";
  fs.writeFileSync(
    walletFile,
    JSON.stringify(
      {
        network: WSS,
        networkId: NETWORK_ID,
        owner: { address: owner.address, secret: owner.secret },
        counterparty: { address: other.address, secret: other.secret },
        passkey: {
          x: passkey.x.toString("hex"),
          y: passkey.y.toString("hex"),
          pkcs8: passkey.pkcs8.toString("hex"),
        },
        results,
      },
      null,
      2
    )
  );
  log("wrote", walletFile);
}

main().catch((error) => {
  log("ERROR", error.stack || error.message);
  summary();
  process.exitCode = 1;
});
