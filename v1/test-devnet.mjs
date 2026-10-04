// Deploy passkey_p256_firewall_v1.wasm on the Passkey Hook Devnet and exercise it.
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
import { derive, libraries, signAndSubmit, utils, XrplClient } from "xrpl-accountlib";
import {
  buildPayload,
  generatePasskey,
  memoFromSignature,
  signPayload,
  verifyPayload,
} from "./sign.mjs";

const { decodeAccountID } = libraries.rippleAddressCodec;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(HERE, "passkey_p256_firewall_v1.wasm");
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

// Active-low 256-bit mask. The seed already leaves ttHOOK_SET (bit 22) off.
// Passing a name toggles that bit, which turns the hook on for that type.
function calculateHookOn(names) {
  const typeCode = { Payment: 0, Invoke: 99 };
  let mask = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF");
  for (const name of names) {
    const bit = typeCode[name];
    if (bit === undefined) throw new Error("unknown transaction type " + name);
    mask ^= 1n << BigInt(bit);
  }
  return mask.toString(16).padStart(64, "0").toUpperCase();
}

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

async function submit(client, wallet, tx) {
  const net = await utils.txNetworkAndAccountValues(client, wallet);
  const prepared = {
    ...tx,
    Account: wallet.address,
    NetworkID: NETWORK_ID,
    Sequence: tx.Sequence ?? net.txValues.Sequence,
    Fee: tx.Fee || TX_FEE,
    LastLedgerSequence: (net.networkInfo.ledgerSequence || 0) + 120,
  };
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

async function signedPayment(client, wallet, { destination, drops, direction, counterparty, passkey, amount }) {
  const sequence = await accountSequence(client, wallet.address);
  const payload = buildPayload({
    direction,
    sequence,
    counterparty,
    drops,
  });
  const sig = await signPayload(passkey.pkcs8, payload);
  const localOk = await verifyPayload(passkey.raw, payload, sig);
  if (!localOk) throw new Error("local P-256 verify failed before submit");
  return submit(client, wallet, {
    TransactionType: "Payment",
    Account: wallet.address,
    Destination: destination,
    Amount: amount || String(drops),
    Sequence: sequence,
    Fee: TX_FEE,
    Memos: [memoFromSignature(sig)],
  });
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

  const passkey = await generatePasskey();
  const probe = buildPayload({
    direction: 0,
    sequence: 1,
    counterparty: Buffer.alloc(20, 7),
    drops: 1000000n,
  });
  const probeSig = await signPayload(passkey.pkcs8, probe);
  if (!(await verifyPayload(passkey.raw, probe, probeSig)))
    throw new Error("signer self-check failed");
  log("signer self-check ok");

  const on = calculateHookOn(["Payment", "Invoke"]);
  if (on !== "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFFFFFFFFFBFFFFE")
    throw new Error("unexpected HookOn mask " + on);
  log("HookOn", on);

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

    const setHook = await submit(client, owner.wallet, {
      TransactionType: "SetHook",
      Account: owner.address,
      Fee: String((wasmHex.length / 2) * 500 + 2_000_000),
      Hooks: [
        {
          Hook: {
            CreateCode: wasmHex,
            Flags: 1,
            HookApiVersion: 0,
            HookNamespace:
              "506173736B657930310000000000000000000000000000000000000000000001",
            // Leave the hook unnamed. A HookName makes it opt-in: the hook
            // runs only when the transaction repeats that name, so a payment
            // can skip the firewall by omitting it.
            HookOn: on,
          },
        },
      ],
    });
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
        ["MODE", "00"],
      ]),
    });
    record("configure PX PY MODE=0", configure, "tesSUCCESS");

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
    record("outgoing with valid signature accepted", goodOut, "tesSUCCESS");

    const sequence = await accountSequence(client, owner.address);
    const badPayload = buildPayload({
      direction: 0,
      sequence,
      counterparty: otherId,
      drops: 1000000n,
    });
    const badSig = Buffer.from(await signPayload(passkey.pkcs8, badPayload));
    badSig[0] ^= 0xff;
    const tampered = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Sequence: sequence,
      Fee: TX_FEE,
      Memos: [memoFromSignature(badSig)],
    });
    record("outgoing with tampered signature rejected", tampered, "tecHOOK_REJECTED");

    const wrongAmountSeq = await accountSequence(client, owner.address);
    const wrongAmountPayload = buildPayload({
      direction: 0,
      sequence: wrongAmountSeq,
      counterparty: otherId,
      drops: 1000000n,
    });
    const wrongAmountSig = await signPayload(passkey.pkcs8, wrongAmountPayload);
    const wrongAmount = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "2000000",
      Sequence: wrongAmountSeq,
      Fee: TX_FEE,
      Memos: [memoFromSignature(wrongAmountSig)],
    });
    record("outgoing signed for a different amount rejected", wrongAmount, "tecHOOK_REJECTED");

    const shortMemoSeq = await accountSequence(client, owner.address);
    const shortMemo = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Sequence: shortMemoSeq,
      Fee: TX_FEE,
      Memos: [
        {
          Memo: {
            MemoType: Buffer.from("xahau.passkey.v1").toString("hex").toUpperCase(),
            MemoData: "00".repeat(63),
          },
        },
      ],
    });
    record("outgoing with 63-byte MemoData rejected", shortMemo, "tecHOOK_REJECTED");

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
    record("incoming with valid signature accepted", incomingSigned, "tesSUCCESS");

    const partialSeq = await accountSequence(client, owner.address);
    const partialPayload = buildPayload({
      direction: 0,
      sequence: partialSeq,
      counterparty: otherId,
      drops: 1000000n,
    });
    const partialSig = await signPayload(passkey.pkcs8, partialPayload);
    const partial = await submit(client, owner.wallet, {
      TransactionType: "Payment",
      Account: owner.address,
      Destination: other.address,
      Amount: "1000000",
      Sequence: partialSeq,
      Fee: TX_FEE,
      Flags: 0x00020000,
      Memos: [memoFromSignature(partialSig)],
    });
    // This devnet rejects a native partial before hooks run. The hook still
  // refuses tfPartialPayment if a partial payment is applied.
  record("partial payment rejected", partial, "temBAD_SEND_NATIVE_PARTIAL");

    writeWallets(owner, other, passkey);
    summary();
    const failed = results.filter((item) => !item.ok).length;
    process.exitCode = failed ? 1 : 0;
  } finally {
    client.close();
  }
}

function writeWallets(owner, other, passkey) {
  const walletFile = "/tmp/passkey-v1-devnet-wallets.json";
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
