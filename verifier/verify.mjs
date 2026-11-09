#!/usr/bin/env node
// The one command a stranger runs. Reads only public chain data with no keys and no
// dependencies, then answers: is the box really a box, and does the record hold up?
//
//   node verifier/verify.mjs [vault.testnet] [--json]
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { replay } from "./replay.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const deployment = JSON.parse(readFileSync(join(HERE, "..", "deployment", "testnet.json"), "utf8"));
const RPC = process.env.NEAR_RPC_URL || deployment.rpc;
const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const vault = argv.find((a) => !a.startsWith("--")) || deployment.vault;
const PAGE = 50;

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "allowance", method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(JSON.stringify(body.error));
  if (body.result?.error) throw new Error(body.result.error);
  return body.result;
}

const query = (params) => rpc("query", { finality: "final", ...params });

async function view(method, args = {}) {
  const result = await query({
    request_type: "call_function",
    account_id: vault,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
  });
  return JSON.parse(Buffer.from(result.result).toString());
}

async function allReceipts(count) {
  const out = [];
  while (out.length < count) {
    const page = await view("get_receipts", { from: String(out.length), limit: PAGE });
    if (page.length === 0) break;
    out.push(...page);
  }
  return out;
}

function base58(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  let s = "";
  while (n > 0n) {
    s = alphabet[Number(n % 58n)] + s;
    n /= 58n;
  }
  return s;
}

function near(yocto) {
  const v = BigInt(yocto);
  return `${v / 10n ** 24n}.${(v % 10n ** 24n).toString().padStart(24, "0").slice(0, 4)}`;
}

const checks = [];
const check = (name, pass, detail) => checks.push({ name, pass, detail });

const [{ keys }, account, status] = await Promise.all([
  query({ request_type: "view_access_key_list", account_id: vault }),
  query({ request_type: "view_account", account_id: vault }),
  view("get_status"),
]);

const fullAccess = keys.filter((k) => k.access_key.permission === "FullAccess");
check("No full-access key exists on the vault", fullAccess.length === 0, `${keys.length} key(s) on the account, ${fullAccess.length} full-access`);

const keysOk = keys.every((k) => {
  const f = k.access_key.permission.FunctionCall;
  return f && f.receiver_id === vault && f.method_names.length === 1 && f.method_names[0] === "propose";
});
check("Every key can only call propose on this vault", keys.length > 0 && keysOk, keys.map((k) => JSON.stringify(k.access_key.permission.FunctionCall?.method_names ?? "FullAccess")).join(", "));

const wasmPath = join(HERE, "..", "deployment", "allowance.wasm");
if (existsSync(wasmPath)) {
  const expected = base58(createHash("sha256").update(readFileSync(wasmPath)).digest());
  check("The code on chain is the code in this repo", account.code_hash === expected, `on chain ${account.code_hash}`);
}

const receipts = await allReceipts(Number(status.receipt_count));
// The head is read before the receipts, so a payment landing mid-run looks like a longer chain, not a tamper.
const atHead = receipts.slice(0, Number(status.receipt_count));
const result = replay(atHead, { vault, head: status.head_hash });
check("Hash chain, signatures and spending rules replay clean", result.ok, `${atHead.length} receipts replayed`);

const ok = checks.every((c) => c.pass);
const s = result.summary;

if (asJson) {
  console.log(JSON.stringify({ ok, vault, checks, problems: result.problems, summary: { ...s, spentYocto: s.spentYocto.toString(), blockedYocto: s.blockedYocto.toString() }, head: status.head_hash }, null, 2));
} else {
  console.log(`\nALLOWANCE verifier: ${vault} on testnet\n`);
  for (const c of checks) console.log(`  ${c.pass ? "PASS" : "FAIL"}  ${c.name}\n        ${c.detail}`);
  for (const p of result.problems) console.log(`  FAIL  receipt ${p.seq} [${p.check}] ${p.message}`);
  console.log(`\n  Paid out:   ${near(s.spentYocto)} NEAR in ${s.allowed - s.settlementFailed} payment(s)`);
  console.log(`  Refused:    ${near(s.blockedYocto)} NEAR in ${s.blocked} attempt(s) ${JSON.stringify(s.blockReasons)}`);
  console.log(`  Frozen now: ${status.paused ? `yes (${status.pause_reason})` : "no"}`);
  if (s.unsettled.length) console.log(`  Awaiting settlement: receipts ${s.unsettled.join(", ")}`);
  console.log(`  Head:       ${status.head_hash}`);
  console.log(`\n  ${ok ? "GREEN: the box held and the record is intact." : "RED: do not trust this vault."}\n`);
}
process.exit(ok ? 0 : 1);
