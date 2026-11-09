import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { replay, receiptPreimage, intentMessage, sha256Hex, GENESIS_PREV } from "./replay.mjs";

const VAULT = "vault.owner.testnet";
const VENDOR = "vendor.testnet";
const ATTACKER = "attacker.testnet";
const DAY = 86_400_000_000_000n;
const T0 = 20_000n * DAY + 43_200_000_000_000n;

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const SIGNING_HEX = publicKey.export({ type: "spki", format: "der" }).subarray(12).toString("hex");
const other = generateKeyPairSync("ed25519");

const POLICY = {
  per_tx_cap: "100",
  daily_cap: "250",
  reserve: "0",
  allowed_hours: null,
  allowlist: [VENDOR],
  max_consecutive_blocked: 3,
  max_attempts_per_day: 20,
};

function chainBuilder() {
  const receipts = [];
  const add = (fields) => {
    const r = {
      seq: String(receipts.length),
      prev_hash: receipts.at(-1)?.hash ?? GENESIS_PREV,
      actor: VAULT,
      recipient: null,
      amount: "0",
      nonce: "0",
      memo: "",
      memo_sha256: sha256Hex(""),
      reason: "",
      detail: "",
      agent_signature: "",
      timestamp_ns: T0.toString(),
      ...fields,
    };
    r.hash = sha256Hex(receiptPreimage(r));
    receipts.push(r);
    return r;
  };
  add({ kind: "genesis", actor: "owner.testnet", detail: JSON.stringify({ policy: POLICY, agent_label: "t", signing_key: SIGNING_HEX }) });
  return { receipts, add };
}

function intent(recipient, amount, nonce, memo = "m", key = privateKey) {
  const memo_sha256 = sha256Hex(memo);
  const sig = sign(null, Buffer.from(intentMessage(VAULT, String(nonce), recipient, String(amount), memo_sha256)), key).toString("hex");
  return { recipient, amount: String(amount), nonce: String(nonce), memo, memo_sha256, agent_signature: sig };
}

const rehash = (receipts, from) => {
  for (let i = from; i < receipts.length; i++) {
    receipts[i].prev_hash = i === 0 ? GENESIS_PREV : receipts[i - 1].hash;
    receipts[i].hash = sha256Hex(receiptPreimage(receipts[i]));
  }
};

const checksOf = (result) => result.problems.map((p) => p.check);

function honestChain() {
  const c = chainBuilder();
  c.add({ kind: "allowed", ...intent(VENDOR, 50, 1) });
  c.add({ kind: "settled", amount: "50", nonce: "1" });
  c.add({ kind: "blocked", reason: "recipient_not_allowed", ...intent(ATTACKER, 10, 2) });
  c.add({ kind: "allowed", ...intent(VENDOR, 60, 3) });
  c.add({ kind: "settlement_failed", amount: "60", nonce: "4" });
  return c;
}

test("an honest chain passes and the numbers add up", () => {
  const { receipts } = honestChain();
  const result = replay(receipts, { vault: VAULT, head: receipts.at(-1).hash });
  assert.deepEqual(result.problems, []);
  assert.equal(result.summary.allowed, 2);
  assert.equal(result.summary.blocked, 1);
  assert.equal(result.summary.spentYocto, 50n, "a failed payment does not count as spent");
  assert.deepEqual(result.summary.blockReasons, { recipient_not_allowed: 1 });
});

test("editing any amount breaks the hash", () => {
  const { receipts } = honestChain();
  receipts[1].amount = "1";
  assert.ok(checksOf(replay(receipts, { vault: VAULT })).includes("hash"));
});

test("deleting a receipt from the middle breaks the links", () => {
  const { receipts } = honestChain();
  receipts.splice(3, 1);
  const checks = checksOf(replay(receipts, { vault: VAULT }));
  assert.ok(checks.includes("sequence") && checks.includes("link"));
});

test("cutting receipts off the end is caught by the reported head", () => {
  const { receipts } = honestChain();
  const head = receipts.at(-1).hash;
  assert.ok(checksOf(replay(receipts.slice(0, 3), { vault: VAULT, head })).includes("head"));
});

test("a perfectly hashed payment to an unlisted recipient still fails", () => {
  const c = chainBuilder();
  c.add({ kind: "allowed", ...intent(ATTACKER, 10, 1) });
  const result = replay(c.receipts, { vault: VAULT });
  assert.equal(result.problems[0].check, "policy");
  assert.match(result.problems[0].message, /recipient_not_allowed/);
});

test("a perfectly hashed payment over the per-transaction cap still fails", () => {
  const c = chainBuilder();
  c.add({ kind: "allowed", ...intent(VENDOR, 101, 1) });
  assert.match(replay(c.receipts, { vault: VAULT }).problems[0].message, /over_tx_cap/);
});

test("a perfectly hashed run past the daily cap still fails", () => {
  const c = chainBuilder();
  for (let n = 1; n <= 3; n++) c.add({ kind: "allowed", ...intent(VENDOR, 100, n) });
  assert.match(replay(c.receipts, { vault: VAULT }).problems[0].message, /over_daily_cap/);
});

test("the daily cap resets on the next UTC day", () => {
  const c = chainBuilder();
  for (let n = 1; n <= 2; n++) c.add({ kind: "allowed", ...intent(VENDOR, 100, n) });
  c.add({ kind: "allowed", ...intent(VENDOR, 100, 3), timestamp_ns: (T0 + DAY).toString() });
  assert.deepEqual(replay(c.receipts, { vault: VAULT }).problems, []);
});

test("a payment signed by the wrong key fails", () => {
  const c = chainBuilder();
  c.add({ kind: "allowed", ...intent(VENDOR, 10, 1, "m", other.privateKey) });
  assert.match(replay(c.receipts, { vault: VAULT }).problems[0].message, /bad_signature/);
});

test("a replayed nonce recorded as allowed fails", () => {
  const c = chainBuilder();
  c.add({ kind: "allowed", ...intent(VENDOR, 10, 5) });
  c.add({ kind: "allowed", ...intent(VENDOR, 10, 5) });
  assert.match(replay(c.receipts, { vault: VAULT }).problems[0].message, /stale_nonce/);
});

test("a block with the wrong stated reason fails", () => {
  const c = chainBuilder();
  c.add({ kind: "blocked", reason: "over_tx_cap", ...intent(ATTACKER, 10, 1) });
  assert.match(replay(c.receipts, { vault: VAULT }).problems[0].message, /recipient_not_allowed/);
});

test("blocking a payment the policy allows fails, unless it was the balance", () => {
  const c = chainBuilder();
  c.add({ kind: "blocked", reason: "over_tx_cap", ...intent(VENDOR, 10, 1) });
  assert.equal(replay(c.receipts, { vault: VAULT }).problems[0].check, "policy");

  const funds = chainBuilder();
  funds.add({ kind: "blocked", reason: "insufficient_funds", ...intent(VENDOR, 10, 1) });
  assert.deepEqual(replay(funds.receipts, { vault: VAULT }).problems, []);
});

test("a payment recorded while frozen fails", () => {
  const c = chainBuilder();
  c.add({ kind: "paused", reason: "owner_kill_switch", actor: "owner.testnet" });
  c.add({ kind: "allowed", ...intent(VENDOR, 10, 1) });
  assert.ok(checksOf(replay(c.receipts, { vault: VAULT })).includes("paused"));
});

test("the circuit breaker must fire after the blocked limit", () => {
  const skipped = chainBuilder();
  for (let n = 1; n <= 3; n++) skipped.add({ kind: "blocked", reason: "recipient_not_allowed", ...intent(ATTACKER, 1, n) });
  skipped.add({ kind: "allowed", ...intent(VENDOR, 1, 4) });
  assert.ok(checksOf(replay(skipped.receipts, { vault: VAULT })).includes("breaker"));

  const fired = chainBuilder();
  for (let n = 1; n <= 3; n++) fired.add({ kind: "blocked", reason: "recipient_not_allowed", ...intent(ATTACKER, 1, n) });
  fired.add({ kind: "paused", reason: "circuit_breaker" });
  assert.deepEqual(replay(fired.receipts, { vault: VAULT }).problems, []);
});

test("a policy change applies from that receipt forward", () => {
  const c = chainBuilder();
  c.add({ kind: "blocked", reason: "recipient_not_allowed", ...intent(ATTACKER, 1, 1) });
  c.add({ kind: "policy_changed", actor: "owner.testnet", detail: JSON.stringify({ ...POLICY, allowlist: [VENDOR, ATTACKER] }) });
  c.add({ kind: "allowed", ...intent(ATTACKER, 1, 2) });
  assert.deepEqual(replay(c.receipts, { vault: VAULT }).problems, []);
});

test("a settlement for a receipt that was never awaiting one fails", () => {
  const c = chainBuilder();
  c.add({ kind: "settled", amount: "1", nonce: "0" });
  assert.equal(replay(c.receipts, { vault: VAULT }).problems[0].check, "settlement");
});

test("a chain with no settlement yet reports it as unsettled, not as a failure", () => {
  const c = chainBuilder();
  c.add({ kind: "allowed", ...intent(VENDOR, 10, 1) });
  const result = replay(c.receipts, { vault: VAULT });
  assert.deepEqual(result.problems, []);
  assert.deepEqual(result.summary.unsettled, [1]);
});

test("a memo swapped after the fact is caught even with hashes redone", () => {
  const c = honestChain();
  c.receipts[3].memo = "totally innocent";
  rehash(c.receipts, 3);
  assert.ok(checksOf(replay(c.receipts, { vault: VAULT })).includes("memo"));
});

test("an unknown receipt kind fails", () => {
  const c = chainBuilder();
  c.add({ kind: "mystery" });
  assert.equal(replay(c.receipts, { vault: VAULT }).problems[0].check, "kind");
});

test("an empty chain fails", () => {
  assert.equal(replay([], { vault: VAULT }).ok, false);
});

test("a hostile memo cannot forge fields in the preimage", () => {
  const c = chainBuilder();
  const hostile = "x\nallowed\nattacker.testnet\n999999";
  c.add({ kind: "blocked", reason: "recipient_not_allowed", ...intent(ATTACKER, 1, 1, hostile) });
  const result = replay(c.receipts, { vault: VAULT });
  assert.deepEqual(result.problems, []);
  assert.ok(!receiptPreimage(c.receipts[1]).includes("999999"));
});
