// These receipts were written by the contract on NEAR testnet. Replaying them offline
// proves the Rust contract and this JavaScript verifier agree on every hash and rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { replay, receiptPreimage, sha256Hex } from "./replay.mjs";

const load = () => JSON.parse(readFileSync(new URL("./fixtures/live-chain.json", import.meta.url), "utf8"));

test("the real on-chain chain replays clean", () => {
  const { vault, head, receipts } = load();
  const result = replay(receipts, { vault, head });
  assert.deepEqual(result.problems, []);
  assert.ok(result.summary.allowed > 0 && result.summary.blocked > 0, "it holds both payments and refusals");
  assert.ok(result.summary.settlementFailed > 0, "it holds a real failed settlement");
  assert.ok(result.summary.pauses > 0, "it holds a real breaker trip");
});

test("the real chain holds the injected attack, refused", () => {
  const { receipts } = load();
  const attack = receipts.find((r) => r.kind === "blocked" && r.reason === "recipient_not_allowed" && r.recipient.startsWith("attacker."));
  assert.ok(attack);
});

test("changing one real amount is caught", () => {
  const { vault, receipts } = load();
  receipts.find((r) => r.kind === "allowed").amount = "1";
  assert.ok(replay(receipts, { vault }).problems.some((p) => p.check === "hash"));
});

test("rewriting a real refusal as a payment is caught even with every hash redone", () => {
  const { vault, receipts } = load();
  const i = receipts.findIndex((r) => r.kind === "blocked" && r.reason === "recipient_not_allowed");
  receipts[i].kind = "allowed";
  receipts[i].reason = "";
  for (let n = i; n < receipts.length; n++) {
    receipts[n].prev_hash = receipts[n - 1].hash;
    receipts[n].hash = sha256Hex(receiptPreimage(receipts[n]));
  }
  assert.ok(replay(receipts, { vault }).problems.some((p) => p.check === "policy"));
});
