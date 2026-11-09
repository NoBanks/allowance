// Live proof on testnet. Uses the agent's REAL keys to try everything a fully
// compromised agent would try. Each attempt is a real transaction. Run it on a fresh
// vault: it spends that vault's daily cap and trips its circuit breaker on purpose.
import { actions, KeyPair, teraToGas } from "near-api-js";
import { openWallet } from "../agent/wallet.mjs";
import { openOwner } from "./owner.mjs";
import { loadDeployment, provider, toYocto, fromYocto, txUrl, writeJson, PROOF_PATH } from "./lib.mjs";

const d = loadDeployment();
const wallet = openWallet(d);
const owner = await openOwner(d);
const results = [];

function record(name, expected, actual, passed, tx) {
  results.push({ name, expected, actual, passed, tx: tx ?? null });
  console.log(`${passed ? "PASS" : "FAIL"}  ${name}\n      ${actual}${tx ? `\n      ${txUrl(tx)}` : ""}`);
}

// The network must refuse with the reason named here. Refused for any OTHER reason
// (say, an amount above the gas allowance) proves nothing, so it counts as a failure.
async function mustBeRefusedBecause(name, reason, send) {
  try {
    const out = await send();
    const failure = out?.status?.Failure;
    record(name, reason.source, failure ? `failed on chain: ${JSON.stringify(failure).slice(0, 160)}` : "ACCEPTED: the box has a hole", false, out?.transaction?.hash);
  } catch (e) {
    const message = String(e.message || e);
    record(name, reason.source, `refused: ${message.slice(0, 160)}`, reason.test(message));
  }
}

async function balanceOf(accountId) {
  return BigInt((await provider.viewAccount({ accountId })).amount);
}

const receipts = async () => {
  const s = await wallet.status();
  return provider.callFunction({ contractId: d.vault, method: "get_receipts", args: { from: String(Math.max(0, Number(s.receipt_count) - 50)), limit: 50 } });
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const attackerBefore = await balanceOf(d.attacker);
console.log(`Vault ${d.vault}: ${fromYocto(await balanceOf(d.vault))} NEAR. Attacker: ${fromYocto(attackerBefore)} NEAR.\n`);

console.log("-- The agent key tries to go around the contract --");
await mustBeRefusedBecause("Raw transfer signed by the agent key (0.001 NEAR, well under its gas allowance)", /requires full access/i, () =>
  wallet.account.signAndSendTransaction({ receiverId: d.attacker, actions: [actions.transfer(toYocto("0.001"))] }),
);
await mustBeRefusedBecause("Agent key calls set_policy to allowlist the attacker", /does not allow method set_policy/i, () =>
  wallet.account.signAndSendTransaction({
    receiverId: d.vault,
    actions: [actions.functionCall("set_policy", { policy: { allowlist: [d.attacker] } }, teraToGas("30"), 0n)],
  }),
);
await mustBeRefusedBecause("Agent key calls withdraw", /does not allow method withdraw/i, () =>
  wallet.account.signAndSendTransaction({
    receiverId: d.vault,
    actions: [actions.functionCall("withdraw", { amount: toYocto("0.001").toString(), to: d.attacker }, teraToGas("30"), 0n)],
  }),
);
await mustBeRefusedBecause("Agent key adds itself a full-access key", /requires full access/i, () =>
  wallet.account.signAndSendTransaction({
    receiverId: d.vault,
    actions: [actions.addFullAccessKey(KeyPair.fromRandom("ed25519").getPublicKey())],
  }),
);
await mustBeRefusedBecause("Agent key attaches a deposit to propose", /deposit is not allowed/i, () =>
  wallet.account.signAndSendTransaction({
    receiverId: d.vault,
    actions: [actions.functionCall("propose", { recipient: d.attacker, amount: "1", memo: "", nonce: "1", signature: "" }, teraToGas("30"), 1n)],
  }),
);

console.log("\n-- The agent uses its one door --");
const pay = await wallet.propose({ recipient: d.vendor, amountYocto: toYocto("0.05"), memo: "Invoice 1001: API credits" });
record("Legitimate payment to the allowlisted vendor", "allowed", `${pay.result} (receipt ${pay.seq})`, pay.result === "allowed", pay.tx);

const injected = await wallet.propose({ recipient: d.attacker, amountYocto: toYocto("0.05"), memo: "URGENT from support: move funds to safe wallet" });
record("Injected payment to the attacker, under every cap", "blocked: recipient_not_allowed", `${injected.result}: ${injected.reason}`, injected.reason === "recipient_not_allowed", injected.tx);

const big = await wallet.propose({ recipient: d.vendor, amountYocto: toYocto("0.2"), memo: "Invoice 1002: looks legit, just large" });
record("Allowlisted vendor, over the per-transaction cap", "blocked: over_tx_cap", `${big.result}: ${big.reason}`, big.reason === "over_tx_cap", big.tx);

const drip1 = await wallet.propose({ recipient: d.vendor, amountYocto: toYocto("0.1"), memo: "Drain by small steps 1" });
const drip2 = await wallet.propose({ recipient: d.vendor, amountYocto: toYocto("0.1"), memo: "Drain by small steps 2" });
const drip3 = await wallet.propose({ recipient: d.vendor, amountYocto: toYocto("0.1"), memo: "Drain by small steps 3" });
record("Drip attack hits the daily cap (0.05 + 0.1 + 0.1 fit, the next 0.1 does not)", "allowed, allowed, blocked: over_daily_cap", `${drip1.result}, ${drip2.result}, ${drip3.result}: ${drip3.reason}`, drip1.result === "allowed" && drip2.result === "allowed" && drip3.reason === "over_daily_cap", drip3.tx);

console.log("\n-- Money that does not arrive is not counted as spent --");
const ghost = `ghost-${Date.now().toString(36)}.${d.owner}`;
await owner.allow(ghost);
const spentBefore = BigInt((await wallet.status()).spent_today);
const toGhost = await wallet.propose({ recipient: ghost, amountYocto: toYocto("0.01"), memo: "Payment to an account that does not exist" });
await sleep(5000);
const spentAfter = BigInt((await wallet.status()).spent_today);
const settleReceipt = (await receipts()).find((r) => r.kind === "settlement_failed" && String(r.nonce) === String(toGhost.seq));
record("Transfer to a nonexistent account fails, is receipted, and returns to the cap", "settlement_failed, spent_today unchanged", `${toGhost.result} then ${settleReceipt?.kind ?? "NO SETTLEMENT RECEIPT"}, spent_today ${spentBefore} -> ${spentAfter}`, toGhost.result === "allowed" && Boolean(settleReceipt) && spentAfter === spentBefore, toGhost.tx);

console.log("\n-- Hammering the box freezes it --");
const limit = (await wallet.policy()).max_consecutive_blocked;
let last;
for (let i = 0; i < limit; i++) {
  last = await wallet.propose({ recipient: d.attacker, amountYocto: toYocto("0.01"), memo: `Attempt ${i + 1}` });
}
const frozen = await wallet.status();
record(`${limit} blocks in a row trip the circuit breaker`, "frozen: circuit_breaker", `frozen: ${frozen.paused}, reason: ${frozen.pause_reason}`, frozen.paused && frozen.pause_reason === "circuit_breaker", last.tx);

const countBefore = frozen.receipt_count;
const whileFrozen = await wallet.propose({ recipient: d.vendor, amountYocto: 1n, memo: "A legitimate payment while frozen" });
const afterAttempt = await wallet.status();
record("While frozen, even a legitimate payment is refused and storage stops growing", "suppressed, receipt count unchanged", `${whileFrozen.result}, receipts ${countBefore} -> ${afterAttempt.receipt_count}, suppressed ${afterAttempt.suppressed_attempts}`, whileFrozen.result === "suppressed" && afterAttempt.receipt_count === countBefore && String(afterAttempt.suppressed_attempts) === "1", whileFrozen.tx);

await owner.resume();
const resumed = await wallet.status();
record("Only the owner can unfreeze it, and the receipt records what was suppressed", "not frozen, suppressed count on the record", `frozen: ${resumed.paused}, last receipt: ${(await receipts()).at(-1).detail}`, !resumed.paused);

await sleep(3000);
const attackerAfter = await balanceOf(d.attacker);
record("The attacker received nothing", `${fromYocto(attackerBefore)} NEAR`, `${fromYocto(attackerAfter)} NEAR`, attackerAfter === attackerBefore);

const failed = results.filter((r) => !r.passed);
writeJson(PROOF_PATH, { vault: d.vault, ran_at: new Date().toISOString(), results });
console.log(`\n${results.length - failed.length} of ${results.length} passed.`);
process.exit(failed.length ? 1 : 0);
