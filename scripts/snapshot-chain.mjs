// Saves the deployed vault's real receipts so the offline tests replay data the
// contract actually wrote, which proves the Rust and JavaScript hashing agree.
import { join } from "node:path";
import { loadDeployment, provider, writeJson, ROOT } from "./lib.mjs";

const { vault } = loadDeployment();
const status = await provider.callFunction({ contractId: vault, method: "get_status", args: {} });
const count = Number(status.receipt_count);
const receipts = [];
while (receipts.length < count) {
  const page = await provider.callFunction({ contractId: vault, method: "get_receipts", args: { from: String(receipts.length), limit: 50 } });
  if (page.length === 0) break;
  receipts.push(...page);
}
writeJson(join(ROOT, "verifier", "fixtures", "live-chain.json"), { vault, head: status.head_hash, receipts });
console.log(`Saved ${receipts.length} receipts from ${vault}`);
