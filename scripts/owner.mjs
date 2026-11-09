// The human's controls. The owner key is the only thing that can change the box.
//
//   node scripts/owner.mjs pause
//   node scripts/owner.mjs resume
//   node scripts/owner.mjs allow <account>
//   node scripts/owner.mjs withdraw <near> [--vault <vault id>]
import { teraToGas } from "near-api-js";
import { accountFor, loadCreds, loadDeployment, provider, toYocto, fromYocto } from "./lib.mjs";

export async function openOwner(deployment = loadDeployment(), creds = loadCreds()) {
  const owner = accountFor(deployment.owner, creds.ownerKey);
  const call = (vault, methodName, args) =>
    owner.callFunction({ contractId: vault, methodName, args, gas: teraToGas("60"), deposit: 0n });
  return {
    pause: (vault = deployment.vault) => call(vault, "pause", {}),
    resume: (vault = deployment.vault) => call(vault, "resume", {}),
    withdraw: (near, vault = deployment.vault) => call(vault, "withdraw", { amount: toYocto(near).toString(), to: deployment.owner }),
    async allow(accountId, vault = deployment.vault) {
      const policy = await provider.callFunction({ contractId: vault, method: "get_policy", args: {} });
      if (!policy.allowlist.includes(accountId)) policy.allowlist.push(accountId);
      return call(vault, "set_policy", { policy });
    },
  };
}

if (process.argv[1]?.endsWith("owner.mjs")) {
  const [command, value] = process.argv.slice(2);
  const i = process.argv.indexOf("--vault");
  const vault = i > -1 ? process.argv[i + 1] : undefined;
  const o = await openOwner();
  if (command === "pause") await o.pause(vault);
  else if (command === "resume") await o.resume(vault);
  else if (command === "allow") await o.allow(value, vault);
  else if (command === "withdraw") await o.withdraw(value, vault);
  else throw new Error(`Unknown command: ${command}`);
  const target = vault || loadDeployment().vault;
  const s = await provider.callFunction({ contractId: target, method: "get_status", args: {} });
  console.log(`${command} done. ${target}: balance ${fromYocto(s.balance.toString())} NEAR, frozen: ${s.paused}, receipts: ${s.receipt_count}`);
}
