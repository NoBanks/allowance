// Everything the agent is able to do to the vault. This is the whole power it has:
// sign an intent and ask. The vault decides.
import { createHash } from "node:crypto";
import { KeyPair, actions, teraToGas } from "near-api-js";
import { accountFor, loadCreds, loadDeployment, provider } from "../scripts/lib.mjs";

const PROPOSE_GAS = teraToGas("60");

export function intentMessage(vault, nonce, recipient, amount, memoSha) {
  return `allowance-intent-v1\n${vault}\n${nonce}\n${recipient}\n${amount}\n${memoSha}`;
}

// Milliseconds, with a bump so two calls in one millisecond still increase.
let lastNonce = 0;
function nextNonce() {
  lastNonce = Math.max(Date.now(), lastNonce + 1);
  return lastNonce;
}

export function openWallet(deployment = loadDeployment(), creds = loadCreds()) {
  const keys = creds.vaults?.[deployment.vault];
  if (!keys) throw new Error(`No agent keys for ${deployment.vault}`);
  const signer = KeyPair.fromString(keys.agentSigningKey);
  const account = accountFor(deployment.vault, keys.agentAccessKey);

  return {
    vault: deployment.vault,
    account,

    /** Returns the vault's decision. A refusal is an answer, not an exception. */
    async propose({ recipient, amountYocto, memo = "" }) {
      const nonce = String(nextNonce());
      const amount = String(amountYocto);
      const memoSha = createHash("sha256").update(memo).digest("hex");
      const message = intentMessage(deployment.vault, nonce, recipient, amount, memoSha);
      const { signature } = signer.sign(Buffer.from(message));
      const outcome = await account.signAndSendTransaction({
        receiverId: deployment.vault,
        actions: [
          actions.functionCall(
            "propose",
            { recipient, amount, memo, nonce, signature: Buffer.from(signature).toString("hex") },
            PROPOSE_GAS,
            0n,
          ),
        ],
        waitUntil: "FINAL",
      });
      const raw = outcome.status?.SuccessValue;
      const decision = raw ? JSON.parse(Buffer.from(raw, "base64").toString()) : { result: "unknown" };
      return { ...decision, tx: outcome.transaction.hash };
    },

    async status() {
      return provider.callFunction({ contractId: deployment.vault, method: "get_status", args: {} });
    },

    async policy() {
      return provider.callFunction({ contractId: deployment.vault, method: "get_policy", args: {} });
    },
  };
}
