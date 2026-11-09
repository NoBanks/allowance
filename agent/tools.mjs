// The whole tool surface, shared by every brain. A brain can read the inbox, check the
// budget, and ask the vault to pay. There is deliberately nothing else to call.
import { fromYocto, toYocto } from "../scripts/lib.mjs";

export const TOOL_DEFINITIONS = [
  {
    name: "list_inbox",
    description: "List the documents in the inbox.",
    input_schema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "read_document",
    description: "Read one document from the inbox by name.",
    input_schema: {
      type: "object",
      properties: { name: { type: "string", description: "Document name from list_inbox" } },
      required: ["name"],
      additionalProperties: false,
    },
  },
  {
    name: "get_budget",
    description: "See how much has been spent today and the current limits.",
    input_schema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "pay",
    description: "Ask the vault to pay a NEAR account. The vault applies its own rules and may refuse. A refusal is final for this payment.",
    input_schema: {
      type: "object",
      properties: {
        recipient: { type: "string", description: "NEAR account id to pay" },
        amount_near: { type: "string", description: "Amount in NEAR as a decimal string, like \"0.02\"" },
        memo: { type: "string", description: "Short reference, 140 bytes or less" },
      },
      required: ["recipient", "amount_near", "memo"],
      additionalProperties: false,
    },
  },
];

function parseAmount(amount) {
  if (!/^\d+(\.\d{1,24})?$/.test(String(amount))) throw new Error(`Not a valid NEAR amount: ${amount}`);
  return toYocto(amount);
}

export function buildToolbox({ wallet, inbox, onEvent = () => {} }) {
  const run = {
    list_inbox: async () => Object.keys(inbox).join("\n"),

    // A lookup in a fixed object: a name can never reach the filesystem.
    read_document: async ({ name }) => {
      if (!Object.hasOwn(inbox, name)) throw new Error(`No such document: ${name}`);
      return inbox[name];
    },

    get_budget: async () => {
      const [status, policy] = await Promise.all([wallet.status(), wallet.policy()]);
      return JSON.stringify({
        spent_today_near: fromYocto(String(status.spent_today)),
        daily_cap_near: fromYocto(policy.daily_cap),
        per_transaction_cap_near: fromYocto(policy.per_tx_cap),
        frozen: status.paused,
      });
    },

    pay: async ({ recipient, amount_near, memo }) => {
      const decision = await wallet.propose({ recipient, amountYocto: parseAmount(amount_near), memo });
      onEvent({ type: "payment", recipient, amount_near, memo, ...decision });
      if (decision.result === "allowed") return `PAID ${amount_near} NEAR to ${recipient}. Receipt ${decision.seq}.`;
      if (decision.result === "blocked") return `REFUSED by the vault: ${decision.reason}. Receipt ${decision.seq}. Nothing was sent.`;
      return `REFUSED: the vault is frozen (${decision.reason}). Nothing was sent.`;
    },
  };

  return {
    definitions: TOOL_DEFINITIONS,
    /** Errors go back to the brain as text, so a bad call cannot crash the run. */
    async call(name, input) {
      const handler = Object.hasOwn(run, name) ? run[name] : null;
      if (!handler) return { isError: true, text: `Unknown tool: ${name}` };
      try {
        return { isError: false, text: await handler(input ?? {}) };
      } catch (e) {
        return { isError: true, text: String(e.message || e).slice(0, 400) };
      }
    },
  };
}
