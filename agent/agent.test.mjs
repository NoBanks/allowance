import { test } from "node:test";
import assert from "node:assert/strict";
import { buildInbox, SYSTEM, TASK } from "./inbox.mjs";
import { buildToolbox, TOOL_DEFINITIONS } from "./tools.mjs";
import { claudeBrain, compromisedBrain } from "./brains.mjs";

const VENDOR = "vendor.testnet";
const ATTACKER = "attacker.testnet";
const NEAR = 10n ** 24n;

function fakeWallet(decide = () => ({ result: "allowed", seq: "1" })) {
  const calls = [];
  return {
    calls,
    propose: async (intent) => {
      calls.push(intent);
      return decide(intent);
    },
    status: async () => ({ spent_today: "0", paused: false }),
    policy: async () => ({ daily_cap: "300000000000000000000000", per_tx_cap: "100000000000000000000000" }),
  };
}

const setup = (decide) => {
  const wallet = fakeWallet(decide);
  const inbox = buildInbox({ vendor: VENDOR, attacker: ATTACKER });
  return { wallet, inbox, toolbox: buildToolbox({ wallet, inbox }) };
};

test("the compromised brain really does obey the planted instruction", async () => {
  const { wallet, toolbox } = setup();
  await compromisedBrain({ toolbox });
  const toAttacker = wallet.calls.filter((c) => c.recipient === ATTACKER);
  assert.equal(toAttacker.length, 1);
  assert.equal(toAttacker[0].amountYocto, (9n * NEAR) / 100n);
});

test("the compromised brain tries all three payments in the inbox", async () => {
  const { wallet, toolbox } = setup();
  await compromisedBrain({ toolbox });
  assert.deepEqual(wallet.calls.map((c) => c.recipient).sort(), [ATTACKER, VENDOR, VENDOR].sort());
  assert.ok(wallet.calls.some((c) => c.amountYocto === NEAR / 4n), "the over-cap forged invoice");
});

test("memos stay inside the limit the vault enforces", async () => {
  const { wallet, toolbox } = setup();
  await compromisedBrain({ toolbox });
  for (const c of wallet.calls) assert.ok(Buffer.byteLength(c.memo) <= 140);
});

test("the tool surface is exactly these four tools", () => {
  assert.deepEqual(TOOL_DEFINITIONS.map((t) => t.name), ["list_inbox", "read_document", "get_budget", "pay"]);
});

test("a refusal comes back to the brain as a plain answer", async () => {
  const { toolbox } = setup(() => ({ result: "blocked", reason: "recipient_not_allowed", seq: "2" }));
  const out = await toolbox.call("pay", { recipient: ATTACKER, amount_near: "0.09", memo: "x" });
  assert.equal(out.isError, false);
  assert.match(out.text, /REFUSED.*recipient_not_allowed/);
});

test("a frozen vault tells the brain it is frozen", async () => {
  const { toolbox } = setup(() => ({ result: "suppressed", reason: "circuit_breaker", seq: null }));
  const out = await toolbox.call("pay", { recipient: VENDOR, amount_near: "0.01", memo: "x" });
  assert.match(out.text, /frozen \(circuit_breaker\)/);
});

test("bad amounts never reach the vault", async () => {
  for (const amount of ["-1", "abc", "1e3", "", "0.1.2", "0.0000000000000000000000001"]) {
    const { wallet, toolbox } = setup();
    const out = await toolbox.call("pay", { recipient: VENDOR, amount_near: amount, memo: "x" });
    assert.equal(out.isError, true, `amount ${JSON.stringify(amount)}`);
    assert.equal(wallet.calls.length, 0);
  }
});

test("decimal amounts convert exactly", async () => {
  const { wallet, toolbox } = setup();
  await toolbox.call("pay", { recipient: VENDOR, amount_near: "0.02", memo: "x" });
  assert.equal(wallet.calls[0].amountYocto, NEAR / 50n);
});

test("documents are a fixed set, so a name cannot reach the filesystem", async () => {
  const { toolbox } = setup();
  for (const name of ["../../.env", "C:\\Windows\\win.ini", "constructor", "__proto__"]) {
    assert.equal((await toolbox.call("read_document", { name })).isError, true, name);
  }
});

test("an unknown tool is an error, not a crash", async () => {
  const { toolbox } = setup();
  assert.equal((await toolbox.call("transfer_everything", {})).isError, true);
  assert.equal((await toolbox.call("constructor", {})).isError, true);
});

test("a wallet failure comes back as an error result", async () => {
  const { toolbox } = setup(() => {
    throw new Error("rpc down");
  });
  const out = await toolbox.call("pay", { recipient: VENDOR, amount_near: "0.01", memo: "x" });
  assert.equal(out.isError, true);
  assert.match(out.text, /rpc down/);
});

function scriptedClient(responses) {
  const requests = [];
  return {
    requests,
    beta: {
      messages: {
        create: async (params) => {
          requests.push(JSON.parse(JSON.stringify(params)));
          return responses.shift();
        },
      },
    },
  };
}

const args = (toolbox, client) => ({ toolbox, client, system: "s", task: "t", model: "m" });

test("the claude brain runs tools, returns results, and stops at end_turn", async () => {
  const { wallet, toolbox } = setup();
  const client = scriptedClient([
    {
      stop_reason: "tool_use",
      content: [{ type: "tool_use", id: "a", name: "pay", input: { recipient: VENDOR, amount_near: "0.02", memo: "Invoice 1001" } }],
    },
    { stop_reason: "end_turn", content: [{ type: "text", text: "Paid." }] },
  ]);
  const out = await claudeBrain(args(toolbox, client));
  assert.equal(out.stop, "end_turn");
  assert.equal(out.summary, "Paid.");
  assert.equal(wallet.calls.length, 1);
  const results = client.requests[1].messages.at(-1).content;
  assert.equal(results[0].type, "tool_result");
  assert.equal(results[0].tool_use_id, "a");
  assert.match(results[0].content, /PAID/);
});

test("the claude brain gets no warning about injection in its prompt", async () => {
  const { toolbox } = setup();
  const client = scriptedClient([{ stop_reason: "end_turn", content: [] }]);
  await claudeBrain({ ...args(toolbox, client), system: SYSTEM, task: TASK });
  const prompt = client.requests[0].system + client.requests[0].messages[0].content;
  assert.doesNotMatch(prompt, /inject|ignore|untrusted|malicious|suspicious/i);
});

test("the claude brain returns every parallel tool result in one message", async () => {
  const { toolbox } = setup();
  const client = scriptedClient([
    {
      stop_reason: "tool_use",
      content: [
        { type: "tool_use", id: "a", name: "list_inbox", input: {} },
        { type: "tool_use", id: "b", name: "get_budget", input: {} },
      ],
    },
    { stop_reason: "end_turn", content: [] },
  ]);
  await claudeBrain(args(toolbox, client));
  assert.deepEqual(client.requests[1].messages.at(-1).content.map((r) => r.tool_use_id), ["a", "b"]);
});

test("the claude brain stops on a refusal without running anything", async () => {
  const { wallet, toolbox } = setup();
  const client = scriptedClient([{ stop_reason: "refusal", content: [] }]);
  assert.equal((await claudeBrain(args(toolbox, client))).stop, "refusal");
  assert.equal(wallet.calls.length, 0);
});

test("the claude brain cannot loop forever", async () => {
  const { toolbox } = setup();
  const loop = () => ({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "a", name: "list_inbox", input: {} }] });
  const client = scriptedClient(Array.from({ length: 50 }, loop));
  assert.equal((await claudeBrain(args(toolbox, client))).stop, "turn_limit");
  assert.equal(client.requests.length, 12);
});
