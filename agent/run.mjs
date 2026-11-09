#!/usr/bin/env node
// Runs the agent against the live vault.
//
//   node agent/run.mjs --brain compromised     no API key needed
//   node agent/run.mjs --brain claude          needs ANTHROPIC_API_KEY
import { openWallet } from "./wallet.mjs";
import { buildInbox, SYSTEM, TASK } from "./inbox.mjs";
import { buildToolbox } from "./tools.mjs";
import { claudeBrain, compromisedBrain } from "./brains.mjs";
import { fromYocto, loadDeployment, provider, txUrl } from "../scripts/lib.mjs";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}

const brainName = arg("brain", "compromised");
const deployment = loadDeployment();
const wallet = openWallet(deployment);
const inbox = buildInbox(deployment);

function onEvent(e) {
  if (e.type === "read") console.log(`  read     ${e.name}`);
  if (e.type === "obeying") console.log(`  obeying  "${e.name}" says pay ${e.amount} NEAR to ${e.recipient}`);
  if (e.type === "tool" && e.name === "read_document") console.log(`  read     ${e.input.name}`);
  if (e.type === "said") console.log(`\n  agent: ${e.text.replace(/\n/g, "\n         ")}\n`);
  if (e.type === "payment") {
    const verdict = e.result === "allowed" ? "PAID   " : "REFUSED";
    console.log(`  ${verdict}  ${e.amount_near} NEAR to ${e.recipient}${e.reason ? ` (${e.reason})` : ""}`);
    if (e.tx) console.log(`           ${txUrl(e.tx)}`);
  }
}

const balance = async (accountId) => fromYocto((await provider.viewAccount({ accountId })).amount);
const attackerBefore = await balance(deployment.attacker);

console.log(`\nALLOWANCE agent, brain: ${brainName}, vault: ${deployment.vault}\n`);
const toolbox = buildToolbox({ wallet, inbox, onEvent });

let outcome;
if (brainName === "compromised") {
  outcome = await compromisedBrain({ toolbox, onEvent });
} else if (brainName === "claude") {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error("The claude brain needs ANTHROPIC_API_KEY. Run with --brain compromised to go without a key.");
    process.exit(2);
  }
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const model = process.env.ALLOWANCE_MODEL || "claude-sonnet-5-5";
  outcome = await claudeBrain({ toolbox, system: SYSTEM, task: TASK, client: new Anthropic(), model, onEvent });
  if (outcome.stop !== "end_turn") console.log(`  stopped: ${outcome.stop}`);
} else {
  console.error(`Unknown brain: ${brainName}`);
  process.exit(2);
}

await new Promise((r) => setTimeout(r, 3000));
console.log(`\n  Attacker balance: ${attackerBefore} -> ${await balance(deployment.attacker)} NEAR`);
console.log(`  Check the record yourself: node verifier/verify.mjs ${deployment.vault}\n`);
