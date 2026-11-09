// Creates everything on NEAR testnet from nothing: a funded owner, a vendor, an
// attacker, and the vault. Free: the owner is funded by the public testnet faucet.
//
// The vault is created in ONE atomic transaction with no key at all. Its only key is
// the agent's function-call key, added by the contract during init. So the vault has
// never had a full-access key, and nobody can sign a raw transfer out of it.
//
//   node scripts/setup-testnet.mjs [--owner name.testnet] [--vault vault] [--fund 4]
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { KeyPair, actions, teraToGas } from "near-api-js";
import { ROOT, DEPLOYMENT_PATH, CREDS_PATH, RPC_URL, accountExists, accountFor, provider, readJson, writeJson, toYocto, txUrl } from "./lib.mjs";

const FAUCET = "https://helper.testnet.near.org/account";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}

async function createViaFaucet(accountId, publicKey) {
  const res = await fetch(FAUCET, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ newAccountId: accountId, newAccountPublicKey: publicKey }),
  });
  if (!res.ok) throw new Error(`Faucet refused ${accountId}: ${res.status} ${await res.text()}`);
}

async function waitFor(check, label, tries = 30) {
  for (let i = 0; i < tries; i++) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

const creds = readJson(CREDS_PATH, {});
const ownerId = arg("owner", creds.ownerId || `allowance-${Date.now().toString(36)}.testnet`);
const vaultId = `${arg("vault", "vault")}.${ownerId}`;
const vendorId = `api-vendor.${ownerId}`;
const attackerId = `attacker.${ownerId}`;
const fund = toYocto(arg("fund", "4"));

// The committed build, so a fresh clone needs no Rust. `npm run build:contract` refreshes it.
const wasm = readFileSync(join(ROOT, "deployment", "allowance.wasm"));

if (!creds.ownerKey) {
  creds.ownerId = ownerId;
  creds.ownerKey = KeyPair.fromRandom("ed25519").toString();
  writeJson(CREDS_PATH, creds);
}
if (!(await accountExists(ownerId))) {
  console.log(`Creating owner ${ownerId} from the faucet...`);
  await createViaFaucet(ownerId, KeyPair.fromString(creds.ownerKey).getPublicKey().toString());
  await waitFor(() => accountExists(ownerId), "owner account");
}
const owner = accountFor(ownerId, creds.ownerKey);

for (const id of [vendorId, attackerId]) {
  if (!(await accountExists(id))) {
    console.log(`Creating ${id}...`);
    await owner.signAndSendTransaction({
      receiverId: id,
      actions: [actions.createAccount(), actions.transfer(toYocto("0.01"))],
    });
  }
}

if (await accountExists(vaultId)) {
  throw new Error(`${vaultId} already exists. Pass --vault <new-name> to make a new one.`);
}

const agentAccessKey = KeyPair.fromRandom("ed25519");
const agentSigningKey = KeyPair.fromRandom("ed25519");
const signingPublicHex = Buffer.from(agentSigningKey.getPublicKey().data).toString("hex");

const policy = {
  per_tx_cap: toYocto("0.1").toString(),
  daily_cap: toYocto("0.3").toString(),
  reserve: toYocto("0.5").toString(),
  allowed_hours: null,
  allowlist: [vendorId],
  max_consecutive_blocked: 5,
  max_attempts_per_day: 100,
};

console.log(`Creating vault ${vaultId} (atomic: create, fund, deploy, init)...`);
const created = await owner.signAndSendTransaction({
  receiverId: vaultId,
  actions: [
    actions.createAccount(),
    actions.transfer(fund),
    actions.deployContract(wasm),
    actions.functionCall(
      "new",
      {
        owner_id: ownerId,
        agent_label: "allowance-agent-1",
        agent_signing_key: signingPublicHex,
        agent_access_key: agentAccessKey.getPublicKey().toString(),
        agent_gas_allowance: toYocto("0.25").toString(),
        policy,
      },
      teraToGas("100"),
      0n,
    ),
  ],
});

creds.vaults = creds.vaults || {};
creds.vaults[vaultId] = { agentAccessKey: agentAccessKey.toString(), agentSigningKey: agentSigningKey.toString() };
writeJson(CREDS_PATH, creds);

await waitFor(async () => (await provider.viewAccessKeyList({ accountId: vaultId })).keys.length > 0, "agent key");
const { keys } = await provider.viewAccessKeyList({ accountId: vaultId });

const deployment = {
  network: "testnet",
  rpc: RPC_URL,
  vault: vaultId,
  owner: ownerId,
  vendor: vendorId,
  attacker: attackerId,
  agent_access_key: agentAccessKey.getPublicKey().toString(),
  agent_signing_key: signingPublicHex,
  wasm_sha256: createHash("sha256").update(wasm).digest("hex"),
  created_tx: created.transaction.hash,
};
writeJson(DEPLOYMENT_PATH, deployment);

console.log(`Vault created: ${txUrl(created.transaction.hash)}`);
console.log(`Keys on the vault: ${keys.length}`);
console.log(JSON.stringify(keys.map((k) => k.access_key.permission), null, 2));
console.log(`Public deployment record: ${DEPLOYMENT_PATH}`);
