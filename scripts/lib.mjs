// Shared helpers for talking to NEAR testnet.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Account, JsonRpcProvider } from "near-api-js";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// ALLOWANCE_HOME points a run at its own throwaway accounts and keys (npm run demo uses it).
const RUN_HOME = process.env.ALLOWANCE_HOME;
export const DEPLOYMENT_PATH = RUN_HOME ? join(RUN_HOME, "deployment.json") : join(ROOT, "deployment", "testnet.json");
export const PROOF_PATH = RUN_HOME ? join(RUN_HOME, "prove-the-box.json") : join(ROOT, "deployment", "prove-the-box.json");
// Private keys live outside the repo.
export const CREDS_PATH = RUN_HOME ? join(RUN_HOME, "credentials.json") : join(homedir(), ".allowance", "testnet-credentials.json");
export const RPC_URL = process.env.NEAR_RPC_URL || "https://test.rpc.fastnear.com";
export const EXPLORER = "https://testnet.nearblocks.io";

export const provider = new JsonRpcProvider({ url: RPC_URL });

export function readJson(path, fallback = null) {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : fallback;
}

export function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

export function loadDeployment() {
  const d = readJson(DEPLOYMENT_PATH);
  if (!d) throw new Error(`No deployment found at ${DEPLOYMENT_PATH}. Run: npm run setup`);
  return d;
}

export function loadCreds() {
  const c = readJson(CREDS_PATH);
  if (!c) throw new Error(`No credentials at ${CREDS_PATH}. Run: npm run setup`);
  return c;
}

export function accountFor(accountId, privateKey) {
  return new Account(accountId, provider, privateKey);
}

export async function accountExists(accountId) {
  try {
    await provider.viewAccount({ accountId });
    return true;
  } catch {
    return false;
  }
}

export function toYocto(near) {
  const [whole, frac = ""] = String(near).split(".");
  return BigInt(whole + frac.padEnd(24, "0").slice(0, 24));
}

export function fromYocto(yocto, places = 4) {
  const v = BigInt(yocto);
  const whole = v / 10n ** 24n;
  const frac = (v % 10n ** 24n).toString().padStart(24, "0").slice(0, places);
  return `${whole}.${frac}`;
}

export function txUrl(hash) {
  return `${EXPLORER}/txns/${hash}`;
}
