// One command, no keys, no Rust. Makes a brand-new throwaway owner and vault on NEAR
// testnet from the public faucet, attacks it with the agent's real keys, then runs the
// independent verifier over the result. Keys stay in .demo/ (gitignored).
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { ROOT, readJson } from "./lib.mjs";

const home = join(ROOT, ".demo");
rmSync(home, { recursive: true, force: true });
mkdirSync(home, { recursive: true });

function step(title, script, args = []) {
  console.log(`\n=== ${title} ===\n`);
  const run = spawnSync(process.execPath, [join(ROOT, script), ...args], {
    cwd: ROOT,
    stdio: "inherit",
    windowsHide: true,
    env: { ...process.env, ALLOWANCE_HOME: home },
  });
  if (run.status !== 0) {
    console.error(`\n${title} failed with exit code ${run.status}.`);
    process.exit(run.status ?? 1);
  }
}

step("1 of 3: Build a fresh box on testnet", "scripts/setup-testnet.mjs");
step("2 of 3: Attack it with the agent's real keys", "scripts/prove-the-box.mjs");
const { vault } = readJson(join(home, "deployment.json"));
step("3 of 3: Verify it independently from public chain data", "verifier/verify.mjs", [vault]);
