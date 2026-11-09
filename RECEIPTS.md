# Receipts

Every claim in the README, mapped to the code that does it and the test that checks it. Line references are checked by `verifier/receipts-doc.test.mjs`.

**Three kinds of evidence, strongest first:**
- **Live:** a real transaction on NEAR testnet, using the agent's real keys. Run `npm run demo` to repeat it on your own fresh vault. Results from the deployed vault: [deployment/prove-the-box.json](deployment/prove-the-box.json).
- **Chain:** replayed from receipts the contract really wrote: `verifier/fixtures/live-chain.json`, part of `npm test`.
- **Unit:** `npm test` (JavaScript) or `cd contract && cargo test` (Rust). Offline, no keys.

## The box

| Claim | Code | Evidence |
|---|---|---|
| The vault is created atomically with no key at all | `scripts/setup-testnet.mjs:93` | Live: `verifier/verify.mjs:79` reads the account's keys from the chain |
| Its only key is the agent's, added by the contract at init | `contract/src/lib.rs:421` | Live: `verifier/verify.mjs:82` |
| The code on chain is the code in this repo | `deployment/allowance.wasm` | Live: `verifier/verify.mjs:91` compares the on-chain code hash |
| The agent key cannot sign a raw transfer | NEAR protocol, function-call key | Live: `scripts/prove-the-box.mjs:47`, refused with "requires full access", using 0.001 NEAR so the gas allowance is not the reason |
| The agent key cannot change the policy or withdraw | NEAR protocol, method list | Live: `scripts/prove-the-box.mjs:50`, `scripts/prove-the-box.mjs:56`. Unit: `contract/src/tests.rs:212` |
| The agent key cannot give itself a full-access key | NEAR protocol | Live: `scripts/prove-the-box.mjs:62` |
| The agent key cannot attach a deposit | NEAR protocol | Live: `scripts/prove-the-box.mjs:68` |
| Nobody else can call `propose` | `contract/src/lib.rs:210` | Unit: `contract/src/tests.rs:202` |

## The rules

| Claim | Code | Evidence |
|---|---|---|
| Spending rules are one pure function, first failing check wins | `contract/src/policy.rs:75` | Unit: tests in `contract/src/policy.rs` |
| An injected payment to an unlisted account is refused | `contract/src/lib.rs:210` | Live: `scripts/prove-the-box.mjs:80`. Chain: `verifier/live-chain.test.mjs:19`. Unit: `contract/src/tests.rs:104` |
| A big payment to a listed account is refused | `contract/src/policy.rs:75` | Live: `scripts/prove-the-box.mjs:83`. Unit: `contract/src/tests.rs:116` |
| Small payments cannot drip past the daily cap | `contract/src/policy.rs:75` | Live: `scripts/prove-the-box.mjs:88`. Unit: `contract/src/tests.rs:116` |
| The reserve cannot be spent | `contract/src/lib.rs:410` | Unit: `contract/src/tests.rs:190` |
| A signature cannot be moved to another amount or recipient | `contract/src/lib.rs:414` | Unit: `contract/src/tests.rs:148`, `contract/src/tests.rs:137` |
| A signed request cannot be replayed | `contract/src/policy.rs:75` | Unit: `contract/src/tests.rs:171` |
| A refusal is written down, not rolled back | `contract/src/lib.rs:7` | Live: receipts on chain after every refusal. Unit: `contract/src/tests.rs:104` |
| A payment that fails to arrive is receipted and returned to the cap | `contract/src/lib.rs:277` | Live: `scripts/prove-the-box.mjs:98`. Unit: `contract/src/tests.rs:286` |
| Repeated refusals freeze the vault | `contract/src/lib.rs:262` | Live: `scripts/prove-the-box.mjs:107`. Unit: `contract/src/tests.rs:229` |
| Too many attempts in a day freeze the vault | `contract/src/lib.rs:269` | Unit: `contract/src/tests.rs:272` |
| While frozen, payments are refused and storage stops growing | `contract/src/lib.rs:210` | Live: `scripts/prove-the-box.mjs:112`. Unit: `contract/src/tests.rs:229` |
| Only the owner can unfreeze it, and the count goes on the record | `contract/src/lib.rs:309` | Live: `scripts/prove-the-box.mjs:116`. Unit: `contract/src/tests.rs:257` |
| The owner can take money back | `contract/src/lib.rs:323` | Live: run by hand on an earlier vault with `scripts/owner.mjs`. Unit: `contract/src/tests.rs:212` checks the agent cannot |

## The record

| Claim | Code | Evidence |
|---|---|---|
| Every receipt links to the one before it | `contract/src/lib.rs:440` | Chain: `verifier/live-chain.test.mjs:10`. Unit: `contract/src/tests.rs:317` |
| Rust and JavaScript agree on every hash | `verifier/core.mjs:67` | Chain: `verifier/live-chain.test.mjs:10` |
| Editing a receipt is caught | `verifier/core.mjs:67` | Unit: `verifier/replay.test.mjs:87`. Chain: `verifier/live-chain.test.mjs:25` |
| Deleting from the middle or cutting the end is caught | `verifier/core.mjs:67` | Unit: `verifier/replay.test.mjs:93`, `verifier/replay.test.mjs:100` |
| A perfectly hashed forbidden payment still fails | `verifier/core.mjs:42` | Unit: `verifier/replay.test.mjs:106`, `verifier/replay.test.mjs:114`, `verifier/replay.test.mjs:120`. Chain: `verifier/live-chain.test.mjs:31` |
| A hostile memo cannot forge receipt fields | `contract/src/lib.rs:440` | Unit: `verifier/replay.test.mjs:220` |
| The browser runs the same replay code as the command line | `dashboard/app.mjs:271`, `verifier/core.mjs:67` | Checked in headless Chrome: `?auto=verify` went green and `?auto=forge` reported the forgery caught |
| The dashboard renders memos as text, never markup | `dashboard/app.mjs:64` | Code review: every value goes through `textContent` |

## The agent

| Claim | Code | Evidence |
|---|---|---|
| The compromised brain really obeys planted instructions | `agent/brains.mjs:11` | Unit: `agent/agent.test.mjs:30`. Live: `npm run agent:compromised` |
| The agent has four tools and no others | `agent/tools.mjs` | Unit: `agent/agent.test.mjs:51` |
| The Claude brain's prompt has no injection warning | `agent/inbox.mjs:32` | Unit: `agent/agent.test.mjs:141` |
| Bad amounts never reach the vault | `agent/tools.mjs` | Unit: `agent/agent.test.mjs:68` |

## Not proven

Said plainly, so nobody has to find it.

- **The Claude brain has not been run against the real API.** It passes tests against a scripted client only.
- **Allowed hours** are unit tested, never exercised live.
- **`rotate_agent`** has no test. The README does not rely on it.
- **`contract/src/lib.rs` was not reviewed by a third party.** Testnet only.
- **The verifier trusts the RPC endpoint it reads from.** Point `NEAR_RPC_URL` at another provider to cross-check.
