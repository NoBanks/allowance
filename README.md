# ALLOWANCE

An AI agent's spending account on NEAR. The agent can pay, but only inside the box, and every move is on the record.

Built at NEAR HACKATHON. Testnet only. Not audited. Do not put real money in it.

## The problem

An agent that can pay can be talked into paying. A web page, an invoice or a tool result can carry instructions, and no system prompt reliably stops that. So ALLOWANCE assumes the model will be fooled and puts the limit somewhere words cannot reach.

## How it works

- **The vault has no full-access key.** It is created in one atomic transaction (create, fund, deploy, init) with no key at all, so nobody can sign a raw transfer out of it. Money leaves only through the contract.
- **The agent holds one function-call key.** NEAR enforces at the protocol level that this key can only call `propose`, can attach no deposit, and has a capped gas allowance.
- **The contract applies the owner's policy:** per-transaction cap, daily cap, recipient allowlist, allowed hours, a reserve the agent can never spend.
- **A refusal is written down.** Blocked attempts return normally instead of panicking, because a panic would roll back the state and erase the evidence.
- **Hammering it freezes it.** Too many blocks in a row, or too many attempts in a day, trips a breaker only the owner can reset. A frozen vault stops writing per-attempt receipts, so an attacker cannot use receipts to lock up its funds in storage.
- **Every receipt is hash-chained and carries the agent's ed25519 signature.**
- **The verifier does not trust the contract.** It re-runs the spending rules over the whole chain. A perfectly hashed receipt for a payment the policy forbids still comes back red.

## Try it: one command, no keys, no Rust

Needs Node 20 or later.

```
git clone https://github.com/NoBanks/allowance
cd allowance
npm install
npm run demo
```

This makes a brand-new owner and vault on NEAR testnet from the public faucet, attacks it with the agent's real keys, then verifies the result from public chain data. It takes about two minutes, costs nothing, and writes throwaway keys to `.demo/` (gitignored). If the faucet is unavailable or rate limited, the verifier below still works.

## Check the deployed vault yourself: no keys, no dependencies

```
node verifier/verify.mjs
```

Reads only public chain data and exits 0 for green, 1 for red.

Deployed vault: see [deployment/testnet.json](deployment/testnet.json).

## Run the agent

The scenario is an inbox with one honest invoice, one vendor status page with a planted prompt injection, and one forged over-limit invoice.

```
npm run setup              # make your own vault (or use npm run demo first)
npm run agent:compromised  # no API key
npm run agent              # needs ANTHROPIC_API_KEY, default model claude-sonnet-5-5
```

The compromised brain obeys any payment instruction it reads, from anyone. It exists because a good model may refuse the injection on its own, and then nothing about the vault has been tested. The Claude brain gets no warning about injection in its prompt: nothing about the safety of this system depends on the prompt.

## Tests

```
npm test                    # verifier and agent, offline, no keys
cd contract && cargo test   # contract, needs Rust stable, offline, no keys
```

`npm run prove` is the live attack suite on your own vault. Run it on a fresh vault: it spends that vault's daily cap and trips its breaker on purpose.

## Known limits

These are real, and worth knowing before trusting any of this.

- **The daily cap resets at UTC midnight, not on a rolling window.** A spender timing it right can spend up to twice the cap across midnight.
- **Gas comes out of the vault.** The agent's calls burn gas from the vault's balance, up to the key's allowance. That is a second, small, capped way for a compromised agent to cost you money.
- **The allowlist is only as good as the account on it.** If a listed vendor is compromised, the agent can still pay it, up to the caps.
- **Suppressed attempts are a count, not individual receipts.** While frozen, attempts only increment a counter, recorded when the owner resumes.
- **`insufficient_funds` cannot be re-derived from the chain alone.** It depends on the live balance, so the verifier accepts it only when every other rule passes.
- **No upgrades.** With no full-access key the code can never change. A fix means a new vault. That is the point, and also a real cost.
- **Native NEAR only.** No fungible tokens yet.
