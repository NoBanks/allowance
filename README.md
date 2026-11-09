# ALLOWANCE

An AI agent's spending account on NEAR. The agent can pay, but only inside the box, and every move is on the record.

Built at NEAR HACKATHON. Work in progress: this README only describes what exists so far.

## What exists today

- `contract/`: the vault contract in Rust (near-sdk). Spending rules, hash-chained receipts, circuit breaker.

## Run the tests

Needs Rust stable. No keys, no network.

```
cd contract
cargo test
```
