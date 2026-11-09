// The replay logic, with no platform dependency. The command-line verifier and the
// dashboard run this same file, so there is one implementation of the rules to trust.
// Three layers: the hash links, the agent's signatures, and the spending rules
// themselves. A vault that wrote a perfectly hashed receipt for a payment its own
// policy forbids still fails here. The rule order mirrors contract/src/policy.rs.
export const GENESIS_PREV = "0".repeat(64);

/** @param {{ sha256Hex: (s: string) => string, verifySignature: (publicKeyHex: string, message: string, signatureHex: string) => boolean }} crypto */
export function makeVerifier({ sha256Hex, verifySignature }) {
  const NS_PER_HOUR = 3_600_000_000_000n;
  const NS_PER_DAY = 24n * NS_PER_HOUR;
  const MAX_MEMO_BYTES = 140;

  function receiptPreimage(r) {
    return [
      "allowance-receipt-v1",
      r.seq,
      r.prev_hash,
      r.kind,
      r.actor,
      r.recipient ?? "",
      r.amount,
      r.nonce,
      r.memo_sha256,
      r.reason,
      sha256Hex(r.detail),
      r.agent_signature,
      r.timestamp_ns,
    ].join("\n");
  }

  function intentMessage(vault, nonce, recipient, amount, memoSha) {
    return `allowance-intent-v1\n${vault}\n${nonce}\n${recipient}\n${amount}\n${memoSha}`;
  }

  function hourInWindow(hour, start, end) {
    return start < end ? hour >= start && hour < end : hour >= start || hour < end;
  }

  // The first rule that would refuse this attempt, or null. `insufficient_funds` depends
  // on the live balance, which the chain alone does not carry; see the caller.
  function expectedBlock(r, state, sigValid) {
    const amount = BigInt(r.amount);
    const nonce = BigInt(r.nonce);
    const ts = BigInt(r.timestamp_ns);
    const p = state.policy;
    if (!sigValid) return "bad_signature";
    if (nonce <= state.lastNonce) return "stale_nonce";
    if (r.memo === "" && r.memo_sha256 !== sha256Hex("") && r.reason === "memo_too_long") return "memo_too_long";
    if (new TextEncoder().encode(r.memo).length > MAX_MEMO_BYTES) return "memo_too_long";
    if (amount === 0n) return "zero_amount";
    if (!p.allowlist.includes(r.recipient)) return "recipient_not_allowed";
    if (amount > BigInt(p.per_tx_cap)) return "over_tx_cap";
    if (p.allowed_hours) {
      const hour = Number((ts % NS_PER_DAY) / NS_PER_HOUR);
      if (!hourInWindow(hour, p.allowed_hours[0], p.allowed_hours[1])) return "outside_hours";
    }
    if (state.spentToday + amount > BigInt(p.daily_cap)) return "over_daily_cap";
    return null;
  }

  /**
   * @param {object[]} receipts every receipt from seq 0
   * @param {object} opts { vault, head } head is the vault's reported head hash, to catch truncation
   * @returns {{ ok: boolean, problems: {seq:number, check:string, message:string}[], summary: object }}
   */
  function replay(receipts, { vault, head } = {}) {
    const problems = [];
    const fail = (seq, check, message) => problems.push({ seq, check, message });
    const summary = { receipts: receipts.length, allowed: 0, blocked: 0, settled: 0, settlementFailed: 0, withdrawn: 0, policyChanges: 0, pauses: 0, spentYocto: 0n, blockedYocto: 0n, unsettled: [], blockReasons: {} };

    if (receipts.length === 0) {
      fail(0, "chain", "no receipts");
      return { ok: false, problems, summary };
    }

    const state = { policy: null, signingKey: null, paused: false, lastNonce: 0n, spentToday: 0n, day: null, attempts: 0, streak: 0, breakerDue: false, spendDays: new Map(), openSettlements: new Set() };
    let prev = GENESIS_PREV;

    receipts.forEach((r, i) => {
      const seq = Number(r.seq);
      if (seq !== i) fail(i, "sequence", `expected seq ${i}, found ${r.seq}`);
      if (r.prev_hash !== prev) fail(seq, "link", `prev_hash does not match receipt ${i - 1}`);
      const computed = sha256Hex(receiptPreimage(r));
      if (computed !== r.hash) fail(seq, "hash", "receipt contents do not match its hash");
      prev = r.hash;

      if (r.memo !== "" && sha256Hex(r.memo) !== r.memo_sha256) fail(seq, "memo", "memo does not match its hash");

      const ts = BigInt(r.timestamp_ns);
      const today = ts / NS_PER_DAY;
      if (state.day !== null && today !== state.day) {
        state.spentToday = 0n;
        state.attempts = 0;
      }
      state.day = today;

      if (state.breakerDue && !(r.kind === "paused" && r.reason === "circuit_breaker")) {
        fail(seq, "breaker", "the blocked streak reached the limit but the vault did not freeze");
      }
      state.breakerDue = false;

      switch (r.kind) {
        case "genesis": {
          if (i !== 0) fail(seq, "genesis", "genesis must be the first receipt");
          const d = JSON.parse(r.detail);
          state.policy = d.policy;
          state.signingKey = d.signing_key;
          break;
        }
        case "policy_changed":
          state.policy = JSON.parse(r.detail);
          summary.policyChanges++;
          break;
        case "agent_rotated":
          state.signingKey = JSON.parse(r.detail).signing_key;
          break;
        case "allowed":
        case "blocked": {
          if (!state.policy) {
            fail(seq, "genesis", "attempt before genesis");
            break;
          }
          if (state.paused) fail(seq, "paused", `${r.kind} attempt recorded while the vault was frozen`);
          state.attempts++;
          const sigValid = vault
            ? verifySignature(state.signingKey, intentMessage(vault, r.nonce, r.recipient, r.amount, r.memo_sha256), r.agent_signature)
            : true;
          const expected = expectedBlock(r, state, sigValid);
          if (r.kind === "allowed") {
            if (expected) fail(seq, "policy", `payment of ${r.amount} to ${r.recipient} was allowed but the policy says ${expected}`);
            state.spentToday += BigInt(r.amount);
            state.lastNonce = BigInt(r.nonce) > state.lastNonce ? BigInt(r.nonce) : state.lastNonce;
            state.streak = 0;
            state.spendDays.set(seq, today);
            state.openSettlements.add(seq);
            summary.allowed++;
            summary.spentYocto += BigInt(r.amount);
          } else {
            // insufficient_funds is the one reason the chain cannot re-derive: it depends on
            // the live balance. It is only accepted when every other rule passes.
            const accepted = expected === r.reason || (expected === null && r.reason === "insufficient_funds");
            if (!accepted) fail(seq, "policy", `blocked as ${r.reason} but the policy says ${expected ?? "allow"}`);
            if (sigValid && BigInt(r.nonce) > state.lastNonce) state.lastNonce = BigInt(r.nonce);
            state.streak++;
            if (state.streak >= state.policy.max_consecutive_blocked) state.breakerDue = true;
            summary.blocked++;
            summary.blockedYocto += BigInt(r.amount);
            summary.blockReasons[r.reason] = (summary.blockReasons[r.reason] || 0) + 1;
          }
          if (state.attempts > state.policy.max_attempts_per_day) fail(seq, "attempt_limit", "more attempts than the daily limit allows");
          break;
        }
        case "settled":
        case "settlement_failed": {
          const of = Number(r.nonce);
          if (!state.openSettlements.has(of)) fail(seq, "settlement", `settles receipt ${of}, which is not awaiting settlement`);
          state.openSettlements.delete(of);
          const wasAgentSpend = state.spendDays.has(of);
          if (r.kind === "settlement_failed") {
            summary.settlementFailed++;
            if (wasAgentSpend) {
              summary.spentYocto -= BigInt(r.amount);
              if (state.spendDays.get(of) === today) {
                state.spentToday = state.spentToday > BigInt(r.amount) ? state.spentToday - BigInt(r.amount) : 0n;
              }
            }
          } else {
            summary.settled++;
          }
          break;
        }
        case "withdrawn":
          state.openSettlements.add(seq);
          summary.withdrawn++;
          break;
        case "paused":
          state.paused = true;
          summary.pauses++;
          break;
        case "resumed":
          state.paused = false;
          state.streak = 0;
          state.attempts = 0;
          break;
        default:
          fail(seq, "kind", `unknown receipt kind ${r.kind}`);
      }
    });

    summary.unsettled = [...state.openSettlements];
    if (head !== undefined && head !== prev) {
      fail(receipts.length - 1, "head", "the vault reports a different latest receipt, so this chain is incomplete or stale");
    }
    return { ok: problems.length === 0, problems, summary };
  }


  return { replay, receiptPreimage, intentMessage };
}
