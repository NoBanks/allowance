// The dashboard is a static page that reads the chain directly: no server, no keys.
// Memos are attacker-controlled text, so everything goes in through textContent.
import { sha256 } from "https://cdn.jsdelivr.net/npm/@noble/hashes@2.0.1/sha2.js/+esm";
import { ed25519 } from "https://cdn.jsdelivr.net/npm/@noble/curves@2.0.1/ed25519.js/+esm";
import { makeVerifier } from "../verifier/core.mjs";

const POLL_MS = 5000;
const PAGE = 50;
const NS_PER_DAY = 86_400_000_000_000n;
const ACCOUNT_ID = /^[a-z0-9._-]{2,64}$/;

const REASONS = {
  recipient_not_allowed: "Not on the list of who may be paid",
  over_tx_cap: "Over the most allowed per payment",
  over_daily_cap: "Would go past today's limit",
  outside_hours: "Outside the allowed hours",
  insufficient_funds: "Would dip into the reserve",
  bad_signature: "Not signed by the agent's key",
  stale_nonce: "Replay of an old request",
  memo_too_long: "Memo too long",
  zero_amount: "Zero amount",
};

const $ = (id) => document.getElementById(id);
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16));
const encoder = new TextEncoder();

const sha256Hex = (text) => hex(sha256(encoder.encode(text)));

const verifier = makeVerifier({
  sha256Hex,
  verifySignature(publicKeyHex, message, signatureHex) {
    if (!/^[0-9a-f]{128}$/.test(signatureHex)) return false;
    try {
      return ed25519.verify(fromHex(signatureHex), encoder.encode(message), fromHex(publicKeyHex));
    } catch {
      return false;
    }
  },
});

function near(yocto, places = 4) {
  const v = BigInt(yocto);
  const whole = v / 10n ** 24n;
  const frac = (v % 10n ** 24n).toString().padStart(24, "0").slice(0, places);
  return `${whole}.${frac}`;
}

function base58(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = BigInt("0x" + hex(bytes));
  let s = "";
  while (n > 0n) {
    s = alphabet[Number(n % 58n)] + s;
    n /= 58n;
  }
  return s;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const state = { deployment: null, vault: null, rpc: null, receipts: [], status: null, keys: [], account: null, shown: -1 };

async function rpc(method, params) {
  const res = await fetch(state.rpc, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "allowance", method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(JSON.stringify(body.error));
  if (body.result?.error) throw new Error(body.result.error);
  return body.result;
}

const query = (params) => rpc("query", { finality: "final", ...params });

async function view(method, args = {}) {
  const result = await query({
    request_type: "call_function",
    account_id: state.vault,
    method_name: method,
    args_base64: btoa(JSON.stringify(args)),
  });
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(result.result)));
}

async function refresh() {
  const [status, policy, keyList, account] = await Promise.all([
    view("get_status"),
    view("get_policy"),
    query({ request_type: "view_access_key_list", account_id: state.vault }),
    query({ request_type: "view_account", account_id: state.vault }),
  ]);
  const count = Number(status.receipt_count);
  while (state.receipts.length < count) {
    const page = await view("get_receipts", { from: String(state.receipts.length), limit: PAGE });
    if (page.length === 0) break;
    state.receipts.push(...page);
  }
  Object.assign(state, { status, policy, keys: keyList.keys, account });
  renderRail();
  renderLedger();
}

function renderRail() {
  const { status, policy, keys } = state;
  const today = BigInt(Date.now()) * 1_000_000n / NS_PER_DAY;
  const spent = BigInt(status.spend_day) === today ? BigInt(status.spent_today) : 0n;
  const cap = BigInt(policy.daily_cap);
  $("spent").textContent = near(spent, 2);
  $("cap").textContent = near(cap, 2);
  const pct = cap === 0n ? 0 : Number((spent * 100n) / cap);
  $("bar").style.width = `${Math.min(pct, 100)}%`;
  $("bar").parentElement.classList.toggle("full", pct >= 100);

  $("balance").textContent = `${near(status.balance, 2)} NEAR`;
  $("txcap").textContent = `${near(policy.per_tx_cap, 2)} NEAR`;
  $("reserve").textContent = `${near(policy.reserve, 2)} NEAR`;
  $("hours").textContent = policy.allowed_hours ? `${policy.allowed_hours[0]}:00 to ${policy.allowed_hours[1]}:00` : "Any";
  $("breaker").textContent = `${policy.max_consecutive_blocked} refusals`;

  $("allowlist").replaceChildren(...policy.allowlist.map((a) => el("li", "", a)));

  const full = keys.filter((k) => k.access_key.permission === "FullAccess").length;
  const box = $("keys");
  box.replaceChildren(
    el("span", full === 0 ? "ok" : "bad", `${full} full-access. `),
    el("span", "", `${keys.length - full} agent key, can only call propose.`),
  );

  $("frozen").hidden = !status.paused;
  $("frozen-why").textContent = status.paused
    ? status.pause_reason === "circuit_breaker" ? "Too many refusals in a row. Only the owner can unfreeze it." : `Reason: ${status.pause_reason}`
    : "";
}

// Payments settle in a later receipt. The book shows one line per payment.
function linesFrom(receipts) {
  const settlement = new Map();
  for (const r of receipts) {
    if (r.kind === "settled" || r.kind === "settlement_failed") settlement.set(String(r.nonce), r.kind);
  }
  return receipts.filter((r) => r.kind !== "settled" && r.kind !== "settlement_failed").map((r) => ({ r, settled: settlement.get(String(r.seq)) }));
}

function renderLine({ r, settled }, fresh) {
  const li = el("li", "line");
  const when = new Date(Number(BigInt(r.timestamp_ns) / 1_000_000n));
  const seq = el("span", "seq", `#${r.seq}`);
  const time = el("span", "when", when.toISOString().slice(5, 16).replace("T", " "));
  const what = el("div", "what");
  const amount = el("div", "amount");
  let stamp = null;

  if (r.kind === "allowed" || r.kind === "withdrawn") {
    const failed = settled === "settlement_failed";
    what.append(el("div", "who", r.recipient));
    if (r.kind === "withdrawn") what.append(el("div", "memo", "Owner took money back"));
    else if (r.memo) what.append(el("div", "memo", r.memo));
    if (failed) what.append(el("div", "why", "Account does not exist. Money came back, cap restored."));
    amount.append(near(r.amount), el("small", "", " NEAR"));
    stamp = failed ? el("span", "stamp bounced", "BOUNCED") : settled ? el("span", "stamp paid", "PAID") : el("span", "stamp pending", "SENDING");
  } else if (r.kind === "blocked") {
    li.classList.add("refused");
    what.append(el("div", "who", r.recipient));
    what.append(el("div", "why", REASONS[r.reason] ?? r.reason));
    if (r.memo) what.append(el("div", "memo", `"${r.memo}"`));
    amount.append(near(r.amount), el("small", "", " NEAR"));
    stamp = el("span", "stamp refused", "REFUSED");
  } else {
    li.classList.add("event");
    const words = {
      genesis: "The box was opened. Terms set by the owner.",
      policy_changed: "The owner changed the terms.",
      paused: r.reason === "circuit_breaker" ? "Frozen: too many refusals in a row." : r.reason === "attempt_limit" ? "Frozen: too many attempts today." : "Frozen by the owner.",
      resumed: `Unfrozen by the owner. ${r.detail ? JSON.parse(r.detail).suppressed_attempts : 0} attempt(s) refused while frozen.`,
      agent_rotated: "The owner replaced the agent's keys.",
    };
    if (r.kind === "paused") li.classList.add("frozen-line");
    what.append(el("div", "who", words[r.kind] ?? r.kind));
  }
  li.append(seq, time, what, amount, stamp ?? el("span"));
  if (fresh) li.classList.add("fresh");
  return li;
}

function renderLedger() {
  const receipts = state.receipts;
  const newest = receipts.length - 1;
  if (newest === state.shown && !state.pendingRedraw) return;
  const firstPaint = state.shown === -1;
  const lines = linesFrom(receipts);
  const nodes = lines
    .slice()
    .reverse()
    .map((line) => renderLine(line, firstPaint || Number(line.r.seq) > state.shown));
  $("ledger").replaceChildren(...nodes);
  state.shown = newest;
  $("count").textContent = `${receipts.length} receipts on chain, shown here as ${lines.length} lines. Newest first.`;
  $("verify").disabled = false;
  $("forge").disabled = false;
}

function showVerdict({ red, title, intro, checks, stats }) {
  const box = $("verdict");
  box.hidden = false;
  box.classList.toggle("red", red);
  box.replaceChildren();
  box.style.animation = "none";
  void box.offsetWidth;
  box.style.animation = "";
  box.append(el("h3", "", title));
  if (intro) box.append(el("p", "", intro));
  const ul = el("ul");
  for (const c of checks) ul.append(el("li", c.pass ? "" : "fail", c.text));
  box.append(ul);
  if (stats) box.append(el("p", "stats", stats));
  document.body.dataset.verdict = red ? "red" : "green";
}

async function liveChecks() {
  const checks = [];
  const full = state.keys.filter((k) => k.access_key.permission === "FullAccess").length;
  checks.push({ pass: full === 0, text: `No full-access key on the vault (${state.keys.length} key, ${full} full-access)` });
  const onlyPropose = state.keys.length > 0 && state.keys.every((k) => {
    const f = k.access_key.permission.FunctionCall;
    return f && f.receiver_id === state.vault && f.method_names.length === 1 && f.method_names[0] === "propose";
  });
  checks.push({ pass: onlyPropose, text: "Every key can only call propose on this vault" });
  const wasm = await (await fetch("../deployment/allowance.wasm")).arrayBuffer();
  const expected = base58(sha256(new Uint8Array(wasm)));
  checks.push({ pass: state.account.code_hash === expected, text: `The code on chain is the code in the repo (${expected.slice(0, 16)}...)` });
  return checks;
}

function statsLine(s) {
  return `Paid out ${near(s.spentYocto)} NEAR. Refused ${near(s.blockedYocto)} NEAR across ${s.blocked} attempts. ${s.receipts} receipts replayed.`;
}

async function runVerify() {
  $("verify").disabled = true;
  try {
    await refresh();
    const receipts = state.receipts.slice(0, Number(state.status.receipt_count));
    const result = verifier.replay(receipts, { vault: state.vault, head: state.status.head_hash });
    const checks = await liveChecks();
    checks.push({ pass: result.ok, text: "Hash chain, signatures and spending rules replay clean, here in your browser" });
    for (const p of result.problems) checks.push({ pass: false, text: `Receipt ${p.seq} [${p.check}] ${p.message}` });
    const ok = checks.every((c) => c.pass);
    showVerdict({
      red: !ok,
      title: ok ? "The box held. The record is intact." : "Do not trust this vault.",
      checks,
      stats: statsLine(result.summary),
    });
  } catch (e) {
    showVerdict({ red: true, title: "Could not finish checking.", checks: [{ pass: false, text: String(e.message || e) }] });
  } finally {
    $("verify").disabled = false;
  }
}

// Works on a private copy in this browser tab. Nothing is written anywhere.
function runForge() {
  const copy = state.receipts.map((r) => ({ ...r }));
  const i = copy.findIndex((r) => r.kind === "blocked" && r.reason === "recipient_not_allowed");
  if (i < 0) {
    showVerdict({ red: false, title: "Nothing to forge yet.", checks: [{ pass: true, text: "This vault has no refused payment to rewrite." }] });
    return;
  }
  const target = copy[i];
  target.kind = "allowed";
  target.reason = "";
  for (let n = i; n < copy.length; n++) {
    copy[n].prev_hash = copy[n - 1].hash;
    copy[n].hash = sha256Hex(verifier.receiptPreimage(copy[n]));
  }
  const result = verifier.replay(copy, { vault: state.vault, head: copy.at(-1).hash });
  const policyCaught = result.problems.find((p) => p.check === "policy");
  showVerdict({
    red: true,
    title: result.ok ? "The forgery got through. This is a bug." : "Forgery caught.",
    intro: `On a private copy in this tab: receipt ${target.seq} was refused, so it was rewritten as paid, and every hash after it was redone so the chain still links perfectly. The hashes all pass. The rules do not.`,
    checks: [
      { pass: true, text: `Hash chain: every link is valid, because the forger redid them all` },
      policyCaught
        ? { pass: false, text: `Receipt ${policyCaught.seq}: ${policyCaught.message.replace(/payment of (\d+)/, (_, y) => `payment of ${near(y)} NEAR`)}` }
        : { pass: false, text: "The verifier did not catch it" },
    ],
    stats: "Nothing was written to the chain. Press Verify it yourself to check the real record.",
  });
  document.body.dataset.forgery = result.ok ? "missed" : "caught";
}

async function start() {
  const params = new URLSearchParams(location.search);
  state.deployment = await (await fetch("../deployment/testnet.json")).json();
  const asked = params.get("vault");
  state.vault = asked && ACCOUNT_ID.test(asked) ? asked : state.deployment.vault;
  state.rpc = state.deployment.rpc;

  const link = $("vault-link");
  link.textContent = state.vault;
  link.href = `https://testnet.nearblocks.io/address/${encodeURIComponent(state.vault)}`;

  $("verify").addEventListener("click", runVerify);
  $("forge").addEventListener("click", runForge);

  await refresh();
  setInterval(() => {
    if (!document.hidden) refresh().catch(() => {});
  }, POLL_MS);

  // For automated checks: ?auto=verify or ?auto=forge presses the button on load.
  if (params.get("auto") === "verify") await runVerify();
  if (params.get("auto") === "forge") runForge();
  document.body.dataset.ready = "1";
}

start().catch((e) => {
  $("count").textContent = `Could not read the chain: ${e.message || e}`;
  document.body.dataset.ready = "error";
});
