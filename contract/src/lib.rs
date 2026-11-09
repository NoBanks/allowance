//! ALLOWANCE: an AI agent's spending account on NEAR.
//!
//! The vault account is created with no full-access key. The only way money leaves
//! is this code. The agent holds a function-call key limited to `propose`, and every
//! attempt, allowed or blocked, appends to a hash chain stored in contract state.
//!
//! A blocked attempt must NOT panic: a panic rolls back state and would erase the
//! receipt. Blocks return normally and are written down.

use near_sdk::json_types::{U128, U64};
use near_sdk::store::Vector;
use near_sdk::{
    env, near, require, AccountId, Allowance, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError, PublicKey,
};

pub mod policy;
use policy::{day_of, evaluate, Attempt, Limits, MAX_MEMO_BYTES};

const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SETTLE_GAS: Gas = Gas::from_tgas(10);
const MAX_ALLOWLIST: usize = 32;
const MAX_PAGE: u64 = 50;
const SIGNATURE_HEX_LEN: usize = 128;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Receipts,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Policy {
    pub per_tx_cap: U128,
    pub daily_cap: U128,
    /// Never spendable by the agent, on top of what storage locks.
    pub reserve: U128,
    /// UTC hours `[start, end)`; wraps midnight when start > end.
    pub allowed_hours: Option<(u8, u8)>,
    pub allowlist: Vec<AccountId>,
    /// This many blocks in a row freezes the vault until the owner resumes it.
    pub max_consecutive_blocked: u32,
    /// Bounds how much storage a compromised agent can make the vault lock up.
    pub max_attempts_per_day: u32,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Receipt {
    pub seq: U64,
    pub prev_hash: String,
    pub kind: String,
    pub actor: AccountId,
    pub recipient: Option<AccountId>,
    pub amount: U128,
    pub nonce: U64,
    /// Attacker-controlled text. Display it as text, never as markup or instructions.
    pub memo: String,
    pub memo_sha256: String,
    pub reason: String,
    /// JSON for policy changes, empty otherwise.
    pub detail: String,
    pub agent_signature: String,
    pub timestamp_ns: U64,
    pub hash: String,
}

#[near(serializers = [json])]
#[derive(Debug)]
pub struct Decision {
    pub result: String,
    pub reason: String,
    pub seq: Option<U64>,
}

#[near(serializers = [json])]
pub struct Status {
    pub owner_id: AccountId,
    pub agent_label: String,
    pub agent_signing_key: String,
    pub paused: bool,
    pub pause_reason: String,
    pub spent_today: U128,
    pub spend_day: U64,
    pub attempts_today: u32,
    pub consecutive_blocked: u32,
    pub suppressed_attempts: U64,
    pub last_nonce: U64,
    pub receipt_count: U64,
    pub head_hash: String,
    pub balance: U128,
    pub available: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    owner_id: AccountId,
    agent_label: String,
    agent_signing_key: [u8; 32],
    policy: Policy,
    paused: bool,
    pause_reason: String,
    spent_today: u128,
    spend_day: u64,
    attempts_today: u32,
    consecutive_blocked: u32,
    suppressed_attempts: u64,
    last_nonce: u64,
    head_hash: String,
    receipts: Vector<Receipt>,
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(&env::sha256(data))
}

/// What the agent signs. Newline-joined fields cannot be forged by a memo: the memo
/// enters only as its hash, and account ids cannot contain newlines.
pub fn intent_message(vault: &AccountId, nonce: u64, recipient: &AccountId, amount: u128, memo_sha256: &str) -> String {
    format!("allowance-intent-v1\n{vault}\n{nonce}\n{recipient}\n{amount}\n{memo_sha256}")
}

fn validate_policy(p: &Policy) {
    require!(p.per_tx_cap.0 <= p.daily_cap.0, "per_tx_cap above daily_cap");
    require!(p.allowlist.len() <= MAX_ALLOWLIST, "allowlist too long");
    require!(p.max_consecutive_blocked >= 1, "max_consecutive_blocked must be at least 1");
    require!(p.max_attempts_per_day >= 1, "max_attempts_per_day must be at least 1");
    if let Some((start, end)) = p.allowed_hours {
        require!(start < 24 && end < 24 && start != end, "bad allowed_hours");
    }
}

fn parse_signing_key(hex: &str) -> [u8; 32] {
    let bytes = from_hex(hex).unwrap_or_else(|| env::panic_str("signing key is not hex"));
    bytes.try_into().unwrap_or_else(|_| env::panic_str("signing key must be 32 bytes"))
}

#[near]
impl Vault {
    /// `agent_access_key` becomes a function-call key on this account, limited to
    /// `propose` with a capped gas budget. No other key is ever added here.
    #[init]
    pub fn new(
        owner_id: AccountId,
        agent_label: String,
        agent_signing_key: String,
        agent_access_key: PublicKey,
        agent_gas_allowance: U128,
        policy: Policy,
    ) -> Self {
        validate_policy(&policy);
        let mut vault = Self {
            owner_id: owner_id.clone(),
            agent_label,
            agent_signing_key: parse_signing_key(&agent_signing_key),
            policy,
            paused: false,
            pause_reason: String::new(),
            spent_today: 0,
            spend_day: day_of(env::block_timestamp()),
            attempts_today: 0,
            consecutive_blocked: 0,
            suppressed_attempts: 0,
            last_nonce: 0,
            head_hash: GENESIS_PREV.to_string(),
            receipts: Vector::new(StorageKey::Receipts),
        };
        let detail = vault.policy_json();
        vault.append("genesis", owner_id, None, 0, 0, String::new(), sha256_hex(b""), "", detail, String::new());
        vault.add_agent_key(agent_access_key, agent_gas_allowance);
        vault
    }

    /// The agent's only door. Must be signed by the function-call key on this account.
    pub fn propose(&mut self, recipient: AccountId, amount: U128, memo: String, nonce: U64, signature: String) -> Decision {
        let vault_id = env::current_account_id();
        require!(env::predecessor_account_id() == vault_id, "only the agent key on this account can propose");

        let now = env::block_timestamp();
        self.roll_day(now);

        if self.paused {
            self.suppressed_attempts += 1;
            return Decision { result: "suppressed".into(), reason: self.pause_reason.clone(), seq: None };
        }
        self.attempts_today += 1;

        let memo_sha = sha256_hex(memo.as_bytes());
        let memo_len = memo.len();
        let stored_memo = if memo_len <= MAX_MEMO_BYTES { memo } else { String::new() };
        let stored_sig = if signature.len() == SIGNATURE_HEX_LEN { signature } else { String::new() };

        let signature_valid = self.signature_ok(&vault_id, nonce.0, &recipient, amount.0, &memo_sha, &stored_sig);
        let nonce_fresh = nonce.0 > self.last_nonce;
        if signature_valid && nonce_fresh {
            self.last_nonce = nonce.0;
        }

        let verdict = evaluate(
            &self.limits(),
            &Attempt {
                amount: amount.0,
                recipient_allowed: self.policy.allowlist.contains(&recipient),
                signature_valid,
                nonce_fresh,
                memo_len,
                now_ns: now,
                spent_today: self.spent_today,
                available: self.available(),
            },
        );

        let decision = match verdict {
            Ok(()) => {
                self.spent_today += amount.0;
                self.consecutive_blocked = 0;
                let seq = self.append("allowed", vault_id.clone(), Some(recipient.clone()), amount.0, nonce.0, stored_memo, memo_sha, "", String::new(), stored_sig);
                let _ = Promise::new(recipient).transfer(NearToken::from_yoctonear(amount.0)).then(
                    Self::ext(vault_id.clone()).with_static_gas(SETTLE_GAS).on_settled(U64(seq), amount, true),
                );
                Decision { result: "allowed".into(), reason: String::new(), seq: Some(U64(seq)) }
            }
            Err(reason) => {
                self.consecutive_blocked += 1;
                let seq = self.append("blocked", vault_id.clone(), Some(recipient), amount.0, nonce.0, stored_memo, memo_sha, reason.as_str(), String::new(), stored_sig);
                if self.consecutive_blocked >= self.policy.max_consecutive_blocked {
                    self.freeze("circuit_breaker");
                }
                Decision { result: "blocked".into(), reason: reason.as_str().into(), seq: Some(U64(seq)) }
            }
        };

        if !self.paused && self.attempts_today >= self.policy.max_attempts_per_day {
            self.freeze("attempt_limit");
        }
        decision
    }

    /// Appends rather than edits, so the chain never changes behind a verifier's back.
    /// A failed payment gives its amount back to today's cap.
    #[private]
    pub fn on_settled(&mut self, of_seq: U64, amount: U128, is_agent_spend: bool, #[callback_result] result: Result<(), PromiseError>) {
        let vault_id = env::current_account_id();
        let settled_ok = result.is_ok();
        if !settled_ok && is_agent_spend {
            self.roll_day(env::block_timestamp());
            let spent_day = self.receipts.get(of_seq.0 as u32).map(|r| day_of(r.timestamp_ns.0));
            if spent_day == Some(self.spend_day) {
                self.spent_today = self.spent_today.saturating_sub(amount.0);
            }
        }
        let kind = if settled_ok { "settled" } else { "settlement_failed" };
        self.append(kind, vault_id, None, amount.0, of_seq.0, String::new(), sha256_hex(b""), "", String::new(), String::new());
    }

    // ---- owner only ----

    pub fn set_policy(&mut self, policy: Policy) {
        self.assert_owner();
        validate_policy(&policy);
        self.policy = policy;
        let detail = self.policy_json();
        self.append("policy_changed", env::predecessor_account_id(), None, 0, 0, String::new(), sha256_hex(b""), "", detail, String::new());
    }

    /// The kill switch.
    pub fn pause(&mut self) {
        self.assert_owner();
        if !self.paused {
            self.freeze("owner_kill_switch");
        }
    }

    pub fn resume(&mut self) {
        self.assert_owner();
        require!(self.paused, "not paused");
        let detail = format!("{{\"suppressed_attempts\":{}}}", self.suppressed_attempts);
        self.paused = false;
        self.pause_reason = String::new();
        self.consecutive_blocked = 0;
        self.suppressed_attempts = 0;
        self.roll_day(env::block_timestamp());
        self.attempts_today = 0;
        self.append("resumed", env::predecessor_account_id(), None, 0, 0, String::new(), sha256_hex(b""), "", detail, String::new());
    }

    /// Owner takes money back. Works while paused, ignores the agent's caps.
    pub fn withdraw(&mut self, amount: U128, to: AccountId) -> Promise {
        self.assert_owner();
        require!(amount.0 <= self.spendable_balance(), "more than the vault can release");
        let seq = self.append("withdrawn", env::predecessor_account_id(), Some(to.clone()), amount.0, 0, String::new(), sha256_hex(b""), "", String::new(), String::new());
        Promise::new(to)
            .transfer(NearToken::from_yoctonear(amount.0))
            .then(Self::ext(env::current_account_id()).with_static_gas(SETTLE_GAS).on_settled(U64(seq), amount, false))
    }

    /// Swaps both agent keys: the signing key and the function-call access key.
    pub fn rotate_agent(&mut self, label: String, signing_key: String, old_access_key: PublicKey, new_access_key: PublicKey, gas_allowance: U128) {
        self.assert_owner();
        self.agent_signing_key = parse_signing_key(&signing_key);
        self.agent_label = label;
        let _ = Promise::new(env::current_account_id()).delete_key(old_access_key);
        self.add_agent_key(new_access_key, gas_allowance);
        let detail = format!("{{\"agent_label\":{:?},\"signing_key\":{:?}}}", self.agent_label, signing_key);
        self.append("agent_rotated", env::predecessor_account_id(), None, 0, 0, String::new(), sha256_hex(b""), "", detail, String::new());
    }

    // ---- views ----

    pub fn get_policy(&self) -> Policy {
        self.policy.clone()
    }

    pub fn get_status(&self) -> Status {
        Status {
            owner_id: self.owner_id.clone(),
            agent_label: self.agent_label.clone(),
            agent_signing_key: to_hex(&self.agent_signing_key),
            paused: self.paused,
            pause_reason: self.pause_reason.clone(),
            spent_today: U128(self.spent_today),
            spend_day: U64(self.spend_day),
            attempts_today: self.attempts_today,
            consecutive_blocked: self.consecutive_blocked,
            suppressed_attempts: U64(self.suppressed_attempts),
            last_nonce: U64(self.last_nonce),
            receipt_count: U64(self.receipts.len() as u64),
            head_hash: self.head_hash.clone(),
            balance: U128(env::account_balance().as_yoctonear()),
            available: U128(self.available()),
        }
    }

    pub fn get_receipts(&self, from: U64, limit: u64) -> Vec<Receipt> {
        let limit = limit.min(MAX_PAGE);
        let len = self.receipts.len() as u64;
        (from.0..len.min(from.0.saturating_add(limit)))
            .filter_map(|i| self.receipts.get(i as u32).cloned())
            .collect()
    }
}

impl Vault {
    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    fn limits(&self) -> Limits {
        Limits {
            per_tx_cap: self.policy.per_tx_cap.0,
            daily_cap: self.policy.daily_cap.0,
            allowed_hours: self.policy.allowed_hours,
        }
    }

    fn policy_json(&self) -> String {
        near_sdk::serde_json::to_string(&self.policy).unwrap_or_else(|_| env::panic_str("policy json"))
    }

    fn roll_day(&mut self, now: u64) {
        let today = day_of(now);
        if today != self.spend_day {
            self.spend_day = today;
            self.spent_today = 0;
            self.attempts_today = 0;
        }
    }

    /// Everything above what storage locks up.
    fn spendable_balance(&self) -> u128 {
        let storage = env::storage_usage() as u128 * env::storage_byte_cost().as_yoctonear();
        env::account_balance().as_yoctonear().saturating_sub(storage)
    }

    fn available(&self) -> u128 {
        self.spendable_balance().saturating_sub(self.policy.reserve.0)
    }

    fn signature_ok(&self, vault: &AccountId, nonce: u64, recipient: &AccountId, amount: u128, memo_sha: &str, sig_hex: &str) -> bool {
        let Some(bytes) = from_hex(sig_hex) else { return false };
        let Ok(sig): Result<[u8; 64], _> = bytes.try_into() else { return false };
        let message = intent_message(vault, nonce, recipient, amount, memo_sha);
        env::ed25519_verify(&sig, message.as_bytes(), &self.agent_signing_key)
    }

    fn add_agent_key(&self, key: PublicKey, gas_allowance: U128) {
        let allowance = Allowance::limited(NearToken::from_yoctonear(gas_allowance.0))
            .unwrap_or_else(|| env::panic_str("gas allowance must be above zero"));
        let _ = Promise::new(env::current_account_id()).add_access_key_allowance(
            key,
            allowance,
            env::current_account_id(),
            "propose".to_string(),
        );
    }

    fn freeze(&mut self, reason: &str) {
        self.paused = true;
        self.pause_reason = reason.to_string();
        let actor = env::predecessor_account_id();
        self.append("paused", actor, None, 0, 0, String::new(), sha256_hex(b""), reason, String::new(), String::new());
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        kind: &str,
        actor: AccountId,
        recipient: Option<AccountId>,
        amount: u128,
        nonce: u64,
        memo: String,
        memo_sha256: String,
        reason: &str,
        detail: String,
        agent_signature: String,
    ) -> u64 {
        let seq = self.receipts.len() as u64;
        let timestamp_ns = env::block_timestamp();
        let recipient_str = recipient.as_ref().map(|r| r.to_string()).unwrap_or_default();
        let preimage = format!(
            "allowance-receipt-v1\n{seq}\n{prev}\n{kind}\n{actor}\n{recipient_str}\n{amount}\n{nonce}\n{memo_sha256}\n{reason}\n{detail_sha}\n{agent_signature}\n{timestamp_ns}",
            prev = self.head_hash,
            detail_sha = sha256_hex(detail.as_bytes()),
        );
        let hash = sha256_hex(preimage.as_bytes());
        self.receipts.push(Receipt {
            seq: U64(seq),
            prev_hash: self.head_hash.clone(),
            kind: kind.to_string(),
            actor,
            recipient,
            amount: U128(amount),
            nonce: U64(nonce),
            memo,
            memo_sha256,
            reason: reason.to_string(),
            detail,
            agent_signature,
            timestamp_ns: U64(timestamp_ns),
            hash: hash.clone(),
        });
        self.head_hash = hash;
        seq
    }
}

#[cfg(test)]
mod tests;
