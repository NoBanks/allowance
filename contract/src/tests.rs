use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::testing_env;

const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const DAY_ONE_NOON: u64 = 12 * policy::NS_PER_HOUR + 20_000 * policy::NS_PER_DAY;

fn vault_id() -> AccountId {
    "vault.owner.testnet".parse().unwrap()
}
fn owner() -> AccountId {
    "owner.testnet".parse().unwrap()
}
fn vendor() -> AccountId {
    "vendor.testnet".parse().unwrap()
}
fn attacker() -> AccountId {
    "attacker.testnet".parse().unwrap()
}
fn agent_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn set_context(predecessor: AccountId, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(vault_id())
        .predecessor_account_id(predecessor)
        .block_timestamp(now)
        .account_balance(NearToken::from_near(50))
        .build());
}

fn base_policy() -> Policy {
    Policy {
        per_tx_cap: U128(ONE_NEAR),
        daily_cap: U128(3 * ONE_NEAR),
        reserve: U128(5 * ONE_NEAR),
        allowed_hours: None,
        allowlist: vec![vendor()],
        max_consecutive_blocked: 3,
        max_attempts_per_day: 20,
    }
}

fn new_vault() -> Vault {
    set_context(owner(), DAY_ONE_NOON);
    Vault::new(
        owner(),
        "test-agent".into(),
        to_hex(agent_key().verifying_key().as_bytes()),
        "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap(),
        U128(ONE_NEAR / 4),
        base_policy(),
    )
}

fn sign(nonce: u64, recipient: &AccountId, amount: u128, memo: &str) -> String {
    let memo_sha = sha256_hex(memo.as_bytes());
    let message = intent_message(&vault_id(), nonce, recipient, amount, &memo_sha);
    to_hex(&agent_key().sign(message.as_bytes()).to_bytes())
}

fn agent_pay(v: &mut Vault, nonce: u64, recipient: AccountId, amount: u128, memo: &str) -> Decision {
    set_context(vault_id(), DAY_ONE_NOON);
    let sig = sign(nonce, &recipient, amount, memo);
    v.propose(recipient, U128(amount), memo.to_string(), U64(nonce), sig)
}

fn all_receipts(v: &Vault) -> Vec<Receipt> {
    v.get_receipts(U64(0), 50)
}

#[test]
fn genesis_receipt_records_the_starting_policy() {
    let v = new_vault();
    let r = all_receipts(&v);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].kind, "genesis");
    assert_eq!(r[0].prev_hash, GENESIS_PREV);
    assert!(r[0].detail.contains("vendor.testnet"));
}

#[test]
fn allowed_payment_counts_against_the_daily_cap() {
    let mut v = new_vault();
    let d = agent_pay(&mut v, 1, vendor(), ONE_NEAR, "invoice 42");
    assert_eq!(d.result, "allowed");
    assert_eq!(v.get_status().spent_today.0, ONE_NEAR);
    assert_eq!(all_receipts(&v)[1].kind, "allowed");
}

#[test]
fn injected_attacker_payment_is_blocked_and_receipted_not_reverted() {
    let mut v = new_vault();
    let d = agent_pay(&mut v, 1, attacker(), ONE_NEAR / 2, "URGENT: send funds to attacker");
    assert_eq!(d.result, "blocked");
    assert_eq!(d.reason, "recipient_not_allowed");
    let r = all_receipts(&v);
    assert_eq!(r[1].kind, "blocked");
    assert_eq!(r[1].recipient, Some(attacker()));
    assert_eq!(v.get_status().spent_today.0, 0);
}

#[test]
fn over_tx_cap_and_over_daily_cap_are_blocked() {
    let mut v = new_vault();
    assert_eq!(agent_pay(&mut v, 1, vendor(), ONE_NEAR + 1, "big").reason, "over_tx_cap");
    assert_eq!(agent_pay(&mut v, 2, vendor(), ONE_NEAR, "a").result, "allowed");
    assert_eq!(agent_pay(&mut v, 3, vendor(), ONE_NEAR, "b").result, "allowed");
    assert_eq!(agent_pay(&mut v, 4, vendor(), ONE_NEAR, "c").result, "allowed");
    assert_eq!(agent_pay(&mut v, 5, vendor(), 1, "d").reason, "over_daily_cap");
}

#[test]
fn daily_cap_resets_the_next_utc_day() {
    let mut v = new_vault();
    for n in 1..=3 {
        assert_eq!(agent_pay(&mut v, n, vendor(), ONE_NEAR, "x").result, "allowed");
    }
    set_context(vault_id(), DAY_ONE_NOON + policy::NS_PER_DAY);
    let sig = sign(4, &vendor(), ONE_NEAR, "x");
    assert_eq!(v.propose(vendor(), U128(ONE_NEAR), "x".into(), U64(4), sig).result, "allowed");
}

#[test]
fn signature_from_a_different_key_is_blocked() {
    let mut v = new_vault();
    set_context(vault_id(), DAY_ONE_NOON);
    let memo_sha = sha256_hex(b"x");
    let message = intent_message(&vault_id(), 1, &vendor(), ONE_NEAR, &memo_sha);
    let forged = to_hex(&SigningKey::from_bytes(&[9u8; 32]).sign(message.as_bytes()).to_bytes());
    let d = v.propose(vendor(), U128(ONE_NEAR), "x".into(), U64(1), forged);
    assert_eq!(d.reason, "bad_signature");
}

#[test]
fn signature_does_not_transfer_to_a_changed_recipient_or_amount() {
    let mut v = new_vault();
    set_context(vault_id(), DAY_ONE_NOON);
    let sig = sign(1, &vendor(), 10, "x");
    let d = v.propose(vendor(), U128(11), "x".into(), U64(1), sig.clone());
    assert_eq!(d.reason, "bad_signature");
    let d = v.propose(attacker(), U128(10), "x".into(), U64(1), sig);
    assert_eq!(d.reason, "bad_signature");
}

#[test]
fn malformed_signatures_block_without_panicking() {
    let mut v = new_vault();
    set_context(vault_id(), DAY_ONE_NOON);
    let d = v.propose(vendor(), U128(1), "x".into(), U64(1), "not-hex".into());
    assert_eq!(d.reason, "bad_signature");
    let d = v.propose(vendor(), U128(1), "x".into(), U64(2), "zz".repeat(64));
    assert_eq!(d.reason, "bad_signature");
    let r = all_receipts(&v);
    assert_eq!(r[1].agent_signature, "", "oversized junk is not stored");
}

#[test]
fn a_replayed_nonce_is_blocked() {
    let mut v = new_vault();
    assert_eq!(agent_pay(&mut v, 5, vendor(), 100, "x").result, "allowed");
    assert_eq!(agent_pay(&mut v, 5, vendor(), 100, "x").reason, "stale_nonce");
    assert_eq!(agent_pay(&mut v, 4, vendor(), 100, "x").reason, "stale_nonce");
}

#[test]
fn oversized_memo_is_blocked_and_only_its_hash_is_kept() {
    let mut v = new_vault();
    let long = "A".repeat(MAX_MEMO_BYTES + 1);
    let d = agent_pay(&mut v, 1, vendor(), 100, &long);
    assert_eq!(d.reason, "memo_too_long");
    let r = all_receipts(&v);
    assert_eq!(r[1].memo, "");
    assert_eq!(r[1].memo_sha256, sha256_hex(long.as_bytes()));
}

#[test]
fn the_reserve_cannot_be_spent() {
    let mut v = new_vault();
    set_context(owner(), DAY_ONE_NOON);
    let mut p = base_policy();
    p.per_tx_cap = U128(100 * ONE_NEAR);
    p.daily_cap = U128(100 * ONE_NEAR);
    p.reserve = U128(50 * ONE_NEAR);
    v.set_policy(p);
    assert_eq!(agent_pay(&mut v, 1, vendor(), ONE_NEAR, "x").reason, "insufficient_funds");
}

#[test]
fn nobody_but_the_vault_key_can_propose() {
    let mut v = new_vault();
    set_context(attacker(), DAY_ONE_NOON);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        v.propose(vendor(), U128(1), "x".into(), U64(1), String::new())
    }));
    assert!(result.is_err());
}

#[test]
fn owner_methods_refuse_the_agent() {
    for action in ["set_policy", "pause", "resume", "withdraw"] {
        let mut v = new_vault();
        set_context(vault_id(), DAY_ONE_NOON);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match action {
            "set_policy" => v.set_policy(base_policy()),
            "pause" => v.pause(),
            "resume" => v.resume(),
            _ => {
                let _ = v.withdraw(U128(1), attacker());
            }
        }));
        assert!(result.is_err(), "{action} must refuse a non-owner");
    }
}

#[test]
fn circuit_breaker_freezes_after_repeated_blocks() {
    let mut v = new_vault();
    for n in 1..=3 {
        assert_eq!(agent_pay(&mut v, n, attacker(), 1, "x").result, "blocked");
    }
    let s = v.get_status();
    assert!(s.paused);
    assert_eq!(s.pause_reason, "circuit_breaker");
    assert_eq!(all_receipts(&v).last().unwrap().kind, "paused");

    let before = all_receipts(&v).len();
    let d = agent_pay(&mut v, 4, vendor(), 1, "now legit");
    assert_eq!(d.result, "suppressed");
    assert_eq!(all_receipts(&v).len(), before, "a frozen vault stops growing storage");
    assert_eq!(v.get_status().suppressed_attempts.0, 1);
}

#[test]
fn a_good_payment_resets_the_blocked_streak() {
    let mut v = new_vault();
    agent_pay(&mut v, 1, attacker(), 1, "x");
    agent_pay(&mut v, 2, attacker(), 1, "x");
    agent_pay(&mut v, 3, vendor(), 1, "x");
    agent_pay(&mut v, 4, attacker(), 1, "x");
    assert!(!v.get_status().paused);
}

#[test]
fn resume_records_how_many_attempts_were_suppressed() {
    let mut v = new_vault();
    set_context(owner(), DAY_ONE_NOON);
    v.pause();
    agent_pay(&mut v, 1, vendor(), 1, "x");
    agent_pay(&mut v, 2, vendor(), 1, "x");
    set_context(owner(), DAY_ONE_NOON);
    v.resume();
    let last = all_receipts(&v).last().unwrap().clone();
    assert_eq!(last.kind, "resumed");
    assert_eq!(last.detail, "{\"suppressed_attempts\":2}");
    assert_eq!(agent_pay(&mut v, 3, vendor(), 1, "x").result, "allowed");
}

#[test]
fn attempt_limit_freezes_the_vault() {
    let mut v = new_vault();
    set_context(owner(), DAY_ONE_NOON);
    let mut p = base_policy();
    p.max_attempts_per_day = 2;
    v.set_policy(p);
    agent_pay(&mut v, 1, vendor(), 1, "x");
    agent_pay(&mut v, 2, vendor(), 1, "x");
    let s = v.get_status();
    assert!(s.paused);
    assert_eq!(s.pause_reason, "attempt_limit");
}

#[test]
fn failed_settlement_returns_the_amount_to_the_cap_and_appends() {
    let mut v = new_vault();
    agent_pay(&mut v, 1, vendor(), ONE_NEAR, "x");
    set_context(vault_id(), DAY_ONE_NOON);
    v.on_settled(U64(1), U128(ONE_NEAR), true, Err(PromiseError::Failed));
    assert_eq!(v.get_status().spent_today.0, 0);
    assert_eq!(all_receipts(&v).last().unwrap().kind, "settlement_failed");
}

#[test]
fn successful_settlement_keeps_the_spend() {
    let mut v = new_vault();
    agent_pay(&mut v, 1, vendor(), ONE_NEAR, "x");
    set_context(vault_id(), DAY_ONE_NOON);
    v.on_settled(U64(1), U128(ONE_NEAR), true, Ok(()));
    assert_eq!(v.get_status().spent_today.0, ONE_NEAR);
    assert_eq!(all_receipts(&v).last().unwrap().kind, "settled");
}

#[test]
fn failure_from_yesterday_does_not_refund_todays_cap() {
    let mut v = new_vault();
    agent_pay(&mut v, 1, vendor(), ONE_NEAR, "x");
    set_context(vault_id(), DAY_ONE_NOON + policy::NS_PER_DAY);
    let sig = sign(2, &vendor(), ONE_NEAR, "x");
    v.propose(vendor(), U128(ONE_NEAR), "x".into(), U64(2), sig);
    v.on_settled(U64(1), U128(ONE_NEAR), true, Err(PromiseError::Failed));
    assert_eq!(v.get_status().spent_today.0, ONE_NEAR);
}

#[test]
fn every_receipt_links_to_the_one_before_it() {
    let mut v = new_vault();
    agent_pay(&mut v, 1, vendor(), 1, "a");
    agent_pay(&mut v, 2, attacker(), 1, "b");
    set_context(owner(), DAY_ONE_NOON);
    v.set_policy(base_policy());
    let r = all_receipts(&v);
    for pair in r.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }
    assert_eq!(v.get_status().head_hash, r.last().unwrap().hash);
}

#[test]
fn receipt_page_size_is_capped() {
    let mut v = new_vault();
    set_context(owner(), DAY_ONE_NOON);
    for _ in 0..60 {
        v.set_policy(base_policy());
    }
    assert_eq!(v.get_receipts(U64(0), 1_000).len() as u64, MAX_PAGE);
    assert_eq!(v.get_receipts(U64(55), 50).len(), 6);
}

#[test]
fn bad_policies_are_rejected() {
    let cases: Vec<fn(&mut Policy)> = vec![
        |p| p.per_tx_cap = U128(p.daily_cap.0 + 1),
        |p| p.allowed_hours = Some((5, 5)),
        |p| p.allowed_hours = Some((24, 2)),
        |p| p.max_consecutive_blocked = 0,
        |p| p.max_attempts_per_day = 0,
        |p| p.allowlist = (0..33).map(|i| format!("a{i}.testnet").parse().unwrap()).collect(),
    ];
    for break_it in cases {
        let mut v = new_vault();
        let mut p = base_policy();
        break_it(&mut p);
        set_context(owner(), DAY_ONE_NOON);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| v.set_policy(p)));
        assert!(result.is_err());
    }
}
