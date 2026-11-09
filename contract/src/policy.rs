//! The spending rules, as a pure function with no chain dependency.
//! The verifier re-implements this exact order of checks in `verifier/replay.mjs`.

pub const NS_PER_HOUR: u64 = 3_600_000_000_000;
pub const NS_PER_DAY: u64 = 24 * NS_PER_HOUR;
pub const MAX_MEMO_BYTES: usize = 140;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    BadSignature,
    StaleNonce,
    MemoTooLong,
    ZeroAmount,
    RecipientNotAllowed,
    OverTxCap,
    OutsideHours,
    OverDailyCap,
    InsufficientFunds,
}

impl BlockReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockReason::BadSignature => "bad_signature",
            BlockReason::StaleNonce => "stale_nonce",
            BlockReason::MemoTooLong => "memo_too_long",
            BlockReason::ZeroAmount => "zero_amount",
            BlockReason::RecipientNotAllowed => "recipient_not_allowed",
            BlockReason::OverTxCap => "over_tx_cap",
            BlockReason::OutsideHours => "outside_hours",
            BlockReason::OverDailyCap => "over_daily_cap",
            BlockReason::InsufficientFunds => "insufficient_funds",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub per_tx_cap: u128,
    pub daily_cap: u128,
    /// UTC hours `[start, end)`. Wraps midnight when start > end.
    pub allowed_hours: Option<(u8, u8)>,
}

#[derive(Clone, Copy, Debug)]
pub struct Attempt {
    pub amount: u128,
    pub recipient_allowed: bool,
    pub signature_valid: bool,
    pub nonce_fresh: bool,
    pub memo_len: usize,
    pub now_ns: u64,
    pub spent_today: u128,
    /// Balance the vault can spend after storage and the owner's reserve.
    pub available: u128,
}

pub fn day_of(now_ns: u64) -> u64 {
    now_ns / NS_PER_DAY
}

pub fn hour_of(now_ns: u64) -> u8 {
    ((now_ns % NS_PER_DAY) / NS_PER_HOUR) as u8
}

pub fn hour_in_window(hour: u8, start: u8, end: u8) -> bool {
    if start < end {
        hour >= start && hour < end
    } else {
        hour >= start || hour < end
    }
}

/// First failing check wins, so a receipt always names one reason.
pub fn evaluate(limits: &Limits, a: &Attempt) -> Result<(), BlockReason> {
    if !a.signature_valid {
        return Err(BlockReason::BadSignature);
    }
    if !a.nonce_fresh {
        return Err(BlockReason::StaleNonce);
    }
    if a.memo_len > MAX_MEMO_BYTES {
        return Err(BlockReason::MemoTooLong);
    }
    if a.amount == 0 {
        return Err(BlockReason::ZeroAmount);
    }
    if !a.recipient_allowed {
        return Err(BlockReason::RecipientNotAllowed);
    }
    if a.amount > limits.per_tx_cap {
        return Err(BlockReason::OverTxCap);
    }
    if let Some((start, end)) = limits.allowed_hours {
        if !hour_in_window(hour_of(a.now_ns), start, end) {
            return Err(BlockReason::OutsideHours);
        }
    }
    match a.spent_today.checked_add(a.amount) {
        Some(total) if total <= limits.daily_cap => {}
        _ => return Err(BlockReason::OverDailyCap),
    }
    if a.amount > a.available {
        return Err(BlockReason::InsufficientFunds);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits { per_tx_cap: 100, daily_cap: 250, allowed_hours: None }
    }

    fn ok_attempt() -> Attempt {
        Attempt {
            amount: 50,
            recipient_allowed: true,
            signature_valid: true,
            nonce_fresh: true,
            memo_len: 10,
            now_ns: 0,
            spent_today: 0,
            available: 1_000,
        }
    }

    #[test]
    fn allows_a_payment_inside_every_rule() {
        assert_eq!(evaluate(&limits(), &ok_attempt()), Ok(()));
    }

    #[test]
    fn blocks_unlisted_recipient() {
        let a = Attempt { recipient_allowed: false, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &a), Err(BlockReason::RecipientNotAllowed));
    }

    #[test]
    fn per_tx_cap_is_inclusive() {
        let at = Attempt { amount: 100, ..ok_attempt() };
        let over = Attempt { amount: 101, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &at), Ok(()));
        assert_eq!(evaluate(&limits(), &over), Err(BlockReason::OverTxCap));
    }

    #[test]
    fn daily_cap_counts_what_was_already_spent() {
        let at = Attempt { amount: 50, spent_today: 200, ..ok_attempt() };
        let over = Attempt { amount: 51, spent_today: 200, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &at), Ok(()));
        assert_eq!(evaluate(&limits(), &over), Err(BlockReason::OverDailyCap));
    }

    #[test]
    fn huge_amount_cannot_overflow_past_the_daily_cap() {
        let l = Limits { per_tx_cap: u128::MAX, daily_cap: 250, allowed_hours: None };
        let a = Attempt { amount: u128::MAX, spent_today: 1, ..ok_attempt() };
        assert_eq!(evaluate(&l, &a), Err(BlockReason::OverDailyCap));
    }

    #[test]
    fn zero_amount_is_blocked() {
        let a = Attempt { amount: 0, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &a), Err(BlockReason::ZeroAmount));
    }

    #[test]
    fn bad_signature_wins_over_everything_else() {
        let a = Attempt { signature_valid: false, recipient_allowed: false, amount: 0, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &a), Err(BlockReason::BadSignature));
    }

    #[test]
    fn replayed_nonce_is_blocked() {
        let a = Attempt { nonce_fresh: false, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &a), Err(BlockReason::StaleNonce));
    }

    #[test]
    fn oversized_memo_is_blocked() {
        let a = Attempt { memo_len: MAX_MEMO_BYTES + 1, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &a), Err(BlockReason::MemoTooLong));
    }

    #[test]
    fn cannot_spend_the_reserve() {
        let a = Attempt { amount: 50, available: 49, ..ok_attempt() };
        assert_eq!(evaluate(&limits(), &a), Err(BlockReason::InsufficientFunds));
    }

    #[test]
    fn hours_window_plain_and_across_midnight() {
        assert!(hour_in_window(9, 9, 17));
        assert!(!hour_in_window(17, 9, 17));
        assert!(hour_in_window(23, 22, 6));
        assert!(hour_in_window(5, 22, 6));
        assert!(!hour_in_window(6, 22, 6));
    }

    #[test]
    fn outside_hours_is_blocked() {
        let l = Limits { allowed_hours: Some((9, 17)), ..limits() };
        let at_8 = Attempt { now_ns: 8 * NS_PER_HOUR, ..ok_attempt() };
        let at_9 = Attempt { now_ns: 9 * NS_PER_HOUR, ..ok_attempt() };
        assert_eq!(evaluate(&l, &at_8), Err(BlockReason::OutsideHours));
        assert_eq!(evaluate(&l, &at_9), Ok(()));
    }

    #[test]
    fn day_rolls_at_utc_midnight() {
        assert_eq!(day_of(NS_PER_DAY - 1), 0);
        assert_eq!(day_of(NS_PER_DAY), 1);
    }
}
