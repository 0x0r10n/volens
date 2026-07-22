//! Verified SWAP instruction layouts (step 1 of the execution path).
//!
//! This module is **reference data only** — it builds no transactions; `tx.rs`
//! consumes it. It exists so the layouts are verified, documented, and
//! regression-locked independently of any code that signs.
//!
//! Every index below was confirmed against real mainnet swaps on 2026-07-20 by
//! resolving each account's on-chain owner, type, and mint. Method identical to
//! the creation layouts in `model::Dex::layout`.
//!
//! # Three traps found during verification
//!
//! 1. **Raydium v4's layout is variable-length.** `swapBaseIn` occurs with both
//!    17 and 18 accounts in live traffic (sampled: 5×17, 1×18). The 18-account
//!    form inserts `amm_target_orders` at index 4, shifting the vaults from
//!    (4, 5) to (5, 6). Nothing in the instruction *data* distinguishes them —
//!    you must branch on `accounts.len()`.
//!
//! 2. **Raydium v4 market accounts may be placeholders.** In a pool with no
//!    OpenBook market, indices 1/3/4/7 were all the *same* account (the pool
//!    itself). So "does index 3 look like an OpenBook account?" is not a safe
//!    way to detect the variant either.
//!
//! 3. **Raydium CPMM positions are INPUT/OUTPUT, not base/quote.** The same
//!    index holds WSOL or the token depending on trade direction. To buy a token
//!    with SOL, the *input* vault is whichever vault holds WSOL — which, given
//!    the orientation flip documented in `Dex::layout`, is CPMM's **base**
//!    vault. Mapping a stored `base_vault` to the input position by convention
//!    would spend the wrong side.

// Reference data. The discriminators and CPMM/v4 indices are now consumed by
// `tx.rs`; the PumpSwap constants are not, because that encoder is still
// blocked (see `tx::pumpswap_pda`). Kept together so the layout knowledge lives
// in one place, and exercised by the tests below.
#![allow(dead_code)]

use crate::model::Dex;

// ---------------------------------------------------------------------------
// Discriminators
// ---------------------------------------------------------------------------

/// Raydium AMM v4 Borsh instruction tags.
pub const RAYDIUM_V4_SWAP_BASE_IN_TAG: u8 = 9;
pub const RAYDIUM_V4_SWAP_BASE_OUT_TAG: u8 = 11;

/// Anchor discriminators, `sha256("global:<method>")[..8]`.
///
/// NOTE: `buy` and `sell` are easy to transpose. `sell` is the one commonly
/// seen first in live traffic. Both are asserted by test.
pub const PUMPSWAP_BUY_DISC: [u8; 8] = [102, 6, 61, 18, 1, 218, 235, 234];
pub const PUMPSWAP_SELL_DISC: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];
pub const CPMM_SWAP_BASE_INPUT_DISC: [u8; 8] = [143, 190, 90, 218, 196, 30, 51, 222];
pub const CPMM_SWAP_BASE_OUTPUT_DISC: [u8; 8] = [55, 217, 98, 86, 163, 74, 180, 173];

// ---------------------------------------------------------------------------
// Raydium v4
// ---------------------------------------------------------------------------

/// Which account-list shape a v4 swap uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V4SwapShape {
    /// 17 accounts — `amm_target_orders` omitted.
    /// 0 token_program, 1 amm, 2 amm_authority, 3 amm_open_orders,
    /// 4 pool_coin_vault, 5 pool_pc_vault, 6 market_program, 7 market,
    /// 8 bids, 9 asks, 10 event_queue, 11 market_coin_vault,
    /// 12 market_pc_vault, 13 market_vault_signer, 14 user_source,
    /// 15 user_destination, 16 user_owner
    NoTargetOrders,
    /// 18 accounts — `amm_target_orders` present at index 4, shifting the rest.
    /// 0 token_program, 1 amm, 2 amm_authority, 3 amm_open_orders,
    /// 4 amm_target_orders, 5 pool_coin_vault, 6 pool_pc_vault, ...
    /// 15 user_source, 16 user_destination, 17 user_owner
    WithTargetOrders,
}

impl V4SwapShape {
    /// Infer the shape from the account count. Returns `None` for anything
    /// unexpected rather than guessing — a wrong guess reads the wrong vault.
    pub fn from_account_count(n: usize) -> Option<Self> {
        match n {
            17 => Some(V4SwapShape::NoTargetOrders),
            18 => Some(V4SwapShape::WithTargetOrders),
            _ => None,
        }
    }

    /// `(coin_vault, pc_vault)` instruction-local indices.
    pub fn vault_indices(self) -> (usize, usize) {
        match self {
            V4SwapShape::NoTargetOrders => (4, 5),
            V4SwapShape::WithTargetOrders => (5, 6),
        }
    }

    /// `(user_source, user_destination, user_owner)` indices.
    pub fn user_indices(self) -> (usize, usize, usize) {
        match self {
            V4SwapShape::NoTargetOrders => (14, 15, 16),
            V4SwapShape::WithTargetOrders => (15, 16, 17),
        }
    }

    pub fn account_count(self) -> usize {
        match self {
            V4SwapShape::NoTargetOrders => 17,
            V4SwapShape::WithTargetOrders => 18,
        }
    }
}

// ---------------------------------------------------------------------------
// Raydium CPMM — fixed 13 accounts, positions are directional
// ---------------------------------------------------------------------------

/// CPMM swap account indices. Verified on two real swaps in *opposite*
/// directions, which is what proved the positions are input/output rather than
/// base/quote.
pub mod cpmm_swap {
    pub const PAYER: usize = 0;
    pub const AUTHORITY: usize = 1;
    pub const AMM_CONFIG: usize = 2;
    pub const POOL_STATE: usize = 3;
    /// User's token account for the asset being SPENT.
    pub const USER_INPUT: usize = 4;
    /// User's token account for the asset being RECEIVED.
    pub const USER_OUTPUT: usize = 5;
    /// Pool vault holding the INPUT mint (not "base").
    pub const INPUT_VAULT: usize = 6;
    /// Pool vault holding the OUTPUT mint (not "quote").
    pub const OUTPUT_VAULT: usize = 7;
    pub const INPUT_TOKEN_PROGRAM: usize = 8;
    pub const OUTPUT_TOKEN_PROGRAM: usize = 9;
    pub const INPUT_MINT: usize = 10;
    pub const OUTPUT_MINT: usize = 11;
    pub const OBSERVATION_STATE: usize = 12;
    pub const ACCOUNT_COUNT: usize = 13;
}

// ---------------------------------------------------------------------------
// PumpSwap — buy/sell share a stable head, diverge in the tail
// ---------------------------------------------------------------------------

/// PumpSwap swap account indices. Indices 0..=8 are identical for `buy` and
/// `sell`; only the tail differs (see `BUY_ACCOUNT_COUNT`).
pub mod pumpswap_swap {
    pub const POOL: usize = 0;
    pub const USER: usize = 1;
    pub const GLOBAL_CONFIG: usize = 2;
    pub const BASE_MINT: usize = 3;
    pub const QUOTE_MINT: usize = 4;
    pub const USER_BASE_ATA: usize = 5;
    pub const USER_QUOTE_ATA: usize = 6;
    /// Pool vault holding `BASE_MINT`; owned by the pool account itself.
    pub const POOL_BASE_VAULT: usize = 7;
    /// Pool vault holding `QUOTE_MINT`; owned by the pool account itself.
    pub const POOL_QUOTE_VAULT: usize = 8;
    pub const PROTOCOL_FEE_RECIPIENT: usize = 9;
    pub const PROTOCOL_FEE_RECIPIENT_ATA: usize = 10;

    /// Observed live. Buy carries two extra accounts (global + user volume
    /// accumulators) that sell does not, so the tail indices differ.
    pub const BUY_ACCOUNT_COUNT: usize = 25;
    pub const SELL_ACCOUNT_COUNT: usize = 23;
}

/// Does this instruction data look like a swap on the given venue?
/// Useful for filtering; not used to build anything.
pub fn is_swap(dex: Dex, data: &[u8]) -> bool {
    match dex {
        Dex::RaydiumV4 => matches!(
            data.first(),
            Some(&RAYDIUM_V4_SWAP_BASE_IN_TAG) | Some(&RAYDIUM_V4_SWAP_BASE_OUT_TAG)
        ),
        Dex::RaydiumCpmm => {
            data.len() >= 8
                && (data[..8] == CPMM_SWAP_BASE_INPUT_DISC
                    || data[..8] == CPMM_SWAP_BASE_OUTPUT_DISC)
        }
        Dex::PumpSwap => {
            data.len() >= 8 && (data[..8] == PUMPSWAP_BUY_DISC || data[..8] == PUMPSWAP_SELL_DISC)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn anchor_disc(name: &str) -> [u8; 8] {
        let mut h = Sha256::new();
        h.update(format!("global:{name}").as_bytes());
        let mut d = [0u8; 8];
        d.copy_from_slice(&h.finalize()[..8]);
        d
    }

    #[test]
    fn swap_discriminators_recompute_correctly() {
        assert_eq!(anchor_disc("buy"), PUMPSWAP_BUY_DISC);
        assert_eq!(anchor_disc("sell"), PUMPSWAP_SELL_DISC);
        assert_eq!(anchor_disc("swap_base_input"), CPMM_SWAP_BASE_INPUT_DISC);
        assert_eq!(anchor_disc("swap_base_output"), CPMM_SWAP_BASE_OUTPUT_DISC);
    }

    /// buy and sell must never be confused — they move funds in opposite
    /// directions, so a transposition would sell instead of buy.
    #[test]
    fn buy_and_sell_are_distinct() {
        assert_ne!(PUMPSWAP_BUY_DISC, PUMPSWAP_SELL_DISC);
    }

    /// The v4 vault shift is the single most dangerous fact in this module:
    /// reading (4,5) on an 18-account instruction yields the open-orders and
    /// target-orders accounts instead of the vaults.
    #[test]
    fn v4_vault_indices_shift_with_target_orders() {
        assert_eq!(V4SwapShape::NoTargetOrders.vault_indices(), (4, 5));
        assert_eq!(V4SwapShape::WithTargetOrders.vault_indices(), (5, 6));
        assert_ne!(
            V4SwapShape::NoTargetOrders.vault_indices(),
            V4SwapShape::WithTargetOrders.vault_indices()
        );
    }

    #[test]
    fn v4_shape_inferred_from_account_count() {
        assert_eq!(V4SwapShape::from_account_count(17), Some(V4SwapShape::NoTargetOrders));
        assert_eq!(V4SwapShape::from_account_count(18), Some(V4SwapShape::WithTargetOrders));
        // Anything else must refuse rather than guess.
        for n in [0, 12, 16, 19, 25] {
            assert_eq!(V4SwapShape::from_account_count(n), None, "n={n}");
        }
    }

    #[test]
    fn v4_shape_roundtrips_its_account_count() {
        for shape in [V4SwapShape::NoTargetOrders, V4SwapShape::WithTargetOrders] {
            assert_eq!(V4SwapShape::from_account_count(shape.account_count()), Some(shape));
        }
    }

    #[test]
    fn v4_user_indices_are_the_last_three() {
        for shape in [V4SwapShape::NoTargetOrders, V4SwapShape::WithTargetOrders] {
            let (src, dst, owner) = shape.user_indices();
            assert_eq!(owner, shape.account_count() - 1);
            assert_eq!(dst, owner - 1);
            assert_eq!(src, owner - 2);
        }
    }

    #[test]
    fn is_swap_matches_real_discriminators() {
        assert!(is_swap(Dex::RaydiumV4, &[9, 0, 0]));
        assert!(is_swap(Dex::RaydiumV4, &[11, 0, 0]));
        // initialize2 is a creation, not a swap.
        assert!(!is_swap(Dex::RaydiumV4, &[1, 0, 0]));

        assert!(is_swap(Dex::RaydiumCpmm, &CPMM_SWAP_BASE_INPUT_DISC));
        assert!(is_swap(Dex::RaydiumCpmm, &CPMM_SWAP_BASE_OUTPUT_DISC));
        assert!(!is_swap(Dex::RaydiumCpmm, &crate::model::RAYDIUM_CPMM_INITIALIZE_DISC));

        assert!(is_swap(Dex::PumpSwap, &PUMPSWAP_BUY_DISC));
        assert!(is_swap(Dex::PumpSwap, &PUMPSWAP_SELL_DISC));
        assert!(!is_swap(Dex::PumpSwap, &crate::model::PUMPSWAP_CREATE_POOL_DISC));
    }

    /// Guards the finding that CPMM positions are directional. If someone later
    /// renames these to BASE/QUOTE, this comment-as-test should stop them.
    #[test]
    fn cpmm_input_output_are_adjacent_and_ordered() {
        assert_eq!(cpmm_swap::INPUT_VAULT + 1, cpmm_swap::OUTPUT_VAULT);
        assert_eq!(cpmm_swap::INPUT_MINT + 1, cpmm_swap::OUTPUT_MINT);
        assert_eq!(cpmm_swap::USER_INPUT + 1, cpmm_swap::USER_OUTPUT);
        assert!(cpmm_swap::OBSERVATION_STATE < cpmm_swap::ACCOUNT_COUNT);
    }

    #[test]
    fn pumpswap_head_is_shared_between_buy_and_sell() {
        // The accounts we need for a swap all live in the shared head.
        assert!(pumpswap_swap::POOL_QUOTE_VAULT < pumpswap_swap::SELL_ACCOUNT_COUNT);
        assert!(pumpswap_swap::POOL_QUOTE_VAULT < pumpswap_swap::BUY_ACCOUNT_COUNT);
        assert!(pumpswap_swap::BUY_ACCOUNT_COUNT > pumpswap_swap::SELL_ACCOUNT_COUNT);
    }
}
