//! Constant-product quote math for `minimum_amount_out`.
//!
//! `minimum_amount_out` is the ONLY slippage protection a swap has. Set it too
//! high and every swap reverts; set it to zero and you accept any output at all,
//! which is precisely what a sandwich bot wants. So the formula here was derived
//! empirically from real mainnet swaps rather than taken on faith, and the
//! constants below are locked by golden tests using those real numbers.
//!
//! # Verified against mainnet (2026-07-20)
//!
//! **Raydium v4** — fee `25/10_000` (0.25%) applied to the input, against RAW
//! vault balances. Reproduced the on-chain output exactly on 3 of 3 sampled
//! swaps.
//!
//! **Raydium CPMM** — fee is per-pool, read from `amm_config.trade_fee_rate`
//! with denominator `1_000_000` (observed 2500 and 3000, i.e. 0.25% and 0.30%,
//! so it must NOT be hardcoded). Reserves are the vault balance MINUS the
//! protocol and fund fees accrued inside that vault. Reproduced the on-chain
//! output exactly on the sampled swaps.
//!
//! # The trap
//!
//! For CPMM, using raw vault balances instead of subtracting accrued fees
//! overestimated the output by **26%** on one sampled pool (432,905 vs an actual
//! 342,673). A `minimum_amount_out` computed that way is unreachable and every
//! swap against such a pool would revert.

// Verified quote math awaiting its consumer: the sniper cannot trade until
// submission lands, so these are unused outside tests today. Committed now so
// the empirical derivation is captured and regression-locked while the evidence
// is fresh — the golden tests below DO exercise every path.
#![allow(dead_code)]

use anyhow::{Result, bail};

/// A fee expressed as a rational applied to the input amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRate {
    pub numerator: u64,
    pub denominator: u64,
}

/// Raydium AMM v4: a flat 0.25% swap fee.
pub const V4_FEE: FeeRate = FeeRate { numerator: 25, denominator: 10_000 };

/// Raydium CPMM: fee varies per pool. Read `trade_fee_rate` from the pool's
/// `amm_config` — do not assume a value.
pub fn cpmm_fee(trade_fee_rate: u64) -> FeeRate {
    FeeRate { numerator: trade_fee_rate, denominator: 1_000_000 }
}

/// Tradable reserves, already adjusted for anything not swappable.
///
/// For CPMM these must be `vault_balance - protocol_fees - fund_fees` for the
/// respective side; see the module note on the 26% error.
#[derive(Debug, Clone, Copy)]
pub struct Reserves {
    pub input: u64,
    pub output: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    /// What the pool would return right now, by the constant-product formula.
    pub expected_out: u64,
    /// `expected_out` reduced by the slippage tolerance. This is what goes into
    /// the instruction.
    pub minimum_out: u64,
    /// How much of the input reserve this trade consumes, in basis points.
    /// A thin new pool can show enormous impact for a small buy — worth
    /// refusing on, which is why it is surfaced rather than hidden.
    pub price_impact_bps: u32,
}

/// Constant-product output: `out = r_out * in_after_fee / (r_in + in_after_fee)`.
///
/// All arithmetic is u128 and checked. The on-chain programs floor-divide, and
/// so does this.
pub fn amount_out(reserves: Reserves, amount_in: u64, fee: FeeRate) -> Result<u64> {
    if fee.denominator == 0 || fee.numerator >= fee.denominator {
        bail!("invalid fee {}/{}", fee.numerator, fee.denominator);
    }
    if reserves.input == 0 || reserves.output == 0 {
        bail!("cannot quote against an empty pool");
    }
    if amount_in == 0 {
        return Ok(0);
    }

    let amount_in = amount_in as u128;
    let r_in = reserves.input as u128;
    let r_out = reserves.output as u128;
    let num = fee.numerator as u128;
    let den = fee.denominator as u128;

    // Fee comes off the input first.
    let in_after_fee = amount_in
        .checked_mul(den - num)
        .and_then(|v| v.checked_div(den))
        .ok_or_else(|| anyhow::anyhow!("fee math overflow"))?;

    let out = r_out
        .checked_mul(in_after_fee)
        .and_then(|v| v.checked_div(r_in.checked_add(in_after_fee)?))
        .ok_or_else(|| anyhow::anyhow!("quote overflow"))?;

    // Cannot drain the pool: the formula guarantees out < r_out, but assert it
    // rather than trusting the algebra after a cast.
    if out >= r_out {
        bail!("quote exceeds output reserve");
    }
    u64::try_from(out).map_err(|_| anyhow::anyhow!("quote exceeds u64"))
}

/// Full quote including the slippage-protected minimum.
///
/// `slippage_bps` is the tolerance, e.g. 300 = 3%. A tolerance of 10_000 (100%)
/// is refused: that is equivalent to `minimum_out = 0`, i.e. no protection at
/// all, and must be a deliberate act rather than a config typo.
pub fn quote(
    reserves: Reserves,
    amount_in: u64,
    fee: FeeRate,
    slippage_bps: u16,
) -> Result<Quote> {
    if slippage_bps >= 10_000 {
        bail!(
            "slippage_bps {slippage_bps} >= 10000 would set minimum_out to 0 \
             (no slippage protection at all)"
        );
    }
    let expected_out = amount_out(reserves, amount_in, fee)?;

    let minimum_out = (expected_out as u128)
        .checked_mul((10_000 - slippage_bps) as u128)
        .map(|v| v / 10_000)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("slippage math overflow"))?;

    // Invariant: the guard can never exceed the estimate, or the swap is
    // guaranteed to revert.
    debug_assert!(minimum_out <= expected_out);

    let in_after_fee = (amount_in as u128) * ((fee.denominator - fee.numerator) as u128)
        / fee.denominator as u128;
    let price_impact_bps = if in_after_fee == 0 {
        0
    } else {
        ((in_after_fee * 10_000) / (reserves.input as u128 + in_after_fee)) as u32
    };

    Ok(Quote { expected_out, minimum_out, price_impact_bps })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GOLDEN: real mainnet swaps, output reproduced exactly ----

    /// Raydium v4, 3 real swaps. Fee 25/10000 against RAW vault balances.
    #[test]
    fn v4_matches_real_mainnet_swaps() {
        // (reserve_in, reserve_out, amount_in, actual_out)
        let cases = [
            // 5GUNGrbruukgudPWDiVpAG3LUSMPgVqPrJ9Jot6LjhPzEaiX5yTJSutrYAkuFDjkq5BpChjHKkDBy3QXeqpHPyJ6
            (695_372_932_701u64, 9_036_954_457_723u64, 49_741_300u64, 644_767_820u64),
            // 3n9qCLks9Lj3ZaaAEiAJmV7hTh6e9m1Km6aJYSSeJqLmkGTdBUa6VxV3xw1j8Xb9xsXJpWZ5RspYKSiMiDFFpka7
            (72_699_848_552_880, 239_132_047_569, 644_938, 2_116),
            // 4o6M4pb2L6XKLGumBjagwnErMZN3nmsbN4UtnvdEKWp2MJazwMoUG4YqwDaq3WHMbgB7sHi2fNeUNsNfHiKLaLxH
            (72_612_093_069_019, 239_420_328_553, 87_755_483_861, 288_280_984),
        ];
        for (r_in, r_out, amt, actual) in cases {
            let got = amount_out(Reserves { input: r_in, output: r_out }, amt, V4_FEE).unwrap();
            assert_eq!(got, actual, "v4 quote must match on-chain exactly");
        }
    }

    /// Raydium CPMM, 2 real swaps. Fee from amm_config (2500 / 1e6), reserves
    /// are vault MINUS accrued protocol+fund fees.
    #[test]
    fn cpmm_matches_real_mainnet_swaps() {
        // 3ij6zLcrthihq9oTjRSEJCfv86bkWh21DEPYTq1vgPXfDYnzNCVEfRuTbowNyFhpvKnfAoKQ3jSV1ChLTh4EPdba
        // vault_in 37163075 - fees 2222058 ; vault_out 611776493 - fees 156450051
        let q = amount_out(
            Reserves { input: 37_163_075 - 2_222_058, output: 611_776_493 - 156_450_051 },
            26_382,
            cpmm_fee(2500),
        )
        .unwrap();
        assert_eq!(q, 342_673);

        // 5khp5eBM2nLxwWvjdQodg4Lyfm4EfnVGLmJqU3xSgQpbdQADgooJCw9g1A8NkfHjBkbzYZLyQ5AXXktapibqsSWh
        let q = amount_out(
            Reserves {
                input: 364_814_101_131 - 67_568_115,
                output: 74_180_725_160_857 - 14_118_029_625,
            },
            5_000_000,
            cpmm_fee(2500),
        )
        .unwrap();
        assert_eq!(q, 1_014_131_353);
    }

    /// THE TRAP: using raw vault balances for CPMM overestimates badly. This
    /// test pins the wrong answer so nobody "simplifies" the fee subtraction
    /// away without a failing test.
    #[test]
    fn cpmm_raw_vault_balances_overestimate_badly() {
        let correct = amount_out(
            Reserves { input: 37_163_075 - 2_222_058, output: 611_776_493 - 156_450_051 },
            26_382,
            cpmm_fee(2500),
        )
        .unwrap();
        let naive = amount_out(
            Reserves { input: 37_163_075, output: 611_776_493 },
            26_382,
            cpmm_fee(2500),
        )
        .unwrap();
        assert_eq!(correct, 342_673);
        assert_eq!(naive, 432_905);
        // ~26% too high — every swap built on it would revert.
        assert!(naive > correct * 5 / 4);
    }

    /// CPMM fee is per-pool; 3000 was also observed live.
    #[test]
    fn cpmm_fee_rate_is_not_hardcoded() {
        assert_ne!(cpmm_fee(2500), cpmm_fee(3000));
        let r = Reserves { input: 1_000_000, output: 1_000_000 };
        assert!(amount_out(r, 10_000, cpmm_fee(3000)).unwrap()
              < amount_out(r, 10_000, cpmm_fee(2500)).unwrap());
    }

    // ---- slippage + safety properties ----

    #[test]
    fn minimum_never_exceeds_expected() {
        let r = Reserves { input: 1_000_000_000, output: 5_000_000_000 };
        for bps in [0u16, 1, 50, 300, 2_500, 9_999] {
            let q = quote(r, 1_000_000, V4_FEE, bps).unwrap();
            assert!(q.minimum_out <= q.expected_out, "bps={bps}");
        }
    }

    #[test]
    fn slippage_reduces_the_minimum_monotonically() {
        let r = Reserves { input: 1_000_000_000, output: 5_000_000_000 };
        let a = quote(r, 1_000_000, V4_FEE, 100).unwrap();
        let b = quote(r, 1_000_000, V4_FEE, 500).unwrap();
        assert_eq!(a.expected_out, b.expected_out);
        assert!(b.minimum_out < a.minimum_out);
        // 3% tolerance on 1000 expected -> 970.
        let q = quote(Reserves { input: 1_000_000, output: 1_000_000 }, 1_000, V4_FEE, 300).unwrap();
        assert_eq!(q.minimum_out, q.expected_out * 9_700 / 10_000);
    }

    /// 100% slippage means "accept anything" — refuse it as a config typo.
    #[test]
    fn full_slippage_is_refused() {
        let r = Reserves { input: 1_000_000, output: 1_000_000 };
        assert!(quote(r, 1_000, V4_FEE, 10_000).is_err());
        assert!(quote(r, 1_000, V4_FEE, 20_000).is_err());
        assert!(quote(r, 1_000, V4_FEE, 9_999).is_ok());
    }

    #[test]
    fn empty_pool_cannot_be_quoted() {
        assert!(amount_out(Reserves { input: 0, output: 1_000 }, 1, V4_FEE).is_err());
        assert!(amount_out(Reserves { input: 1_000, output: 0 }, 1, V4_FEE).is_err());
    }

    #[test]
    fn zero_input_yields_zero() {
        let r = Reserves { input: 1_000, output: 1_000 };
        assert_eq!(amount_out(r, 0, V4_FEE).unwrap(), 0);
    }

    #[test]
    fn invalid_fee_is_rejected() {
        let r = Reserves { input: 1_000, output: 1_000 };
        assert!(amount_out(r, 1, FeeRate { numerator: 1, denominator: 0 }).is_err());
        assert!(amount_out(r, 1, FeeRate { numerator: 10, denominator: 10 }).is_err());
    }

    /// Output can never meet or exceed the output reserve, however large the
    /// input — the pool cannot be drained.
    #[test]
    fn output_is_bounded_by_the_reserve() {
        let r = Reserves { input: 1_000, output: 1_000_000 };
        let out = amount_out(r, u64::MAX / 2, V4_FEE).unwrap();
        assert!(out < r.output, "got {out}");
    }

    /// Extreme values must not panic or wrap.
    #[test]
    fn extreme_values_do_not_overflow() {
        let r = Reserves { input: u64::MAX, output: u64::MAX };
        assert!(amount_out(r, u64::MAX, V4_FEE).is_ok());
        let r = Reserves { input: 1, output: u64::MAX };
        assert!(amount_out(r, u64::MAX, V4_FEE).is_ok());
    }

    /// A thin pool must report large price impact — the signal a sniper needs
    /// to refuse buying into a pool it would itself move 40%.
    #[test]
    fn thin_pools_report_large_price_impact() {
        // Buying 1 SOL into a pool holding 2 SOL.
        let thin = quote(
            Reserves { input: 2_000_000_000, output: 1_000_000_000_000 },
            1_000_000_000,
            V4_FEE,
            300,
        )
        .unwrap();
        assert!(thin.price_impact_bps > 3_000, "got {}", thin.price_impact_bps);

        // Same trade into a 1000 SOL pool is negligible.
        let deep = quote(
            Reserves { input: 1_000_000_000_000, output: 1_000_000_000_000 },
            1_000_000_000,
            V4_FEE,
            300,
        )
        .unwrap();
        assert!(deep.price_impact_bps < 110, "got {}", deep.price_impact_bps);
    }
}
