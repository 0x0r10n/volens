//! Prices derived from the transaction stream we already receive.
//!
//! # Why not a price API
//!
//! Every swap on a watched venue moves a token one way and SOL the other, so
//! the price is already in the data:
//!
//! ```text
//!     price_sol = SOL moved / tokens moved
//! ```
//!
//! That is a REAL EXECUTED FILL, not a router's quote. Measured on the live
//! stream: 56% of transactions yield an observation, 314 distinct tokens in 30
//! seconds. It costs no API call, has no key, and cannot be rate limited or
//! IP-blocked — which is what took the previous price source out.
//!
//! It also produces VOLUME, which no quote API gives us.
//!
//! # Raw observations are NOT trustworthy
//!
//! Measured on the same stream, WSOL/USDC observations ranged from $0.00 to
//! $76.83 against a true price of ~$76.50, including a 68,579 SOL "swap"
//! priced at zero. Multi-hop routes, pool rebalances and owners holding
//! several accounts all produce pairs that are not a trade.
//!
//! So a single observation is never a price. Every reader goes through a
//! MEDIAN of recent observations, which is robust to those artifacts in a way
//! that a mean or a last-tick is not.
//!
//! # SOL/USD is gated harder than token prices
//!
//! SOL moves a few percent a day; a memecoin moves 10x in a minute. A jump
//! filter that protects the first would destroy the second. So SOL/USD gets
//! the full ladder (plausibility band, staleness, jump protection with
//! re-anchor and capitulation) while token prices get only positivity and
//! staleness — for them, the jump IS the signal.
//!
//! # A missing price is an outage
//!
//! Nothing here ever substitutes a default. Readers return `Option`, and an
//! unknown price must propagate as unknown rather than become a plausible
//! wrong number that no one notices.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use yellowstone_grpc_proto::prelude::{SubscribeUpdateTransactionInfo, TransactionStatusMeta};

/// Programs watched PURELY for price observations.
///
/// Detection only needs venues where pools are created; pricing needs every
/// venue a token might actually trade on, and those are not the same set. A
/// token still on the pump.fun bonding curve — most fresh launches, and
/// exactly what smart money buys early — trades on a program that creates no
/// pool, so it was invisible to the price feed while trading hundreds of
/// thousands of dollars a day.
///
/// Measured over 30s on venues that were NOT watched:
/// ```text
///   pump.fun curve   1160 tx      meteora damm v2   661 tx
///   raydium clmm      147 tx      orca whirlpool    164 tx
///   -> 70 tokens priced that could not be priced before
/// ```
pub const PRICE_ONLY_PROGRAMS: &[(&str, &str)] = &[
    // The bonding curve tokens live on BEFORE graduating to PumpSwap.
    ("pump.fun curve", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"),
    // Where Meteora DBC tokens graduate to — i.e. the ones that succeeded.
    ("meteora damm v2", "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG"),
    ("raydium clmm", "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"),
    ("orca whirlpool", "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"),
];

pub const WSOL: &str = "So11111111111111111111111111111111111111112";
pub const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Observations kept per token. Enough for a stable median, small enough that
/// tens of thousands of tokens stay cheap.
const KEEP_PER_TOKEN: usize = 9;
/// Observations an EXIT decision looks at — see `exit_price_sol`. Three is the
/// smallest window that still needs corroboration: one bad print cannot carry
/// the median, but the window turns within a few trades instead of nine.
const EXIT_OBS: usize = 3;
/// Observations kept for SOL/USD. Larger because it is one series and the
/// artifacts are frequent.
const KEEP_SOL: usize = 25;
/// Ignore dust: a 0.001 SOL swap prices nothing and is mostly noise.
const MIN_OBS_SOL: f64 = 0.02;
/// Most weight any single observation may carry, in SOL.
///
/// Weighting exists to stop dust voting equally with real size — it was never
/// meant to let one trade dictate a price outright. Without a cap the SOL leg
/// is both the thing we divide by AND the thing that decides whose division
/// wins, so a single 40 SOL fill with a misread token leg outvotes nine honest
/// ones instead of being outvoted by them.
///
/// Set near an ordinary fill, not above it. At 5 SOL a single observation still
/// outweighed nine half-SOL trades combined, which is the same failure with a
/// higher threshold. Past ~1 SOL a trade is real; more size does not make it
/// better evidence about the price.
const MAX_OBS_WEIGHT_SOL: f64 = 1.0;
/// Least share of a mint's movement in one transaction that an owner must
/// account for before their side is read as the trade.
///
/// Verified against chain. In one refused observation the buyer paid in NATIVE
/// SOL — invisible in token balances — so the only WSOL movement present was a
/// fee vault receiving 0.065 SOL, and that vault also happened to hold 608
/// tokens. Dividing one by the other priced the token 527x over its market.
/// Those 608 tokens were 0.0009% of the 70,386,983 that moved.
///
/// In a real swap the trader and the pool are the two largest movers and are
/// equal but for fees, so both clear this easily; fee vaults, dust recipients
/// and routing residues do not clear it at all.
const MIN_TOKEN_SHARE: f64 = 0.5;
/// Observations required before a token has a price at all.
///
/// One fill is an anecdote: nothing has corroborated it and the jump guard has
/// no baseline to judge it against, so a single artifact becomes the price. A
/// token nobody has traded twice is better reported as unpriced than as a
/// number we cannot check.
const MIN_OBS_FOR_PRICE: usize = 2;
/// SOL/USD outside this band is an artifact, not a market move.
const SOL_USD_MIN: f64 = 1.0;
const SOL_USD_MAX: f64 = 10_000.0;
/// Largest price change one fill may make, as a ratio to the current median.
///
/// Deliberately loose. A new token really can run 50x in a minute, and refusing
/// that would make us useless exactly when a call is working — but it runs
/// through a sequence of fills, each a small step. A single fill that jumps 50x
/// has not repriced the token, it has mis-measured it.
const MAX_TOKEN_JUMP: f64 = 50.0;
/// Consecutive rejects before the series is treated as the stale party.
const TOKEN_JUMP_CAPITULATE: u32 = 3;

#[derive(Debug, Clone, Copy)]
struct Obs {
    at: Instant,
    /// SOL per token, or USD per SOL for the SOL series.
    price: f64,
    /// Size in SOL, used to reject dust.
    size_sol: f64,
}

#[derive(Debug, Default)]
struct TokenSeries {
    recent: VecDeque<Obs>,
    /// Cumulative SOL traded since this token was first seen.
    volume_sol: f64,
    trades: u64,
    /// Observations refused in a row for jumping. Bounds the refusal so a
    /// series that has genuinely fallen behind cannot reject the market forever.
    jump_rejects: u32,
}

/// A price with the age of the newest observation behind it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Priced {
    pub price_sol: f64,
    pub age: Duration,
    pub observations: usize,
}

pub struct PriceIndex {
    tokens: Mutex<HashMap<String, TokenSeries>>,
    sol: Mutex<SolSeries>,
}

#[derive(Debug, Default)]
struct SolSeries {
    recent: VecDeque<Obs>,
    /// Last ACCEPTED price, and when. The anchor for jump protection.
    anchor: Option<(f64, Instant)>,
    consecutive_jump_rejects: u32,
}

impl Default for PriceIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl PriceIndex {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            sol: Mutex::new(SolSeries::default()),
        }
    }

    fn tokens(&self) -> std::sync::MutexGuard<'_, HashMap<String, TokenSeries>> {
        self.tokens.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Extract every price observation in one transaction.
    ///
    /// Called for EVERY streamed transaction, so it does no allocation beyond
    /// the two balance maps and never touches the network.
    pub fn observe(&self, tx: &SubscribeUpdateTransactionInfo, meta: &TransactionStatusMeta) {
        // (owner, mint) -> delta
        let mut before: HashMap<(&str, &str), f64> = HashMap::new();
        for b in &meta.pre_token_balances {
            if let Some(a) = b.ui_token_amount.as_ref() {
                before.insert((b.owner.as_str(), b.mint.as_str()), a.ui_amount);
            }
        }

        // Per owner: how much SOL moved, how much USDC moved, and every other
        // mint that moved. Pairing per OWNER is what makes this a trade rather
        // than two unrelated balance changes.
        let mut sol_delta: HashMap<&str, f64> = HashMap::new();
        let mut usdc_delta: HashMap<&str, f64> = HashMap::new();
        let mut token_deltas: Vec<(&str, &str, f64)> = Vec::new();

        for b in &meta.post_token_balances {
            let Some(a) = b.ui_token_amount.as_ref() else { continue };
            let prev = before
                .get(&(b.owner.as_str(), b.mint.as_str()))
                .copied()
                .unwrap_or(0.0);
            let delta = a.ui_amount - prev;
            if delta == 0.0 {
                continue;
            }
            match b.mint.as_str() {
                WSOL => *sol_delta.entry(b.owner.as_str()).or_default() += delta,
                USDC => *usdc_delta.entry(b.owner.as_str()).or_default() += delta,
                other => token_deltas.push((b.owner.as_str(), other, delta)),
            }
        }

        let now = Instant::now();

        // --- SOL/USD, from an owner who moved WSOL and USDC in opposite
        // directions. Same-direction means it was not a swap between them.
        for (owner, dsol) in &sol_delta {
            let Some(dusdc) = usdc_delta.get(owner) else { continue };
            if dsol.abs() < MIN_OBS_SOL || dusdc.abs() < 1.0 {
                continue;
            }
            if (*dsol > 0.0) == (*dusdc > 0.0) {
                continue;
            }
            self.observe_sol_usd(dusdc.abs() / dsol.abs(), dsol.abs(), now);
        }

        // How many distinct tokens each owner moved. An owner who moved several
        // cannot have their single SOL leg attributed to any one of them.
        let mut tokens_moved: HashMap<&str, usize> = HashMap::new();
        for (owner, _, _) in &token_deltas {
            *tokens_moved.entry(owner).or_default() += 1;
        }

        // The largest movement of each mint anywhere in the transaction. The
        // trade is between the two biggest movers; everyone else is a fee, a
        // residue or an onlooker, and pricing off them is how a 0.065 SOL fee
        // receipt became a 527x.
        let mut largest_move: HashMap<&str, f64> = HashMap::new();
        for (_, mint, dtok) in &token_deltas {
            let e = largest_move.entry(mint).or_insert(0.0);
            *e = e.max(dtok.abs());
        }

        // --- Token prices, from an owner who moved ONE token against SOL.
        for (owner, mint, dtok) in token_deltas {
            let Some(dsol) = sol_delta.get(owner) else { continue };
            // The SOL leg is the size of the whole transaction. A multi-hop
            // route (SOL -> MID -> OUT) leaves an unswept dust remainder in the
            // intermediate, and dividing the full SOL leg by that residue
            // prices it at millions of SOL each. Worse, the observation is
            // weighted BY that SOL leg, so it does not just join the median, it
            // outvotes every honest fill in the series. That is how a token
            // reported x69364 at a $353M market cap.
            if tokens_moved.get(owner).copied() != Some(1) {
                continue;
            }
            if dsol.abs() < MIN_OBS_SOL || dtok.abs() <= 0.0 {
                continue;
            }
            // Only the principals to the trade. A fee vault that receives SOL
            // and happens to hold a few of the tokens is not a counterparty,
            // and its ratio is not a price.
            let largest = largest_move.get(mint).copied().unwrap_or(0.0);
            if largest > 0.0 && dtok.abs() < largest * MIN_TOKEN_SHARE {
                continue;
            }
            if (*dsol > 0.0) == (dtok > 0.0) {
                continue;
            }
            let price = dsol.abs() / dtok.abs();
            if !price.is_finite() || price <= 0.0 {
                continue;
            }
            self.observe_token_from(mint, price, dsol.abs(), now, &tx.signature);
        }
    }

    /// `observe_token` plus the signature of the transaction it came from, so a
    /// refused observation can be looked up on an explorer.
    ///
    /// Refusals are the interesting ones. When a token prices absurdly we need
    /// the actual transaction to see which leg was misread — reasoning about it
    /// from the aggregate has cost a day already.
    fn observe_token_from(
        &self,
        mint: &str,
        price: f64,
        size_sol: f64,
        now: Instant,
        sig: &[u8],
    ) {
        if let Some(current) = self.price_sol(mint, Duration::from_secs(600)) {
            let ratio = price / current.price_sol;
            if !(1.0 / MAX_TOKEN_JUMP..=MAX_TOKEN_JUMP).contains(&ratio) {
                // warn, not debug: this is the only breadcrumb back to the
                // transaction behind a bad price, and at debug it is invisible
                // under the default filter — a diagnostic nobody can read is
                // not a diagnostic.
                tracing::warn!(
                    mint,
                    signature = %bs58::encode(sig).into_string(),
                    candidate = price,
                    current = current.price_sol,
                    ratio,
                    size_sol,
                    "price observation refused as a jump"
                );
            }
        }
        self.observe_token(mint, price, size_sol, now);
    }

    /// Record one token observation, refusing moves no single fill can make.
    ///
    /// Attribution above is the fix for the failure we actually saw; this is the
    /// backstop for the ones we have not. A fill executes against a curve, so it
    /// moves the price continuously — a 50x step between consecutive fills is an
    /// accounting artifact, not a trade. Rejection is bounded the same way the
    /// SOL/USD ladder is: if observations keep disagreeing with the series, the
    /// series is what is stale, so it capitulates rather than wedging forever.
    fn observe_token(&self, mint: &str, price: f64, size_sol: f64, now: Instant) {
        let mut map = self.tokens();
        let series = map.entry(mint.to_string()).or_default();
        // Volume counts the trade even if its price is refused below: the swap
        // happened, and only our reading of the price is in question.
        series.volume_sol += size_sol;
        series.trades += 1;

        if let Some(current) = weighted_median(&series.recent) {
            let ratio = price / current;
            if !(1.0 / MAX_TOKEN_JUMP..=MAX_TOKEN_JUMP).contains(&ratio) {
                series.jump_rejects += 1;
                if series.jump_rejects < TOKEN_JUMP_CAPITULATE {
                    return;
                }
                // Repeatedly told the same thing: believe the market, not the
                // history, and start the series over from this observation.
                series.recent.clear();
            }
        }
        series.jump_rejects = 0;

        series.recent.push_back(Obs { at: now, price, size_sol });
        if series.recent.len() > KEEP_PER_TOKEN {
            series.recent.pop_front();
        }
    }

    /// Apply the SOL/USD gate ladder to one candidate observation.
    ///
    /// Order is load-bearing. A candidate must clear plausibility BEFORE jump
    /// protection, or a run of artifacts could bully the anchor.
    fn observe_sol_usd(&self, price: f64, size_sol: f64, now: Instant) {
        // 1. Positive and plausible. $0.00 and $10^6 are artifacts, not moves.
        if !price.is_finite() || !(SOL_USD_MIN..=SOL_USD_MAX).contains(&price) {
            return;
        }

        let mut sol = self.sol.lock().unwrap_or_else(|p| p.into_inner());

        // 2. Jump protection, with the two escape hatches that stop it wedging.
        if let Some((anchor, at)) = sol.anchor {
            // Re-anchor: an old anchor is no longer evidence about anything.
            // Without this, any outage longer than a real move makes every
            // fresh price look like a jump — and nothing is ever accepted
            // again, so the anchor never refreshes. Permanent deadlock.
            let anchor_stale = at.elapsed() > Duration::from_secs(120);
            let ratio = price / anchor;
            let jumped = !(0.85..=1.18).contains(&ratio);

            if anchor_stale && jumped {
                // The anchor aged out AND the price moved far. That is a new
                // regime, not a tick: observations from before the gap would
                // drag the median toward a price that no longer exists.
                sol.recent.clear();
            }
            if jumped && !anchor_stale {
                sol.consecutive_jump_rejects += 1;
                // Capitulate: if we keep rejecting, the market gapped and WE
                // are the ones who are wrong.
                let capitulate = sol.consecutive_jump_rejects >= 5;
                // ...but never across a hard band. Persistence is not
                // evidence: a stuck upstream repeats itself exactly as
                // readily as a real gap does. The escape hatch needs its own.
                let within_hard_band = (0.5..=2.0).contains(&ratio);
                if !(capitulate && within_hard_band) {
                    return;
                }
            }
        }

        sol.consecutive_jump_rejects = 0;
        sol.anchor = Some((price, now));
        sol.recent.push_back(Obs { at: now, price, size_sol });
        if sol.recent.len() > KEEP_SOL {
            sol.recent.pop_front();
        }
    }

    /// SOL/USD, or `None` when it cannot be known.
    ///
    /// Never substitutes a default: a missing price is an outage, and a
    /// plausible-but-invented number is worse than a blank field because
    /// nothing flags it.
    pub fn sol_usd(&self, max_age: Duration) -> Option<f64> {
        let sol = self.sol.lock().unwrap_or_else(|p| p.into_inner());
        let newest = sol.recent.iter().map(|o| o.at).max()?;
        if newest.elapsed() > max_age {
            return None;
        }
        median(sol.recent.iter().map(|o| o.price))
    }

    /// Price of a token in SOL, as the median of recent fills.
    ///
    /// Needs `MIN_OBS_FOR_PRICE` corroborating fills — see the artifact rates
    /// in the module docs.
    pub fn price_sol(&self, mint: &str, max_age: Duration) -> Option<Priced> {
        let map = self.tokens();
        let series = map.get(mint)?;
        if series.recent.len() < MIN_OBS_FOR_PRICE {
            return None;
        }
        let newest = series.recent.iter().map(|o| o.at).max()?;
        let age = newest.elapsed();
        if age > max_age {
            return None;
        }
        let price = weighted_median(&series.recent)?;
        Some(Priced { price_sol: price, age, observations: series.recent.len() })
    }

    /// Price for an EXIT decision, where recency beats smoothness.
    ///
    /// `price_sol` takes the weighted median of all `KEEP_PER_TOKEN`
    /// observations. That is right for the detector — the median is what
    /// rejects the fee-vault and migration artifacts that produced $11T market
    /// caps — but it is wrong as a sell trigger, because a median exists
    /// precisely to *suppress* recent movement. When a token drops 80%, several
    /// of the last nine prints are still pre-drop, so the median barely moves
    /// and a stop-loss reading it cannot see the crash until it is over.
    ///
    /// So exits read only the newest `EXIT_OBS` observations. Still a median,
    /// because one print with a misread token leg should not be able to fire a
    /// sell on its own, but over a window short enough to actually turn.
    ///
    /// `max_age` should be TIGHT here (seconds, not the hour the detector
    /// tolerates). Returning `None` is the honest answer for a position that
    /// has stopped printing: the caller treats it as unpriceable and alerts
    /// rather than selling blind, which is correct — no recent trades is the
    /// shape a rug takes, and we could not have sold into it anyway.
    pub fn exit_price_sol(&self, mint: &str, max_age: Duration) -> Option<Priced> {
        let map = self.tokens();
        let series = map.get(mint)?;
        if series.recent.len() < MIN_OBS_FOR_PRICE {
            return None;
        }
        let newest = series.recent.iter().map(|o| o.at).max()?;
        let age = newest.elapsed();
        if age > max_age {
            return None;
        }
        // `recent` is chronological (push_back / pop_front), so the tail is the
        // newest. Collected back into order for the weighting to read normally.
        let tail: VecDeque<Obs> =
            series.recent.iter().rev().take(EXIT_OBS).rev().copied().collect();
        let price = weighted_median(&tail)?;
        Some(Priced { price_sol: price, age, observations: tail.len() })
    }

    /// Cumulative SOL traded for a token since it was first observed.
    pub fn volume_sol(&self, mint: &str) -> Option<f64> {
        self.tokens().get(mint).map(|s| s.volume_sol)
    }

    pub fn tracked_tokens(&self) -> usize {
        self.tokens().len()
    }

    /// Seed an observation directly. Test-only: production observations come
    /// from the stream, but tests need a populated index without a network.
    #[cfg(test)]
    pub fn seed(&self, mint: &str, price_sol: f64, size_sol: f64) {
        let mut map = self.tokens();
        let series = map.entry(mint.to_string()).or_default();
        series.recent.push_back(Obs { at: Instant::now(), price: price_sol, size_sol });
        series.volume_sol += size_sol;
        series.trades += 1;
    }

    /// Seed a SOL/USD observation. Test-only.
    #[cfg(test)]
    pub fn seed_sol_usd(&self, price: f64) {
        self.observe_sol_usd(price, 10.0, Instant::now());
    }

    /// Drop tokens with no observation inside `max_age`.
    ///
    /// The index sees hundreds of distinct tokens a minute, so without this it
    /// grows without bound. A token nobody has traded in hours is also not one
    /// we can price.
    pub fn prune(&self, max_age: Duration) -> usize {
        let mut map = self.tokens();
        let before = map.len();
        map.retain(|_, s| s.recent.iter().any(|o| o.at.elapsed() <= max_age));
        before - map.len()
    }
}

/// Median weighted by trade size.
///
/// An unweighted median treats a 0.03 SOL dust trade as equal evidence to a
/// 40 SOL one, and dust carries most of the slippage. Observed live: a token's
/// reported multiple swinging 9.9x -> 16.4x inside 90 seconds, which is the
/// aggregation moving, not the price. Weighting by size lets the trades that
/// actually set the market dominate.
///
/// Weight is capped at `MAX_OBS_WEIGHT_SOL`. Past a few SOL, extra size is no
/// longer better evidence about the price — and leaving it uncapped means the
/// same SOL figure both forms the price and decides whose price wins, so one
/// large fill with a misread token leg carries the vote outright.
fn weighted_median(obs: &VecDeque<Obs>) -> Option<f64> {
    let mut v: Vec<(f64, f64)> = obs
        .iter()
        .filter(|o| o.price.is_finite() && o.price > 0.0 && o.size_sol > 0.0)
        .map(|o| (o.price, o.size_sol.min(MAX_OBS_WEIGHT_SOL)))
        .collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.0.total_cmp(&b.0));
    let total: f64 = v.iter().map(|(_, w)| w).sum();
    let mut acc = 0.0;
    for (price, w) in &v {
        acc += w;
        if acc >= total / 2.0 {
            return Some(*price);
        }
    }
    v.last().map(|(p, _)| *p)
}

/// Median of an iterator of prices. `None` when empty.
///
/// Median rather than mean: measured artifacts include a 68,579 SOL "swap"
/// priced at zero, which would drag any average badly while leaving the median
/// untouched.
fn median(values: impl Iterator<Item = f64>) -> Option<f64> {
    let mut v: Vec<f64> = values.filter(|p| p.is_finite() && *p > 0.0).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    Some(if v.len() % 2 == 0 { (v[mid - 1] + v[mid]) / 2.0 } else { v[mid] })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx() -> PriceIndex {
        PriceIndex::new()
    }

    #[test]
    fn median_ignores_the_outliers_a_mean_would_swallow() {
        // The real shape of the data: a cluster around 76 plus a zero-priced
        // artifact from a 68,579 SOL "swap".
        let vals = [76.4, 76.5, 76.6, 0.0001, 76.45];
        assert_eq!(median(vals.into_iter()), Some(76.45));
        let mean: f64 = vals.iter().sum::<f64>() / vals.len() as f64;
        assert!(mean < 62.0, "a mean is dragged to {mean:.1} by one artifact");
        assert!(mean < 76.4 - 14.0, "and it lands far outside the true cluster");
    }

    /// A dust trade must not carry the same weight as a large one: dust is
    /// where the slippage lives, and letting it vote equally made a token's
    /// reported multiple swing 9.9x -> 16.4x in 90 seconds.
    #[test]
    fn weighting_lets_real_size_set_the_price() {
        let mut obs = VecDeque::new();
        // Three dust trades at silly prices, one large trade at the real one.
        for p in [2.0, 3.0, 4.0] {
            obs.push_back(Obs { at: Instant::now(), price: p, size_sol: 0.03 });
        }
        obs.push_back(Obs { at: Instant::now(), price: 1.0, size_sol: 40.0 });

        assert_eq!(weighted_median(&obs), Some(1.0), "the 40 SOL trade should decide");
        // The unweighted median would have picked a dust price.
        assert_eq!(median(obs.iter().map(|o| o.price)), Some(2.5));
    }

    /// The shape of the 2738x sample: nine honest fills and one large trade
    /// whose token leg was misread. Uncapped, its 40 SOL outweighs the other
    /// nine combined and it becomes the price outright — the weighting meant to
    /// suppress noise amplifying it instead.
    #[test]
    fn one_large_trade_cannot_outvote_the_market() {
        let mut obs = VecDeque::new();
        for _ in 0..9 {
            obs.push_back(Obs { at: Instant::now(), price: 0.001, size_sol: 0.5 });
        }
        obs.push_back(Obs { at: Instant::now(), price: 2.5, size_sol: 40.0 });

        assert_eq!(weighted_median(&obs), Some(0.001), "nine fills outweigh one");
        // Uncapped, 40 > 9 * 0.5 and the outlier would carry the vote alone.
        let uncapped: f64 = 40.0;
        assert!(uncapped > 9.0 * 0.5, "premise: it really does dominate on raw size");
    }

    /// Capping must not flip the original problem back on: dust still loses.
    #[test]
    fn dust_still_loses_to_real_size() {
        let mut obs = VecDeque::new();
        for p in [2.0, 3.0, 4.0] {
            obs.push_back(Obs { at: Instant::now(), price: p, size_sol: 0.03 });
        }
        obs.push_back(Obs { at: Instant::now(), price: 1.0, size_sol: 40.0 });
        assert_eq!(weighted_median(&obs), Some(1.0));
    }

    #[test]
    fn weighted_median_handles_degenerate_input() {
        assert_eq!(weighted_median(&VecDeque::new()), None);
        let mut obs = VecDeque::new();
        obs.push_back(Obs { at: Instant::now(), price: 5.0, size_sol: 0.0 });
        assert_eq!(weighted_median(&obs), None, "zero-size observations carry no weight");
    }

    #[test]
    fn median_of_nothing_is_none() {
        assert_eq!(median(std::iter::empty()), None);
        assert_eq!(median([f64::NAN, -1.0, 0.0].into_iter()), None);
    }

    #[test]
    fn sol_usd_rejects_implausible_observations() {
        let i = idx();
        let now = Instant::now();
        i.observe_sol_usd(0.0001, 68_579.0, now); // the measured artifact
        i.observe_sol_usd(1e9, 5.0, now);
        assert_eq!(i.sol_usd(Duration::from_secs(60)), None, "artifacts must not seed a price");

        i.observe_sol_usd(76.5, 10.0, now);
        assert_eq!(i.sol_usd(Duration::from_secs(60)), Some(76.5));
    }

    /// SOL does not move 40% in a tick. A jump that large is an artifact.
    #[test]
    fn sol_usd_rejects_a_sudden_jump() {
        let i = idx();
        let now = Instant::now();
        i.observe_sol_usd(76.0, 10.0, now);
        i.observe_sol_usd(120.0, 10.0, now);
        assert_eq!(i.sol_usd(Duration::from_secs(60)), Some(76.0), "the jump must be refused");
    }

    /// The deadlock the re-anchor exists to prevent: after any gap longer than
    /// a real move, every fresh price looks like a jump from a stale anchor —
    /// so nothing is accepted, so the anchor never refreshes. Forever.
    #[test]
    fn a_stale_anchor_does_not_wedge_the_feed() {
        let i = idx();
        let old = Instant::now() - Duration::from_secs(300);
        i.observe_sol_usd(76.0, 10.0, old);
        // 200 is a "jump" from 76, but the anchor is five minutes old and is
        // no longer evidence about anything.
        i.observe_sol_usd(200.0, 10.0, Instant::now());
        assert_eq!(
            i.sol_usd(Duration::from_secs(60)),
            Some(200.0),
            "a stale anchor must not block every future price"
        );
    }

    /// If we keep rejecting, the market gapped and we are the ones who are
    /// wrong — but capitulation must never cross the hard band, or a stuck
    /// upstream that merely repeats itself gets force-accepted.
    #[test]
    fn capitulation_is_bounded_by_a_hard_band() {
        let i = idx();
        let now = Instant::now();
        i.observe_sol_usd(76.0, 10.0, now);
        // A persistent 10x. Repetition is not evidence.
        for _ in 0..20 {
            i.observe_sol_usd(760.0, 10.0, now);
        }
        assert_eq!(
            i.sol_usd(Duration::from_secs(60)),
            Some(76.0),
            "persistence must not force-accept a 10x"
        );

        // A persistent move INSIDE the band is a real gap; accept it.
        let j = idx();
        j.observe_sol_usd(76.0, 10.0, now);
        for _ in 0..6 {
            j.observe_sol_usd(90.0, 10.0, now);
        }
        assert_eq!(j.sol_usd(Duration::from_secs(60)), Some(90.0));
    }

    #[test]
    fn a_stale_price_is_no_price() {
        let i = idx();
        i.observe_sol_usd(76.5, 10.0, Instant::now() - Duration::from_secs(120));
        assert_eq!(i.sol_usd(Duration::from_secs(60)), None);
        assert_eq!(i.sol_usd(Duration::from_secs(300)), Some(76.5));
    }

    #[test]
    fn unknown_tokens_have_no_price() {
        assert!(idx().price_sol("NEVER_SEEN", Duration::from_secs(60)).is_none());
        assert!(idx().volume_sol("NEVER_SEEN").is_none());
    }

    // --- observe(): building a transaction the way the stream delivers one.

    fn bal(owner: &str, mint: &str, amount: f64) -> yellowstone_grpc_proto::prelude::TokenBalance {
        yellowstone_grpc_proto::prelude::TokenBalance {
            account_index: 0,
            mint: mint.into(),
            owner: owner.into(),
            program_id: String::new(),
            ui_token_amount: Some(yellowstone_grpc_proto::prelude::UiTokenAmount {
                ui_amount: amount,
                decimals: 6,
                amount: String::new(),
                ui_amount_string: String::new(),
            }),
        }
    }

    fn observed(pre: Vec<yellowstone_grpc_proto::prelude::TokenBalance>,
                post: Vec<yellowstone_grpc_proto::prelude::TokenBalance>) -> PriceIndex {
        let i = idx();
        let meta = TransactionStatusMeta {
            pre_token_balances: pre,
            post_token_balances: post,
            ..Default::default()
        };
        i.observe(&SubscribeUpdateTransactionInfo::default(), &meta);
        i
    }

    /// An ordinary swap: one owner, SOL out, one token in. One fill is not yet
    /// a price — nothing has corroborated it and the jump guard has no baseline
    /// to judge it against, so a lone artifact would simply become the price.
    #[test]
    fn a_plain_swap_prices_the_token() {
        let i = observed(
            vec![bal("alice", WSOL, 10.0), bal("alice", "TOK", 0.0)],
            vec![bal("alice", WSOL, 5.0), bal("alice", "TOK", 1000.0)],
        );
        assert!(i.price_sol("TOK", Duration::from_secs(60)).is_none(),
                "a single fill is an anecdote, not a price");

        i.observe_token("TOK", 0.005, 5.0, Instant::now());
        let p = i.price_sol("TOK", Duration::from_secs(60)).unwrap();
        assert!((p.price_sol - 0.005).abs() < 1e-9, "5 SOL for 1000 tokens, got {}", p.price_sol);
    }

    /// A multi-hop route leaves a dust residue in the intermediate token, while
    /// the SOL leg is the size of the WHOLE trade. Attributing all that SOL to
    /// the residue prices the intermediate at millions of SOL each — and because
    /// the observation is weighted by the SOL leg, it does not merely join the
    /// median, it OUTVOTES every honest trade in the series.
    ///
    /// This is what put `$Callout` at x69364 and a $353M market cap.
    #[test]
    fn a_routing_residue_does_not_price_the_intermediate_token() {
        let i = observed(
            vec![bal("router", WSOL, 10.0), bal("router", "MID", 0.0), bal("router", "OUT", 0.0)],
            // 5 SOL spent, ending in OUT; MID keeps an unswept dust remainder.
            vec![bal("router", WSOL, 5.0), bal("router", "MID", 0.000001),
                 bal("router", "OUT", 1000.0)],
        );
        assert!(
            i.price_sol("MID", Duration::from_secs(60)).is_none(),
            "the SOL leg cannot be attributed to any one token when several moved"
        );
    }

    /// The same defect with no dust involved: two tokens moved, so each would be
    /// credited with the full SOL leg and both prices would be wrong.
    #[test]
    fn a_two_token_transfer_prices_neither_token() {
        let i = observed(
            vec![bal("bob", WSOL, 10.0), bal("bob", "AAA", 0.0), bal("bob", "BBB", 0.0)],
            vec![bal("bob", WSOL, 6.0), bal("bob", "AAA", 100.0), bal("bob", "BBB", 200.0)],
        );
        assert!(i.price_sol("AAA", Duration::from_secs(60)).is_none());
        assert!(i.price_sol("BBB", Duration::from_secs(60)).is_none());
    }

    /// Replayed from chain: signature 5aSGU3L1WQAt…, which priced mint
    /// 4hB733Gh at 527x its market.
    ///
    /// The buyer paid in NATIVE SOL, which never appears in token balances, so
    /// the only WSOL movement in the whole transaction belonged to a fee vault
    /// receiving 0.065 SOL — a vault that also held 608 tokens. Nothing here is
    /// a swap we can see; the correct output is no price at all, not the ratio
    /// between two unrelated numbers.
    #[test]
    fn a_fee_vault_is_not_a_counterparty() {
        let i = observed(
            vec![
                bal("pool", "TOK", 70_386_983.7),
                bal("buyer", "TOK", 0.0),
                bal("feevault", "TOK", 608.4),
                bal("feevault", WSOL, 0.0),
            ],
            vec![
                bal("pool", "TOK", 0.0),
                bal("buyer", "TOK", 70_317_239.5),
                // The vault's tokens go down while its WSOL goes up: opposite
                // signs, which is all the old rule asked for.
                bal("feevault", "TOK", 0.0),
                bal("feevault", WSOL, 0.065073542),
            ],
        );
        assert!(
            i.price_sol("TOK", Duration::from_secs(60)).is_none(),
            "0.065 SOL over 608 tokens is a fee, not a market"
        );
    }

    /// The rule must not reject the trade it is meant to protect: in a real
    /// swap the trader and the pool are the two largest movers, equal but for
    /// fees, so both are read and they corroborate each other.
    #[test]
    fn both_sides_of_a_real_swap_are_still_read() {
        let i = observed(
            vec![bal("pool", "TOK", 1000.0), bal("pool", WSOL, 0.0),
                 bal("trader", "TOK", 0.0), bal("trader", WSOL, 5.0)],
            vec![bal("pool", "TOK", 0.0), bal("pool", WSOL, 5.0),
                 bal("trader", "TOK", 1000.0), bal("trader", WSOL, 0.0)],
        );
        let p = i.price_sol("TOK", Duration::from_secs(60)).unwrap();
        assert!((p.price_sol - 0.005).abs() < 1e-9, "got {}", p.price_sol);
        assert_eq!(p.observations, 2, "trader and pool each corroborate the other");
    }

    /// Two owners in one transaction are two independent trades, not a route.
    /// Only the owner who moved several tokens is ambiguous.
    #[test]
    fn separate_owners_are_still_priced_independently() {
        let i = observed(
            vec![bal("alice", WSOL, 10.0), bal("carol", WSOL, 10.0)],
            vec![bal("alice", WSOL, 9.0), bal("alice", "TOK", 500.0),
                 bal("carol", WSOL, 8.0), bal("carol", "TOK", 1000.0)],
        );
        let p = i.price_sol("TOK", Duration::from_secs(60)).unwrap();
        assert_eq!(p.observations, 2, "both owners should have been priced");
    }

    /// The backstop must not fight a token that is genuinely running: each fill
    /// is a small step, so a 100x over a series of trades is accepted in full.
    #[test]
    fn a_real_run_is_tracked_all_the_way_up() {
        let i = idx();
        let mut p = 0.001;
        for _ in 0..24 {
            i.observe_token("RUNNER", p, 5.0, Instant::now());
            p *= 1.25;
        }
        let out = i.price_sol("RUNNER", Duration::from_secs(60)).unwrap();
        assert!(out.price_sol > 0.05, "a 200x run must come through, got {}", out.price_sol);
    }

    /// One impossible fill among honest ones is refused rather than believed.
    #[test]
    fn a_single_impossible_fill_is_refused() {
        let i = idx();
        for _ in 0..5 {
            i.seed("TOK", 0.001, 1.0);
        }
        // The shape of the bug: an absurd price carrying a heavy SOL weight.
        i.observe_token("TOK", 69_364.0, 40.0, Instant::now());
        let p = i.price_sol("TOK", Duration::from_secs(60)).unwrap();
        assert!((p.price_sol - 0.001).abs() < 1e-9, "expected 0.001, got {}", p.price_sol);
    }

    /// …but if the market keeps saying it, the series is the stale party.
    #[test]
    fn repeated_disagreement_capitulates() {
        let i = idx();
        for _ in 0..5 {
            i.seed("TOK", 0.001, 1.0);
        }
        for _ in 0..TOKEN_JUMP_CAPITULATE {
            i.observe_token("TOK", 1.0, 1.0, Instant::now());
        }
        // Capitulation clears the stale history, leaving one observation — which
        // is below the corroboration floor, so there is deliberately no price
        // until the new level is confirmed by a second fill.
        assert!(i.price_sol("TOK", Duration::from_secs(60)).is_none());
        i.observe_token("TOK", 1.0, 1.0, Instant::now());
        let p = i.price_sol("TOK", Duration::from_secs(60)).unwrap();
        assert_eq!(p.price_sol, 1.0, "a sustained repricing must eventually be believed");
        assert_eq!(p.observations, 2, "and the stale history is discarded, not blended");
    }

    /// Volume is a record of trades, not of prices we accepted.
    #[test]
    fn refused_observations_still_count_as_volume() {
        let i = idx();
        i.observe_token("TOK", 0.001, 1.0, Instant::now());
        i.observe_token("TOK", 69_364.0, 40.0, Instant::now());
        assert_eq!(i.volume_sol("TOK"), Some(41.0));
    }

    #[test]
    fn pruning_reclaims_tokens_that_stopped_trading() {
        let i = idx();
        {
            let mut map = i.tokens();
            let fresh = map.entry("FRESH".into()).or_default();
            fresh.recent.push_back(Obs { at: Instant::now(), price: 1.0, size_sol: 1.0 });
            let old = map.entry("STALE".into()).or_default();
            old.recent.push_back(Obs {
                at: Instant::now() - Duration::from_secs(7200),
                price: 1.0,
                size_sol: 1.0,
            });
        }
        assert_eq!(i.tracked_tokens(), 2);
        assert_eq!(i.prune(Duration::from_secs(3600)), 1);
        assert_eq!(i.tracked_tokens(), 1);
    }

    /// The failure this function exists for: a position that has crashed, where
    /// the full-window median still reports it near the old price.
    ///
    /// Six prints at 1.0, then three at 0.2 — an 80% drop. The detector's
    /// median sits on the pre-drop majority and shows almost no move, so a
    /// -15% stop reading it never fires. The exit price follows the crash.
    #[test]
    fn exit_price_follows_a_crash_the_full_median_cannot_see() {
        let i = PriceIndex::new();
        for _ in 0..6 {
            i.seed("mint", 1.0, 1.0);
        }
        for _ in 0..3 {
            i.seed("mint", 0.2, 1.0);
        }

        let detector = i.price_sol("mint", Duration::from_secs(60)).unwrap().price_sol;
        let exit = i.exit_price_sol("mint", Duration::from_secs(60)).unwrap().price_sol;

        assert_eq!(detector, 1.0, "full median is still anchored to the pre-crash prints");
        assert_eq!(exit, 0.2, "exit price sees the crash");

        // The point of the whole change, stated as the number the ladder reads.
        let entry = 1.0;
        assert!(
            (exit - entry) / entry <= -0.15,
            "a -15% stop must be able to fire on this position"
        );
        assert!(
            (detector - entry) / entry > -0.15,
            "and would NOT have fired on the full median"
        );
    }

    #[test]
    fn exit_price_refuses_a_stale_series() {
        let i = PriceIndex::new();
        i.seed("mint", 1.0, 1.0);
        i.seed("mint", 1.0, 1.0);
        // Fresh enough at a minute, not at a millisecond.
        assert!(i.exit_price_sol("mint", Duration::from_secs(60)).is_some());
        assert!(
            i.exit_price_sol("mint", Duration::from_millis(0)).is_none(),
            "a price too old to trust is None, not a sell signal"
        );
    }

    #[test]
    fn exit_price_still_needs_corroboration() {
        let i = PriceIndex::new();
        i.seed("mint", 1.0, 1.0);
        assert!(
            i.exit_price_sol("mint", Duration::from_secs(60)).is_none(),
            "one print cannot fire a sell on its own"
        );
    }
}
