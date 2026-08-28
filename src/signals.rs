//! Announced conviction signals, and tracking how they performed.
//!
//! # How performance is measured
//!
//! Not by re-deriving a price. Each signal stores a **reference trade** taken
//! from the buy that triggered it: `reference_sol` paid for
//! `reference_tokens_raw` tokens. Performance is then one division:
//!
//! ```text
//!     multiple = (SOL those same tokens fetch NOW) / (SOL originally paid)
//! ```
//!
//! This avoids an entire class of bugs. There is no decimals arithmetic, no
//! mid-price that ignores slippage, and no need to know which pool the token
//! trades in. The denominator is a real executed fill by a real wallet, and the
//! numerator is a real routed quote for the same quantity, so the ratio is what
//! that wallet's position is actually worth.
//!
//! It also degrades honestly: if the token cannot be routed at all — the usual
//! shape of a rug — the quote fails and the signal reports nothing rather than
//! inventing a number.
//!
//! # Why a ladder of multiples instead of a percentage
//!
//! A single "alert above N% gain" threshold cannot work: set it low and one
//! token that keeps drifting up re-posts forever; set it high and you never
//! hear about a 3x. Updates fire when a signal crosses the next rung of a
//! configurable ladder (2x, 3x, 5x, …) and each rung fires at most once, which
//! is both bounded and how call channels actually speak.
//!
//! # Persistence
//!
//! Signals outlive the process — a restart during a runner must not lose the
//! entry price, which is unrecoverable after the fact. The store appends to
//! JSONL and reloads on boot.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// One announced signal, with everything needed to re-price it later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRecord {
    pub mint: String,
    /// Sanitized display name/symbol captured at announce time.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub symbol: String,
    pub first_seen_utc: DateTime<Utc>,
    /// Telegram message id of the original call, so updates thread under it.
    #[serde(default)]
    pub message_id: Option<i64>,
    /// Reference trade — the basis for every later multiple.
    pub reference_sol: f64,
    pub reference_tokens_raw: u64,
    /// Decimals of the token, so `reference_tokens_raw` can be converted to UI
    /// units when re-pricing. Without it a live market cap cannot be computed.
    #[serde(default)]
    pub decimals: u32,
    /// FDV in USD at announce time, when it could be computed.
    #[serde(default)]
    pub fdv_usd_at_signal: Option<f64>,
    #[serde(default)]
    pub supply: Option<f64>,
    pub wallets: Vec<String>,
    pub total_sol: f64,
    /// SOL/USD as of the call. Volume is converted with THIS rate forever, so
    /// a change in "SM Vol" always means more buying — never a move in the
    /// yardstick.
    #[serde(default)]
    pub sol_usd_at_signal: Option<f64>,
    /// Fees paid across every tracked buy of this token, including buys that
    /// arrived AFTER the call. Grows over the tracking window, which is what
    /// makes it worth repeating in an update.
    #[serde(default)]
    pub total_fees_sol: f64,
    /// Highest ladder rung already announced. Starts at 1.0 (nothing reported).
    #[serde(default = "one")]
    pub last_reported_multiple: f64,
    /// Most recent observed multiple, refreshed on every re-pricing sweep even
    /// when no rung fires. Stored so `/calls` can answer instantly instead of
    /// issuing a live quote per tracked signal.
    #[serde(default = "one")]
    pub last_multiple: f64,
    /// Highest multiple ever measured for this call.
    ///
    /// # Why the leaderboard ranks on this and not `last_multiple`
    ///
    /// Ranking by the CURRENT price penalises exactly the calls that worked. A
    /// token that ran to 1000x and settled at 649x outperformed one sitting
    /// flat at 3x, and a board that puts the second above the first is
    /// measuring when you happened to look rather than how the call did.
    ///
    /// Defaulted rather than required so records written before this field
    /// existed load rather than being discarded; they converge on their real
    /// peak from the next sweep onward.
    #[serde(default)]
    pub peak_multiple: f64,
    /// When `last_multiple` was measured, so a stale figure can say so.
    #[serde(default)]
    pub last_checked_utc: Option<DateTime<Utc>>,
}

fn one() -> f64 {
    1.0
}

impl SignalRecord {
    /// Age in seconds, used to retire signals from tracking.
    /// The highest multiple seen, tolerating records written before the field
    /// existed (they carry 0.0 until the next sweep re-measures them).
    pub fn peak(&self) -> f64 {
        self.peak_multiple.max(self.last_multiple)
    }

    pub fn age_secs(&self, now: DateTime<Utc>) -> i64 {
        (now - self.first_seen_utc).num_seconds()
    }
}

/// In-memory index of announced signals, persisted to JSONL.
///
/// Keyed by mint: a token that signals again while already tracked keeps its
/// ORIGINAL entry, because the performance question is always "since the call",
/// and re-basing on a later buy would quietly erase a gain that already
/// happened.
pub struct SignalStore {
    path: String,
    by_mint: Mutex<HashMap<String, SignalRecord>>,
}

impl SignalStore {
    /// Load previously announced signals. A missing file is normal on first
    /// run; a corrupt line is skipped rather than fatal.
    pub fn load(path: &str) -> Self {
        let mut by_mint = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(rec) = serde_json::from_str::<SignalRecord>(line) {
                    // Later lines are updates to earlier ones; last wins.
                    by_mint.insert(rec.mint.clone(), rec);
                }
            }
        }
        Self { path: path.to_string(), by_mint: Mutex::new(by_mint) }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Every tracked signal. Backs Alpha wallet scoring, which needs the whole
    /// history rather than the active window — a wallet's record is made of
    /// calls that have already finished running.
    pub fn all(&self) -> Vec<SignalRecord> {
        self.lock().values().cloned().collect()
    }

    #[cfg(test)]
    pub fn contains(&self, mint: &str) -> bool {
        self.lock().contains_key(mint)
    }

    /// Record a newly announced signal. Returns false if the mint was already
    /// tracked, in which case the existing entry is preserved untouched.
    pub fn insert(&self, rec: SignalRecord) -> bool {
        let mut map = self.lock();
        if map.contains_key(&rec.mint) {
            return false;
        }
        map.insert(rec.mint.clone(), rec.clone());
        drop(map);
        self.append(&rec);
        true
    }

    /// Signals still worth re-pricing.
    pub fn active(&self, now: DateTime<Utc>, max_age_secs: i64) -> Vec<SignalRecord> {
        self.lock()
            .values()
            .filter(|r| r.age_secs(now) <= max_age_secs)
            .cloned()
            .collect()
    }

    /// Fold a later buy into an already-announced token.
    ///
    /// A called token keeps being bought even though it has stopped being
    /// announced. Without this, every figure except market cap would be frozen
    /// at the moment of the call, and an update would repeat stale numbers
    /// beside a live one.
    ///
    /// Not persisted per call: this fires on every tracked buy, and appending a
    /// JSONL line each time would grow the file without bound for an active
    /// token. The next `mark_reported` writes the accumulated totals, and a
    /// restart losing a partial sum costs slightly low figures, not correctness.
    pub fn add_buy(&self, mint: &str, wallet: &str, sol: f64, fees: f64) {
        let mut map = self.lock();
        let Some(rec) = map.get_mut(mint) else { return };
        rec.total_sol += sol;
        rec.total_fees_sol += fees;
        // Distinct by ADDRESS. Display names repeat (several are just a
        // shortened address), so counting by name would undercount buyers.
        if !rec.wallets.iter().any(|w| w == wallet) {
            rec.wallets.push(wallet.to_string());
        }
    }

    /// Record the latest observed multiple. Called on every sweep, including
    /// the vast majority that announce nothing.
    ///
    /// Deliberately NOT persisted per call: this fires every few minutes for
    /// every tracked signal, and a JSONL line each time would bloat the file.
    /// A restart loses only the freshness of a number recomputed next sweep.
    pub fn mark_checked(&self, mint: &str, multiple: f64, at: DateTime<Utc>) {
        if let Some(rec) = self.lock().get_mut(mint) {
            rec.last_multiple = multiple;
            // A peak only ever rises. `last_reported_multiple` is not a
            // substitute: it is quantised to announcement rungs, so a call that
            // ran to 7.4x and never crossed the next rung reads as 5x forever.
            rec.peak_multiple = rec.peak_multiple.max(multiple);
            rec.last_checked_utc = Some(at);
        }
    }

    /// Tracked signals, newest first. The re-pricing sweep works this order so
    /// a cap drops the oldest rather than an arbitrary slice.
    pub fn ranked_by_recency(&self, now: DateTime<Utc>, max_age_secs: i64) -> Vec<SignalRecord> {
        let mut out = self.active(now, max_age_secs);
        out.sort_by(|a, b| b.first_seen_utc.cmp(&a.first_seen_utc));
        out
    }

    /// Every tracked signal, best performer first.
    ///
    /// Ranked on the PEAK, not the current price — see `peak_multiple`.
    pub fn ranked(&self, now: DateTime<Utc>, max_age_secs: i64) -> Vec<SignalRecord> {
        let mut out = self.active(now, max_age_secs);
        // Ties break on recency rather than HashMap order, so the list is
        // stable between calls instead of reshuffling.
        out.sort_by(|a, b| {
            b.peak()
                .total_cmp(&a.peak())
                .then(b.first_seen_utc.cmp(&a.first_seen_utc))
        });
        out
    }

    /// Raise the highest-reported rung after an update is posted.
    pub fn mark_reported(&self, mint: &str, multiple: f64) {
        let mut map = self.lock();
        let Some(rec) = map.get_mut(mint) else { return };
        rec.last_reported_multiple = multiple;
        let snapshot = rec.clone();
        drop(map);
        self.append(&snapshot);
    }

    /// Rewrite the file from current in-memory state.
    ///
    /// `mark_checked` fires for every signal on every sweep and is deliberately
    /// not persisted per call. Without a periodic flush, though, a restart
    /// reloads every record at `last_multiple = 1.0` with no check time — which
    /// is exactly the "everything shows x1.0, nothing re-priced" symptom.
    ///
    /// Rewriting also COMPACTS: the append-only log accumulates one line per
    /// update per signal, and only the last line for each mint is ever read.
    pub fn persist_all(&self) {
        if let Err(e) = self.persist_all_inner() {
            tracing::warn!(error = %e, path = %self.path, "failed to persist signals");
        }
    }

    fn persist_all_inner(&self) -> anyhow::Result<()> {
        use std::io::Write;
        let snapshot: Vec<SignalRecord> = self.lock().values().cloned().collect();
        if let Some(parent) = std::path::Path::new(&self.path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        // Write-then-rename: a crash mid-write must not truncate the only
        // record of every call's entry price.
        let tmp = format!("{}.tmp", self.path);
        {
            let mut f = std::fs::File::create(&tmp)?;
            for rec in &snapshot {
                writeln!(f, "{}", serde_json::to_string(rec)?)?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Fill in the USD rate when it was unavailable at call time.
    ///
    /// A later rate is not the rate that applied then, but SOL moves single
    /// digits over hours while the alternative is no USD figures at all.
    pub fn set_sol_rate(&self, mint: &str, rate: f64) {
        let mut map = self.lock();
        let Some(rec) = map.get_mut(mint) else { return };
        if rec.sol_usd_at_signal.is_none() && rate > 0.0 {
            rec.sol_usd_at_signal = Some(rate);
            // The reference fill is exact in SOL, so the signal-time FDV can be
            // reconstructed as soon as a rate exists.
            if rec.fdv_usd_at_signal.is_none() {
                if let (Some(supply), true) = (rec.supply, rec.decimals > 0) {
                    let tokens_ui =
                        rec.reference_tokens_raw as f64 / 10f64.powi(rec.decimals as i32);
                    if tokens_ui > 0.0 && supply > 0.0 {
                        let fdv = (rec.reference_sol / tokens_ui) * supply * rate;
                        if fdv.is_finite() {
                            rec.fdv_usd_at_signal = Some(fdv);
                        }
                    }
                }
            }
        }
    }

    /// Fill in decimals resolved after the fact.
    pub fn set_decimals(&self, mint: &str, decimals: u32) {
        if let Some(rec) = self.lock().get_mut(mint) {
            rec.decimals = decimals;
        }
    }

    /// Fill in a name/symbol resolved after the fact.
    pub fn set_identity(&self, mint: &str, name: &str, symbol: &str) {
        if let Some(rec) = self.lock().get_mut(mint) {
            rec.name = name.to_string();
            rec.symbol = symbol.to_string();
        }
    }

    /// Drop signals older than `max_age_secs` from memory. The JSONL keeps the
    /// history; this only bounds what gets re-priced.
    pub fn retire(&self, now: DateTime<Utc>, max_age_secs: i64) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, r| r.age_secs(now) <= max_age_secs);
        before - map.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, SignalRecord>> {
        // The map is rebuildable state; a poisoned lock is not worth killing
        // the tracker over.
        self.by_mint.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn append(&self, rec: &SignalRecord) {
        if let Err(e) = self.append_inner(rec) {
            tracing::warn!(error = %e, path = %self.path, "failed to persist signal");
        }
    }

    fn append_inner(&self, rec: &SignalRecord) -> anyhow::Result<()> {
        use std::io::Write;
        if let Some(parent) = std::path::Path::new(&self.path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(rec)?)?;
        Ok(())
    }
}

/// The highest ladder rung `multiple` has reached that is above
/// `already_reported`, or `None` if it has not cleared a new one.
///
/// Returns the HIGHEST cleared rung, not the next one: a token that goes
/// straight from 1x to 12x should announce "12x", not crawl up posting 2x, 3x,
/// 5x and 10x in sequence.
///
/// # The ladder does not end
///
/// Above the last configured rung the sequence CONTINUES, generated on a
/// 1–2.5–5 progression per decade (…100, 250, 500, 1000, 2500…). A fixed list
/// would mean the best outcome the bot can produce is also the one it stops
/// reporting: a token that ran 500x would go silent after 100x, exactly when
/// the updates are worth the most.
pub fn next_rung(multiple: f64, already_reported: f64, ladder: &[f64]) -> Option<f64> {
    if !multiple.is_finite() || multiple <= 0.0 {
        return None;
    }
    let cleared = |acc: Option<f64>, r: f64| -> Option<f64> {
        (multiple >= r && r > already_reported)
            .then(|| acc.map_or(r, |a: f64| a.max(r)))
            .or(acc)
    };

    let mut best = ladder.iter().copied().fold(None, cleared);
    for r in rungs_above(ladder.iter().copied().fold(0.0, f64::max)) {
        if r > multiple {
            break;
        }
        best = cleared(best, r);
    }
    best
}

/// Rungs beyond the configured ladder, on a 1–2.5–5 progression per decade.
///
/// Bounded at 1e9: past that the "multiple" is far more likely a broken quote
/// than a real position, and an unbounded generator would spin.
fn rungs_above(top: f64) -> impl Iterator<Item = f64> {
    const STEPS: [f64; 3] = [1.0, 2.5, 5.0];
    let start = if top.is_finite() && top > 0.0 { top } else { 100.0 };
    let mut decade = 10f64.powf(start.log10().floor());
    let mut i = 0usize;
    std::iter::from_fn(move || {
        loop {
            if decade > 1e9 {
                return None;
            }
            let r = decade * STEPS[i % 3];
            i += 1;
            if i % 3 == 0 {
                decade *= 10.0;
            }
            if r > start {
                return Some(r);
            }
        }
    })
}

/// Fully-diluted valuation right now, measured rather than extrapolated.
///
/// `sol_now` is what the reference token quantity fetches today, so the price
/// per token follows directly; supply is re-read because it can change.
/// Raw token units converted to UI units. Returns 0 when decimals are unknown
/// (records written before the field existed default to 0), which makes the
/// caller treat the price as unavailable rather than compute a wrong one.
pub fn tokens_ui(raw: u64, decimals: u32) -> f64 {
    if decimals == 0 || raw == 0 {
        return 0.0;
    }
    raw as f64 / 10f64.powi(decimals as i32)
}

async fn live_fdv_usd(
    rpc: &crate::rpc::RpcClient,
    rec: &SignalRecord,
    sol_now: f64,
    prices: &crate::prices::PriceIndex,
) -> Option<f64> {
    // `decimals == 0` means UNKNOWN here, not "a zero-decimal token": records
    // written before the field existed default to 0, and treating that as real
    // makes `tokens_ui` enormous and the computed price ~0. Genuine 0-decimal
    // tokens are rare and simply fall back to the scaled estimate, which is
    // the safe direction to be wrong in.
    if rec.decimals == 0 || rec.reference_tokens_raw == 0 {
        return None;
    }
    let supply = rpc.token_supply(&rec.mint).await?;
    if supply <= 0.0 {
        return None;
    }
    let tokens_ui = rec.reference_tokens_raw as f64 / 10f64.powi(rec.decimals as i32);
    if tokens_ui <= 0.0 {
        return None;
    }
    let sol_usd = prices.sol_usd(std::time::Duration::from_secs(300))?;
    let fdv = (sol_now / tokens_ui) * supply * sol_usd;
    fdv.is_finite().then_some(fdv)
}

/// Render a performance update. Threaded as a reply to the original call.
pub fn render_update(
    rec: &SignalRecord,
    multiple: f64,
    current_fdv_usd: Option<f64>,
    now: DateTime<Utc>,
    tz_offset_hours: i32,
) -> String {
    // The ticker alone. An update is a reply to the original call, so the token
    // is already identified one message up — repeating name, mint and buyer
    // list is the spam this format exists to remove.
    // `$` is a TICKER sigil. A name is not a ticker, and a mint certainly is
    // not — `$HukaK2…myT8WJ` reads as a ticker and is not one.
    let ticker = if !rec.symbol.is_empty() {
        format!("${}", rec.symbol)
    } else if !rec.name.is_empty() {
        rec.name.clone()
    } else {
        crate::conviction::short_mint(&rec.mint)
    };

    let mut s = format!("🚀 <b>{ticker} {}</b> 🚀\n\n", format_multiple(multiple));

    // Only claim a move when BOTH ends are known. One known side and one blank
    // reads as a collapse to zero.
    // Degrades in steps rather than all-or-nothing. A known CURRENT market cap
    // is useful on its own; refusing to show it because the signal-time figure
    // is missing throws away the half we do have.
    let elapsed = format_elapsed((now - rec.first_seen_utc).num_seconds().max(0));
    match (rec.fdv_usd_at_signal, current_fdv_usd) {
        (Some(then), Some(now_mc)) => s.push_str(&format!(
            "💵 MC: {} → {} in {elapsed}\n",
            crate::conviction::format_usd(then),
            crate::conviction::format_usd(now_mc),
        )),
        (None, Some(now_mc)) => s.push_str(&format!(
            "💵 MC now: {} ({} in {elapsed})\n",
            crate::conviction::format_usd(now_mc),
            format_multiple(multiple),
        )),
        (Some(then), None) => s.push_str(&format!(
            "💵 MC at signal: {} ({} in {elapsed})\n",
            crate::conviction::format_usd(then),
            format_multiple(multiple),
        )),
        (None, None) => s.push_str(&format!("💵 {} in {elapsed}\n", format_multiple(multiple))),
    }

    // Recomputed from the CURRENT running total at the call's own SOL/USD
    // rate: a change here always means more buying, never a move in FX.
    s.push_str(&format!("SM: {}\n", rec.wallets.len()));
    match rec.sol_usd_at_signal {
        Some(rate) if rate > 0.0 => s.push_str(&format!(
            "SM Vol: {}\n",
            crate::conviction::format_usd(rec.total_sol * rate)
        )),
        _ => s.push_str(&format!(
            "SM Vol: {}\n",
            crate::conviction::format_sol(rec.total_sol)
        )),
    }
    // Includes buys that landed AFTER the call — the token kept being bought
    // even though it stopped being announced, so this is a live number rather
    // than a copy of the one in the original message.
    if rec.total_fees_sol > 0.0 {
        s.push_str(&format!(
            "SM Fees: {}\n",
            crate::conviction::format_sol(rec.total_fees_sol)
        ));
    }

    s.push_str(&crate::conviction::stamp(now, tz_offset_hours));
    s
}

/// `45s`, `2m`, `3h12m` — coarse on purpose. "in 2m" is the useful fact; "in
/// 2m14s" implies a precision the check interval does not have.
fn format_elapsed(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s => {
            let (h, m) = (s / 3600, (s % 3600) / 60);
            if m == 0 { format!("{h}h") } else { format!("{h}h{m}m") }
        }
    }
}

/// `x2.4`, `x12.6`, `x900` — TRUNCATED, never rounded up.
///
/// Rounding overstates: 12.6 displayed as `x13`, and worse, 99.7 as `x100` —
/// claiming a milestone the token has not reached. A performance figure that
/// flatters itself is not one you can act on, so the displayed value is always
/// at or below the measured one.
fn format_multiple(m: f64) -> String {
    if !m.is_finite() || m <= 0.0 {
        return "x0".to_string();
    }
    if m >= 100.0 {
        format!("x{}", m.trunc())
    } else {
        format!("x{:.1}", (m * 10.0).trunc() / 10.0)
    }
}

/// Current SOL value of `tokens_raw` of `mint`, via a routed Jupiter quote.
///
/// A failure here is the normal outcome for a rugged token — no route exists —
/// so it returns `None` rather than an error the caller must interpret.
pub async fn quote_sol_value(
    jup: &crate::jupiter::Jupiter,
    mint: &str,
    tokens_raw: u64,
) -> Option<f64> {
    const WSOL: &str = "So11111111111111111111111111111111111111112";
    if tokens_raw == 0 {
        return None;
    }
    // 100 bps: this is a valuation, not an execution. A tight slippage bound
    // would reject routes that are perfectly good for pricing.
    let q = jup.quote(mint, WSOL, tokens_raw, 100).await.ok()?;
    let out: u64 = q.raw.get("outAmount")?.as_str()?.parse().ok()?;
    Some(out as f64 / 1_000_000_000.0)
}

/// Periodically re-price announced signals and post updates.
///
/// FDV "now" is derived by scaling the signal-time FDV by the multiple rather
/// than re-reading supply: same token quantity, same supply, so the ratio
/// carries through exactly. A second supply read could disagree with the first
/// and make the two FDV figures inconsistent with the stated multiple.
///
/// Runs on its own task. Quotes are issued one at a time with a small gap:
/// Jupiter's free tier rate-limits, and a burst of parallel requests across
/// every tracked signal is the reliable way to get throttled into silence.
#[allow(clippy::too_many_arguments)]
pub fn spawn_tracker(
    store: std::sync::Arc<SignalStore>,
    alerter: std::sync::Arc<crate::alerts::Alerter>,
    rpc: std::sync::Arc<crate::rpc::RpcClient>,
    prices: std::sync::Arc<crate::prices::PriceIndex>,
    cfg: crate::config::TrackedConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        // Floor of 5s, not 30: the 30 was a guard against a sweep that made a
        // network call per signal. Pricing is local now and a sweep measures
        // in microseconds, so the floor exists only to stop a config typo
        // spinning the task.
        let interval = std::time::Duration::from_secs(cfg.update_check_secs.max(5));
        // A price older than this is not a price. A token nobody has traded in
        // an hour cannot be marked to market, and saying so is more honest
        // than reporting the last trade as if it were current.
        let max_price_age = std::time::Duration::from_secs(3600);
        let max_age = cfg.track_for_secs as i64;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                    continue;
                }
            }

            let now = Utc::now();
            let retired = store.retire(now, max_age);
            // Newest first, then capped: a sweep must finish well inside its
            // own interval or updates arrive after they stop being useful.
            let mut batch = store.ranked_by_recency(now, max_age);
            let total = batch.len();
            let cap = cfg.max_repriced_per_sweep.max(1);
            batch.truncate(cap);
            let skipped = total.saturating_sub(batch.len());
            // Counted and reported per sweep. Without this the tracker is
            // invisible: a healthy sweep that crosses no rung logs nothing, so
            // "no updates" and "not running" look identical from the outside.
            let started = std::time::Instant::now();
            let mut priced = 0usize;
            let mut unpriced = 0usize;
            let mut best = 0.0f64;
            if skipped > 0 {
                tracing::warn!(
                    total,
                    cap,
                    skipped,
                    "signal queue exceeds the per-sweep cap; oldest calls not re-priced \
                     this round (lower tracked.track_for_secs or raise max_repriced_per_sweep)"
                );
            }
            tracing::info!(tracking = batch.len(), total, retired, "re-pricing signals");

            let mut named = 0usize;

            // The SOL rate is fetched ONCE per sweep, not per record. Per
            // record it produced dozens of identical failures per second when
            // the endpoint was unhappy, because a failed fetch caches nothing
            // and every record retried it.
            let sweep_rate = prices.sol_usd(std::time::Duration::from_secs(300));

            // NO ABORT. This used to stop the sweep after 8 consecutive
            // failures, from when pricing was an HTTP quote and a refusing
            // provider would refuse the next 119 too.
            //
            // Pricing now reads the in-process stream index: there is no
            // endpoint to hammer, and "unpriced" is not a failure — it is the
            // normal state of a token nobody has traded in the last hour.
            //
            // Aborting on it was actively harmful. The batch is sorted
            // NEWEST-FIRST, and brand-new tokens are exactly the ones with no
            // observations yet, so a cluster of them at the top ended the sweep
            // before it reached the older, actively-traded calls below. A token
            // at 273x stopped being re-priced for hours while the log blamed
            // "the quote endpoint", which was not even in the code path.
            // Pricing is now free (it reads the in-process index), but the
            // identity/decimals backfills still hit the RPC. With a fast sweep
            // interval an unbounded backfill would hammer it, so only a few
            // records are repaired per sweep — they converge within minutes.
            const MAX_BACKFILLS_PER_SWEEP: usize = 8;
            let mut backfills = 0usize;

            for rec in batch {
                if *shutdown.borrow() {
                    return;
                }
                // Backfill an identity that was unresolvable at call time.
                // Metadata can appear seconds AFTER the mint, and older records
                // predate the Token-2022 lookup entirely, so a call announced
                // as a bare mint gets its ticker here rather than never.
                let name_is_really_the_mint =
                    rec.name == crate::conviction::short_mint(&rec.mint);
                let may_backfill = backfills < MAX_BACKFILLS_PER_SWEEP;
                if may_backfill && (rec.symbol.is_empty() || name_is_really_the_mint) {
                    backfills += 1;
                    if let Some(m) = rpc.token_meta(&rec.mint).await {
                        let name =
                            crate::wallets::sanitize_token_label(&m.name).unwrap_or_default();
                        let symbol =
                            crate::wallets::sanitize_token_label(&m.symbol).unwrap_or_default();
                        if !name.is_empty() || !symbol.is_empty() {
                            store.set_identity(&rec.mint, &name, &symbol);
                            named += 1;
                        }
                    }
                }
                if let (Some(rate), true) = (sweep_rate, rec.sol_usd_at_signal.is_none()) {
                    store.set_sol_rate(&rec.mint, rate);
                }
                if rec.decimals == 0 && backfills < MAX_BACKFILLS_PER_SWEEP {
                    backfills += 1;
                    if let Some(info) = rpc.mint_info(&rec.mint).await {
                        if info.decimals > 0 {
                            store.set_decimals(&rec.mint, info.decimals as u32);
                        }
                    }
                }

                // Straight from the stream: no request, no rate limit, and a
                // real fill rather than a router's quote.
                // A zero is not a price: `tokens_ui` returns 0 when decimals
                // are unknown, and multiplying through would report a real
                // token as worthless rather than as unpriceable.
                let quoted = prices
                    .price_sol(&rec.mint, max_price_age)
                    .map(|p| p.price_sol * tokens_ui(rec.reference_tokens_raw, rec.decimals))
                    .filter(|v| *v > 0.0);

                // Pacing is applied on EVERY iteration, including failures.
                // Putting it after an early `continue` meant a failing endpoint
                // got hammered with no delay at all: 120 quotes in one second,
                // which is a feedback loop that sustains its own rate limit.
                if let Some(sol_now) = quoted {
                    priced += 1;
                    if rec.reference_sol > 0.0 {
                        let multiple = sol_now / rec.reference_sol;
                        best = best.max(multiple);
                        store.mark_checked(&rec.mint, multiple, now);

                        if let Some(rung) = next_rung(
                            multiple,
                            rec.last_reported_multiple,
                            &cfg.update_multiples,
                        ) {
                            // MEASURED, not scaled: `fdv_at_signal * multiple`
                            // assumes constant supply, which is wrong for
                            // exactly the tokens with a live mint authority.
                            let fdv_now = live_fdv_usd(&rpc, &rec, sol_now, &prices)
                                .await
                                .or_else(|| rec.fdv_usd_at_signal.map(|f| f * multiple));

                            tracing::info!(
                                mint = %rec.mint,
                                multiple = format!("{multiple:.2}"),
                                rung,
                                "conviction signal update"
                            );
                            let body = render_update(
                                &rec,
                                multiple,
                                fdv_now,
                                now,
                                cfg.display_utc_offset_hours,
                            );
                            alerter.send_html_returning_id(body, rec.message_id).await;
                            store.mark_reported(&rec.mint, rung);
                        }
                    }
                } else {
                    unpriced += 1;
                    tracing::debug!(mint = %rec.mint, "no recent fills — cannot price yet");
                }

                // No sleep here: `jupiter::throttle` spaces every request
                // process-wide, so a second sleep would only slow the sweep
                // without bounding anything the throttle does not already.
            }

            // Flush AFTER the sweep so observed multiples and any backfilled
            // tickers survive a restart.
            store.persist_all();

            tracing::info!(
                priced,
                unpriced,
                named,
                best = format!("{best:.2}x"),
                took_secs = started.elapsed().as_secs(),
                "re-pricing sweep complete"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const LADDER: &[f64] = &[2.0, 3.0, 5.0, 10.0, 25.0, 50.0, 100.0];

    fn rec(mint: &str) -> SignalRecord {
        SignalRecord {
            mint: mint.into(),
            name: "Credible".into(),
            symbol: "CRED".into(),
            first_seen_utc: Utc::now(),
            message_id: Some(42),
            reference_sol: 1.0,
            reference_tokens_raw: 1_000_000,
            decimals: 6,
            fdv_usd_at_signal: Some(41_200.0),
            supply: Some(1_000_000_000.0),
            wallets: vec!["W1".into(), "W2".into()],
            total_sol: 3.5,
            sol_usd_at_signal: Some(75.0),
            total_fees_sol: 0.042,
            last_multiple: 1.0,
            peak_multiple: 1.0,
            last_checked_utc: None,
            last_reported_multiple: 1.0,
        }
    }

    #[test]
    fn no_rung_below_the_first_threshold() {
        assert_eq!(next_rung(1.9, 1.0, LADDER), None);
    }

    #[test]
    fn crossing_the_first_rung_reports_it() {
        assert_eq!(next_rung(2.1, 1.0, LADDER), Some(2.0));
    }

    /// A token that gaps straight to 12x announces 12x's rung, not a sequence
    /// of four messages climbing the ladder.
    #[test]
    fn a_gap_reports_the_highest_cleared_rung_only() {
        assert_eq!(next_rung(12.0, 1.0, LADDER), Some(10.0));
    }

    /// The anti-spam rule: a rung already announced never fires again, so a
    /// token hovering at 2.05x does not re-post on every check.
    #[test]
    fn an_already_reported_rung_does_not_refire() {
        assert_eq!(next_rung(2.05, 2.0, LADDER), None);
        assert_eq!(next_rung(2.9, 2.0, LADDER), None);
        assert_eq!(next_rung(3.1, 2.0, LADDER), Some(3.0));
    }

    #[test]
    fn a_fall_reports_nothing() {
        assert_eq!(next_rung(0.4, 2.0, LADDER), None);
        assert_eq!(next_rung(1.0, 2.0, LADDER), None);
    }

    #[test]
    fn nonsense_multiples_are_rejected() {
        assert_eq!(next_rung(f64::NAN, 1.0, LADDER), None);
        // Infinity can only come from a broken quote (or a zero denominator,
        // which the caller already guards). Announcing "∞x" would be worse
        // than staying quiet.
        assert_eq!(next_rung(f64::INFINITY, 1.0, LADDER), None);
        assert_eq!(next_rung(-3.0, 1.0, LADDER), None);
        assert_eq!(next_rung(2.0, 1.0, &[]), None);
    }

    /// The behaviour the operator actually cares about: a token climbing over
    /// time produces one update per rung, in order, with none repeated and none
    /// skipped-then-missed. Simulated against the SHIPPING ladder rather than a
    /// test-local one, so a config change that breaks the sequence fails here.
    #[test]
    fn a_climbing_token_fires_each_rung_once_in_order() {
        let ladder = crate::config::TrackedConfig::default().update_multiples;
        // A plausible run: drifts up, crosses 1.5x, stalls, then legs up.
        let path = [
            1.02, 1.31, 1.49, // nothing yet
            1.52, 1.61, 1.88, // 1.5x
            2.04, 2.31, // 2x
            2.55, // 2.5x
            2.9, 3.4, // 3x
            3.9, 4.2,  // 4x
            12.0, // gaps past 5, 7.5, 10 -> reports 10x only
        ];

        let mut reported = 1.0;
        let mut fired = Vec::new();
        for m in path {
            if let Some(rung) = next_rung(m, reported, &ladder) {
                fired.push(rung);
                reported = rung;
            }
        }

        assert_eq!(
            fired,
            vec![1.5, 2.0, 2.5, 3.0, 4.0, 10.0],
            "each rung once, in order; a gap reports only the highest cleared"
        );
    }

    /// A token that peaks and falls back must not re-fire rungs on the way
    /// down, nor when it climbs back through ground it already reported.
    /// A fixed ladder would go silent exactly when the updates matter most:
    /// the best outcome the bot can produce would also be the one it stops
    /// reporting.
    #[test]
    fn the_ladder_continues_past_its_last_configured_rung() {
        let l = crate::config::TrackedConfig::default().update_multiples;
        assert_eq!(next_rung(250.0, 100.0, &l), Some(250.0));
        assert_eq!(next_rung(600.0, 250.0, &l), Some(500.0));
        assert_eq!(next_rung(1_500.0, 500.0, &l), Some(1000.0));
        assert_eq!(next_rung(10_000.0, 100.0, &l), Some(10_000.0));
    }

    /// A moonshot must not produce a message per rung it blew through.
    #[test]
    fn a_gap_far_past_the_ladder_reports_once() {
        let l = crate::config::TrackedConfig::default().update_multiples;
        let mut reported = 1.0;
        let mut fired = Vec::new();
        for m in [3.0, 900.0] {
            if let Some(r) = next_rung(m, reported, &l) {
                fired.push(r);
                reported = r;
            }
        }
        assert_eq!(fired, vec![3.0, 500.0], "one update per observation, not per rung");
    }

    /// Generated rungs must ascend and stay finite, or the loop that walks
    /// them could spin.
    #[test]
    fn generated_rungs_ascend_and_terminate() {
        let rungs: Vec<f64> = rungs_above(100.0).collect();
        assert!(!rungs.is_empty());
        assert_eq!(&rungs[..4], &[250.0, 500.0, 1000.0, 2500.0]);
        for w in rungs.windows(2) {
            assert!(w[1] > w[0], "must ascend: {:?}", &rungs[..8.min(rungs.len())]);
        }
        assert!(rungs.len() < 40, "must terminate, got {}", rungs.len());
        assert!(rungs.last().unwrap().is_finite());
    }

    /// An absurd multiple from a broken quote must not walk the generator
    /// forever.
    #[test]
    fn an_absurd_multiple_still_terminates() {
        let l = crate::config::TrackedConfig::default().update_multiples;
        let r = next_rung(1e18, 100.0, &l);
        assert!(r.is_some_and(|v| v.is_finite() && v <= 1e10), "got {r:?}");
    }

    #[test]
    fn a_retrace_produces_no_updates() {
        let ladder = crate::config::TrackedConfig::default().update_multiples;
        let mut reported = 1.0;
        let mut fired = 0;
        for m in [1.6, 2.1, 1.4, 0.7, 1.9, 2.05] {
            if let Some(rung) = next_rung(m, reported, &ladder) {
                fired += 1;
                reported = rung;
            }
        }
        assert_eq!(fired, 2, "only the 1.5x and 2x crossings, never a repeat");
    }

    /// Every rung in the shipping ladder must be reachable — a duplicate or an
    /// out-of-order entry would silently make one unreportable.
    #[test]
    fn shipping_ladder_is_sorted_and_unique() {
        let ladder = crate::config::TrackedConfig::default().update_multiples;
        assert!(ladder.len() >= 5);
        assert!(ladder[0] > 1.0, "a rung at or below 1x would fire on any call");
        for w in ladder.windows(2) {
            assert!(w[1] > w[0], "ladder must ascend strictly: {:?}", ladder);
        }
        // Each rung is individually reachable from a fresh signal.
        for &r in &ladder {
            assert_eq!(next_rung(r, 1.0, &ladder), Some(r), "rung {r} unreachable");
        }
    }

    #[test]
    fn store_roundtrips_through_disk() {
        let dir = std::env::temp_dir().join(format!("volens-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("signals.jsonl");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let store = SignalStore::load(&p);
        assert!(store.insert(rec("MINT_A")));
        store.mark_reported("MINT_A", 3.0);

        // A fresh load must see the RAISED rung, or a restart re-announces
        // every multiple the token already passed.
        let reloaded = SignalStore::load(&p);
        assert_eq!(reloaded.len(), 1);
        let active = reloaded.active(Utc::now(), 86_400);
        assert_eq!(active[0].last_reported_multiple, 3.0);
        let _ = std::fs::remove_file(&path);
    }

    /// Re-signalling must not re-base the entry price — that would erase a gain
    /// that already happened.
    #[test]
    fn inserting_a_tracked_mint_preserves_the_original_entry() {
        let dir = std::env::temp_dir().join(format!("volens-sig2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.jsonl");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let store = SignalStore::load(&p);
        let mut first = rec("MINT_A");
        first.reference_sol = 1.0;
        assert!(store.insert(first));

        let mut second = rec("MINT_A");
        second.reference_sol = 9.9;
        assert!(!store.insert(second), "duplicate must be refused");

        assert_eq!(store.active(Utc::now(), 86_400)[0].reference_sol, 1.0);
        let _ = std::fs::remove_file(&path);
    }

    /// The reported bug: market cap moved in updates while volume, buyer count
    /// and fees stayed frozen at the values from the original call.
    #[test]
    fn later_buys_move_volume_buyers_and_fees() {
        let dir = std::env::temp_dir().join(format!("volens-acc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("acc.jsonl");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let store = SignalStore::load(&p);
        let mut r = rec("MINT_A");
        r.total_sol = 3.5;
        r.total_fees_sol = 0.042;
        r.wallets = vec!["W1".into(), "W2".into(), "W3".into()];
        store.insert(r);

        // A fourth wallet buys after the call.
        store.add_buy("MINT_A", "W4", 2.0, 0.008);
        // …and W2 buys again: volume and fees grow, the buyer count does not.
        store.add_buy("MINT_A", "W2", 1.0, 0.004);

        let after = &store.active(Utc::now(), 86_400)[0];
        assert!((after.total_sol - 6.5).abs() < 1e-9, "volume: {}", after.total_sol);
        assert!((after.total_fees_sol - 0.054).abs() < 1e-9, "fees: {}", after.total_fees_sol);
        assert_eq!(after.wallets.len(), 4, "a repeat buyer must not raise the count");

        // And the rendered update carries the NEW figures, not the old ones.
        let out = render_update(after, 2.0, Some(80_000.0), Utc::now(), 8);
        assert!(out.contains("SM: 4"), "got:\n{out}");
        assert!(out.contains("SM Vol: $488"), "6.5 SOL x $75:\n{out}");
        assert!(out.contains("SM Fees: 0.0540 SOL"), "got:\n{out}");
        let _ = std::fs::remove_file(&path);
    }

    /// An untracked mint must not create a phantom record.
    #[test]
    fn add_buy_on_an_unknown_mint_is_a_no_op() {
        let store = SignalStore::load("/nonexistent/volens-noop.jsonl");
        store.add_buy("NEVER_CALLED", "W1", 5.0, 0.01);
        assert_eq!(store.len(), 0);
    }

    /// The restart bug: observed multiples were held only in memory, so every
    /// restart reloaded the whole book at x1.0 with no check time — which reads
    /// as "nothing has ever been re-priced".
    #[test]
    fn observed_multiples_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.jsonl");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let store = SignalStore::load(&p);
        store.insert(rec("MINT_A"));
        let at = Utc::now();
        store.mark_checked("MINT_A", 3.7, at);
        store.set_identity("MINT_A", "Cheesecoin", "CHEESE");
        store.persist_all();

        let reloaded = SignalStore::load(&p);
        let r = &reloaded.active(Utc::now(), 86_400)[0];
        assert_eq!(r.last_multiple, 3.7, "multiple must survive");
        assert!(r.last_checked_utc.is_some(), "check time must survive");
        assert_eq!(r.symbol, "CHEESE", "backfilled ticker must survive");
        let _ = std::fs::remove_file(&path);
    }

    /// The append-only log grows one line per update per signal; only the last
    /// line per mint is ever read. A flush must compact it.
    #[test]
    fn persist_all_compacts_the_log() {
        let dir = std::env::temp_dir().join(format!("volens-compact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.jsonl");
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let store = SignalStore::load(&p);
        store.insert(rec("MINT_A"));
        for m in [1.5, 2.0, 2.5, 3.0] {
            store.mark_reported("MINT_A", m);
        }
        let before = std::fs::read_to_string(&p).unwrap().lines().count();
        assert!(before > 1, "appends accumulate");

        store.persist_all();
        let after = std::fs::read_to_string(&p).unwrap().lines().count();
        assert_eq!(after, 1, "one line per mint after a flush");
        let _ = std::fs::remove_file(&path);
    }

    /// Ties must not reshuffle between calls — a list that reorders itself
    /// looks like the data changed when nothing did.
    #[test]
    fn ranking_is_highest_first_and_stable() {
        let store = SignalStore::load("/nonexistent/volens-rank.jsonl");
        let now = Utc::now();
        for (mint, mult, age) in [("A", 1.0, 300), ("B", 4.2, 100), ("C", 1.0, 60), ("D", 2.1, 200)] {
            let mut r = rec(mint);
            r.last_multiple = mult;
            r.first_seen_utc = now - chrono::Duration::seconds(age);
            store.lock().insert(mint.to_string(), r);
        }
        let ranked: Vec<String> = store.ranked(now, 86_400).iter().map(|r| r.mint.clone()).collect();
        assert_eq!(ranked, vec!["B", "D", "C", "A"], "multiple desc, then newest");
    }

    /// A sweep must stay bounded. Uncapped, a day's queue would take ~96
    /// minutes against a 5-minute interval and every update would land late.
    #[test]
    fn recency_order_puts_the_newest_first_so_a_cap_drops_the_oldest() {
        let store = SignalStore::load("/nonexistent/volens-cap.jsonl");
        let now = Utc::now();
        for (mint, age) in [("OLD", 20_000), ("NEW", 60), ("MID", 5_000)] {
            let mut r = rec(mint);
            r.first_seen_utc = now - chrono::Duration::seconds(age);
            store.lock().insert(mint.to_string(), r);
        }
        let order: Vec<String> = store
            .ranked_by_recency(now, 86_400)
            .iter()
            .map(|r| r.mint.clone())
            .collect();
        assert_eq!(order, vec!["NEW", "MID", "OLD"]);

        // A cap of 2 therefore keeps the two newest.
        let mut capped = store.ranked_by_recency(now, 86_400);
        capped.truncate(2);
        assert_eq!(
            capped.iter().map(|r| r.mint.as_str()).collect::<Vec<_>>(),
            vec!["NEW", "MID"]
        );
    }

    #[test]
    fn retire_drops_only_the_old() {
        let store = SignalStore::load("/nonexistent/volens-test-signals.jsonl");
        let mut old = rec("OLD");
        old.first_seen_utc = Utc::now() - chrono::Duration::seconds(7200);
        let fresh = rec("FRESH");
        store.lock().insert("OLD".into(), old);
        store.lock().insert("FRESH".into(), fresh);

        assert_eq!(store.retire(Utc::now(), 3600), 1);
        assert!(store.contains("FRESH"));
        assert!(!store.contains("OLD"));
    }

    /// The measured market cap must agree with the scaled estimate when
    /// supply has not changed — and the arithmetic must survive the decimals
    /// conversion, which previously produced $0 on records with no decimals.
    #[tokio::test]
    async fn measured_fdv_matches_the_scaled_estimate() {
        let prices = crate::prices::PriceIndex::new();
        prices.seed_sol_usd(75.0);

        let mut r = rec("MINT_A");
        r.decimals = 6;
        r.reference_tokens_raw = 1_000_000; // 1.0 token
        r.reference_sol = 0.001;            // 0.001 SOL per token
        r.supply = Some(1_000_000_000.0);
        r.fdv_usd_at_signal = Some(0.001 * 1e9 * 75.0);

        // Doubled in SOL terms.
        let sol_now = 0.002;
        let multiple = sol_now / r.reference_sol;
        let scaled = r.fdv_usd_at_signal.map(|f| f * multiple);

        let rpc = crate::rpc::RpcClient::new(&crate::config::RpcConfig {
            url: String::new(),
            commitment: "confirmed".into(),
            initial_delay_ms: 0,
            retries: 1,
            retry_delay_ms: 1,
            ws_url: String::new(),
        });
        // With no RPC the supply read fails, so the measured path declines
        // rather than inventing a figure — and the caller falls back.
        let measured = live_fdv_usd(&rpc, &r, sol_now, &prices).await;
        assert!(measured.is_none(), "no supply read must not fabricate an FDV");
        assert_eq!(scaled, Some(150_000_000.0));
    }

    /// Unknown decimals must make the price unavailable, never wrong. Records
    /// written before the field existed default to 0, and treating that as a
    /// real value produced $0 market caps.
    #[test]
    fn unknown_decimals_yield_no_size_rather_than_a_wrong_one() {
        assert_eq!(tokens_ui(1_000_000, 0), 0.0);
        assert_eq!(tokens_ui(0, 6), 0.0);
        assert_eq!(tokens_ui(1_000_000, 6), 1.0);
        assert_eq!(tokens_ui(49_524_237_099_818, 6), 49_524_237.099818);
    }

    /// Live proof of the pricing half: re-quote every signal actually recorded
    /// on this machine and report the multiple. The rung logic is unit-tested
    /// above; this is the part that can only be verified against a real router.
    ///
    ///   cargo test -- --ignored --nocapture live_reprice_recorded_signals
    #[ignore = "hits the Jupiter API; needs recorded signals"]
    #[tokio::test]
    async fn live_reprice_recorded_signals() {
        let path = std::env::var("SIGNALS_PATH")
            .unwrap_or_else(|_| "conviction_signals.jsonl".to_string());
        let store = SignalStore::load(&path);
        let recs = store.active(Utc::now(), 7 * 86_400);
        if recs.is_empty() {
            println!("no recorded signals at {path}; nothing to re-price");
            return;
        }

        let cfg = crate::config::TrackedConfig::default();
        let jup = crate::jupiter::Jupiter::new(&cfg.jupiter_base_url);
        let mut priced = 0;
        let mut routeless = 0;

        for rec in recs.iter().take(10) {
            let ticker = if rec.symbol.is_empty() { &rec.mint[..8] } else { &rec.symbol };
            match quote_sol_value(&jup, &rec.mint, rec.reference_tokens_raw).await {
                Some(now_sol) if rec.reference_sol > 0.0 => {
                    let m = now_sol / rec.reference_sol;
                    let rung = next_rung(m, rec.last_reported_multiple, &cfg.update_multiples);
                    println!(
                        "{ticker:>10}  paid {:.4} SOL -> worth {now_sol:.4} SOL  = {}  rung={rung:?}",
                        rec.reference_sol,
                        format_multiple(m)
                    );
                    priced += 1;
                }
                _ => {
                    // The normal shape of a rug: no route out.
                    println!("{ticker:>10}  no route (unsellable or dead)");
                    routeless += 1;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        }

        println!("\npriced {priced}, routeless {routeless}");
        assert!(priced + routeless > 0);
    }

    #[test]
    fn update_renders_both_fdv_ends() {
        let out = render_update(&rec("M"), 2.4, Some(98_900.0), Utc::now(), 8);
        println!("\n--- update ---\n{out}\n");

        assert!(out.contains("🚀 <b>$CRED x2.4</b> 🚀"), "got:\n{out}");
        assert!(out.contains("💵 MC: $41.2K → $98.9K in"), "got:\n{out}");
        assert!(out.contains("SM Vol: $262"), "got:\n{out}");
        assert!(out.contains("SM: 2"), "buyer count must be current:\n{out}");
        assert!(out.contains("(UTC+8)"));
    }

    /// An update replies to the original call, so the token is already
    /// identified one message up. Repeating the mint and buyer list is the
    /// spam this format removes.
    #[test]
    fn update_is_short_and_does_not_repeat_the_call() {
        let out = render_update(&rec("M"), 2.4, Some(98_900.0), Utc::now(), 8);
        assert!(!out.contains("MINT"), "mint repeated:\n{out}");
        assert!(!out.contains("W1"), "wallets repeated:\n{out}");
        assert!(!out.contains("First signal"), "redundant in a reply:\n{out}");
        assert!(out.lines().count() <= 7, "too many lines:\n{out}");
    }

    /// Elapsed time is coarse on purpose: "in 2m" is the useful fact, and
    /// "2m14s" implies a precision the check interval does not have.
    #[test]
    fn elapsed_is_coarse() {
        assert_eq!(format_elapsed(45), "45s");
        assert_eq!(format_elapsed(134), "2m");
        assert_eq!(format_elapsed(3600), "1h");
        assert_eq!(format_elapsed(11_520), "3h12m");
        assert_eq!(format_elapsed(-5), "-5s");
    }

    /// The reported bug: an update three hours later said "MC: unavailable"
    /// because the SOL price happened to be missing in the single instant the
    /// call was made. A known current figure must still be shown.
    #[test]
    fn a_missing_signal_time_mc_still_shows_the_current_one() {
        let mut r = rec("M");
        r.fdv_usd_at_signal = None;
        let out = render_update(&r, 3.5, Some(88_000.0), Utc::now(), 8);
        assert!(out.contains("MC now: $88.0K"), "got:\n{out}");
        assert!(!out.contains("unavailable"), "half the data is not none of it:\n{out}");
    }

    /// Only when BOTH are unknown does the line reduce to the multiple.
    #[test]
    fn with_no_mc_at_all_the_line_reduces_to_the_multiple() {
        let mut r = rec("M");
        r.fdv_usd_at_signal = None;
        let out = render_update(&r, 3.5, None, Utc::now(), 8);
        assert!(out.contains("💵 x3.5 in"), "got:\n{out}");
        assert!(!out.contains("MC"), "got:\n{out}");
    }

    /// `$HukaK2…myT8WJ` — a mint wearing a ticker sigil, because the name field
    /// had been poisoned with the shortened mint.
    #[test]
    fn a_mint_never_wears_a_ticker_sigil() {
        let mut r = rec("HukaK2eHhbTyiuUwuKMntjPJP4aGdD4VwiExsNmyT8WJ");
        r.symbol = String::new();
        r.name = String::new();
        let out = render_update(&r, 32.5, None, Utc::now(), 8);
        assert!(!out.contains("$HukaK2"), "got:\n{out}");
        assert!(out.contains("HukaK2"), "the mint should still identify it:\n{out}");

        // A name is not a ticker either.
        r.name = "Grok Bot".into();
        let out = render_update(&r, 32.5, None, Utc::now(), 8);
        assert!(out.contains("Grok Bot"), "got:\n{out}");
        assert!(!out.contains("$Grok"), "a name must not get a $ sigil:\n{out}");
    }

    /// Recovering the rate must reconstruct the signal-time market cap too,
    /// or the update still cannot show a "then -> now" move.
    #[test]
    fn recovering_the_rate_reconstructs_the_signal_time_mc() {
        let store = SignalStore::load("/nonexistent/volens-rate.jsonl");
        let mut r = rec("MINT_A");
        r.sol_usd_at_signal = None;
        r.fdv_usd_at_signal = None;
        r.supply = Some(1_000_000_000.0);
        r.decimals = 6;
        r.reference_tokens_raw = 1_000_000;   // 1.0 token
        r.reference_sol = 0.001;              // 0.001 SOL per token
        store.lock().insert("MINT_A".into(), r);

        store.set_sol_rate("MINT_A", 75.0);
        let back = store.active(Utc::now(), 86_400).pop().unwrap();
        assert_eq!(back.sol_usd_at_signal, Some(75.0));
        // 0.001 SOL/token x 1e9 supply x $75 = $75,000,000
        assert_eq!(back.fdv_usd_at_signal, Some(75_000_000.0));
    }

    /// A rate that arrived on time must never be overwritten by a later one.
    #[test]
    fn an_existing_rate_is_not_replaced() {
        let store = SignalStore::load("/nonexistent/volens-rate2.jsonl");
        let mut r = rec("MINT_A");
        r.sol_usd_at_signal = Some(74.0);
        store.lock().insert("MINT_A".into(), r);
        store.set_sol_rate("MINT_A", 99.0);
        assert_eq!(store.active(Utc::now(), 86_400)[0].sol_usd_at_signal, Some(74.0));
    }

    /// A known "then" with an unknown "now" must not render as a collapse:
    /// no arrow, and no implied move to zero.
    #[test]
    fn a_missing_current_fdv_is_stated_not_implied() {
        let out = render_update(&rec("M"), 2.4, None, Utc::now(), 8);
        assert!(out.contains("MC at signal: $41.2K"), "got:\n{out}");
        assert!(!out.contains("→"), "no arrow without both ends:\n{out}");
        assert!(!out.contains("$0"), "must not imply a collapse:\n{out}");
    }

    /// A performance figure must never flatter itself. Rounding turned 99.7
    /// into "x100" — claiming a milestone the token had not reached.
    #[test]
    fn multiples_are_truncated_never_rounded_up() {
        assert_eq!(format_multiple(2.44), "x2.4");
        assert_eq!(format_multiple(2.49), "x2.4", "must not round to 2.5");
        assert_eq!(format_multiple(12.6), "x12.6", "real value, not x13");
        assert_eq!(format_multiple(99.7), "x99.7", "must not claim x100");
        assert_eq!(format_multiple(3.999), "x3.9");
        assert_eq!(format_multiple(900.0), "x900");
        assert_eq!(format_multiple(1234.9), "x1234");
    }

    #[test]
    fn nonsense_multiples_render_safely() {
        assert_eq!(format_multiple(f64::NAN), "x0");
        assert_eq!(format_multiple(-2.0), "x0");
        assert_eq!(format_multiple(0.0), "x0");
    }

    /// The displayed value must never exceed the measured one.
    #[test]
    fn displayed_never_exceeds_measured() {
        for m in [1.05, 1.99, 2.349, 9.99, 10.04, 49.95, 99.99, 100.9, 5000.7] {
            let shown: f64 = format_multiple(m).trim_start_matches('x').parse().unwrap();
            assert!(shown <= m, "displayed {shown} > measured {m}");
        }
    }
}

