//! Outcome sampling: what happened to every token a tracked wallet bought.
//!
//! # Why this exists separately from [`crate::signals`]
//!
//! `signals` tracks tokens that reached a CALL — three wallets converging. That
//! is a biased sample by construction: it can only ever tell you how the
//! consensus performed, never whether an individual wallet's solo buys were
//! worth following. Scoring 700 wallets needs the outcome of *every* buy,
//! including the ones nobody else touched.
//!
//! # Why it must be collected forward
//!
//! Price history is not recoverable after the fact from anything we hold. A
//! token that ran 5x in twenty minutes and died looks identical, a day later,
//! to one that never moved. Every hour this is not running is an hour of
//! unscoreable history.
//!
//! # What is recorded
//!
//! For each distinct token, at each configured horizon: what the FIRST buyer's
//! token quantity is worth then, as a multiple of what they paid. Using a real
//! executed fill as the basis means no mid-price and no decimals arithmetic —
//! the same approach `signals` uses, for the same reasons.
//!
//! A token that cannot be routed is recorded as `routed: false`, not skipped.
//! Unsellable IS the outcome, and it is the one that matters most for scoring:
//! a wallet whose buys routinely stop routing is the wallet to drop.
//!
//! # Resolution
//!
//! `peak` is the maximum across SAMPLED points, not a true high-water mark. A
//! spike between two samples is invisible. Horizons are configurable for
//! exactly this reason — memecoins do most of their moving early, so adding
//! shorter horizons buys resolution where it matters.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// A token awaiting its remaining samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingToken {
    pub mint: String,
    /// When the first tracked wallet bought it — the clock for every horizon.
    pub first_buy_utc: DateTime<Utc>,
    /// Reference fill: this many raw tokens cost this much SOL.
    pub reference_tokens_raw: u64,
    pub reference_sol: f64,
    #[serde(default)]
    pub decimals: u32,
    /// Wallet that got there first, so scoring can credit discovery.
    #[serde(default)]
    pub first_wallet: String,
    /// Horizons already sampled, in seconds.
    #[serde(default)]
    pub sampled: Vec<u64>,
}

impl PendingToken {
    /// The next horizon that is due, if any.
    fn due(&self, now: DateTime<Utc>, horizons: &[u64]) -> Option<u64> {
        let age = (now - self.first_buy_utc).num_seconds();
        if age < 0 {
            return None;
        }
        horizons
            .iter()
            .copied()
            .filter(|h| !self.sampled.contains(h) && age >= *h as i64)
            .min()
    }

    fn finished(&self, horizons: &[u64]) -> bool {
        horizons.iter().all(|h| self.sampled.contains(h))
    }
}

/// One observation, appended to the outcomes log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutcomeSample {
    pub mint: String,
    pub horizon_secs: u64,
    pub at: DateTime<Utc>,
    pub first_buy_utc: DateTime<Utc>,
    pub first_wallet: String,
    /// SOL the reference quantity fetches at this horizon. 0 when unroutable.
    pub sol_value: f64,
    pub reference_sol: f64,
    /// `sol_value / reference_sol`. 0 when unroutable.
    pub multiple: f64,
    /// False = no route out. Unsellable is an outcome, not a missing datapoint.
    pub routed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fdv_usd: Option<f64>,
}

/// Pending tokens, persisted so a 24-hour horizon survives a restart.
pub struct OutcomeStore {
    pending_path: String,
    samples_path: String,
    pending: Mutex<HashMap<String, PendingToken>>,
}

impl OutcomeStore {
    pub fn load(pending_path: &str, samples_path: &str) -> Self {
        let mut pending = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(pending_path) {
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(p) = serde_json::from_str::<PendingToken>(line) {
                    pending.insert(p.mint.clone(), p);
                }
            }
        }
        Self {
            pending_path: pending_path.to_string(),
            samples_path: samples_path.to_string(),
            pending: Mutex::new(pending),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingToken>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Register a token on its FIRST tracked buy.
    ///
    /// Later buys never rebase the reference: the question this data answers is
    /// "what happened after smart money first showed up", and moving the basis
    /// each time a new wallet bought would quietly erase the early move.
    pub fn register(&self, token: PendingToken) -> bool {
        let mut map = self.lock();
        if map.contains_key(&token.mint) {
            return false;
        }
        map.insert(token.mint.clone(), token);
        true
    }

    /// Tokens with a horizon due now, paired with that horizon.
    pub fn due(&self, now: DateTime<Utc>, horizons: &[u64]) -> Vec<(PendingToken, u64)> {
        self.lock()
            .values()
            .filter_map(|p| p.due(now, horizons).map(|h| (p.clone(), h)))
            .collect()
    }

    /// Mark a horizon sampled, and drop the token once all are done.
    pub fn mark_sampled(&self, mint: &str, horizon: u64, horizons: &[u64]) {
        let mut map = self.lock();
        let Some(p) = map.get_mut(mint) else { return };
        if !p.sampled.contains(&horizon) {
            p.sampled.push(horizon);
        }
        if p.finished(horizons) {
            map.remove(mint);
        }
    }

    /// Drop tokens whose last horizon has long passed but never sampled —
    /// otherwise a token registered while the sampler was down would sit in the
    /// queue forever.
    pub fn expire(&self, now: DateTime<Utc>, horizons: &[u64]) -> usize {
        let longest = horizons.iter().copied().max().unwrap_or(86_400) as i64;
        let grace = longest * 2;
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, p| (now - p.first_buy_utc).num_seconds() < grace);
        before - map.len()
    }

    pub fn append_sample(&self, s: &OutcomeSample) {
        if let Err(e) = self.append_sample_inner(s) {
            tracing::warn!(error = %e, path = %self.samples_path, "failed to log outcome");
        }
    }

    fn append_sample_inner(&self, s: &OutcomeSample) -> anyhow::Result<()> {
        use std::io::Write;
        ensure_parent(&self.samples_path);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.samples_path)?;
        writeln!(f, "{}", serde_json::to_string(s)?)?;
        Ok(())
    }

    /// Persist the pending queue. Write-then-rename: a crash mid-write must not
    /// lose tokens that are hours into a 24-hour horizon.
    pub fn persist_pending(&self) {
        if let Err(e) = self.persist_pending_inner() {
            tracing::warn!(error = %e, path = %self.pending_path, "failed to persist pending");
        }
    }

    fn persist_pending_inner(&self) -> anyhow::Result<()> {
        use std::io::Write;
        let snapshot: Vec<PendingToken> = self.lock().values().cloned().collect();
        ensure_parent(&self.pending_path);
        let tmp = format!("{}.tmp", self.pending_path);
        {
            let mut f = std::fs::File::create(&tmp)?;
            for p in &snapshot {
                writeln!(f, "{}", serde_json::to_string(p)?)?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.pending_path)?;
        Ok(())
    }
}

fn ensure_parent(path: &str) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
}

/// Poll for due horizons and record outcomes.
///
/// Runs on its own task, independent of the conviction tracker: a token bought
/// by ONE wallet is sampled here and never appears there.
pub fn spawn_sampler(
    store: std::sync::Arc<OutcomeStore>,
    rpc: std::sync::Arc<crate::rpc::RpcClient>,
    prices: std::sync::Arc<crate::prices::PriceIndex>,
    cfg: crate::config::TrackedConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let tick = std::time::Duration::from_secs(cfg.sample_check_secs.max(30));
        let horizons = cfg.outcome_horizons_secs.clone();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(tick) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                    continue;
                }
            }

            let now = Utc::now();
            let expired = store.expire(now, &horizons);
            let batch = store.due(now, &horizons);
            if batch.is_empty() {
                if expired > 0 {
                    store.persist_pending();
                }
                continue;
            }

            let started = std::time::Instant::now();
            let (mut routed, mut dead) = (0usize, 0usize);
            // A run of failures means the quote endpoint is refusing us, not
            // that every token rugged at once. Stop rather than spend the whole
            // batch on it — and, critically, do not mark those horizons
            // sampled, or a provider outage would be recorded as a rug.
            const ABORT_AFTER: usize = 8;
            let mut consecutive_fail = 0usize;

            for (token, horizon) in batch {
                if *shutdown.borrow() {
                    return;
                }
                if consecutive_fail >= ABORT_AFTER {
                    tracing::warn!(
                        consecutive_fail,
                        "aborting outcome sweep: quote endpoint failing repeatedly"
                    );
                    break;
                }

                // From the stream. A token with no trade inside the window is
                // not priceable — and "nobody is trading it" is exactly the
                // outcome scoring wants to record.
                let sol_value = prices
                    .price_sol(&token.mint, std::time::Duration::from_secs(3600))
                    .map(|p| {
                        p.price_sol
                            * crate::signals::tokens_ui(
                                token.reference_tokens_raw,
                                token.decimals,
                            )
                    })
                    .filter(|v| *v > 0.0);

                let (value, ok) = match sol_value {
                    Some(v) => {
                        consecutive_fail = 0;
                        routed += 1;
                        (v, true)
                    }
                    // Unsellable IS the outcome — recorded, never skipped.
                    None => {
                        consecutive_fail += 1;
                        dead += 1;
                        (0.0, false)
                    }
                };

                let multiple = if token.reference_sol > 0.0 {
                    value / token.reference_sol
                } else {
                    0.0
                };

                let fdv_usd = if ok {
                    live_fdv(&rpc, &token, value, &prices).await
                } else {
                    Some(0.0)
                };

                store.append_sample(&OutcomeSample {
                    mint: token.mint.clone(),
                    horizon_secs: horizon,
                    at: now,
                    first_buy_utc: token.first_buy_utc,
                    first_wallet: token.first_wallet.clone(),
                    sol_value: value,
                    reference_sol: token.reference_sol,
                    multiple,
                    routed: ok,
                    fdv_usd,
                });
                store.mark_sampled(&token.mint, horizon, &horizons);

                // Spacing is handled process-wide by `jupiter::throttle`,
                // which the sampler shares with the re-pricing sweep.
            }

            store.persist_pending();
            tracing::info!(
                routed,
                unsellable = dead,
                expired,
                pending = store.len(),
                took_secs = started.elapsed().as_secs(),
                "outcome samples recorded"
            );
        }
    });
}

/// FDV in USD at sample time, when supply and rate are both readable.
async fn live_fdv(
    rpc: &crate::rpc::RpcClient,
    token: &PendingToken,
    sol_value: f64,
    prices: &crate::prices::PriceIndex,
) -> Option<f64> {
    if token.decimals == 0 || token.reference_tokens_raw == 0 {
        return None;
    }
    let supply = rpc.token_supply(&token.mint).await?;
    if supply <= 0.0 {
        return None;
    }
    let tokens_ui = token.reference_tokens_raw as f64 / 10f64.powi(token.decimals as i32);
    if tokens_ui <= 0.0 {
        return None;
    }
    let sol_usd = prices.sol_usd(std::time::Duration::from_secs(300))?;
    let fdv = (sol_value / tokens_ui) * supply * sol_usd;
    fdv.is_finite().then_some(fdv)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HORIZONS: &[u64] = &[3600, 21_600, 86_400];

    fn token(mint: &str, age_secs: i64) -> PendingToken {
        PendingToken {
            mint: mint.into(),
            first_buy_utc: Utc::now() - chrono::Duration::seconds(age_secs),
            reference_tokens_raw: 1_000_000,
            reference_sol: 1.0,
            decimals: 6,
            first_wallet: "W1".into(),
            sampled: vec![],
        }
    }

    #[test]
    fn nothing_is_due_before_the_first_horizon() {
        assert_eq!(token("M", 60).due(Utc::now(), HORIZONS), None);
        assert_eq!(token("M", 3599).due(Utc::now(), HORIZONS), None);
    }

    #[test]
    fn the_earliest_unsampled_horizon_comes_first() {
        let t = token("M", 3601);
        assert_eq!(t.due(Utc::now(), HORIZONS), Some(3600));
    }

    /// A token registered while the sampler was down is older than several
    /// horizons at once. It must take them in order, not skip to the newest,
    /// or the early datapoints are silently lost.
    #[test]
    fn a_backlogged_token_takes_horizons_in_order() {
        let mut t = token("M", 90_000);
        assert_eq!(t.due(Utc::now(), HORIZONS), Some(3600));
        t.sampled.push(3600);
        assert_eq!(t.due(Utc::now(), HORIZONS), Some(21_600));
        t.sampled.push(21_600);
        assert_eq!(t.due(Utc::now(), HORIZONS), Some(86_400));
        t.sampled.push(86_400);
        assert_eq!(t.due(Utc::now(), HORIZONS), None);
        assert!(t.finished(HORIZONS));
    }

    #[test]
    fn a_sampled_horizon_never_repeats() {
        let mut t = token("M", 100_000);
        t.sampled = vec![3600, 21_600];
        assert_eq!(t.due(Utc::now(), HORIZONS), Some(86_400));
    }

    /// The first buy is the basis. A later buyer must not rebase it, or the
    /// early move — the part worth measuring — disappears.
    #[test]
    fn registering_a_known_token_keeps_the_original_reference() {
        let store = OutcomeStore::load("/nonexistent/p.jsonl", "/nonexistent/s.jsonl");
        let mut first = token("MINT_A", 0);
        first.reference_sol = 1.0;
        assert!(store.register(first));

        let mut second = token("MINT_A", 0);
        second.reference_sol = 99.0;
        assert!(!store.register(second), "duplicate must be refused");

        let kept = store.lock().get("MINT_A").unwrap().clone();
        assert_eq!(kept.reference_sol, 1.0);
    }

    #[test]
    fn a_token_is_dropped_once_every_horizon_is_sampled() {
        let store = OutcomeStore::load("/nonexistent/p2.jsonl", "/nonexistent/s2.jsonl");
        store.register(token("MINT_A", 90_000));
        for h in HORIZONS {
            store.mark_sampled("MINT_A", *h, HORIZONS);
        }
        assert_eq!(store.len(), 0, "finished tokens must not linger");
    }

    /// Without expiry, a token registered while the sampler was down would sit
    /// in the queue forever, since its horizons can never all complete.
    #[test]
    fn long_stale_tokens_expire() {
        let store = OutcomeStore::load("/nonexistent/p3.jsonl", "/nonexistent/s3.jsonl");
        store.register(token("FRESH", 100));
        store.register(token("STALE", 86_400 * 3));
        assert_eq!(store.expire(Utc::now(), HORIZONS), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn pending_queue_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pending.jsonl").to_string_lossy().to_string();
        let s = dir.join("samples.jsonl").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let store = OutcomeStore::load(&p, &s);
        store.register(token("MINT_A", 4000));
        store.mark_sampled("MINT_A", 3600, HORIZONS);
        store.persist_pending();

        // A 24h horizon must survive a restart, or every long sample is lost.
        let reloaded = OutcomeStore::load(&p, &s);
        assert_eq!(reloaded.len(), 1);
        let t = reloaded.lock().get("MINT_A").unwrap().clone();
        assert_eq!(t.sampled, vec![3600]);
        assert_eq!(t.due(Utc::now(), HORIZONS), None, "6h not yet reached");
        let _ = std::fs::remove_file(&p);
    }

    /// Unsellable is the single most important outcome for scoring. It must be
    /// recorded as a zero, never dropped as a missing datapoint.
    #[test]
    fn an_unsellable_token_is_recorded_not_skipped() {
        let dir = std::env::temp_dir().join(format!("volens-dead-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = dir.join("samples.jsonl").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&s);

        let store = OutcomeStore::load("/nonexistent/p4.jsonl", &s);
        store.append_sample(&OutcomeSample {
            mint: "DEAD".into(),
            horizon_secs: 3600,
            at: Utc::now(),
            first_buy_utc: Utc::now(),
            first_wallet: "W1".into(),
            sol_value: 0.0,
            reference_sol: 2.0,
            multiple: 0.0,
            routed: false,
            fdv_usd: Some(0.0),
        });
        let line = std::fs::read_to_string(&s).unwrap();
        let back: OutcomeSample = serde_json::from_str(line.trim()).unwrap();
        assert!(!back.routed);
        assert_eq!(back.multiple, 0.0);
        let _ = std::fs::remove_file(&s);
    }
}
