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
    /// FDV in USD at announce time, when it could be computed.
    #[serde(default)]
    pub fdv_usd_at_signal: Option<f64>,
    #[serde(default)]
    pub supply: Option<f64>,
    pub wallets: Vec<String>,
    pub total_sol: f64,
    /// Smart-money volume in USD at announce time. Stored rather than
    /// recomputed: an update converting with a LATER SOL/USD rate would show a
    /// different "Vol" for the same buys, which reads as the number moving when
    /// only the yardstick did.
    #[serde(default)]
    pub total_usd: Option<f64>,
    /// Fees paid across every tracked buy of this token, including buys that
    /// arrived AFTER the call. Grows over the tracking window, which is what
    /// makes it worth repeating in an update.
    #[serde(default)]
    pub total_fees_sol: f64,
    /// Highest ladder rung already announced. Starts at 1.0 (nothing reported).
    #[serde(default = "one")]
    pub last_reported_multiple: f64,
}

fn one() -> f64 {
    1.0
}

impl SignalRecord {
    /// Age in seconds, used to retire signals from tracking.
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

    /// Fold a later buy's fees into an already-announced token.
    ///
    /// Not persisted per call: this fires on every tracked buy, and appending a
    /// JSONL line each time would grow the file without bound for an active
    /// token. The next `mark_reported` writes the accumulated total, and a
    /// restart losing a partial sum costs a slightly low fee figure, not
    /// correctness.
    pub fn add_fees(&self, mint: &str, sol: f64) {
        if let Some(rec) = self.lock().get_mut(mint) {
            rec.total_fees_sol += sol;
        }
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
pub fn next_rung(multiple: f64, already_reported: f64, ladder: &[f64]) -> Option<f64> {
    if !multiple.is_finite() || multiple <= 0.0 {
        return None;
    }
    ladder
        .iter()
        .copied()
        .filter(|r| multiple >= *r && *r > already_reported)
        .fold(None, |acc: Option<f64>, r| Some(acc.map_or(r, |a: f64| a.max(r))))
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
    let ticker = if !rec.symbol.is_empty() {
        format!("${}", rec.symbol)
    } else if !rec.name.is_empty() {
        format!("${}", rec.name)
    } else {
        crate::conviction::short_mint(&rec.mint)
    };

    let mut s = format!("🚀 <b>{ticker} {}</b> 🚀\n\n", format_multiple(multiple));

    // Only claim a move when BOTH ends are known. One known side and one blank
    // reads as a collapse to zero.
    match (rec.fdv_usd_at_signal, current_fdv_usd) {
        (Some(then), Some(now_mc)) => {
            s.push_str(&format!(
                "💵 MC: {} → {} in {}\n",
                crate::conviction::format_usd(then),
                crate::conviction::format_usd(now_mc),
                format_elapsed((now - rec.first_seen_utc).num_seconds().max(0))
            ));
        }
        _ => s.push_str(&format!(
            "💵 MC: unavailable — {} in {}\n",
            format_multiple(multiple),
            format_elapsed((now - rec.first_seen_utc).num_seconds().max(0))
        )),
    }

    if let Some(vol) = rec.total_usd {
        s.push_str(&format!("Vol: {}\n", crate::conviction::format_usd(vol)));
    }
    // Includes buys that landed AFTER the call — the token kept being bought
    // even though it stopped being announced, so this is a live number rather
    // than a copy of the one in the original message.
    if rec.total_fees_sol > 0.0 {
        s.push_str(&format!(
            "Fees: {}\n",
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

/// `2.4x`, `12x` — drop the decimal once it stops carrying information.
fn format_multiple(m: f64) -> String {
    if m >= 10.0 {
        format!("x{m:.0}")
    } else {
        format!("x{m:.1}")
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
    cfg: crate::config::TrackedConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let jup = crate::jupiter::Jupiter::new(&cfg.jupiter_base_url);
        let interval = std::time::Duration::from_secs(cfg.update_check_secs.max(30));
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
            if retired > 0 {
                tracing::debug!(retired, "retired signals past tracking window");
            }

            for rec in store.active(now, max_age) {
                if *shutdown.borrow() {
                    return;
                }

                let Some(sol_now) = quote_sol_value(&jup, &rec.mint, rec.reference_tokens_raw).await
                else {
                    tracing::debug!(mint = %rec.mint, "no route; skipping update");
                    continue;
                };
                if rec.reference_sol <= 0.0 {
                    continue;
                }

                let multiple = sol_now / rec.reference_sol;
                let Some(rung) = next_rung(multiple, rec.last_reported_multiple, &cfg.update_multiples)
                else {
                    continue;
                };

                // FDV now scales with the multiple by construction: same token
                // quantity, same supply, so the ratio carries straight through.
                // Deriving it this way avoids a second supply read that could
                // disagree with the one taken at signal time.
                let fdv_now = rec.fdv_usd_at_signal.map(|f| f * multiple);

                tracing::info!(
                    mint = %rec.mint,
                    multiple = format!("{multiple:.2}"),
                    rung,
                    "conviction signal update"
                );
                let body = render_update(&rec, multiple, fdv_now, now, cfg.display_utc_offset_hours);
                alerter
                    .send_html_returning_id(body, rec.message_id)
                    .await;
                store.mark_reported(&rec.mint, rung);

                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }        }
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
            fdv_usd_at_signal: Some(41_200.0),
            supply: Some(1_000_000_000.0),
            wallets: vec!["W1".into(), "W2".into()],
            total_sol: 3.5,
            total_usd: Some(262.5),
            total_fees_sol: 0.042,
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

    #[test]
    fn update_renders_both_fdv_ends() {
        let out = render_update(&rec("M"), 2.4, Some(98_900.0), Utc::now(), 8);
        println!("\n--- update ---\n{out}\n");

        assert!(out.contains("🚀 <b>$CRED x2.4</b> 🚀"), "got:\n{out}");
        assert!(out.contains("💵 MC: $41.2K → $98.9K in"), "got:\n{out}");
        assert!(out.contains("Vol: $262"), "got:\n{out}");
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
        assert!(out.lines().count() <= 6, "too many lines:\n{out}");
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

    /// A known "then" with an unknown "now" must not render as a collapse.
    #[test]
    fn a_missing_current_fdv_is_stated_not_implied() {
        let out = render_update(&rec("M"), 2.4, None, Utc::now(), 8);
        assert!(out.contains("MC: unavailable"), "got:\n{out}");
        assert!(!out.contains("→"), "no arrow without both ends:\n{out}");
    }

    #[test]
    fn large_multiples_drop_the_decimal() {
        assert_eq!(format_multiple(2.44), "x2.4");
        assert_eq!(format_multiple(12.6), "x13");
    }
}
