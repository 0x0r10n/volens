//! Alpha Smart Money Mode — a second, independent buy trigger.
//!
//! # What this is
//!
//! Normal auto-buy fires on aggregate smart-money SOL volume: enough tracked
//! money moved into a token inside the window. It does not care WHICH wallets
//! moved it.
//!
//! Alpha asks the other question. It scores the tracked wallets on how their
//! past calls actually performed, promotes the ones that clear a bar, and buys
//! when one of THOSE wallets buys — on its own size, with its own exits,
//! regardless of whether the volume trigger ever fires.
//!
//! The two are additive and may both fire on the same token. That is intended:
//! they are different theses, and the overlap is the strongest case of all.
//!
//! # Where the scores come from
//!
//! Nothing new is recorded. `SignalStore` already keeps, per announced token,
//! the list of tracked wallets that bought it and the highest multiple that
//! token ever reached. Joining those two gives a per-wallet track record for
//! free, and it is the same data the leaderboard already reports, so a wallet's
//! score can always be reconciled against something the operator has seen.
//!
//! # The approximation, stated plainly
//!
//! `peak_multiple` is measured from the CALL, not from the individual wallet's
//! entry. A wallet that bought moments after the call gets credited with very
//! nearly its own result; one that bought late gets credited with more than it
//! earned. Per-wallet entry prices are not recorded, and inventing them from
//! the stream would be a guess wearing a number's clothes. The bar below is set
//! high enough that this bias cannot promote a wallet on its own — a wallet
//! still has to be present on many winners to qualify.

use crate::signals::SignalRecord;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// One resolved call: a token, the tracked wallets that bought it, and the
/// highest multiple it reached.
///
/// The unit scoring works in, and deliberately not `SignalRecord`. A signal is
/// LIVE STATE — the tracker retires it after `track_for_secs`, which is a day —
/// while a track record has to outlive the thing it was measured on. Scoring
/// read the live store directly at first, so "look back 7 days" silently meant
/// "look back over whatever is still being tracked", and every score was built
/// on a single day no matter what the lookback said.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub mint: String,
    pub wallets: Vec<String>,
    /// Highest multiple this call reached, measured from the call.
    pub peak: f64,
    /// When the call was made — what the lookback and maturity windows use.
    pub at: DateTime<Utc>,
}

impl Call {
    pub fn from_signal(r: &SignalRecord) -> Self {
        Self {
            mint: r.mint.clone(),
            wallets: r.wallets.clone(),
            peak: r.peak(),
            at: r.first_seen_utc,
        }
    }
}

/// Append-only archive of resolved calls.
///
/// Written when the tracker retires a signal, which is the moment its peak
/// stops changing and the call becomes history. This is what lets a wallet
/// accumulate a record over 30 days out of a store that only holds one.
pub struct ScoreLedger {
    path: String,
}

impl ScoreLedger {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    /// Load every archived call. A corrupt line is skipped, not fatal — a
    /// half-written final line from a crash must not blank the whole record.
    pub fn load(&self) -> Vec<Call> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        text.lines().filter_map(|l| serde_json::from_str::<Call>(l.trim()).ok()).collect()
    }

    /// Archive calls the tracker has just retired.
    pub fn append(&self, calls: &[Call]) {
        use std::io::Write;
        if calls.is_empty() || self.path.is_empty() {
            return;
        }
        let mut buf = String::new();
        for c in calls {
            // A call nobody tracked teaches nothing and would only grow the file.
            if c.wallets.is_empty() {
                continue;
            }
            if let Ok(line) = serde_json::to_string(c) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        if buf.is_empty() {
            return;
        }
        match std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(buf.as_bytes()) {
                    tracing::warn!(path = %self.path, error = %e, "could not archive resolved calls");
                }
            }
            Err(e) => {
                tracing::warn!(path = %self.path, error = %e, "could not open the score ledger")
            }
        }
    }

    /// Rewrite the file keeping only calls inside `keep_secs`.
    ///
    /// Called rarely. The ledger is the scoring history, so pruning is bounded
    /// by the lookback and nothing else — dropping a call still inside the
    /// window would silently shorten every wallet's record.
    pub fn prune(&self, now: DateTime<Utc>, keep_secs: i64) -> usize {
        let all = self.load();
        let kept: Vec<&Call> =
            all.iter().filter(|c| (now - c.at).num_seconds() <= keep_secs).collect();
        let dropped = all.len() - kept.len();
        if dropped == 0 {
            return 0;
        }
        let mut buf = String::new();
        for c in &kept {
            if let Ok(line) = serde_json::to_string(c) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        let tmp = format!("{}.tmp", self.path);
        if std::fs::write(&tmp, buf).is_ok() && std::fs::rename(&tmp, &self.path).is_ok() {
            dropped
        } else {
            0
        }
    }
}

/// Merge the archive with the calls still being tracked.
///
/// Both are needed. The archive holds everything older than the tracking
/// window; the live store holds today, which has not been archived yet and is
/// the half a wallet's recency is judged on. Keyed by mint, and where both have
/// the same call the HIGHER peak wins — the live one is still being re-priced
/// and may have moved up since it was written.
pub fn merge_calls(archived: Vec<Call>, live: &[SignalRecord]) -> Vec<Call> {
    let mut by_mint: HashMap<String, Call> = HashMap::new();
    for c in archived {
        by_mint.insert(c.mint.clone(), c);
    }
    for r in live {
        let c = Call::from_signal(r);
        by_mint
            .entry(c.mint.clone())
            .and_modify(|e| {
                if c.peak > e.peak {
                    e.peak = c.peak;
                }
            })
            .or_insert(c);
    }
    by_mint.into_values().collect()
}

/// The bar a wallet must clear to be treated as Alpha.
///
/// These are BACKEND rules, set in `config.toml` and deliberately not exposed
/// over Telegram: they decide which wallets are trusted with money, and that is
/// not a dial to nudge between trades.
#[derive(Debug, Clone)]
pub struct AlphaRules {
    /// Minimum resolved calls before a wallet can qualify at all. The guard
    /// against promoting a wallet that got lucky once.
    pub min_samples: usize,
    /// Share of its samples that must be hits, 0.0–1.0.
    ///
    /// Must be read against the BASELINE, not against intuition. Measured on
    /// the live book: 18.7% of called tokens reach 2x, but the median wallet
    /// with enough samples sits at 32.9% — because a wallet's rate is only ever
    /// measured on tokens that got CALLED, and those already had several smart
    /// wallets buying them. A bar of 35% therefore admitted half the book while
    /// looking selective. It has to clear the median by a real margin.
    pub min_hit_rate: f64,
    /// The MEDIAN peak a wallet's calls must reach.
    ///
    /// Hit rate alone cannot tell "usually right" from "occasionally lucky". A
    /// wallet on the live book scored a 44.4% hit rate with a median of 1.00x —
    /// half its calls went nowhere at all — and qualified anyway, because
    /// touching 2x on the other half was enough. This is the check that says
    /// what the TYPICAL call did, and it is the one that rejects that wallet.
    pub min_median_peak: f64,
    /// The multiple that counts as a hit.
    pub hit_multiple: f64,
    /// How far back to look for samples, in seconds.
    pub lookback_secs: i64,
    /// A wallet must have bought something inside this window to stay Alpha.
    /// A wallet that has stopped trading has stopped being evidence.
    pub recency_secs: i64,
    /// How old a call must be before it counts as a sample.
    ///
    /// Without this, a wallet's score is dragged down by tokens called minutes
    /// ago that have not had time to go anywhere — every fresh call sits near
    /// 1.0x and reads as a miss. The most ACTIVE wallets would be penalised
    /// hardest, which is precisely backwards.
    pub maturity_secs: i64,
}

impl Default for AlphaRules {
    fn default() -> Self {
        Self {
            // Raised from 8. At 8 samples a 37.5% rate is three hits, and its
            // confidence interval spans most of the range — indistinguishable
            // from chance, yet it read as a qualification.
            min_samples: 20,
            min_hit_rate: 0.51,
            min_median_peak: 1.5,
            hit_multiple: 2.0,
            lookback_secs: 30 * 24 * 3600,
            recency_secs: 3 * 24 * 3600,
            maturity_secs: 3600,
        }
    }
}

/// One wallet's measured track record over the lookback window.
#[derive(Debug, Clone, PartialEq)]
pub struct WalletPerf {
    pub address: String,
    /// Resolved calls this wallet was present on.
    pub samples: usize,
    /// How many of those reached `hit_multiple`.
    pub hits: usize,
    /// Best multiple across its samples.
    pub best_peak: f64,
    /// Mean peak across its samples. Reported, never used to qualify: one
    /// 900x drags an average somewhere no median would go.
    pub avg_peak: f64,
    /// Median peak — what a TYPICAL call by this wallet did. Unlike the mean,
    /// a single moonshot cannot lift it, which is exactly why it qualifies.
    pub median_peak: f64,
    /// Most recent buy seen, including calls too fresh to be samples — this
    /// measures activity, not performance.
    pub last_seen: DateTime<Utc>,
}

impl WalletPerf {
    pub fn hit_rate(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        self.hits as f64 / self.samples as f64
    }

    /// Whether this wallet is Alpha right now.
    pub fn qualifies(&self, rules: &AlphaRules, now: DateTime<Utc>) -> bool {
        if self.samples < rules.min_samples {
            return false;
        }
        if self.hit_rate() < rules.min_hit_rate {
            return false;
        }
        if self.median_peak < rules.min_median_peak {
            return false;
        }
        (now - self.last_seen).num_seconds() <= rules.recency_secs
    }
}

/// Build a per-wallet track record from the announced-signal history.
///
/// `records` is the whole signal store; this filters to the lookback window
/// itself so callers cannot get it subtly wrong in two places.
pub fn wallet_performance(
    records: &[Call],
    rules: &AlphaRules,
    now: DateTime<Utc>,
) -> Vec<WalletPerf> {
    struct Acc {
        samples: usize,
        hits: usize,
        best_peak: f64,
        sum_peak: f64,
        peaks: Vec<f64>,
        last_seen: DateTime<Utc>,
    }
    let mut by_wallet: HashMap<String, Acc> = HashMap::new();

    for rec in records {
        let age = (now - rec.at).num_seconds();
        if age > rules.lookback_secs || age < 0 {
            continue;
        }
        // Fresh calls still update recency — a wallet buying right now is
        // active — but they are not yet evidence of anything.
        let mature = age >= rules.maturity_secs;
        let peak = rec.peak;
        let hit = peak >= rules.hit_multiple;

        // One wallet can appear once per token. A wallet that bought the same
        // call repeatedly is one sample, not several: sizing up on conviction
        // is not the same as being right more often.
        for w in rec.wallets.iter().collect::<HashSet<_>>() {
            let acc = by_wallet.entry(w.clone()).or_insert(Acc {
                samples: 0,
                hits: 0,
                best_peak: 0.0,
                sum_peak: 0.0,
                peaks: Vec::new(),
                last_seen: rec.at,
            });
            if rec.at > acc.last_seen {
                acc.last_seen = rec.at;
            }
            if !mature {
                continue;
            }
            acc.samples += 1;
            acc.hits += usize::from(hit);
            acc.sum_peak += peak;
            acc.peaks.push(peak);
            if peak > acc.best_peak {
                acc.best_peak = peak;
            }
        }
    }

    let mut out: Vec<WalletPerf> = by_wallet
        .into_iter()
        .map(|(address, a)| WalletPerf {
            address,
            samples: a.samples,
            hits: a.hits,
            best_peak: a.best_peak,
            avg_peak: if a.samples == 0 { 0.0 } else { a.sum_peak / a.samples as f64 },
            median_peak: median(a.peaks),
            last_seen: a.last_seen,
        })
        .collect();
    // Best first, then by sample count so a thin record never outranks a
    // thick one at the same rate.
    out.sort_by(|a, b| {
        b.hit_rate()
            .partial_cmp(&a.hit_rate())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.samples.cmp(&a.samples))
    });
    out
}

/// Middle value of a sample, 0.0 when there is nothing to measure.
fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

/// The set of wallet addresses currently trusted with Alpha money.
pub fn qualifying_set(
    records: &[Call],
    rules: &AlphaRules,
    now: DateTime<Utc>,
) -> HashSet<String> {
    wallet_performance(records, rules, now)
        .into_iter()
        .filter(|p| p.qualifies(rules, now))
        .map(|p| p.address)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-28T12:00:00Z").unwrap().with_timezone(&Utc)
    }

    fn rec(mint: &str, age_secs: i64, peak: f64, wallets: &[&str]) -> Call {
        Call {
            mint: mint.to_string(),
            wallets: wallets.iter().map(|s| s.to_string()).collect(),
            peak,
            at: now() - Duration::seconds(age_secs),
        }
    }

    fn rules() -> AlphaRules {
        AlphaRules {
            min_samples: 3,
            min_hit_rate: 0.5,
            // Off for the older tests, which predate this rule and exercise
            // the hit-rate logic on purpose.
            min_median_peak: 0.0,
            hit_multiple: 2.0,
            lookback_secs: 7 * 24 * 3600,
            recency_secs: 3 * 24 * 3600,
            maturity_secs: 3600,
        }
    }

    fn perf_of(v: &[WalletPerf], addr: &str) -> WalletPerf {
        v.iter().find(|p| p.address == addr).expect("wallet present").clone()
    }

    #[test]
    fn hit_rate_counts_only_calls_that_reached_the_multiple() {
        let recs = vec![
            rec("A", 7200, 5.0, &["w1"]),
            rec("B", 7200, 1.2, &["w1"]),
            rec("C", 7200, 2.0, &["w1"]),
            rec("D", 7200, 0.4, &["w1"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &rules(), now()), "w1");
        assert_eq!(p.samples, 4);
        assert_eq!(p.hits, 2, "5.0x and exactly 2.0x count; 1.2x and 0.4x do not");
        assert_eq!(p.hit_rate(), 0.5);
        assert_eq!(p.best_peak, 5.0);
    }

    /// The bias this guards against: a wallet that buys constantly has many
    /// calls too young to have moved. Counting those as misses would rank the
    /// most active wallets the lowest.
    #[test]
    fn calls_too_fresh_to_have_resolved_are_not_samples() {
        let recs = vec![
            rec("A", 7200, 5.0, &["w1"]),
            rec("B", 7200, 4.0, &["w1"]),
            rec("C", 60, 1.0, &["w1"]),
            rec("D", 120, 1.0, &["w1"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &rules(), now()), "w1");
        assert_eq!(p.samples, 2, "the two fresh calls are not evidence yet");
        assert_eq!(p.hit_rate(), 1.0);
    }

    /// ...but they still prove the wallet is active, or a wallet trading right
    /// now could be dropped for staleness.
    #[test]
    fn a_fresh_call_still_counts_as_activity() {
        let recs = vec![
            rec("A", 6 * 24 * 3600, 5.0, &["w1"]),
            rec("B", 6 * 24 * 3600, 4.0, &["w1"]),
            rec("C", 6 * 24 * 3600, 3.0, &["w1"]),
            rec("D", 60, 1.0, &["w1"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &rules(), now()), "w1");
        assert_eq!(p.samples, 3);
        assert!(p.qualifies(&rules(), now()), "it bought a minute ago");
    }

    #[test]
    fn buying_one_call_twice_is_still_one_sample() {
        let recs = vec![rec("A", 7200, 5.0, &["w1", "w1", "w1"])];
        let p = perf_of(&wallet_performance(&recs, &rules(), now()), "w1");
        assert_eq!(p.samples, 1);
    }

    #[test]
    fn a_thin_record_does_not_qualify_however_good() {
        let recs = vec![rec("A", 7200, 900.0, &["w1"]), rec("B", 7200, 50.0, &["w1"])];
        let p = perf_of(&wallet_performance(&recs, &rules(), now()), "w1");
        assert_eq!(p.hit_rate(), 1.0);
        assert!(!p.qualifies(&rules(), now()), "2 samples is under the minimum of 3");
    }

    #[test]
    fn a_wallet_that_stopped_trading_falls_out() {
        let stale = 5 * 24 * 3600;
        let recs = vec![
            rec("A", stale, 5.0, &["w1"]),
            rec("B", stale, 4.0, &["w1"]),
            rec("C", stale, 3.0, &["w1"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &rules(), now()), "w1");
        assert_eq!(p.hit_rate(), 1.0, "the record is still perfect");
        assert!(!p.qualifies(&rules(), now()), "but it has not traded in 5 days");
    }

    #[test]
    fn calls_outside_the_lookback_are_ignored_entirely() {
        let recs = vec![rec("A", 30 * 24 * 3600, 900.0, &["w1"])];
        assert!(wallet_performance(&recs, &rules(), now()).is_empty());
    }

    #[test]
    fn qualifying_set_admits_only_wallets_over_the_bar() {
        let recs = vec![
            rec("A", 7200, 5.0, &["good", "bad"]),
            rec("B", 7200, 4.0, &["good", "bad"]),
            rec("C", 7200, 1.0, &["good", "bad"]),
            rec("D", 7200, 1.0, &["bad"]),
            rec("E", 7200, 1.0, &["bad"]),
        ];
        let set = qualifying_set(&recs, &rules(), now());
        assert!(set.contains("good"), "2 hits of 3 clears a 0.5 rate");
        assert!(!set.contains("bad"), "2 hits of 5 does not");
    }

    /// A record written before `peak_multiple` existed carries 0.0 and falls
    /// back to `last_multiple`; it must not read as a catastrophic loss.
    /// `Call::from_signal` folds `peak_multiple`/`last_multiple` together, so a
    /// record written before peak tracking existed still scores correctly
    /// rather than reading as a total loss.
    #[test]
    fn a_signal_predating_peak_tracking_uses_its_last_multiple() {
        let mut sr = crate::signals::SignalRecord {
            mint: "A".into(),
            name: String::new(),
            symbol: String::new(),
            first_seen_utc: now() - Duration::seconds(7200),
            message_id: None,
            reference_sol: 1.0,
            reference_tokens_raw: 1,
            decimals: 6,
            fdv_usd_at_signal: None,
            supply: None,
            wallets: vec!["w1".into()],
            total_sol: 1.0,
            sol_usd_at_signal: None,
            total_fees_sol: 0.0,
            last_reported_multiple: 1.0,
            last_multiple: 3.0,
            peak_multiple: 0.0,
            last_checked_utc: None,
        };
        sr.peak_multiple = 0.0;
        let c = Call::from_signal(&sr);
        assert_eq!(c.peak, 3.0);
        let p = perf_of(&wallet_performance(&[c], &rules(), now()), "w1");
        assert_eq!(p.hits, 1);
    }

    /// The bug this whole archive exists to fix: the live store retires a call
    /// after a day, so scoring it directly capped every record at one day no
    /// matter what the lookback said. The archive holds the older half.
    #[test]
    fn the_archive_and_the_live_store_are_merged() {
        // Five days old: long past the live store's one-day retention, so it
        // can only be here because the archive kept it.
        let archived = vec![rec("OLD", 5 * 24 * 3600, 5.0, &["w1"])];
        let live = vec![crate::signals::SignalRecord {
            mint: "NEW".into(),
            name: String::new(),
            symbol: String::new(),
            first_seen_utc: now() - Duration::seconds(7200),
            message_id: None,
            reference_sol: 1.0,
            reference_tokens_raw: 1,
            decimals: 6,
            fdv_usd_at_signal: None,
            supply: None,
            wallets: vec!["w1".into()],
            total_sol: 1.0,
            sol_usd_at_signal: None,
            total_fees_sol: 0.0,
            last_reported_multiple: 1.0,
            last_multiple: 4.0,
            peak_multiple: 4.0,
            last_checked_utc: None,
        }];
        let merged = merge_calls(archived, &live);
        assert_eq!(merged.len(), 2, "a 20-day-old call survives alongside today's");
        let p = perf_of(&wallet_performance(&merged, &rules(), now()), "w1");
        assert_eq!(p.samples, 2);
    }

    /// A call in both places takes the higher peak: the live copy is still
    /// being re-priced and may have run further since it was archived.
    #[test]
    fn a_call_in_both_places_keeps_the_higher_peak() {
        let archived = vec![rec("M", 7200, 2.0, &["w1"])];
        let live = vec![crate::signals::SignalRecord {
            mint: "M".into(),
            name: String::new(),
            symbol: String::new(),
            first_seen_utc: now() - Duration::seconds(7200),
            message_id: None,
            reference_sol: 1.0,
            reference_tokens_raw: 1,
            decimals: 6,
            fdv_usd_at_signal: None,
            supply: None,
            wallets: vec!["w1".into()],
            total_sol: 1.0,
            sol_usd_at_signal: None,
            total_fees_sol: 0.0,
            last_reported_multiple: 1.0,
            last_multiple: 9.0,
            peak_multiple: 9.0,
            last_checked_utc: None,
        }];
        let merged = merge_calls(archived, &live);
        assert_eq!(merged.len(), 1, "one token, not two");
        assert_eq!(merged[0].peak, 9.0);
    }

    /// The case that exposed the flaw: a wallet on the live book with a 44.4%
    /// hit rate whose MEDIAN call did 1.00x — half its picks went nowhere at
    /// all. Hit rate alone admitted it, and Alpha bought on its signal.
    #[test]
    fn a_wallet_whose_typical_call_goes_nowhere_is_rejected() {
        let mut r = rules();
        r.min_median_peak = 1.5;
        // Four calls: two big winners, two flat. 50% hit rate, median 1.0x.
        let recs = vec![
            rec("A", 7200, 8.0, &["lucky"]),
            rec("B", 7200, 6.0, &["lucky"]),
            rec("C", 7200, 1.0, &["lucky"]),
            rec("D", 7200, 1.0, &["lucky"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &r, now()), "lucky");
        assert_eq!(p.hit_rate(), 0.5, "it clears the hit-rate bar");
        assert_eq!(p.median_peak, 3.5, "(1.0 + 6.0) / 2 across the middle pair");

        // Now the real shape: mostly flat with a couple of spikes.
        let recs = vec![
            rec("A", 7200, 20.0, &["lucky"]),
            rec("B", 7200, 1.0, &["lucky"]),
            rec("C", 7200, 1.0, &["lucky"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &r, now()), "lucky");
        assert_eq!(p.median_peak, 1.0, "the typical call did nothing");
        assert!(!p.qualifies(&r, now()), "and that is disqualifying");
    }

    /// A single moonshot must not carry a wallet. The mean would let it.
    #[test]
    fn one_huge_winner_cannot_lift_the_median() {
        let mut r = rules();
        r.min_median_peak = 1.5;
        let recs = vec![
            rec("A", 7200, 900.0, &["onehit"]),
            rec("B", 7200, 1.0, &["onehit"]),
            rec("C", 7200, 1.0, &["onehit"]),
            rec("D", 7200, 1.0, &["onehit"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &r, now()), "onehit");
        assert!(p.avg_peak > 200.0, "the mean is dragged all the way up");
        assert_eq!(p.median_peak, 1.0, "the median is not");
        assert!(!p.qualifies(&r, now()));
    }

    /// A wallet that is consistently right still qualifies.
    #[test]
    fn a_consistently_good_wallet_still_qualifies() {
        let mut r = rules();
        r.min_median_peak = 1.5;
        let recs = vec![
            rec("A", 7200, 3.0, &["steady"]),
            rec("B", 7200, 2.5, &["steady"]),
            rec("C", 7200, 1.8, &["steady"]),
            rec("D", 7200, 1.2, &["steady"]),
        ];
        let p = perf_of(&wallet_performance(&recs, &r, now()), "steady");
        assert_eq!(p.median_peak, 2.15);
        assert!(p.qualifies(&r, now()));
    }

    #[test]
    fn ranking_puts_the_thicker_record_first_at_an_equal_rate() {
        let recs = vec![
            rec("A", 7200, 5.0, &["thin", "thick"]),
            rec("B", 7200, 5.0, &["thick"]),
            rec("C", 7200, 5.0, &["thick"]),
        ];
        let ranked = wallet_performance(&recs, &rules(), now());
        assert_eq!(ranked[0].address, "thick");
    }
}
