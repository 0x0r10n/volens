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
use std::collections::{HashMap, HashSet};

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
    pub min_hit_rate: f64,
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
            min_samples: 8,
            min_hit_rate: 0.35,
            hit_multiple: 2.0,
            lookback_secs: 7 * 24 * 3600,
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
        (now - self.last_seen).num_seconds() <= rules.recency_secs
    }
}

/// Build a per-wallet track record from the announced-signal history.
///
/// `records` is the whole signal store; this filters to the lookback window
/// itself so callers cannot get it subtly wrong in two places.
pub fn wallet_performance(
    records: &[SignalRecord],
    rules: &AlphaRules,
    now: DateTime<Utc>,
) -> Vec<WalletPerf> {
    struct Acc {
        samples: usize,
        hits: usize,
        best_peak: f64,
        sum_peak: f64,
        last_seen: DateTime<Utc>,
    }
    let mut by_wallet: HashMap<String, Acc> = HashMap::new();

    for rec in records {
        let age = (now - rec.first_seen_utc).num_seconds();
        if age > rules.lookback_secs || age < 0 {
            continue;
        }
        // Fresh calls still update recency — a wallet buying right now is
        // active — but they are not yet evidence of anything.
        let mature = age >= rules.maturity_secs;
        let peak = rec.peak();
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
                last_seen: rec.first_seen_utc,
            });
            if rec.first_seen_utc > acc.last_seen {
                acc.last_seen = rec.first_seen_utc;
            }
            if !mature {
                continue;
            }
            acc.samples += 1;
            acc.hits += usize::from(hit);
            acc.sum_peak += peak;
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

/// The set of wallet addresses currently trusted with Alpha money.
pub fn qualifying_set(
    records: &[SignalRecord],
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

    fn rec(mint: &str, age_secs: i64, peak: f64, wallets: &[&str]) -> SignalRecord {
        SignalRecord {
            mint: mint.to_string(),
            name: String::new(),
            symbol: String::new(),
            first_seen_utc: now() - Duration::seconds(age_secs),
            message_id: None,
            reference_sol: 1.0,
            reference_tokens_raw: 1,
            decimals: 6,
            fdv_usd_at_signal: None,
            supply: None,
            wallets: wallets.iter().map(|s| s.to_string()).collect(),
            total_sol: 1.0,
            sol_usd_at_signal: None,
            total_fees_sol: 0.0,
            last_reported_multiple: 1.0,
            last_multiple: peak,
            peak_multiple: peak,
            last_checked_utc: None,
        }
    }

    fn rules() -> AlphaRules {
        AlphaRules {
            min_samples: 3,
            min_hit_rate: 0.5,
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
    #[test]
    fn a_record_predating_peak_tracking_uses_its_last_multiple() {
        let mut r = rec("A", 7200, 0.0, &["w1"]);
        r.peak_multiple = 0.0;
        r.last_multiple = 3.0;
        let p = perf_of(&wallet_performance(&[r], &rules(), now()), "w1");
        assert_eq!(p.hits, 1);
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
