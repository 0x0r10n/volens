//! Rebound mode — buy a token the smart money already left, if it comes back.
//!
//! # The thesis
//!
//! The normal trigger and Alpha both fire at the moment tracked wallets are
//! buying. Rebound watches what happens AFTER that: a token the smart money
//! touched, went quiet, and then started trading again on fresh volume from
//! anyone at all.
//!
//! Every token a tracked wallet touches enters the observation pool for a
//! configurable window. Nothing is bought on entry — the pool is a watchlist,
//! not a position.
//!
//! # Fresh volume, not lifetime volume
//!
//! The trigger measures volume in a SHORT ROLLING WINDOW, not since the token
//! was first observed. Cumulative volume only ever grows, so a threshold
//! against it fires once on every token that has ever traded and says nothing
//! about whether anything is happening now. "It is trading again" is a
//! statement about the last few minutes, and that is what this measures.
//!
//! # One entry per observation cycle
//!
//! A token that triggers is marked and will not trigger again while it stays in
//! the pool. Without that, a token trading steadily above the threshold would
//! be bought on every pass for as long as its watch window lasted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One token under observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Watch {
    pub mint: String,
    /// When a tracked wallet last touched it — the start of the window.
    pub since: DateTime<Utc>,
    /// Set once a rebound entry has been taken for this cycle.
    #[serde(default)]
    pub triggered: bool,
}

impl Watch {
    pub fn expired(&self, now: DateTime<Utc>, watch_secs: i64) -> bool {
        (now - self.since).num_seconds() > watch_secs
    }
}

/// Why a token did not produce a rebound entry. Returned rather than logged so
/// the caller decides how loud each case should be.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Skip {
    NotWatched,
    AlreadyTriggered,
    Expired,
    /// Fresh volume was below the threshold.
    TooQuiet,
}

/// The observation pool.
#[derive(Debug, Default)]
pub struct ReboundPool {
    watching: HashMap<String, Watch>,
}

impl ReboundPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_watches(list: Vec<Watch>) -> Self {
        Self { watching: list.into_iter().map(|w| (w.mint.clone(), w)).collect() }
    }

    pub fn len(&self) -> usize {
        self.watching.len()
    }

    pub fn is_empty(&self) -> bool {
        self.watching.is_empty()
    }

    pub fn watches(&self) -> Vec<Watch> {
        self.watching.values().cloned().collect()
    }

    pub fn mints(&self) -> Vec<String> {
        self.watching.keys().cloned().collect()
    }

    /// Put a token under observation, or refresh the window if it is already
    /// there.
    ///
    /// A fresh touch by tracked money RESTARTS the clock and clears the
    /// triggered flag: that is a new observation cycle, and the token has
    /// earned another chance to rebound.
    ///
    /// Returns true when this began a new cycle, so the caller can log it once
    /// rather than on every buy in the same token.
    pub fn observe(&mut self, mint: &str, now: DateTime<Utc>, watch_secs: i64) -> bool {
        match self.watching.get_mut(mint) {
            Some(w) => {
                // Only an EXPIRED or already-spent watch restarts. Refreshing on
                // every touch would let a token that tracked wallets keep
                // nibbling at sit in the pool forever, permanently armed.
                if w.triggered || w.expired(now, watch_secs) {
                    w.since = now;
                    w.triggered = false;
                    true
                } else {
                    false
                }
            }
            None => {
                self.watching
                    .insert(mint.to_string(), Watch { mint: mint.to_string(), since: now, triggered: false });
                true
            }
        }
    }

    /// Drop watches whose window has closed. Returns how many were removed.
    pub fn expire(&mut self, now: DateTime<Utc>, watch_secs: i64) -> usize {
        let before = self.watching.len();
        self.watching.retain(|_, w| !w.expired(now, watch_secs));
        before - self.watching.len()
    }

    /// Would this token trigger a rebound entry right now?
    ///
    /// Pure: it does not mutate. `mark_triggered` is separate so a buy that is
    /// refused downstream — by a safety veto, a position limit — does not burn
    /// the token's one entry for the cycle.
    pub fn evaluate(
        &self,
        mint: &str,
        fresh_volume_sol: f64,
        min_volume_sol: f64,
        now: DateTime<Utc>,
        watch_secs: i64,
    ) -> Result<(), Skip> {
        let Some(w) = self.watching.get(mint) else { return Err(Skip::NotWatched) };
        if w.triggered {
            return Err(Skip::AlreadyTriggered);
        }
        if w.expired(now, watch_secs) {
            return Err(Skip::Expired);
        }
        // A threshold of zero would fire on any token that has traded at all,
        // which is every token in the pool.
        if min_volume_sol <= 0.0 || fresh_volume_sol < min_volume_sol {
            return Err(Skip::TooQuiet);
        }
        Ok(())
    }

    /// Spend this token's entry for the current cycle.
    pub fn mark_triggered(&mut self, mint: &str) {
        if let Some(w) = self.watching.get_mut(mint) {
            w.triggered = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z").unwrap().with_timezone(&Utc)
    }

    const WATCH: i64 = 72 * 3600;

    #[test]
    fn a_touched_token_enters_the_pool_once() {
        let mut p = ReboundPool::new();
        assert!(p.observe("M", now(), WATCH), "first touch opens a cycle");
        assert!(!p.observe("M", now(), WATCH), "a second touch is the same cycle");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn fresh_volume_over_the_threshold_triggers() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        assert_eq!(p.evaluate("M", 12.0, 10.0, now(), WATCH), Ok(()));
    }

    #[test]
    fn quiet_tokens_do_not_trigger() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        assert_eq!(p.evaluate("M", 4.0, 10.0, now(), WATCH), Err(Skip::TooQuiet));
    }

    /// A threshold of zero would fire on every token in the pool, which is
    /// every token smart money has touched — the opposite of selective.
    #[test]
    fn a_zero_threshold_never_triggers() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        assert_eq!(p.evaluate("M", 999.0, 0.0, now(), WATCH), Err(Skip::TooQuiet));
    }

    #[test]
    fn a_token_nobody_tracked_is_not_watched() {
        let p = ReboundPool::new();
        assert_eq!(p.evaluate("M", 999.0, 1.0, now(), WATCH), Err(Skip::NotWatched));
    }

    /// One entry per cycle. A token trading steadily above the threshold would
    /// otherwise be bought on every pass for three days.
    #[test]
    fn a_token_only_triggers_once_per_cycle() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Ok(()));
        p.mark_triggered("M");
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Err(Skip::AlreadyTriggered));
    }

    /// Marking is separate from evaluating precisely so a refused buy does not
    /// consume the token's one chance.
    #[test]
    fn evaluating_alone_does_not_spend_the_entry() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Ok(()));
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Ok(()), "still armed");
    }

    #[test]
    fn the_window_closes() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        let later = now() + Duration::seconds(WATCH + 1);
        assert_eq!(p.evaluate("M", 50.0, 10.0, later, WATCH), Err(Skip::Expired));
        assert_eq!(p.expire(later, WATCH), 1);
        assert!(p.is_empty());
    }

    /// Smart money coming back re-arms a spent token — that is a new thesis,
    /// not a repeat of the old one.
    #[test]
    fn a_new_touch_after_triggering_starts_a_fresh_cycle() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        p.mark_triggered("M");
        let later = now() + Duration::seconds(3600);
        assert!(p.observe("M", later, WATCH), "a new cycle opened");
        assert_eq!(p.evaluate("M", 50.0, 10.0, later, WATCH), Ok(()));
    }

    /// ...but a touch DURING a live, unspent cycle must not keep pushing the
    /// deadline out, or a token tracked wallets keep nibbling never expires.
    #[test]
    fn a_touch_during_a_live_cycle_does_not_extend_it() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH);
        let mid = now() + Duration::seconds(WATCH - 60);
        assert!(!p.observe("M", mid, WATCH));
        let after = now() + Duration::seconds(WATCH + 1);
        assert_eq!(p.evaluate("M", 50.0, 10.0, after, WATCH), Err(Skip::Expired));
    }

    #[test]
    fn watches_survive_a_round_trip() {
        let mut p = ReboundPool::new();
        p.observe("A", now(), WATCH);
        p.observe("B", now(), WATCH);
        p.mark_triggered("B");
        let restored = ReboundPool::from_watches(p.watches());
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.evaluate("B", 50.0, 1.0, now(), WATCH), Err(Skip::AlreadyTriggered));
        assert_eq!(restored.evaluate("A", 50.0, 1.0, now(), WATCH), Ok(()));
    }
}
