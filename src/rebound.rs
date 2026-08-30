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
    /// Set once the rebound has been ANNOUNCED for this cycle.
    ///
    /// Deliberately separate from `triggered`. Watching is worth reporting on
    /// its own — a token that rugged and started trading again is the whole
    /// point of the mode — and that reporting must not depend on whether a buy
    /// was configured, allowed, or successful. Two flags means the alert fires
    /// once and the entry is still available if the buy was refused.
    #[serde(default)]
    pub alerted: bool,
    /// Has this token actually gone quiet since the watch opened?
    ///
    /// THE condition that makes this a rebound rather than a follow. A token
    /// joins the watchlist at the exact moment tracked wallets are buying it,
    /// so its fresh volume is at its highest right then — without this, every
    /// watched token would trigger within seconds of being added and the mode
    /// would just be a slower copy of the normal trigger.
    ///
    /// Set by the watcher the first time it observes volume BELOW the
    /// threshold. Nothing can fire until then.
    #[serde(default)]
    pub went_quiet: bool,
    /// Price when the REBOUND alert fired, and the message it was announced in.
    ///
    /// The baseline for follow-up updates: "3.2x" on a rebound means since the
    /// rebound was called, not since the original smart-money signal, because
    /// the rebound alert is the entry being reported on.
    #[serde(default)]
    pub alert_price: Option<f64>,
    #[serde(default)]
    pub alert_msg_id: Option<i64>,
    /// Highest rung already announced for this rebound. Starts at 1.0.
    #[serde(default)]
    pub reported_multiple: f64,
    /// Price per token when the watch opened, if the stream could price it.
    ///
    /// What makes the alert readable: "trading again" is unremarkable on its
    /// own, and "trading again at 0.11x of where smart money bought it" is the
    /// thing worth looking at.
    #[serde(default)]
    pub price_at_watch: Option<f64>,
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
    /// Still busy from the activity that put it on the watchlist. A rebound is
    /// a RETURN, so the token has to go quiet before it can come back.
    NeverQuiet,
}

/// The observation pool.
#[derive(Debug, Default)]
pub struct ReboundPool {
    watching: HashMap<String, Watch>,
    /// Set by any change; cleared when the caller persists.
    ///
    /// The pool takes on a token per tracked buy — thousands a day — and saving
    /// rewrites the whole file, so writes are batched by the watcher loop
    /// rather than done per observation on the stream's hot path.
    dirty: bool,
}

impl ReboundPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_watches(list: Vec<Watch>) -> Self {
        Self { watching: list.into_iter().map(|w| (w.mint.clone(), w)).collect(), dirty: false }
    }

    /// Has the pool changed since it was last persisted? Clears the flag.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// Put the flag back when a caller took it but did not persist.
    ///
    /// Saving is throttled, so a pass can observe changes it does not write.
    /// Without this the flag would be consumed and those changes would never be
    /// persisted at all.
    pub fn set_dirty(&mut self) {
        self.dirty = true;
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
    pub fn observe(
        &mut self,
        mint: &str,
        now: DateTime<Utc>,
        watch_secs: i64,
        price: Option<f64>,
    ) -> bool {
        match self.watching.get_mut(mint) {
            Some(w) => {
                // Only an EXPIRED or already-spent watch restarts. Refreshing on
                // every touch would let a token that tracked wallets keep
                // nibbling at sit in the pool forever, permanently armed.
                if w.triggered || w.expired(now, watch_secs) {
                    w.since = now;
                    w.triggered = false;
                    w.alerted = false;
                    w.went_quiet = false;
                    w.alert_price = None;
                    w.alert_msg_id = None;
                    w.reported_multiple = 0.0;
                    w.price_at_watch = price;
                    self.dirty = true;
                    true
                } else {
                    false
                }
            }
            None => {
                self.watching.insert(
                    mint.to_string(),
                    Watch {
                        mint: mint.to_string(),
                        since: now,
                        triggered: false,
                        alerted: false,
                        went_quiet: false,
                        alert_price: None,
                        alert_msg_id: None,
                        reported_multiple: 0.0,
                        price_at_watch: price,
                    },
                );
                self.dirty = true;
                true
            }
        }
    }

    /// Drop watches whose window has closed. Returns how many were removed.
    pub fn expire(&mut self, now: DateTime<Utc>, watch_secs: i64) -> usize {
        let before = self.watching.len();
        self.watching.retain(|_, w| !w.expired(now, watch_secs));
        let dropped = before - self.watching.len();
        if dropped > 0 {
            self.dirty = true;
        }
        dropped
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
        if !w.went_quiet {
            return Err(Skip::NeverQuiet);
        }
        // A threshold of zero would fire on any token that has traded at all,
        // which is every token in the pool.
        if min_volume_sol <= 0.0 || fresh_volume_sol < min_volume_sol {
            return Err(Skip::TooQuiet);
        }
        Ok(())
    }

    /// Is this token worth ANNOUNCING right now?
    ///
    /// The same volume test as `evaluate`, against the alert's own once-per-cycle
    /// flag. Kept separate so a token can be reported even when no buy is
    /// configured — which is the normal state while thresholds are being chosen.
    pub fn evaluate_alert(
        &self,
        mint: &str,
        fresh_volume_sol: f64,
        min_volume_sol: f64,
        now: DateTime<Utc>,
        watch_secs: i64,
    ) -> Result<(), Skip> {
        let Some(w) = self.watching.get(mint) else { return Err(Skip::NotWatched) };
        if w.alerted {
            return Err(Skip::AlreadyTriggered);
        }
        if w.expired(now, watch_secs) {
            return Err(Skip::Expired);
        }
        // It has to have LEFT before it can come back.
        if !w.went_quiet {
            return Err(Skip::NeverQuiet);
        }
        if min_volume_sol <= 0.0 || fresh_volume_sol < min_volume_sol {
            return Err(Skip::TooQuiet);
        }
        Ok(())
    }

    /// What the token was worth when the watch opened, and how long ago.
    pub fn context(&self, mint: &str) -> Option<(Option<f64>, DateTime<Utc>)> {
        self.watching.get(mint).map(|w| (w.price_at_watch, w.since))
    }

    /// Record that a token is currently below the threshold.
    ///
    /// Returns true the first time, so the caller can log the transition once.
    pub fn mark_quiet(&mut self, mint: &str) -> bool {
        match self.watching.get_mut(mint) {
            Some(w) if !w.went_quiet => {
                w.went_quiet = true;
                self.dirty = true;
                true
            }
            _ => false,
        }
    }

    pub fn mark_alerted(&mut self, mint: &str) {
        if let Some(w) = self.watching.get_mut(mint) {
            w.alerted = true;
            self.dirty = true;
        }
    }

    /// Record the baseline a rebound's follow-up updates measure from.
    pub fn set_alert_baseline(&mut self, mint: &str, price: Option<f64>, msg_id: Option<i64>) {
        if let Some(w) = self.watching.get_mut(mint) {
            w.alert_price = price;
            w.alert_msg_id = msg_id;
            w.reported_multiple = 1.0;
            self.dirty = true;
        }
    }

    /// Rebounds that have been announced and can still be re-priced.
    pub fn announced(&self) -> Vec<Watch> {
        self.watching.values().filter(|w| w.alert_price.is_some()).cloned().collect()
    }

    /// Raise the highest rung announced for a rebound.
    pub fn set_reported(&mut self, mint: &str, multiple: f64) {
        if let Some(w) = self.watching.get_mut(mint) {
            w.reported_multiple = multiple;
            self.dirty = true;
        }
    }

    /// Spend this token's entry for the current cycle.
    pub fn mark_triggered(&mut self, mint: &str) {
        if let Some(w) = self.watching.get_mut(mint) {
            w.triggered = true;
            self.dirty = true;
        }
    }
}

/// Read a persisted watchlist. A missing file is normal on first run; a corrupt
/// one is treated as empty rather than fatal.
pub fn load_watches(path: &str) -> Vec<Watch> {
    if path.is_empty() {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<Watch>>(&text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(path, error = %e, "unreadable rebound watchlist; starting empty");
            Vec::new()
        }
    }
}

/// Write the watchlist atomically.
///
/// Whole-file rewrite through a temp file and a rename, not an append: the
/// watchlist is CURRENT STATE, not history — entries expire, and the triggered
/// flag flips — so a log of changes would have to be replayed to be understood.
/// The rename means a crash mid-write leaves the previous list intact rather
/// than a truncated one.
///
/// Without this the 72-hour window lived only in memory, so every restart wiped
/// it. On a bot that gets deployed several times a day that is not a rare edge
/// case — it is the normal state, and it would silently mean Rebound never saw
/// a token long enough to watch it.
pub fn save_watches(path: &str, watches: &[Watch]) {
    if path.is_empty() {
        return;
    }
    let Ok(body) = serde_json::to_string(watches) else { return };
    let tmp = format!("{path}.tmp");
    if std::fs::write(&tmp, body).is_err() {
        tracing::warn!(path, "could not write the rebound watchlist");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!(path, error = %e, "could not replace the rebound watchlist");
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
        assert!(p.observe("M", now(), WATCH, None), "first touch opens a cycle");
        assert!(!p.observe("M", now(), WATCH, None), "a second touch is the same cycle");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn fresh_volume_over_the_threshold_triggers() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        assert_eq!(p.evaluate("M", 12.0, 10.0, now(), WATCH), Ok(()));
    }

    #[test]
    fn quiet_tokens_do_not_trigger() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        assert_eq!(p.evaluate("M", 4.0, 10.0, now(), WATCH), Err(Skip::TooQuiet));
    }

    /// A threshold of zero would fire on every token in the pool, which is
    /// every token smart money has touched — the opposite of selective.
    #[test]
    fn a_zero_threshold_never_triggers() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
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
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Ok(()));
        p.mark_triggered("M");
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Err(Skip::AlreadyTriggered));
    }

    /// Marking is separate from evaluating precisely so a refused buy does not
    /// consume the token's one chance.
    #[test]
    fn evaluating_alone_does_not_spend_the_entry() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Ok(()));
        assert_eq!(p.evaluate("M", 50.0, 10.0, now(), WATCH), Ok(()), "still armed");
    }

    #[test]
    fn the_window_closes() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
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
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        p.mark_triggered("M");
        let later = now() + Duration::seconds(3600);
        assert!(p.observe("M", later, WATCH, None), "a new cycle opened");
        assert_eq!(
            p.evaluate("M", 50.0, 10.0, later, WATCH),
            Err(Skip::NeverQuiet),
            "a fresh cycle must see it go quiet again first"
        );
        p.mark_quiet("M");
        assert_eq!(p.evaluate("M", 50.0, 10.0, later, WATCH), Ok(()));
    }

    /// ...but a touch DURING a live, unspent cycle must not keep pushing the
    /// deadline out, or a token tracked wallets keep nibbling never expires.
    #[test]
    fn a_touch_during_a_live_cycle_does_not_extend_it() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        let mid = now() + Duration::seconds(WATCH - 60);
        assert!(!p.observe("M", mid, WATCH, None));
        let after = now() + Duration::seconds(WATCH + 1);
        assert_eq!(p.evaluate("M", 50.0, 10.0, after, WATCH), Err(Skip::Expired));
    }

    /// The whole point of persisting: a 72-hour window must outlive a deploy.
    #[test]
    fn the_watchlist_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-rebound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("watch.json");
        let p = path.to_string_lossy().to_string();

        let mut pool = ReboundPool::new();
        pool.observe("A", now(), WATCH, None);
        pool.mark_quiet("A");
        pool.observe("B", now(), WATCH, None);
        pool.mark_quiet("B");
        pool.mark_triggered("B");
        save_watches(&p, &pool.watches());

        let restored = ReboundPool::from_watches(load_watches(&p));
        assert_eq!(restored.len(), 2, "both watches came back");
        assert_eq!(
            restored.evaluate("B", 50.0, 1.0, now(), WATCH),
            Err(Skip::AlreadyTriggered),
            "and B is still spent — a restart must not re-arm it"
        );
        assert_eq!(restored.evaluate("A", 50.0, 1.0, now(), WATCH), Ok(()));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The alert must not depend on a buy being configured — reporting that a
    /// token is trading again is the point of the mode, and thresholds get
    /// chosen by watching those reports first.
    #[test]
    fn alerting_and_buying_are_independent() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");

        assert_eq!(p.evaluate_alert("M", 50.0, 10.0, now(), WATCH), Ok(()));
        p.mark_alerted("M");
        assert_eq!(
            p.evaluate_alert("M", 50.0, 10.0, now(), WATCH),
            Err(Skip::AlreadyTriggered),
            "announced once per cycle"
        );
        assert_eq!(
            p.evaluate("M", 50.0, 10.0, now(), WATCH),
            Ok(()),
            "but the entry is still available"
        );
    }

    /// THE condition that separates a rebound from a follow. A token joins the
    /// watchlist while tracked wallets are buying it, so its volume is at its
    /// highest right then — firing on that would make this a slower copy of the
    /// normal trigger rather than a re-entry.
    #[test]
    fn a_token_must_go_quiet_before_it_can_rebound() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        assert_eq!(
            p.evaluate("M", 999.0, 10.0, now(), WATCH),
            Err(Skip::NeverQuiet),
            "still busy from the buying that put it on the list"
        );
        assert_eq!(
            p.evaluate_alert("M", 999.0, 10.0, now(), WATCH),
            Err(Skip::NeverQuiet),
            "and it must not be announced either"
        );

        assert!(p.mark_quiet("M"), "the first quiet observation is the transition");
        assert!(!p.mark_quiet("M"), "and it is recorded only once");
        assert_eq!(p.evaluate("M", 999.0, 10.0, now(), WATCH), Ok(()), "now it is a rebound");
    }

    /// Saving is throttled, so a pass can take the flag without writing. The
    /// change must not be lost when that happens.
    #[test]
    fn an_unpersisted_change_can_be_put_back() {
        let mut p = ReboundPool::new();
        p.observe("A", now(), WATCH, None);
        assert!(p.take_dirty());
        p.set_dirty();
        assert!(p.take_dirty(), "still outstanding for the next eligible pass");
    }

    /// A refused buy must not silence the next cycle's alert either.
    #[test]
    fn a_new_cycle_re_arms_both_flags() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, None);
        p.mark_quiet("M");
        p.mark_alerted("M");
        p.mark_triggered("M");
        let later = now() + Duration::seconds(3600);
        assert!(p.observe("M", later, WATCH, None));
        p.mark_quiet("M");
        assert_eq!(p.evaluate_alert("M", 50.0, 10.0, later, WATCH), Ok(()));
        assert_eq!(p.evaluate("M", 50.0, 10.0, later, WATCH), Ok(()));
    }

    /// The price at watch time is what makes "trading again" readable as
    /// "trading again at a tenth of where smart money bought it".
    #[test]
    fn the_watch_price_is_kept_for_context() {
        let mut p = ReboundPool::new();
        p.observe("M", now(), WATCH, Some(0.000_02));
        let (price, since) = p.context("M").unwrap();
        assert_eq!(price, Some(0.000_02));
        assert_eq!(since, now());
    }

    /// Saving is batched off the hot path, so the pool has to be able to say
    /// whether it changed. A missed flag means a lost watch.
    #[test]
    fn every_change_marks_the_pool_dirty() {
        let mut p = ReboundPool::new();
        assert!(!p.take_dirty(), "a fresh pool has nothing to save");

        p.observe("A", now(), WATCH, None);
        p.mark_quiet("A");
        assert!(p.take_dirty(), "a new watch");
        assert!(!p.take_dirty(), "and the flag clears");

        p.observe("A", now(), WATCH, None);
        p.mark_quiet("A");
        assert!(!p.take_dirty(), "a repeat touch in the same cycle changes nothing");

        p.mark_triggered("A");
        assert!(p.take_dirty(), "spending the entry must be persisted");

        p.expire(now() + Duration::seconds(WATCH + 1), WATCH);
        assert!(p.take_dirty(), "so must an expiry");
    }

    /// A restored pool is already in sync with the file it came from.
    #[test]
    fn a_loaded_pool_starts_clean() {
        let mut p = ReboundPool::from_watches(vec![Watch {
            mint: "A".into(),
            since: now(),
            triggered: false,
            alerted: false,
            went_quiet: true,
            alert_price: None,
            alert_msg_id: None,
            reported_multiple: 0.0,
            price_at_watch: None,
        }]);
        assert!(!p.take_dirty());
    }

    #[test]
    fn a_missing_or_corrupt_watchlist_is_not_fatal() {
        assert!(load_watches("/nonexistent/volens/watch.json").is_empty());
        let dir = std::env::temp_dir().join(format!("volens-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_watches(&path.to_string_lossy()).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn watches_survive_a_round_trip() {
        let mut p = ReboundPool::new();
        p.observe("A", now(), WATCH, None);
        p.mark_quiet("A");
        p.observe("B", now(), WATCH, None);
        p.mark_quiet("B");
        p.mark_triggered("B");
        let restored = ReboundPool::from_watches(p.watches());
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.evaluate("B", 50.0, 1.0, now(), WATCH), Err(Skip::AlreadyTriggered));
        assert_eq!(restored.evaluate("A", 50.0, 1.0, now(), WATCH), Ok(()));
    }
}
