//! When to sell a position, decided without touching the network.
//!
//! # Why the rules are a pure function
//!
//! This is the code that decides whether real money leaves a position while
//! nobody is watching. Everything here is a pure function of (rules, state,
//! current multiple) so it can be tested exhaustively — the task that drives it
//! only reads prices and calls `sell`.
//!
//! # The order of checks is the design
//!
//! Protective exits are evaluated BEFORE profit rungs, and at most one action
//! fires per tick. A position that gaps from 3x to 0.4x between ticks should
//! leave, not take a profit rung on the way past — the rung's premise (that the
//! token is worth 3x) is already false by the time we see it.
//!
//! # What a "multiple" means here
//!
//! `value_now / cost_basis`, both in SOL. 1.0 is break-even before fees. It is
//! NOT the figure shown on a call alert, which is measured from the smart
//! wallet's own fill — a price a follower could never have paid.

use serde::{Deserialize, Serialize};

/// One rung of the take-profit ladder: once the position is up `at_gain_pct`,
/// sell `sell_pct` of what is still held.
///
/// Both numbers are percentages, and they mean different things:
///
/// * `at_gain_pct` is the GAIN from cost. 100 means the position has doubled.
/// * `sell_pct` is of the REMAINING balance, not the original. Selling 50% at
///   +100% and 50% at +200% leaves 25% running, which is what a ladder is
///   normally understood to do.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Rung {
    /// Gain from cost, in percent. 0 disables the rung.
    pub at_gain_pct: u32,
    pub sell_pct: u8,
}

impl Rung {
    pub fn is_armed(&self) -> bool {
        self.at_gain_pct > 0 && (1..=100).contains(&self.sell_pct)
    }

    /// The value/cost ratio this rung triggers at.
    pub fn trigger_multiple(&self) -> f64 {
        1.0 + self.at_gain_pct as f64 / 100.0
    }
}

/// The full exit policy for every position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitRules {
    /// Master switch. Off means this module observes and never acts.
    pub enabled: bool,
    /// Three take-profit rungs, evaluated lowest-first.
    pub rungs: [Rung; 3],
    /// Sell everything once down this many percent from cost. 0 = off.
    pub stop_loss_pct: u8,
    /// Sell everything once down this many percent from the PEAK seen. 0 = off.
    pub trailing_pct: u8,
    /// Sell everything when the pool's liquidity is pulled.
    pub exit_on_liquidity_pull: bool,
}

impl Default for ExitRules {
    fn default() -> Self {
        Self {
            // Off until the operator turns it on. An exit policy that starts
            // enabled with values nobody chose would sell real positions on
            // defaults picked by a config author.
            enabled: false,
            rungs: [
                Rung { at_gain_pct: 100, sell_pct: 50 },
                Rung { at_gain_pct: 200, sell_pct: 50 },
                Rung { at_gain_pct: 400, sell_pct: 100 },
            ],
            stop_loss_pct: 50,
            trailing_pct: 0,
            exit_on_liquidity_pull: true,
        }
    }
}

/// Per-position memory: which rungs have fired, and the best multiple seen.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PositionState {
    /// Highest multiple observed. The trailing stop measures from this.
    pub peak_multiple: f64,
    /// Indices of rungs already taken, so each fires once.
    pub fired: Vec<usize>,
}

/// What to do about a position right now.
#[derive(Debug, Clone, PartialEq)]
pub enum ExitAction {
    Hold,
    Sell { pct: u8, reason: String },
}

/// Decide, and record what was decided.
///
/// `multiple` is value/cost. Updating `state` is part of the call: the peak has
/// to move even on a tick where nothing sells, or a trailing stop measured on
/// the next tick would use a stale high.
pub fn evaluate(rules: &ExitRules, state: &mut PositionState, multiple: f64) -> ExitAction {
    if !multiple.is_finite() || multiple <= 0.0 {
        // No usable price is not a reason to sell. An unpriced token looks
        // exactly like a worthless one, and acting on that confusion is how a
        // provider outage turns into a liquidation.
        return ExitAction::Hold;
    }
    if multiple > state.peak_multiple {
        state.peak_multiple = multiple;
    }
    if !rules.enabled {
        return ExitAction::Hold;
    }

    // --- Protective exits first. See the module note on ordering.
    if rules.stop_loss_pct > 0 {
        let floor = 1.0 - (rules.stop_loss_pct as f64 / 100.0);
        if multiple <= floor {
            return ExitAction::Sell {
                pct: 100,
                reason: format!("stop loss: {multiple:.2}x, floor {floor:.2}x"),
            };
        }
    }
    if rules.trailing_pct > 0 && state.peak_multiple > 1.0 {
        let trigger = state.peak_multiple * (1.0 - rules.trailing_pct as f64 / 100.0);
        // Only trails once the position has been in profit: a trailing stop
        // measured from a peak of 1.0 is just a second, looser stop loss, and
        // would close new positions on ordinary entry slippage.
        if multiple <= trigger {
            return ExitAction::Sell {
                pct: 100,
                reason: format!(
                    "trailing stop: {multiple:.2}x, peak {:.2}x, trigger {trigger:.2}x",
                    state.peak_multiple
                ),
            };
        }
    }

    // --- Then profit rungs, lowest first, one per tick.
    //
    // Lowest-first matters on a gap: a jump straight to +500% takes the +100%
    // rung now and the higher ones on later ticks, so a position cannot skip
    // past its own ladder and sell everything at once on a single print.
    let mut order: Vec<usize> = (0..rules.rungs.len()).collect();
    order.sort_by_key(|i| rules.rungs[*i].at_gain_pct);
    for i in order {
        let rung = rules.rungs[i];
        if !rung.is_armed() || state.fired.contains(&i) {
            continue;
        }
        if multiple >= rung.trigger_multiple() {
            state.fired.push(i);
            return ExitAction::Sell {
                pct: rung.sell_pct,
                reason: format!("take profit +{}% (rung {})", rung.at_gain_pct, i + 1),
            };
        }
    }

    ExitAction::Hold
}

/// A one-line summary for the settings screen.
pub fn describe(rules: &ExitRules) -> String {
    if !rules.enabled {
        return "off".into();
    }
    let rungs: Vec<String> = rules
        .rungs
        .iter()
        .filter(|r| r.is_armed())
        .map(|r| format!("{}%@+{}%", r.sell_pct, r.at_gain_pct))
        .collect();
    let mut parts = Vec::new();
    if !rungs.is_empty() {
        parts.push(rungs.join(" "));
    }
    if rules.stop_loss_pct > 0 {
        parts.push(format!("SL -{}%", rules.stop_loss_pct));
    }
    if rules.trailing_pct > 0 {
        parts.push(format!("trail -{}%", rules.trailing_pct));
    }
    if parts.is_empty() {
        // Enabled with every rule disabled does nothing, and should read as
        // nothing rather than as protection.
        return "on, but no rules set".into();
    }
    parts.join(" · ")
}


/// Per-position exit memory, persisted so a restart does not re-take rungs the
/// ladder has already taken or forget a peak the trailing stop measures from.
pub struct ExitStateStore {
    path: String,
    inner: std::sync::Mutex<std::collections::HashMap<String, PositionState>>,
}

impl ExitStateStore {
    pub fn load(path: &str) -> Self {
        let map = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        Self { path: path.to_string(), inner: std::sync::Mutex::new(map) }
    }

    pub fn ephemeral() -> Self {
        Self { path: String::new(), inner: std::sync::Mutex::new(Default::default()) }
    }

    /// Evaluate one position and persist whatever the decision changed.
    pub fn decide(&self, rules: &ExitRules, mint: &str, multiple: f64) -> ExitAction {
        let action = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let st = g.entry(mint.to_string()).or_default();
            evaluate(rules, st, multiple)
        };
        // Persist on any state change. A rung recorded as fired but never saved
        // would fire again after a restart and sell the position twice.
        self.save();
        action
    }

    /// Forget a position, e.g. once fully sold.
    pub fn forget(&self, mint: &str) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).remove(mint);
        self.save();
    }

    pub fn peak(&self, mint: &str) -> f64 {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(mint)
            .map(|s| s.peak_multiple)
            .unwrap_or(0.0)
    }

    fn save(&self) {
        if self.path.is_empty() {
            return;
        }
        let snapshot = { self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone() };
        let tmp = format!("{}.tmp", self.path);
        let written = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| std::io::Error::other(e.to_string()))
            .and_then(|body| std::fs::write(&tmp, body))
            .and_then(|_| std::fs::rename(&tmp, &self.path));
        if let Err(e) = written {
            tracing::warn!(path = %self.path, error = %e, "could not persist exit state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> ExitRules {
        ExitRules { enabled: true, ..Default::default() }
    }


    /// A rung recorded as fired but never saved would fire again after a
    /// restart and sell the position a second time.
    #[test]
    fn a_fired_rung_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-exits-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("exit_state.json").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let store = ExitStateStore::load(&p);
        let r = rules();
        assert!(matches!(store.decide(&r, "MINT", 2.5), ExitAction::Sell { .. }));

        let reloaded = ExitStateStore::load(&p);
        assert_eq!(reloaded.decide(&r, "MINT", 2.5), ExitAction::Hold, "must not re-fire");
        assert_eq!(reloaded.peak("MINT"), 2.5, "and the peak is remembered");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn forgetting_a_position_clears_its_ladder() {
        let store = ExitStateStore::ephemeral();
        let r = rules();
        assert!(matches!(store.decide(&r, "M", 2.5), ExitAction::Sell { .. }));
        store.forget("M");
        assert!(matches!(store.decide(&r, "M", 2.5), ExitAction::Sell { .. }), "fresh again");
    }

    #[test]
    fn nothing_happens_while_disabled() {
        let mut s = PositionState::default();
        let off = ExitRules { enabled: false, ..Default::default() };
        assert_eq!(evaluate(&off, &mut s, 10.0), ExitAction::Hold);
        assert_eq!(evaluate(&off, &mut s, 0.01), ExitAction::Hold);
        // …but the peak is still tracked, so enabling it later is not blind.
        assert_eq!(s.peak_multiple, 10.0);
    }

    /// An unpriced token looks identical to a worthless one. Treating the two
    /// the same is how a provider outage becomes a liquidation — the same
    /// confusion that once wrote live tokens into the dataset as rugs.
    #[test]
    fn an_unusable_price_never_sells() {
        let mut s = PositionState::default();
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(evaluate(&rules(), &mut s, bad), ExitAction::Hold, "{bad}");
        }
        assert_eq!(s.peak_multiple, 0.0, "a bad print must not move the peak either");
    }

    #[test]
    fn each_rung_fires_once() {
        let mut s = PositionState::default();
        let r = rules();
        match evaluate(&r, &mut s, 2.1) {
            ExitAction::Sell { pct, .. } => assert_eq!(pct, 50),
            a => panic!("expected the 2x rung, got {a:?}"),
        }
        assert_eq!(evaluate(&r, &mut s, 2.2), ExitAction::Hold, "must not re-fire");
        match evaluate(&r, &mut s, 3.5) {
            ExitAction::Sell { pct, .. } => assert_eq!(pct, 50),
            a => panic!("expected the 3x rung, got {a:?}"),
        }
        match evaluate(&r, &mut s, 5.0) {
            ExitAction::Sell { pct, .. } => assert_eq!(pct, 100),
            a => panic!("expected the 5x rung, got {a:?}"),
        }
        assert_eq!(evaluate(&r, &mut s, 9.0), ExitAction::Hold, "ladder exhausted");
    }

    /// A token that gaps past several rungs takes them in order rather than
    /// dumping the whole position on one print.
    #[test]
    fn a_gap_up_takes_the_lowest_rung_first() {
        let mut s = PositionState::default();
        let r = rules();
        for expected in [50u8, 50, 100] {
            match evaluate(&r, &mut s, 6.0) {
                ExitAction::Sell { pct, .. } => assert_eq!(pct, expected),
                a => panic!("expected a rung, got {a:?}"),
            }
        }
        assert_eq!(evaluate(&r, &mut s, 6.0), ExitAction::Hold);
    }

    #[test]
    fn the_stop_loss_sells_everything() {
        let mut s = PositionState::default();
        let r = rules(); // 50% stop
        assert_eq!(evaluate(&r, &mut s, 0.6), ExitAction::Hold, "above the floor");
        match evaluate(&r, &mut s, 0.5) {
            ExitAction::Sell { pct, reason } => {
                assert_eq!(pct, 100);
                assert!(reason.contains("stop loss"), "{reason}");
            }
            a => panic!("expected a stop loss, got {a:?}"),
        }
    }

    /// The case the ordering exists for: a position that gaps from profit to
    /// deep loss between ticks must leave, not take a profit rung on the way.
    #[test]
    fn a_collapse_exits_rather_than_taking_profit() {
        let mut s = PositionState::default();
        let r = rules();
        evaluate(&r, &mut s, 4.0); // fires the 2x rung, peak now 4
        match evaluate(&r, &mut s, 0.3) {
            ExitAction::Sell { pct, reason } => {
                assert_eq!(pct, 100);
                assert!(reason.contains("stop loss"), "expected protection first: {reason}");
            }
            a => panic!("expected an exit, got {a:?}"),
        }
    }

    #[test]
    fn the_trailing_stop_measures_from_the_peak() {
        let mut s = PositionState::default();
        let r = ExitRules {
            enabled: true,
            trailing_pct: 30,
            stop_loss_pct: 0,
            rungs: [Rung { at_gain_pct: 0, sell_pct: 0 }; 3], // ladder off
            ..Default::default()
        };
        evaluate(&r, &mut s, 4.0);
        assert_eq!(s.peak_multiple, 4.0);
        assert_eq!(evaluate(&r, &mut s, 3.0), ExitAction::Hold, "25% off the peak");
        match evaluate(&r, &mut s, 2.8) {
            ExitAction::Sell { pct, reason } => {
                assert_eq!(pct, 100);
                assert!(reason.contains("trailing"), "{reason}");
            }
            a => panic!("expected a trailing stop, got {a:?}"),
        }
    }

    /// A trailing stop that acted before any profit would just be a second,
    /// looser stop loss — and would close fresh positions on entry slippage.
    #[test]
    fn the_trailing_stop_waits_for_profit() {
        let mut s = PositionState::default();
        let r = ExitRules {
            enabled: true,
            trailing_pct: 10,
            stop_loss_pct: 0,
            rungs: [Rung { at_gain_pct: 0, sell_pct: 0 }; 3],
            ..Default::default()
        };
        assert_eq!(evaluate(&r, &mut s, 0.95), ExitAction::Hold);
        assert_eq!(evaluate(&r, &mut s, 0.85), ExitAction::Hold, "never been in profit");
    }

    #[test]
    fn disarmed_rungs_are_skipped() {
        let mut s = PositionState::default();
        let r = ExitRules {
            enabled: true,
            stop_loss_pct: 0,
            rungs: [
                Rung { at_gain_pct: 0, sell_pct: 50 },    // no trigger set
                Rung { at_gain_pct: 100, sell_pct: 0 },   // sells nothing
                Rung { at_gain_pct: 200, sell_pct: 50 },
            ],
            ..Default::default()
        };
        assert_eq!(evaluate(&r, &mut s, 2.5), ExitAction::Hold);
        assert!(matches!(evaluate(&r, &mut s, 3.0), ExitAction::Sell { pct: 50, .. }));
    }

    #[test]
    fn describe_reads_like_a_policy() {
        assert_eq!(describe(&ExitRules::default()), "off");
        let d = describe(&rules());
        assert!(d.contains("50%@+100%"), "{d}");
        assert!(d.contains("SL -50%"), "{d}");

        // Enabled with nothing configured must not read as protection.
        let hollow = ExitRules {
            enabled: true,
            stop_loss_pct: 0,
            trailing_pct: 0,
            rungs: [Rung { at_gain_pct: 0, sell_pct: 0 }; 3],
            ..Default::default()
        };
        assert_eq!(describe(&hollow), "on, but no rules set");
    }
}
