//! When to sell a position, decided without touching the network.
//!
//! # One list, not two kinds of rule
//!
//! A stop and a target are the same thing: a percentage move from cost, and how
//! much to sell when it happens. A negative trigger is a stop, a positive one a
//! target. Modelling them separately made "add a second stop" impossible and
//! left the amounts unaddable.
//!
//! # Amounts are percentages of the ORIGINAL position
//!
//! This is what makes a ladder legible:
//!
//! ```text
//!   -25% → 100%     stop: close the position
//!   +100% →  50%    takes out your initials, exactly
//!   +250% →  20%
//!   +400% →  20%
//!   +900% →  10%
//!                   ── targets total 100%
//! ```
//!
//! Percent-of-REMAINING was the first design here and it was wrong: those same
//! numbers would leave 28.8% held forever, and "sums to 100%" would mean
//! nothing. Of-original is what makes the column addable and makes "takes out
//! your initials" true rather than approximately true.
//!
//! # The order of checks is the design
//!
//! Stops are evaluated before targets, and at most one order fires per tick. A
//! position that gaps from +300% to −60% between ticks should leave, not take a
//! target on the way past — the target's premise is already false by the time
//! we see it.
//!
//! # What a "multiple" means here
//!
//! `value_now / cost_basis`, both in SOL. 1.0 is break-even before fees. It is
//! NOT the figure on a call alert, which is measured from the smart wallet's
//! own fill — a price a follower could never have paid.

use serde::{Deserialize, Serialize};

/// Most orders one profile may hold. Enough for a stop plus a four-rung ladder
/// with room to spare; small enough that the screen stays tappable.
pub const MAX_ORDERS: usize = 6;

/// One sell order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellOrder {
    /// Trigger, as a percent move from cost. `-25` is a stop at −25%, `100` a
    /// target at +100% (a double).
    pub at_pct: i32,
    /// How much of the ORIGINAL position to sell, in percent.
    pub amount_pct: u8,
}

impl SellOrder {
    pub fn is_armed(&self) -> bool {
        self.at_pct != 0 && (1..=100).contains(&self.amount_pct)
    }

    pub fn is_stop(&self) -> bool {
        self.at_pct < 0
    }

    /// The value/cost ratio this order triggers at.
    pub fn trigger_multiple(&self) -> f64 {
        1.0 + self.at_pct as f64 / 100.0
    }

    pub fn label(&self) -> String {
        let sign = if self.at_pct > 0 { "+" } else { "" };
        format!("{sign}{}% → sell {}%", self.at_pct, self.amount_pct)
    }
}

/// The exit policy applied to every position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitRules {
    /// Master switch. Off means this module observes and never acts.
    pub enabled: bool,
    pub orders: Vec<SellOrder>,
    /// Sell everything once the position falls this far from its PEAK. 0 = off.
    ///
    /// Kept separate because a list of fixed triggers cannot express it: the
    /// level it fires at moves with the position.
    pub trailing_pct: u8,
    /// Sell everything when the pool's liquidity is pulled.
    pub exit_on_liquidity_pull: bool,
}

impl Default for ExitRules {
    fn default() -> Self {
        Self {
            // Off until the operator turns it on. A policy that started enabled
            // would sell real positions on values a config author chose.
            enabled: false,
            orders: vec![
                SellOrder { at_pct: -25, amount_pct: 100 },
                SellOrder { at_pct: 100, amount_pct: 50 },
                SellOrder { at_pct: 250, amount_pct: 20 },
                SellOrder { at_pct: 400, amount_pct: 20 },
                SellOrder { at_pct: 900, amount_pct: 10 },
            ],
            trailing_pct: 0,
            exit_on_liquidity_pull: true,
        }
    }
}

impl ExitRules {
    /// Total of the TARGET amounts. Stops are excluded: a stop closes the
    /// position, so counting it would always read as over 100.
    pub fn target_total_pct(&self) -> u32 {
        self.orders
            .iter()
            .filter(|o| o.is_armed() && !o.is_stop())
            .map(|o| o.amount_pct as u32)
            .sum()
    }

    /// Orders in evaluation order: stops first, then targets lowest-first.
    fn evaluation_order(&self) -> Vec<SellOrder> {
        let mut v: Vec<SellOrder> = self.orders.iter().copied().filter(|o| o.is_armed()).collect();
        v.sort_by_key(|o| (!o.is_stop(), o.at_pct));
        v
    }
}

/// Per-position memory.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PositionState {
    /// Highest multiple observed. The trailing stop measures from this.
    pub peak_multiple: f64,
    /// Triggers already taken, by their `at_pct`.
    ///
    /// Keyed by trigger rather than by list position so that editing the
    /// profile does not silently re-arm an order that already fired, or
    /// suppress a new one because it inherited a used slot.
    pub fired_at: Vec<i32>,
    /// Largest balance seen, in raw units — the base for percent-of-original.
    ///
    /// Largest-ever rather than first-seen because a position can be added to,
    /// and the ladder should measure against the full size rather than whatever
    /// happened to be held the first time it was observed.
    pub original_raw: u64,
}

/// What to do about a position right now.
#[derive(Debug, Clone, PartialEq)]
pub enum ExitAction {
    Hold,
    /// Sell this percentage of the ORIGINAL position. The caller converts it to
    /// a share of the current balance, which is what a sell can act on.
    Sell { amount_pct_of_original: u8, reason: String },
}

/// Decide, and record what was decided.
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

    // Trailing is checked with the stops: it is protective, and its trigger
    // moves, so a target must never pre-empt it.
    if rules.trailing_pct > 0 && state.peak_multiple > 1.0 {
        let trigger = state.peak_multiple * (1.0 - rules.trailing_pct as f64 / 100.0);
        // Only trails once the position has been in profit: measured from a
        // peak of 1.0 it is just a second, looser stop, and would close fresh
        // entries on ordinary slippage.
        if multiple <= trigger {
            return ExitAction::Sell {
                amount_pct_of_original: 100,
                reason: format!(
                    "trailing stop −{}% (peak {:.2}x, now {multiple:.2}x)",
                    rules.trailing_pct, state.peak_multiple
                ),
            };
        }
    }

    for order in rules.evaluation_order() {
        if state.fired_at.contains(&order.at_pct) {
            continue;
        }
        let hit = if order.is_stop() {
            multiple <= order.trigger_multiple()
        } else {
            multiple >= order.trigger_multiple()
        };
        if hit {
            state.fired_at.push(order.at_pct);
            let kind = if order.is_stop() { "stop" } else { "target" };
            return ExitAction::Sell {
                amount_pct_of_original: order.amount_pct,
                reason: format!("{kind} {}", order.label()),
            };
        }
    }

    ExitAction::Hold
}

/// Convert "x% of the original position" into "y% of what is held now", which
/// is what a sell can actually act on.
///
/// Rounds UP and saturates at 100: the alternative leaves a sliver behind on
/// every order, and a ladder that never quite closes its share is worse than
/// one that closes a hair more.
pub fn share_of_current(amount_pct_of_original: u8, original_raw: u64, current_raw: u64) -> u8 {
    if current_raw == 0 || original_raw == 0 {
        return 0;
    }
    let want = (original_raw as u128 * amount_pct_of_original as u128) / 100;
    if want == 0 {
        return 0;
    }
    let pct = (want * 100).div_ceil(current_raw as u128);
    pct.clamp(1, 100) as u8
}

/// A one-line summary for the settings screen.
pub fn describe(rules: &ExitRules) -> String {
    if !rules.enabled {
        return "off".into();
    }
    let armed = rules.orders.iter().filter(|o| o.is_armed()).count();
    if armed == 0 && rules.trailing_pct == 0 {
        // Enabled with nothing configured does nothing, and should read as
        // nothing rather than as protection.
        return "on, no orders".into();
    }
    let mut parts = Vec::new();
    if armed > 0 {
        parts.push(format!("{armed} order{}", if armed == 1 { "" } else { "s" }));
    }
    if rules.trailing_pct > 0 {
        parts.push(format!("trail −{}%", rules.trailing_pct));
    }
    parts.join(" · ")
}


/// A position as the ladder sees it: what it cost, what is held, what it is
/// worth per token.
#[derive(Debug, Clone)]
pub struct Holding {
    pub mint: String,
    pub sol_spent: f64,
    pub raw: u64,
    pub decimals: u32,
    /// SOL per whole token, or `None` if nothing has traded in our window.
    pub price_sol: Option<f64>,
}

/// One decided exit.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedSell {
    pub mint: String,
    /// Share of the CURRENT balance to sell — what a sell can act on.
    pub pct_of_current: u8,
    pub reason: String,
}

/// Decide every exit for a set of holdings, without touching the network.
///
/// Split out of the sweep so the JOIN can be tested — the step that reads a
/// position out of the audit log and hands it to the ladder. That join was
/// broken for smart-money buys (their audit records were skipped by cost-basis
/// parsing) and the failure was invisible: the ladder was correct, the rules
/// were correct, and the list it was given was simply empty. Testing the rules
/// in isolation could never have caught it.
///
/// Returns the sells to make, and the mints whose position is gone and whose
/// ladder state should be forgotten.
pub fn plan_exits(
    rules: &ExitRules,
    state: &ExitStateStore,
    holdings: &[Holding],
) -> (Vec<PlannedSell>, Vec<String>) {
    let mut sells = Vec::new();
    let mut closed = Vec::new();
    if !rules.enabled {
        return (sells, closed);
    }
    for h in holdings {
        if h.raw == 0 {
            // Closed by hand or fully sold: drop the ladder so a re-entry
            // starts fresh rather than inheriting spent orders.
            closed.push(h.mint.clone());
            continue;
        }
        if h.sol_spent <= 0.0 {
            continue;
        }
        let Some(price) = h.price_sol else { continue };
        let tokens = h.raw as f64 / 10f64.powi(h.decimals as i32);
        let multiple = (price * tokens) / h.sol_spent;

        let (action, pct_now) = state.decide(rules, &h.mint, multiple, h.raw);
        if let ExitAction::Sell { reason, .. } = action
            && pct_now > 0
        {
            sells.push(PlannedSell { mint: h.mint.clone(), pct_of_current: pct_now, reason });
        }
    }
    (sells, closed)
}

/// Per-position exit memory, persisted so a restart does not re-take an order
/// already taken or forget the peak a trailing stop measures from.
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

    /// Evaluate one position, remembering the balance it is measured against.
    ///
    /// Returns the action together with the share of the CURRENT balance to
    /// sell, so the caller never has to redo the of-original arithmetic.
    pub fn decide(
        &self,
        rules: &ExitRules,
        mint: &str,
        multiple: f64,
        current_raw: u64,
    ) -> (ExitAction, u8) {
        let (action, pct_now) = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let st = g.entry(mint.to_string()).or_default();
            if current_raw > st.original_raw {
                st.original_raw = current_raw;
            }
            let action = evaluate(rules, st, multiple);
            let pct_now = match &action {
                ExitAction::Sell { amount_pct_of_original, .. } => {
                    share_of_current(*amount_pct_of_original, st.original_raw, current_raw)
                }
                ExitAction::Hold => 0,
            };
            (action, pct_now)
        };
        // Persist on any state change. An order recorded as fired but never
        // saved would fire again after a restart and sell the position twice.
        self.save();
        (action, pct_now)
    }

    /// Forget a position, e.g. once fully sold.
    pub fn forget(&self, mint: &str) {
        let existed =
            self.inner.lock().unwrap_or_else(|p| p.into_inner()).remove(mint).is_some();
        if existed {
            self.save();
        }
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

    // --- The join: audit record -> position -> ladder.
    //
    // This is the layer that failed in production. The rules were right, the
    // ladder was right, and the list handed to it was empty — so nothing sold,
    // through a +150% peak and all the way down to zero.

    fn holding(mint: &str, sol_spent: f64, raw: u64, price: Option<f64>) -> Holding {
        Holding { mint: mint.into(), sol_spent, raw, decimals: 6, price_sol: price }
    }

    /// A smart-money buy must reach the ladder. The audit shape it is written
    /// in was skipped by cost-basis parsing, which made the position invisible.
    #[test]
    fn a_smart_money_position_reaches_the_ladder() {
        let log = r#"{"ts":"2026-08-16T01:00:00Z","action":"smart_buy","mint":"MINT_A","sol":0.05,"outcome":"confirmed:abc","mode":"armed"}"#;
        let basis = crate::positions::cost_basis_from_audit(log);
        let cost = basis.get("MINT_A").expect("the position must exist at all").sol_spent;

        // Bought 1,000,000 tokens for 0.05 SOL; now worth 2.5x.
        let raw = 1_000_000_000_000u64; // 1e6 tokens at 6 decimals
        let entry_price = cost / 1_000_000.0;
        let now_price = entry_price * 2.5;

        let store = ExitStateStore::ephemeral();
        let (sells, _) = plan_exits(
            &ExitRules { enabled: true, ..Default::default() },
            &store,
            &[holding("MINT_A", cost, raw, Some(now_price))],
        );
        assert_eq!(sells.len(), 1, "the +100% target should have fired");
        assert_eq!(sells[0].pct_of_current, 50);
    }

    /// The failure exactly as it happened: up 150%, then down through the stop.
    /// Both must act.
    #[test]
    fn a_run_up_then_a_collapse_both_fire() {
        let store = ExitStateStore::ephemeral();
        let rules = ExitRules { enabled: true, ..Default::default() };
        let raw = 1_000_000_000_000u64;
        let cost = 0.05;
        let entry = cost / 1_000_000.0;

        // +150%: the +100% target takes half.
        let (sells, _) = plan_exits(&rules, &store, &[holding("M", cost, raw, Some(entry * 2.5))]);
        assert_eq!(sells.len(), 1, "take-profit must fire on the way up");
        assert!(sells[0].reason.contains("target"), "{}", sells[0].reason);

        // Then it collapses. Half is already sold, so the stop closes the rest.
        let left = raw / 2;
        let (sells, _) = plan_exits(&rules, &store, &[holding("M", cost, left, Some(entry * 0.3))]);
        assert_eq!(sells.len(), 1, "the stop must fire on the way down");
        assert_eq!(sells[0].pct_of_current, 100);
        assert!(sells[0].reason.contains("stop"), "{}", sells[0].reason);
    }

    /// A rehearsal is not a position, so nothing is ever sold from a dry run.
    #[test]
    fn a_dry_run_never_produces_something_to_sell() {
        let log = r#"{"ts":"2026-08-16T01:00:00Z","action":"smart_buy","mint":"M","sol":0.05,"outcome":"would-succeed","mode":"dry_run"}"#;
        assert!(crate::positions::cost_basis_from_audit(log).is_empty());
    }

    /// An unpriced position is left alone. The whole point of gathering the
    /// price separately is that "we could not price it" must not read as "it is
    /// worthless" — that confusion has already cost this project a dataset.
    #[test]
    fn an_unpriced_position_is_never_sold() {
        let store = ExitStateStore::ephemeral();
        let (sells, closed) = plan_exits(
            &ExitRules { enabled: true, ..Default::default() },
            &store,
            &[holding("M", 0.05, 1_000_000_000_000, None)],
        );
        assert!(sells.is_empty());
        assert!(closed.is_empty(), "and it is still a position");
    }

    /// A position that is gone releases its ladder, so a re-entry starts fresh
    /// rather than inheriting spent orders.
    #[test]
    fn a_closed_position_is_forgotten() {
        let store = ExitStateStore::ephemeral();
        let (sells, closed) = plan_exits(
            &ExitRules { enabled: true, ..Default::default() },
            &store,
            &[holding("M", 0.05, 0, Some(1.0))],
        );
        assert!(sells.is_empty());
        assert_eq!(closed, vec!["M".to_string()]);
    }

    /// Disabled means disabled, whatever the prices are doing.
    #[test]
    fn nothing_is_planned_while_auto_sell_is_off() {
        let store = ExitStateStore::ephemeral();
        let (sells, _) = plan_exits(
            &ExitRules::default(),
            &store,
            &[holding("M", 0.05, 1_000_000_000_000, Some(1.0))],
        );
        assert!(sells.is_empty());
    }
    use super::*;

    fn rules() -> ExitRules {
        ExitRules { enabled: true, ..Default::default() }
    }

    #[test]
    fn nothing_happens_while_disabled() {
        let mut s = PositionState::default();
        let off = ExitRules::default();
        assert_eq!(evaluate(&off, &mut s, 10.0), ExitAction::Hold);
        assert_eq!(evaluate(&off, &mut s, 0.01), ExitAction::Hold);
        assert_eq!(s.peak_multiple, 10.0, "the peak is still tracked");
    }

    /// An unpriced token looks identical to a worthless one. Treating the two
    /// the same is how a provider outage becomes a liquidation.
    #[test]
    fn an_unusable_price_never_sells() {
        let mut s = PositionState::default();
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(evaluate(&rules(), &mut s, bad), ExitAction::Hold, "{bad}");
        }
        assert_eq!(s.peak_multiple, 0.0, "a bad print must not move the peak");
    }

    /// The default profile is the worked example, and its target column has to
    /// add to exactly 100 or the ladder leaves a remainder.
    #[test]
    fn the_default_ladder_sells_the_whole_position() {
        assert_eq!(rules().target_total_pct(), 100);
    }

    #[test]
    fn targets_fire_lowest_first_and_only_once() {
        let mut s = PositionState::default();
        let r = rules();
        for expected in [50u8, 20, 20, 10] {
            match evaluate(&r, &mut s, 11.0) {
                ExitAction::Sell { amount_pct_of_original, .. } => {
                    assert_eq!(amount_pct_of_original, expected)
                }
                a => panic!("expected a target, got {a:?}"),
            }
        }
        assert_eq!(evaluate(&r, &mut s, 11.0), ExitAction::Hold, "ladder exhausted");
    }

    #[test]
    fn a_stop_closes_the_position() {
        let mut s = PositionState::default();
        let r = rules(); // −25% stop
        assert_eq!(evaluate(&r, &mut s, 0.80), ExitAction::Hold, "above the stop");
        match evaluate(&r, &mut s, 0.75) {
            ExitAction::Sell { amount_pct_of_original, reason } => {
                assert_eq!(amount_pct_of_original, 100);
                assert!(reason.contains("stop"), "{reason}");
            }
            a => panic!("expected a stop, got {a:?}"),
        }
    }

    /// The case the ordering exists for: a collapse must exit rather than take
    /// a target on the way past.
    #[test]
    fn a_collapse_exits_rather_than_taking_a_target() {
        let mut s = PositionState::default();
        let r = rules();
        evaluate(&r, &mut s, 4.0);
        match evaluate(&r, &mut s, 0.3) {
            ExitAction::Sell { amount_pct_of_original, reason } => {
                assert_eq!(amount_pct_of_original, 100);
                assert!(reason.contains("stop"), "expected protection first: {reason}");
            }
            a => panic!("expected an exit, got {a:?}"),
        }
    }

    #[test]
    fn the_trailing_stop_measures_from_the_peak() {
        let mut s = PositionState::default();
        let r = ExitRules { enabled: true, orders: vec![], trailing_pct: 30, ..Default::default() };
        evaluate(&r, &mut s, 4.0);
        assert_eq!(evaluate(&r, &mut s, 3.0), ExitAction::Hold, "25% off the peak");
        match evaluate(&r, &mut s, 2.8) {
            ExitAction::Sell { amount_pct_of_original, reason } => {
                assert_eq!(amount_pct_of_original, 100);
                assert!(reason.contains("trailing"), "{reason}");
            }
            a => panic!("expected a trailing stop, got {a:?}"),
        }
    }

    #[test]
    fn the_trailing_stop_waits_for_profit() {
        let mut s = PositionState::default();
        let r = ExitRules { enabled: true, orders: vec![], trailing_pct: 10, ..Default::default() };
        assert_eq!(evaluate(&r, &mut s, 0.95), ExitAction::Hold);
        assert_eq!(evaluate(&r, &mut s, 0.85), ExitAction::Hold, "never been in profit");
    }

    /// Editing a profile must not re-arm an order that already fired, nor
    /// suppress a new one because it landed in a used slot.
    #[test]
    fn fired_orders_are_tracked_by_trigger_not_by_slot() {
        let mut s = PositionState::default();
        let mut r = ExitRules {
            enabled: true,
            orders: vec![SellOrder { at_pct: 100, amount_pct: 50 }],
            ..Default::default()
        };
        assert!(matches!(evaluate(&r, &mut s, 2.5), ExitAction::Sell { .. }));
        assert_eq!(evaluate(&r, &mut s, 2.5), ExitAction::Hold);

        r.orders[0] = SellOrder { at_pct: 120, amount_pct: 25 };
        match evaluate(&r, &mut s, 2.5) {
            ExitAction::Sell { amount_pct_of_original, .. } => {
                assert_eq!(amount_pct_of_original, 25)
            }
            a => panic!("an edited order should be live again, got {a:?}"),
        }
    }

    #[test]
    fn disarmed_orders_are_skipped() {
        let mut s = PositionState::default();
        let r = ExitRules {
            enabled: true,
            orders: vec![
                SellOrder { at_pct: 0, amount_pct: 50 },   // no trigger
                SellOrder { at_pct: 100, amount_pct: 0 },  // sells nothing
                SellOrder { at_pct: 200, amount_pct: 50 },
            ],
            ..Default::default()
        };
        assert_eq!(evaluate(&r, &mut s, 2.5), ExitAction::Hold);
        assert!(matches!(evaluate(&r, &mut s, 3.0), ExitAction::Sell { .. }));
    }

    /// The conversion that makes percent-of-original work against a shrinking
    /// balance. After selling half, "20% of original" is 40% of what is left.
    #[test]
    fn a_share_of_the_original_converts_to_a_share_of_what_is_left() {
        assert_eq!(share_of_current(50, 1_000, 1_000), 50, "untouched position");
        assert_eq!(share_of_current(20, 1_000, 500), 40, "half already sold");
        assert_eq!(share_of_current(10, 1_000, 100), 100, "the rest is all there is");
        assert_eq!(share_of_current(100, 1_000, 250), 100, "saturates, never over-asks");
        assert_eq!(share_of_current(50, 0, 100), 0, "no basis, no order");
        assert_eq!(share_of_current(50, 100, 0), 0, "nothing held");
    }

    #[test]
    fn the_conversion_rounds_up_rather_than_leaving_dust() {
        assert_eq!(share_of_current(1, 1_000, 999), 2);
        assert!(share_of_current(33, 1_000, 999) >= 33);
    }

    #[test]
    fn stops_do_not_count_toward_the_target_total() {
        let r = ExitRules {
            enabled: true,
            orders: vec![
                SellOrder { at_pct: -25, amount_pct: 100 },
                SellOrder { at_pct: 100, amount_pct: 60 },
            ],
            ..Default::default()
        };
        assert_eq!(r.target_total_pct(), 60, "a stop closes the position, it is not a rung");
    }

    #[test]
    fn describe_reads_like_a_policy() {
        assert_eq!(describe(&ExitRules::default()), "off");
        assert_eq!(describe(&rules()), "5 orders");
        let t = ExitRules { enabled: true, orders: vec![], trailing_pct: 30, ..Default::default() };
        assert_eq!(describe(&t), "trail −30%");
        let hollow = ExitRules { enabled: true, orders: vec![], ..Default::default() };
        assert_eq!(describe(&hollow), "on, no orders");
    }

    /// An order recorded as fired but never saved would fire again after a
    /// restart and sell the position a second time.
    #[test]
    fn a_fired_order_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-exits-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("exit_state.json").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let store = ExitStateStore::load(&p);
        let r = rules();
        let (a, pct) = store.decide(&r, "MINT", 2.5, 1_000);
        assert!(matches!(a, ExitAction::Sell { .. }));
        assert_eq!(pct, 50, "a full position: of-original and of-current agree");

        let reloaded = ExitStateStore::load(&p);
        // Half sold, so the +250% order's 20%-of-original is 40% of the rest.
        let (a2, pct2) = reloaded.decide(&r, "MINT", 3.5, 500);
        assert!(matches!(a2, ExitAction::Sell { .. }), "the next target should fire");
        assert_eq!(pct2, 40);
        assert_eq!(reloaded.peak("MINT"), 3.5);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn forgetting_a_position_clears_its_ladder() {
        let store = ExitStateStore::ephemeral();
        let r = rules();
        assert!(matches!(store.decide(&r, "M", 2.5, 100).0, ExitAction::Sell { .. }));
        store.forget("M");
        assert!(matches!(store.decide(&r, "M", 2.5, 100).0, ExitAction::Sell { .. }), "fresh again");
    }

    /// The position that exposed the whole problem.
    ///
    /// The stream index priced it as +25% and the ladder fired a take-profit.
    /// A real quote said the same tokens would return 0.006875 SOL against a
    /// 0.010 basis — the position was DOWN 31%, and the stop-loss should have
    /// been the thing that fired.
    ///
    /// So the ladder is fed the REALIZABLE price now. Given that price, this is
    /// unambiguous: a stop, not a target. Nothing is vetoed, nothing waits for
    /// confirmation — the decision is simply made against a number that is true.
    #[test]
    fn a_position_that_is_really_down_fires_the_stop_not_the_target() {
        let rules = ExitRules {
            enabled: true,
            orders: vec![
                SellOrder { at_pct: -15, amount_pct: 100 },
                SellOrder { at_pct: 25, amount_pct: 100 },
            ],
            ..Default::default()
        };
        let store = ExitStateStore::ephemeral();
        // 0.010 SOL basis, 1.0 whole token, realizable 0.006875 -> -31%.
        let h = holding("M", 0.010, 1_000_000, Some(0.006875));
        let (sells, _) = plan_exits(&rules, &store, &[h]);
        assert_eq!(sells.len(), 1, "the position must be acted on, not skipped");
        assert_eq!(sells[0].pct_of_current, 100);
        assert!(
            sells[0].reason.contains("-15") || sells[0].reason.to_lowercase().contains("stop"),
            "must be the STOP, not a take-profit; got: {}",
            sells[0].reason
        );
    }

    /// And the mirror: a position genuinely up takes the target.
    #[test]
    fn a_position_that_is_really_up_takes_the_target() {
        let rules = ExitRules {
            enabled: true,
            orders: vec![
                SellOrder { at_pct: -15, amount_pct: 100 },
                SellOrder { at_pct: 25, amount_pct: 100 },
            ],
            ..Default::default()
        };
        let store = ExitStateStore::ephemeral();
        let h = holding("M", 0.010, 1_000_000, Some(0.0125)); // +25% realizable
        let (sells, _) = plan_exits(&rules, &store, &[h]);
        assert_eq!(sells.len(), 1);
        assert!(
            sells[0].reason.contains("25"),
            "must be the target; got: {}",
            sells[0].reason
        );
    }
}
