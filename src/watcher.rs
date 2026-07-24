//! Delayed follow-up check on a detected pool.
//!
//! WHY THIS EXISTS: LP burn/lock is almost always a *separate, later*
//! transaction, not part of pool creation. Measured on mainnet: one verified
//! PumpSwap pool had its LP burned 479 seconds (~8 min) after creation; a
//! verified Raydium CPMM pool never burned LP at all (its LP mint has exactly
//! one transaction — the creation).
//!
//! So LP custody is NOT knowable at detection time. A synchronous filter shaped
//! like the liquidity/safety checks would reject legitimate launches that burn
//! moments later. Instead we re-read after a delay and emit a follow-up.
//!
//! The re-read also catches the thing that actually costs money: liquidity being
//! pulled shortly after launch.

use crate::alerts::Alerter;
use crate::config::WatchConfig;
use crate::metrics::Metrics;
use crate::model::PoolEvent;
use crate::rpc::RpcClient;
use crate::storage::Storage;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Outcome of the delayed re-check.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Quote-side liquidity fell by at least the configured fraction.
    LiquidityPulled { before: f64, after: f64, drop_pct: f64 },
    /// Quote-side liquidity GREW by at least the configured amount — net buy
    /// inflow. The alpha/momentum signal: real money committed after launch.
    VolumeSpike { before: f64, after: f64, growth: f64 },
    /// LP supply fell to ~zero — the LP tokens were destroyed.
    LpBurned,
    /// LP still outstanding and liquidity intact.
    LpOutstanding { liquidity: Option<f64> },
    /// Nothing could be read.
    Unknown,
}

impl Verdict {
    /// Should this outcome be alerted on? Routine "still fine" results are
    /// suppressed by default so follow-ups don't become their own noise. A
    /// volume spike IS notable — it is the signal you actually want to act on.
    pub fn is_notable(&self) -> bool {
        matches!(
            self,
            Verdict::LiquidityPulled { .. } | Verdict::VolumeSpike { .. } | Verdict::LpBurned
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Verdict::LiquidityPulled { .. } => "🚨 LIQUIDITY PULLED",
            Verdict::VolumeSpike { .. } => "📈 VOLUME SPIKE",
            Verdict::LpBurned => "🔥 LP burned",
            Verdict::LpOutstanding { .. } => "LP outstanding",
            Verdict::Unknown => "unknown",
        }
    }
}

/// Decide the verdict from before/after readings. Pure, so it is unit-testable
/// without any network.
/// Is the LP supply burned (or otherwise gone to ~zero)?
///
/// Kept separate from `evaluate` on purpose: `evaluate` collapses to a SINGLE
/// verdict with precedence, so a pool that burned its LP *and* drew volume
/// reports `VolumeSpike` and the burn is invisible. Alert filtering needs the
/// burn as an independent fact, not a verdict that a higher-priority signal can
/// mask. Guards against calling a burn when there was no "before" reading.
pub fn lp_is_burned(lp_supply_before: Option<f64>, lp_supply_after: Option<f64>) -> bool {
    matches!(lp_supply_after, Some(after)
        if after <= f64::EPSILON && lp_supply_before.is_some_and(|b| b > 0.0))
}

pub fn evaluate(
    liquidity_before: Option<f64>,
    liquidity_after: Option<f64>,
    lp_supply_before: Option<f64>,
    lp_supply_after: Option<f64>,
    rug_drop_pct: f64,
    min_volume_growth: f64,
) -> Verdict {
    if let (Some(before), Some(after)) = (liquidity_before, liquidity_after) {
        // Liquidity pull takes precedence: it is the outcome that costs money.
        if before > 0.0 {
            let drop = (before - after) / before;
            if drop >= rug_drop_pct {
                return Verdict::LiquidityPulled { before, after, drop_pct: drop * 100.0 };
            }
        }
        // Volume spike: the quote vault grew because buyers added quote and took
        // token. Net growth over the window is net buy inflow. Ranked above the
        // burn because it is the actionable signal. `min_volume_growth == 0`
        // disables it.
        if min_volume_growth > 0.0 {
            let growth = after - before;
            if growth >= min_volume_growth {
                return Verdict::VolumeSpike { before, after, growth };
            }
        }
    }

    if lp_is_burned(lp_supply_before, lp_supply_after) {
        return Verdict::LpBurned;
    }

    if lp_supply_after.is_some() || liquidity_after.is_some() {
        return Verdict::LpOutstanding { liquidity: liquidity_after };
    }
    Verdict::Unknown
}

/// Handle to the sniper, for Guard-mode entries. A unit type in builds without
/// the execution feature so the call site is identical either way.
#[cfg(feature = "sniper")]
pub type SniperHandle = Option<Arc<crate::sniper::Sniper>>;
#[cfg(not(feature = "sniper"))]
pub type SniperHandle = ();

/// Schedule the follow-up watch. Returns immediately; the work happens in a task.
#[allow(clippy::too_many_arguments)]
pub fn spawn_watch(
    event: PoolEvent,
    rpc: Arc<RpcClient>,
    alerter: Arc<Alerter>,
    storage: Arc<Storage>,
    metrics: Arc<Metrics>,
    cfg: WatchConfig,
    sniper: SniperHandle,
) {
    tokio::spawn(async move {
        // Two phases, because LP burn is a LATER transaction than pool creation
        // (measured ~479s on a real PumpSwap pool). A single check at
        // `delay_secs` would miss most burns and the pool would never be
        // announced at all.
        //
        //  1. BEFORE secured — poll for the burn. Nothing is announced. Pools
        //     that never secure are dropped silently: that is the noise filter.
        //  2. AFTER secured  — the pool is announced once, then kept under
        //     watch so further buy inflow on a *secured* token still alerts.
        //
        // A liquidity pull ends the watch at any point and always alerts.
        let baseline_liq = event.quote_liquidity;
        let lp_before = event.lp_supply_at_detection;
        let mut secured = false;
        // Growth is measured from here; reset on each volume alert so the same
        // inflow is not reported over and over.
        let mut volume_mark = baseline_liq;
        let mut elapsed = cfg.delay_secs;

        tokio::time::sleep(Duration::from_secs(cfg.delay_secs)).await;

        loop {
            let liquidity_now = match event.quote_asset_vault.as_deref() {
                Some(v) => rpc.vault_balance(v).await,
                None => None,
            };
            // Once burned, LP cannot un-burn — stop paying for that read.
            let lp_now = if secured {
                None
            } else {
                match event.lp_mint.as_deref() {
                    Some(m) => rpc.token_supply(m).await,
                    None => None,
                }
            };

            // --- Rug: takes precedence and ends the watch.
            //
            // Only ALERT the group if the pool was actually announced (secured),
            // or if we're not in secured-only mode. A pull on a pool that never
            // secured is a rug on a token the group was deliberately never told
            // about — announcing it is exactly the noise secured-only mode
            // exists to remove. Still logged and persisted locally either way.
            if let (Some(before), Some(after)) = (baseline_liq, liquidity_now)
                && before > 0.0
                && (before - after) / before >= cfg.rug_drop_pct
            {
                let drop_pct = (before - after) / before * 100.0;
                metrics.incr(&metrics.rug_detected);
                warn!(
                    pool = %event.pool,
                    token = event.new_token_mint.as_deref().unwrap_or("?"),
                    before, after, drop_pct, after_secs = elapsed, announced = secured,
                    "🚨 liquidity pulled"
                );
                let verdict = Verdict::LiquidityPulled { before, after, drop_pct };
                let mut f = event.clone();
                f.quote_liquidity = liquidity_now;
                storage.record_followup(&f, verdict.label()).await;
                if secured || !cfg.alert_only_secured_lp {
                    alerter
                        .send_html(render_followup(&event, &verdict, liquidity_now, elapsed))
                        .await;
                }
                return;
            }

            // --- LP secured: the moment the pool becomes announceable.
            if !secured && lp_is_burned(lp_before, lp_now) {
                secured = true;
                metrics.incr(&metrics.lp_burned);
                info!(pool = %event.pool, after_secs = elapsed, "🔥 LP burned / secured");
                let mut f = event.clone();
                f.quote_liquidity = liquidity_now;
                storage.record_followup(&f, Verdict::LpBurned.label()).await;
                alerter
                    .send_html(render_followup(&event, &Verdict::LpBurned, liquidity_now, elapsed))
                    .await;

                // GUARD MODE ENTRY: buy only now that LP is confirmed secured,
                // sized against freshly re-read liquidity rather than detection.
                #[cfg(feature = "sniper")]
                if let Some(s) = &sniper
                    && s.snipe_mode() == crate::sniper::SnipeMode::Guard
                {
                    let mut confirmed = event.clone();
                    confirmed.quote_liquidity = liquidity_now;
                    let exec = s.handle(&confirmed).await;
                    if exec.is_alertable(false)
                        && let Some(msg) = crate::alerts::render_execution(&exec)
                    {
                        alerter.send_html(msg).await;
                    }
                }

                // Measure later volume from the moment of securing.
                if liquidity_now.is_some() {
                    volume_mark = liquidity_now;
                }
            }

            // --- Volume, for SECURED pools only. Unsecured pools are never
            // announced, so a spike on one would be noise about a token the
            // group was deliberately not told about.
            if secured
                && cfg.min_volume_growth_sol > 0.0
                && let (Some(mark), Some(now)) = (volume_mark, liquidity_now)
                && now - mark >= cfg.min_volume_growth_sol
            {
                let growth = now - mark;
                metrics.incr(&metrics.volume_confirmed);
                info!(
                    pool = %event.pool,
                    token = event.new_token_mint.as_deref().unwrap_or("?"),
                    before = mark, after = now, growth, after_secs = elapsed,
                    "📈 volume spike on secured pool"
                );
                let verdict = Verdict::VolumeSpike { before: mark, after: now, growth };
                let mut f = event.clone();
                f.quote_liquidity = liquidity_now;
                storage.record_followup(&f, verdict.label()).await;
                alerter
                    .send_html(render_followup(&event, &verdict, liquidity_now, elapsed))
                    .await;
                volume_mark = liquidity_now;
            }

            if elapsed >= cfg.max_watch_secs {
                if !secured {
                    info!(
                        pool = %event.pool,
                        watched_secs = elapsed,
                        "LP never secured — dropping without announcing"
                    );
                }
                return;
            }
            let step = cfg.recheck_interval_secs.max(1);
            tokio::time::sleep(Duration::from_secs(step)).await;
            elapsed += step;
        }
    });
}

fn render_followup(
    ev: &PoolEvent,
    verdict: &Verdict,
    liquidity_after: Option<f64>,
    delay_secs: u64,
) -> String {
    let detail = match verdict {
        Verdict::LiquidityPulled { before, after, drop_pct } => format!(
            "<b>Liquidity:</b> {before:.3} → {after:.3} (<b>-{drop_pct:.1}%</b>)\n"
        ),
        Verdict::VolumeSpike { before, after, growth } => format!(
            "<b>Liquidity:</b> {before:.3} → {after:.3} (<b>+{growth:.3} net buys</b>)\n"
        ),
        _ => match liquidity_after {
            Some(v) => format!("<b>Liquidity:</b> {v:.3}\n"),
            None => String::new(),
        },
    };
    let token = ev
        .new_token_mint
        .as_deref()
        .map(|m| format!("<b>Token:</b> <code>{m}</code>\n"))
        .unwrap_or_default();

    format!(
        "{head} — {dex}  (+{delay_secs}s)\n{token}{detail}<b>Pool:</b> <code>{pool}</code>\n\
         <a href=\"{link}\">pool</a>",
        head = verdict.label(),
        dex = ev.dex.label(),
        pool = ev.pool,
        link = ev.solscan_pool(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_liquidity_pull() {
        let v = evaluate(Some(10.0), Some(0.5), Some(100.0), Some(100.0), 0.5, 0.0);
        match v {
            Verdict::LiquidityPulled { before, after, drop_pct } => {
                assert_eq!(before, 10.0);
                assert_eq!(after, 0.5);
                assert!((drop_pct - 95.0).abs() < 1e-9);
            }
            other => panic!("expected pull, got {other:?}"),
        }
    }

    #[test]
    fn small_drop_is_not_a_pull() {
        // Normal trading moves the vault; only a large drop counts.
        let v = evaluate(Some(10.0), Some(9.0), Some(100.0), Some(100.0), 0.5, 0.0);
        assert!(matches!(v, Verdict::LpOutstanding { .. }));
    }

    /// The volume signal: the quote vault grew past the threshold = net buy
    /// inflow. This is the alpha filter Yianni asked for.
    #[test]
    fn detects_volume_spike() {
        // Launched at 15 SOL, grew to 22 → +7 net buys, threshold 5.
        let v = evaluate(Some(15.0), Some(22.0), Some(100.0), Some(100.0), 0.5, 5.0);
        match v {
            Verdict::VolumeSpike { before, after, growth } => {
                assert_eq!(before, 15.0);
                assert_eq!(after, 22.0);
                assert!((growth - 7.0).abs() < 1e-9);
            }
            other => panic!("expected volume spike, got {other:?}"),
        }
    }

    /// Growth below the threshold is not a spike — a dead pool that drifted up a
    /// little must not fire the signal.
    #[test]
    fn small_growth_is_not_a_spike() {
        let v = evaluate(Some(15.0), Some(17.0), Some(100.0), Some(100.0), 0.5, 5.0);
        assert!(matches!(v, Verdict::LpOutstanding { .. }), "got {v:?}");
    }

    /// A pull outranks a spike: even if the vault ended higher for a moment, a
    /// drop past the rug threshold is the outcome that matters. (Here growth is
    /// negative, so only the pull branch can fire.)
    #[test]
    fn pull_outranks_spike() {
        let v = evaluate(Some(20.0), Some(5.0), Some(100.0), Some(100.0), 0.5, 5.0);
        assert!(matches!(v, Verdict::LiquidityPulled { .. }));
    }

    /// A spike outranks a burn: when a pool both locked LP and drew buys, the
    /// actionable signal (buys) surfaces.
    #[test]
    fn spike_outranks_burn() {
        let v = evaluate(Some(10.0), Some(20.0), Some(450.0), Some(0.0), 0.5, 5.0);
        assert!(matches!(v, Verdict::VolumeSpike { .. }), "got {v:?}");
    }

    /// `min_volume_growth == 0` disables the signal entirely (opt-out).
    #[test]
    fn zero_threshold_disables_volume_signal() {
        let v = evaluate(Some(10.0), Some(50.0), Some(100.0), Some(100.0), 0.5, 0.0);
        assert!(matches!(v, Verdict::LpOutstanding { .. }), "got {v:?}");
    }

    #[test]
    fn volume_spike_is_notable() {
        assert!(Verdict::VolumeSpike { before: 10.0, after: 20.0, growth: 10.0 }.is_notable());
    }

    #[test]
    fn detects_lp_burn() {
        assert_eq!(
            evaluate(Some(10.0), Some(10.0), Some(450.0), Some(0.0), 0.5, 0.0),
            Verdict::LpBurned
        );
    }

    /// A pull outranks a burn: if both happened, the money already left.
    #[test]
    fn liquidity_pull_takes_precedence_over_burn() {
        let v = evaluate(Some(10.0), Some(0.0), Some(450.0), Some(0.0), 0.5, 0.0);
        assert!(matches!(v, Verdict::LiquidityPulled { .. }));
    }

    /// Without a "before" supply we cannot claim a burn — an LP mint that was
    /// always zero is not evidence of anything.
    #[test]
    fn zero_supply_without_baseline_is_not_a_burn() {
        let v = evaluate(Some(10.0), Some(10.0), None, Some(0.0), 0.5, 0.0);
        assert!(matches!(v, Verdict::LpOutstanding { .. }));
    }

    #[test]
    fn nothing_readable_is_unknown() {
        assert_eq!(evaluate(None, None, None, None, 0.5, 0.0), Verdict::Unknown);
    }

    /// Zero liquidity at detection must not cause a divide-by-zero verdict.
    #[test]
    fn zero_baseline_liquidity_is_safe() {
        let v = evaluate(Some(0.0), Some(0.0), Some(1.0), Some(1.0), 0.5, 0.0);
        assert!(matches!(v, Verdict::LpOutstanding { .. }));
    }

    #[test]
    fn routine_outcomes_are_not_alerted() {
        assert!(!Verdict::LpOutstanding { liquidity: Some(1.0) }.is_notable());
        assert!(!Verdict::Unknown.is_notable());
        assert!(Verdict::LpBurned.is_notable());
        assert!(Verdict::LiquidityPulled { before: 1.0, after: 0.0, drop_pct: 100.0 }.is_notable());
    }

    #[test]
    fn lp_burn_needs_a_before_reading() {
        // Supply gone to zero, with a real "before": a genuine burn.
        assert!(lp_is_burned(Some(1_000.0), Some(0.0)));
        // No "before" reading — an LP mint that was always empty is NOT a burn.
        assert!(!lp_is_burned(None, Some(0.0)));
        // Still outstanding.
        assert!(!lp_is_burned(Some(1_000.0), Some(1_000.0)));
        // Unreadable after.
        assert!(!lp_is_burned(Some(1_000.0), None));
    }

    /// The reason `lp_is_burned` exists separately: `evaluate` ranks a volume
    /// spike ABOVE a burn, so a pool that burned LP *and* drew volume reports
    /// VolumeSpike. Filtering on the verdict alone would drop exactly the best
    /// pools — secured LP *and* real buying.
    #[test]
    fn volume_spike_masks_the_burn_in_the_verdict_but_not_the_signal() {
        let v = evaluate(Some(10.0), Some(100.0), Some(1_000.0), Some(0.0), 0.5, 5.0);
        assert!(
            matches!(v, Verdict::VolumeSpike { .. }),
            "volume outranks burn in the collapsed verdict"
        );
        assert!(
            lp_is_burned(Some(1_000.0), Some(0.0)),
            "but the burn is still true, and secured-LP filtering must see it"
        );
    }
}
