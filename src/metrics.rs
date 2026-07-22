//! Lightweight counters, logged periodically. Useful when tuning filters:
//! if `filtered_out` dwarfs `detected`, the quote-pair filter is doing the work;
//! if `parsed` is ~0 the layouts or discriminators are wrong.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tracing::info;

#[derive(Default)]
pub struct Metrics {
    /// Transactions received from the stream (post vote/failed filtering).
    pub tx_seen: AtomicU64,
    /// Pool-creation instructions successfully decoded.
    pub parsed: AtomicU64,
    /// Dropped because the pair had no recognized quote asset.
    pub filtered_out: AtomicU64,
    /// Dropped as a duplicate of a pool already seen within the TTL.
    pub duplicates: AtomicU64,
    /// Dropped because quote-side liquidity was below the threshold.
    pub low_liquidity_filtered: AtomicU64,
    /// Dropped by the mint-safety checks (live authority / risky extension).
    pub unsafe_mint_filtered: AtomicU64,
    /// Emitted to storage + alerts.
    pub detected: AtomicU64,
    /// Follow-up found quote liquidity largely gone.
    pub rug_detected: AtomicU64,
    /// Follow-up found LP supply burned to zero.
    pub lp_burned: AtomicU64,
    /// Follow-up found net buy inflow above the threshold — the volume signal.
    pub volume_confirmed: AtomicU64,
}

impl Metrics {
    pub fn incr(&self, field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }

    /// Point-in-time copy of every counter. Public so the Telegram command bot
    /// can serve `/status` and `/metrics` from the same source the periodic
    /// reporter uses — two counter sets would drift.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            tx_seen: self.tx_seen.load(Ordering::Relaxed),
            parsed: self.parsed.load(Ordering::Relaxed),
            filtered_out: self.filtered_out.load(Ordering::Relaxed),
            duplicates: self.duplicates.load(Ordering::Relaxed),
            low_liquidity: self.low_liquidity_filtered.load(Ordering::Relaxed),
            unsafe_mint: self.unsafe_mint_filtered.load(Ordering::Relaxed),
            detected: self.detected.load(Ordering::Relaxed),
            rug_detected: self.rug_detected.load(Ordering::Relaxed),
            lp_burned: self.lp_burned.load(Ordering::Relaxed),
            volume_confirmed: self.volume_confirmed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Snapshot {
    pub tx_seen: u64,
    pub parsed: u64,
    pub filtered_out: u64,
    pub duplicates: u64,
    pub low_liquidity: u64,
    pub unsafe_mint: u64,
    pub detected: u64,
    pub rug_detected: u64,
    pub lp_burned: u64,
    pub volume_confirmed: u64,
}

/// Spawn a task that logs a counter summary every `period`, plus deltas since
/// the previous report so a quiet stream is obvious at a glance.
pub fn spawn_reporter(
    metrics: Arc<Metrics>,
    period: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut prev = metrics.snapshot();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(period) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                    continue;
                }
            }
            let cur = metrics.snapshot();
            info!(
                tx_seen = cur.tx_seen,
                parsed = cur.parsed,
                filtered_out = cur.filtered_out,
                duplicates = cur.duplicates,
                low_liquidity = cur.low_liquidity,
                unsafe_mint = cur.unsafe_mint,
                detected = cur.detected,
                rug_detected = cur.rug_detected,
                lp_burned = cur.lp_burned,
                volume_confirmed = cur.volume_confirmed,
                tx_delta = cur.tx_seen.saturating_sub(prev.tx_seen),
                detected_delta = cur.detected.saturating_sub(prev.detected),
                "metrics"
            );
            prev = cur;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_independently() {
        let m = Metrics::default();
        m.incr(&m.detected);
        m.incr(&m.detected);
        m.incr(&m.filtered_out);
        let s = m.snapshot();
        assert_eq!(s.detected, 2);
        assert_eq!(s.filtered_out, 1);
        assert_eq!(s.low_liquidity, 0);
        assert_eq!(s.tx_seen, 0);
    }

    /// The reporter must terminate on shutdown rather than leaking a task that
    /// keeps the runtime alive.
    #[tokio::test]
    async fn reporter_stops_on_shutdown() {
        let m = Arc::new(Metrics::default());
        let (tx, rx) = watch::channel(false);
        spawn_reporter(m.clone(), Duration::from_millis(20), rx);

        // Let it emit at least one report.
        tokio::time::sleep(Duration::from_millis(70)).await;
        tx.send(true).unwrap();

        // If the reporter ignored shutdown this would hang the test runtime.
        tokio::time::timeout(Duration::from_millis(500), async {
            while Arc::strong_count(&m) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reporter task should drop its Arc after shutdown");
    }
}
