//! Jupiter aggregator client — the EXIT path (sell a held token back to SOL).
//!
//! WHY JUPITER FOR EXITS, NOT THE DIRECT-DEX PATH:
//! The buy path (`execute.rs`) hand-builds a swap into ONE specific pool for
//! speed and front-run resistance — that matters when racing to snipe a launch.
//! An exit has the opposite priorities: you are not racing anyone to sell, and
//! you must NOT be locked into dumping back through the exact pool you bought
//! from (which may be the thin/rugging pool you are trying to escape). Jupiter
//! routes token->SOL across every venue and picks the best path, and it works
//! for any token the wallet holds without reconstructing per-venue accounts.
//!
//! This module only talks HTTP + parses JSON. Signing/sending the returned
//! transaction is the submitter's job; simulating it is the sniper's. Keeping
//! the network boundary here makes the pure pieces (amount math, quote parsing)
//! unit-testable without a wallet or a live endpoint.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

/// Compute `pct`% of a raw token amount, in base units, without overflow.
/// Saturates at the full balance for pct >= 100. Integer math on purpose:
/// token amounts are exact, and Jupiter wants an integer `amount`.
pub fn fraction_of(amount: u64, pct: u8) -> u64 {
    let pct = pct.min(100) as u128;
    ((amount as u128 * pct) / 100) as u64
}

/// A Jupiter quote, kept whole. The `/swap` endpoint requires the ENTIRE quote
/// response echoed back verbatim, so we store the raw JSON and read fields off
/// it rather than reshaping into a struct that would lose the parts /swap needs.
#[derive(Debug, Clone)]
pub struct Quote {
    pub raw: Value,
}

impl Quote {
    /// SOL out, in lamports (raw). None if the field is missing/unparseable.
    pub fn out_lamports(&self) -> Option<u64> {
        self.raw.get("outAmount")?.as_str()?.parse().ok()
    }

    /// SOL out in UI units (for display). 1 SOL = 1e9 lamports.
    pub fn out_sol(&self) -> Option<f64> {
        self.out_lamports().map(|l| l as f64 / 1_000_000_000.0)
    }

    /// Price impact as a percentage (e.g. 3.2 for 3.2%). 0.0 if absent.
    /// Price impact as a PERCENT (5.0 means 5%).
    ///
    /// The API reports a fraction — verified live, a 1 SOL swap returned
    /// `"0.0000070039..."` for an impact of 0.0007%. Reading that number as a
    /// percent understates impact by 100x, which silently disabled the guard
    /// meant to refuse thin markets and made the rehearsal display wrong.
    pub fn price_impact_pct(&self) -> f64 {
        self.raw
            .get("priceImpactPct")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok())
            .map(|fraction| fraction * 100.0)
            .unwrap_or(0.0)
    }
}

pub struct Jupiter {
    client: reqwest::Client,
    base_url: String,
}

impl Jupiter {
    /// `base_url` is the Jupiter swap API root, e.g.
    /// `https://lite-api.jup.ag/swap/v1` (free) or `https://api.jup.ag/swap/v1`
    /// (paid). Configurable because Jupiter has migrated endpoints before.
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get a route for `amount` (raw base units) of `input_mint` -> `output_mint`.
    ///
    /// Rate-limited process-wide before the request goes out — see
    /// [`throttle`]. Every quote in the process shares one budget.
    pub async fn quote(
        &self,
        input_mint: &str,
        output_mint: &str,
        amount: u64,
        slippage_bps: u16,
    ) -> Result<Quote> {
        throttle().await;
        let url = format!("{}/quote", self.base_url);
        let amount_s = amount.to_string();
        let slip_s = slippage_bps.to_string();
        let resp = self
            .client
            .get(&url)
            .query(&[
                ("inputMint", input_mint),
                ("outputMint", output_mint),
                ("amount", amount_s.as_str()),
                ("slippageBps", slip_s.as_str()),
                // Fewer hops = fewer ways to fail on a fresh token; still routed.
                ("restrictIntermediateTokens", "true"),
            ])
            .send()
            .await
            .context("jupiter quote request")?;
        let status = resp.status();
        // Read the body as TEXT first. Parsing JSON before checking the status
        // turns a 429 (whose body is plain text) into "bad JSON: expected value
        // at line 1 column 1" — which hides the status code and makes a rate
        // limit look like a parser bug. The same blind spot cost a day on a
        // 429ing RPC provider.
        let body = resp.text().await.context("jupiter quote: unreadable body")?;
        if !status.is_success() {
            if status.as_u16() == 429 {
                note_rate_limited();
            }
            let snippet: String = body.chars().take(120).collect();
            bail!("jupiter quote HTTP {status}: {snippet}");
        }
        note_success();
        let raw: Value = serde_json::from_str(&body).map_err(|e| {
            let snippet: String = body.chars().take(120).collect();
            anyhow::anyhow!("jupiter quote: non-JSON body ({e}): {snippet}")
        })?;
        if raw.get("error").is_some() {
            bail!("jupiter quote failed: {raw}");
        }
        if raw.get("outAmount").is_none() {
            bail!("jupiter quote: no route found for this token: {raw}");
        }
        Ok(Quote { raw })
    }

    /// Current SOL price in USD, derived from a real routed quote of
    /// 1 SOL -> USDC.
    ///
    /// Deliberately reuses `/quote` rather than a separate price endpoint: it is
    /// the same call the exit path already depends on, so there is one endpoint
    /// to keep working instead of two, and the number is an actually-executable
    /// price rather than an index.
    pub async fn sol_price_usd(&self) -> Result<f64> {
        const WSOL: &str = "So11111111111111111111111111111111111111112";
        const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let q = self.quote(WSOL, USDC, 1_000_000_000, 50).await?;
        let out: u64 = q
            .raw
            .get("outAmount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("no outAmount in SOL price quote"))?;
        // USDC has 6 decimals.
        Ok(out as f64 / 1_000_000.0)
    }

    /// Turn a quote into an unsigned swap transaction (base64 VersionedTransaction).
    /// `wrapAndUnwrapSol` makes the SOL output arrive as native SOL, not WSOL.
    pub async fn swap_tx(&self, quote: &Quote, user_pubkey: &str) -> Result<String> {
        let url = format!("{}/swap", self.base_url);
        let body = json!({
            "quoteResponse": quote.raw,
            "userPublicKey": user_pubkey,
            "wrapAndUnwrapSol": true,
            "dynamicComputeUnitLimit": true,
            "prioritizationFeeLamports": "auto",
        });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("jupiter swap request")?;
        let status = resp.status();
        let v: Value = resp.json().await.context("jupiter swap: bad JSON")?;
        if !status.is_success() {
            bail!("jupiter swap failed ({status}): {v}");
        }
        v.get("swapTransaction")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("jupiter swap: no swapTransaction in response: {v}"))
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    /// The hardening that matters: once a price is cached, a dead endpoint
    /// must not blank it. The previous behaviour returned `None` on any error,
    /// which disabled the market-cap ceiling — a guard failing OPEN.
    ///
    ///   cargo test -- --ignored --nocapture live_sol_price_serves_stale
    #[ignore = "hits the Jupiter API"]
    #[tokio::test]
    async fn live_sol_price_serves_stale_when_refresh_fails() {
        // Warm the shared cache from the real endpoint.
        let good = cached_sol_price_usd("https://lite-api.jup.ag/swap/v1")
            .await
            .expect("a live SOL price");
        println!("live SOL price: ${good:.2}");
        assert!((10.0..2000.0).contains(&good), "implausible price: {good}");

        // Now ask through an endpoint that cannot answer. Inside the TTL the
        // cached value is returned without any request at all.
        let via_dead = cached_sol_price_usd("https://127.0.0.1:1/swap/v1").await;
        assert_eq!(via_dead, Some(good), "a dead endpoint must not blank a warm cache");
    }

    /// A cold cache with a dead endpoint has nothing to serve, and must say so
    /// rather than invent a number.
    #[tokio::test]
    async fn a_failed_refresh_never_fabricates_a_price() {
        let v = cached_sol_price_usd("https://127.0.0.1:1/swap/v1").await;
        // Either None (cold) or a real cached price (warmed by another test in
        // this process) — never zero or negative.
        assert!(v.is_none_or(|p| p > 0.0), "got {v:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fraction_of_is_exact_integer_math() {
        assert_eq!(fraction_of(1_000, 100), 1_000, "100% is the whole balance");
        assert_eq!(fraction_of(1_000, 50), 500);
        assert_eq!(fraction_of(1_001, 50), 500, "truncates, never rounds up past balance");
        assert_eq!(fraction_of(0, 100), 0);
        assert_eq!(fraction_of(1_000, 0), 0, "0% sells nothing");
    }

    #[test]
    fn fraction_of_saturates_above_100_and_never_overflows() {
        assert_eq!(fraction_of(1_000, 200), 1_000, "pct is clamped to 100");
        // No overflow even at the top of the u64 range.
        assert_eq!(fraction_of(u64::MAX, 100), u64::MAX);
    }

    #[test]
    fn quote_reads_out_amount_and_impact() {
        let q = Quote {
            raw: serde_json::json!({
                "outAmount": "1500000000",
                // A fraction, as the API sends it: 2.5% impact.
                "priceImpactPct": "0.025",
                "inAmount": "42",
            }),
        };
        assert_eq!(q.out_lamports(), Some(1_500_000_000));
        assert_eq!(q.out_sol(), Some(1.5));
        assert_eq!(q.price_impact_pct(), 2.5);
    }

    #[test]
    fn quote_missing_fields_are_none_not_panic() {
        let q = Quote { raw: serde_json::json!({}) };
        assert_eq!(q.out_lamports(), None);
        assert_eq!(q.out_sol(), None);
        assert_eq!(q.price_impact_pct(), 0.0, "absent impact defaults to 0");
    }
}

/// Process-wide SOL/USD, cached for five minutes, serving stale on failure.
///
/// # Why this is shared rather than per-caller
///
/// Two callers need it — the sniper's market-cap ceiling and the conviction
/// alert's USD figures. Each previously had its own answer: the sniper cached
/// but returned `None` on any error, and the conviction path re-quoted from
/// scratch on every alert with no cache at all. That meant a single transient
/// Jupiter failure blanked an entire alert's USD side, and a healthy process
/// still made two independent round trips.
///
/// # Stale beats absent
///
/// SOL does not move enough in five minutes to change a market-cap ceiling or
/// a displayed figure, but the difference between "$41.2K" and no line at all
/// is total. On a failed refresh the last good price is served and the failure
/// is logged; only a cold cache with a failing endpoint yields `None`.
pub async fn cached_sol_price_usd(base_url: &str) -> Option<f64> {
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    const TTL: Duration = Duration::from_secs(300);
    /// After a failed refresh, wait this long before spending another request.
    const FAIL_COOLDOWN: Duration = Duration::from_secs(60);

    static CACHE: OnceLock<Mutex<Option<(f64, Instant)>>> = OnceLock::new();
    static LAST_FAIL: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();

    // A poisoned lock means another task panicked mid-update. The cached price
    // is still valid data, so recover rather than propagate.
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let fails = LAST_FAIL.get_or_init(|| Mutex::new(None));
    let cached = *cache.lock().unwrap_or_else(|p| p.into_inner());
    let stale = cached.map(|(p, _)| p);

    if let Some((price, at)) = cached {
        if at.elapsed() < TTL {
            return Some(price);
        }
    }

    // Negative caching. Without it a FAILED refresh stores nothing, so the very
    // next caller retries immediately — failures then generate MORE requests,
    // which is exactly what sustains a rate limit. Observed live as repeated
    // 429s spaced one throttle-interval apart.
    if let Some(at) = *fails.lock().unwrap_or_else(|p| p.into_inner()) {
        if at.elapsed() < FAIL_COOLDOWN {
            return stale;
        }
    }

    match Jupiter::new(base_url).sol_price_usd().await {
        Ok(p) if p.is_finite() && p > 0.0 => {
            *cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((p, Instant::now()));
            *fails.lock().unwrap_or_else(|e| e.into_inner()) = None;
            Some(p)
        }
        Ok(bad) => {
            *fails.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            tracing::warn!(price = bad, "nonsensical SOL price; keeping previous");
            stale
        }
        Err(e) => {
            *fails.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            tracing::warn!(
                error = %format!("{e:#}"),
                cooldown_secs = FAIL_COOLDOWN.as_secs(),
                "SOL price refresh failed; serving cached and pausing retries"
            );
            stale
        }
    }
}

/// Configured floor for request spacing, in milliseconds.
static BASE_INTERVAL_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1200);
/// Spacing actually in force. Widens on a 429, decays back toward the base.
static CURRENT_INTERVAL_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1200);
/// Ceiling on the adaptive backoff — beyond this the tracker is too slow to
/// be useful and the operator should move to the paid endpoint.
const MAX_INTERVAL_MS: u64 = 15_000;

/// Set the global request spacing floor. Called once at startup from config.
pub fn set_min_interval_ms(ms: u64) {
    use std::sync::atomic::Ordering;
    let ms = ms.max(50);
    BASE_INTERVAL_MS.store(ms, Ordering::Relaxed);
    CURRENT_INTERVAL_MS.store(ms, Ordering::Relaxed);
}

/// Widen the global spacing after a rate-limit rejection.
///
/// The documented free-tier limit and the limit an individual IP actually gets
/// are different numbers — a VPS kept getting 429s at 50 req/min against a
/// published ~60. Rather than guess a constant that is wrong on some hosts,
/// the spacing doubles on every 429 and decays back on sustained success, so
/// it converges on whatever this host is really allowed.
pub fn note_rate_limited() {
    use std::sync::atomic::Ordering;
    let cur = CURRENT_INTERVAL_MS.load(Ordering::Relaxed);
    let next = (cur.saturating_mul(2)).min(MAX_INTERVAL_MS);
    if next != cur {
        CURRENT_INTERVAL_MS.store(next, Ordering::Relaxed);
        tracing::warn!(
            from_ms = cur,
            to_ms = next,
            "rate limited by the quote API; widening request spacing"
        );
    }
}

/// Ease the spacing back toward the configured base after successes.
///
/// Decays slowly (10% per success) so one lucky request does not undo a
/// backoff that is holding the rate limit at bay.
fn note_success() {
    use std::sync::atomic::Ordering;
    let base = BASE_INTERVAL_MS.load(Ordering::Relaxed);
    let cur = CURRENT_INTERVAL_MS.load(Ordering::Relaxed);
    if cur > base {
        let next = base.max(cur - (cur / 10).max(1));
        CURRENT_INTERVAL_MS.store(next, Ordering::Relaxed);
    }
}

/// Spacing currently in force, for logging and tests.
pub fn current_interval_ms() -> u64 {
    CURRENT_INTERVAL_MS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Process-wide request spacing for the Jupiter API.
///
/// # Why this cannot live in the calling loops
///
/// There are three independent callers — the conviction re-pricing sweep, the
/// outcome sampler, and the SOL price refresh. Each previously paced itself
/// with its own `sleep`, which bounds nothing in aggregate: two loops at 400ms
/// are 300 requests/minute against a free tier of roughly 60, and the answer is
/// a 429 that makes every one of them fail.
///
/// It also has to be time-based, not sleep-based. A `sleep(400ms)` between
/// iterations means the RATE depends on how long each request takes, so the
/// same code is fine on a slow link and floods on a fast one — which is exactly
/// why this surfaced on the VPS and never locally.
///
/// A single async mutex serialises callers and enforces the gap from the last
/// request's start, so the combined rate is bounded no matter how many loops
/// exist or how fast the host is.
pub async fn throttle() {
    use std::sync::atomic::Ordering;
    use std::time::Instant;
    use tokio::sync::Mutex;

    static LAST: std::sync::OnceLock<Mutex<Option<Instant>>> = std::sync::OnceLock::new();
    let cell = LAST.get_or_init(|| Mutex::new(None));

    // Held across the await deliberately: that is what serialises callers.
    let mut last = cell.lock().await;
    let gap = Duration::from_millis(CURRENT_INTERVAL_MS.load(Ordering::Relaxed));
    if let Some(prev) = *last {
        let elapsed = prev.elapsed();
        if elapsed < gap {
            tokio::time::sleep(gap - elapsed).await;
        }
    }
    *last = Some(Instant::now());
}

#[cfg(test)]
mod throttle_tests {
    use super::*;

    /// The gap must be enforced between request STARTS, independent of how
    /// long each request takes — otherwise the same code floods on a fast
    /// host and behaves on a slow one.
    #[tokio::test]
    async fn requests_are_spaced_by_at_least_the_interval() {
        set_min_interval_ms(120);
        let start = std::time::Instant::now();
        for _ in 0..4 {
            throttle().await;
        }
        // Four calls = three enforced gaps.
        assert!(
            start.elapsed() >= Duration::from_millis(350),
            "spacing not enforced: {:?}",
            start.elapsed()
        );
        set_min_interval_ms(1200);
    }

    /// The published free-tier limit and what an individual IP actually gets
    /// are different numbers — a VPS kept getting 429s at 50 req/min against a
    /// documented ~60. The spacing must therefore find the real limit rather
    /// than trust a constant.
    #[test]
    fn spacing_widens_on_a_rate_limit_and_recovers_on_success() {
        set_min_interval_ms(1000);
        assert_eq!(current_interval_ms(), 1000);

        note_rate_limited();
        assert_eq!(current_interval_ms(), 2000, "a 429 must widen the gap");
        note_rate_limited();
        assert_eq!(current_interval_ms(), 4000);

        // Recovery is gradual: one lucky request must not undo a backoff that
        // is holding the limit at bay.
        note_success();
        let after_one = current_interval_ms();
        assert!(after_one < 4000 && after_one > 3000, "got {after_one}");

        for _ in 0..200 {
            note_success();
        }
        assert_eq!(current_interval_ms(), 1000, "must return to the configured base");
        set_min_interval_ms(1200);
    }

    /// Backoff is bounded: past a point the tracker is too slow to be useful
    /// and the operator should move to the paid endpoint.
    #[test]
    fn backoff_is_capped() {
        set_min_interval_ms(1000);
        for _ in 0..50 {
            note_rate_limited();
        }
        assert_eq!(current_interval_ms(), MAX_INTERVAL_MS);
        set_min_interval_ms(1200);
    }

    /// Concurrent callers share ONE budget. Per-loop pacing cannot do this,
    /// which is the whole reason the throttle is global.
    #[tokio::test]
    async fn concurrent_callers_share_one_budget() {
        set_min_interval_ms(100);
        let start = std::time::Instant::now();
        let mut set = Vec::new();
        for _ in 0..5 {
            set.push(tokio::spawn(async { throttle().await }));
        }
        for h in set {
            h.await.unwrap();
        }
        assert!(
            start.elapsed() >= Duration::from_millis(380),
            "concurrent callers bypassed the budget: {:?}",
            start.elapsed()
        );
        set_min_interval_ms(1200);
    }
}
