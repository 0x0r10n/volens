//! Rolling-window conviction scoring across tracked wallets.
//!
//! # The problem this solves
//!
//! 700 tracked wallets produce ~861 transactions per minute. Alerting on every
//! buy would be unusable, and it would also be the wrong signal: one wallet
//! buying something says very little.
//!
//! The signal worth acting on is **independent convergence** — several tracked
//! wallets buying the SAME token inside a short window, without coordinating.
//! That is what an early runner looks like before it trends.
//!
//! ```text
//!   1 distinct buyer  in 10 min  ->  recorded, silent
//!   2 distinct buyers in 10 min  ->  signal
//!   3rd, 4th buyer               ->  signal again, escalating
//! ```
//!
//! # Why distinct wallets, not buy count
//!
//! One wallet buying the same token five times is one opinion, and scaling into
//! a position is ordinary behaviour. Counting buys instead of buyers would let
//! a single active wallet manufacture a "signal" on its own. Only the first buy
//! from each wallet moves the count.
//!
//! # Time is injected, never read
//!
//! Every entry point takes `now`. A tracker that called `Instant::now()`
//! internally could only be tested by sleeping, so the window logic — the part
//! most likely to be wrong — would go untested.
//!
//! # Two clocks, deliberately
//!
//! Windowing uses [`Instant`] (monotonic) and display uses [`DateTime<Utc>`]
//! (wall clock). They are not interchangeable: an NTP correction can move the
//! wall clock backwards, which would make a buy appear to arrive before one
//! recorded earlier and corrupt the window. A monotonic clock cannot be
//! rendered as a timestamp, so both are carried.
//!
//! # Performance tracking
//!
//! A signal is only half the story; how it performed lives in [`crate::signals`].
//! The entry price is **captured at announce time and never re-derived** — a
//! later read returns the price now, not the price then, so it is unrecoverable
//! after the fact. `Detector::spawn_conviction_alert` persists the triggering
//! buy as the reference trade for that reason.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One wallet's first buy of a token inside the current window.
#[derive(Debug, Clone)]
struct Buyer {
    wallet: String,
    name: String,
    /// Monotonic — drives the window.
    at: Instant,
    /// Wall clock — drives the rendered timestamp only.
    at_utc: DateTime<Utc>,
    sol: f64,
    fees: f64,
}

/// Emitted when a new distinct wallet pushes a token to or past the threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct ConvictionSignal {
    pub mint: String,
    /// Distinct tracked wallets that bought inside the window.
    pub distinct_buyers: usize,
    /// Combined SOL committed by those wallets.
    pub total_sol: f64,
    /// `(name, sol)` oldest first — the order they arrived.
    pub buyers: Vec<(String, f64)>,
    /// Buyer ADDRESSES, for counting. Names are display labels and can repeat
    /// across wallets (several are just a shortened address), so counting
    /// distinct buyers by name would undercount.
    pub buyer_addresses: Vec<String>,
    /// Seconds between the first and latest buy. Small values mean the
    /// convergence was tight, which is the stronger version of the signal.
    pub spread_secs: u64,
    /// When the FIRST tracked buy of this token landed, in UTC. Not the time
    /// the threshold was crossed — the point is how long the accumulation has
    /// been running, which is what tells you whether you are early.
    pub first_seen_utc: DateTime<Utc>,
    /// Fees paid across the buys that produced this signal — network, tips and
    /// platform. NOT the token's all-time trading fees: volens sees 700
    /// wallets, not the whole market.
    pub total_fees_sol: f64,
}

/// Tracks recent tracked-wallet buys per token.
///
/// Not `Sync`-safe by itself — the detector owns one behind a mutex, because
/// buys arrive from a single stream task and ordering matters.
#[derive(Debug)]
pub struct ConvictionTracker {
    window: Duration,
    threshold: usize,
    tokens: HashMap<String, Vec<Buyer>>,
    /// Tokens already announced, and when. A token fires ONCE: further buyers
    /// arriving after the threshold are not new information, they are the same
    /// call getting louder, and re-posting them is what makes a channel
    /// unreadable. Entries expire so a token that goes quiet for a day and
    /// genuinely re-accumulates can call again.
    announced: HashMap<String, Instant>,
    announce_ttl: Duration,
    /// Full sweeps are O(tokens); doing one per buy would be wasteful at 861
    /// tx/min. Sweep when the map has grown instead.
    sweep_at: usize,
}

impl ConvictionTracker {
    pub fn new(window: Duration, threshold: usize, announce_ttl: Duration) -> Self {
        Self {
            window,
            // A threshold below 2 makes every single buy a "signal", which is
            // the noise this module exists to remove.
            threshold: threshold.max(2),
            tokens: HashMap::new(),
            announced: HashMap::new(),
            announce_ttl,
            sweep_at: 512,
        }
    }

    /// Record a buy. Returns a signal only on the buy that FIRST takes a token
    /// to the threshold, and only once per token per `announce_ttl`.
    ///
    /// Two separate suppressions, both deliberate:
    ///
    /// * a wallet already counted for this token never counts twice — scaling
    ///   into a position is one opinion, not two;
    /// * a token already announced never announces again — the 4th and 5th
    ///   buyer are the same call getting louder, not a new one.
    /// Wallets that have bought this token inside the current window.
    ///
    /// Exposed so the caller can apply its OWN filter — the tracker knows
    /// nothing about cohorts, and should not. Alerting counts every tracked
    /// wallet; trading may want a subset, and keeping that decision outside
    /// here stops the two from drifting into one another.
    pub fn buyers_in_window(&self, mint: &str, now: Instant) -> Vec<String> {
        let window = self.window;
        self.tokens
            .get(mint)
            .map(|e| {
                e.iter()
                    .filter(|b| now.duration_since(b.at) < window)
                    .map(|b| b.wallet.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn record(
        &mut self,
        mint: &str,
        wallet: &str,
        name: &str,
        sol: f64,
        fees: f64,
        now: Instant,
        now_utc: DateTime<Utc>,
    ) -> Option<ConvictionSignal> {
        if self.tokens.len() > self.sweep_at {
            self.sweep(now);
        }

        // Already called: stay quiet, but KEEP RECORDING.
        //
        // This used to `return None` here, before the buyer was pushed — so a
        // token's buyer list froze at the alert threshold the moment it called.
        // Anything reading that list for a stricter decision (auto-buy needs
        // more buyers than an alert does) could never see enough, and silently
        // never fired.
        let ttl = self.announce_ttl;
        let suppressed = match self.announced.get(mint) {
            Some(at) if now.duration_since(*at) < ttl => true,
            Some(_) => {
                self.announced.remove(mint);
                false
            }
            None => false,
        };

        let window = self.window;
        let entries = self.tokens.entry(mint.to_string()).or_default();
        entries.retain(|b| now.duration_since(b.at) < window);

        // Already counted inside the window? Refresh nothing, emit nothing.
        if entries.iter().any(|b| b.wallet == wallet) {
            return None;
        }

        entries.push(Buyer {
            wallet: wallet.to_string(),
            name: name.to_string(),
            at: now,
            at_utc: now_utc,
            sol,
            fees,
        });

        if suppressed || entries.len() < self.threshold {
            return None;
        }

        // The oldest entry by the MONOTONIC clock, then read its wall-clock
        // stamp. Picking the minimum `at_utc` directly would let a backwards
        // clock correction nominate the wrong buy as "first".
        let oldest = entries
            .iter()
            .min_by_key(|b| b.at)
            .map(|b| (b.at, b.at_utc))
            .unwrap_or((now, now_utc));

        self.announced.insert(mint.to_string(), now);

        Some(ConvictionSignal {
            mint: mint.to_string(),
            distinct_buyers: entries.len(),
            total_sol: entries.iter().map(|b| b.sol).sum(),
            buyers: entries.iter().map(|b| (b.name.clone(), b.sol)).collect(),
            buyer_addresses: entries.iter().map(|b| b.wallet.clone()).collect(),
            spread_secs: now.duration_since(oldest.0).as_secs(),
            first_seen_utc: oldest.1,
            total_fees_sol: entries.iter().map(|b| b.fees).sum(),
        })
    }


    /// Distinct buyers currently inside the window, and their combined SOL.
    ///
    /// Test-only: kept because it is how `sweep`'s memory reclamation and the
    /// per-token accounting are verified, but nothing in the running bot reads
    /// it — there is no `/conviction` command.
    #[cfg(test)]
    pub fn active(&self, now: Instant) -> Vec<(String, usize, f64)> {
        let mut out: Vec<(String, usize, f64)> = self
            .tokens
            .iter()
            .filter_map(|(mint, buyers)| {
                let live: Vec<&Buyer> = buyers
                    .iter()
                    .filter(|b| now.duration_since(b.at) < self.window)
                    .collect();
                if live.is_empty() {
                    return None;
                }
                Some((mint.clone(), live.len(), live.iter().map(|b| b.sol).sum()))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.total_cmp(&a.2)));
        out
    }

    /// Tokens currently held in the window. Test-only: proves `sweep` actually
    /// reclaims, which is otherwise invisible.
    #[cfg(test)]
    pub fn tracked_tokens(&self) -> usize {
        self.tokens.len()
    }

    /// Drop tokens whose entries have all expired. Without this the map grows
    /// for every token any tracked wallet has ever touched.
    pub fn sweep(&mut self, now: Instant) {
        let window = self.window;
        self.tokens.retain(|_, buyers| {
            buyers.retain(|b| now.duration_since(b.at) < window);
            !buyers.is_empty()
        });
        let ttl = self.announce_ttl;
        self.announced.retain(|_, at| now.duration_since(*at) < ttl);
    }

}

/// USD context for one token, resolved once per signal.
///
/// Every figure in an alert is converted with the SAME `sol_usd` rate. Fetching
/// it per line would let two numbers in one message disagree — a total that
/// does not match the sum of its parts reads as a bug even when both rates were
/// individually correct.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MarketSnapshot {
    pub sol_usd: f64,
    /// USD per token, from the reference fill.
    pub price_usd: Option<f64>,
    /// Fully-diluted valuation in USD.
    pub fdv_usd: Option<f64>,
}

impl MarketSnapshot {
    pub fn usd(&self, sol: f64) -> f64 {
        sol * self.sol_usd
    }
}

/// Render a conviction signal as a Telegram HTML message.
///
/// # Buyers are counted, not named
///
/// No wallet names, no per-wallet sizes. The names are third-party labels of
/// real traders, and publishing who bought what is a different act from
/// publishing that smart money bought — the aggregate carries the signal
/// without exposing anyone's book. `SM` is the count alone.
///
/// # The mint is shown in FULL, not shortened
///
/// Telegram copies a `<code>` block's **literal contents**. A shortened
/// `8Ky9Bm…abcd` would therefore copy a truncated string that is not a valid
/// address — the tap appears to work and silently yields something useless.
/// No markup displays short text while copying a longer value, so the full
/// mint is rendered. It needs no caption: a code block is self-evidently
/// tappable.
///
/// # Denomination
///
/// Money is USD. SOL is a moving yardstick, so a size in SOL is not comparable
/// across alerts. When the rate is unknown the figure falls back to SOL rather
/// than vanishing, and the unit is always labelled.
pub fn render_signal(
    signal: &ConvictionSignal,
    meta: Option<&(String, String)>,
    mint_info: Option<&crate::rpc::MintInfo>,
    market: Option<&MarketSnapshot>,
    socials: Option<&crate::socials::Socials>,
    holders: Option<&crate::rpc::HolderStats>,
    tz_offset_hours: i32,
) -> String {
    // The `$` prefix is a TICKER sigil, so it is only ever applied to a real
    // symbol. When metadata is missing, prefixing the shortened mint produces
    // `$ER8j7V…9JZ9LJ`, which reads as a ticker and is not one — worse than
    // saying nothing, because it looks like an answer.
    let title = match meta {
        Some((n, sym)) if !sym.is_empty() => {
            format!("${} ({})", html_escape(sym), html_escape(n))
        }
        Some((n, _)) if !n.is_empty() => html_escape(n),
        _ => short_mint(&signal.mint),
    };

    let mut s = String::from("🔥<b>Smart Money Buying Alerts</b>🔥\n\n");
    s.push_str(&format!(
        "Message push time: {}\n\n",
        stamp(Utc::now(), tz_offset_hours)
    ));

    s.push_str(&format!("<b>{title}</b>\n"));
    s.push_str(&format!("<code>{}</code>\n\n", signal.mint));

    s.push_str(&format!("SM: {}\n", signal.distinct_buyers));
    if let Some(mc) = market.and_then(|m| m.fdv_usd) {
        s.push_str(&format!("MC: {}\n", format_usd(mc)));
    }
    // "SM" prefixes make the scope explicit: this is what the tracked wallets
    // spent, not the token's market-wide volume or lifetime fees.
    s.push_str(&format!("SM Vol: {}\n", money(signal.total_sol, market)));
    // Fees stay in SOL even though everything above is USD. They are a cost of
    // execution, and execution is priced in SOL — a tip is chosen in lamports,
    // not dollars. Converting it would obscure the number the trader actually
    // set.
    if signal.total_fees_sol > 0.0 {
        s.push_str(&format!("SM Fees: {}\n", format_sol(signal.total_fees_sol)));
    }

    // Risk: how many hold it, and how concentrated the non-pool holders are.
    // Omitted entirely when unreadable rather than shown as 0 — a fabricated
    // "0 holders" would read as a rug on a perfectly fine token.
    if let Some(h) = holders {
        s.push_str(&format!(
            "Holders: {}{}\n",
            h.count,
            if h.capped { "+" } else { "" }
        ));
        s.push_str(&format!("Top10: {:.1}%\n", h.top10_pct));
    }

    // Safety stays an annotation, and only when it has something to say. A
    // "clean" line on every alert is noise; a risk flag is not.
    if let Some(warning) = risk_flag(mint_info) {
        s.push_str(&format!("{warning}\n"));
    }

    s.push_str(&format!(
        "\nFirst signal: {}\n",
        stamp(signal.first_seen_utc, tz_offset_hours)
    ));
    s.push_str(&format!(
        "\n<a href=\"https://dexscreener.com/solana/{}\">Chart</a>",
        signal.mint
    ));
    // Socials sit on the same line as the chart, separated by pipes, so a
    // token with three links does not add three lines to every alert.
    if let Some(soc) = socials {
        if let Some(u) = &soc.twitter {
            s.push_str(&format!(" | <a href=\"{u}\">X</a>"));
        }
        if let Some(u) = &soc.telegram {
            s.push_str(&format!(" | <a href=\"{u}\">TG</a>"));
        }
        if let Some(u) = &soc.website {
            s.push_str(&format!(" | <a href=\"{u}\">Web</a>"));
        }
    }
    s
}

/// `08-11 15:58:38 (UTC+8)` — local trading time, not UTC.
pub fn stamp(t: DateTime<Utc>, offset_hours: i32) -> String {
    let sign = if offset_hours < 0 { "-" } else { "+" };
    let offset = chrono::FixedOffset::east_opt(offset_hours * 3600)
        .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).expect("utc"));
    format!(
        "{} (UTC{sign}{})",
        t.with_timezone(&offset).format("%m-%d %H:%M:%S"),
        offset_hours.abs()
    )
}

/// `8Ky9Bm…W1abcd`, for a token with no on-chain name.
pub fn short_mint(mint: &str) -> String {
    if mint.len() <= 12 {
        return mint.to_string();
    }
    format!("{}…{}", &mint[..6], &mint[mint.len() - 6..])
}

/// A one-line risk warning, or `None` when there is nothing to warn about.
///
/// Returns `None` for BOTH a clean mint and an unreadable one, because neither
/// is a warning — but they are not the same thing, and the caller must not
/// treat silence as a safety claim.
fn risk_flag(mint_info: Option<&crate::rpc::MintInfo>) -> Option<String> {
    let info = mint_info?;
    let mut flags = Vec::new();
    if info.mint_authority.is_some() {
        flags.push("mint authority live");
    }
    if info.freeze_authority.is_some() {
        flags.push("freeze authority live");
    }
    if !info.risky_extensions.is_empty() {
        flags.push("risky extensions");
    }
    (!flags.is_empty()).then(|| format!("⚠️ {}", flags.join(", ")))
}

/// SOL with precision that survives small numbers. A tip of 0.0004 SOL must
/// not render as `0.00 SOL`.
pub fn format_sol(v: f64) -> String {
    if v >= 1.0 {
        format!("{v:.2} SOL")
    } else if v >= 0.001 {
        format!("{v:.4} SOL")
    } else {
        format!("{v:.6} SOL")
    }
}

/// A SOL amount rendered in USD, falling back to SOL when no rate is known.
fn money(sol: f64, market: Option<&MarketSnapshot>) -> String {
    match market {
        Some(m) if m.sol_usd > 0.0 => format_usd(m.usd(sol)),
        _ => format!("{sol:.2} SOL"),
    }
}


/// Format a USD figure the way a call channel reads it: `$41.2K`, `$1.8M`.
pub fn format_usd(v: f64) -> String {
    match v {
        v if v >= 1_000_000_000.0 => format!("${:.2}B", v / 1_000_000_000.0),
        v if v >= 1_000_000.0 => format!("${:.2}M", v / 1_000_000.0),
        v if v >= 1_000.0 => format!("${:.1}K", v / 1_000.0),
        v => format!("${v:.0}"),
    }
}



fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {

    /// A called token must keep accumulating buyers.
    ///
    /// It did not: `record` returned before pushing once the token had
    /// announced, so the buyer list froze at the alert threshold. Anything
    /// wanting a STRICTER rule than the alert — auto-buy needs more buyers than
    /// an alert does — could never see enough, and failed silently: no error,
    /// no log, simply no trades, forever.
    #[test]
    fn buyers_keep_accumulating_after_the_call() {
        let mut t = ConvictionTracker::new(
            Duration::from_secs(600),
            3,
            Duration::from_secs(3600),
        );
        let now = Instant::now();
        let utc = Utc::now();

        assert!(t.record("MINT", "w1", "a", 1.0, 0.0, now, utc).is_none());
        assert!(t.record("MINT", "w2", "b", 1.0, 0.0, now, utc).is_none());
        assert!(t.record("MINT", "w3", "c", 1.0, 0.0, now, utc).is_some(), "should call at 3");
        assert_eq!(t.buyers_in_window("MINT", now).len(), 3);

        // Two more buyers arrive. Silent — the token already called — but they
        // must still be counted.
        assert!(t.record("MINT", "w4", "d", 1.0, 0.0, now, utc).is_none(), "must not re-announce");
        assert!(t.record("MINT", "w5", "e", 1.0, 0.0, now, utc).is_none());
        assert_eq!(
            t.buyers_in_window("MINT", now).len(),
            5,
            "a stricter rule than the alert must be able to see the later buyers"
        );
    }

    /// The same wallet buying twice is still one buyer.
    #[test]
    fn a_repeat_buyer_is_counted_once() {
        let mut t = ConvictionTracker::new(
            Duration::from_secs(600),
            3,
            Duration::from_secs(3600),
        );
        let now = Instant::now();
        let utc = Utc::now();
        t.record("MINT", "w1", "a", 1.0, 0.0, now, utc);
        t.record("MINT", "w1", "a", 1.0, 0.0, now, utc);
        assert_eq!(t.buyers_in_window("MINT", now).len(), 1);
    }
    use super::*;

    const MINT: &str = "TokenMint111111111111111111111111111111111";

    fn tracker() -> ConvictionTracker {
        ConvictionTracker::new(Duration::from_secs(600), 2, Duration::from_secs(86_400))
    }

    /// Fixed wall clock. The window is driven by the injected `Instant`, so the
    /// UTC stamp is free to be constant except where a test asserts on it.
    fn utc() -> DateTime<Utc> {
        DateTime::from_timestamp(1_786_326_266, 0).unwrap()
    }

    #[test]
    fn one_buyer_is_silent() {
        let mut t = tracker();
        assert!(t.record(MINT, "W1", "Alice", 1.0, 0.01, Instant::now(), utc()).is_none());
    }

    #[test]
    fn second_distinct_buyer_signals() {
        let mut t = tracker();
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "Alice", 1.0, 0.01, now, utc()).is_none());

        let s = t.record(MINT, "W2", "Bob", 2.5, 0.01, now + Duration::from_secs(60), utc()).unwrap();
        assert_eq!(s.distinct_buyers, 2);
        assert!((s.total_sol - 3.5).abs() < 1e-9);
        assert_eq!(s.spread_secs, 60);
        assert_eq!(s.buyers, vec![("Alice".into(), 1.0), ("Bob".into(), 2.5)]);
    }

    /// The core anti-noise rule: one wallet cannot manufacture conviction by
    /// scaling into a position.
    #[test]
    fn same_wallet_buying_repeatedly_never_signals() {
        let mut t = tracker();
        let now = Instant::now();
        for i in 0..10 {
            let at = now + Duration::from_secs(i * 5);
            assert!(
                t.record(MINT, "W1", "Alice", 1.0, 0.01, at, utc()).is_none(),
                "buy {i} from the same wallet must not signal"
            );
        }
    }

    /// A token calls ONCE. The 3rd and 4th buyer are the same call getting
    /// louder, not a new one — re-posting them is what makes a channel
    /// unreadable.
    #[test]
    fn a_token_announces_once_no_matter_how_many_more_buy() {
        let mut t = tracker();
        let now = Instant::now();
        t.record(MINT, "W1", "A", 1.0, 0.01, now, utc());
        assert!(t.record(MINT, "W2", "B", 1.0, 0.01, now, utc()).is_some(), "first crossing fires");

        for (i, w) in ["W3", "W4", "W5", "W6"].iter().enumerate() {
            let at = now + Duration::from_secs(30 * (i as u64 + 1));
            assert!(
                t.record(MINT, w, "X", 1.0, 0.01, at, utc()).is_none(),
                "{w} must not re-announce an already-called token"
            );
        }
    }

    /// Fees are summed across the buyers in the window, not taken from the
    /// last one.
    #[test]
    fn fees_accumulate_across_buyers() {
        let mut t = tracker();
        let now = Instant::now();
        t.record(MINT, "W1", "A", 1.0, 0.011, now, utc());
        let s = t.record(MINT, "W2", "B", 1.0, 0.004, now, utc()).unwrap();
        assert!((s.total_fees_sol - 0.015).abs() < 1e-9, "got {}", s.total_fees_sol);
    }

    /// After the suppression expires, genuine fresh accumulation may call
    /// again — otherwise a token that runs twice in a week is only ever
    /// reported once.
    #[test]
    fn a_token_can_call_again_once_the_suppression_expires() {
        let mut t = ConvictionTracker::new(
            Duration::from_secs(600),
            2,
            Duration::from_secs(3600),
        );
        let now = Instant::now();
        t.record(MINT, "W1", "A", 1.0, 0.01, now, utc());
        assert!(t.record(MINT, "W2", "B", 1.0, 0.01, now, utc()).is_some());

        let later = now + Duration::from_secs(3700);
        t.record(MINT, "W1", "A", 1.0, 0.01, later, utc());
        assert!(
            t.record(MINT, "W2", "B", 1.0, 0.01, later, utc()).is_some(),
            "suppression must lapse, not be permanent"
        );
    }

    /// Buys outside the window are not convergence — they are two unrelated
    /// people who happened to buy the same thing an hour apart.
    #[test]
    fn buys_outside_the_window_do_not_combine() {
        let mut t = tracker();
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "Alice", 1.0, 0.01, now, utc()).is_none());

        // 11 minutes later: the first buy has aged out, so this is buyer #1.
        let late = now + Duration::from_secs(660);
        assert!(
            t.record(MINT, "W2", "Bob", 1.0, 0.01, late, utc()).is_none(),
            "expired entry must not count toward the threshold"
        );
    }

    #[test]
    fn a_wallet_can_count_again_after_its_entry_expires() {
        let mut t = tracker();
        let now = Instant::now();
        t.record(MINT, "W1", "Alice", 1.0, 0.01, now, utc());
        let late = now + Duration::from_secs(700);
        assert!(t.record(MINT, "W1", "Alice", 1.0, 0.01, late, utc()).is_none());
        assert!(t.record(MINT, "W2", "Bob", 1.0, 0.01, late, utc()).is_some());
    }

    /// The stamp must be the FIRST buy, not the moment the threshold was
    /// crossed. Those differ by however long the accumulation ran, which is
    /// exactly the number that tells you whether you are early.
    #[test]
    fn first_seen_is_the_first_buy_not_the_threshold_crossing() {
        let mut t = tracker();
        let now = Instant::now();
        let first_utc = DateTime::from_timestamp(1_786_326_000, 0).unwrap();
        let later_utc = DateTime::from_timestamp(1_786_326_180, 0).unwrap();

        t.record(MINT, "W1", "Alice", 1.0, 0.01, now, first_utc);
        let s = t
            .record(MINT, "W2", "Bob", 1.0, 0.01, now + Duration::from_secs(180), later_utc)
            .unwrap();

        assert_eq!(s.first_seen_utc, first_utc, "must report the earliest buy");
        assert_eq!(s.spread_secs, 180);
    }

    /// A backwards wall-clock correction (NTP) must not change which buy is
    /// considered first — the monotonic clock decides.
    #[test]
    fn backwards_clock_correction_does_not_reorder_first_seen() {
        let mut t = tracker();
        let now = Instant::now();
        let first_utc = DateTime::from_timestamp(1_786_326_000, 0).unwrap();
        // Second buy arrives LATER monotonically but stamps EARLIER in UTC.
        let skewed_utc = DateTime::from_timestamp(1_786_325_000, 0).unwrap();

        t.record(MINT, "W1", "Alice", 1.0, 0.01, now, first_utc);
        let s = t
            .record(MINT, "W2", "Bob", 1.0, 0.01, now + Duration::from_secs(60), skewed_utc)
            .unwrap();

        assert_eq!(
            s.first_seen_utc, first_utc,
            "monotonic order wins; a skewed stamp must not become 'first'"
        );
    }

    #[test]
    fn different_tokens_are_independent() {
        let mut t = tracker();
        let now = Instant::now();
        assert!(t.record("MINT_A", "W1", "A", 1.0, 0.01, now, utc()).is_none());
        assert!(
            t.record("MINT_B", "W2", "B", 1.0, 0.01, now, utc()).is_none(),
            "buyers of a different token must not combine"
        );
    }

    #[test]
    fn threshold_below_two_is_clamped() {
        let mut t = ConvictionTracker::new(Duration::from_secs(600), 0, Duration::from_secs(86_400));
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "A", 1.0, 0.01, now, utc()).is_none(), "1 buyer is never a signal");
        assert!(t.record(MINT, "W2", "B", 1.0, 0.01, now, utc()).is_some());
    }

    #[test]
    fn higher_threshold_waits() {
        let mut t = ConvictionTracker::new(Duration::from_secs(600), 3, Duration::from_secs(86_400));
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "A", 1.0, 0.01, now, utc()).is_none());
        assert!(t.record(MINT, "W2", "B", 1.0, 0.01, now, utc()).is_none());
        assert!(t.record(MINT, "W3", "C", 1.0, 0.01, now, utc()).is_some());
    }

    #[test]
    fn sweep_drops_expired_tokens() {
        let mut t = tracker();
        let now = Instant::now();
        t.record("MINT_A", "W1", "A", 1.0, 0.01, now, utc());
        t.record("MINT_B", "W2", "B", 1.0, 0.01, now, utc());
        assert_eq!(t.tracked_tokens(), 2);

        t.sweep(now + Duration::from_secs(700));
        assert_eq!(t.tracked_tokens(), 0, "expired tokens must be reclaimed");
    }

    #[test]
    fn active_ranks_by_distinct_buyers() {
        let mut t = tracker();
        let now = Instant::now();
        t.record("MINT_A", "W1", "A", 1.0, 0.01, now, utc());
        t.record("MINT_B", "W1", "A", 5.0, 0.01, now, utc());
        t.record("MINT_B", "W2", "B", 5.0, 0.01, now, utc());

        let active = t.active(now);
        assert_eq!(active[0].0, "MINT_B");
        assert_eq!(active[0].1, 2);
        assert_eq!(active[1].0, "MINT_A");
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;

    fn market() -> MarketSnapshot {
        MarketSnapshot {
            sol_usd: 75.0,
            price_usd: Some(0.0000612),
            fdv_usd: Some(41_200.0),
        }
    }

    fn signal() -> ConvictionSignal {
        ConvictionSignal {
            mint: "8Ky9Bm6zSAtXeS3dA3UuVqZKqFqL2yPmXn4tRcW1abcd".into(),
            distinct_buyers: 3,
            total_sol: 26.39,
            buyers: vec![
                ("Silver".into(), 0.987),
                ("Ratwiz".into(), 0.115),
                ("OGANT".into(), 25.288),
            ],
            spread_secs: 143,
            buyer_addresses: vec!["W1".into(), "W2".into(), "W3".into()],
            total_fees_sol: 0.0412,
            first_seen_utc: DateTime::from_timestamp(1_786_326_266, 0).unwrap(),
        }
    }

    #[test]
    fn renders_a_readable_alert() {
        let meta = ("Credible".to_string(), "CRED".to_string());
        let out = render_signal(&signal(), Some(&meta), None, Some(&market()), None, None, 8);
        println!("\n--- initial alert ---\n{out}\n");

        assert!(out.contains("$CRED (Credible)"), "ticker first, name in parens:\n{out}");
        assert!(out.contains("SM: 3"));
        assert!(out.contains("MC: $41.2K"));
        assert!(out.contains("Vol: $2.0K"));
        // Mint in a code block, with no caption telling you to tap it.
        assert!(out.contains("<code>8Ky9Bm6zSAtXeS3dA3UuVqZKqFqL2yPmXn4tRcW1abcd</code>"));
        assert!(!out.to_lowercase().contains("tap to copy"));
    }

    /// Individual traders and their sizes must not be published: the count
    /// carries the signal without exposing anyone's book.
    #[test]
    fn no_wallet_names_or_individual_sizes_are_published() {
        let meta = ("Credible".to_string(), "CRED".to_string());
        let out = render_signal(&signal(), Some(&meta), None, Some(&market()), None, None, 8);

        for name in ["Silver", "Ratwiz", "OGANT"] {
            assert!(!out.contains(name), "{name} leaked into the alert:\n{out}");
        }
        assert!(!out.contains("25.29"), "individual size leaked:\n{out}");
        // The aggregate survives.
        assert!(out.contains("SM: 3"));
        assert!(out.contains("SM Vol:"));
    }

    /// Times are local trading time, not UTC.
    #[test]
    fn timestamps_render_in_the_configured_offset() {
        let out = render_signal(&signal(), None, None, Some(&market()), None, None, 8);
        assert!(out.contains("(UTC+8)"), "got:\n{out}");
        assert!(out.contains("First signal:"));

        let west = render_signal(&signal(), None, None, Some(&market()), None, None, -5);
        assert!(west.contains("(UTC-5)"), "got:\n{west}");
    }

    /// A clean mint says nothing; only a risk is worth a line.
    #[test]
    fn safety_appears_only_when_there_is_a_risk() {
        use crate::rpc::MintInfo;
        let clean = MintInfo {
            mint_authority: None,
            freeze_authority: None,
            decimals: 6,
            risky_extensions: vec![],
        };
        let out = render_signal(&signal(), None, Some(&clean), Some(&market()), None, None, 8);
        assert!(!out.contains("⚠️"), "a clean mint must not add a line:\n{out}");

        let risky = MintInfo {
            mint_authority: Some("Auth".into()),
            freeze_authority: None,
            decimals: 6,
            risky_extensions: vec![],
        };
        let out = render_signal(&signal(), None, Some(&risky), Some(&market()), None, None, 8);
        assert!(out.contains("⚠️"), "a live authority must be flagged:\n{out}");
    }

    /// The `$` sigil marks a TICKER. Without metadata there is no ticker, and
    /// prefixing the shortened mint produced `$ER8j7V…9JZ9LJ` — which reads as
    /// a ticker, is not one, and is worse than saying nothing because it looks
    /// like an answer.
    #[test]
    fn a_nameless_token_shows_the_mint_without_a_ticker_sigil() {
        let out = render_signal(&signal(), None, None, Some(&market()), None, None, 8);
        assert!(out.contains("8Ky9Bm…W1abcd"), "got:\n{out}");
        assert!(!out.contains("$8Ky9Bm"), "a mint must not wear a $ sigil:\n{out}");
    }

    /// A token with a name but no symbol shows the name, still unsigiled.
    #[test]
    fn a_symbolless_token_shows_its_name() {
        let meta = ("Cheesecoin".to_string(), String::new());
        let out = render_signal(&signal(), Some(&meta), None, Some(&market()), None, None, 8);
        assert!(out.contains("Cheesecoin"), "got:\n{out}");
        assert!(!out.contains("$Cheesecoin"), "no symbol means no ticker:\n{out}");
    }

    /// Holder risk appears only when readable. A fabricated "0 holders" would
    /// read as a rug on a perfectly healthy token.
    #[test]
    fn holder_risk_renders_only_when_known() {
        let out = render_signal(&signal(), None, None, Some(&market()), None, None, 8);
        assert!(!out.contains("Holders:"), "unknown must be omitted:\n{out}");

        let h = crate::rpc::HolderStats {
            count: 14,
            capped: false,
            top10_pct: 6.1,
            largest_pct: 91.7,
        };
        let out = render_signal(&signal(), None, None, Some(&market()), None, Some(&h), 8);
        assert!(out.contains("Holders: 14"), "got:\n{out}");
        assert!(out.contains("Top10: 6.1%"), "got:\n{out}");
        // 20 is the RPC ceiling, so a full page is a floor, not a count.
        let capped = crate::rpc::HolderStats { count: 20, capped: true, ..h };
        let out = render_signal(&signal(), None, None, Some(&market()), None, Some(&capped), 8);
        assert!(out.contains("Holders: 20+"), "a capped count must say so:\n{out}");
    }

    /// Socials render inline with the chart link, and only when present.
    #[test]
    fn socials_render_beside_the_chart_link() {
        let none = render_signal(&signal(), None, None, Some(&market()), None, None, 8);
        assert!(none.contains(">Chart</a>"));
        assert!(!none.contains(">X</a>"), "no socials means no pipes:\n{none}");

        let soc = crate::socials::Socials {
            twitter: Some("https://x.com/foo".into()),
            telegram: None,
            website: Some("https://example.com".into()),
            image: None,
        };
        let out = render_signal(&signal(), None, None, Some(&market()), Some(&soc), None, 8);
        assert!(out.contains(r#"| <a href="https://x.com/foo">X</a>"#), "got:\n{out}");
        assert!(out.contains(r#"| <a href="https://example.com">Web</a>"#), "got:\n{out}");
        assert!(!out.contains(">TG</a>"), "absent link must not render:\n{out}");
    }

    /// A missing SOL/USD rate must not blank the volume figure.
    #[test]
    fn without_a_rate_it_falls_back_to_sol_rather_than_dropping_figures() {
        let out = render_signal(&signal(), None, None, None, None, None, 8);
        assert!(out.contains("Vol: 26.39 SOL"), "got:\n{out}");
        assert!(!out.contains("MC:"), "no rate means no market cap to claim");
    }

    /// A zero rate is a broken rate, not free tokens.
    #[test]
    fn a_zero_rate_is_treated_as_unknown() {
        let broken = MarketSnapshot { sol_usd: 0.0, price_usd: None, fdv_usd: None };
        let out = render_signal(&signal(), None, None, Some(&broken), None, None, 8);
        assert!(out.contains("26.39 SOL"), "got:\n{out}");
    }

    #[test]
    fn token_name_from_chain_is_escaped() {
        let evil = ("<b>PUMP</b>".to_string(), "X".to_string());
        let out = render_signal(&signal(), Some(&evil), None, Some(&market()), None, None, 8);
        assert!(out.contains("&lt;b&gt;PUMP&lt;/b&gt;"));
        assert!(!out.contains("<b>PUMP</b>"));
    }
}
