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

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One wallet's first buy of a token inside the current window.
#[derive(Debug, Clone)]
struct Buyer {
    wallet: String,
    name: String,
    at: Instant,
    sol: f64,
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
    /// Seconds between the first and latest buy. Small values mean the
    /// convergence was tight, which is the stronger version of the signal.
    pub spread_secs: u64,
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
    /// Full sweeps are O(tokens); doing one per buy would be wasteful at 861
    /// tx/min. Sweep when the map has grown instead.
    sweep_at: usize,
}

impl ConvictionTracker {
    pub fn new(window: Duration, threshold: usize) -> Self {
        Self {
            window,
            // A threshold below 2 makes every single buy a "signal", which is
            // the noise this module exists to remove.
            threshold: threshold.max(2),
            tokens: HashMap::new(),
            sweep_at: 512,
        }
    }

    /// Record a buy. Returns a signal only when this buy is from a wallet not
    /// already counted for this token AND the distinct count is at or above the
    /// threshold.
    ///
    /// Returning `None` for a repeat buy by an already-counted wallet is the
    /// deliberate part: it stops one wallet scaling into a position from
    /// re-alerting the same token indefinitely.
    pub fn record(
        &mut self,
        mint: &str,
        wallet: &str,
        name: &str,
        sol: f64,
        now: Instant,
    ) -> Option<ConvictionSignal> {
        if self.tokens.len() > self.sweep_at {
            self.sweep(now);
        }

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
            sol,
        });

        if entries.len() < self.threshold {
            return None;
        }

        let oldest = entries.iter().map(|b| b.at).min().unwrap_or(now);
        Some(ConvictionSignal {
            mint: mint.to_string(),
            distinct_buyers: entries.len(),
            total_sol: entries.iter().map(|b| b.sol).sum(),
            buyers: entries.iter().map(|b| (b.name.clone(), b.sol)).collect(),
            spread_secs: now.duration_since(oldest).as_secs(),
        })
    }

    /// Distinct buyers currently inside the window, for `/conviction`.
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

    /// Drop tokens whose entries have all expired. Without this the map grows
    /// for every token any tracked wallet has ever touched.
    pub fn sweep(&mut self, now: Instant) {
        let window = self.window;
        self.tokens.retain(|_, buyers| {
            buyers.retain(|b| now.duration_since(b.at) < window);
            !buyers.is_empty()
        });
    }

    pub fn tracked_tokens(&self) -> usize {
        self.tokens.len()
    }
}

/// Render a conviction signal as a Telegram HTML message.
///
/// Buyer names are already sanitized at load time (`wallets::sanitize_name`),
/// so they are safe to interpolate here. The mint goes in a `<code>` block
/// because Telegram copies a code block's literal contents on tap.
pub fn render_signal(
    signal: &ConvictionSignal,
    meta: Option<&(String, String)>,
    mint_info: Option<&crate::rpc::MintInfo>,
) -> String {
    let mut s = String::new();

    let title = match meta {
        Some((name, symbol)) if !name.is_empty() => {
            format!("{} ({})", html_escape(name), html_escape(symbol))
        }
        _ => "Unknown token".to_string(),
    };

    s.push_str(&format!(
        "🧠 <b>SMART MONEY</b> — {} wallets\n<b>{}</b>\n",
        signal.distinct_buyers, title
    ));
    s.push_str(&format!("<code>{}</code>\n\n", signal.mint));

    for (name, sol) in &signal.buyers {
        s.push_str(&format!("• {name} — {sol:.2} SOL\n"));
    }

    s.push_str(&format!(
        "\n<b>{:.2} SOL</b> total, within {}\n",
        signal.total_sol,
        format_spread(signal.spread_secs)
    ));

    // Safety is advisory here, not a gate. An explicit "unverified" is kept
    // distinct from "clean": failing to read a mint is not evidence of safety.
    match mint_info {
        Some(info) => {
            let mut flags = Vec::new();
            if info.mint_authority.is_some() {
                flags.push("mint authority LIVE");
            }
            if info.freeze_authority.is_some() {
                flags.push("freeze authority LIVE");
            }
            if !info.risky_extensions.is_empty() {
                flags.push("risky extensions");
            }
            if flags.is_empty() {
                s.push_str("✅ mint clean\n");
            } else {
                s.push_str(&format!("⚠️ <b>{}</b>\n", flags.join(", ")));
            }
        }
        None => s.push_str("❓ mint safety unverified\n"),
    }

    s.push_str(&format!(
        "\n<a href=\"https://dexscreener.com/solana/{}\">chart</a>",
        signal.mint
    ));
    s
}

fn format_spread(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m{}s", secs / 60, secs % 60)
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINT: &str = "TokenMint111111111111111111111111111111111";

    fn tracker() -> ConvictionTracker {
        ConvictionTracker::new(Duration::from_secs(600), 2)
    }

    #[test]
    fn one_buyer_is_silent() {
        let mut t = tracker();
        assert!(t.record(MINT, "W1", "Alice", 1.0, Instant::now()).is_none());
    }

    #[test]
    fn second_distinct_buyer_signals() {
        let mut t = tracker();
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "Alice", 1.0, now).is_none());

        let s = t.record(MINT, "W2", "Bob", 2.5, now + Duration::from_secs(60)).unwrap();
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
                t.record(MINT, "W1", "Alice", 1.0, at).is_none(),
                "buy {i} from the same wallet must not signal"
            );
        }
    }

    #[test]
    fn escalates_on_each_new_distinct_buyer() {
        let mut t = tracker();
        let now = Instant::now();
        t.record(MINT, "W1", "A", 1.0, now);
        assert_eq!(t.record(MINT, "W2", "B", 1.0, now).unwrap().distinct_buyers, 2);
        assert_eq!(t.record(MINT, "W3", "C", 1.0, now).unwrap().distinct_buyers, 3);
        assert_eq!(t.record(MINT, "W4", "D", 1.0, now).unwrap().distinct_buyers, 4);
    }

    /// Buys outside the window are not convergence — they are two unrelated
    /// people who happened to buy the same thing an hour apart.
    #[test]
    fn buys_outside_the_window_do_not_combine() {
        let mut t = tracker();
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "Alice", 1.0, now).is_none());

        // 11 minutes later: the first buy has aged out, so this is buyer #1.
        let late = now + Duration::from_secs(660);
        assert!(
            t.record(MINT, "W2", "Bob", 1.0, late).is_none(),
            "expired entry must not count toward the threshold"
        );
    }

    #[test]
    fn a_wallet_can_count_again_after_its_entry_expires() {
        let mut t = tracker();
        let now = Instant::now();
        t.record(MINT, "W1", "Alice", 1.0, now);
        let late = now + Duration::from_secs(700);
        assert!(t.record(MINT, "W1", "Alice", 1.0, late).is_none());
        assert!(t.record(MINT, "W2", "Bob", 1.0, late).is_some());
    }

    #[test]
    fn different_tokens_are_independent() {
        let mut t = tracker();
        let now = Instant::now();
        assert!(t.record("MINT_A", "W1", "A", 1.0, now).is_none());
        assert!(
            t.record("MINT_B", "W2", "B", 1.0, now).is_none(),
            "buyers of a different token must not combine"
        );
    }

    #[test]
    fn threshold_below_two_is_clamped() {
        let mut t = ConvictionTracker::new(Duration::from_secs(600), 0);
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "A", 1.0, now).is_none(), "1 buyer is never a signal");
        assert!(t.record(MINT, "W2", "B", 1.0, now).is_some());
    }

    #[test]
    fn higher_threshold_waits() {
        let mut t = ConvictionTracker::new(Duration::from_secs(600), 3);
        let now = Instant::now();
        assert!(t.record(MINT, "W1", "A", 1.0, now).is_none());
        assert!(t.record(MINT, "W2", "B", 1.0, now).is_none());
        assert!(t.record(MINT, "W3", "C", 1.0, now).is_some());
    }

    #[test]
    fn sweep_drops_expired_tokens() {
        let mut t = tracker();
        let now = Instant::now();
        t.record("MINT_A", "W1", "A", 1.0, now);
        t.record("MINT_B", "W2", "B", 1.0, now);
        assert_eq!(t.tracked_tokens(), 2);

        t.sweep(now + Duration::from_secs(700));
        assert_eq!(t.tracked_tokens(), 0, "expired tokens must be reclaimed");
    }

    #[test]
    fn active_ranks_by_distinct_buyers() {
        let mut t = tracker();
        let now = Instant::now();
        t.record("MINT_A", "W1", "A", 1.0, now);
        t.record("MINT_B", "W1", "A", 5.0, now);
        t.record("MINT_B", "W2", "B", 5.0, now);

        let active = t.active(now);
        assert_eq!(active[0].0, "MINT_B");
        assert_eq!(active[0].1, 2);
        assert_eq!(active[1].0, "MINT_A");
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;

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
        }
    }

    #[test]
    fn renders_a_readable_alert() {
        let meta = ("Credible".to_string(), "CRED".to_string());
        let out = render_signal(&signal(), Some(&meta), None);
        println!("\n--- unverified mint ---\n{out}\n");

        assert!(out.contains("SMART MONEY"));
        assert!(out.contains("Credible (CRED)"));
        assert!(out.contains("OGANT — 25.29 SOL"));
        assert!(out.contains("2m23s"));
        // Mint in a code block so Telegram copies it on tap.
        assert!(out.contains("<code>8Ky9Bm6zSAtXeS3dA3UuVqZKqFqL2yPmXn4tRcW1abcd</code>"));
        // Unreadable safety must never render as clean.
        assert!(out.contains("unverified"));
        assert!(!out.contains("mint clean"));
    }

    #[test]
    fn a_nameless_token_still_renders() {
        let out = render_signal(&signal(), None, None);
        assert!(out.contains("Unknown token"));
    }

    /// A token name is attacker-controlled on-chain data and goes into an HTML
    /// message body. It must be escaped, not trusted.
    #[test]
    fn token_name_from_chain_is_escaped() {
        let evil = ("<b>PUMP</b>".to_string(), "X".to_string());
        let out = render_signal(&signal(), Some(&evil), None);
        assert!(out.contains("&lt;b&gt;PUMP&lt;/b&gt;"));
        assert!(!out.contains("<b>PUMP</b>"));
    }
}
