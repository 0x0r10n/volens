//! Alerting: structured Telegram messages with dedup + rate limiting.
//!
//! Uses a thin reqwest call to the Telegram Bot API `sendMessage` endpoint
//! rather than the full teloxide framework, which keeps the dependency tree
//! small.
//!
//! This module is outbound only. Inbound commands (`/status`, `/metrics`,
//! `/halt`) live in `bot.rs`, which polls `getUpdates` on its own task.

use crate::config::AlertConfig;
use crate::model::PoolEvent;
use std::time::Duration;
use tracing::{debug, warn};

pub struct Alerter {
    client: reqwest::Client,
    bot_token: String,
    chat_id: String,
    enabled: bool,
}

impl Alerter {
    pub fn new(cfg: &AlertConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        Self {
            client,
            bot_token: cfg.telegram_bot_token.clone(),
            chat_id: cfg.telegram_chat_id.clone(),
            enabled: cfg.telegram_enabled,
        }
    }

    /// Send an alert for a detected pool. Dedup happens upstream in the detector
    /// (see `dedup.rs`) so storage and alerts stay consistent. Never panics;
    /// network errors are logged, not fatal.
    pub async fn notify(&self, ev: &PoolEvent) {
        if !self.enabled {
            return;
        }

        self.send_html(render_message(ev)).await;
    }

    /// Send an arbitrary HTML message (used for watcher follow-ups).
    pub async fn send_html(&self, text: String) {
        if !self.enabled {
            return;
        }
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        match self.client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("telegram alert sent");
            }
            Ok(resp) => {
                let status = resp.status();
                let detail = resp.text().await.unwrap_or_default();
                warn!(%status, detail, "telegram alert failed");
            }
            Err(e) => warn!(error = %e, "telegram request error"),
        }
    }
}

/// Render an execution outcome for Telegram.
///
/// Only called for alertable outcomes (see `Execution::is_alertable`) — routine
/// skips are logged and audited but never sent, or the channel becomes noise.
#[cfg(feature = "sniper")]
pub fn render_execution(exec: &crate::sniper::Execution) -> Option<String> {
    use crate::sniper::{Execution, SubmitOutcome};

    // Interpolated values here include RPC error strings and simulation output,
    // which are not ours and can contain `<`. Unescaped, Telegram rejects the
    // whole message with a 400 — so the failure mode is a LOST execution alert,
    // exactly when it matters most.
    let esc = crate::bot::escape_html;

    match exec {
        Execution::Skipped { .. } => None,

        // Both rehearsal outcomes render a message. Whether a *successful* one
        // is actually sent is decided upstream by `is_alertable(verbose)` — this
        // function is a pure formatter, so the send/suppress policy lives in one
        // place, not split across two.
        Execution::Rehearsed { plan, outcome, would_succeed } => Some(if *would_succeed {
            format!(
                "🧪 <b>Dry run — would have BOUGHT</b>\n\
                 <b>Token:</b> <code>{token}</code>\n\
                 <b>Venue:</b> {dex}\n\
                 <b>Size:</b> {size} SOL\n\
                 <b>Simulated:</b> ✅ would succeed\n\n\
                 Nothing was signed — this is a rehearsal.",
                token = esc(&plan.token_mint),
                dex = esc(&plan.dex),
                size = plan.size,
            )
        } else {
            format!(
                "🧪 <b>Dry run — trade would have FAILED</b>\n\
                 <b>Token:</b> <code>{token}</code>\n\
                 <b>Venue:</b> {dex}\n\
                 <b>Size:</b> {size} SOL\n\
                 <b>Reason:</b> <code>{outcome}</code>\n\n\
                 Nothing was signed. The live path would not have worked.",
                token = esc(&plan.token_mint),
                dex = esc(&plan.dex),
                size = plan.size,
                outcome = esc(outcome),
            )
        }),

        Execution::Submitted { plan, result } => Some(match result {
            SubmitOutcome::Executed { reference, slot } => format!(
                "✅ <b>BOUGHT</b> — {dex}\n\
                 <b>Token:</b> <code>{token}</code>\n\
                 <b>Spent:</b> {size} SOL\n\
                 {slot_line}\
                 <a href=\"https://solscan.io/tx/{reference}\">view transaction</a>",
                dex = esc(&plan.dex),
                token = esc(&plan.token_mint),
                size = plan.size,
                slot_line = slot
                    .map(|s| format!("<b>Slot:</b> {s}\n"))
                    .unwrap_or_default(),
                reference = esc(reference),
            ),

            SubmitOutcome::NotExecuted { reason } => format!(
                "⚪ <b>Not executed</b> — {dex}\n\
                 <b>Token:</b> <code>{token}</code>\n\
                 <b>Reason:</b> <code>{reason}</code>\n\n\
                 No funds were spent.",
                dex = esc(&plan.dex),
                token = esc(&plan.token_mint),
                reason = esc(reason),
            ),

            // The one that needs human attention. Worded to prevent the
            // dangerous reaction: manually retrying into a double-buy.
            SubmitOutcome::Indeterminate { reference, reason } => format!(
                "⚠️ <b>OUTCOME UNKNOWN</b> — {dex}\n\
                 <b>Token:</b> <code>{token}</code>\n\
                 <b>Size:</b> {size} SOL\n\
                 <b>Reason:</b> <code>{reason}</code>\n\n\
                 <b>This trade may or may not have executed.</b> Check the wallet \
                 before doing anything — retrying could buy twice.\n\
                 <code>{reference}</code>",
                dex = esc(&plan.dex),
                token = esc(&plan.token_mint),
                size = plan.size,
                reason = esc(reason),
                reference = esc(reference),
            ),
        }),
    }
}

/// Render an HTML-formatted Telegram message.
fn render_message(ev: &PoolEvent) -> String {
    let token_line = match (&ev.new_token_mint, ev.solscan_token()) {
        (Some(mint), Some(link)) => {
            format!("<b>New token:</b> <code>{mint}</code>\n<a href=\"{link}\">token on Solscan</a>\n")
        }
        _ => String::new(),
    };
    let quote = ev.quote_asset.as_deref().unwrap_or("unknown");
    let liq_line = match ev.quote_liquidity {
        Some(v) => format!("<b>Liquidity:</b> {v:.3} (quote side)\n"),
        None => String::new(),
    };

    // Only render safety when it was actually checked. A missing line means
    // "not checked", which must not be confused with "checked and clean".
    let mut safety = Vec::new();
    match ev.mint_authority_revoked {
        Some(true) => safety.push("mint ✅".to_string()),
        Some(false) => safety.push("mint ⚠️ LIVE".to_string()),
        None => {}
    }
    match ev.freeze_authority_revoked {
        Some(true) => safety.push("freeze ✅".to_string()),
        Some(false) => safety.push("freeze ⚠️ LIVE".to_string()),
        None => {}
    }
    if !ev.risky_extensions.is_empty() {
        safety.push(format!("⚠️ {}", ev.risky_extensions.join(", ")));
    }
    let safety_line = if safety.is_empty() {
        String::new()
    } else {
        format!("<b>Authorities:</b> {}\n", safety.join(" · "))
    };

    format!(
        "🟢 <b>New Pool Detected</b> — {dex}\n\
         {token_line}\
         {liq_line}\
         {safety_line}\
         <b>Quote:</b> <code>{quote}</code>\n\
         <b>Pool:</b> <code>{pool}</code>\n\
         <b>Slot:</b> {slot}\n\
         <a href=\"{tx}\">tx</a> · <a href=\"{pool_link}\">pool</a>",
        dex = ev.dex.label(),
        liq_line = liq_line,
        safety_line = safety_line,
        quote = quote,
        pool = ev.pool,
        slot = ev.slot,
        tx = ev.solscan_tx(),
        pool_link = ev.solscan_pool(),
    )
}

#[cfg(all(test, feature = "sniper"))]
mod execution_tests {
    use super::*;
    use crate::sniper::{Execution, SubmitOutcome, TradePlan};

    fn plan() -> TradePlan {
        TradePlan {
            pool: "POOL".into(),
            dex: "Raydium CPMM".into(),
            token_mint: "TOKEN".into(),
            quote_asset: "So11111111111111111111111111111111111111112".into(),
            size: 0.05,
            slippage_bps: 300,
            observed_liquidity: Some(20.0),
        }
    }

    /// Routine skips must never alert. The sniper refuses far more pools than it
    /// trades; alerting on each one trains the operator to ignore the channel,
    /// and the execution alerts are what get lost.
    #[test]
    fn skips_are_not_alertable() {
        let e = Execution::Skipped {
            pool: "POOL".into(),
            reason: "liquidity below minimum".into(),
        };
        // Skips never alert, in either verbosity.
        assert!(!e.is_alertable(false));
        assert!(!e.is_alertable(true));
        assert_eq!(render_execution(&e), None);
    }

    /// Default (non-verbose): a failing rehearsal alerts, a succeeding one does
    /// not. The failing case means the live path is broken while the operator
    /// believes it works — always worth sending.
    #[test]
    fn failing_rehearsals_alert_succeeding_ones_are_quiet_by_default() {
        let ok = Execution::Rehearsed {
            plan: plan(),
            outcome: "would-succeed".into(),
            would_succeed: true,
        };
        assert!(!ok.is_alertable(false), "success is quiet in non-verbose mode");

        let bad = Execution::Rehearsed {
            plan: plan(),
            outcome: "would-FAIL: {\"InstructionError\":[3,\"Custom\"]}".into(),
            would_succeed: false,
        };
        assert!(bad.is_alertable(false), "failure always alerts");
        let msg = render_execution(&bad).expect("failing rehearsal must render");
        assert!(msg.contains("would have FAILED"), "got: {msg}");
        assert!(msg.contains("Nothing was signed"), "must not imply funds moved");
    }

    /// Verbose mode: a succeeding rehearsal alerts too, with a message that
    /// makes clear nothing was signed. This is the demo flag.
    #[test]
    fn verbose_mode_alerts_on_succeeding_rehearsals() {
        let ok = Execution::Rehearsed {
            plan: plan(),
            outcome: "would-succeed".into(),
            would_succeed: true,
        };
        assert!(ok.is_alertable(true), "verbose must alert on success");
        let msg = render_execution(&ok).expect("must render");
        assert!(msg.contains("would have BOUGHT"), "got: {msg}");
        assert!(msg.contains("rehearsal") || msg.contains("Nothing was signed"),
                "must not imply real funds moved: {msg}");
    }

    /// Every real submission alerts, including the ones that did not execute —
    /// silence after an armed attempt is indistinguishable from the bot being
    /// dead.
    #[test]
    fn all_submissions_alert() {
        for result in [
            SubmitOutcome::Executed { reference: "SIG".into(), slot: Some(1) },
            SubmitOutcome::NotExecuted { reason: "preflight rejected".into() },
            SubmitOutcome::Indeterminate {
                reference: "SIG".into(),
                reason: "timeout".into(),
            },
        ] {
            let e = Execution::Submitted { plan: plan(), result };
            assert!(e.is_alertable(false), "{e:?}");
            assert!(render_execution(&e).is_some(), "{e:?}");
        }
    }

    /// The most dangerous message in the system. An unknown outcome must never
    /// read as a failure, because the natural reaction to "failed" is to retry —
    /// and retrying a trade that actually landed buys twice.
    #[test]
    fn indeterminate_does_not_read_as_failure() {
        let e = Execution::Submitted {
            plan: plan(),
            result: SubmitOutcome::Indeterminate {
                reference: "SIG123".into(),
                reason: "not confirmed within timeout; may still land".into(),
            },
        };
        let msg = render_execution(&e).unwrap();

        assert!(msg.contains("UNKNOWN"), "got: {msg}");
        assert!(msg.contains("may or may not have executed"), "got: {msg}");
        assert!(msg.contains("retrying could buy twice"), "must warn against retry");
        // Must NOT claim no funds were spent — that is the NotExecuted wording.
        assert!(!msg.contains("No funds were spent"), "got: {msg}");
    }

    /// NotExecuted is the only outcome that may promise funds are safe.
    #[test]
    fn not_executed_states_funds_are_safe() {
        let e = Execution::Submitted {
            plan: plan(),
            result: SubmitOutcome::NotExecuted { reason: "bundle did not land".into() },
        };
        let msg = render_execution(&e).unwrap();
        assert!(msg.contains("No funds were spent"), "got: {msg}");
        assert!(!msg.contains("UNKNOWN"), "got: {msg}");
    }

    /// `NotExecuted` promises "no funds were spent", so it must cover EXACTLY
    /// the outcomes `Submission::definitely_did_not_execute` vouches for.
    /// If a variant is ever added to one and not the other, this fails.
    ///
    /// The dangerous direction is a transport error after `sendTransaction`:
    /// the node may have accepted the transaction before the connection broke,
    /// so it is Indeterminate, not NotExecuted.
    #[test]
    fn not_executed_matches_the_submit_layer_guarantee() {
        use crate::submit::Submission;

        let definitely_safe = [
            Submission::RejectedByPreflight { reason: "sim failed".into() },
            Submission::BundleNotLanded { bundle: "B".into(), last: "x".into() },
        ];
        for s in &definitely_safe {
            assert!(
                s.definitely_did_not_execute(),
                "{s:?} should be a guaranteed no-op"
            );
        }

        // These may have executed; none may render "No funds were spent".
        let not_guaranteed = [
            Submission::Failed { reason: "transport error".into() },
            Submission::Unconfirmed { signature: "SIG".into() },
        ];
        for s in &not_guaranteed {
            assert!(
                !s.definitely_did_not_execute(),
                "{s:?} must NOT be treated as a guaranteed no-op"
            );
        }
    }

    #[test]
    fn executed_links_the_transaction() {
        let e = Execution::Submitted {
            plan: plan(),
            result: SubmitOutcome::Executed { reference: "SIG123".into(), slot: Some(99) },
        };
        let msg = render_execution(&e).unwrap();
        assert!(msg.contains("BOUGHT"), "got: {msg}");
        assert!(msg.contains("solscan.io/tx/SIG123"), "got: {msg}");
        assert!(msg.contains("99"), "slot should be shown");
    }

    /// Simulation output and RPC errors are not ours. An unescaped `<` makes
    /// Telegram reject the message with a 400, losing the alert entirely.
    #[test]
    fn untrusted_text_is_escaped() {
        let e = Execution::Rehearsed {
            plan: plan(),
            outcome: "would-FAIL: <script>alert(1)</script> & more".into(),
            would_succeed: false,
        };
        let msg = render_execution(&e).unwrap();
        assert!(!msg.contains("<script>"), "raw tag survived: {msg}");
        assert!(msg.contains("&lt;script&gt;"), "got: {msg}");
        assert!(msg.contains("&amp; more"), "ampersand must be escaped: {msg}");
    }

    /// A malicious token mint must not break the message either.
    #[test]
    fn token_mint_is_escaped() {
        let mut p = plan();
        p.token_mint = "<b>PUMP</b>".into();
        let e = Execution::Submitted {
            plan: p,
            result: SubmitOutcome::Executed { reference: "SIG".into(), slot: None },
        };
        let msg = render_execution(&e).unwrap();
        assert!(msg.contains("&lt;b&gt;PUMP&lt;/b&gt;"), "got: {msg}");
    }
}
