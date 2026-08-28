//! Position tracking and PnL for `/positions`.
//!
//! # What's real and what isn't
//!
//! PnL has two halves and only one is easy:
//!
//! * **Holdings** (what the wallet has now) — read live from the chain.
//! * **Cost basis** (what was paid) — the bot can only know this for buys IT
//!   made, reconstructed from the audit log. It cannot know the cost of tokens
//!   that arrived by manual buys or airdrops, so those show as "untracked".
//! * **Current value** (to get the PnL number) — a mid-price mark from the
//!   pool's reserves: `price = sol_reserve / token_reserve`, where orientation
//!   is resolved by reading which mint each vault actually holds (the pool's own
//!   "base"/"quote" naming is venue-relative and cannot be trusted). This is
//!   **mark-to-mid**, not what you'd actually receive selling into a thin pool
//!   (that includes slippage), so it flatters small/illiquid positions. Labelled
//!   as an estimate for that reason.
//!
//! Until real trades happen, the cost-basis map is empty and `/positions` shows
//! holdings only. The plumbing fills in automatically once the bot executes.

use std::collections::HashMap;

/// A position the bot opened, aggregated across all its buys of one token.
#[derive(Debug, Clone, PartialEq)]
pub struct CostBasis {
    pub pool: String,
    pub dex: String,
    /// Total quote (SOL/USDC) spent buying this token.
    pub sol_spent: f64,
    /// Number of executed buys aggregated here.
    pub trades: u32,
    /// Vaults for pricing, if the audit recorded them.
    pub base_vault: Option<String>,
    pub quote_vault: Option<String>,
}

/// Parse the sniper audit log into per-token cost basis.
///
/// Counts ONLY executed live buys — `mode == "armed"` with an outcome that
/// actually moved funds (`confirmed:` / `bundle_landed:`). Dry-run rehearsals,
/// skips, failures, and indeterminate outcomes are excluded: cost basis must
/// reflect money that truly left the wallet, or the PnL is fiction.
///
/// Malformed lines are skipped, not fatal — a half-written final line (crash
/// mid-append) must not blank the whole history.
pub fn cost_basis_from_audit(audit_jsonl: &str) -> HashMap<String, CostBasis> {
    let mut out: HashMap<String, CostBasis> = HashMap::new();

    for line in audit_jsonl.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        if rec.get("mode").and_then(|m| m.as_str()) != Some("armed") {
            continue;
        }
        let outcome = rec.get("outcome").and_then(|o| o.as_str()).unwrap_or("");
        if !executed(outcome) {
            continue;
        }

        // Smart-money entries are a different record shape: no `plan`, and the
        // mint and size at the top level.
        //
        // These were invisible here, because the filter below skipped every
        // record carrying an `action`. Cost basis is how `sweep_exits` FINDS a
        // position, so a smart-money buy could never be seen by take-profit,
        // stop-loss or trailing — the position was held until it was worthless
        // and nothing in the logs said why.
        match rec.get("action").and_then(|a| a.as_str()) {
            None => {}
            // An Alpha entry is money out of the wallet exactly like any other
            // buy, so it carries cost basis identically. The tag only decides
            // which exit rules the position gets, never whether it is counted.
            Some("smart_buy") | Some("alpha_buy") => {
                let Some(mint) = rec.get("mint").and_then(|m| m.as_str()) else { continue };
                let size = rec.get("sol").and_then(|s| s.as_f64()).unwrap_or(0.0);
                if size <= 0.0 {
                    continue;
                }
                let entry = out.entry(mint.to_string()).or_insert_with(|| CostBasis {
                    // No pool: the entry was routed, not built from a pool we
                    // decoded. Selling falls back accordingly.
                    pool: String::new(),
                    dex: "routed".to_string(),
                    sol_spent: 0.0,
                    trades: 0,
                    base_vault: None,
                    quote_vault: None,
                });
                entry.sol_spent += size;
                entry.trades += 1;
                continue;
            }
            // Sells and withdrawals: a `confirmed:` on those must never count
            // as buy spend.
            Some(_) => continue,
        }

        let Some(plan) = rec.get("plan") else { continue };
        let Some(mint) = plan.get("token_mint").and_then(|m| m.as_str()) else {
            continue;
        };
        let size = plan.get("size").and_then(|s| s.as_f64()).unwrap_or(0.0);
        if size <= 0.0 {
            continue;
        }

        let entry = out.entry(mint.to_string()).or_insert_with(|| CostBasis {
            pool: plan.get("pool").and_then(|p| p.as_str()).unwrap_or("").to_string(),
            dex: rec.get("dex").and_then(|d| d.as_str()).unwrap_or("?").to_string(),
            sol_spent: 0.0,
            trades: 0,
            base_vault: rec.get("base_vault").and_then(|v| v.as_str()).map(str::to_string),
            quote_vault: rec.get("quote_vault").and_then(|v| v.as_str()).map(str::to_string),
        });
        entry.sol_spent += size;
        entry.trades += 1;
    }

    out
}

/// Mints opened by ALPHA SMART MONEY MODE, from the same audit log.
///
/// A position is Alpha if any executed Alpha buy contributed to it. Both
/// triggers may fire on the same token, and when they do there is still only
/// ONE position on chain with one balance and one cost basis — so there is only
/// one set of exits to apply, and this decides which.
///
/// Alpha wins the overlap deliberately. It is the more specific thesis: it
/// fired because a wallet with a measured record bought, and its TP/SL were
/// chosen for exactly that case. Letting the general rules govern a position
/// that Alpha also wanted would mean the Alpha settings silently did nothing on
/// precisely the strongest signals the mode exists to catch.
pub fn alpha_mints_from_audit(audit_jsonl: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for line in audit_jsonl.lines() {
        let Ok(rec) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        if rec.get("action").and_then(|a| a.as_str()) != Some("alpha_buy") {
            continue;
        }
        // Same bar as cost basis: only entries that actually moved funds. A
        // rehearsed or failed Alpha buy did not open a position, so it must not
        // redirect the exits of one opened by the normal trigger.
        if rec.get("mode").and_then(|m| m.as_str()) != Some("armed") {
            continue;
        }
        if !executed(rec.get("outcome").and_then(|o| o.as_str()).unwrap_or("")) {
            continue;
        }
        if let Some(mint) = rec.get("mint").and_then(|m| m.as_str()) {
            out.insert(mint.to_string());
        }
    }
    out
}

/// Did this outcome move funds? Mirrors the `SubmitOutcome::Executed` cases.
/// Deliberately strict — an `unconfirmed`/`error`/`would-*` outcome is NOT a
/// confirmed spend and must not be counted as cost basis.
fn executed(outcome: &str) -> bool {
    outcome.starts_with("confirmed:") || outcome.starts_with("bundle_landed:")
}

/// Mid-price mark of a holding, in SOL.
///
/// `value = held_tokens * (sol_reserve / token_reserve)`. This is the pool's
/// current mid-price — NOT a slippage-adjusted sell quote, so it overstates what
/// a large or illiquid position would actually fetch. Returns `None` if the
/// reserves can't price it (empty token reserve → no meaningful price).
///
/// Parameters are deliberately named by WHAT THE VAULT HOLDS, not by the pool's "base"/"quote"
/// field names. Those names are venue-relative — on Raydium CPMM and PumpSwap
/// the "base" side is WSOL — and naming these parameters after them once caused
/// the price to be computed upside down (tokens-per-SOL), marking positions
/// millions of times off. The caller must resolve orientation from the vault's
/// actual mint before calling this.
pub fn mid_price_value(sol_reserve: f64, token_reserve: f64, held_tokens: f64) -> Option<f64> {
    if token_reserve <= 0.0 || !sol_reserve.is_finite() || !held_tokens.is_finite() {
        return None;
    }
    let price_sol_per_token = sol_reserve / token_reserve;
    Some(held_tokens * price_sol_per_token)
}

/// Unrealized PnL given cost basis and a current mark.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pnl {
    pub cost: f64,
    pub value: f64,
    pub abs: f64,
    pub pct: f64,
}

pub fn unrealized(cost: f64, value: f64) -> Pnl {
    let abs = value - cost;
    let pct = if cost > 0.0 { abs / cost * 100.0 } else { 0.0 };
    Pnl { cost, value, abs, pct }
}

#[cfg(test)]
mod tests {

    /// The bug that made auto-sell blind.
    ///
    /// Smart-money entries are audited with an `action` field and no `plan`,
    /// and the filter skipped every record carrying an `action`. Cost basis is
    /// how `sweep_exits` FINDS a position, so take-profit, stop-loss and
    /// trailing never saw one — the position was held to zero and nothing said
    /// why.
    #[test]
    fn a_smart_money_buy_produces_a_cost_basis() {
        let log = r#"
{"ts":"2026-08-16T01:00:00Z","action":"smart_buy","mint":"MINT_A","sol":0.05,"outcome":"confirmed:abc","mode":"armed"}
{"ts":"2026-08-16T01:05:00Z","action":"smart_buy","mint":"MINT_A","sol":0.05,"outcome":"confirmed:def","mode":"armed"}
"#;
        let basis = cost_basis_from_audit(log);
        let a = basis.get("MINT_A").expect("a routed entry is still a position");
        assert!((a.sol_spent - 0.10).abs() < 1e-9);
        assert_eq!(a.trades, 2);
    }

    /// The guard against the failure that actually happened: the writer and
    /// the reader drifting apart.
    ///
    /// This feeds the REAL record produced by the sniper through the reader,
    /// rather than a hand-written line that can be updated to match while the
    /// production format quietly does not.
    #[cfg(feature = "sniper")]
    #[test]
    fn the_reader_understands_what_the_writer_actually_writes() {
        let rec = crate::sniper::smart_buy_record(
            "OWNER", "MINT_A", 0.05, "4 tracked wallets in window", "confirmed:sig", true, false,
        );
        let basis = cost_basis_from_audit(&rec.to_string());
        let a = basis
            .get("MINT_A")
            .expect("a position the bot opened must be visible to the exit policy");
        assert!((a.sol_spent - 0.05).abs() < 1e-9);

        // …and a rehearsal from the same writer must NOT become a position.
        let dry = crate::sniper::smart_buy_record(
            "OWNER", "MINT_A", 0.05, "r", "would-succeed", false, false,
        );
        assert!(cost_basis_from_audit(&dry.to_string()).is_empty());
    }

    /// Sells and withdrawals must still be excluded — a `confirmed:` on those
    /// is money leaving, not money spent acquiring.
    #[test]
    fn sells_and_withdrawals_are_not_buy_spend() {
        let log = r#"
{"ts":"2026-08-16T01:00:00Z","action":"sell","mint":"MINT_A","sol":0.9,"outcome":"confirmed:x","mode":"armed"}
{"ts":"2026-08-16T01:01:00Z","action":"withdraw","mint":"MINT_A","sol":1.0,"outcome":"confirmed:y","mode":"armed"}
"#;
        assert!(cost_basis_from_audit(log).is_empty());
    }

    /// A rehearsal is not a position. Dry-run records must never appear as
    /// money spent.
    #[test]
    fn a_rehearsed_smart_buy_is_not_a_position() {
        let log = r#"
{"ts":"2026-08-16T01:00:00Z","action":"smart_buy","mint":"MINT_A","sol":0.05,"outcome":"would-succeed","mode":"dry_run"}
"#;
        assert!(cost_basis_from_audit(log).is_empty());
    }
    use super::*;

    const T1: &str = "So11111111111111111111111111111111111111112";

    /// Only executed live buys count. Rehearsals, skips, failures, and
    /// unconfirmed sends must NOT contribute cost basis — that would invent
    /// spending that never happened.
    #[test]
    fn only_executed_armed_buys_count_as_cost_basis() {
        let log = format!(
            r#"{{"mode":"dry_run","outcome":"would-succeed","plan":{{"token_mint":"{T1}","size":0.5,"pool":"P"}}}}
{{"mode":"armed","outcome":"confirmed:SIG1","dex":"Raydium CPMM","base_vault":"BV","quote_vault":"QV","plan":{{"token_mint":"{T1}","size":0.05,"pool":"P1"}}}}
{{"mode":"armed","outcome":"confirmed:SIG2","plan":{{"token_mint":"{T1}","size":0.03,"pool":"P1"}}}}
{{"mode":"armed","outcome":"unconfirmed:SIG3","plan":{{"token_mint":"{T1}","size":9.9,"pool":"P1"}}}}
{{"mode":"armed","outcome":"failed:blah","plan":{{"token_mint":"{T1}","size":9.9,"pool":"P1"}}}}
{{"mode":"armed","decision":"skipped","denial":"disabled","outcome":null,"plan":null}}"#
        );
        let cb = cost_basis_from_audit(&log);
        let p = cb.get(T1).expect("token tracked");
        // 0.05 + 0.03 = 0.08. The dry-run 0.5, unconfirmed 9.9, failed 9.9 excluded.
        assert!((p.sol_spent - 0.08).abs() < 1e-9, "got {}", p.sol_spent);
        assert_eq!(p.trades, 2);
        assert_eq!(p.dex, "Raydium CPMM");
        assert_eq!(p.base_vault.as_deref(), Some("BV"));
    }

    /// Regression: the price is SOL-per-token. Passing the reserves the other
    /// way round (the pool's "quote_vault" first, which on PumpSwap holds the
    /// TOKEN) inverts it and marks a position millions of times too high.
    #[test]
    fn price_is_sol_per_token_not_the_inverse() {
        // 10 SOL and 1_000_000 tokens => 0.00001 SOL/token. 100k tokens = 1 SOL.
        let right = mid_price_value(10.0, 1_000_000.0, 100_000.0).unwrap();
        assert!((right - 1.0).abs() < 1e-9, "got {right}");

        // Arguments swapped: the bug that shipped. Off by 1e10 here.
        let wrong = mid_price_value(1_000_000.0, 10.0, 100_000.0).unwrap();
        assert!(wrong > right * 1e9, "inverted mark should be absurdly large");
    }

    #[test]
    fn bundle_landed_counts_too() {
        let log = format!(
            r#"{{"mode":"armed","outcome":"bundle_landed:B1","plan":{{"token_mint":"{T1}","size":0.1,"pool":"P"}}}}"#
        );
        assert!((cost_basis_from_audit(&log)[T1].sol_spent - 0.1).abs() < 1e-9);
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let log = format!(
            "not json\n{{\"mode\":\"armed\",\"outcome\":\"confirmed:S\",\"plan\":{{\"token_mint\":\"{T1}\",\"size\":0.05,\"pool\":\"P\"}}}}\n{{ broken"
        );
        let cb = cost_basis_from_audit(&log);
        assert_eq!(cb.len(), 1);
        assert!((cb[T1].sol_spent - 0.05).abs() < 1e-9);
    }

    #[test]
    fn empty_audit_is_empty_map() {
        assert!(cost_basis_from_audit("").is_empty());
        assert!(cost_basis_from_audit("\n\n").is_empty());
    }

    #[test]
    fn mid_price_marks_correctly() {
        // Pool: 100 SOL quote, 1_000_000 tokens base → price 0.0001 SOL/token.
        // Holding 200_000 tokens → 20 SOL.
        assert_eq!(mid_price_value(100.0, 1_000_000.0, 200_000.0), Some(20.0));
    }

    #[test]
    fn mid_price_refuses_to_divide_by_zero() {
        assert_eq!(mid_price_value(100.0, 0.0, 5.0), None);
    }

    #[test]
    fn pnl_math() {
        // Spent 0.05, now worth 0.08 → +0.03, +60%.
        let p = unrealized(0.05, 0.08);
        assert!((p.abs - 0.03).abs() < 1e-9);
        assert!((p.pct - 60.0).abs() < 1e-9);

        // Loss.
        let p = unrealized(0.10, 0.04);
        assert!((p.abs + 0.06).abs() < 1e-9);
        assert!((p.pct + 60.0).abs() < 1e-9);

        // Zero cost basis must not divide by zero.
        let p = unrealized(0.0, 1.0);
        assert_eq!(p.pct, 0.0);
    }

    fn alpha_line(mint: &str, mode: &str, outcome: &str) -> String {
        serde_json::json!({
            "ts": "2026-08-28T12:00:00Z", "action": "alpha_buy", "owner": "O",
            "mint": mint, "sol": 0.05, "reason": "alpha wallet W",
            "outcome": outcome, "mode": mode,
        })
        .to_string()
    }

    /// An Alpha entry is spend like any other: it must carry cost basis, or the
    /// exit sweep cannot see the position it opened.
    #[test]
    fn an_alpha_buy_produces_a_cost_basis() {
        let log = alpha_line("MINT_A", "armed", "confirmed:sig");
        let basis = cost_basis_from_audit(&log);
        assert_eq!(basis.get("MINT_A").map(|b| b.sol_spent), Some(0.05));
    }

    /// Both triggers on one token is one position with the SUM of both sizes.
    /// Counting only one would under-report what is actually at risk.
    #[test]
    fn both_triggers_on_one_token_aggregate_into_one_position() {
        let log = format!(
            "{}\n{}",
            crate::sniper::smart_buy_record(
                "O", "MINT_A", 0.05, "r", "confirmed:s1", true, false
            ),
            alpha_line("MINT_A", "armed", "confirmed:s2")
        );
        let basis = cost_basis_from_audit(&log);
        let b = basis.get("MINT_A").expect("one position");
        assert_eq!(b.trades, 2);
        assert!((b.sol_spent - 0.10).abs() < 1e-9, "0.05 + 0.05");
        assert!(
            alpha_mints_from_audit(&log).contains("MINT_A"),
            "and it is governed by the alpha exits"
        );
    }

    #[test]
    fn a_normal_buy_is_not_an_alpha_position() {
        let log = crate::sniper::smart_buy_record(
            "O", "MINT_A", 0.05, "r", "confirmed:s", true, false,
        )
        .to_string();
        assert!(alpha_mints_from_audit(&log).is_empty());
    }

    /// A rehearsed or failed Alpha buy opened nothing, so it must not divert
    /// the exits of a position the normal trigger really did open.
    #[test]
    fn only_alpha_buys_that_moved_funds_route_the_exits() {
        for (mode, outcome) in
            [("dry_run", "would-succeed"), ("armed", "error: blockhash"), ("armed", "unconfirmed")]
        {
            let log = alpha_line("MINT_A", mode, outcome);
            assert!(
                alpha_mints_from_audit(&log).is_empty(),
                "{mode}/{outcome} did not open a position"
            );
        }
    }
}
