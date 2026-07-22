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
//!   pool's reserves: `price = quote_reserve / base_reserve`. This is
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

/// Did this outcome move funds? Mirrors the `SubmitOutcome::Executed` cases.
/// Deliberately strict — an `unconfirmed`/`error`/`would-*` outcome is NOT a
/// confirmed spend and must not be counted as cost basis.
fn executed(outcome: &str) -> bool {
    outcome.starts_with("confirmed:") || outcome.starts_with("bundle_landed:")
}

/// Mid-price mark of a holding, in quote units (SOL/USDC).
///
/// `value = held_tokens * (quote_reserve / base_reserve)`. This is the pool's
/// current mid-price — NOT a slippage-adjusted sell quote, so it overstates what
/// a large or illiquid position would actually fetch. Returns `None` if the
/// reserves can't price it (empty base reserve → no meaningful price).
pub fn mid_price_value(quote_reserve: f64, base_reserve: f64, held_tokens: f64) -> Option<f64> {
    if base_reserve <= 0.0 || !quote_reserve.is_finite() || !held_tokens.is_finite() {
        return None;
    }
    let price = quote_reserve / base_reserve;
    Some(held_tokens * price)
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
}
