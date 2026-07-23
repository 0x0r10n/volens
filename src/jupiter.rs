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
    pub fn price_impact_pct(&self) -> f64 {
        self.raw
            .get("priceImpactPct")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
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
    pub async fn quote(
        &self,
        input_mint: &str,
        output_mint: &str,
        amount: u64,
        slippage_bps: u16,
    ) -> Result<Quote> {
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
        let raw: Value = resp.json().await.context("jupiter quote: bad JSON")?;
        if !status.is_success() || raw.get("error").is_some() {
            bail!("jupiter quote failed ({status}): {raw}");
        }
        if raw.get("outAmount").is_none() {
            bail!("jupiter quote: no route found for this token: {raw}");
        }
        Ok(Quote { raw })
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
                "priceImpactPct": "2.5",
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
