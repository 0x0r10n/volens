//! Jito bundle submission.
//!
//! A bundle is an atomic group of up to 5 transactions executed in order by a
//! Jito-enabled validator, bypassing the public mempool. For a sniper this buys
//! two things: front-run resistance, and all-or-nothing execution.
//!
//! # Why this is SAFER than plain submission, in one specific way
//!
//! The tip is an ordinary transfer *inside* the bundle. If the bundle does not
//! land, the tip is not paid — nothing executes at all. A plain transaction that
//! fails on-chain still burns its fee; a bundle that loses simply never happens.
//!
//! # Where it is more dangerous
//!
//! Jito does **not** simulate bundles. There is no preflight, so a malformed
//! transaction is discovered only by its absence. This module therefore keeps
//! the normal RPC simulation as a mandatory gate before bundling — see
//! `Submitter::send_bundle`.
//!
//! # Contract, verified against the live block engine
//!
//! * `sendBundle` takes `[[tx, ...], {"encoding": "base64"}]`, max **5** txs
//!   (the engine rejects 6 with an explicit error).
//! * `getBundleStatuses` returns `{context, value: []}` for an unknown bundle —
//!   an EMPTY ARRAY, not an error. "Not found" must never be read as landed, and
//!   equally must not be read as failed: a bundle can be in flight.
//! * Tip accounts are fetched via `getTipAccounts` rather than hardcoded. They
//!   are operational infrastructure and can rotate; a stale list means tipping
//!   an address that no longer counts.

use anyhow::{Result, bail};
use serde_json::json;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Jito's cap on transactions per bundle.
pub const MAX_BUNDLE_TXS: usize = 5;

/// Where a bundle got to. Deliberately distinguishes "we cannot see it" from
/// both success and failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStatus {
    /// Included on-chain.
    Landed { slot: u64 },
    /// Accepted and still in flight.
    Pending,
    /// The engine rejected or dropped it.
    Failed { reason: String },
    /// The engine has no record. It may simply not have propagated yet — this
    /// is NOT a failure and NOT a success.
    Unknown,
}

impl BundleStatus {
    pub fn is_landed(&self) -> bool {
        matches!(self, BundleStatus::Landed { .. })
    }
}

pub struct JitoClient {
    client: reqwest::Client,
    url: String,
    tip_lamports: u64,
    /// Fetched from the engine, never hardcoded.
    tip_accounts: Mutex<Vec<Pubkey>>,
    /// Rotates the tip account per bundle; Jito advises spreading tips across
    /// accounts to avoid write-lock contention on a single one.
    next_tip: Mutex<usize>,
}

impl JitoClient {
    pub fn new(url: &str, tip_lamports: u64) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
            url: url.trim_end_matches('/').to_string(),
            tip_lamports,
            tip_accounts: Mutex::new(Vec::new()),
            next_tip: Mutex::new(0),
        }
    }

    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: serde_json::Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if let Some(e) = resp.get("error") {
            bail!("jito {method}: {e}");
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("jito {method}: no result"))
    }

    /// Fetch the tip accounts. Call once at startup; refuse to bundle without them.
    pub async fn refresh_tip_accounts(&self) -> Result<usize> {
        let r = self.rpc("getTipAccounts", json!([])).await?;
        let list = r
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("getTipAccounts: expected an array"))?;
        let mut parsed = Vec::with_capacity(list.len());
        for v in list {
            let s = v
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("getTipAccounts: non-string entry"))?;
            parsed.push(Pubkey::from_str(s).map_err(|e| anyhow::anyhow!("bad tip account {s}: {e}"))?);
        }
        if parsed.is_empty() {
            bail!("getTipAccounts returned an empty list");
        }
        let n = parsed.len();
        *self.tip_accounts.lock().unwrap() = parsed;
        info!(count = n, "jito tip accounts loaded");
        Ok(n)
    }

    /// The tip instruction to include in the bundle.
    ///
    /// Errors rather than skipping the tip when no accounts are loaded: an
    /// untipped bundle is simply ignored by the engine, which would look like a
    /// silent failure to land.
    pub fn tip_instruction(&self, payer: &Pubkey) -> Result<Instruction> {
        let accounts = self.tip_accounts.lock().unwrap();
        if accounts.is_empty() {
            bail!("no Jito tip accounts loaded; call refresh_tip_accounts() first");
        }
        let mut idx = self.next_tip.lock().unwrap();
        let account = accounts[*idx % accounts.len()];
        *idx = idx.wrapping_add(1);
        Ok(solana_system_interface::instruction::transfer(
            payer,
            &account,
            self.tip_lamports,
        ))
    }

    /// Submit base64-encoded transactions as one atomic bundle.
    pub async fn send_bundle(&self, txs_base64: &[String]) -> Result<String> {
        if txs_base64.is_empty() {
            bail!("cannot send an empty bundle");
        }
        if txs_base64.len() > MAX_BUNDLE_TXS {
            bail!(
                "bundle has {} transactions; Jito's maximum is {MAX_BUNDLE_TXS}",
                txs_base64.len()
            );
        }
        let r = self
            .rpc("sendBundle", json!([txs_base64, {"encoding": "base64"}]))
            .await?;
        let id = r
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("sendBundle: expected a bundle id"))?
            .to_string();
        info!(bundle = %id, txs = txs_base64.len(), "bundle submitted");
        Ok(id)
    }

    /// Look up a bundle. An empty result means the engine has no record yet,
    /// which is reported as `Unknown` rather than guessed either way.
    pub async fn bundle_status(&self, id: &str) -> Result<BundleStatus> {
        let r = self.rpc("getBundleStatuses", json!([[id]])).await?;
        let entries = r.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let Some(first) = entries.into_iter().find(|e| !e.is_null()) else {
            return Ok(BundleStatus::Unknown);
        };
        if let Some(err) = first.get("err") {
            // Jito reports `{"Ok": null}` for success.
            let ok = err.get("Ok").map(|v| v.is_null()).unwrap_or(false);
            if !ok && !err.is_null() {
                return Ok(BundleStatus::Failed { reason: err.to_string() });
            }
        }
        match first.get("confirmation_status").and_then(|v| v.as_str()) {
            Some("confirmed") | Some("finalized") => {
                let slot = first.get("slot").and_then(|v| v.as_u64()).unwrap_or(0);
                Ok(BundleStatus::Landed { slot })
            }
            _ => Ok(BundleStatus::Pending),
        }
    }

    /// Poll until landed, failed, or the deadline passes.
    ///
    /// A timeout yields the last observed state — never a fabricated success.
    pub async fn await_bundle(&self, id: &str, timeout: Duration) -> BundleStatus {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last = BundleStatus::Unknown;
        while tokio::time::Instant::now() < deadline {
            match self.bundle_status(id).await {
                Ok(s) => {
                    if s.is_landed() || matches!(s, BundleStatus::Failed { .. }) {
                        return s;
                    }
                    last = s;
                }
                Err(e) => debug!(error = %e, "bundle status poll failed"),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        warn!(bundle = %id, ?last, "bundle not resolved before timeout");
        last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> JitoClient {
        JitoClient::new("https://mainnet.block-engine.jito.wtf/api/v1/bundles", 10_000)
    }

    /// Without loaded tip accounts, tipping must fail loudly. An untipped bundle
    /// is silently ignored by the engine, which is the worst failure mode.
    #[test]
    fn tip_requires_loaded_accounts() {
        let err = client().tip_instruction(&Pubkey::new_unique()).unwrap_err().to_string();
        assert!(err.contains("tip accounts"), "got: {err}");
    }

    #[test]
    fn tip_rotates_across_accounts() {
        let c = client();
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        *c.tip_accounts.lock().unwrap() = vec![a, b];
        let payer = Pubkey::new_unique();

        let first = c.tip_instruction(&payer).unwrap().accounts[1].pubkey;
        let second = c.tip_instruction(&payer).unwrap().accounts[1].pubkey;
        let third = c.tip_instruction(&payer).unwrap().accounts[1].pubkey;
        assert_ne!(first, second, "consecutive tips must not hit one account");
        assert_eq!(first, third, "and must cycle");
    }

    #[test]
    fn tip_amount_is_carried() {
        let c = JitoClient::new("http://x", 12_345);
        *c.tip_accounts.lock().unwrap() = vec![Pubkey::new_unique()];
        let ix = c.tip_instruction(&Pubkey::new_unique()).unwrap();
        // SystemProgram transfer: 4-byte discriminant + u64 lamports.
        assert_eq!(&ix.data[4..12], &12_345u64.to_le_bytes());
    }

    #[tokio::test]
    async fn bundle_size_limit_is_enforced_before_sending() {
        let c = client();
        let six: Vec<String> = std::iter::repeat_n("AQ==".to_string(), 6).collect();
        let err = c.send_bundle(&six).await.unwrap_err().to_string();
        assert!(err.contains("maximum is 5"), "got: {err}");

        assert!(c.send_bundle(&[]).await.is_err(), "empty bundle must be refused");
    }

    /// "Unknown" must be distinguishable from both success and failure.
    #[test]
    fn unknown_is_neither_landed_nor_failed() {
        assert!(!BundleStatus::Unknown.is_landed());
        assert!(!BundleStatus::Pending.is_landed());
        assert!(BundleStatus::Landed { slot: 1 }.is_landed());
        assert!(!BundleStatus::Failed { reason: "x".into() }.is_landed());
    }

    /// LIVE: the tip accounts must be fetchable, and must parse as real pubkeys.
    ///
    ///   cargo test --features sniper -- --ignored --nocapture live_jito
    #[tokio::test]
    #[ignore = "hits the Jito block engine"]
    async fn live_jito_tip_accounts_and_status() {
        let c = client();
        let n = c.refresh_tip_accounts().await.expect("tip accounts");
        println!("loaded {n} tip accounts");
        assert!(n >= 4, "expected several tip accounts, got {n}");

        let ix = c.tip_instruction(&Pubkey::new_unique()).unwrap();
        println!("tip -> {}", ix.accounts[1].pubkey);
        assert_eq!(ix.program_id, solana_system_interface::program::ID);

        // An unknown bundle id must read as Unknown, not as landed or failed.
        let st = c
            .bundle_status("0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .expect("status query");
        println!("unknown bundle -> {st:?}");
        assert_eq!(st, BundleStatus::Unknown);
    }
}
