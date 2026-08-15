//! Where a held token can be sold back to SOL.
//!
//! # Why this file exists
//!
//! The only exit path was Jupiter — the same service that IP-blocked this box
//! repeatedly, that was removed from the pricing path for exactly that reason,
//! and that killed two scoring runs in one afternoon. An exit that depends on a
//! third party which has already refused us is not an exit; it is a hope. A
//! stop-loss routed through it would fail precisely when it is needed, which is
//! worse than having none, because it would be trusted.
//!
//! A direct sell needs the pool's accounts. Some of them cannot be recovered
//! after the fact:
//!
//! * PumpSwap's `pool_v2` is **captured from the pool's creation transaction**
//!   and cannot be derived — roughly 400 candidate PDA seeds were tried and
//!   none produce it. Miss it at buy time and that position can never be sold
//!   directly, ever.
//! * Raydium v4's `open_orders` / `market` live in the AMM account, which this
//!   codebase has no decoder for.
//!
//! At the moment we buy we are holding a fully-populated `PoolEvent` containing
//! all of it. So the route is recorded then, rather than reconstructed later
//! from a decoder that does not exist against an account that may by then have
//! migrated.
//!
//! Append-only, last-write-wins on replay: a position re-bought through a
//! different pool ends up pointing at the pool actually used.

use crate::model::PoolEvent;
use std::collections::HashMap;
use std::sync::Mutex;

/// Sell routes, keyed by token mint.
pub struct RouteStore {
    path: String,
    inner: Mutex<HashMap<String, PoolEvent>>,
}

impl RouteStore {
    /// Replay the log. A malformed line is skipped, never fatal: one bad record
    /// must not cost us the exit route for every other position.
    pub fn load(path: &str) -> Self {
        let mut map = HashMap::new();
        if let Ok(raw) = std::fs::read_to_string(path) {
            for line in raw.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<PoolEvent>(line) {
                    Ok(ev) => {
                        if let Some(mint) = ev.new_token_mint.clone() {
                            map.insert(mint, ev);
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "skipping malformed sell route"),
                }
            }
        }
        if !map.is_empty() {
            tracing::info!(routes = map.len(), path, "sell routes loaded");
        }
        Self { path: path.to_string(), inner: Mutex::new(map) }
    }

    pub fn ephemeral() -> Self {
        Self { path: String::new(), inner: Mutex::new(HashMap::new()) }
    }

    /// Record how to get out of a position we are about to enter.
    ///
    /// Called BEFORE submitting the buy, deliberately. If it were written after
    /// a confirmed fill, a crash between submit and confirm would leave a
    /// position on chain with no recorded way out.
    pub fn remember(&self, ev: &PoolEvent) {
        let Some(mint) = ev.new_token_mint.clone() else { return };
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).insert(mint.clone(), ev.clone());
        if self.path.is_empty() {
            return;
        }
        match serde_json::to_string(ev) {
            Ok(mut line) => {
                line.push('\n');
                use std::io::Write;
                let appended = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                    .and_then(|mut f| f.write_all(line.as_bytes()));
                if let Err(e) = appended {
                    // Loud: the position is still sellable this session via the
                    // in-memory copy, but a restart would lose the route.
                    tracing::warn!(error = %e, mint, "could not persist sell route");
                }
            }
            Err(e) => tracing::warn!(error = %e, mint, "could not encode sell route"),
        }
    }

    pub fn get(&self, mint: &str) -> Option<PoolEvent> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).get(mint).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dex, SwapAccounts};

    fn ev(mint: &str, pool_v2: Option<&str>) -> PoolEvent {
        PoolEvent {
            dex: Dex::PumpSwap,
            pool: "POOL".into(),
            base_mint: mint.into(),
            quote_mint: crate::model::WSOL_MINT.into(),
            new_token_mint: Some(mint.into()),
            quote_asset: Some(crate::model::WSOL_MINT.into()),
            quote_asset_vault: None,
            quote_liquidity: Some(20.0),
            mint_authority_revoked: Some(true),
            freeze_authority_revoked: Some(true),
            risky_extensions: Vec::new(),
            lp_mint: None,
            base_vault: Some("BASEV".into()),
            quote_vault: Some("QUOTEV".into()),
            swap_accounts: SwapAccounts {
                pool_v2: pool_v2.map(str::to_string),
                ..Default::default()
            },
            lp_supply_at_detection: None,
            token_name: None,
            token_symbol: None,
            signature: "SIG".into(),
            slot: 1,
            detected_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn a_route_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-routes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("routes.jsonl").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let s = RouteStore::load(&p);
        s.remember(&ev("MINT_A", Some("POOLV2")));
        assert_eq!(s.len(), 1);

        let reloaded = RouteStore::load(&p);
        let got = reloaded.get("MINT_A").expect("route must survive");
        // The undocumented, underivable account is the whole reason this is
        // captured at buy time rather than rebuilt later.
        assert_eq!(got.swap_accounts.pool_v2.as_deref(), Some("POOLV2"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn re_buying_updates_the_route_to_the_pool_actually_used() {
        let s = RouteStore::ephemeral();
        s.remember(&ev("MINT_A", Some("FIRST")));
        let mut second = ev("MINT_A", Some("SECOND"));
        second.pool = "POOL2".into();
        s.remember(&second);
        assert_eq!(s.len(), 1, "one route per mint");
        assert_eq!(s.get("MINT_A").unwrap().pool, "POOL2");
    }

    #[test]
    fn an_unknown_mint_has_no_route() {
        assert!(RouteStore::ephemeral().get("NEVER_BOUGHT").is_none());
    }

    /// One corrupt line must not cost us every other exit route.
    #[test]
    fn a_malformed_line_does_not_lose_the_rest() {
        let dir = std::env::temp_dir().join(format!("volens-routes2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("routes.jsonl").to_string_lossy().to_string();
        let good = serde_json::to_string(&ev("MINT_B", Some("V2"))).unwrap();
        std::fs::write(&p, format!("{{ not json\n{good}\n")).unwrap();

        let s = RouteStore::load(&p);
        assert!(s.get("MINT_B").is_some(), "the good route must still load");
        let _ = std::fs::remove_file(&p);
    }
}
