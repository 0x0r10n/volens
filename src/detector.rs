//! The detector: connect to Yellowstone gRPC, subscribe to transactions on the
//! target programs, decode pool creations, filter, and dispatch to alerts +
//! storage. Owns the reconnect/backoff loop.

use crate::alerts::Alerter;
use crate::config::Config;
use crate::dedup::Dedup;
use crate::rpc::RpcClient;
use crate::metrics::{self, Metrics};
use crate::model::{Dex, PoolEvent};
use crate::parser::{self, ParsedPool, TargetProgram};
use crate::storage::Storage;
use crate::watcher;
#[cfg(feature = "sniper")]
use crate::sniper::Sniper;
use anyhow::{Context, Result};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use yellowstone_grpc_client::{ClientTlsConfig, GeyserGrpcClient};
use yellowstone_grpc_proto::prelude::{
    CommitmentLevel, SubscribeRequest, SubscribeRequestFilterTransactions, subscribe_update::UpdateOneof,
};

/// Strip credentials before logging an endpoint.
///
/// Provider RPC URLs carry the API key in the query string (Helius) or the
/// path (Triton, QuickNode). Logging one verbatim leaks it into log files,
/// shipped log aggregators, and any screenshot the operator posts asking for
/// help. Only host survives.
fn redact(url: &str) -> String {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = no_scheme.split(['/', '?']).next().unwrap_or(no_scheme);
    format!("{host}/…")
}

pub struct Detector {
    cfg: Arc<Config>,
    alerter: Arc<Alerter>,
    storage: Arc<Storage>,
    targets: Vec<TargetProgram>,
    quote_mints: Vec<String>,
    dedup: Dedup,
    metrics: Arc<Metrics>,
    rpc: Arc<RpcClient>,
    #[cfg(feature = "sniper")]
    sniper: Arc<Sniper>,
}

impl Detector {
    pub fn new(cfg: Arc<Config>, alerter: Arc<Alerter>, storage: Arc<Storage>) -> Result<Self> {
        let targets: Vec<TargetProgram> =
            cfg.enabled_dexes().into_iter().map(TargetProgram::new).collect();
        let quote_mints = cfg.filters.quote_mints.clone();
        let dedup = Dedup::new(Duration::from_secs(cfg.alerts.dedup_ttl_secs));
        let rpc = Arc::new(RpcClient::new(&cfg.rpc));
        #[cfg(feature = "sniper")]
        let sniper = Arc::new(Sniper::new(cfg.sniper.clone(), rpc.clone(), &cfg.rpc)?);
        Ok(Self {
            cfg,
            alerter,
            storage,
            targets,
            quote_mints,
            dedup,
            metrics: Arc::new(Metrics::default()),
            rpc,
            #[cfg(feature = "sniper")]
            sniper,
        })
    }

    /// Shared counter handle, so the Telegram command bot reports the same
    /// numbers the periodic reporter logs.
    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// Ping the RPC once at startup and report the result loudly.
    ///
    /// Severity is deliberately graded rather than uniform:
    ///
    /// * **Nothing needs the RPC** — skipped silently. A detector-only run is a
    ///   legitimate configuration, not a degraded one.
    /// * **Enrichment needs it** — a hard `WARN` and the run continues. Losing
    ///   liquidity and safety data is bad but not dangerous: the filters fail
    ///   open to "unknown", which is visible in the alerts themselves.
    /// * **Armed** — a startup ERROR that stops the process. An armed sniper
    ///   with a dead RPC would build trades from unreadable pool state and
    ///   rehearse nothing, so every guard that depends on a live read becomes
    ///   inert exactly when money is at stake. Refusing to start is the only
    ///   honest option.
    async fn check_rpc_health(&self) -> Result<()> {
        let needs_rpc = self.cfg.liquidity.enabled
            || self.cfg.safety.enabled
            || self.cfg.watch.enabled
            || self.cfg.sniper.enabled;
        if !needs_rpc {
            return Ok(());
        }

        // Only true in a build that can actually trade — `armed` is ignored
        // without the feature, and the config layer already errors on that.
        #[cfg(feature = "sniper")]
        let armed = self.cfg.sniper.armed;
        #[cfg(not(feature = "sniper"))]
        let armed = false;

        match self.rpc.health().await {
            Ok(()) => {
                info!(commitment = %self.cfg.rpc.commitment, "RPC endpoint healthy");
                Ok(())
            }
            Err(reason) if armed => {
                anyhow::bail!(
                    "RPC health check FAILED ({reason}) and the sniper is ARMED. \
                     Refusing to start: liquidity, mint-safety and preflight all \
                     depend on this endpoint, and trading with them unreadable is \
                     not safe. Fix [rpc].url / RPC_URL, or disarm."
                );
            }
            Err(reason) => {
                warn!(
                    reason = %reason,
                    "*** RPC HEALTH CHECK FAILED *** liquidity, mint-safety, watcher \
                     and dry-run simulation will all report UNKNOWN. Detection still \
                     works (separate gRPC endpoint), so alerts will keep arriving \
                     with enrichment fields missing. Fix [rpc].url or RPC_URL."
                );
                Ok(())
            }
        }
    }

    /// Shared RPC client, for the command bot's `/balance`.
    pub fn rpc(&self) -> Arc<RpcClient> {
        self.rpc.clone()
    }

    /// Shared sniper, so `/balance` can report the trading wallet.
    #[cfg(feature = "sniper")]
    pub fn sniper(&self) -> Arc<Sniper> {
        self.sniper.clone()
    }

    /// Run until `shutdown` flips to true. Reconnects with exponential backoff on
    /// any stream/connection error.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if self.targets.is_empty() {
            anyhow::bail!("no DEXes enabled — check [filters].programs");
        }
        info!(
            dexes = ?self.cfg.enabled_dexes().iter().map(|d| d.label()).collect::<Vec<_>>(),
            commitment = %self.cfg.grpc.commitment,
            "starting detector"
        );

        self.check_rpc_health().await?;

        #[cfg(feature = "sniper")]
        self.sniper.prepare().await?;

        metrics::spawn_reporter(
            self.metrics.clone(),
            Duration::from_secs(60),
            shutdown.clone(),
        );

        let min = Duration::from_secs(self.cfg.grpc.backoff_min_secs.max(1));
        let max = Duration::from_secs(self.cfg.grpc.backoff_max_secs.max(1));
        let mut backoff = min;

        // Source selection. gRPC is preferred whenever it is configured; the
        // WebSocket path exists so a standard RPC plan still works at all.
        let ws_url = self.resolve_ws_url();
        let mut using_ws = if self.cfg.grpc.is_configured() {
            false
        } else {
            let Some(url) = ws_url.as_deref() else {
                anyhow::bail!(
                    "no transaction source available: gRPC is not configured \
                     (GRPC_ENDPOINT) and no RPC url is set to fall back to \
                     ([rpc].url / RPC_URL)"
                );
            };
            warn!(
                url = %redact(url),
                "no gRPC endpoint configured — using WebSocket logsSubscribe. \
                 Detection runs SECONDS behind gRPC (getTransaction cannot read \
                 below `confirmed` commitment). Set GRPC_ENDPOINT for the fast path."
            );
            true
        };

        // Consecutive gRPC connect failures, reset by any healthy session.
        let mut grpc_failures = 0u32;

        loop {
            if *shutdown.borrow() {
                break;
            }

            // `connected` is set once the subscription is live, so a session that
            // got established and later dropped restarts from the minimum backoff
            // instead of inheriting the previous failure's growth.
            let mut connected = false;
            let session = if using_ws {
                let url = ws_url.clone().expect("ws url checked at selection");
                self.ws_stream_once(&url, &mut shutdown, &mut connected).await
            } else {
                let r = self.stream_once(&mut shutdown, &mut connected).await;
                // Only a failure to ESTABLISH counts toward fallback. A session
                // that connected and later dropped is a normal reconnect, not
                // evidence that gRPC is unavailable.
                if r.is_err() && !connected {
                    grpc_failures += 1;
                    if self.cfg.grpc.fallback_to_websocket
                        && grpc_failures >= self.cfg.grpc.max_failures_before_fallback
                    {
                        match ws_url.as_deref() {
                            Some(url) => {
                                warn!(
                                    failures = grpc_failures,
                                    url = %redact(url),
                                    "*** FALLING BACK TO WEBSOCKET *** gRPC failed to connect \
                                     repeatedly. Detection continues but runs SECONDS behind \
                                     (getTransaction cannot read below `confirmed`). This is \
                                     permanent for this process — restart once gRPC is fixed."
                                );
                                using_ws = true;
                                backoff = min;
                            }
                            None => warn!(
                                failures = grpc_failures,
                                "gRPC failing and no RPC url configured to fall back to"
                            ),
                        }
                    }
                } else if connected {
                    grpc_failures = 0;
                }
                r
            };

            match session {
                // Clean shutdown requested from inside the stream loop.
                Ok(()) => break,
                Err(e) => {
                    if *shutdown.borrow() {
                        break;
                    }
                    if connected {
                        backoff = min;
                    }
                    // `{:#}` renders the full anyhow context chain (e.g.
                    // "connecting to <ep>: transport error: connection refused"),
                    // which is what you actually need to debug a dead endpoint.
                    let cause = format!("{e:#}");
                    warn!(error = %cause, backoff_secs = backoff.as_secs(), "stream error; reconnecting");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
                    }
                    backoff = (backoff * 2).min(max);
                }
            }
        }

        info!("detector stopped");
        Ok(())
    }

    /// Resolve the WebSocket URL: explicit override, else derived from the RPC
    /// url. `None` when there is no RPC url to derive from.
    fn resolve_ws_url(&self) -> Option<String> {
        if !self.cfg.rpc.ws_url.trim().is_empty() {
            return Some(self.cfg.rpc.ws_url.trim().to_string());
        }
        if self.cfg.rpc.url.trim().is_empty() {
            return None;
        }
        match crate::ws::derive_ws_url(&self.cfg.rpc.url) {
            Ok(u) => Some(u),
            Err(e) => {
                warn!(error = %e, "could not derive a WebSocket URL from [rpc].url");
                None
            }
        }
    }

    /// One WebSocket session: subscribe to logs, fetch each candidate, and feed
    /// the results through the exact same `handle_transaction` the gRPC path
    /// uses. Everything downstream is source-agnostic by construction.
    async fn ws_stream_once(
        &self,
        ws_url: &str,
        shutdown: &mut watch::Receiver<bool>,
        connected: &mut bool,
    ) -> Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Bounded: if the pipeline stalls, backpressure slows the fetchers
        // rather than growing an unbounded queue of stale pools.
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let dexes = self.cfg.enabled_dexes();
        let flag = AtomicBool::new(false);
        let mut sd = shutdown.clone();

        let session = crate::ws::stream_once(ws_url, self.rpc.clone(), &dexes, tx, &mut sd, &flag);
        tokio::pin!(session);

        loop {
            tokio::select! {
                r = &mut session => {
                    *connected = flag.load(Ordering::Relaxed);
                    return r;
                }
                Some(item) = rx.recv() => {
                    *connected = flag.load(Ordering::Relaxed);
                    self.handle_transaction(&item.info, item.slot).await;
                }
            }
        }
    }

    /// One connect + subscribe + consume session. Returns Ok(()) only on a
    /// requested shutdown; any transport error is returned as Err to trigger
    /// backoff/reconnect. Sets `connected = true` once the subscription is live
    /// so the caller can reset its backoff.
    async fn stream_once(
        &self,
        shutdown: &mut watch::Receiver<bool>,
        connected: &mut bool,
    ) -> Result<()> {
        let endpoint = self.cfg.grpc.endpoint.clone();
        let token = if self.cfg.grpc.x_token.is_empty() {
            None
        } else {
            Some(self.cfg.grpc.x_token.clone())
        };

        let mut client = GeyserGrpcClient::build_from_shared(endpoint.clone())
            .context("invalid gRPC endpoint")?
            .x_token(token)
            .context("invalid x-token")?
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .context("tls config")?
            .connect()
            .await
            .with_context(|| format!("connecting to {endpoint}"))?;

        let request = self.build_request();
        // `_request_sink` must stay bound for the lifetime of this function:
        // it is the client->server half of the bidi stream, and dropping it
        // tears down the subscription. Do not replace with `let _ = ...`.
        let (_request_sink, mut stream) = client
            .subscribe_with_request(Some(request))
            .await
            .context("subscribe")?;

        *connected = true;
        info!("connected & subscribed");

        loop {
            tokio::select! {
                item = stream.next() => {
                    let Some(item) = item else {
                        anyhow::bail!("stream ended");
                    };
                    let update = item.context("stream item error")?;
                    if let Some(UpdateOneof::Transaction(tx_update)) = update.update_oneof {
                        if let Some(tx_info) = tx_update.transaction.as_ref() {
                            // Skip vote txs and failed txs cheaply.
                            if tx_info.is_vote {
                                continue;
                            }
                            if let Some(meta) = tx_info.meta.as_ref() {
                                if meta.err.is_some() {
                                    continue;
                                }
                            }
                            self.handle_transaction(tx_info, tx_update.slot).await;
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("shutdown signal received; closing stream");
                        return Ok(());
                    }
                }
            }
        }
    }

    fn build_request(&self) -> SubscribeRequest {
        let program_ids: Vec<String> =
            self.targets.iter().map(|t| t.dex.program_id().to_string()).collect();

        let mut transactions = HashMap::new();
        transactions.insert(
            "pool_creations".to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                signature: None,
                account_include: program_ids,
                account_exclude: vec![],
                account_required: vec![],
                token_accounts: None,
            },
        );

        SubscribeRequest {
            accounts: HashMap::new(),
            slots: HashMap::new(),
            transactions,
            transactions_status: HashMap::new(),
            blocks: HashMap::new(),
            blocks_meta: HashMap::new(),
            entry: HashMap::new(),
            commitment: Some(self.commitment() as i32),
            accounts_data_slice: vec![],
            ping: None,
            from_slot: None,
        }
    }

    fn commitment(&self) -> CommitmentLevel {
        match self.cfg.grpc.commitment.as_str() {
            "confirmed" => CommitmentLevel::Confirmed,
            "finalized" => CommitmentLevel::Finalized,
            _ => CommitmentLevel::Processed,
        }
    }

    async fn handle_transaction(
        &self,
        tx_info: &yellowstone_grpc_proto::prelude::SubscribeUpdateTransactionInfo,
        slot: u64,
    ) {
        self.metrics.incr(&self.metrics.tx_seen);

        let parsed = parser::parse_transaction(tx_info, &self.targets);
        if parsed.is_empty() {
            return;
        }
        let signature = parser::signature_b58(tx_info);

        for p in parsed {
            self.metrics.incr(&self.metrics.parsed);

            let Some(event) = self.classify(p, &signature, slot) else {
                self.metrics.incr(&self.metrics.filtered_out);
                continue;
            };

            // Dedup BEFORE either sink. A single transaction can yield the same
            // pool twice (top-level instruction + inner CPI), and a gRPC
            // reconnect can replay a slot — without this, storage records
            // duplicates even when alerts are suppressed.
            if !self.dedup.check_and_insert(&event.pool) {
                self.metrics.incr(&self.metrics.duplicates);
                debug!(pool = %event.pool, "duplicate pool suppressed");
                continue;
            }
            // Hand off to a task: the liquidity read is a network round-trip
            // with retries, and awaiting it here would stall consumption of the
            // gRPC stream and back-pressure the whole detector.
            self.spawn_finalize(event);
        }
    }

    /// Optionally read quote-side liquidity, apply the threshold, then emit.
    fn spawn_finalize(&self, mut event: PoolEvent) {
        let alerter = self.alerter.clone();
        let storage = self.storage.clone();
        let metrics = self.metrics.clone();
        let rpc = self.rpc.clone();
        let enabled = self.cfg.liquidity.enabled;
        let min_liq = self.cfg.liquidity.min_quote_liquidity;
        let emit_on_unknown = self.cfg.liquidity.emit_on_unknown;
        let safety = self.cfg.safety.clone();
        let watch = self.cfg.watch.clone();
        #[cfg(feature = "sniper")]
        let sniper = self.sniper.clone();
        #[cfg(feature = "sniper")]
        let verbose_rehearsals = self.cfg.sniper.alert_on_all_rehearsals;

        tokio::spawn(async move {
            if enabled {
                match event.quote_asset_vault.clone() {
                    Some(vault) => {
                        let balance = rpc.vault_balance(&vault).await;
                        event.quote_liquidity = balance;

                        match balance {
                            Some(b) if b < min_liq => {
                                metrics.incr(&metrics.low_liquidity_filtered);
                                debug!(
                                    pool = %event.pool,
                                    liquidity = b,
                                    threshold = min_liq,
                                    "below liquidity threshold, dropped"
                                );
                                return;
                            }
                            None if !emit_on_unknown => {
                                metrics.incr(&metrics.low_liquidity_filtered);
                                debug!(pool = %event.pool, "liquidity unknown, dropped");
                                return;
                            }
                            _ => {}
                        }
                    }
                    // No recognized quote asset means no meaningful side to
                    // measure; the quote-pair filter governs these instead.
                    None => debug!(pool = %event.pool, "no quote vault, skipping liquidity check"),
                }
            }

            // Mint-safety checks on the launched token. A live mint authority
            // means supply can be inflated at will; a live freeze authority is
            // the classic honeypot (buy freely, then get frozen out of selling).
            if safety.enabled {
                if let Some(mint) = event.new_token_mint.clone() {
                    match rpc.mint_info(&mint).await {
                        Some(info) => {
                            event.mint_authority_revoked = Some(info.mint_authority_revoked());
                            event.freeze_authority_revoked = Some(info.freeze_authority_revoked());
                            event.risky_extensions = info.risky_extensions.clone();

                            let mut reasons: Vec<&str> = Vec::new();
                            if safety.require_mint_authority_revoked && !info.mint_authority_revoked() {
                                reasons.push("mint authority live");
                            }
                            if safety.require_freeze_authority_revoked
                                && !info.freeze_authority_revoked()
                            {
                                reasons.push("freeze authority live");
                            }
                            if safety.reject_risky_extensions && !info.risky_extensions.is_empty() {
                                reasons.push("risky token-2022 extension");
                            }
                            if !reasons.is_empty() {
                                metrics.incr(&metrics.unsafe_mint_filtered);
                                debug!(
                                    pool = %event.pool,
                                    mint = %mint,
                                    reasons = ?reasons,
                                    extensions = ?info.risky_extensions,
                                    "unsafe mint, dropped"
                                );
                                return;
                            }
                        }
                        None if !safety.emit_on_unknown => {
                            metrics.incr(&metrics.unsafe_mint_filtered);
                            debug!(pool = %event.pool, "mint unreadable, dropped");
                            return;
                        }
                        None => debug!(pool = %event.pool, "mint unreadable, emitting anyway"),
                    }
                }
            }

            metrics.incr(&metrics.detected);
            info!(
                dex = event.dex.label(),
                pool = %event.pool,
                token = event.new_token_mint.as_deref().unwrap_or("?"),
                quote = event.quote_asset.as_deref().unwrap_or("?"),
                liquidity = event.quote_liquidity.unwrap_or(f64::NAN),
                mint_revoked = ?event.mint_authority_revoked,
                freeze_revoked = ?event.freeze_authority_revoked,
                slot = event.slot,
                sig = %event.signature,
                "🟢 new pool detected"
            );
            storage.record(&event).await;
            // In secured-LP mode the detection alert is suppressed: LP lock/burn
            // is a LATER transaction, so at t=0 every pool looks unlocked and
            // alerting here means alerting on everything. The watcher re-check
            // becomes the alert, firing only once the LP is actually secured.
            // Detection is still logged and persisted either way.
            if !(watch.enabled && watch.alert_only_secured_lp) {
                alerter.notify(&event).await;
            }

            // Auto-execution, if compiled in. Runs after the alert so a slow or
            // refused trade never delays notification.
            // Guard mode does NOT buy here: at t=0 every pool's LP is still
            // unlocked, so the decision is deferred to the watcher re-check,
            // which buys only once the LP is confirmed burned/locked.
            #[cfg(feature = "sniper")]
            if sniper.snipe_mode() == crate::sniper::SnipeMode::Open {
                let exec = sniper.handle(&event).await;
                // Alerting lives here, not in the sniper: a failing Telegram
                // call must not sit inside the execution path. Routine skips
                // are filtered by `is_alertable` so the channel stays signal.
                if exec.is_alertable(verbose_rehearsals)
                    && let Some(msg) = crate::alerts::render_execution(&exec)
                {
                    alerter.send_html(msg).await;
                }
            }

            // Schedule the delayed re-check. LP custody and rug-by-liquidity-pull
            // are only observable after the fact, so this runs later rather than
            // gating the alert.
            if watch.enabled {
                // Baseline the LP supply NOW. The follow-up compares against
                // this; without a "before" reading a zero supply later proves
                // nothing (an LP mint that was always empty is not a burn).
                if let Some(lp) = event.lp_mint.clone() {
                    event.lp_supply_at_detection = rpc.token_supply(&lp).await;
                }
                // Guard mode buys from inside the watcher, so it needs the
                // sniper. A unit value in a detector-only build.
                #[cfg(feature = "sniper")]
                let sniper_handle: watcher::SniperHandle = Some(sniper.clone());
                #[cfg(not(feature = "sniper"))]
                let sniper_handle: watcher::SniperHandle = ();
                watcher::spawn_watch(
                    event,
                    rpc.clone(),
                    alerter.clone(),
                    storage.clone(),
                    metrics.clone(),
                    watch,
                    sniper_handle,
                );
            }
        });
    }

    /// Apply quote-pair filtering and classify which mint is the new token.
    fn classify(&self, p: ParsedPool, signature: &str, slot: u64) -> Option<PoolEvent> {
        classify_pool(
            p,
            &self.quote_mints,
            self.cfg.filters.require_quote_pair,
            signature,
            slot,
        )
    }
}

/// Pure classification: decide which side is the launched token, which side is
/// the recognized quote asset, and therefore which vault measures real capital.
///
/// Free-standing so it can be tested without constructing a whole `Detector`.
pub fn classify_pool(
    p: ParsedPool,
    quote_mints: &[String],
    require_quote_pair: bool,
    signature: &str,
    slot: u64,
) -> Option<PoolEvent> {
    {
        let base_is_quote = quote_mints.contains(&p.base_mint);
        let quote_is_quote = quote_mints.contains(&p.quote_mint);

        // Pick the vault on the SAME side as the recognized quote asset. Vault
        // and mint are paired by index (base_vault holds base_mint), and since
        // orientation flips between venues we must follow the classification
        // rather than assume the quote side is `quote_mint`.
        let (new_token_mint, quote_asset, quote_asset_vault) =
            match (base_is_quote, quote_is_quote) {
                // base is the new token, quote side is the recognized asset.
                (false, true) => (
                    Some(p.base_mint.clone()),
                    Some(p.quote_mint.clone()),
                    Some(p.quote_vault.clone()),
                ),
                // Reversed (Raydium CPMM / PumpSwap): WSOL sits on the base side.
                (true, false) => (
                    Some(p.quote_mint.clone()),
                    Some(p.base_mint.clone()),
                    Some(p.base_vault.clone()),
                ),
                (true, true) => {
                    // Both sides are quote assets (e.g. WSOL/USDC) — not a launch.
                    (None, Some(p.quote_mint.clone()), Some(p.quote_vault.clone()))
                }
                (false, false) => (None, None, None),
            };

        if require_quote_pair && quote_asset.is_none() {
            return None;
        }

        Some(PoolEvent {
            dex: p.dex,
            pool: p.pool,
            base_mint: p.base_mint,
            quote_mint: p.quote_mint,
            new_token_mint,
            quote_asset,
            quote_asset_vault,
            quote_liquidity: None,
            mint_authority_revoked: None,
            freeze_authority_revoked: None,
            risky_extensions: Vec::new(),
            base_vault: Some(p.base_vault.clone()),
            quote_vault: Some(p.quote_vault.clone()),
            swap_accounts: p.swap_accounts.clone(),
            lp_mint: Some(p.lp_mint.clone()),
            lp_supply_at_detection: None,
            signature: signature.to_string(),
            slot,
            detected_at: chrono::Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{USDC_MINT, WSOL_MINT};

    fn quotes() -> Vec<String> {
        vec![WSOL_MINT.to_string(), USDC_MINT.to_string()]
    }

    fn parsed(dex: Dex, base_mint: &str, quote_mint: &str) -> ParsedPool {
        ParsedPool {
            dex,
            pool: "POOL".into(),
            base_mint: base_mint.into(),
            quote_mint: quote_mint.into(),
            base_vault: "BASE_VAULT".into(),
            quote_vault: "QUOTE_VAULT".into(),
            lp_mint: "LP_MINT".into(),
            swap_accounts: Default::default(),
        }
    }

    /// Raydium v4 orientation: new token on base, WSOL on quote.
    /// The measurable side is therefore the QUOTE vault.
    #[test]
    fn v4_orientation_picks_quote_vault() {
        let p = parsed(Dex::RaydiumV4, "NEWTOKEN", WSOL_MINT);
        let ev = classify_pool(p, &quotes(), true, "sig", 1).unwrap();

        assert_eq!(ev.new_token_mint.as_deref(), Some("NEWTOKEN"));
        assert_eq!(ev.quote_asset.as_deref(), Some(WSOL_MINT));
        assert_eq!(ev.quote_asset_vault.as_deref(), Some("QUOTE_VAULT"));
    }

    /// CPMM / PumpSwap orientation: WSOL sits on the BASE side, so the
    /// measurable side is the BASE vault. Getting this backwards would read the
    /// memecoin vault and compare a token count against a SOL threshold.
    #[test]
    fn reversed_orientation_picks_base_vault() {
        for dex in [Dex::RaydiumCpmm, Dex::PumpSwap] {
            let p = parsed(dex, WSOL_MINT, "NEWTOKEN");
            let ev = classify_pool(p, &quotes(), true, "sig", 1).unwrap();

            assert_eq!(ev.new_token_mint.as_deref(), Some("NEWTOKEN"), "{dex:?}");
            assert_eq!(ev.quote_asset.as_deref(), Some(WSOL_MINT), "{dex:?}");
            assert_eq!(
                ev.quote_asset_vault.as_deref(),
                Some("BASE_VAULT"),
                "{dex:?} must measure the WSOL side, which is the base vault"
            );
        }
    }

    #[test]
    fn usdc_pair_is_recognized() {
        let p = parsed(Dex::RaydiumV4, "NEWTOKEN", USDC_MINT);
        let ev = classify_pool(p, &quotes(), true, "sig", 1).unwrap();
        assert_eq!(ev.quote_asset.as_deref(), Some(USDC_MINT));
        assert_eq!(ev.quote_asset_vault.as_deref(), Some("QUOTE_VAULT"));
    }

    #[test]
    fn exotic_pair_dropped_when_quote_required() {
        let p = parsed(Dex::RaydiumV4, "TOKEN_A", "TOKEN_B");
        assert!(classify_pool(p, &quotes(), true, "sig", 1).is_none());
    }

    /// With the filter off, an exotic pair still emits but has nothing to measure.
    #[test]
    fn exotic_pair_emitted_without_vault_when_filter_off() {
        let p = parsed(Dex::RaydiumV4, "TOKEN_A", "TOKEN_B");
        let ev = classify_pool(p, &quotes(), false, "sig", 1).unwrap();
        assert!(ev.new_token_mint.is_none());
        assert!(ev.quote_asset_vault.is_none());
        assert!(ev.quote_liquidity.is_none());
    }

    /// WSOL/USDC is two quote assets, not a token launch.
    #[test]
    fn quote_to_quote_pair_has_no_new_token() {
        let p = parsed(Dex::RaydiumV4, WSOL_MINT, USDC_MINT);
        let ev = classify_pool(p, &quotes(), true, "sig", 1).unwrap();
        assert!(ev.new_token_mint.is_none());
    }
}

/// Log a one-line summary of which programs we watch. Small helper kept public
/// so `main` can print startup context without reaching into internals.
pub fn describe_targets(cfg: &Config) -> String {
    cfg.enabled_dexes()
        .iter()
        .map(|d: &Dex| format!("{} ({})", d.label(), d.program_id()))
        .collect::<Vec<_>>()
        .join(", ")
}
