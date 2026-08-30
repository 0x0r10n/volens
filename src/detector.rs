//! The detector: connect to Yellowstone gRPC, subscribe to transactions on the
//! target programs, decode pool creations, filter, and dispatch to alerts +
//! storage. Owns the reconnect/backoff loop.

use crate::alerts::Alerter;
use crate::config::Config;
use crate::conviction::ConvictionTracker;
use crate::dedup::Dedup;
use crate::rpc::RpcClient;
use crate::metrics::{self, Metrics};
use crate::model::{Dex, PoolEvent};
use crate::parser::{self, ParsedPool, TargetProgram};
use crate::storage::Storage;
use crate::wallets::{self, WalletBook};
use crate::watcher;
#[cfg(feature = "sniper")]
use crate::sniper::Sniper;
use anyhow::{Context, Result};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, info, warn};
use yellowstone_grpc_client::{ClientTlsConfig, GeyserGrpcClient};
use yellowstone_grpc_proto::prelude::SubscribeUpdateTransactionInfo;
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

/// Server-side filter labels. The provider echoes these back on each update so
/// one stream can carry two independent subscriptions.
const POOL_FILTER: &str = "pool_creations";
const TRACKED_FILTER: &str = "tracked_wallets";
/// Venues watched only to price tokens, never parsed for pool creations.
const PRICE_FILTER: &str = "price_feed";

pub struct Detector {
    cfg: Arc<Config>,
    alerter: Arc<Alerter>,
    storage: Arc<Storage>,
    targets: Vec<TargetProgram>,
    quote_mints: Vec<String>,
    dedup: Dedup,
    metrics: Arc<Metrics>,
    rpc: Arc<RpcClient>,
    /// Tracked "smart money" wallets. Empty when the feature is off, which is
    /// also what suppresses the second subscription.
    wallets: Arc<WalletBook>,
    /// Guarded because buys arrive from the stream task and the window is
    /// order-sensitive: two buys in the same slot must be counted in sequence.
    conviction: Arc<Mutex<ConvictionTracker>>,
    /// Announced signals, for performance updates. Always constructed so the
    /// field is not feature-shaped; it stays empty when tracking is off.
    signals: Arc<crate::signals::SignalStore>,
    /// Prices derived from the stream itself — no external API, so nothing to
    /// rate limit or IP-block.
    prices: Arc<crate::prices::PriceIndex>,
    /// Outcome sampling for EVERY token a tracked wallet buys — the data
    /// wallet scoring needs, which the call-only view cannot provide.
    outcomes: Arc<crate::outcomes::OutcomeStore>,
    #[cfg(feature = "sniper")]
    sniper: Arc<Sniper>,
    /// Mints already auto-bought, so one signal opens one position.
    #[cfg(feature = "sniper")]
    smart_bought: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Qualifying Alpha wallets, with the time they were computed.
    ///
    /// Cached because the scoring pass walks the whole signal history and this
    /// is consulted on EVERY tracked buy — roughly 861 a minute. Recomputing it
    /// per buy would put a full history scan in the hot path of the stream.
    #[cfg(feature = "sniper")]
    alpha_wallets: std::sync::Mutex<Option<(Instant, std::collections::HashSet<String>)>>,
    /// The permanent record wallet scoring is built from.
    alpha_ledger: std::sync::Arc<crate::alpha::ScoreLedger>,
    /// Tokens smart money has touched, watched for a rebound.
    #[cfg(feature = "sniper")]
    rebound: std::sync::Arc<std::sync::Mutex<crate::rebound::ReboundPool>>,
}

impl Detector {
    pub fn new(cfg: Arc<Config>, alerter: Arc<Alerter>, storage: Arc<Storage>) -> Result<Self> {
        let targets: Vec<TargetProgram> =
            cfg.enabled_dexes().into_iter().map(TargetProgram::new).collect();
        let quote_mints = cfg.filters.quote_mints.clone();
        let dedup = Dedup::new(Duration::from_secs(cfg.alerts.dedup_ttl_secs));
        let rpc = Arc::new(RpcClient::new(&cfg.rpc));
        let prices = Arc::new(crate::prices::PriceIndex::new());
        #[cfg(feature = "sniper")]
        let sniper = Arc::new(Sniper::new(
            cfg.sniper.clone(),
            rpc.clone(),
            &cfg.rpc,
            prices.clone(),
        )?);

        // Load the tracked-wallet list up front so a bad path is a startup
        // error, not a feature that silently never fires.
        let wallets = if cfg.tracked.enabled {
            let path = &cfg.tracked.wallets_path;
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading tracked wallets from {path}"))?;
            let book = WalletBook::from_export_json(&raw)
                .with_context(|| format!("parsing tracked wallets from {path}"))?;
            anyhow::ensure!(!book.is_empty(), "{path} contained no usable addresses");
            let groups = &cfg.tracked.auto_buy_groups;
            let eligible = book.count_in_groups(groups);
            info!(
                wallets = book.len(),
                auto_buy = cfg.tracked.auto_buy,
                auto_buy_eligible = eligible,
                cohorts = ?groups,
                path = %path,
                "tracked wallets loaded"
            );
            // A cohort name that matches nothing fails SILENTLY: the bot runs,
            // logs normally, alerts normally, and never buys.
            if cfg.tracked.auto_buy && !groups.is_empty() && eligible == 0 {
                anyhow::bail!(
                    "auto_buy_groups {groups:?} matched none of the {} tracked wallets — \
                     check the cohort names against the `groups` field in {path}",
                    book.len()
                );
            }
            book
        } else {
            WalletBook::default()
        };

        let cfg_signals_path = cfg.tracked.signals_path.clone();
        let cfg_pending_path = cfg.tracked.outcome_pending_path.clone();
        let cfg_outcomes_path = cfg.tracked.outcomes_path.clone();
        let conviction = ConvictionTracker::new(
            Duration::from_secs(cfg.tracked.window_secs),
            cfg.tracked.conviction_threshold,
            // A token calls once, then stays quiet for as long as it is being
            // tracked for performance — re-calling a live position is noise.
            Duration::from_secs(cfg.tracked.track_for_secs),
        );

        let alpha_ledger =
            Arc::new(crate::alpha::ScoreLedger::new(cfg.sniper.alpha_ledger_path.clone()));
        #[cfg(feature = "sniper")]
        let rebound_state_path = cfg.sniper.rebound_state_path.clone();

        Ok(Self {
            cfg,
            alerter,
            storage,
            targets,
            quote_mints,
            dedup,
            metrics: Arc::new(Metrics::default()),
            rpc,
            wallets: Arc::new(wallets),
            conviction: Arc::new(Mutex::new(conviction)),
            signals: Arc::new(crate::signals::SignalStore::load(&cfg_signals_path)),
            prices,
            outcomes: Arc::new(crate::outcomes::OutcomeStore::load(
                &cfg_pending_path,
                &cfg_outcomes_path,
            )),
            #[cfg(feature = "sniper")]
            sniper,
            #[cfg(feature = "sniper")]
            smart_bought: std::sync::Mutex::new(std::collections::HashSet::new()),
            #[cfg(feature = "sniper")]
            alpha_wallets: std::sync::Mutex::new(None),
            alpha_ledger,
            #[cfg(feature = "sniper")]
            rebound: std::sync::Arc::new(std::sync::Mutex::new(
                crate::rebound::ReboundPool::from_watches(crate::rebound::load_watches(
                    &rebound_state_path,
                )),
            )),
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

    /// The stream-derived price index, shared with the trackers.
    pub fn prices(&self) -> Arc<crate::prices::PriceIndex> {
        self.prices.clone()
    }

    /// Announced calls, for the command bot's `/calls`.
    pub fn signals(&self) -> Arc<crate::signals::SignalStore> {
        self.signals.clone()
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

        // One shared budget for every Jupiter caller in the process.
        crate::jupiter::set_min_interval_ms(self.cfg.tracked.jupiter_min_interval_ms);

        self.check_rpc_health().await?;

        #[cfg(feature = "sniper")]
        self.sniper.prepare().await?;

        metrics::spawn_reporter(
            self.metrics.clone(),
            Duration::from_secs(60),
            shutdown.clone(),
        );

        // The price index is now load-bearing for every USD figure, every
        // performance update and the market-cap ceiling. A silent price system
        // is how the previous one stayed broken for hours, so it reports.
        {
            let prices = self.prices.clone();
            let mut sd = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                        _ = sd.changed() => { if *sd.borrow() { return; } continue; }
                    }
                    // Retained for six hours, not one. The outcome sampler
                    // asks about tokens at +1h/+6h/+24h, and pruning at an
                    // hour meant those lookups found nothing and recorded a
                    // live token as unsellable. Memory is the cheaper side of
                    // that trade: a few hundred bytes per token against a
                    // corrupted scoring dataset.
                    let pruned = prices.prune(Duration::from_secs(6 * 3600));
                    match prices.sol_usd(Duration::from_secs(300)) {
                        Some(p) => info!(
                            sol_usd = format!("{p:.2}"),
                            tokens = prices.tracked_tokens(),
                            pruned,
                            "price index"
                        ),
                        None => warn!(
                            tokens = prices.tracked_tokens(),
                            "price index has NO SOL/USD — every USD figure will be blank \
                             and the market-cap ceiling will refuse trades"
                        ),
                    }
                }
            });
        }

        if self.cfg.tracked.enabled && self.cfg.tracked.track_outcomes {
            info!(
                pending = self.outcomes.len(),
                horizons = ?self.cfg.tracked.outcome_horizons_secs,
                "outcome sampling enabled"
            );
            // Spawned independently of the conviction tracker: outcome data is
            // collected for every token, including ones that never call.
            crate::outcomes::spawn_sampler(
                self.outcomes.clone(),
                self.rpc.clone(),
                self.prices.clone(),
                self.cfg.tracked.clone(),
                shutdown.clone(),
            );
        }
        if self.cfg.tracked.enabled && self.cfg.tracked.track_performance {
            info!(
                tracking = self.signals.len(),
                every_secs = self.cfg.tracked.update_check_secs,
                rungs = ?self.cfg.tracked.update_multiples,
                "conviction performance tracking enabled"
            );
            crate::signals::spawn_tracker(
                self.signals.clone(),
                self.alerter.clone(),
                self.rpc.clone(),
                self.prices.clone(),
                self.cfg.tracked.clone(),
                self.alpha_ledger.clone(),
                shutdown.clone(),
            );
        }

        // Auto-sell. Spawned unconditionally when the sniper is compiled in:
        // the policy's own `enabled` flag decides whether it acts, and that
        // flag is toggled from Telegram at runtime, so gating the task on a
        // startup value would make the button silently do nothing until the
        // next restart.
        #[cfg(feature = "sniper")]
        {
            let sniper = self.sniper.clone();
            let alerter = self.alerter.clone();
            let state = Arc::new(crate::exits::ExitStateStore::load(
                &self.cfg.sniper.exit_state_path,
            ));
            let every = Duration::from_secs(self.cfg.sniper.exit_check_secs.max(5));
            let mut shutdown = shutdown.clone();
            info!(every_secs = every.as_secs(), "auto-sell watcher started");
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { return; }
                            continue;
                        }
                    }
                    let (considered, sold) = sniper.sweep_exits(&state, &alerter).await;
                    if sold > 0 {
                        info!(considered, sold, "auto-sell sweep");
                    }
                }
            });
        }

        // REBOUND WATCHER. Checks the pool for fresh volume and takes at most
        // one entry per token per observation cycle.
        //
        // On its own loop, independent of the buy stream: the whole point is
        // that the entry comes LATER than the smart-money activity that put the
        // token on the list, so it cannot be driven by that activity arriving.
        #[cfg(feature = "sniper")]
        {
            let sniper = self.sniper.clone();
            let prices = self.prices.clone();
            let alerter = self.alerter.clone();
            let pool = self.rebound.clone();
            let signals = self.signals.clone();
            let state_path = self.cfg.sniper.rebound_state_path.clone();
            // Fresh volume means RECENT volume. The signal window is what the
            // rest of the bot already treats as "now", so it is reused rather
            // than adding another number to tune.
            let fresh_window = Duration::from_secs(self.cfg.tracked.window_secs.max(60));
            let mut shutdown = shutdown.clone();
            tokio::spawn(async move {
                let every = Duration::from_secs(30);
                // The watchlist is ~15,700 entries after 72 hours, about 2MB of
                // JSON, and a save rewrites all of it. New tokens arrive
                // constantly, so it is dirty on nearly every pass — saving each
                // time would put roughly 6GB a day of writes on the same disk
                // the trading path uses. Losing a few minutes of observations
                // to a crash costs nothing: the token is re-observed the next
                // time tracked money touches it.
                const SAVE_EVERY: Duration = Duration::from_secs(300);
                let mut last_save = Instant::now();
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                // Flush on the way out so a clean restart keeps
                                // everything, not just the last checkpoint.
                                let snapshot = {
                                    let mut p =
                                        pool.lock().unwrap_or_else(|e| e.into_inner());
                                    p.take_dirty().then(|| p.watches())
                                };
                                if let Some(w) = snapshot {
                                    crate::rebound::save_watches(&state_path, &w);
                                }
                                return;
                            }
                            continue;
                        }
                    }
                    let live = sniper.live();
                    if !live.rebound_enabled {
                        continue;
                    }
                    let watch_secs = live.rebound_watch_hours.max(1) * 3600;
                    let now = chrono::Utc::now();

                    // EXPIRY AND PERSISTENCE RUN BEFORE THE THRESHOLD GATE.
                    //
                    // Observation is on whenever the mode is, so the pool fills
                    // whether or not a threshold has been chosen. Skipping this
                    // when the threshold is unset — the exact state a new
                    // operator sits in — meant the watchlist grew for every
                    // token smart money touched and nothing ever aged out.
                    let (expired, watching, snapshot, dirty) = {
                        let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                        let n = p.expire(now, watch_secs);
                        let dirty = p.take_dirty() || n > 0;
                        (n, p.mints(), p.watches(), dirty)
                    };
                    if expired > 0 {
                        info!(expired, watching = watching.len(), "rebound: watches closed");
                    }
                    // Batched here rather than written on every observation.
                    // The pool takes on a token per tracked buy — thousands a
                    // day — and each save rewrites the whole file, so saving
                    // per observation would rewrite a large file every few
                    // seconds on the stream's own thread. Losing a few seconds
                    // of observations to a crash costs nothing: the token is
                    // re-observed the next time it is touched.
                    if dirty && last_save.elapsed() >= SAVE_EVERY {
                        crate::rebound::save_watches(&state_path, &snapshot);
                        last_save = Instant::now();
                    } else if dirty {
                        // Put the flag back: this pass did not persist, so the
                        // change is still outstanding and the next eligible pass
                        // must pick it up.
                        let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                        p.set_dirty();
                    }

                    // Nothing can trigger without a threshold, and a zero one
                    // would fire on every token in the pool.
                    if live.rebound_min_volume_sol <= 0.0 {
                        continue;
                    }

                    // A badly-chosen threshold could match hundreds of watched
                    // tokens at once. Capped per pass so Telegram is never
                    // flooded: an un-announced token keeps its flag and is
                    // picked up on the next pass, so nothing is lost — the
                    // reports are just spread out.
                    const MAX_ALERTS_PER_PASS: usize = 5;
                    let mut alerted = 0usize;

                    // Every watched token's volume under ONE lock, and the
                    // quiet ones marked under one more. Per-token locking here
                    // meant ~31,000 acquisitions a pass against the same mutex
                    // the stream writes fills through.
                    let volumes = prices.volumes_sol_in(&watching, fresh_window);
                    let (busy, quiet): (Vec<&String>, Vec<&String>) = watching
                        .iter()
                        .partition(|m| {
                            volumes.get(*m).copied().unwrap_or(0.0)
                                >= live.rebound_min_volume_sol
                        });
                    if !quiet.is_empty() {
                        // BELOW the threshold is the state a rebound comes back
                        // FROM. A token added while its buyers were still
                        // active has never been quiet and cannot rebound yet.
                        let mut newly = 0usize;
                        let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                        for m in quiet {
                            if p.mark_quiet(m) {
                                newly += 1;
                            }
                        }
                        if newly > 0 {
                            debug!(newly, "rebound: tokens gone quiet — now armed");
                        }
                    }

                    for mint in busy.into_iter().cloned() {
                        let fresh = volumes.get(&mint).copied().unwrap_or(0.0);

                        // ANNOUNCE FIRST, and independently of buying. A token
                        // that fell to nothing and started trading again is
                        // worth seeing whether or not a buy is configured.
                        let (announce, ctx) = {
                            let p = pool.lock().unwrap_or_else(|e| e.into_inner());
                            (
                                p.evaluate_alert(
                                    &mint,
                                    fresh,
                                    live.rebound_min_volume_sol,
                                    now,
                                    watch_secs,
                                ),
                                p.context(&mint),
                            )
                        };
                        if announce.is_ok() && alerted < MAX_ALERTS_PER_PASS {
                            alerted += 1;
                            let (watch_price, since) = ctx.unwrap_or((None, now));
                            let hours = (now - since).num_minutes() as f64 / 60.0;
                            let since_watch = watch_price.and_then(|p0| {
                                (p0 > 0.0).then(|| {
                                    prices
                                        .price_sol(&mint, std::time::Duration::from_secs(3600))
                                        .map(|p| p.price_sol / p0)
                                })
                            }).flatten();
                            let symbol = signals.symbol_of(&mint);
                            info!(
                                %mint,
                                fresh_volume = fresh,
                                since_watch = since_watch.unwrap_or(0.0),
                                hours,
                                "rebound: trading again"
                            );
                            {
                                let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                                p.mark_alerted(&mint);
                            }
                            alerter
                                .send_html(crate::alerts::render_rebound_signal(
                                    &mint,
                                    symbol.as_deref(),
                                    fresh,
                                    since_watch,
                                    hours,
                                ))
                                .await;
                        }

                        let armed = {
                            let p = pool.lock().unwrap_or_else(|e| e.into_inner());
                            p.evaluate(
                                &mint,
                                fresh,
                                live.rebound_min_volume_sol,
                                now,
                                watch_secs,
                            )
                        };
                        // Only the interesting outcome is logged. "Too quiet" is
                        // the normal state of nearly every watched token and
                        // would bury the log in noise every 30 seconds.
                        if armed.is_err() {
                            continue;
                        }
                        let reason = format!("rebound: {fresh:.2} SOL fresh volume");
                        let outcome = sniper.rebound_buy(&mint, &reason).await;
                        // The entry is spent only when the buy actually landed.
                        // A refusal — a veto, a position limit, a thin moment —
                        // must not burn the token's one chance for the cycle.
                        let landed = matches!(
                            outcome,
                            crate::sniper::BuyOutcome::Submitted {
                                result: crate::sniper::SubmitOutcome::Executed { .. },
                                ..
                            }
                        );
                        if landed {
                            let snapshot = {
                                let mut p = pool.lock().unwrap_or_else(|e| e.into_inner());
                                p.mark_triggered(&mint);
                                p.watches()
                            };
                            // Written immediately: a restart between the buy and
                            // the next save would re-arm a token already bought.
                            crate::rebound::save_watches(&state_path, &snapshot);
                        }
                        info!(%mint, ?outcome, landed, "rebound buy");
                        if let Some(msg) =
                            crate::alerts::render_rebound_buy(&mint, fresh, &outcome)
                        {
                            alerter.send_html(msg).await;
                        }
                    }
                }
            });
        }

        // DAILY WALLET RANKING.
        // DAILY WALLET RANKING. Scores are continuous — a wallet's record
        // accumulates across the whole lookback — so this is a periodic
        // REPORT of that running record, not a fresh measurement.
        //
        // It also prunes the archive. The ledger is the scoring history, so it
        // is pruned to the lookback and nothing tighter: dropping a call still
        // inside the window would silently shorten every wallet's record.
        #[cfg(feature = "sniper")]
        {
            let ledger = self.alpha_ledger.clone();
            let signals = self.signals.clone();
            let sniper = self.sniper.clone();
            let mut shutdown = shutdown.clone();
            tokio::spawn(async move {
                // First pass shortly after boot, then daily. A 24h-only timer
                // means a box restarted each day never ranks at all.
                let mut every = Duration::from_secs(600);
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { return; }
                            continue;
                        }
                    }
                    every = Duration::from_secs(86_400);
                    let rules = sniper.alpha_rules();
                    let now = chrono::Utc::now();
                    let dropped = ledger.prune(now, rules.lookback_secs);
                    let calls = crate::alpha::merge_calls(ledger.load(), &signals.all());
                    let ranked = crate::alpha::wallet_performance(&calls, &rules, now);
                    let qualified = ranked.iter().filter(|p| p.qualifies(&rules, now)).count();
                    info!(
                        calls_scored = calls.len(),
                        wallets_scored = ranked.len(),
                        qualified,
                        pruned = dropped,
                        lookback_days = rules.lookback_secs / 86_400,
                        "daily wallet ranking"
                    );
                    for p in ranked.iter().filter(|p| p.samples >= rules.min_samples).take(15) {
                        info!(
                            wallet = %p.address,
                            samples = p.samples,
                            hit_rate = format!("{:.1}%", p.hit_rate() * 100.0),
                            median = format!("{:.2}x", p.median_peak),
                            best = format!("{:.1}x", p.best_peak),
                            alpha = p.qualifies(&rules, now),
                            "wallet rank"
                        );
                    }
                }
            });
        }

        // LEADERBOARD. Every `leaderboard_every_secs`, post the best-performing
        // calls to the group. 0 disables.
        //
        // Deliberately NOT anchored to the wall clock: a fixed 00:00/05:00
        // schedule would drift relative to when the process actually started,
        // and a restart would either skip a post or double one. An interval
        // from boot is predictable and has no edge cases.
        if self.cfg.tracked.leaderboard_every_secs > 0 {
            let signals = self.signals.clone();
            let alerter = self.alerter.clone();
            let every = Duration::from_secs(self.cfg.tracked.leaderboard_every_secs.max(300));
            let window = self.cfg.tracked.track_for_secs;
            let tz = self.cfg.tracked.display_utc_offset_hours;
            let audit_path = self.leaderboard_audit_path();
            let mut shutdown = shutdown.clone();
            info!(every_secs = every.as_secs(), "leaderboard scheduled");
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { return; }
                            continue;
                        }
                    }
                    let now = chrono::Utc::now();
                    let calls = signals.ranked(now, window as i64);
                    if calls.is_empty() {
                        continue;
                    }
                    // Which of these the bot actually took a position in. Read
                    // from the audit log so it survives a restart — the
                    // in-memory set does not, and a leaderboard that forgets
                    // its own trades after a restart is worse than one that
                    // never marked them.
                    let traded = read_traded_mints(&audit_path).await;
                    let msg =
                        crate::alerts::render_leaderboard(&calls, &traded, window, now, tz);
                    alerter.send_html(msg).await;
                    info!(entries = calls.len(), taken = traded.len(), "leaderboard posted");
                }
            });
        }

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

        let mut client = connect_geyser(&endpoint, token).await?;

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

        // STREAM WATCHDOG.
        //
        // A subscription can be established and then deliver nothing. Observed
        // twice in one evening: `connected & subscribed` logged, `tx_seen`
        // frozen at 0 for minutes, no error, no disconnect — the reconnect
        // logic below never engaged because from its point of view the stream
        // was fine. Only a manual restart fixed it.
        //
        // That failure is worse than an outage: every other subsystem looks
        // healthy, so a bot that is completely blind reads as a quiet market.
        // On a server nobody is watching the log, and the only symptom is
        // trades that never happen.
        //
        // So silence is treated as a fault. Bailing here drops into the same
        // backoff-and-reconnect path a dropped stream takes.
        let idle_limit = Duration::from_secs(self.cfg.grpc.idle_timeout_secs.max(5));
        let mut last_item = Instant::now();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(idle_limit) => {
                    let idle = last_item.elapsed();
                    if idle >= idle_limit {
                        warn!(
                            idle_secs = idle.as_secs(),
                            limit_secs = idle_limit.as_secs(),
                            "stream delivered nothing — treating as dead and reconnecting"
                        );
                        anyhow::bail!("stream idle for {}s", idle.as_secs());
                    }
                }
                item = stream.next() => {
                    last_item = Instant::now();
                    let Some(item) = item else {
                        anyhow::bail!("stream ended");
                    };
                    let update = item.context("stream item error")?;
                    // Which filter(s) matched. Captured before `update_oneof`
                    // is moved out.
                    let matched = update.filters.clone();
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

                            // Every transaction is a price observation, not
                            // just the ones that parse as a pool creation.
                            // This is the whole price feed: ~56% of the stream
                            // yields a fill, at no network cost.
                            if let Some(meta) = tx_info.meta.as_ref() {
                                self.prices.observe(tx_info, meta);
                            }

                            let tracked = matched.iter().any(|f| f == TRACKED_FILTER);
                            let pools = matched.iter().any(|f| f == POOL_FILTER);
                            // Price-only venues are observed above and then
                            // dropped: they create no pools worth parsing, and
                            // running the parser over them is pure waste.
                            let price_only =
                                matched.iter().any(|f| f == PRICE_FILTER) && !pools && !tracked;
                            if price_only {
                                self.metrics.incr(&self.metrics.price_only_tx);
                                continue;
                            }

                            // A transaction can match BOTH filters — a tracked
                            // wallet buying into a pool it just created. Route
                            // to each handler independently rather than picking
                            // one. The `!tracked && !pools` arm covers a server
                            // that does not label updates: without it an
                            // unlabelled stream would be silently dropped.
                            if pools || (!tracked && !pools) {
                                self.handle_transaction(tx_info, tx_update.slot).await;
                            }
                            if tracked {
                                self.handle_tracked(tx_info, tx_update.slot).await;
                            }
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
            POOL_FILTER.to_string(),
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

        // Third filter: venues that create no pools we care about but DO
        // carry the trades that price a token. Without these a pump.fun
        // token trading $100k/day has no price at all.
        transactions.insert(
            PRICE_FILTER.to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                signature: None,
                account_include: crate::prices::PRICE_ONLY_PROGRAMS
                    .iter()
                    .map(|(_, p)| (*p).to_string())
                    .collect(),
                account_exclude: vec![],
                account_required: vec![],
                token_accounts: None,
            },
        );

        // Second, independent filter on the SAME stream. Separate filter keys
        // let the server label each update, so a transaction that is both a
        // pool creation and a tracked-wallet buy arrives once per filter and is
        // routed to both handlers rather than being classified as one or the
        // other. Verified against a live endpoint at 700 addresses.
        if !self.wallets.is_empty() {
            transactions.insert(
                TRACKED_FILTER.to_string(),
                SubscribeRequestFilterTransactions {
                    vote: Some(false),
                    failed: Some(false),
                    signature: None,
                    account_include: self.wallets.addresses(),
                    account_exclude: vec![],
                    account_required: vec![],
                    token_accounts: None,
                },
            );
        }

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

    /// Handle a transaction that touched a tracked wallet.
    ///
    /// Every buy is logged unconditionally — that log is the raw material for
    /// scoring which wallets are actually worth following, and it can only be
    /// collected forwards, never reconstructed later. Alerting is separate and
    /// requires conviction.
    async fn handle_tracked(&self, tx_info: &SubscribeUpdateTransactionInfo, slot: u64) {
        let signature = parser::signature_b58(tx_info);
        let buys = wallets::detect_buys(
            tx_info,
            &self.wallets,
            self.cfg.tracked.min_buy_sol,
            &signature,
            slot,
        );

        for buy in buys {
            self.metrics.incr(&self.metrics.tracked_buys);
            debug!(
                wallet = %buy.wallet_name,
                mint = %buy.mint,
                sol = buy.sol_spent,
                "tracked buy"
            );

            if self.cfg.tracked.log_all_buys {
                wallets::append_buy(&self.cfg.tracked.buys_path, &buy).await;
            }

            // Scoped so the lock is never held across an await. `record` is
            // pure map work; the alert that may follow is network-bound.
            let signal = {
                let mut tracker = match self.conviction.lock() {
                    Ok(t) => t,
                    // A panic in another task poisoned the lock. The window is
                    // rebuildable state, not something worth killing the
                    // detector over.
                    Err(poisoned) => poisoned.into_inner(),
                };
                tracker.record(
                    &buy.mint,
                    &buy.wallet,
                    &buy.wallet_name,
                    buy.sol_spent,
                    buy.fees_sol,
                    Instant::now(),
                    chrono::Utc::now(),
                )
            };

            // A token stops announcing once called, but its buys keep
            // arriving. Folding them in means an update reports volume, buyers
            // and fees as they stand NOW — otherwise every figure except market
            // cap would be frozen at the moment of the call.
            self.signals
                .add_buy(&buy.mint, &buy.wallet, buy.sol_spent, buy.fees_sol);

            // Every distinct token, not just the ones that reach a call. This
            // is the unbiased sample wallet scoring needs.
            if self.cfg.tracked.track_outcomes {
                self.outcomes.register(crate::outcomes::PendingToken {
                    mint: buy.mint.clone(),
                    first_buy_utc: chrono::Utc::now(),
                    reference_tokens_raw: buy.token_amount_raw,
                    reference_sol: buy.sol_spent,
                    // Pinned by the sampler on the first price it observes
                    // AFTER this moment — a price a follower could act on.
                    entry_price_sol: None,
                    decimals: buy.decimals,
                    first_wallet: buy.wallet.clone(),
                    sampled: Vec::new(),
                });
            }

            // --- REBOUND OBSERVATION. Every token tracked money touches goes
            // on the watchlist, whether or not anything is bought. Nothing is
            // entered here: the pool is a watchlist, not a position.
            #[cfg(feature = "sniper")]
            {
                let live = self.sniper.live();
                if live.rebound_enabled {
                    let watch_secs = live.rebound_watch_hours.max(1) * 3600;
                    // Marks the pool dirty; the watcher loop persists it. This
                    // runs on the stream's hot path, so it must not touch disk.
                    // The price now, so a later rebound can be described as
                    // "trading again at a fraction of where smart money was"
                    // rather than just "trading again". Read outside the lock.
                    let price_now = self
                        .prices
                        .price_sol(&buy.mint, std::time::Duration::from_secs(3600))
                        .map(|p| p.price_sol);
                    let (opened, watching) = {
                        let mut pool =
                            self.rebound.lock().unwrap_or_else(|p| p.into_inner());
                        let opened =
                            pool.observe(&buy.mint, chrono::Utc::now(), watch_secs, price_now);
                        (opened, pool.len())
                    };
                    if opened {
                        info!(
                            mint = %buy.mint,
                            wallet = %buy.wallet,
                            watching,
                            watch_hours = live.rebound_watch_hours,
                            "rebound: watching — touched by tracked money"
                        );
                    }
                }
            }

            // --- Auto-buy. Evaluated on EVERY tracked buy, not only when a
            // call fires: the trading threshold is higher than the alert
            // threshold, so the buy that crosses it usually arrives after the
            // alert has already gone out.
            // Read live, not from config: the operator can stop auto-buying
            // from Telegram, and that has to take effect on the next signal
            // rather than the next restart.
            #[cfg(feature = "sniper")]
            {
                let live = self.sniper.live();
                let env = self.sniper.envelope();
                if live.auto_buy_active(&env) {
                    // SOL VOLUME IS THE TRIGGER, not the wallet count.
                    //
                    // Counting wallets treats every buy as one vote, so five
                    // wallets putting in 0.05 SOL each outranks two putting in
                    // 5 SOL. Conviction is expressed in size, not in headcount,
                    // and the count cannot tell those apart.
                    //
                    // There is no wallet condition at all. It was removed
                    // rather than defaulted off: a threshold that exists but is
                    // disabled is a thing to misconfigure later, and the count
                    // is still logged, so nothing observable is lost.
                    let need_sol = live.min_smart_sol_in;
                    let (eligible, smart_sol) = {
                        let tracker = match self.conviction.lock() {
                            Ok(t) => t,
                            Err(p) => p.into_inner(),
                        };
                        let now = Instant::now();
                        let wallets: Vec<String> = tracker
                            .buyers_in_window(&buy.mint, now)
                            .into_iter()
                            .filter(|w| {
                                self.wallets.in_groups(w, &self.cfg.tracked.auto_buy_groups)
                            })
                            .collect();
                        (wallets, tracker.sol_in_window(&buy.mint, now))
                    };

                    // A threshold of 0 means "not configured", NOT "buy
                    // everything": auto-buy with no trigger set must do nothing
                    // rather than fire on the first tracked buy of any token.
                    let sol_ok = need_sol > 0.0 && smart_sol >= need_sol;

                    // Logged for anything at least halfway to the threshold.
                    // "No trades" and "nothing strong enough" look identical
                    // from outside, and telling them apart should not require
                    // reading the source.
                    if need_sol > 0.0 && smart_sol * 2.0 >= need_sol {
                        info!(
                            mint = %buy.mint,
                            smart_sol,
                            need_sol,
                            wallets = eligible.len(),
                            "auto-buy progress"
                        );
                    }

                    if sol_ok {
                        // Token-volume confirmation, unchanged in spirit: it
                        // can only ever BLOCK a signal the trigger admitted.
                        let passed = if live.volume_mode && live.min_token_volume_sol > 0.0 {
                            let window = Duration::from_secs(self.cfg.tracked.window_secs);
                            let token_vol = self.prices.volume_sol_in(&buy.mint, window);
                            let ok = token_vol >= live.min_token_volume_sol;
                            info!(
                                mint = %buy.mint,
                                token_volume = token_vol,
                                need_volume = live.min_token_volume_sol,
                                passed = ok,
                                "volume confirmation"
                            );
                            ok
                        } else {
                            true
                        };
                        if passed {
                            info!(
                                mint = %buy.mint,
                                smart_sol,
                                wallets = eligible.len(),
                                "auto-buy triggered on smart-money SOL volume"
                            );
                            self.spawn_smart_buy(&buy.mint, eligible.len()).await;
                        }
                    }
                }
            }

            if let Some(signal) = signal {
                self.metrics.incr(&self.metrics.conviction_signals);
                // The triggering buy becomes the reference trade for every
                // later performance update — a real fill, captured now,
                // because it cannot be reconstructed afterwards.
                self.spawn_conviction_alert(signal, buy);
            }
        }
    }

    /// Is this wallet currently trusted with Alpha money?
    ///
    /// The qualifying set is recomputed at most every five minutes. Scores move
    /// as calls resolve, not tick by tick, so a fresher answer would cost a full
    /// history scan per buy to tell us the same thing.
    #[cfg(feature = "sniper")]
    fn alpha_qualified(&self, wallet: &str) -> bool {
        const REFRESH: Duration = Duration::from_secs(300);

        // Staleness is decided under the lock; the REBUILD is not.
        //
        // Rebuilding reads and parses the whole score archive — tens of
        // thousands of rows — and this is called on the tracked-buy path, which
        // carries roughly 861 transactions a minute. Doing that file work while
        // holding the lock stalled every other caller behind it on an async
        // worker thread.
        //
        // The timestamp is stamped BEFORE the rebuild, so a burst of callers
        // arriving together does not each start their own scan.
        let stale = {
            let mut cache = self.alpha_wallets.lock().unwrap_or_else(|p| p.into_inner());
            match cache.as_mut() {
                Some((at, _)) if at.elapsed() < REFRESH => false,
                Some((at, _)) => {
                    *at = Instant::now();
                    true
                }
                None => {
                    // Nothing to serve yet: claim the rebuild with an empty set
                    // so concurrent callers wait for it rather than duplicating.
                    *cache = Some((Instant::now(), std::collections::HashSet::new()));
                    true
                }
            }
        };

        if stale {
            let rules = self.sniper.alpha_rules();
            // ARCHIVE first, live store second. The archive is the 30-day
            // record; the live store is today, which has not been archived yet.
            // Scoring on the live store alone silently capped every wallet's
            // record at `track_for_secs` — one day — no matter what the
            // lookback said.
            let calls = crate::alpha::merge_calls(self.alpha_ledger.load(), &self.signals.all());
            let set = crate::alpha::qualifying_set(&calls, &rules, chrono::Utc::now());
            info!(
                qualifying = set.len(),
                of_wallets = self.wallets.len(),
                calls_scored = calls.len(),
                lookback_days = rules.lookback_secs / 86_400,
                min_samples = rules.min_samples,
                min_hit_rate = rules.min_hit_rate,
                "alpha wallet set refreshed"
            );
            let mut cache = self.alpha_wallets.lock().unwrap_or_else(|p| p.into_inner());
            *cache = Some((Instant::now(), set));
        }

        let cache = self.alpha_wallets.lock().unwrap_or_else(|p| p.into_inner());
        cache.as_ref().map(|(_, s)| s.contains(wallet)).unwrap_or(false)
    }

    /// Fire a smart-money buy, once per token, and tell the group either way.
    ///
    /// Deduped by mint for the process lifetime: a signal keeps accumulating
    /// buys after it crosses the threshold, and each one would otherwise
    /// trigger another entry into the same position.
    #[cfg(feature = "sniper")]
    async fn spawn_smart_buy(&self, mint: &str, wallets: usize) {
        {
            let mut seen = self.smart_bought.lock().unwrap_or_else(|p| p.into_inner());
            if !seen.insert(mint.to_string()) {
                return;
            }
        }
        // Second line of defence, and the one that survives a restart: the
        // in-memory set above is empty on boot, so a token still inside its
        // window would be bought AGAIN. Holding any of it already means the
        // position is open.
        if let Some((owner, _)) = self.sniper.trading_identity()
            && let Some((raw, _)) = self.rpc.token_balance_raw(&owner.to_string(), mint).await
            && raw > 0
        {
            info!(%mint, "already holding — not opening a second position");
            return;
        }
        // IS A QUALIFYING ALPHA WALLET IN THIS TOKEN?
        //
        // Asked here, on a trade the normal trigger has already approved.
        // Alpha never reaches this point on its own — it only decides whether
        // an already-valid entry is worth extra size.
        let alpha_wallet = {
            let buyers = {
                let tracker = match self.conviction.lock() {
                    Ok(t) => t,
                    Err(p) => p.into_inner(),
                };
                tracker.buyers_in_window(mint, Instant::now())
            };
            buyers.into_iter().find(|w| {
                self.wallets.in_groups(w, &self.cfg.tracked.auto_buy_groups)
                    && self.alpha_qualified(w)
            })
        };

        let reason = match &alpha_wallet {
            Some(w) => {
                let label = self
                    .wallets
                    .get(w)
                    .map(|x| x.name.clone())
                    .unwrap_or_else(|| crate::wallets::short_address(w));
                info!(%mint, wallet = %w, %label, "alpha wallet in this token — adding size");
                format!("{wallets} tracked wallets in window · alpha {label}")
            }
            None => format!("{wallets} tracked wallets in window"),
        };
        let outcome = if alpha_wallet.is_some() {
            self.sniper.buy_mint_with_alpha(mint, &reason).await
        } else {
            self.sniper.buy_mint(mint, &reason).await
        };
        info!(%mint, wallets, ?outcome, "smart-money buy");

        // A REFUSAL IS NOT A POSITION.
        //
        // The claim taken above exists to stop a burst of signals opening two
        // positions in the same token. It was also, accidentally, remembering
        // that a token had once been unbuyable — and the reasons a buy is
        // refused are mostly temporary. HALT gets lifted, daily caps reset,
        // price impact moves, market caps change.
        //
        // The cost of getting this wrong was measured: a token refused at
        // 22:27 because HALT was engaged could never be reconsidered. Nine
        // minutes later it had 17 eligible buyers, 68 SOL of tracked inflow and
        // 11,643 SOL of volume, passed every gate — and was silently skipped,
        // because the mint was already in this set.
        //
        // Releasing the claim costs a re-check on the next tracked buy, and
        // every guard that would permanently reject a token (rug blacklist,
        // mint authority, freeze) runs before any network call, so a genuinely
        // bad token is re-refused cheaply.
        let opened = matches!(
            outcome,
            crate::sniper::BuyOutcome::Submitted { .. } | crate::sniper::BuyOutcome::Rehearsed { .. }
        );
        if !opened {
            let mut seen = self.smart_bought.lock().unwrap_or_else(|p| p.into_inner());
            seen.remove(mint);
        }
        // Entry valuation, computed from the fill we just got rather than a
        // fresh quote: `tokens_out` and `sol_in` are the price we actually
        // paid, and by the time an alert renders the market has already moved.
        // Best-effort — a missing supply or SOL price omits the figure rather
        // than delaying or blocking the alert.
        let entry_mcap = match &outcome {
            // `tokens_out` is UI units on BOTH paths — see `buy_mint`. It was
            // raw on one of them, and dividing here as well produced an entry
            // valuation of $21.4B. No conversion belongs at this layer.
            crate::sniper::BuyOutcome::Submitted { sol_in, tokens_out, .. } if *tokens_out > 0.0 => {
                match (
                    self.prices.sol_usd(Duration::from_secs(600)),
                    self.rpc.token_supply(mint).await,
                ) {
                    (Some(sol_usd), Some(supply)) => {
                        Some((sol_in / tokens_out) * supply * sol_usd)
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(msg) = crate::alerts::render_smart_buy(mint, wallets, &outcome, entry_mcap) {
            self.alerter.send_html(msg).await;
        }

        // PRIMARY supply-ceiling enforcement: right after the fill, on the
        // real balance. The sweep repeats this as a fallback, but doing it here
        // means an oversized position is trimmed in seconds rather than
        // whenever the next reconciliation happens to come round.
        if opened {
            self.sniper.enforce_supply_cap(mint, &self.alerter).await;
        }
    }

    /// Where the trade record lives, for marking leaderboard rows.
    fn leaderboard_audit_path(&self) -> String {
        #[cfg(feature = "sniper")]
        { self.cfg.sniper.audit_log.clone() }
        #[cfg(not(feature = "sniper"))]
        { String::new() }
    }

    /// Enrich a conviction signal and announce it.
    ///
    /// Enrichment is the same path pool detection uses — name/symbol plus mint
    /// safety. Safety is reported rather than used to drop the alert: smart
    /// money buying something with a live mint authority is itself worth
    /// knowing, and in an alerts-only phase a silent drop teaches you nothing
    /// about where the threshold belongs.
    fn spawn_conviction_alert(
        &self,
        signal: crate::conviction::ConvictionSignal,
        reference: crate::wallets::TrackedBuy,
    ) {
        let alerter = self.alerter.clone();
        let rpc = self.rpc.clone();
        let safety_enabled = self.cfg.safety.enabled;
        let signals = self.signals.clone();
        let track = self.cfg.tracked.track_performance;
        let prices = self.prices.clone();
        let tz = self.cfg.tracked.display_utc_offset_hours;

        tokio::spawn(async move {
            // Covers BOTH metadata homes — the Token-2022 extension on the
            // mint and the classic Metaplex PDA. Checking only Metaplex is why
            // Token-2022 launches were rendering as a bare mint.
            let meta_full = rpc.token_meta(&signal.mint).await;
            let meta = meta_full
                .as_ref()
                .map(|m| (m.name.clone(), m.symbol.clone()));

            // Socials live in an off-chain JSON the launcher controls, so this
            // is one extra hostile-input fetch. It only runs on a call, never
            // on the hot path.
            let socials = match meta_full.as_ref().and_then(|m| m.uri.as_deref()) {
                Some(uri) => {
                    let s = crate::socials::fetch(uri).await;
                    (!s.is_empty()).then_some(s)
                }
                None => None,
            };

            let mint_info = if safety_enabled {
                rpc.mint_info(&signal.mint).await
            } else {
                None
            };

            // FDV at signal time, from the reference fill: the wallet's own
            // execution price times total supply times SOL/USD. Captured now
            // because a later read returns the price THEN-unknowable — it
            // returns the price now, which is a different number.
            // Always resolved, not just when tracking: the alert itself is
            // denominated in USD, so the rate is needed even if nothing will
            // re-price this token later.
            let supply = rpc.token_supply(&signal.mint).await;
            // Holder concentration. One extra RPC call, and only on a CALL —
            // never on the hot path.
            let holders = rpc.holder_stats(&signal.mint).await;
            let market = market_at_signal(&reference, supply, &prices);
            let fdv_usd = market.and_then(|m| m.fdv_usd);

            let body = crate::conviction::render_signal(
                &signal,
                meta.as_ref(),
                mint_info.as_ref(),
                market.as_ref(),
                socials.as_ref(),
                holders.as_ref(),
                tz,
            );
            // The image is decoration — `send_photo_html` falls back to a
            // plain message if Telegram cannot fetch it, so a broken image
            // never costs the call itself.
            let image = socials.as_ref().and_then(|s| s.image.as_deref());
            let message_id = alerter.send_photo_html(image, body, None).await;

            if track {
                let (name, symbol) = meta.unwrap_or_default();
                signals.insert(crate::signals::SignalRecord {
                    mint: signal.mint.clone(),
                    // NOT `sanitize_name`: its address fallback would store
                    // the mint as the token's name, which then renders as a
                    // ticker and blocks the identity backfill forever.
                    name: crate::wallets::sanitize_token_label(&name).unwrap_or_default(),
                    symbol: crate::wallets::sanitize_token_label(&symbol).unwrap_or_default(),
                    first_seen_utc: signal.first_seen_utc,
                    message_id,
                    reference_sol: reference.sol_spent,
                    reference_tokens_raw: reference.token_amount_raw,
                    decimals: reference.decimals,
                    fdv_usd_at_signal: fdv_usd,
                    supply,
                    wallets: signal.buyer_addresses.clone(),
                    total_sol: signal.total_sol,
                    total_fees_sol: signal.total_fees_sol,
                    sol_usd_at_signal: market.map(|m| m.sol_usd),
                    last_reported_multiple: 1.0,
                    last_multiple: 1.0,
                    peak_multiple: 1.0,
                    last_checked_utc: None,
                });
            }
        });
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
        let pool_auto_buy = self.cfg.sniper.pool_auto_buy;

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

            // Resolve the token NAME from on-chain metadata. Only here, after
            // the pool has passed every filter, so we never pay for a name on a
            // pool we drop. Checks both homes — the Token-2022 extension on the
            // mint and the Metaplex PDA — because a growing share of launches
            // are Token-2022 and carry no PDA at all.
            if let Some(mint) = event.new_token_mint.clone() {
                if let Some((name, symbol)) = rpc.token_name_symbol(&mint).await {
                    event.token_name = (!name.is_empty()).then_some(name);
                    event.token_symbol = (!symbol.is_empty()).then_some(symbol);
                }
            }

            metrics.incr(&metrics.detected);
            info!(
                dex = event.dex.label(),
                pool = %event.pool,
                token = event.new_token_mint.as_deref().unwrap_or("?"),
                name = event.token_name.as_deref().unwrap_or("?"),
                symbol = event.token_symbol.as_deref().unwrap_or("?"),
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
            if pool_auto_buy && sniper.snipe_mode() == crate::sniper::SnipeMode::Open {
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
            lp_mint: p.lp_mint.clone(),
            lp_supply_at_detection: None,
            token_name: None,
            token_symbol: None,
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
            lp_mint: Some("LP_MINT".into()),
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

    /// Live check that the configured Geyser endpoint actually connects,
    /// authenticates, and delivers transactions. Run before trusting a new
    /// provider — a silent fallback to WebSocket costs seconds per detection
    /// and looks identical in the logs to a healthy run.
    ///
    ///   cargo test -- --ignored --nocapture live_grpc_connects
    #[ignore = "hits a live Geyser endpoint; needs GRPC_ENDPOINT"]
    #[tokio::test]
    async fn live_grpc_connects() {
        let _ = dotenvy::dotenv();
        let endpoint = std::env::var("GRPC_ENDPOINT").expect("GRPC_ENDPOINT");
        let token = std::env::var("GRPC_X_TOKEN").ok().filter(|t| !t.is_empty());
        println!("endpoint: {}", redact(&endpoint));

        let mut client = connect_geyser(&endpoint, token).await.expect("connect");

        // Watch every enabled program so this also proves the filter is accepted.
        let mut transactions = HashMap::new();
        transactions.insert(
            "probe".to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                account_include: vec![Dex::RaydiumV4.program_id().to_string()],
                ..Default::default()
            },
        );
        let request = SubscribeRequest {
            transactions,
            commitment: Some(CommitmentLevel::Processed as i32),
            ..Default::default()
        };

        let started = std::time::Instant::now();
        let (_sink, mut stream) = client
            .subscribe_with_request(Some(request))
            .await
            .expect("subscribe");
        println!("subscribed in {:?}", started.elapsed());

        // A live mainnet stream filtered to one busy program should produce
        // traffic within seconds. Silence here means auth passed but the
        // subscription is not actually delivering.
        let mut seen = 0usize;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while seen < 3 {
            let Ok(Some(item)) = tokio::time::timeout_at(deadline, stream.next()).await else {
                break;
            };
            let update = item.expect("stream item");
            if let Some(UpdateOneof::Transaction(tx)) = update.update_oneof {
                seen += 1;
                println!("update {seen}: slot {}", tx.slot);
            }
        }
        assert!(seen > 0, "connected but received no transactions in 20s");
    }

    /// Feasibility probe for smart-wallet tracking: can the provider accept a
    /// large `account_include` filter, and what traffic does it produce?
    ///
    /// Both answers gate the design. If the provider caps the filter list we
    /// need multiple subscriptions or client-side filtering; if 700 active
    /// traders produce more traffic than the program stream, the wallet path
    /// needs its own budget rather than sharing the detector's.
    ///
    ///   WALLETS=/path/to/wallets.txt \
    ///     cargo test -- --ignored --nocapture live_grpc_wallet_filter_capacity
    #[ignore = "hits a live Geyser endpoint; needs GRPC_ENDPOINT + WALLETS"]
    #[tokio::test]
    async fn live_grpc_wallet_filter_capacity() {
        let _ = dotenvy::dotenv();
        let endpoint = std::env::var("GRPC_ENDPOINT").expect("GRPC_ENDPOINT");
        let token = std::env::var("GRPC_X_TOKEN").ok().filter(|t| !t.is_empty());
        let path = std::env::var("WALLETS").expect("WALLETS=/path/to/wallets.txt");
        let wallets: Vec<String> = std::fs::read_to_string(&path)
            .expect("read wallet list")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        println!("subscribing to {} wallets", wallets.len());

        let mut client = connect_geyser(&endpoint, token).await.expect("connect");

        let mut transactions = HashMap::new();
        transactions.insert(
            "wallets".to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                account_include: wallets.clone(),
                ..Default::default()
            },
        );
        let request = SubscribeRequest {
            transactions,
            commitment: Some(CommitmentLevel::Processed as i32),
            ..Default::default()
        };

        let (_sink, mut stream) = client
            .subscribe_with_request(Some(request))
            .await
            .expect("subscribe REJECTED — provider caps the filter list");
        println!("subscription ACCEPTED with {} addresses", wallets.len());

        // Measure for 60s: how many wallet transactions per minute, and how
        // many distinct wallets are actually active in that window.
        let window = Duration::from_secs(60);
        let started = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + window;
        let mut count = 0usize;
        let mut first_at: Option<Duration> = None;

        while let Ok(Some(item)) = tokio::time::timeout_at(deadline, stream.next()).await {
            let update = item.expect("stream item");
            if let Some(UpdateOneof::Transaction(_)) = update.update_oneof {
                count += 1;
                first_at.get_or_insert_with(|| started.elapsed());
            }
        }

        println!("--- {} wallet txs in {:?} ---", count, started.elapsed());
        println!("first update after: {:?}", first_at);
        println!("rate: {:.1} tx/min", count as f64 / started.elapsed().as_secs_f64() * 60.0);
    }
}

/// USD context at signal time, derived from the reference fill.
///
/// Price comes from a trade that actually executed (`sol_spent / tokens`), not
/// a mid-price — so it already includes the slippage a real buyer paid. Market
/// cap is that price times total supply.
///
/// The SOL/USD rate is fetched once and returned, so every figure in the alert
/// converts with the same number. Returns `None` only when the rate itself is
/// unknown; price and market cap degrade independently, because a missing
/// supply should not also cost you the buy sizes.
fn market_at_signal(
    reference: &crate::wallets::TrackedBuy,
    supply: Option<f64>,
    prices: &crate::prices::PriceIndex,
) -> Option<crate::conviction::MarketSnapshot> {
    let sol_usd = prices.sol_usd(std::time::Duration::from_secs(300))?;

    let price_usd = (reference.token_amount > 0.0)
        .then(|| reference.sol_spent / reference.token_amount * sol_usd)
        .filter(|p| p.is_finite() && *p > 0.0);

    let fdv_usd = match (price_usd, supply) {
        (Some(p), Some(s)) if s > 0.0 => Some(p * s).filter(|f| f.is_finite()),
        _ => None,
    };

    Some(crate::conviction::MarketSnapshot { sol_usd, price_usd, fdv_usd })
}

/// Connect to a Geyser endpoint, applying TLS only when the URL asks for it.
///
/// Providers differ on transport: most terminate TLS (`https://host:443`), but
/// some serve plaintext gRPC on a custom port (`http://host:4512`). Handing a
/// TLS config to a plaintext endpoint makes tonic attempt a handshake the
/// server never answers, and the failure surfaces as an opaque transport error
/// with nothing pointing at the scheme — so the scheme decides, not a flag.
async fn connect_geyser(
    endpoint: &str,
    token: Option<String>,
) -> Result<GeyserGrpcClient> {
    let mut builder = GeyserGrpcClient::build_from_shared(endpoint.to_string())
        .context("invalid gRPC endpoint")?
        .x_token(token)
        .context("invalid x-token")?;

    if endpoint.trim_start().starts_with("https://") {
        builder = builder
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .context("tls config")?;
    }

    builder
        .connect()
        .await
        .with_context(|| format!("connecting to {}", redact(endpoint)))
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

#[cfg(test)]
mod price_from_stream_probe {
    use super::*;

    /// Can we derive token prices from the stream we ALREADY receive, without
    /// any external price API?
    ///
    /// Counts, over a short window, how many streamed transactions yield a
    /// usable (mint, sol_delta, token_delta) observation using the same
    /// balance-delta technique `wallets::detect_buys` uses.
    ///
    ///   cargo test --features sniper -- --ignored --nocapture price_from_stream
    #[ignore = "hits a live Geyser endpoint"]
    #[tokio::test]
    async fn price_from_stream_feasibility() {
        let _ = dotenvy::dotenv();
        let endpoint = std::env::var("GRPC_ENDPOINT").expect("GRPC_ENDPOINT");
        let token = std::env::var("GRPC_X_TOKEN").ok().filter(|t| !t.is_empty());
        let mut client = connect_geyser(&endpoint, token).await.expect("connect");

        let programs: Vec<String> = [
            Dex::RaydiumV4, Dex::RaydiumCpmm, Dex::PumpSwap,
            Dex::MeteoraDbc, Dex::MeteoraDlmm,
        ]
        .iter()
        .map(|d| d.program_id().to_string())
        .collect();

        let mut transactions = HashMap::new();
        transactions.insert(
            "swaps".to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                account_include: programs,
                ..Default::default()
            },
        );
        let (_sink, mut stream) = client
            .subscribe_with_request(Some(SubscribeRequest {
                transactions,
                commitment: Some(CommitmentLevel::Processed as i32),
                ..Default::default()
            }))
            .await
            .expect("subscribe");

        const WSOL: &str = "So11111111111111111111111111111111111111112";
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let (mut seen, mut priced) = (0usize, 0usize);
        let mut mints = std::collections::HashSet::new();
        let mut sol_volume = 0.0f64;
        let mut samples: Vec<(String, f64)> = Vec::new();

        while let Ok(Some(item)) = tokio::time::timeout_at(deadline, stream.next()).await {
            let Ok(update) = item else { continue };
            let Some(UpdateOneof::Transaction(tx)) = update.update_oneof else { continue };
            let Some(info) = tx.transaction.as_ref() else { continue };
            let Some(meta) = info.meta.as_ref() else { continue };
            if info.is_vote || meta.err.is_some() {
                continue;
            }
            seen += 1;

            // Same technique as detect_buys: pair a token delta with a SOL delta.
            let mut before = HashMap::new();
            for b in &meta.pre_token_balances {
                if let Some(a) = b.ui_token_amount.as_ref() {
                    before.insert((b.owner.as_str(), b.mint.as_str()), a.ui_amount);
                }
            }
            let mut sol_moved: f64 = 0.0;
            for b in &meta.post_token_balances {
                if b.mint != WSOL {
                    continue;
                }
                if let Some(a) = b.ui_token_amount.as_ref() {
                    let prev = before.get(&(b.owner.as_str(), b.mint.as_str())).copied().unwrap_or(0.0);
                    sol_moved = sol_moved.max((a.ui_amount - prev).abs());
                }
            }
            for b in &meta.post_token_balances {
                if b.mint == WSOL {
                    continue;
                }
                let Some(a) = b.ui_token_amount.as_ref() else { continue };
                let prev = before.get(&(b.owner.as_str(), b.mint.as_str())).copied().unwrap_or(0.0);
                let delta = (a.ui_amount - prev).abs();
                if delta > 0.0 && sol_moved > 0.0 {
                    priced += 1;
                    mints.insert(b.mint.clone());
                    sol_volume += sol_moved;
                    if samples.len() < 5 {
                        samples.push((b.mint.clone(), sol_moved / delta));
                    }
                    break;
                }
            }
        }

        println!("\n--- 30s of the stream we already receive ---");
        println!("transactions           {seen}");
        println!("yielded a price        {priced}  ({:.0}%)", 100.0 * priced as f64 / seen.max(1) as f64);
        println!("distinct tokens        {}", mints.len());
        println!("SOL volume observed    {sol_volume:.1}");
        println!("\nsample prices (SOL per token):");
        for (m, p) in &samples {
            println!("  {}  {p:.3e}", &m[..12]);
        }
        assert!(priced > 0, "no prices derivable from the stream");
    }

    /// Which extra programs carry price traffic we currently miss?
    ///
    ///   cargo test --features sniper -- --ignored --nocapture missing_venues
    #[ignore = "hits a live Geyser endpoint"]
    #[tokio::test]
    async fn missing_venue_coverage() {
        let _ = dotenvy::dotenv();
        let endpoint = std::env::var("GRPC_ENDPOINT").expect("GRPC_ENDPOINT");
        let token = std::env::var("GRPC_X_TOKEN").ok().filter(|t| !t.is_empty());
        let mut client = connect_geyser(&endpoint, token).await.expect("connect");

        // Candidates we do NOT currently watch.
        let candidates: Vec<(&str, &str)> = vec![
            ("pump.fun curve", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"),
            ("meteora damm v2", "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG"),
            ("raydium clmm", "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"),
            ("orca whirlpool", "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"),
        ];

        let mut transactions = HashMap::new();
        for (name, prog) in &candidates {
            transactions.insert(
                (*name).to_string(),
                SubscribeRequestFilterTransactions {
                    vote: Some(false),
                    failed: Some(false),
                    account_include: vec![(*prog).to_string()],
                    ..Default::default()
                },
            );
        }
        let (_sink, mut stream) = client
            .subscribe_with_request(Some(SubscribeRequest {
                transactions,
                commitment: Some(CommitmentLevel::Processed as i32),
                ..Default::default()
            }))
            .await
            .expect("subscribe");

        let index = crate::prices::PriceIndex::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut per_filter: HashMap<String, usize> = HashMap::new();

        while let Ok(Some(item)) = tokio::time::timeout_at(deadline, stream.next()).await {
            let Ok(update) = item else { continue };
            let labels = update.filters.clone();
            let Some(UpdateOneof::Transaction(tx)) = update.update_oneof else { continue };
            let Some(info) = tx.transaction.as_ref() else { continue };
            let Some(meta) = info.meta.as_ref() else { continue };
            if info.is_vote || meta.err.is_some() {
                continue;
            }
            for l in labels {
                *per_filter.entry(l).or_default() += 1;
            }
            index.observe(info, meta);
        }

        println!("\n--- 30s on venues we do NOT currently watch ---");
        for (name, _) in &candidates {
            println!("  {name:<16} {} tx", per_filter.get(*name).copied().unwrap_or(0));
        }
        println!("  tokens priced from them: {}", index.tracked_tokens());
    }

    /// Can SOL/USD be derived from the SAME stream, with no external feed?
    /// A swap that moves WSOL one way and USDC the other IS a SOL price.
    ///
    ///   cargo test --features sniper -- --ignored --nocapture sol_usd_from_stream
    #[ignore = "hits a live Geyser endpoint"]
    #[tokio::test]
    async fn sol_usd_from_stream_feasibility() {
        let _ = dotenvy::dotenv();
        let endpoint = std::env::var("GRPC_ENDPOINT").expect("GRPC_ENDPOINT");
        let token = std::env::var("GRPC_X_TOKEN").ok().filter(|t| !t.is_empty());
        let mut client = connect_geyser(&endpoint, token).await.expect("connect");

        let programs: Vec<String> = [Dex::RaydiumV4, Dex::RaydiumCpmm, Dex::PumpSwap]
            .iter()
            .map(|d| d.program_id().to_string())
            .collect();
        let mut transactions = HashMap::new();
        transactions.insert(
            "swaps".to_string(),
            SubscribeRequestFilterTransactions {
                vote: Some(false),
                failed: Some(false),
                account_include: programs,
                ..Default::default()
            },
        );
        let (_sink, mut stream) = client
            .subscribe_with_request(Some(SubscribeRequest {
                transactions,
                commitment: Some(CommitmentLevel::Processed as i32),
                ..Default::default()
            }))
            .await
            .expect("subscribe");

        const WSOL: &str = "So11111111111111111111111111111111111111112";
        const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let mut obs: Vec<(f64, f64)> = Vec::new(); // (price, size_sol)

        while let Ok(Some(item)) = tokio::time::timeout_at(deadline, stream.next()).await {
            let Ok(update) = item else { continue };
            let Some(UpdateOneof::Transaction(tx)) = update.update_oneof else { continue };
            let Some(info) = tx.transaction.as_ref() else { continue };
            let Some(meta) = info.meta.as_ref() else { continue };
            if info.is_vote || meta.err.is_some() {
                continue;
            }

            let mut before: HashMap<(&str, &str), f64> = HashMap::new();
            for b in &meta.pre_token_balances {
                if let Some(a) = b.ui_token_amount.as_ref() {
                    before.insert((b.owner.as_str(), b.mint.as_str()), a.ui_amount);
                }
            }
            // One owner whose WSOL and USDC both moved, in opposite directions.
            let mut per_owner: HashMap<&str, (f64, f64)> = HashMap::new();
            for b in &meta.post_token_balances {
                let Some(a) = b.ui_token_amount.as_ref() else { continue };
                let prev = before.get(&(b.owner.as_str(), b.mint.as_str())).copied().unwrap_or(0.0);
                let d = a.ui_amount - prev;
                if b.mint == WSOL {
                    per_owner.entry(b.owner.as_str()).or_default().0 += d;
                } else if b.mint == USDC {
                    per_owner.entry(b.owner.as_str()).or_default().1 += d;
                }
            }
            for (_, (dsol, dusdc)) in per_owner {
                if dsol.abs() > 0.01 && dusdc.abs() > 1.0 && (dsol > 0.0) != (dusdc > 0.0) {
                    obs.push((dusdc.abs() / dsol.abs(), dsol.abs()));
                }
            }
        }

        obs.sort_by(|a, b| a.0.total_cmp(&b.0));
        println!("\n--- 45s: SOL/USD observations from our own stream ---");
        println!("observations: {}", obs.len());
        if !obs.is_empty() {
            let med = obs[obs.len() / 2].0;
            let biggest = obs.iter().max_by(|a, b| a.1.total_cmp(&b.1)).unwrap();
            println!("median price: ${med:.2}");
            println!("range:        ${:.2} - ${:.2}", obs[0].0, obs[obs.len() - 1].0);
            println!("largest swap: {:.1} SOL @ ${:.2}", biggest.1, biggest.0);
        }
        assert!(!obs.is_empty(), "no WSOL/USDC swaps seen — SOL/USD not derivable this way");
    }
}

/// Mints the bot actually opened a position in, from the audit log.
///
/// Only CONFIRMED buys count. A refused or failed attempt is not a position,
/// and marking one on the leaderboard would claim credit for a trade that
/// never happened.
pub async fn read_traded_mints(path: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if path.is_empty() {
        return out;
    }
    let Ok(body) = tokio::fs::read_to_string(path).await else { return out };
    for line in body.lines() {
        let Ok(rec) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if rec.get("action").and_then(|a| a.as_str()) != Some("smart_buy") {
            continue;
        }
        let confirmed = rec
            .get("outcome")
            .and_then(|o| o.as_str())
            .is_some_and(|o| o.starts_with("confirmed"));
        if !confirmed {
            continue;
        }
        if let Some(m) = rec.get("mint").and_then(|m| m.as_str()) {
            out.insert(m.to_string());
        }
    }
    out
}
