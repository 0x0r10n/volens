//! Sniper: guarded auto-execution on detected pools.
//!
//! # Safety model
//!
//! This module spends real money. Its structure is deliberately hostile to
//! accidental execution:
//!
//! 1. **Compiled out by default.** The whole module is behind the `sniper`
//!    cargo feature. A default build cannot execute trades at all.
//! 2. **Dry-run is inert, not flag-guarded.** `Mode::DryRun` carries no signing
//!    capability. Execution requires `Mode::Armed(_)`, so a dry run cannot sign
//!    even if a caller ignores every boolean — it is a type error, not a
//!    runtime check. A `if dry_run { ... }` guard is one bad merge away from
//!    spending funds; this is not.
//! 3. **Arming requires a keypair file.** Without `keypair_path` there is no
//!    wallet, so `Mode::Armed` cannot be constructed at all.
//! 4. **Every decision is audited**, allowed or denied, to an append-only log.
//! 5. **Dry run is a real rehearsal.** With `simulate_as` set it builds the
//!    actual transaction and simulates it against live mainnet, reporting
//!    whether the trade *would* have succeeded. A pubkey cannot sign, so this
//!    adds no capability.
//!
//! # No live trade has ever been executed by this code
//!
//! Construction is verified extensively (golden fixtures, simulation). The send
//! path is not — it cannot be, without sending. Run dry for a while, then make
//! the first armed trade a supervised one at minimum size.

use crate::config::{RpcConfig, SniperConfig};
use crate::execute;
use crate::model::PoolEvent;
use crate::rpc::RpcClient;
use crate::jito::JitoClient;
use crate::submit::{Submission, Submitter};
use crate::tx::Wallet;
use anyhow::{Result, bail};
use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;
use solana_pubkey::Pubkey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::{info, warn};

/// Execution capability. Only `Armed` can ever sign; `DryRun` holds nothing.
///
/// This is the core safety invariant — do not add a keypair to `DryRun`, and do
/// not add a boolean that bypasses the distinction.
#[derive(Debug)]
pub enum Mode {
    /// Holds at most a PUBKEY, for building and simulating. A pubkey cannot
    /// sign, so this variant can never submit.
    DryRun { simulate_as: Option<Pubkey> },
    Armed(SigningCapability),
}

/// Real signing capability. Constructible only by loading a keypair file, so
/// possessing one is proof the operator pointed at a wallet on purpose.
#[derive(Debug)]
pub struct SigningCapability {
    wallet: Wallet,
}

/// A fully specified trade intent. Produced whether or not we can execute, so
/// dry runs log exactly what would have been sent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TradePlan {
    pub pool: String,
    pub dex: String,
    pub token_mint: String,
    pub quote_asset: String,
    /// Amount of the quote asset to spend.
    pub size: f64,
    pub slippage_bps: u16,
    pub observed_liquidity: Option<f64>,
}

/// Why a trade was refused. Every variant is a deliberate stop, not an error.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Denial {
    Disabled,
    KillSwitchEngaged,
    NoQuoteAsset,
    NoTokenMint,
    LiquidityBelowMinimum { observed: Option<f64>, required: f64 },
    UnsafeMint { reason: String },
    TradeSizeExceedsMax { size: f64, max: f64 },
    DailyCapReached { spent: f64, cap: f64 },
    DailyTradeCountReached { count: u32, max: u32 },
    /// Already traded this pool recently. Guards against re-detection and
    /// stream replay buying the same pool twice.
    PoolCoolingDown { seconds_remaining: i64 },
    /// The venue has no verified encoder, or state could not be read.
    CannotBuild { reason: String },
    /// The trade would move the pool more than we tolerate.
    PriceImpactTooHigh { impact_bps: u32, max_bps: u32 },
    /// Dry run with no `simulate_as` configured — nothing to rehearse as.
    NoSimulationIdentity,
}

impl Denial {
    pub fn label(&self) -> &'static str {
        match self {
            Denial::Disabled => "sniper disabled",
            Denial::KillSwitchEngaged => "kill switch engaged",
            Denial::NoQuoteAsset => "no recognized quote asset",
            Denial::NoTokenMint => "no launched token identified",
            Denial::LiquidityBelowMinimum { .. } => "liquidity below minimum",
            Denial::UnsafeMint { .. } => "unsafe mint",
            Denial::TradeSizeExceedsMax { .. } => "trade size exceeds max",
            Denial::DailyCapReached { .. } => "daily spend cap reached",
            Denial::DailyTradeCountReached { .. } => "daily trade count reached",
            Denial::PoolCoolingDown { .. } => "pool traded recently",
            Denial::CannotBuild { .. } => "cannot build trade",
            Denial::PriceImpactTooHigh { .. } => "price impact too high",
            Denial::NoSimulationIdentity => "no simulate_as configured",
        }
    }
}

/// Whether the reported wallet can actually be spent from by this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletRole {
    /// A keypair is loaded. This process can sign and spend.
    Armed,
    /// `simulate_as` only. A pubkey cannot sign; this process holds no key for
    /// it and cannot move these funds.
    Rehearsal,
}

/// What `handle` did, returned so the caller can alert on it.
///
/// The sniper deliberately does not own an `Alerter`: it decides and executes,
/// the detector dispatches. That keeps a network failure in the alert path from
/// sitting inside the execution path.
#[derive(Debug, Clone, PartialEq)]
pub enum Execution {
    /// Refused before any transaction was built.
    Skipped { pool: String, reason: String },
    /// Dry run: the real transaction was built and simulated.
    Rehearsed { plan: TradePlan, outcome: String, would_succeed: bool },
    /// Armed: a transaction was actually submitted.
    Submitted { plan: TradePlan, result: SubmitOutcome },
}

/// Outcome of a real submission, classified by what it means for the operator.
#[derive(Debug, Clone, PartialEq)]
pub enum SubmitOutcome {
    /// Funds were spent and the trade executed.
    Executed { reference: String, slot: Option<u64> },
    /// Definitively did not execute — safe to consider the trade not taken.
    NotExecuted { reason: String },
    /// Unknown. May still land. NOT safe to retry, and the operator needs to
    /// check manually — this is the outcome worth waking someone up for.
    Indeterminate { reference: String, reason: String },
}

impl Execution {
    /// Should this be sent to Telegram?
    ///
    /// Routine denials (wrong quote asset, thin liquidity, cooling down) are
    /// filtered out on purpose: the sniper skips far more pools than it trades,
    /// and alerting on every skip trains the operator to ignore the channel —
    /// which is exactly when a real execution alert gets missed.
    ///
    /// `verbose_rehearsals` makes successful dry-run rehearsals alert too. Off
    /// by default (they are noise in steady state); on for a live demo, where
    /// the point is to watch the bot *decide to trade* with no money at risk.
    pub fn is_alertable(&self, verbose_rehearsals: bool) -> bool {
        match self {
            // Skips are logged and audited, never alerted.
            Execution::Skipped { .. } => false,
            // A failing rehearsal always alerts: the live path is broken while
            // you believe it works. A succeeding one alerts only in verbose mode.
            Execution::Rehearsed { would_succeed, .. } => verbose_rehearsals || !would_succeed,
            // Every real submission is alertable — money moved, or might have.
            Execution::Submitted { .. } => true,
        }
    }
}

/// Rolling per-day spend/count plus per-pool cooldowns.
///
/// Both live behind one lock deliberately: a trade that consumes daily budget
/// must record its cooldown in the same critical section, or two concurrent
/// detections of the same pool could each pass the cooldown check before either
/// records it.
#[derive(Debug, Default)]
struct DailyState {
    day: Option<i32>,
    spent: f64,
    trades: u32,
    /// Pool address -> when it was last traded.
    recent_pools: HashMap<String, DateTime<Utc>>,
}

impl DailyState {
    /// Roll the window if the UTC day changed.
    fn roll(&mut self, now: DateTime<Utc>) {
        let ord = now.year() * 1000 + now.ordinal() as i32;
        if self.day != Some(ord) {
            self.day = Some(ord);
            self.spent = 0.0;
            self.trades = 0;
            // Note: `recent_pools` deliberately does NOT reset here. A cooldown
            // is about not buying the same pool twice; that concern doesn't
            // expire at midnight UTC just because the spend budget does.
        }
    }

    /// Is this pool still cooling down? `window == 0` disables the check.
    fn cooling_down(&self, pool: &str, now: DateTime<Utc>, window: u64) -> Option<i64> {
        if window == 0 {
            return None;
        }
        let last = self.recent_pools.get(pool)?;
        let elapsed = now.signed_duration_since(*last).num_seconds();
        // A negative elapsed means the clock went backwards (NTP correction).
        // Treat that as still cooling: refusing a trade is the safe direction.
        (elapsed < window as i64).then(|| (window as i64 - elapsed).max(0))
    }

    /// Record a trade against a pool, and opportunistically drop entries that
    /// have aged out so the map cannot grow without bound on a long run.
    fn record_pool(&mut self, pool: String, now: DateTime<Utc>, window: u64) {
        if window > 0 {
            self.recent_pools.retain(|_, t| {
                now.signed_duration_since(*t).num_seconds() < window as i64
            });
        }
        self.recent_pools.insert(pool, now);
    }
}

/// Runtime-tunable working values, adjustable from Telegram but only ever
/// toward SAFER. The `SniperConfig` values are the risk ceilings; these start
/// equal to them and can move to reduce risk, never past them.
///
/// The safety property: a command can lower size, tighten slippage, or raise the
/// minimum liquidity — all of which reduce exposure. It can never do the reverse.
/// So a leaked bot token cannot make the bot spend more or accept worse fills;
/// raising a ceiling requires editing config on the host.
#[derive(Debug, Clone, Copy)]
struct Tunable {
    trade_size_sol: f64,
    slippage_bps: u16,
    min_liquidity_sol: f64,
}

pub struct Sniper {
    cfg: SniperConfig,
    mode: Mode,
    state: Mutex<DailyState>,
    /// See `Tunable`. Behind its own lock; read once per decision.
    tunable: Mutex<Tunable>,
    rpc: Arc<RpcClient>,
    submitter: Submitter,
    jito: Option<JitoClient>,
}

/// Manual `Debug`: never render the wallet, and keep the mode legible.
impl std::fmt::Debug for Sniper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sniper")
            .field("enabled", &self.cfg.enabled)
            .field(
                "mode",
                &match self.mode {
                    Mode::Armed(_) => "armed",
                    Mode::DryRun { .. } => "dry_run",
                },
            )
            .finish()
    }
}

impl Sniper {
    /// Build a sniper.
    ///
    /// Arming loads the configured keypair; a missing path or unreadable file is
    /// a hard error, never a silent fallback to dry run.
    pub fn new(cfg: SniperConfig, rpc: Arc<RpcClient>, rpc_cfg: &RpcConfig) -> Result<Self> {
        if cfg.trade_size_sol > cfg.max_trade_size_sol {
            bail!(
                "sniper.trade_size_sol ({}) exceeds max_trade_size_sol ({})",
                cfg.trade_size_sol,
                cfg.max_trade_size_sol
            );
        }
        let mode = if cfg.armed {
            if cfg.keypair_path.is_empty() {
                bail!(
                    "sniper.armed = true requires sniper.keypair_path. Use a \
                     DEDICATED wallet, never your main one."
                );
            }
            let wallet = Wallet::load(&cfg.keypair_path)?;
            warn!(
                pubkey = %wallet.pubkey(),
                trade_size_sol = cfg.trade_size_sol,
                daily_cap_sol = cfg.daily_cap_sol,
                max_trades_per_day = cfg.max_trades_per_day,
                kill_switch = %cfg.kill_switch_file,
                "*** SNIPER ARMED — THIS WILL SPEND REAL FUNDS *** \
                 no live trade has ever been executed by this code; \
                 supervise the first one"
            );
            Mode::Armed(SigningCapability { wallet })
        } else {
            let simulate_as = if cfg.simulate_as.is_empty() {
                None
            } else {
                Some(crate::tx::pk(&cfg.simulate_as)?)
            };
            if cfg.enabled {
                warn!(
                    trade_size_sol = cfg.trade_size_sol,
                    rehearsing = simulate_as.is_some(),
                    "sniper enabled in DRY RUN — nothing will be signed"
                );
            }
            Mode::DryRun { simulate_as }
        };

        let submitter = Submitter::new(rpc_cfg, cfg.preflight, cfg.confirm_timeout_secs);
        let jito = cfg.jito_enabled.then(|| {
            JitoClient::new(&cfg.jito_block_engine_url, cfg.jito_tip_lamports)
        });
        let tunable = Tunable {
            trade_size_sol: cfg.trade_size_sol,
            slippage_bps: cfg.slippage_bps,
            min_liquidity_sol: cfg.min_liquidity_sol,
        };
        Ok(Self {
            cfg,
            mode,
            state: Mutex::new(DailyState::default()),
            tunable: Mutex::new(tunable),
            rpc,
            submitter,
            jito,
        })
    }

    /// Load Jito tip accounts. Must succeed before an armed run can bundle —
    /// an untipped bundle is silently ignored by the block engine.
    pub async fn prepare(&self) -> Result<()> {
        if let Some(j) = &self.jito {
            let n = j.refresh_tip_accounts().await?;
            warn!(
                tip_accounts = n,
                tip_lamports = self.cfg.jito_tip_lamports,
                "sniper: Jito bundle submission ENABLED"
            );
        }
        Ok(())
    }

    /// Consume daily budget and start the pool's cooldown, for a trade that is
    /// going ahead.
    ///
    /// The cooldown is recorded HERE rather than at the cooldown check, so it
    /// tracks trades that actually proceed. Recording at check time would cool
    /// down a pool whose build later failed — permanently locking out a pool we
    /// never traded — and recording nowhere would let a re-detection buy twice.
    fn reserve(&self, pool: &str, size: f64, now: DateTime<Utc>) {
        let mut st = self.state.lock().unwrap();
        st.roll(now);
        st.spent += size;
        st.trades += 1;
        st.record_pool(pool.to_string(), now, self.cfg.pool_cooldown_secs);
    }

    /// Identity to build the transaction for: the wallet when armed, the
    /// configured `simulate_as` when rehearsing.
    fn owner(&self) -> Option<Pubkey> {
        match &self.mode {
            Mode::Armed(c) => Some(c.wallet.pubkey()),
            Mode::DryRun { simulate_as } => *simulate_as,
        }
    }

    /// The wallet `/balance` should report on, and what kind of wallet it is.
    ///
    /// Returns the address only — never key material. The distinction matters
    /// for reporting: a rehearsal pubkey is somebody's real wallet being
    /// simulated against, not an account this process can spend from, and
    /// showing them identically would misrepresent what is at risk.
    pub fn trading_identity(&self) -> Option<(String, WalletRole)> {
        let role = match &self.mode {
            Mode::Armed(_) => WalletRole::Armed,
            Mode::DryRun { .. } => WalletRole::Rehearsal,
        };
        self.owner().map(|pk| (pk.to_string(), role))
    }

    /// Human-readable settings snapshot for `/settings`. Read-only; exposes no
    /// key material. Shows the current (possibly tuned-down) working values, with
    /// the locally-set ceilings labelled distinctly so it is clear which can
    /// never be moved from Telegram.
    pub fn settings_rows(&self) -> Vec<(&'static str, String)> {
        let armed = matches!(self.mode, Mode::Armed(_));
        let c = &self.cfg;
        let t = *self.tunable.lock().unwrap();
        vec![
            ("Mode", if armed { "🔴 ARMED (live)".into() } else { "🧪 dry run".into() }),
            ("Trade size", format!("{} SOL (ceiling {})", t.trade_size_sol, c.trade_size_sol)),
            ("Slippage", format!("{} bps ({:.1}%)", t.slippage_bps, t.slippage_bps as f64 / 100.0)),
            ("Min liquidity", format!("{} SOL (floor {})", t.min_liquidity_sol, c.min_liquidity_sol)),
            ("Max price impact", format!("{} bps", c.max_price_impact_bps)),
            ("— hard cap: max trade", format!("{} SOL", c.max_trade_size_sol)),
            ("— hard cap: daily spend", format!("{} SOL", c.daily_cap_sol)),
            ("— hard cap: trades/day", format!("{}", c.max_trades_per_day)),
            ("Pool cooldown", format!("{}s", c.pool_cooldown_secs)),
            ("Preflight", if c.preflight { "on".into() } else { "OFF".into() }),
            ("Jito bundles", if c.jito_enabled { "on".into() } else { "off".into() }),
        ]
    }

    /// Lower the working trade size. Tighten-only: refuses any value above the
    /// configured `trade_size_sol` ceiling, so a command can shrink the trade
    /// but never grow it. Raising the ceiling is a host-side config change.
    pub fn set_trade_size(&self, v: f64) -> Result<String, String> {
        if v <= 0.0 || v.is_nan() {
            return Err("trade size must be greater than 0".into());
        }
        if v > self.cfg.trade_size_sol {
            return Err(format!(
                "can only LOWER the trade size from here. Ceiling is {} SOL — \
                 raise it in config on the host.",
                self.cfg.trade_size_sol
            ));
        }
        self.tunable.lock().unwrap().trade_size_sol = v;
        Ok(format!("trade size set to {v} SOL"))
    }

    /// Tighten slippage. Refuses any value above the configured `slippage_bps`,
    /// so it can only get stricter (less sandwich exposure), never looser.
    pub fn set_slippage_bps(&self, bps: u16) -> Result<String, String> {
        if bps == 0 {
            return Err("slippage of 0 bps would essentially never fill".into());
        }
        if bps > self.cfg.slippage_bps {
            return Err(format!(
                "can only TIGHTEN slippage from here. Current ceiling is {} bps.",
                self.cfg.slippage_bps
            ));
        }
        self.tunable.lock().unwrap().slippage_bps = bps;
        Ok(format!("slippage set to {bps} bps"))
    }

    /// Raise the minimum liquidity. Refuses any value below the configured
    /// `min_liquidity_sol`, so it can only become MORE selective, never less.
    pub fn set_min_liquidity(&self, v: f64) -> Result<String, String> {
        if v < 0.0 {
            return Err("minimum liquidity cannot be negative".into());
        }
        if v < self.cfg.min_liquidity_sol {
            return Err(format!(
                "can only RAISE the minimum liquidity from here (more cautious). \
                 Floor is {} SOL — lower it in config on the host.",
                self.cfg.min_liquidity_sol
            ));
        }
        self.tunable.lock().unwrap().min_liquidity_sol = v;
        Ok(format!("minimum liquidity set to {v} SOL"))
    }

    /// Is the kill switch file present? Checked per-decision so it takes effect
    /// immediately, with no restart and no signal handling.
    fn kill_switch_engaged(&self) -> bool {
        !self.cfg.kill_switch_file.is_empty()
            && Path::new(&self.cfg.kill_switch_file).exists()
    }

    /// Evaluate a detected pool and either produce a plan or a reason to refuse.
    ///
    /// Pure with respect to funds: this never sends anything. It is also where
    /// the pre-trade re-checks live, so a pool that degraded between detection
    /// and execution is caught.
    pub fn consider(&self, ev: &PoolEvent, now: DateTime<Utc>) -> Result<TradePlan, Denial> {
        // Snapshot the tuned working values once, so a mid-decision change from
        // Telegram cannot make the checks and the plan disagree.
        let tuned = *self.tunable.lock().unwrap();

        if !self.cfg.enabled {
            return Err(Denial::Disabled);
        }
        if self.kill_switch_engaged() {
            return Err(Denial::KillSwitchEngaged);
        }

        let Some(token_mint) = ev.new_token_mint.clone() else {
            return Err(Denial::NoTokenMint);
        };
        let Some(quote_asset) = ev.quote_asset.clone() else {
            return Err(Denial::NoQuoteAsset);
        };

        // Re-check safety at execution time rather than trusting the detection
        // snapshot: these are the properties that make a token untradeable.
        if ev.mint_authority_revoked == Some(false) {
            return Err(Denial::UnsafeMint { reason: "mint authority live".into() });
        }
        if ev.freeze_authority_revoked == Some(false) {
            return Err(Denial::UnsafeMint { reason: "freeze authority live".into() });
        }
        if !ev.risky_extensions.is_empty() {
            return Err(Denial::UnsafeMint {
                reason: format!("token-2022 extensions: {}", ev.risky_extensions.join(", ")),
            });
        }

        // Liquidity must be known AND sufficient. Unknown is refused here even
        // though the alert path emits it — spending money on an unverified pool
        // is a different risk posture from sending a notification about one.
        match ev.quote_liquidity {
            Some(l) if l >= tuned.min_liquidity_sol => {}
            observed => {
                return Err(Denial::LiquidityBelowMinimum {
                    observed,
                    required: tuned.min_liquidity_sol,
                });
            }
        }

        let size = tuned.trade_size_sol;
        if size > self.cfg.max_trade_size_sol {
            return Err(Denial::TradeSizeExceedsMax { size, max: self.cfg.max_trade_size_sol });
        }

        // Daily limits and per-pool cooldown share one lock: they are checked
        // against the same state that `reserve` mutates.
        {
            let mut st = self.state.lock().unwrap();
            st.roll(now);
            if let Some(seconds_remaining) =
                st.cooling_down(&ev.pool, now, self.cfg.pool_cooldown_secs)
            {
                return Err(Denial::PoolCoolingDown { seconds_remaining });
            }
            if st.trades >= self.cfg.max_trades_per_day {
                return Err(Denial::DailyTradeCountReached {
                    count: st.trades,
                    max: self.cfg.max_trades_per_day,
                });
            }
            if st.spent + size > self.cfg.daily_cap_sol {
                return Err(Denial::DailyCapReached {
                    spent: st.spent,
                    cap: self.cfg.daily_cap_sol,
                });
            }
        }

        Ok(TradePlan {
            pool: ev.pool.clone(),
            dex: ev.dex.label().to_string(),
            token_mint,
            quote_asset,
            size,
            slippage_bps: tuned.slippage_bps,
            observed_liquidity: ev.quote_liquidity,
        })
    }

    /// Consider a pool, build the real transaction, then rehearse or execute.
    /// Always audits.
    pub async fn handle(&self, ev: &PoolEvent) -> Execution {
        let now = Utc::now();
        let plan = match self.consider(ev, now) {
            Err(denial) => {
                info!(pool = %ev.pool, reason = denial.label(), "sniper: skipped");
                self.audit(ev, None, Some(&denial), None).await;
                return Execution::Skipped {
                    pool: ev.pool.clone(),
                    reason: denial.label().to_string(),
                };
            }
            Ok(p) => p,
        };

        let Some(owner) = self.owner() else {
            let d = Denial::NoSimulationIdentity;
            info!(pool = %ev.pool, reason = d.label(), "sniper: skipped");
            self.audit(ev, Some(&plan), Some(&d), None).await;
            return Execution::Skipped {
                pool: ev.pool.clone(),
                reason: d.label().to_string(),
            };
        };

        // Build against FRESH pool state — the reserves seen at detection are
        // already stale, and a quote from stale reserves misprices the guard.
        let lamports = (plan.size * 1_000_000_000.0) as u64;
        let built = execute::build_buy(
            &self.rpc,
            ev,
            &owner,
            lamports,
            plan.slippage_bps,
            self.cfg.compute_unit_limit,
            self.cfg.priority_fee_micro_lamports,
        )
        .await;

        let exec = match built {
            Ok(e) => e,
            Err(e) => {
                let d = Denial::CannotBuild { reason: format!("{e:#}") };
                info!(pool = %ev.pool, reason = %format!("{e:#}"), "sniper: cannot build");
                self.audit(ev, Some(&plan), Some(&d), None).await;
                return Execution::Skipped {
                    pool: ev.pool.clone(),
                    reason: d.label().to_string(),
                };
            }
        };

        // A buy that moves the pool this much is buying its own bad fill.
        if exec.quote.price_impact_bps > self.cfg.max_price_impact_bps {
            let d = Denial::PriceImpactTooHigh {
                impact_bps: exec.quote.price_impact_bps,
                max_bps: self.cfg.max_price_impact_bps,
            };
            info!(
                pool = %ev.pool,
                impact_bps = exec.quote.price_impact_bps,
                max_bps = self.cfg.max_price_impact_bps,
                "sniper: price impact too high"
            );
            self.audit(ev, Some(&plan), Some(&d), None).await;
            return Execution::Skipped {
                pool: ev.pool.clone(),
                reason: d.label().to_string(),
            };
        }

        // Reserve against the daily budget once the trade is actually going
        // ahead, so a rehearsed day matches what a live day would have spent.
        // Deliberately NOT reserved for trades refused earlier — budget should
        // only be consumed by trades that really happen.
        self.reserve(&plan.pool, plan.size, now);

        match &self.mode {
            Mode::DryRun { .. } => {
                // Rehearse: simulate the real transaction and report whether it
                // would have worked.
                let outcome = self.rehearse(&exec).await;
                info!(
                    pool = %plan.pool,
                    dex = %plan.dex,
                    token = %plan.token_mint,
                    size_sol = plan.size,
                    expected_out = exec.quote.expected_out,
                    minimum_out = exec.quote.minimum_out,
                    impact_bps = exec.quote.price_impact_bps,
                    outcome = %outcome,
                    "sniper: DRY RUN (nothing signed)"
                );
                self.audit(ev, Some(&plan), None, Some(&outcome)).await;
                // Only "would-FAIL:" means the simulation ran and the trade was
                // rejected. Deliberately NOT treating every non-success as a
                // failure: "simulation-unavailable" means the RPC didn't answer,
                // which says nothing about the trade, and alerting on it would
                // fire on every RPC hiccup.
                let would_succeed = !outcome.starts_with("would-FAIL");
                Execution::Rehearsed { plan, outcome, would_succeed }
            }
            Mode::Armed(cap) => {
                warn!(
                    pool = %plan.pool,
                    token = %plan.token_mint,
                    size_sol = plan.size,
                    minimum_out = exec.quote.minimum_out,
                    "sniper: SUBMITTING REAL TRADE"
                );
                let res = match &self.jito {
                    Some(j) => {
                        self.submitter
                            .send_bundle(
                                &exec.instructions,
                                &cap.wallet.pubkey(),
                                cap.wallet.keypair(),
                                j,
                                std::time::Duration::from_secs(self.cfg.confirm_timeout_secs),
                            )
                            .await
                    }
                    None => {
                        self.submitter
                            .send(&exec.instructions, &cap.wallet.pubkey(), cap.wallet.keypair())
                            .await
                    }
                };
                // Classified by what it means for funds, not by whether the call
                // returned Ok. The critical distinction is Executed vs
                // NotExecuted vs Indeterminate — see `SubmitOutcome`.
                let (outcome, result) = match res {
                    Ok(Submission::BundleLanded { bundle, slot }) => {
                        info!(%bundle, slot, "sniper: bundle LANDED");
                        (
                            format!("bundle_landed:{bundle}"),
                            SubmitOutcome::Executed { reference: bundle, slot: Some(slot) },
                        )
                    }
                    // Atomic: nothing executed and no tip was paid, so unlike an
                    // unconfirmed plain tx this is genuinely safe to retry.
                    Ok(Submission::BundleNotLanded { bundle, last }) => {
                        warn!(%bundle, %last, "sniper: bundle did NOT land; nothing executed");
                        (
                            format!("bundle_not_landed:{bundle}:{last}"),
                            SubmitOutcome::NotExecuted {
                                reason: format!("bundle did not land ({last})"),
                            },
                        )
                    }
                    Ok(Submission::Confirmed { signature, slot }) => {
                        info!(%signature, slot, "sniper: trade CONFIRMED");
                        (
                            format!("confirmed:{signature}"),
                            SubmitOutcome::Executed { reference: signature, slot: Some(slot) },
                        )
                    }
                    Ok(Submission::Unconfirmed { signature }) => {
                        // Explicitly not a failure: it may still land, so a
                        // retry here could double-buy.
                        warn!(%signature, "sniper: trade UNCONFIRMED — may still land, not retrying");
                        (
                            format!("unconfirmed:{signature}"),
                            SubmitOutcome::Indeterminate {
                                reference: signature,
                                reason: "not confirmed within timeout; may still land".into(),
                            },
                        )
                    }
                    Ok(Submission::RejectedByPreflight { reason }) => {
                        warn!(%reason, "sniper: rejected by preflight, nothing sent");
                        (
                            format!("preflight_rejected:{reason}"),
                            SubmitOutcome::NotExecuted {
                                reason: format!("preflight rejected: {reason}"),
                            },
                        )
                    }
                    // NOT NotExecuted. `Submission::Failed` covers RPC transport
                    // errors from `sendTransaction` (submit.rs:238), which
                    // include a request that timed out or dropped its connection
                    // AFTER the node accepted the transaction. Reporting "no
                    // funds were spent" there is a false assurance in the exact
                    // case where it costs the most: the operator retries and
                    // buys twice. `Submission::definitely_did_not_execute`
                    // excludes this variant for the same reason.
                    Ok(Submission::Failed { reason }) => {
                        warn!(%reason, "sniper: submission failed — outcome not guaranteed");
                        (
                            format!("failed:{reason}"),
                            SubmitOutcome::Indeterminate {
                                reference: "no-signature".into(),
                                reason,
                            },
                        )
                    }
                    Err(e) => {
                        // A transport error after the send is genuinely unknown:
                        // the node may have accepted the transaction before the
                        // connection broke. Reporting this as "failed" could lead
                        // the operator to retry into a double-buy.
                        let reason = format!("{e:#}");
                        warn!(error = %reason, "sniper: submission error — outcome UNKNOWN");
                        (
                            format!("error:{reason}"),
                            SubmitOutcome::Indeterminate {
                                reference: "no-signature".into(),
                                reason,
                            },
                        )
                    }
                };
                self.audit(ev, Some(&plan), None, Some(&outcome)).await;
                Execution::Submitted { plan, result }
            }
        }
    }

    /// Simulate a built plan without signing. Used by dry run.
    async fn rehearse(&self, exec: &execute::ExecutionPlan) -> String {
        use base64::Engine;
        use solana_message::Message;
        use solana_transaction::Transaction;

        let Some(owner) = self.owner() else {
            return "no-identity".into();
        };
        let msg = Message::new(&exec.instructions, Some(&owner));
        let tx = Transaction::new_unsigned(msg);
        let Ok(bytes) = bincode::serialize(&tx) else {
            return "serialize-failed".into();
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        match self.rpc.simulate_transaction(&b64).await {
            None => "simulation-unavailable".into(),
            Some(v) => {
                let err = v.get("err").cloned().unwrap_or(serde_json::Value::Null);
                if err.is_null() {
                    "would-succeed".into()
                } else {
                    format!("would-FAIL: {err}")
                }
            }
        }
    }

    /// Append-only audit trail of every decision.
    async fn audit(
        &self,
        ev: &PoolEvent,
        plan: Option<&TradePlan>,
        denial: Option<&Denial>,
        outcome: Option<&str>,
    ) {
        if self.cfg.audit_log.is_empty() {
            return;
        }
        let record = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "pool": ev.pool,
            "signature": ev.signature,
            "decision": if denial.is_some() { "skipped" } else { "traded" },
            "mode": match self.mode {
                Mode::Armed(_) => "armed",
                Mode::DryRun { .. } => "dry_run",
            },
            "plan": plan,
            "denial": denial,
            "outcome": outcome,
            // Vaults + venue recorded so `/positions` can price a holding later
            // (mid-price = quote_vault / base_vault). Cost basis alone isn't PnL.
            "dex": ev.dex.label(),
            "base_vault": ev.base_vault,
            "quote_vault": ev.quote_vault,
        });
        if let Err(e) = append_line(&self.cfg.audit_log, &record).await {
            warn!(error = %e, "failed to write sniper audit log");
        }
    }
}

async fn append_line(path: &str, value: &serde_json::Value) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
    }
    let mut line = serde_json::to_string(value)?;
    line.push('\n');
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    f.write_all(line.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Dex, PoolEvent, WSOL_MINT};

    fn cfg() -> SniperConfig {
        SniperConfig {
            enabled: true,
            armed: false,
            trade_size_sol: 0.1,
            max_trade_size_sol: 1.0,
            daily_cap_sol: 1.0,
            max_trades_per_day: 5,
            // Off by default in tests so existing cases that reuse the same
            // pool address keep exercising what they were written to test.
            // Cooldown behaviour is covered explicitly below.
            pool_cooldown_secs: 0,
            min_liquidity_sol: 5.0,
            slippage_bps: 300,
            kill_switch_file: String::new(),
            audit_log: String::new(),
            keypair_path: String::new(),
            simulate_as: String::new(),
            max_price_impact_bps: 1_000,
            preflight: true,
            confirm_timeout_secs: 5,
            compute_unit_limit: 200_000,
            priority_fee_micro_lamports: 1,
            jito_enabled: false,
            jito_block_engine_url: "https://mainnet.block-engine.jito.wtf/api/v1/bundles".into(),
            jito_tip_lamports: 10_000,
            jito_fallback_to_rpc: false,
            wallet_dir: "wallets".into(),
            alert_on_all_rehearsals: false,
        }
    }

    fn mk(c: SniperConfig) -> Result<Sniper> {
        let rpc_cfg = RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            ..Default::default()
        };
        Sniper::new(c, Arc::new(RpcClient::new(&rpc_cfg)), &rpc_cfg)
    }

    fn event() -> PoolEvent {
        PoolEvent {
            dex: Dex::RaydiumV4,
            pool: "POOL".into(),
            base_mint: "TOKEN".into(),
            quote_mint: WSOL_MINT.into(),
            new_token_mint: Some("TOKEN".into()),
            quote_asset: Some(WSOL_MINT.into()),
            quote_asset_vault: Some("VAULT".into()),
            quote_liquidity: Some(20.0),
            mint_authority_revoked: Some(true),
            freeze_authority_revoked: Some(true),
            risky_extensions: vec![],
            lp_mint: Some("LP".into()),
            base_vault: None,
            quote_vault: None,
            swap_accounts: Default::default(),
            lp_supply_at_detection: Some(1.0),
            signature: "SIG".into(),
            slot: 1,
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn a_healthy_pool_produces_a_plan() {
        let s = mk(cfg()).unwrap();
        let plan = s.consider(&event(), Utc::now()).unwrap();
        assert_eq!(plan.size, 0.1);
        assert_eq!(plan.token_mint, "TOKEN");
    }

    /// Arming without a keypair must be refused: there is no wallet to sign
    /// with, so `Mode::Armed` must not be constructible.
    #[test]
    fn arming_without_a_keypair_is_refused() {
        let mut c = cfg();
        c.armed = true;
        c.keypair_path = String::new();
        let err = mk(c).unwrap_err().to_string();
        assert!(err.contains("keypair_path"), "got: {err}");
    }

    /// A missing keypair file must fail loudly rather than silently dry-running.
    #[test]
    fn arming_with_a_missing_keypair_file_is_refused() {
        let mut c = cfg();
        c.armed = true;
        c.keypair_path = "/nonexistent/volens-test-key.json".into();
        assert!(mk(c).is_err());
    }

    /// The armed path must actually construct with a real keypair. Without
    /// this, a wallet-loading bug would only surface at the moment of the first
    /// real trade.
    #[test]
    fn arming_with_a_valid_keypair_succeeds() {
        use solana_signer::Signer;
        let dir = std::env::temp_dir().join(format!("volens-arm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.json");

        let kp = solana_keypair::Keypair::new();
        let bytes = kp.to_bytes().to_vec();
        std::fs::write(&path, serde_json::to_string(&bytes).unwrap()).unwrap();

        let mut c = cfg();
        c.armed = true;
        c.keypair_path = path.to_string_lossy().into_owned();
        let s = mk(c).expect("arming with a valid keypair must succeed");

        assert!(matches!(s.mode, Mode::Armed(_)), "must be armed");
        assert_eq!(s.owner(), Some(kp.pubkey()), "owner must be the loaded wallet");

        // The wallet must never render its secret, even in Debug output.
        let dbg = format!("{s:?}");
        assert!(dbg.contains("armed"));
        let secret_prefix = format!("{:?}", &bytes[..8]);
        assert!(!dbg.contains(&secret_prefix), "secret key must not appear in Debug");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Dry run must never hold signing capability, whatever else is configured.
    #[test]
    fn dry_run_holds_no_signing_capability() {
        let s = mk(cfg()).unwrap();
        assert!(matches!(s.mode, Mode::DryRun { .. }));
        // No wallet => no owner to build as, unless simulate_as is set.
        assert!(s.owner().is_none());
    }

    #[test]
    fn simulate_as_gives_dry_run_an_identity_but_not_a_signer() {
        let mut c = cfg();
        c.simulate_as = "GEUDKx63wXKrn7ognB2gkmy8YRNkVF1hgS4sBEg9nZVm".into();
        let s = mk(c).unwrap();
        assert!(matches!(s.mode, Mode::DryRun { .. }), "still a dry run");
        assert!(s.owner().is_some(), "can build/simulate");
    }

    #[test]
    fn trade_size_above_max_is_rejected_at_construction() {
        let mut c = cfg();
        c.trade_size_sol = 5.0;
        assert!(mk(c).is_err());
    }

    /// A refused trade must not consume budget — otherwise a run of denials
    /// silently exhausts the daily cap.
    #[tokio::test]
    async fn refused_trades_do_not_consume_budget() {
        let mut c = cfg();
        c.max_trades_per_day = 1;
        let s = mk(c).unwrap();
        let mut ev = event();
        ev.quote_liquidity = Some(0.0); // refused: below minimum liquidity

        s.handle(&ev).await;
        s.handle(&ev).await;
        // Budget untouched, so a good pool would still be tradable.
        assert!(s.consider(&event(), Utc::now()).is_ok());
    }

    /// The core safety property of runtime tuning: it can only move settings
    /// SAFER. A leaked bot token must not be able to raise spend or loosen
    /// slippage. The config values are the risk ceilings.
    #[test]
    fn tuning_is_tighten_only() {
        let mut c = cfg();
        c.trade_size_sol = 0.05;
        c.slippage_bps = 300;
        c.min_liquidity_sol = 10.0;
        let s = mk(c).unwrap();

        // Size: lowering is allowed, raising above the ceiling is refused.
        assert!(s.set_trade_size(0.02).is_ok());
        assert!(s.set_trade_size(0.05).is_ok(), "equal to ceiling is fine");
        assert!(s.set_trade_size(0.06).is_err(), "above ceiling must be refused");
        assert!(s.set_trade_size(0.0).is_err(), "zero/negative refused");

        // Slippage: tightening allowed, loosening refused.
        assert!(s.set_slippage_bps(200).is_ok());
        assert!(s.set_slippage_bps(301).is_err(), "looser than ceiling refused");

        // Min liquidity: raising allowed (more cautious), lowering refused.
        assert!(s.set_min_liquidity(20.0).is_ok());
        assert!(s.set_min_liquidity(9.0).is_err(), "below floor refused");
    }

    /// A tuned-down size must actually be what `consider` plans and checks — not
    /// just a stored number. Verifies the plumbing, not only the setter.
    #[test]
    fn tuned_size_flows_into_the_plan() {
        let mut c = cfg();
        c.trade_size_sol = 0.05;
        let s = mk(c).unwrap();

        s.set_trade_size(0.01).unwrap();
        let plan = s.consider(&event(), Utc::now()).unwrap();
        assert_eq!(plan.size, 0.01, "plan must use the tuned size, not the config default");
    }

    /// A raised min-liquidity floor must cause a pool that was fine before to be
    /// refused — proving the tuned floor reaches the liquidity gate.
    #[test]
    fn tuned_min_liquidity_gate_applies() {
        let mut c = cfg();
        c.min_liquidity_sol = 5.0;
        let s = mk(c).unwrap();

        let mut ev = event();
        ev.quote_liquidity = Some(15.0);
        assert!(s.consider(&ev, Utc::now()).is_ok(), "15 SOL clears the 5 SOL floor");

        s.set_min_liquidity(20.0).unwrap();
        assert!(
            matches!(s.consider(&ev, Utc::now()), Err(Denial::LiquidityBelowMinimum { .. })),
            "raising the floor to 20 must now refuse the 15 SOL pool"
        );
    }

    #[test]
    fn pool_cooldown_blocks_a_second_trade() {
        let mut c = cfg();
        c.pool_cooldown_secs = 3600;
        let s = mk(c).unwrap();
        let ev = event();
        let now = Utc::now();

        // First trade is fine, and reserving starts the cooldown.
        assert!(s.consider(&ev, now).is_ok());
        s.reserve(&ev.pool, 0.1, now);

        match s.consider(&ev, now) {
            Err(Denial::PoolCoolingDown { seconds_remaining }) => {
                assert!(seconds_remaining > 3500, "got {seconds_remaining}");
            }
            other => panic!("expected PoolCoolingDown, got {other:?}"),
        }
    }

    /// A different pool must be unaffected — the cooldown is per-pool, not a
    /// global rate limit. Without this, the test above would pass even if the
    /// cooldown blocked everything.
    #[test]
    fn cooldown_is_scoped_to_one_pool() {
        let mut c = cfg();
        c.pool_cooldown_secs = 3600;
        let s = mk(c).unwrap();
        let now = Utc::now();

        let a = event();
        s.reserve(&a.pool, 0.1, now);

        let mut b = event();
        b.pool = "OTHER_POOL".into();
        assert!(s.consider(&b, now).is_ok(), "a different pool must still trade");
    }

    #[test]
    fn cooldown_expires() {
        let mut c = cfg();
        c.pool_cooldown_secs = 60;
        let s = mk(c).unwrap();
        let ev = event();
        let t0 = Utc::now();

        s.reserve(&ev.pool, 0.1, t0);
        assert!(s.consider(&ev, t0).is_err(), "blocked immediately after");
        assert!(
            s.consider(&ev, t0 + chrono::Duration::seconds(61)).is_ok(),
            "must be tradable again once the window passes"
        );
    }

    #[test]
    fn zero_cooldown_disables_the_check() {
        let mut c = cfg();
        c.pool_cooldown_secs = 0;
        let s = mk(c).unwrap();
        let ev = event();
        let now = Utc::now();

        s.reserve(&ev.pool, 0.1, now);
        assert!(s.consider(&ev, now).is_ok(), "0 must disable the cooldown");
    }

    /// The reason `record_pool` lives in `reserve` and not at the check.
    ///
    /// A pool whose trade never proceeded (build failure, price impact, refused
    /// by an earlier guard) must NOT be cooled down — that would permanently
    /// lock out a pool we never actually bought.
    #[tokio::test]
    async fn a_refused_trade_does_not_start_the_cooldown() {
        let mut c = cfg();
        c.pool_cooldown_secs = 3600;
        let s = mk(c).unwrap();

        let mut bad = event();
        bad.quote_liquidity = Some(0.0); // refused: below minimum liquidity
        s.handle(&bad).await;

        // Same pool, now with good liquidity: must be tradable, because the
        // refused attempt never consumed anything.
        let good = event();
        assert!(
            s.consider(&good, Utc::now()).is_ok(),
            "a refused trade must not cool down the pool"
        );
    }

    /// A backwards clock (NTP correction) must not open a re-trade window.
    #[test]
    fn clock_going_backwards_keeps_the_pool_cooled() {
        let mut c = cfg();
        c.pool_cooldown_secs = 3600;
        let s = mk(c).unwrap();
        let ev = event();
        let t0 = Utc::now();

        s.reserve(&ev.pool, 0.1, t0);
        let earlier = t0 - chrono::Duration::seconds(120);
        assert!(
            s.consider(&ev, earlier).is_err(),
            "a backwards clock must not permit a second trade"
        );
    }

    /// The cooldown map must not grow without bound on a long-running process.
    #[test]
    fn cooldown_map_evicts_expired_entries() {
        let mut st = DailyState::default();
        let t0 = Utc::now();
        for i in 0..100 {
            st.record_pool(format!("POOL{i}"), t0, 60);
        }
        assert_eq!(st.recent_pools.len(), 100);

        // A later insert past the window sweeps the stale entries.
        st.record_pool("FRESH".into(), t0 + chrono::Duration::seconds(120), 60);
        assert_eq!(st.recent_pools.len(), 1, "expired entries must be evicted");
        assert!(st.recent_pools.contains_key("FRESH"));
    }

    /// Midnight UTC resets the spend budget; it must not reset cooldowns. A
    /// pool bought at 23:59 must still be cooled down at 00:01.
    #[test]
    fn day_rollover_does_not_clear_cooldowns() {
        let mut c = cfg();
        c.pool_cooldown_secs = 3600;
        let s = mk(c).unwrap();
        let ev = event();

        let before = chrono::DateTime::parse_from_rfc3339("2026-07-21T23:59:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let after = chrono::DateTime::parse_from_rfc3339("2026-07-22T00:01:00Z")
            .unwrap()
            .with_timezone(&Utc);

        s.reserve(&ev.pool, 0.1, before);
        assert!(
            s.consider(&ev, after).is_err(),
            "cooldown must survive the UTC day rollover"
        );
    }

    #[test]
    fn disabled_sniper_refuses() {
        let mut c = cfg();
        c.enabled = false;
        let s = mk(c).unwrap();
        assert_eq!(s.consider(&event(), Utc::now()), Err(Denial::Disabled));
    }

    #[test]
    fn kill_switch_file_halts_everything() {
        let dir = std::env::temp_dir().join(format!("volens-kill-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("HALT");
        std::fs::write(&file, b"stop").unwrap();

        let mut c = cfg();
        c.kill_switch_file = file.to_string_lossy().into_owned();
        let s = mk(c).unwrap();
        assert_eq!(s.consider(&event(), Utc::now()), Err(Denial::KillSwitchEngaged));

        // Removing it re-enables trading without a restart.
        std::fs::remove_file(&file).unwrap();
        assert!(s.consider(&event(), Utc::now()).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn thin_liquidity_is_refused() {
        let s = mk(cfg()).unwrap();
        let mut ev = event();
        ev.quote_liquidity = Some(1.0);
        assert!(matches!(
            s.consider(&ev, Utc::now()),
            Err(Denial::LiquidityBelowMinimum { .. })
        ));
    }

    /// Unknown liquidity is emitted as an alert but must NOT be traded on:
    /// notifying about an unverified pool and buying into one are different
    /// risk postures.
    #[test]
    fn unknown_liquidity_is_refused_even_though_alerts_allow_it() {
        let s = mk(cfg()).unwrap();
        let mut ev = event();
        ev.quote_liquidity = None;
        assert!(matches!(
            s.consider(&ev, Utc::now()),
            Err(Denial::LiquidityBelowMinimum { observed: None, .. })
        ));
    }

    #[test]
    fn live_authorities_are_refused() {
        let s = mk(cfg()).unwrap();

        let mut ev = event();
        ev.freeze_authority_revoked = Some(false);
        assert!(matches!(s.consider(&ev, Utc::now()), Err(Denial::UnsafeMint { .. })));

        let mut ev = event();
        ev.mint_authority_revoked = Some(false);
        assert!(matches!(s.consider(&ev, Utc::now()), Err(Denial::UnsafeMint { .. })));

        let mut ev = event();
        ev.risky_extensions = vec!["transferHook".into()];
        assert!(matches!(s.consider(&ev, Utc::now()), Err(Denial::UnsafeMint { .. })));
    }

    #[test]
    fn daily_spend_cap_is_enforced() {
        let mut c = cfg();
        c.trade_size_sol = 0.4;
        c.daily_cap_sol = 1.0;
        let s = mk(c).unwrap();
        let now = Utc::now();

        // 0.4 + 0.4 = 0.8 fits; the third would reach 1.2 > 1.0.
        // Distinct pools so the per-pool cooldown can never be what denies the
        // third trade — this test must fail for cap reasons only.
        s.reserve("POOL_A", 0.4, now);
        s.reserve("POOL_B", 0.4, now);
        assert!(matches!(
            s.consider(&event(), now),
            Err(Denial::DailyCapReached { .. })
        ));
    }

    #[test]
    fn daily_trade_count_is_enforced() {
        let mut c = cfg();
        c.max_trades_per_day = 2;
        c.daily_cap_sol = 100.0;
        let s = mk(c).unwrap();
        let now = Utc::now();

        s.reserve("POOL_A", 0.1, now);
        s.reserve("POOL_B", 0.1, now);
        assert!(matches!(
            s.consider(&event(), now),
            Err(Denial::DailyTradeCountReached { count: 2, max: 2 })
        ));
    }

    /// Budget must reset on a new UTC day, not accumulate forever.
    #[test]
    fn daily_state_rolls_over() {
        let mut c = cfg();
        c.trade_size_sol = 0.9;
        c.daily_cap_sol = 1.0;
        let s = mk(c).unwrap();
        let today = Utc::now();
        s.reserve("POOL_A", 0.9, today);
        assert!(matches!(
            s.consider(&event(), today),
            Err(Denial::DailyCapReached { .. })
        ));

        let tomorrow = today + chrono::Duration::days(1);
        assert!(s.consider(&event(), tomorrow).is_ok(), "budget must reset next day");
    }
}
