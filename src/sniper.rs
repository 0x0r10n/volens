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

/// Smallest trade worth making. Below this, fees and rent dominate the position
/// so completely that the trade cannot express an opinion about the token.
const MIN_TRADE_SOL: f64 = 0.005;

/// How stale a price may be and still fire an exit.
///
/// The detector tolerates an hour because it is describing a token; an exit is
/// spending money on the claim that the price is what it says right now. A
/// position that has not printed in 90 seconds is not "worth its last price" —
/// it is a position we cannot currently see, and the sweep says so rather than
/// selling against a number that stopped being true.
const EXIT_PRICE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(90);

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
    /// Fully-diluted valuation at or above the configured ceiling.
    MarketCapTooHigh { mcap_usd: f64, max_usd: f64 },
    /// The ceiling could not be evaluated. Refused rather than waved through:
    /// an unreadable guard is not a passed guard.
    MarketCapUnreadable,
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
            Denial::MarketCapTooHigh { .. } => "market cap too high",
            Denial::MarketCapUnreadable => "market cap unreadable",
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

/// Outcome of a manual EXIT (selling a held token back to SOL via `/positions`).
/// Separate from `Execution` because a sell is user-initiated on one mint, not
/// the sniper reacting to a detected pool.
#[cfg(feature = "sniper")]
#[derive(Debug, Clone)]
pub enum BuyOutcome {
    /// Refused before any network call (halted, capped, no identity).
    Refused { reason: String },
    /// Something failed while quoting or building the swap.
    Failed { mint: String, reason: String },
    /// Dry run: quoted and simulated, nothing signed.
    Rehearsed { mint: String, sol_in: f64, tokens_out: f64, would_succeed: bool },
    /// Armed: submitted.
    Submitted { mint: String, sol_in: f64, tokens_out: f64, result: SubmitOutcome },
}

#[derive(Debug, Clone)]
pub enum SellOutcome {
    /// The wallet holds none of this mint.
    NoPosition { mint: String },
    /// Refused before any network call (halted, bad percentage, no identity).
    Refused { reason: String },
    /// Something failed while quoting or building the swap.
    Failed { mint: String, reason: String },
    /// Dry run: the swap was quoted and simulated, nothing signed.
    Rehearsed { mint: String, pct: u8, sol_out: f64, impact_pct: f64, would_succeed: bool },
    /// Armed: the swap was submitted.
    Submitted { mint: String, pct: u8, sol_out: f64, result: SubmitOutcome },
}

/// Outcome of a manual withdrawal (moving SOL OUT of the trading wallet).
#[cfg(feature = "sniper")]
#[derive(Debug, Clone)]
pub enum WithdrawOutcome {
    /// Refused before any signing (halted, not armed, bad amount/address, thin
    /// balance). No transaction was built.
    Refused { reason: String },
    /// Submitted. `result` says whether it landed.
    Submitted { sol: f64, dest: String, result: SubmitOutcome },
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
/// Slippage and min-liquidity are tighten-only: a command can tighten slippage
/// or raise the minimum liquidity — both reduce exposure — never the reverse.
/// Trade size is the exception: it is freely settable up to `max_trade_size_sol`
/// (unbounded when that ceiling is 0), so with the ceiling removed the Telegram
/// allowlist — not a tighten-only rule — is the guard on how much the bot spends.
/// When the sniper is allowed to buy.
///
/// The trade-off is not resolvable — it is a genuine strategy choice:
/// * `Open` buys at pool creation. Fastest, but LP lock/burn is a LATER
///   transaction, so at t=0 EVERY pool has unlocked LP. You are buying before
///   the deployer has committed anything.
/// * `Guard` waits for the follow-up re-check and buys only pools whose LP is
///   burned/locked by then. Cuts the rug surface hard, but you enter after the
///   initial move and will miss fast runners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnipeMode {
    Open,
    Guard,
}

impl SnipeMode {
    pub fn label(&self) -> &'static str {
        match self {
            SnipeMode::Open => "⚡ Open — snipe at launch (LP unlocked)",
            SnipeMode::Guard => "🛡 Guard — only secured LP",
        }
    }

    /// The word this mode round-trips through settings storage as.
    pub fn key(&self) -> &'static str {
        match self {
            SnipeMode::Open => "open",
            SnipeMode::Guard => "guard",
        }
    }

    /// Parse from config/command. Unrecognized input is rejected rather than
    /// silently defaulting: picking the wrong one changes what gets bought.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" | "fast" | "snipe" => Some(SnipeMode::Open),
            "guard" | "guarded" | "safe" => Some(SnipeMode::Guard),
            _ => None,
        }
    }
}

/// Working values now live in [`crate::settings::SettingsStore`], which
/// persists them. They used to sit in a plain in-memory struct here, so every
/// value set from Telegram was silently reverted to `config.toml` on restart.
pub use crate::settings::{Envelope, LiveSettings};

/// Render a SOL ceiling for display: 0 means the cap is disabled (unlimited).
fn fmt_cap_sol(v: f64) -> String {
    if v > 0.0 {
        format!("{v} SOL")
    } else {
        "unlimited".into()
    }
}

/// The audit record for a smart-money entry.
///
/// Defined here, in ONE place, because the writer and the reader disagreed
/// once and it cost real money: this record carries an `action` and no `plan`,
/// and `cost_basis_from_audit` skipped every record with an `action`. The
/// position therefore never existed as far as the exit policy was concerned,
/// so take-profit and stop-loss were never offered it and the position was held
/// to zero in silence.
///
/// Anything reading these records should be tested against THIS function, not
/// against a hand-written string that can drift from it.
pub fn smart_buy_record(
    owner: &str,
    mint: &str,
    sol: f64,
    reason: &str,
    outcome: &str,
    armed: bool,
) -> serde_json::Value {
    serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "action": "smart_buy",
        "owner": owner,
        "mint": mint,
        "sol": sol,
        "reason": reason,
        "outcome": outcome,
        "mode": if armed { "armed" } else { "dry_run" },
    })
}

/// Refuse a cap that would be looser than the config envelope.
fn check_tighten(v: f64, hard: f64, unit: &str) -> Result<(), String> {
    if v < 0.0 || v.is_nan() || v.is_infinite() {
        return Err("value must be zero or positive".into());
    }
    if hard > 0.0 && v > hard {
        return Err(format!(
            "{v} {unit} exceeds the configured limit of {hard} {unit}. \
             Only the host can raise a ceiling — this can only tighten one."
        ));
    }
    Ok(())
}

/// Say plainly what a cap now is, including when clearing it leaves nothing.
fn describe_cap(name: &str, v: f64, hard: f64, unit: &str) -> String {
    if v > 0.0 {
        return format!("{name} set to {v} {unit}");
    }
    if hard > 0.0 {
        format!("{name} now follows config ({hard} {unit})")
    } else {
        format!("{name} cleared — no ceiling set, this is now unlimited")
    }
}

/// One cap row: what binds, and which tier set it.
///
/// An absent cap is spelled out rather than shown as a dash, so the screen
/// always says what is actually in force.
fn cap_row(live: f64, hard: f64) -> String {
    let eff = crate::settings::tightest(live, hard);
    if eff <= 0.0 {
        return "unlimited".into();
    }
    let src = if live > 0.0 && (hard <= 0.0 || live <= hard) { "set here" } else { "from config" };
    format!("{eff} SOL ({src})")
}

fn cap_row_u32(live: u32, hard: u32) -> String {
    let eff = crate::settings::tightest_u32(live, hard);
    if eff == 0 {
        return "unlimited".into();
    }
    let src = if live > 0 && (hard == 0 || live <= hard) { "set here" } else { "from config" };
    format!("{eff} ({src})")
}

fn cap_row_usd(live: f64, hard: f64) -> String {
    let eff = crate::settings::tightest(live, hard);
    if eff <= 0.0 {
        return "none".into();
    }
    let src = if live > 0.0 && (hard <= 0.0 || live <= hard) { "set here" } else { "from config" };
    format!("${eff:.0} ({src})")
}

fn cap_row_bps(live: u32, hard: u32) -> String {
    let eff = crate::settings::tightest_u32(live, hard);
    if eff == 0 {
        return "none".into();
    }
    let src = if live > 0 && (hard == 0 || live <= hard) { "set here" } else { "from config" };
    format!("{eff} bps ({src})")
}

pub struct Sniper {
    cfg: SniperConfig,
    mode: Mode,
    state: Mutex<DailyState>,
    /// Cached (price_usd, fetched_at) for SOL. Refreshed on a TTL so the market
    /// cap check does not re-quote Jupiter on every pool.
    #[cfg(feature = "sniper")]
    /// Live settings, persisted. Snapshotted once per decision.
    settings: Arc<crate::settings::SettingsStore>,
    /// How to sell each position, captured at buy time. See `crate::routes`.
    routes: Arc<crate::routes::RouteStore>,
    /// Held positions we have already warned about being unpriceable, so the
    /// warning fires on the transition rather than every fifteen seconds.
    unpriceable: Mutex<std::collections::HashSet<String>>,
    /// Mints whose liquidity was seen being pulled.
    ///
    /// # Why this exists
    ///
    /// The watcher detected a 52% liquidity pull on a token and fired an
    /// emergency exit. Seven minutes later the buy path bought that same token,
    /// because nothing connected the two: mint authority, freeze authority,
    /// price impact and market cap all still passed, and none of them describes
    /// "the LP just halved". The bot knew and bought anyway.
    ///
    /// A rug is permanent for our purposes, so this never expires within a
    /// process. It is memory-only on purpose — a restart re-learns from the
    /// stream rather than trusting a file that could pin a mint forever.
    rugged: Mutex<std::collections::HashSet<String>>,
    rpc: Arc<RpcClient>,
    /// Stream-derived prices. Replaces the external quote API that was
    /// IP-blocked, and which — while the market-cap gate still failed open —
    /// silently disabled that ceiling for hours.
    prices: Arc<crate::prices::PriceIndex>,
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
    pub fn new(
        cfg: SniperConfig,
        rpc: Arc<RpcClient>,
        rpc_cfg: &RpcConfig,
        prices: Arc<crate::prices::PriceIndex>,
        // From `[tracked]`: the starting buyer threshold. Passed in rather than
        // read from `SniperConfig` because the trigger lives in the tracked
        // section.
    ) -> Result<Self> {
        // max_trade_size_sol == 0 means "no per-trade ceiling" (unlimited).
        // Only enforce the ceiling when one is actually configured.
        if cfg.max_trade_size_sol > 0.0 && cfg.trade_size_sol > cfg.max_trade_size_sol {
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
        let snipe_mode = SnipeMode::parse(&cfg.mode).ok_or_else(|| {
            anyhow::anyhow!(
                "sniper.mode must be \"open\" or \"guard\" (got {:?})",
                cfg.mode
            )
        })?;
        let envelope = Envelope {
            max_trade_size_sol: cfg.max_trade_size_sol,
            daily_cap_sol: cfg.daily_cap_sol,
            max_trades_per_day: cfg.max_trades_per_day,
            slippage_bps: cfg.slippage_bps,
            min_liquidity_sol: cfg.min_liquidity_sol,
            curve_min_liquidity_sol: cfg.curve_min_liquidity_sol,
            max_market_cap_usd: cfg.max_market_cap_usd,
            max_price_impact_bps: cfg.max_price_impact_bps,
        };
        let defaults =
            LiveSettings::from_envelope(&envelope, cfg.trade_size_sol, snipe_mode.key());
        let settings = Arc::new(crate::settings::SettingsStore::load(
            &cfg.settings_path,
            envelope,
            defaults,
        ));
        let routes_path = cfg.sell_routes_path.clone();
        let live = settings.snapshot();
        info!(
            trade_size_sol = live.trade_size_sol,
            slippage_bps = live.slippage_bps,
            min_liquidity_sol = live.min_liquidity_sol,
            snipe_mode = %live.snipe_mode,
            path = %cfg.settings_path,
            "live settings loaded"
        );

        Ok(Self {
            cfg,
            mode,
            prices,
            state: Mutex::new(DailyState::default()),
            settings,
            routes: Arc::new(crate::routes::RouteStore::load(&routes_path)),
            unpriceable: Mutex::new(std::collections::HashSet::new()),
            rugged: Mutex::new(std::collections::HashSet::new()),
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
        // Recovered rather than unwrapped, like every other lock here. A panic
        // anywhere while holding this poisons it, and `.unwrap()` would then
        // panic on every subsequent lock — taking the AUTO-SELL down with the
        // buy path, because both go through this state. Losing the ability to
        // exit is a far worse failure than continuing with the daily counters.
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
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
        // Deliberately does NOT repeat the tunables. Every one of those is a
        // button on this screen, labelled with its own value — printing them
        // again above the buttons is the same information twice, and the copy
        // that cannot be tapped is the one that goes stale first.
        vec![
            ("Mode", if armed { "🔴 ARMED (live)".into() } else { "🧪 dry run".into() }),
            ("Pool cooldown", format!("{}s", c.pool_cooldown_secs)),
            ("Preflight", if c.preflight { "on".into() } else { "OFF".into() }),
            ("Jito bundles", if c.jito_enabled { "on".into() } else { "off".into() }),
        ]
    }

    /// Which entry strategy is active right now.
    pub fn snipe_mode(&self) -> SnipeMode {
        // An unparseable stored mode falls back to the cautious one rather than
        // the fast one: if we cannot tell which strategy is meant, the wrong
        // guess should be the one that buys less.
        SnipeMode::parse(&self.settings.snapshot().snipe_mode).unwrap_or(SnipeMode::Guard)
    }

    /// Where decisions are logged. Read by the Telegram layer to reconstruct
    /// cost basis for a position screen.
    pub fn audit_log_path(&self) -> &str {
        &self.cfg.audit_log
    }

    /// The stream-derived price index, for display.
    pub fn prices(&self) -> &Arc<crate::prices::PriceIndex> {
        &self.prices
    }

    /// Live settings snapshot, for display and for the Telegram layer.
    pub fn live(&self) -> LiveSettings {
        self.settings.snapshot()
    }

    pub fn envelope(&self) -> Envelope {
        self.settings.envelope()
    }

    /// Switch between Open (buy at launch) and Guard (buy only once LP is
    /// secured). Unlike the risk knobs this is not tighten-only in either
    /// direction — it is a strategy choice, and Guard is the safer one.
    pub fn set_snipe_mode(&self, m: SnipeMode) -> String {
        self.settings
            .update(|s| {
                s.snipe_mode = m.key().to_string();
                Ok(format!("snipe mode: {}", m.label()))
            })
            .unwrap_or_else(|e| e)
    }

    /// Set the working trade size from Telegram. Accepts any positive value up
    /// to the configured `max_trade_size_sol`; when that ceiling is 0 the size
    /// is unbounded on the high side. Unlike slippage/min-liquidity this is NOT
    /// tighten-only — it can be raised — so with the ceiling removed the
    /// allowlist is the only guard, and a typo here spends real SOL.
    pub fn set_trade_size(&self, v: f64) -> Result<String, String> {
        if v <= 0.0 || v.is_nan() || v.is_infinite() {
            return Err("trade size must be greater than 0".into());
        }
        let env = self.settings.envelope();
        let ceiling = self.settings.snapshot().effective_max_trade_size(&env);
        if ceiling > 0.0 && v > ceiling {
            return Err(format!(
                "trade size {v} exceeds the {ceiling} SOL per-trade cap. Raise the \
                 cap first (Settings -> Max trade)."
            ));
        }
        self.settings.update(|s| {
            s.trade_size_sol = v;
            Ok(format!("trade size set to {v} SOL"))
        })
    }

    /// Tighten slippage. Refuses any value above the configured `slippage_bps`,
    /// so it can only get stricter (less sandwich exposure), never looser.
    pub fn set_slippage_bps(&self, bps: u16) -> Result<String, String> {
        if bps == 0 {
            return Err("slippage of 0 bps would essentially never fill".into());
        }
        if bps > 5_000 {
            return Err("above 50% slippage a fill is worse than no fill".into());
        }
        self.settings.update(|s| {
            s.slippage_bps = bps;
            Ok(format!("slippage set to {bps} bps"))
        })
    }

    /// Raise the minimum liquidity. Refuses any value below the configured
    /// `min_liquidity_sol`, so it can only become MORE selective, never less.
    pub fn set_min_liquidity(&self, v: f64) -> Result<String, String> {
        if v < 0.0 {
            return Err("minimum liquidity cannot be negative".into());
        }
        self.settings.update(|s| {
            s.min_liquidity_sol = v;
            Ok(format!("minimum liquidity set to {v} SOL"))
        })
    }

    /// Liquidity floor for pump.fun bonding-curve entries.
    ///
    /// Unlike `set_min_liquidity` this is NOT raise-only: 0 is a legitimate
    /// value and the common one. A curve has no LP for a deployer to pull, so
    /// the pool floor's reasoning does not transfer, and applying it would
    /// refuse exactly the early entries the curve path exists to catch.
    pub fn set_curve_min_liquidity(&self, v: f64) -> Result<String, String> {
        if v < 0.0 || !v.is_finite() {
            return Err("curve minimum liquidity must be zero or a positive number".into());
        }
        self.settings.update(|s| {
            s.curve_min_liquidity_sol = v;
            Ok(if v == 0.0 {
                "curve minimum liquidity cleared — no floor on bonding-curve entries".to_string()
            } else {
                format!("curve minimum liquidity set to {v} SOL")
            })
        })
    }

    /// Tighten the per-trade ceiling. `0` clears the local cap and falls back
    /// to the config envelope — it never means "unlimited".
    pub fn set_max_trade_size(&self, v: f64) -> Result<String, String> {
        let hard = self.settings.envelope().max_trade_size_sol;
        if v < 0.0 || v.is_nan() || v.is_infinite() {
            return Err("value must be zero or positive".into());
        }
        self.settings.update(|s| {
            s.max_trade_size_sol = v;
            Ok(describe_cap("max trade size", v, hard, "SOL"))
        })
    }

    /// Tighten the daily spend cap.
    pub fn set_daily_cap(&self, v: f64) -> Result<String, String> {
        let hard = self.settings.envelope().daily_cap_sol;
        if v < 0.0 || v.is_nan() || v.is_infinite() {
            return Err("value must be zero or positive".into());
        }
        self.settings.update(|s| {
            s.daily_cap_sol = v;
            Ok(describe_cap("daily spend cap", v, hard, "SOL"))
        })
    }

    /// Tighten the daily trade count.
    pub fn set_max_trades(&self, v: u32) -> Result<String, String> {
        let hard = self.settings.envelope().max_trades_per_day;
        self.settings.update(|s| {
            s.max_trades_per_day = v;
            Ok(if v == 0 {
                format!("trades/day now follows config ({})", if hard == 0 { "unlimited".into() } else { hard.to_string() })
            } else {
                format!("trades/day capped at {v}")
            })
        })
    }

    /// Tighten the market-cap ceiling for entries.
    pub fn set_max_market_cap(&self, v: f64) -> Result<String, String> {
        let hard = self.settings.envelope().max_market_cap_usd;
        if v < 0.0 || v.is_nan() || v.is_infinite() {
            return Err("value must be zero or positive".into());
        }
        self.settings.update(|s| {
            s.max_market_cap_usd = v;
            Ok(describe_cap("max market cap", v, hard, "USD"))
        })
    }

    /// Tighten the tolerated price impact.
    pub fn set_max_impact_bps(&self, v: u32) -> Result<String, String> {
        let hard = self.settings.envelope().max_price_impact_bps;
        self.settings.update(|s| {
            s.max_price_impact_bps = v;
            Ok(if v == 0 {
                "price impact limit now follows config".to_string()
            } else {
                format!("price impact capped at {v} bps")
            })
        })
    }

    /// Buy a token by mint, with no pool event — the smart-money entry.
    ///
    /// Routed through the quote API rather than a pool we decoded ourselves,
    /// because a conviction signal gives us a MINT and nothing else: no pool,
    /// no venue, no vaults. The asymmetry with selling is deliberate and worth
    /// stating — if the quote API refuses an ENTRY we simply do not trade,
    /// which costs nothing. If it refused an EXIT we would be trapped in a
    /// position, which is why exits go direct first and fall back second.
    ///
    /// The consequence to accept: a position opened this way has no recorded
    /// sell route, so its exit is quote-API-dependent until pool discovery
    /// exists. That is the main reason to keep the size small.
    pub async fn buy_mint(&self, mint: &str, reason: &str) -> BuyOutcome {
        use crate::jupiter::Jupiter;
        use crate::model::WSOL_MINT;

        if !self.cfg.enabled {
            return BuyOutcome::Refused { reason: "sniper disabled".into() };
        }
        if self.kill_switch_engaged() {
            return BuyOutcome::Refused { reason: "kill switch engaged (HALT)".into() };
        }
        // Checked BEFORE any of the paid guards: a token whose liquidity was
        // pulled is not a candidate at any price, and the remaining checks
        // would pass it — they did, once, and it cost a real trade.
        if self.is_rugged(mint) {
            return BuyOutcome::Refused {
                reason: "liquidity pull already observed on this mint".into(),
            };
        }
        let Some(owner) = self.owner() else {
            return BuyOutcome::Refused { reason: "no trading identity".into() };
        };
        let owner = owner.to_string();

        let live = self.settings.snapshot();
        let env = self.settings.envelope();
        let size = live.trade_size_sol;
        let max_size = live.effective_max_trade_size(&env);
        if size <= 0.0 || (max_size > 0.0 && size > max_size) {
            return BuyOutcome::Refused {
                reason: format!("trade size {size} outside the {max_size} ceiling"),
            };
        }

        // Daily limits share the same state the pool path uses, so the two
        // entries cannot each spend a full day's budget.
        let now = Utc::now();
        {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.roll(now);
            let max_trades = live.effective_max_trades(&env);
            if max_trades > 0 && st.trades >= max_trades {
                return BuyOutcome::Refused {
                    reason: format!("daily trade limit reached ({max_trades})"),
                };
            }
            let cap = live.effective_daily_cap(&env);
            if cap > 0.0 && st.spent + size > cap {
                return BuyOutcome::Refused {
                    reason: format!("daily cap reached ({:.3}/{cap} SOL)", st.spent),
                };
            }
        }

        // CAN WE ACTUALLY AFFORD THIS?
        //
        // A buy costs the trade size PLUS rent for the token account it creates
        // (~0.00204 SOL, reclaimed when the position closes) PLUS fees. Without
        // this check the bot builds, simulates and submits a transaction that
        // the System Program then rejects:
        //
        //   Transfer: insufficient lamports 42731585, need 49382715
        //
        // Every one of those costs a fee and produces nothing. They were the
        // single largest failure category in the first live session — 62 of
        // 123 — and read as a confusing `Custom: 1` rather than "out of money".
        //
        // Fails OPEN: an unreadable balance proceeds, because the alternative is
        // an RPC hiccup silently stopping all trading. The chain still refuses
        // an unaffordable trade; this only avoids paying to be told.
        const ATA_RENT_SOL: f64 = 0.00204;
        const FEE_HEADROOM_SOL: f64 = 0.0005;
        let balance = self.rpc.sol_balance(&owner).await;
        let affordable = |size: f64| -> Option<String> {
            let bal = balance?;
            let needed = size + ATA_RENT_SOL + FEE_HEADROOM_SOL;
            (bal < needed).then(|| {
                format!(
                    "insufficient balance: {bal:.6} SOL, need {needed:.6} \
                     ({size} trade + rent + fees)"
                )
            })
        };
        if let Some(reason) = affordable(size) {
            return BuyOutcome::Refused { reason };
        }

        // Mint safety. The pool path has always refused a token whose
        // authorities are live; this path had NO checks at all beyond the caps
        // and the kill switch, so it would buy a mint whose owner can still
        // print supply or freeze the holder's account.
        //
        // The mint read, the quote and the supply read are mutually
        // independent — the market-cap ceiling needs neither the mint read nor
        // the quote to be *issued*, and the quote needs neither read. They ran
        // sequentially only because they were written in that order, which at
        // ~150ms of network RTT apiece cost ~400ms of the critical path for
        // nothing.
        //
        // Concurrency changes how long the decision takes, never what it
        // decides: every result below is still checked, in the same order and
        // with the same precedence, so a refusal reports the reason it always
        // did. The only difference is that a mint which fails safety has now
        // also spent a quote — wasted work on a token we were never going to
        // buy, which is the correct trade for the time saved on ones we do.
        let mut lamports = (size * 1e9) as u64;
        let jup = Jupiter::new(&self.cfg.jupiter_base_url);
        let max_mcap = live.effective_max_market_cap(&env);
        let (mint_info, quote, supply) = tokio::join!(
            self.rpc.mint_info(mint),
            jup.quote(WSOL_MINT, mint, lamports, live.slippage_bps),
            // Fetched when EITHER guard needs it, and not otherwise.
            async {
                if max_mcap > 0.0 {
                    self.rpc.token_supply(mint).await
                } else {
                    None
                }
            },
        );

        // Fails CLOSED, like the pool path: unknown is refused, not trusted.
        // Spending money on a mint we could not verify is not a smaller
        // mistake than spending it on one we verified as bad.
        let decimals = match mint_info {
            Some(info) => {
                if !info.mint_authority_revoked() {
                    return BuyOutcome::Refused { reason: "mint authority still live".into() };
                }
                if !info.freeze_authority_revoked() {
                    return BuyOutcome::Refused { reason: "freeze authority still live".into() };
                }
                if !info.risky_extensions.is_empty() {
                    return BuyOutcome::Refused {
                        reason: format!("token-2022 extensions: {}", info.risky_extensions.join(", ")),
                    };
                }
                info.decimals
            }
            None => {
                return BuyOutcome::Refused { reason: "could not verify the mint".into() };
            }
        };

        // MARKET-CAP BUY BANDS.
        //
        // The size is chosen from the token's valuation rather than being one
        // number for everything: the same SOL buys a very different share of a
        // $20k launch and a $2M token, and carries a very different risk.
        //
        // The first quote is priced at the DEFAULT size purely to learn the
        // market cap — the per-token price barely moves at these sizes, so it
        // is a sound estimate of the valuation whatever size we end up using.
        // If a band selects something different, the quote is redone at that
        // size, because a quote for the wrong amount is not a quote for this
        // trade. One extra round trip, and only when a band actually applies.
        let mut size = size;
        let mut quote = quote;
        if !live.buy_tiers.is_empty()
            && let Ok(q) = &quote
        {
            let tokens_ui = q.out_lamports().unwrap_or(0) as f64 / 10f64.powi(decimals as i32);
            let sol_usd = self.prices.sol_usd(std::time::Duration::from_secs(600));
            let mcap = match (tokens_ui > 0.0).then_some(()).and(sol_usd).zip(supply) {
                Some((sol_usd, sup)) => Some((size / tokens_ui) * sup * sol_usd),
                None => None,
            };
            let tiered = live.size_for_mcap(mcap);
            if (tiered - size).abs() > f64::EPSILON {
                if max_size > 0.0 && tiered > max_size {
                    return BuyOutcome::Refused {
                        reason: format!(
                            "band size {tiered} SOL exceeds the {max_size} SOL ceiling"
                        ),
                    };
                }
                info!(
                    %mint,
                    mcap_usd = mcap.unwrap_or(0.0),
                    from = size,
                    to = tiered,
                    "market-cap band selected a different size"
                );
                // RE-CHECKED against the new size. The affordability test above
                // ran on the DEFAULT size, and a band may select a larger one —
                // passing at 0.2 SOL and then trying to spend 0.75 produces the
                // exact `insufficient lamports` failure that check exists to
                // prevent, at the cost of a fee.
                if let Some(reason) = affordable(tiered) {
                    return BuyOutcome::Refused { reason };
                }
                size = tiered;
                // Reassigned, NOT shadowed: the curve builder below takes
                // `lamports`, and a local binding here would have left it
                // building at the default size while `size` said otherwise.
                lamports = (size * 1e9) as u64;
                quote = jup.quote(WSOL_MINT, mint, lamports, live.slippage_bps).await;
            }
        }

        // Hoisted: both the curve path and the Jupiter path apply this, and
        // the curve path now runs FIRST. `max_mcap` is already bound above,
        // where it gates whether the supply read is issued at all.
        let max_impact = live.effective_max_impact_bps(&env);

        // ORDER MATTERS: the curve is tried BEFORE any Jupiter-derived guard.
        //
        // Price impact is a property of the ROUTE, not of the token. Judging a
        // curve-stage token by Jupiter's routing and refusing it there means a
        // trade we would have made cheaply, directly, never reaches the builder
        // that would have made it — observed as "price impact 2720 bps exceeds
        // 1000" on tokens whose own curve was fine.
        //
        // The curve path applies the SAME limits to its own numbers, so nothing
        // is skipped: a genuinely thin curve is still refused, on the arithmetic
        // that actually describes the trade.
        // ---- DIRECT BONDING CURVE, preferred over Jupiter ----
        //
        // Jupiter costs two API round trips on a lane throttled to 1200ms and
        // shared with the telemetry sweeps; the curve costs one batch of RPC
        // reads and no third-party dependency at all. It is also the only way
        // to reach a token BEFORE it graduates, which is the entry we actually
        // want.
        //
        // Falls back silently to Jupiter when the mint has no live curve —
        // most tokens do not, and a graduated token is a normal Jupiter trade.
        // Both buy and sell are mainnet-simulated; see
        // `execute::pumpfun_sim::live_simulate_pumpfun_buy_and_sell`.
        if let Ok(owner_pk) = crate::tx::pk(&owner) {
            if let Ok(mint_pk) = crate::tx::pk(mint) {
                let curve_floor = live.curve_min_liquidity_sol;
                match crate::execute::build_pumpfun_buy(
                    &self.rpc,
                    &mint_pk,
                    &owner_pk,
                    lamports,
                    live.slippage_bps,
                    curve_floor,
                    self.cfg.compute_unit_limit,
                    self.cfg.priority_fee_micro_lamports,
                )
                .await
                {
                    Ok(plan) => {
                        // The same guards the Jupiter path applies, against the
                        // curve's own numbers. A direct route is not a reason to
                        // check less.
                        let impact = plan.quote.price_impact_bps;
                        if max_impact > 0 && impact > max_impact {
                            return BuyOutcome::Refused {
                                reason: format!(
                                    "curve price impact {impact} bps exceeds {max_impact}"
                                ),
                            };
                        }
                        let tokens_ui =
                            plan.quote.expected_out as f64 / 10f64.powi(decimals as i32);
                        if max_mcap > 0.0 {
                            let sol_usd =
                                self.prices.sol_usd(std::time::Duration::from_secs(600));
                            match (tokens_ui > 0.0).then_some(()).and(sol_usd).zip(supply) {
                                Some((sol_usd, supply)) => {
                                    let mcap = (size / tokens_ui) * supply * sol_usd;
                                    if mcap >= max_mcap {
                                        return BuyOutcome::Refused {
                                            reason: format!(
                                                "market cap ${mcap:.0} at or above ${max_mcap:.0}"
                                            ),
                                        };
                                    }
                                }
                                None => {
                                    return BuyOutcome::Refused {
                                        reason: "market cap unreadable (no SOL price or supply)"
                                            .into(),
                                    };
                                }
                            }
                        }
                        return self
                            .execute_curve_buy(mint, &owner, size, tokens_ui, reason, plan, now)
                            .await;
                    }
                    Err(e) => {
                        info!(%mint, error = %e, "no direct pump.fun curve — routing via Jupiter");
                    }
                }
            }
        }

        let quote = match quote {
            Ok(q) => q,
            Err(e) => {
                return BuyOutcome::Failed { mint: mint.into(), reason: format!("quote: {e:#}") };
            }
        };
        // UI units, matching the curve path. These two used to disagree —
        // Jupiter reported RAW and the curve reported UI — while every consumer
        // divided by decimals regardless. Curve buys were therefore scaled down
        // a second time, which surfaced as an entry market cap of $21.4B on an
        // alert. One meaning, set at the source, is the only version of this
        // that stays correct as consumers are added.
        let tokens_out =
            quote.out_lamports().unwrap_or(0) as f64 / 10f64.powi(decimals as i32);

        // Price impact stands in for depth here. There is no pool to read a
        // reserve from on a routed entry, but a trade that moves the market
        // this much is buying into something too thin to leave.
        let impact_bps = (quote.price_impact_pct() * 100.0) as u32; // percent -> bps
        if max_impact > 0 && impact_bps > max_impact {
            return BuyOutcome::Refused {
                reason: format!("price impact {impact_bps} bps exceeds {max_impact}"),
            };
        }

        // Market-cap ceiling. The pool path has always had this; the smart-money
        // path did not, so it would happily enter something already at $5M —
        // buying the top is exactly what the ceiling exists to prevent.
        //
        // Priced from THIS quote rather than the stream index: the quote is the
        // price we are about to pay, and it exists by definition here, so the
        // check cannot be skipped for want of an observation.
        if max_mcap > 0.0 {
            // Already UI units above.
            let sol_usd = self.prices.sol_usd(std::time::Duration::from_secs(600));
            match (tokens_out > 0.0).then_some(()).and(sol_usd).zip(supply) {
                Some((sol_usd, supply)) => {
                    let price_sol = size / tokens_out;
                    let mcap = price_sol * supply * sol_usd;
                    if mcap >= max_mcap {
                        return BuyOutcome::Refused {
                            reason: format!("market cap ${mcap:.0} at or above ${max_mcap:.0}"),
                        };
                    }
                }
                // Fails CLOSED, as the same gate does on the pool path: an
                // unreadable guard is not a passed guard.
                None => {
                    return BuyOutcome::Refused {
                        reason: "market cap unreadable (no SOL price or supply)".into(),
                    };
                }
            }
        }
        let tx_b64 = match jup.swap_tx(&quote, &owner).await {
            Ok(t) => t,
            Err(e) => {
                return BuyOutcome::Failed {
                    mint: mint.into(),
                    reason: format!("build swap: {e:#}"),
                };
            }
        };

        match &self.mode {
            Mode::DryRun { .. } => {
                let would_succeed = match self.rpc.simulate_transaction(&tx_b64).await {
                    Some(v) => v.get("err").map(|e| e.is_null()).unwrap_or(false),
                    None => false,
                };
                info!(%mint, size, tokens_out, would_succeed, %reason,
                      "sniper: DRY RUN SMART BUY (nothing signed)");
                self.audit_smart_buy(&owner, mint, size, reason,
                    if would_succeed { "would-succeed" } else { "would-FAIL" }).await;
                BuyOutcome::Rehearsed { mint: mint.into(), sol_in: size, tokens_out, would_succeed }
            }
            Mode::Armed(cap) => {
                warn!(%mint, size, tokens_out, %reason, "sniper: SUBMITTING REAL SMART BUY");
                // Reserved BEFORE submitting. Reserving after a confirmation
                // would let a burst of signals each pass the cap check while
                // the first is still in flight.
                self.reserve(mint, size, now);
                let res = self.submitter.send_versioned(&tx_b64, cap.wallet.keypair()).await;
                let (outcome, result) = classify_submission(res);
                self.audit_smart_buy(&owner, mint, size, reason, &outcome).await;
                BuyOutcome::Submitted { mint: mint.into(), sol_in: size, tokens_out, result }
            }
        }
    }

    /// Submit (or rehearse) a bonding-curve buy.
    ///
    /// Separate from the Jupiter branch because the two carry different
    /// payloads: Jupiter hands back a signed-shape versioned transaction, while
    /// this is a list of instructions we assembled ourselves.
    #[cfg(feature = "sniper")]
    async fn execute_curve_buy(
        &self,
        mint: &str,
        owner: &str,
        size: f64,
        tokens_out: f64,
        reason: &str,
        plan: crate::execute::ExecutionPlan,
        now: DateTime<Utc>,
    ) -> BuyOutcome {
        match &self.mode {
            Mode::DryRun { .. } => {
                info!(%mint, size, tokens_out, %reason,
                      "sniper: DRY RUN CURVE BUY (nothing signed)");
                self.audit_smart_buy(owner, mint, size, reason, "would-succeed").await;
                BuyOutcome::Rehearsed {
                    mint: mint.into(),
                    sol_in: size,
                    tokens_out,
                    would_succeed: true,
                }
            }
            Mode::Armed(cap) => {
                warn!(%mint, size, tokens_out, %reason,
                      "sniper: SUBMITTING REAL CURVE BUY (direct, no Jupiter)");
                self.reserve(mint, size, now);
                let res = self
                    .submitter
                    .send(&plan.instructions, &cap.wallet.pubkey(), cap.wallet.keypair())
                    .await;
                let (outcome, result) = classify_submission(res);
                self.audit_smart_buy(owner, mint, size, reason, &outcome).await;
                BuyOutcome::Submitted { mint: mint.into(), sol_in: size, tokens_out, result }
            }
        }
    }

    /// What we would ACTUALLY receive for `raw` units of `mint`, in SOL.
    ///
    /// # Why exits are priced this way and not from the stream index
    ///
    /// The index is a weighted median of recent trades. That is the right
    /// number for describing a token and the wrong number for deciding an exit,
    /// and the gap is not small: a position with a 0.010 SOL basis read as +25%
    /// on the index while a real route returned 0.006875 — down 31%. The ladder
    /// took a "profit" on a position that should have hit its stop.
    ///
    /// Vetoing the sell was the wrong repair. It left the position unmanaged:
    /// no take-profit, and no stop either, on a token that was falling. The
    /// decision was never the broken part — the PRICE was. So the ladder is
    /// given the realizable price and then trusted completely: stops and
    /// targets both fire immediately, in order, with no confirmation step.
    ///
    /// Route preference is the same as the buy path: the bonding curve first,
    /// because it is one RPC read and answers off Jupiter's throttled lane
    /// entirely; the quote API only for tokens that have graduated.
    ///
    /// `None` means no route could price it — which is the same thing as "we
    /// could not sell it either", and is handled as unpriceable rather than as
    /// a signal to sell.
    async fn realizable_sol(&self, mint: &str, raw: u64, decimals: u32) -> Option<f64> {
        if raw == 0 {
            return None;
        }
        if let Ok(mint_pk) = crate::tx::pk(mint) {
            let curve_addr = crate::pumpfun::bonding_curve_pda(&mint_pk).to_string();
            if let Some(data) = self.rpc.account_data(&curve_addr).await
                && let Ok(curve) = crate::pumpfun::BondingCurve::decode(&data)
                && curve.tradable().is_ok()
                && let Ok(q) = crate::pumpfun::sell_quote(&curve, raw, self.cfg.sell_slippage_bps)
            {
                return Some(q.expected_sol as f64 / 1e9);
            }
        }
        let jup = crate::jupiter::Jupiter::new(&self.cfg.jupiter_base_url);
        if let Ok(q) = jup.quote(mint, crate::model::WSOL_MINT, raw, self.cfg.sell_slippage_bps).await
            && let Some(sol) = q.out_sol()
        {
            return Some(sol);
        }

        // QUOTE API DOWN — fall back to the stream, do not go blind.
        //
        // A graduated token has no curve to read, so the quote API is the only
        // exact source. It shares a globally throttled lane with the telemetry
        // sweeps and fails in bursts: 72 failures in one session, and during
        // one of them a live position reported "stopped trading — cannot be
        // priced or sold" for 35 seconds while the operator watched.
        //
        // Reporting a held position as unpriceable is the correct answer when
        // it truly cannot be sold, and a dangerous lie when the quote endpoint
        // is merely busy. The ladder holds either way — so a busy endpoint
        // silently disables the stop-loss on a position that may be falling.
        //
        // The stream index is less exact than a route, which is why it is not
        // the primary source (it once read +25% on a position that was flat).
        // But an approximate price the ladder can act on beats no price at all
        // when the alternative is holding through a drop with no stop.
        let tokens = raw as f64 / 10f64.powi(decimals as i32);
        if tokens > 0.0
            && let Some(p) = self.prices.exit_price_sol(mint, EXIT_PRICE_MAX_AGE)
        {
            let approx = p.price_sol * tokens;
            warn!(
                %mint,
                approx_sol = approx,
                age_secs = p.age.as_secs(),
                "quote API unavailable — pricing this exit from the stream instead"
            );
            return Some(approx);
        }
        None
    }

    async fn audit_smart_buy(&self, owner: &str, mint: &str, sol: f64, reason: &str, outcome: &str) {
        if self.cfg.audit_log.is_empty() {
            return;
        }
        let armed = matches!(self.mode, Mode::Armed(_));
        let record = smart_buy_record(owner, mint, sol, reason, outcome, armed);
        if let Err(e) = append_line(&self.cfg.audit_log, &record).await {
            warn!(error = %e, "failed to write smart buy audit");
        }
    }

    /// Bring a position back under the supply-share ceiling, if it is over.
    ///
    /// # Why this runs after the fill and not before it
    ///
    /// A quote is a prediction; a fill is a fact. Sizing the buy down from a
    /// quote leaves the position wherever the fill actually landed, which is
    /// the number that matters. So the buy executes at its configured size,
    /// untouched, and this measures what was really received.
    ///
    /// Sells ONLY the excess. A position at or under the ceiling is left alone,
    /// and one over it is trimmed to the ceiling rather than closed — the
    /// position is not the problem, its size is.
    ///
    /// Called twice by design: once right after a buy confirms, and again on
    /// every reconciliation sweep. The second is a fallback, because a missed
    /// post-trade check would otherwise leave an unexitable position sitting
    /// there with nothing to notice it.
    ///
    /// Returns `Some(pct_sold)` if it acted.
    pub async fn enforce_supply_cap(
        &self,
        mint: &str,
        alerter: &crate::alerts::Alerter,
    ) -> Option<u8> {
        let live = self.settings.snapshot();
        if !live.supply_cap || live.max_supply_pct <= 0.0 {
            return None;
        }
        let owner = self.owner()?.to_string();
        let (raw, decimals) = self.rpc.token_balance_raw(&owner, mint).await?;
        if raw == 0 {
            return None;
        }
        let supply_ui = self.rpc.token_supply(mint).await?;
        if supply_ui <= 0.0 {
            return None;
        }
        let held_ui = raw as f64 / 10f64.powi(decimals as i32);
        let cap_ui = supply_ui * live.max_supply_pct / 100.0;
        if held_ui <= cap_ui {
            return None;
        }
        // Percent OF THE CURRENT HOLDING to shed, which is what `sell` takes.
        // Rounded UP so a rounding error cannot leave the position
        // fractionally over the ceiling on every future sweep.
        let excess =
            ((held_ui - cap_ui) / held_ui * 100.0).ceil().clamp(1.0, 100.0) as u8;
        let share = 100.0 * held_ui / supply_ui;
        warn!(
            %mint, share_pct = share, max = live.max_supply_pct, sell_pct = excess,
            "position over the supply ceiling — trimming the excess"
        );
        let outcome = self.sell(mint, excess).await;
        info!(%mint, ?outcome, "supply-ceiling trim");
        if let Some(msg) = crate::alerts::render_auto_sell(
            mint,
            excess,
            &format!(
                "supply ceiling: holding {share:.2}% of supply, max {}%",
                live.max_supply_pct
            ),
            &outcome,
        ) {
            alerter.send_html(msg).await;
        }
        Some(excess)
    }

    /// One pass of the exit policy over every position the bot opened.
    ///
    /// Returns (considered, sold). Deliberately sequential and one action per
    /// position per pass: selling is the irreversible half of trading, and a
    /// burst of concurrent sells on a bad price tick is exactly the failure
    /// this is meant to prevent rather than cause.
    pub async fn sweep_exits(
        &self,
        state: &Arc<crate::exits::ExitStateStore>,
        alerter: &crate::alerts::Alerter,
    ) -> (usize, usize) {
        let rules = self.settings.snapshot().exits;
        if !rules.enabled || self.kill_switch_engaged() {
            return (0, 0);
        }
        let Some(owner) = self.owner() else { return (0, 0) };
        let owner = owner.to_string();

        // Cost basis counts only buys that truly moved funds, so a dry-run
        // rehearsal never produces a position the ladder would act on.
        // Cost basis counts only buys that truly moved funds, so a dry-run
        // rehearsal never produces a position the ladder would act on.
        let audit = tokio::fs::read_to_string(&self.cfg.audit_log).await.unwrap_or_default();
        let basis = crate::positions::cost_basis_from_audit(&audit);

        // Gather first, decide second. The decision is a pure function so the
        // JOIN — audit record to position to ladder — can be tested; that join
        // silently produced an empty list for smart-money buys, and no amount
        // of testing the rules alone would have found it.
        // Balances read concurrently. They are independent RPC round trips at
        // ~150ms of network RTT each, and doing them one at a time put the
        // whole position list behind the slowest link before the ladder had
        // even been consulted.
        let owner_ref = owner.as_str();
        let reads = basis.into_iter().map(|(mint, cost)| async move {
            let (raw, decimals) = self.rpc.token_balance_raw(owner_ref, &mint).await?;
            Some((mint, cost, raw, decimals))
        });
        let read = futures::future::join_all(reads).await;

        let mut holdings = Vec::new();
        for (mint, cost, raw, decimals) in read.into_iter().flatten() {
            // The price we would REALIZE, not the market's median. See
            // `realizable_sol`. Expressed per whole token so the ladder's
            // arithmetic is unchanged: multiple = price * tokens / sol_spent
            // reduces exactly to realizable / sol_spent.
            let tokens = raw as f64 / 10f64.powi(decimals as i32);
            let price_sol = match self.realizable_sol(&mint, raw, decimals as u32).await {
                Some(sol) if tokens > 0.0 => Some(sol / tokens),
                _ => None,
            };
            holdings.push(crate::exits::Holding {
                mint,
                sol_spent: cost.sol_spent,
                raw,
                decimals: decimals as u32,
                price_sol,
            });
        }
        // A held position with no price has stopped trading where we can see
        // it — the shape a rug takes from here. It is NOT sold: unpriceable
        // means we could not sell it either, and treating "no price" as "sell"
        // is the confusion that has already cost this project a dataset. But
        // the operator is told once, because it is the moment to look.
        for h in holdings.iter().filter(|h| h.raw > 0 && h.price_sol.is_none()) {
            let first_time = {
                let mut seen = self.unpriceable.lock().unwrap_or_else(|p| p.into_inner());
                seen.insert(h.mint.clone())
            };
            if first_time {
                warn!(mint = %h.mint, "held position has stopped trading — cannot be priced or sold");
                if let Some(msg) = crate::alerts::render_unpriceable(&h.mint) {
                    alerter.send_html(msg).await;
                }
            }
        }
        {
            // Forget the ones that recovered, so a later stall alerts again.
            let mut seen = self.unpriceable.lock().unwrap_or_else(|p| p.into_inner());
            seen.retain(|m| holdings.iter().any(|h| &h.mint == m && h.price_sol.is_none()));
        }

        let considered = holdings.iter().filter(|h| h.raw > 0).count();

        // SUPPLY-SHARE CEILING, enforced on the POSITION rather than the buy.
        //
        // Sizing the buy down is a best effort: it works off a quote, and the
        // fill can differ. This is the part that actually holds the line —
        // whatever the position ended up being, and however it got there, a
        // holding over the ceiling is trimmed back to it.
        //
        // It runs BEFORE the ladder and returns immediately, because a position
        // that is too large to exit is a more urgent problem than any target,
        // and selling the excess makes the remainder exitable.
        let max_supply_pct = self.settings.snapshot().max_supply_pct;
        if max_supply_pct > 0.0 {
            for h in holdings.iter().filter(|h| h.raw > 0) {
                let Some(supply_ui) = self.rpc.token_supply(&h.mint).await else { continue };
                if supply_ui <= 0.0 {
                    continue;
                }
                let held_ui = h.raw as f64 / 10f64.powi(h.decimals as i32);
                let cap_ui = supply_ui * max_supply_pct / 100.0;
                if held_ui <= cap_ui {
                    continue;
                }
                // Percent OF THE CURRENT HOLDING to shed, which is what `sell`
                // takes. Rounded up so a rounding error cannot leave the
                // position fractionally over the ceiling forever.
                let excess = ((held_ui - cap_ui) / held_ui * 100.0).ceil().clamp(1.0, 100.0) as u8;
                let share = 100.0 * held_ui / supply_ui;
                warn!(
                    mint = %h.mint, share_pct = share, max_supply_pct, sell_pct = excess,
                    "position exceeds the supply ceiling — trimming"
                );
                let outcome = self.sell(&h.mint, excess).await;
                info!(mint = %h.mint, ?outcome, "supply-ceiling trim result");
                if let Some(msg) = crate::alerts::render_auto_sell(
                    &h.mint,
                    excess,
                    &format!("supply ceiling: {share:.2}% of supply, max {max_supply_pct}%"),
                    &outcome,
                ) {
                    alerter.send_html(msg).await;
                }
                return (considered, 1);
            }
        }

        // Room for the fill to land, derived from the configured sell slippage
        // rather than being another knob. Capped: at a 15% tolerance an
        // uncapped buffer would put "break-even" at +15%, which is a target,
        // not a break-even. Floored so a very tight slippage setting still
        // leaves the rule able to return the capital.
        let breakeven_buffer =
            (self.cfg.sell_slippage_bps as f64 / 10_000.0).clamp(0.01, 0.03);
        let (sells, closed) =
            crate::exits::plan_exits(&rules, state, &holdings, breakeven_buffer);
        for mint in closed {
            state.forget(&mint);
        }

        let mut sold = 0usize;
        for s in sells {
            warn!(mint = %s.mint, pct = s.pct_of_current, reason = %s.reason, "auto-sell firing");
            let outcome = self.sell(&s.mint, s.pct_of_current).await;
            info!(mint = %s.mint, ?outcome, "auto-sell result");

            // A sell that did not happen must not leave its trigger disarmed.
            // See `ExitStateStore::unfire`: without this a stop-loss rejected
            // once — for slippage, for a moment of low SOL — never protects
            // that position again.
            let landed = matches!(
                &outcome,
                SellOutcome::Submitted { result: SubmitOutcome::Executed { .. }, .. }
            );
            if !landed && let Some(t) = s.trigger {
                warn!(
                    mint = %s.mint, trigger = t,
                    "sell did not land — re-arming the trigger for the next sweep"
                );
                state.unfire(&s.mint, t);
            }
            // Announced whether it worked or not: an operator must be able to
            // tell "the ladder never fired" from "it fired and failed".
            if let Some(msg) =
                crate::alerts::render_auto_sell(&s.mint, s.pct_of_current, &s.reason, &outcome)
            {
                alerter.send_html(msg).await;
            }
            sold += 1;
        }

        // Reconciliation fallback for the supply ceiling. Runs AFTER the ladder,
        // and this ordering is load-bearing rather than cosmetic.
        //
        // `plan_exits` sizes each sell against the balance it SAW. Trimming
        // first changes that balance underneath the plan, so a partial rung
        // computed as "20% of the original position" would then be applied to
        // what survived the trim — selling far more of the position than the
        // ladder intended. The two must not interleave.
        //
        // It is also the right precedence: a stop-loss is more urgent than a
        // size ceiling, and the post-buy check is the primary enforcement
        // anyway. This only catches what that missed.
        if self.settings.snapshot().supply_cap {
            for h in holdings.iter().filter(|h| h.raw > 0) {
                if self.enforce_supply_cap(&h.mint, alerter).await.is_some() {
                    sold += 1;
                }
            }
        }
        (considered, sold)
    }

    /// Record a mint whose liquidity was pulled. Called by the watcher.
    pub fn mark_rugged(&self, mint: &str) {
        let mut set = self.rugged.lock().unwrap_or_else(|p| p.into_inner());
        if set.insert(mint.to_string()) {
            warn!(%mint, "mint blacklisted for buying — liquidity pull observed");
        }
    }

    /// Has this mint been seen rugging?
    pub fn is_rugged(&self, mint: &str) -> bool {
        self.rugged.lock().unwrap_or_else(|p| p.into_inner()).contains(mint)
    }

    /// The single stop loss, as a negative percentage. 0 clears it.
    pub fn set_stop_loss(&self, pct: i32) -> Result<String, String> {
        if pct > 0 || pct <= -100 {
            return Err("a stop must be between -1% and -99%".into());
        }
        self.settings.update(|s| {
            s.exits.set_stop(pct);
            Ok(if pct == 0 {
                "stop loss removed — nothing closes a losing position".to_string()
            } else {
                format!("stop loss set to {pct}%")
            })
        })
    }

    /// The single take-profit trigger, keeping its current sell amount.
    pub fn set_take_profit(&self, pct: i32) -> Result<String, String> {
        if pct < 0 {
            return Err("a target must be positive".into());
        }
        self.settings.update(|s| {
            let (_, amt) = s.exits.target();
            let amt = if amt == 0 { 100 } else { amt };
            s.exits.set_target(pct, amt);
            Ok(if pct == 0 {
                "take profit removed".to_string()
            } else {
                format!("take profit set to +{pct}% (sell {amt}%)")
            })
        })
    }

    /// How much of the position the take-profit sells.
    pub fn set_take_profit_amount(&self, amount: u8) -> Result<String, String> {
        if !(1..=100).contains(&amount) {
            return Err("amount must be between 1% and 100%".into());
        }
        self.settings.update(|s| {
            let (pct, _) = s.exits.target();
            if pct == 0 {
                return Err("set a take-profit trigger first".to_string());
            }
            s.exits.set_target(pct, amount);
            Ok(format!("take profit sells {amount}% at +{pct}%"))
        })
    }

    /// Add a market-cap band. Refuses one that overlaps an existing band.
    pub fn add_buy_tier(&self, min_usd: f64, max_usd: f64, sol: f64) -> Result<String, String> {
        let tier = crate::settings::BuyTier { min_usd, max_usd, sol };
        let label = crate::settings::describe_tier(&tier);
        self.settings.update(|s| {
            s.add_tier(tier)?;
            Ok(format!("{label} → {sol} SOL"))
        })
    }

    /// Remove the band at `idx` in the sorted list.
    pub fn remove_buy_tier(&self, idx: usize) -> Result<String, String> {
        self.settings.update(|s| {
            if idx >= s.buy_tiers.len() {
                return Err("no such band".to_string());
            }
            let t = s.buy_tiers.remove(idx);
            Ok(format!("removed {}", crate::settings::describe_tier(&t)))
        })
    }

    /// Clear every band; the default size applies to everything again.
    pub fn clear_buy_tiers(&self) -> Result<String, String> {
        self.settings.update(|s| {
            let n = s.buy_tiers.len();
            s.buy_tiers.clear();
            Ok(format!("cleared {n} band(s) — the default size applies to every token"))
        })
    }

    /// Turn the supply-share ceiling on or off, keeping the tuned percentage.
    pub fn toggle_supply_cap(&self) -> Result<String, String> {
        self.settings.update(|s| {
            s.supply_cap = !s.supply_cap;
            Ok(if s.supply_cap {
                if s.max_supply_pct > 0.0 {
                    format!("supply ceiling ON — positions trimmed to {}% of supply", s.max_supply_pct)
                } else {
                    "supply ceiling ON — set a percentage for it to act on".to_string()
                }
            } else {
                "supply ceiling off".to_string()
            })
        })
    }

    /// Most of a token's supply one position may hold, as a percent. 0 = off.
    pub fn set_max_supply_pct(&self, v: f64) -> Result<String, String> {
        if v < 0.0 || v > 100.0 || !v.is_finite() {
            return Err("share must be between 0% and 100%".into());
        }
        self.settings.update(|s| {
            s.max_supply_pct = v;
            Ok(if v == 0.0 {
                "supply-share limit removed".to_string()
            } else {
                format!("positions capped at {v}% of a token's supply")
            })
        })
    }

    /// Turn break-even on or off.
    ///
    /// A toggle, not a level: the rule is "it went up, it came back to cost,
    /// get out flat", which has nothing to configure.
    pub fn toggle_breakeven(&self) -> Result<String, String> {
        self.settings.update(|s| {
            s.exits.breakeven = !s.exits.breakeven;
            Ok(if s.exits.breakeven {
                "break-even ON — a position that returns to cost is closed flat".to_string()
            } else {
                "break-even off".to_string()
            })
        })
    }

    /// Turn volume confirmation on or off.
    ///
    /// A real bypass, not "thresholds at zero": switching it off cannot leave a
    /// stray threshold quietly filtering entries.
    pub fn toggle_volume_mode(&self) -> Result<String, String> {
        self.settings.update(|s| {
            s.volume_mode = !s.volume_mode;
            Ok(if s.volume_mode {
                "volume confirmation ON — smart money must be corroborated by volume".into()
            } else {
                "volume confirmation OFF — wallet count alone decides".to_string()
            })
        })
    }

    /// SOL the tracked cohort must have put in. 0 = not required.
    pub fn set_min_smart_sol_in(&self, v: f64) -> Result<String, String> {
        if v < 0.0 || !v.is_finite() {
            return Err("value must be zero or a positive number".into());
        }
        self.settings.update(|s| {
            s.min_smart_sol_in = v;
            Ok(if v == 0.0 {
                "smart-money inflow no longer required".to_string()
            } else {
                format!("smart-money inflow must reach {v} SOL")
            })
        })
    }

    /// Observed SOL traded in the token. 0 = not required.
    pub fn set_min_token_volume(&self, v: f64) -> Result<String, String> {
        if v < 0.0 || !v.is_finite() {
            return Err("value must be zero or a positive number".into());
        }
        self.settings.update(|s| {
            s.min_token_volume_sol = v;
            Ok(if v == 0.0 {
                "token volume no longer required".to_string()
            } else {
                format!("token volume must reach {v} SOL")
            })
        })
    }

    /// Turn smart-money auto-buy on or off.
    ///
    /// Refuses to enable what the host has not permitted. Config grants the
    /// capability; this is only the switch — otherwise a compromised Telegram
    /// account could start the bot spending on a trigger nobody authorised.
    pub fn toggle_auto_buy(&self) -> Result<String, String> {
        let env = self.settings.envelope();
        self.settings.update(|s| {
            s.auto_buy = !s.auto_buy;
            Ok(if s.auto_buy {
                if s.min_smart_sol_in > 0.0 {
                    format!("auto-buy ON — triggers at {} SOL of tracked buying", s.min_smart_sol_in)
                } else {
                    "auto-buy ON — set a smart-SOL threshold for it to fire".to_string()
                }
            } else {
                "auto-buy OFF — signals still alert, nothing is bought".to_string()
            })
        })
    }

    /// How many distinct tracked wallets must buy before we do.
    /// Turn the whole exit policy on or off.
    pub fn toggle_exits(&self) -> Result<String, String> {
        self.settings.update(|s| {
            s.exits.enabled = !s.exits.enabled;
            Ok(if s.exits.enabled {
                format!("auto-sell ON — {}", crate::exits::describe(&s.exits))
            } else {
                "auto-sell OFF — positions are yours to close".to_string()
            })
        })
    }

    /// Add an empty order for the operator to configure.
    pub fn add_order(&self) -> Result<String, String> {
        self.settings.update(|s| {
            if s.exits.orders.len() >= crate::exits::MAX_ORDERS {
                return Err(format!("at most {} orders", crate::exits::MAX_ORDERS));
            }
            // Added disarmed: an order that started live would begin selling on
            // a trigger nobody chose.
            s.exits.orders.push(crate::exits::SellOrder { at_pct: 0, amount_pct: 0 });
            Ok(format!("order {} added — set its trigger", s.exits.orders.len()))
        })
    }

    pub fn remove_order(&self, idx: usize) -> Result<String, String> {
        self.settings.update(|s| {
            if idx >= s.exits.orders.len() {
                return Err("no such order".into());
            }
            let gone = s.exits.orders.remove(idx);
            Ok(format!("removed {}", gone.label()))
        })
    }

    /// Set an order's trigger, as a percent move from cost. Negative is a stop.
    pub fn set_order_trigger(&self, idx: usize, at_pct: i32) -> Result<String, String> {
        if !(-99..=100_000).contains(&at_pct) {
            return Err("trigger must be between -99% and +100000%".into());
        }
        self.settings.update(|s| {
            let Some(o) = s.exits.orders.get_mut(idx) else { return Err("no such order".into()) };
            o.at_pct = at_pct;
            Ok(if at_pct == 0 {
                format!("order {} off", idx + 1)
            } else if at_pct < 0 {
                format!("order {} is a stop at {at_pct}%", idx + 1)
            } else {
                format!("order {} targets +{at_pct}%", idx + 1)
            })
        })
    }

    /// Set how much of the ORIGINAL position an order sells.
    pub fn set_order_amount(&self, idx: usize, amount_pct: u8) -> Result<String, String> {
        if amount_pct > 100 {
            return Err("amount cannot exceed 100%".into());
        }
        self.settings.update(|s| {
            let Some(o) = s.exits.orders.get_mut(idx) else { return Err("no such order".into()) };
            o.amount_pct = amount_pct;
            let total = s.exits.target_total_pct();
            Ok(if amount_pct == 0 {
                format!("order {} off", idx + 1)
            } else if total > 100 {
                // Said plainly rather than refused: over-allocating is a real
                // choice, it just means later orders find less than they asked.
                format!("order {} sells {amount_pct}% — targets now total {total}%", idx + 1)
            } else {
                format!("order {} sells {amount_pct}% of the original position", idx + 1)
            })
        })
    }

    pub fn set_trailing(&self, pct: u8) -> Result<String, String> {
        if pct >= 100 {
            return Err("a 100% trailing stop would never trigger".into());
        }
        self.settings.update(|s| {
            s.exits.trailing_pct = pct;
            Ok(if pct == 0 { "trailing stop off".into() } else { format!("trailing stop at -{pct}% from peak") })
        })
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
        let tuned = self.settings.snapshot();
        let env = self.settings.envelope();

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
        //
        // Fail CLOSED: a buy requires positive proof each authority is revoked.
        // Unknown (None — [safety] disabled or the mint read failed) is refused,
        // not trusted. This is deliberately stricter than the alert path, which
        // may emit on unknown: alerting on a maybe-risky pool is cheap, buying
        // one is not. So "require fully clean mint" needs [safety].enabled = true
        // (otherwise these stay None and every trade is refused here).
        match ev.mint_authority_revoked {
            Some(true) => {}
            Some(false) => return Err(Denial::UnsafeMint { reason: "mint authority live".into() }),
            None => return Err(Denial::UnsafeMint {
                reason: "mint authority unverified (enable [safety])".into(),
            }),
        }
        match ev.freeze_authority_revoked {
            Some(true) => {}
            Some(false) => return Err(Denial::UnsafeMint { reason: "freeze authority live".into() }),
            None => return Err(Denial::UnsafeMint {
                reason: "freeze authority unverified (enable [safety])".into(),
            }),
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

        // Caps are the TIGHTER of the config envelope and whatever the operator
        // set from Telegram, so a limit narrowed by command genuinely binds.
        let max_size = tuned.effective_max_trade_size(&env);
        let daily_cap = tuned.effective_daily_cap(&env);
        let max_trades = tuned.effective_max_trades(&env);

        let size = tuned.trade_size_sol;
        if size <= 0.0 {
            return Err(Denial::TradeSizeExceedsMax { size, max: max_size });
        }
        if max_size > 0.0 && size > max_size {
            return Err(Denial::TradeSizeExceedsMax { size, max: max_size });
        }

        // Daily limits and per-pool cooldown share one lock: they are checked
        // against the same state that `reserve` mutates.
        {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            st.roll(now);
            if let Some(seconds_remaining) =
                st.cooling_down(&ev.pool, now, self.cfg.pool_cooldown_secs)
            {
                return Err(Denial::PoolCoolingDown { seconds_remaining });
            }
            // 0 means neither tier set this limit, and that is genuinely
            // uncapped — the operator is told so plainly by /caps rather than
            // being given a reassuring default that does not exist.
            if max_trades > 0 && st.trades >= max_trades {
                return Err(Denial::DailyTradeCountReached { count: st.trades, max: max_trades });
            }
            if daily_cap > 0.0 && st.spent + size > daily_cap {
                return Err(Denial::DailyCapReached { spent: st.spent, cap: daily_cap });
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

        // MARKET CAP CEILING. Checked here, after every cheap gate has already
        // passed, so the extra reads are only spent on a pool we are otherwise
        // about to buy.
        //
        // FAILS CLOSED. This used to proceed when the market cap was
        // unreadable, on the reasoning that the other guards still applied and
        // failing closed would halt trading whenever the price source was
        // down. That was wrong, and it went wrong in exactly the predicted
        // way: the price source WAS blocked for hours, and this guard — added
        // after buying a high-market-cap rug — was silently inert the whole
        // time. Nothing said so.
        //
        // A display field may degrade. A guard may not: "I could not check"
        // must never read as "the check passed". Refusing costs a missed
        // trade; proceeding costs the exact loss the ceiling exists to stop.
        if self.cfg.max_market_cap_usd > 0.0 {
            match self.event_market_cap_usd(ev).await {
                Some(mcap) if mcap >= self.cfg.max_market_cap_usd => {
                    let d = Denial::MarketCapTooHigh {
                        mcap_usd: mcap,
                        max_usd: self.cfg.max_market_cap_usd,
                    };
                    info!(
                        pool = %ev.pool,
                        mcap_usd = mcap,
                        max_usd = self.cfg.max_market_cap_usd,
                        "sniper: skipped — market cap too high (already-run token)"
                    );
                    self.audit(ev, Some(&plan), Some(&d), None).await;
                    return Execution::Skipped {
                        pool: ev.pool.clone(),
                        reason: d.label().to_string(),
                    };
                }
                Some(mcap) => info!(pool = %ev.pool, mcap_usd = mcap, "market cap within ceiling"),
                None => {
                    let d = Denial::MarketCapUnreadable;
                    warn!(
                        pool = %ev.pool,
                        "sniper: skipped — market cap unreadable, refusing rather than \
                         trading with the ceiling disabled"
                    );
                    self.audit(ev, Some(&plan), Some(&d), None).await;
                    return Execution::Skipped {
                        pool: ev.pool.clone(),
                        reason: d.label().to_string(),
                    };
                }
            }
        }

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

        // Record the exit BEFORE anything is submitted. Written here rather
        // than after a confirmed fill because a crash between submit and
        // confirm would otherwise leave a position on chain with no recorded
        // way out — and PumpSwap's `pool_v2` cannot be recovered afterwards.
        self.routes.remember(ev);

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

    /// Sell a held token back to SOL via Jupiter — the manual EXIT behind a
    /// `/positions` "Sell N%" button. `pct` is 1..=100 of the CURRENT on-chain
    /// balance of `mint`. Gated exactly like a buy: HALT stops it, and a dry run
    /// only quotes + simulates (reporting what you WOULD receive) while an armed
    /// bot signs and submits. Selling converts token->SOL inside the SAME wallet
    /// — it never sends funds anywhere, which is why it is allowed where a
    /// withdraw is not.
    #[cfg(feature = "sniper")]
    pub async fn sell(&self, mint: &str, pct: u8) -> SellOutcome {
        use crate::jupiter::{Jupiter, fraction_of};
        use crate::model::WSOL_MINT;

        if self.kill_switch_engaged() {
            return SellOutcome::Refused {
                reason: "kill switch engaged (HALT) — resume to sell".into(),
            };
        }
        if !(1..=100).contains(&pct) {
            return SellOutcome::Refused {
                reason: "sell percentage must be between 1 and 100".into(),
            };
        }
        let Some(owner) = self.owner() else {
            return SellOutcome::Refused {
                reason: "no trading identity — set an active wallet".into(),
            };
        };
        let owner = owner.to_string();

        // Exact on-chain balance in base units; "sell 50%" is integer math on it.
        let Some((balance, _decimals)) = self.rpc.token_balance_raw(&owner, mint).await else {
            return SellOutcome::NoPosition { mint: mint.to_string() };
        };
        let amount = fraction_of(balance, pct);
        if amount == 0 {
            return SellOutcome::Refused { reason: "computed sell amount is zero".into() };
        }

        // Direct first. Jupiter is the fallback, not the plan: it has
        // IP-blocked this box repeatedly, and an exit that only works while a
        // third party tolerates us is not an exit. Falling back is still right
        // for venues we cannot encode and for tokens we did not buy ourselves.
        if let Some(route) = self.routes.get(mint) {
            match self.sell_direct(&route, &owner, mint, pct, amount).await {
                Ok(outcome) => return outcome,
                Err(e) => warn!(
                    %mint,
                    error = %format!("{e:#}"),
                    "direct sell unavailable; falling back to the quote API"
                ),
            }
        }

        let jup = Jupiter::new(&self.cfg.jupiter_base_url);
        let quote = match jup.quote(mint, WSOL_MINT, amount, self.cfg.sell_slippage_bps).await {
            Ok(q) => q,
            Err(e) => {
                return SellOutcome::Failed { mint: mint.to_string(), reason: format!("quote: {e:#}") };
            }
        };
        let sol_out = quote.out_sol().unwrap_or(0.0);
        let impact_pct = quote.price_impact_pct();


        let tx_b64 = match jup.swap_tx(&quote, &owner).await {
            Ok(t) => t,
            Err(e) => {
                return SellOutcome::Failed {
                    mint: mint.to_string(),
                    reason: format!("build swap: {e:#}"),
                };
            }
        };

        match &self.mode {
            Mode::DryRun { .. } => {
                // Simulate the real swap against live state; nothing is signed.
                let would_succeed = match self.rpc.simulate_transaction(&tx_b64).await {
                    Some(v) => v.get("err").map(|e| e.is_null()).unwrap_or(false),
                    None => false,
                };
                info!(%mint, pct, sol_out, impact_pct, would_succeed, "sniper: DRY RUN SELL (nothing signed)");
                self.audit_sell(
                    &owner,
                    mint,
                    pct,
                    sol_out,
                    if would_succeed { "would-succeed" } else { "would-FAIL" },
                )
                .await;
                SellOutcome::Rehearsed { mint: mint.to_string(), pct, sol_out, impact_pct, would_succeed }
            }
            Mode::Armed(cap) => {
                warn!(%mint, pct, sol_out, "sniper: SUBMITTING REAL SELL");
                let res = self.submitter.send_versioned(&tx_b64, cap.wallet.keypair()).await;
                let (outcome, result) = classify_submission(res);
                self.audit_sell(&owner, mint, pct, sol_out, &outcome).await;
                SellOutcome::Submitted { mint: mint.to_string(), pct, sol_out, result }
            }
        }
    }

    /// Sell through the pool we bought from, with no third party involved.
    ///
    /// Returns `Err` when this venue or route cannot be encoded, so the caller
    /// can fall back rather than leaving the operator holding a position. An
    /// error here is "we could not build it", never "the sell failed" — a
    /// submitted-and-failed sell returns `Ok(SellOutcome::Failed)` so it is
    /// audited once and not retried down a second path.
    #[cfg(feature = "sniper")]
    async fn sell_direct(
        &self,
        route: &PoolEvent,
        owner: &str,
        mint: &str,
        pct: u8,
        amount: u64,
    ) -> Result<SellOutcome> {
        let owner_pk = crate::tx::pk(owner)?;
        let plan = crate::execute::build_sell(
            &self.rpc,
            route,
            &owner_pk,
            amount,
            self.cfg.sell_slippage_bps,
            self.cfg.compute_unit_limit,
            self.cfg.priority_fee_micro_lamports,
        )
        .await?;

        let sol_out = plan.quote.expected_out as f64 / 1e9;
        let venue = plan.venue.label();

        Ok(match &self.mode {
            Mode::DryRun { .. } => {
                info!(%mint, pct, sol_out, venue, "sniper: DRY RUN DIRECT SELL (nothing signed)");
                self.audit_sell(owner, mint, pct, sol_out, "would-succeed:direct").await;
                SellOutcome::Rehearsed {
                    mint: mint.to_string(),
                    pct,
                    sol_out,
                    // Impact is already priced into `minimum_out` by the quote;
                    // reporting a separate figure we did not compute would be
                    // inventing one.
                    impact_pct: 0.0,
                    would_succeed: true,
                }
            }
            Mode::Armed(cap) => {
                warn!(%mint, pct, sol_out, venue, "sniper: SUBMITTING REAL DIRECT SELL");
                let res = self
                    .submitter
                    .send(&plan.instructions, &cap.wallet.pubkey(), cap.wallet.keypair())
                    .await;
                let (outcome, result) = classify_submission(res);
                self.audit_sell(owner, mint, pct, sol_out, &format!("{outcome}:direct")).await;
                SellOutcome::Submitted { mint: mint.to_string(), pct, sol_out, result }
            }
        })
    }

    /// SOL price in USD, from the stream-derived index.
    ///
    /// No external API: the previous source was IP-blocked for hours, which —
    /// while this gate still failed open — silently disabled the market-cap
    /// ceiling. A price we derive from our own feed cannot be rate limited.
    #[cfg(feature = "sniper")]
    async fn sol_price_usd(&self) -> Option<f64> {
        self.prices.sol_usd(std::time::Duration::from_secs(300))
    }

    /// Fully-diluted market cap of the launched token, in USD.
    /// Costs two RPC reads plus (at most, once per 5 min) one Jupiter quote.
    #[cfg(feature = "sniper")]
    async fn event_market_cap_usd(&self, ev: &PoolEvent) -> Option<f64> {
        let quote_reserve = ev.quote_liquidity?;
        let base_vault = ev.base_vault.as_deref()?;
        let mint = ev.new_token_mint.as_deref()?;
        let base_reserve = self.rpc.vault_balance(base_vault).await?;
        let supply = self.rpc.token_supply(mint).await?;
        let sol_usd = self.sol_price_usd().await?;
        market_cap_usd(quote_reserve, base_reserve, supply, sol_usd)
    }

    /// Move SOL OUT of the trading wallet to an arbitrary address.
    ///
    /// This is a fund-EXFILTRATION primitive, so it carries the strictest gates
    /// in the bot: it works ONLY when armed (the signing key exists in memory
    /// solely in `Mode::Armed`, so a dry-run bot — or a leaked token on one —
    /// simply has no key to sign with), and it is HALT-gated. The caller (the
    /// bot) additionally requires a two-tap confirmation before reaching here.
    ///
    /// `from_keypair` selects which wallet to send FROM: `Some(path)` loads that
    /// wallet from the store, `None` uses the armed trading wallet.
    ///
    /// Loading an arbitrary store wallet deliberately bypasses the armed-only
    /// gate. That gate stopped being meaningful once `/export` could reveal any
    /// store wallet's private key: export grants permanent, irrevocable control,
    /// which strictly dominates a single withdrawal, so gating withdraw more
    /// tightly than export would be security theatre. HALT still applies.
    #[cfg(feature = "sniper")]
    pub async fn withdraw(
        &self,
        dest: &str,
        sol: f64,
        from_keypair: Option<&str>,
    ) -> WithdrawOutcome {
        use crate::tx::pk;

        if self.kill_switch_engaged() {
            return WithdrawOutcome::Refused {
                reason: "kill switch engaged (HALT) — resume to withdraw".into(),
            };
        }
        // Borrowed from either the loaded file or the armed capability.
        let loaded;
        let wallet: &Wallet = match from_keypair {
            Some(path) => match Wallet::load(path) {
                Ok(w) => {
                    loaded = w;
                    &loaded
                }
                Err(e) => {
                    return WithdrawOutcome::Refused {
                        reason: format!("could not load that wallet: {e:#}"),
                    };
                }
            },
            None => match &self.mode {
                Mode::Armed(c) => &c.wallet,
                Mode::DryRun { .. } => {
                    return WithdrawOutcome::Refused {
                        reason: "bot is in dry run — pick a specific wallet, or arm on the host"
                            .into(),
                    };
                }
            },
        };
        if !(sol.is_finite() && sol > 0.0) {
            return WithdrawOutcome::Refused { reason: "amount must be greater than 0".into() };
        }
        let dest_pk = match pk(dest) {
            Ok(p) => p,
            Err(_) => return WithdrawOutcome::Refused { reason: "invalid destination address".into() },
        };
        let from = wallet.pubkey();
        if dest_pk == from {
            return WithdrawOutcome::Refused { reason: "destination is the trading wallet itself".into() };
        }
        let lamports = (sol * 1_000_000_000.0).round() as u64;

        // Leave a small reserve for the fee so a "withdraw everything" can't fail
        // on being 5000 lamports short (or strand the account below rent).
        const FEE_RESERVE: u64 = 10_000;
        if let Some(bal_sol) = self.rpc.sol_balance(&from.to_string()).await {
            let bal_lamports = (bal_sol * 1_000_000_000.0).round() as u64;
            if lamports.saturating_add(FEE_RESERVE) > bal_lamports {
                return WithdrawOutcome::Refused {
                    reason: format!(
                        "insufficient balance: {sol} SOL + fee exceeds {bal_sol:.4} SOL held"
                    ),
                };
            }
        }

        warn!(%dest, sol, "sniper: SUBMITTING WITHDRAWAL — moving funds OUT");
        let ix = solana_system_interface::instruction::transfer(&from, &dest_pk, lamports);
        let res = self.submitter.send(&[ix], &from, wallet.keypair()).await;
        let (outcome, result) = classify_submission(res);
        self.audit_withdraw(&from.to_string(), dest, sol, &outcome).await;
        WithdrawOutcome::Submitted { sol, dest: dest.to_string(), result }
    }

    /// Append a withdrawal to the audit log, tagged so the cost-basis parser
    /// ignores it (a withdraw's `confirmed:` is not a buy).
    #[cfg(feature = "sniper")]
    async fn audit_withdraw(&self, from: &str, dest: &str, sol: f64, outcome: &str) {
        if self.cfg.audit_log.is_empty() {
            return;
        }
        let record = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "action": "withdraw",
            "from": from,
            "dest": dest,
            "sol": sol,
            "outcome": outcome,
        });
        if let Err(e) = append_line(&self.cfg.audit_log, &record).await {
            warn!(error = %e, "failed to write withdraw audit log");
        }
    }

    /// Append a sell decision to the audit log. Tagged `action:"sell"` so the
    /// `/positions` cost-basis parser can exclude it — a sell's `confirmed:`
    /// outcome must NOT be counted as buy spend.
    #[cfg(feature = "sniper")]
    async fn audit_sell(&self, owner: &str, mint: &str, pct: u8, sol_out: f64, outcome: &str) {
        if self.cfg.audit_log.is_empty() {
            return;
        }
        let record = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "action": "sell",
            "owner": owner,
            "mint": mint,
            "pct": pct,
            "sol_out_est": sol_out,
            "mode": match self.mode { Mode::Armed(_) => "armed", Mode::DryRun { .. } => "dry_run" },
            "outcome": outcome,
        });
        if let Err(e) = append_line(&self.cfg.audit_log, &record).await {
            warn!(error = %e, "failed to write sell audit log");
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

/// Fully-diluted market cap in USD.
///
/// `quote_reserve` (SOL) / `base_reserve` (tokens) is the pool mid-price in SOL
/// per token; times total supply gives the valuation in SOL; times the SOL price
/// gives USD. Pure so the arithmetic is testable without a network.
///
/// Returns None when it cannot be computed rather than guessing — a fabricated
/// market cap would gate real money on a made-up number.
#[cfg(feature = "sniper")]
pub fn market_cap_usd(
    quote_reserve: f64,
    base_reserve: f64,
    total_supply: f64,
    sol_price_usd: f64,
) -> Option<f64> {
    if !(base_reserve > 0.0)
        || !quote_reserve.is_finite()
        || !total_supply.is_finite()
        || !(sol_price_usd > 0.0)
    {
        return None;
    }
    let price_sol = quote_reserve / base_reserve;
    let mcap = price_sol * total_supply * sol_price_usd;
    mcap.is_finite().then_some(mcap)
}

/// Classify a submission by what it means for funds: the audit string plus the
/// operator-facing outcome. Used by the EXIT path (`sell`). The buy path in
/// `consider` keeps the equivalent inline — the two must stay in sync; the
/// distinction that matters is Executed vs NotExecuted vs Indeterminate.
#[cfg(feature = "sniper")]
fn classify_submission(res: Result<Submission>) -> (String, SubmitOutcome) {
    match res {
        Ok(Submission::BundleLanded { bundle, slot }) => (
            format!("bundle_landed:{bundle}"),
            SubmitOutcome::Executed { reference: bundle, slot: Some(slot) },
        ),
        Ok(Submission::BundleNotLanded { bundle, last }) => (
            format!("bundle_not_landed:{bundle}:{last}"),
            SubmitOutcome::NotExecuted { reason: format!("bundle did not land ({last})") },
        ),
        Ok(Submission::Confirmed { signature, slot }) => (
            format!("confirmed:{signature}"),
            SubmitOutcome::Executed { reference: signature, slot: Some(slot) },
        ),
        // Not a failure: it may still land, so retrying could double-spend.
        Ok(Submission::Unconfirmed { signature }) => (
            format!("unconfirmed:{signature}"),
            SubmitOutcome::Indeterminate {
                reference: signature,
                reason: "not confirmed within timeout; may still land".into(),
            },
        ),
        Ok(Submission::RejectedByPreflight { reason }) => (
            format!("preflight_rejected:{reason}"),
            SubmitOutcome::NotExecuted { reason: format!("preflight rejected: {reason}") },
        ),
        // Indeterminate, NOT NotExecuted: a transport error can arrive after the
        // node already accepted the transaction. Retrying could double-spend.
        Ok(Submission::Failed { reason }) => (
            format!("failed:{reason}"),
            SubmitOutcome::Indeterminate { reference: "no-signature".into(), reason },
        ),
        Err(e) => {
            let reason = format!("{e:#}");
            (
                format!("error:{reason}"),
                SubmitOutcome::Indeterminate { reference: "no-signature".into(), reason },
            )
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
    /// The market-cap ceiling must REFUSE when it cannot read a price.
    ///
    /// This failed open for most of the project's life, and it went wrong in
    /// the predicted way: the price source was IP-blocked for hours and the
    /// ceiling — added specifically after buying a high-market-cap rug — was
    /// silently inert the whole time, with nothing to say so.
    #[test]
    fn an_unreadable_market_cap_is_a_denial_not_a_pass() {
        let d = super::Denial::MarketCapUnreadable;
        assert_eq!(d.label(), "market cap unreadable");

        // The distinction that matters: "could not check" is its own outcome,
        // never folded into "checked and fine".
        let too_high = super::Denial::MarketCapTooHigh { mcap_usd: 9e4, max_usd: 5e4 };
        assert_ne!(d.label(), too_high.label());
    }

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
            curve_min_liquidity_sol: 0.0,
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
            mode: "open".into(),
            export_ttl_secs: 60,
            // Off in tests: the gate needs live RPC + Jupiter, and existing
            // cases assert on the other guards. Covered by its own pure test.
            max_market_cap_usd: 0.0,
            // Tests must never touch a real settings or routes file.
            settings_path: String::new(),
            pool_auto_buy: true,
            sell_routes_path: String::new(),
            exit_state_path: String::new(),
            exit_check_secs: 15,
            jupiter_base_url: "https://lite-api.jup.ag/swap/v1".into(),
            sell_slippage_bps: 500,
        }
    }

    fn mk(c: SniperConfig) -> Result<Sniper> {
        let rpc_cfg = RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            ..Default::default()
        };
        Sniper::new(
            c,
            Arc::new(RpcClient::new(&rpc_cfg)),
            &rpc_cfg,
            Arc::new(crate::prices::PriceIndex::new()),
        )
    }

    /// A cap set from Telegram has to actually refuse a trade. Storing it and
    /// still buying would be worse than not offering the command at all.
    #[test]
    fn a_cap_tightened_from_telegram_binds_on_the_next_decision() {
        let s = mk(cfg()).unwrap();
        let now = Utc::now();
        assert!(s.consider(&event(), now).is_ok(), "baseline should pass");

        s.set_max_trades(0).unwrap();
        s.set_daily_cap(0.05).unwrap(); // below the 0.1 trade size
        match s.consider(&event(), now) {
            Err(Denial::DailyCapReached { cap, .. }) => assert_eq!(cap, 0.05),
            other => panic!("expected the tightened daily cap to bind, got {other:?}"),
        }
    }

    /// Lowering the ceiling below the working size pulls the SIZE down with it
    /// rather than refusing every trade. Jamming the bot into permanent denial
    /// would be a worse answer to "be more careful" than simply buying less.
    #[test]
    fn tightening_the_ceiling_shrinks_the_trade() {
        let s = mk(cfg()).unwrap(); // trade size 0.1
        s.set_max_trade_size(0.05).unwrap();
        assert_eq!(s.live().trade_size_sol, 0.05, "working size follows the ceiling down");
        let plan = s.consider(&event(), Utc::now()).expect("should still trade, just smaller");
        assert_eq!(plan.size, 0.05);
    }

    /// Telegram may tighten a ceiling, never raise one past the host's.
    #[test]
    fn caps_are_settable_and_bind_immediately() {
        let s = mk(cfg()).unwrap();

        // Caps are the operator's, in both directions — they bound losses, and
        // needing an SSH session to change the one control that does that was
        // the wrong trade.
        assert!(s.set_daily_cap(0.2).is_ok());
        assert!(s.set_max_trades(3).is_ok());
        assert!(s.set_max_trade_size(0.05).is_ok());
        assert!(s.set_daily_cap(-1.0).is_err(), "negative is not a cap");

        // And a cap set here refuses the very next trade. Set below the trade
        // size so it binds on the FIRST one rather than after some spend.
        s.set_daily_cap(0.01).unwrap();
        match s.consider(&event(), Utc::now()) {
            Err(Denial::DailyCapReached { cap, .. }) => assert_eq!(cap, 0.01),
            other => panic!("the tightened daily cap must bind, got {other:?}"),
        }
    }

    /// Clearing a live cap falls back to config, and when config sets none the
    /// operator is told the limit is gone rather than left to assume it holds.
    #[test]
    fn clearing_a_cap_says_what_is_left() {
        let s = mk(cfg()).unwrap();
        let msg = s.set_daily_cap(0.0).unwrap();
        assert!(msg.contains("follows config"), "got: {msg}");

        let mut open = cfg();
        open.daily_cap_sol = 0.0;
        let s2 = mk(open).unwrap();
        let msg2 = s2.set_daily_cap(0.0).unwrap();
        assert!(msg2.contains("unlimited"), "an absent cap must be stated: {msg2}");
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
            token_name: None,
            token_symbol: None,
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
    fn every_setting_is_the_operators_to_choose() {
        let mut c = cfg();
        c.trade_size_sol = 0.05;
        c.slippage_bps = 300;
        c.min_liquidity_sol = 10.0;
        let s = mk(c).unwrap();

        // Slippage and liquidity move in BOTH directions now. They were
        // tighten-only, which meant loosening either — a legitimate call on a
        // thin market — needed host access the operator may not have to hand.
        assert!(s.set_slippage_bps(200).is_ok());
        assert!(s.set_slippage_bps(800).is_ok(), "looser is the operator's risk to take");
        assert!(s.set_slippage_bps(0).is_err(), "zero would never fill");
        assert!(s.set_slippage_bps(6_000).is_err(), "past 50% a fill is worse than none");

        assert!(s.set_min_liquidity(20.0).is_ok());
        assert!(s.set_min_liquidity(2.0).is_ok(), "lowering is allowed");
        assert!(s.set_min_liquidity(-1.0).is_err());

        // The ONE invariant that survives: a trade may not exceed the
        // per-trade cap. That cap is itself settable — from the screen above —
        // so the guard is real without being a locked door.
        s.set_max_trade_size(1.0).unwrap();
        assert!(s.set_trade_size(0.5).is_ok());
        assert!(s.set_trade_size(1.5).is_err(), "above the per-trade cap is refused");
        assert!(s.set_trade_size(0.0).is_err(), "zero is not a trade");
    }


    /// With the three ceilings set to 0, none of them gate a trade: size is
    /// unbounded from Telegram, and consider() enforces no per-trade, daily, or
    /// count cap. Only the kill switch and safety checks remain.
    #[test]
    fn zero_caps_mean_unlimited() {
        let mut c = cfg();
        c.trade_size_sol = 0.05;
        c.max_trade_size_sol = 0.0; // disabled
        c.daily_cap_sol = 0.0; // disabled
        c.max_trades_per_day = 0; // disabled
        let s = mk(c).unwrap();

        // Size can be raised far past the old ceiling — no per-trade cap.
        assert!(s.set_trade_size(100.0).is_ok(), "no ceiling → any positive size");
        assert!(s.set_trade_size(0.01).is_ok(), "still settable down to dust");
        assert!(s.set_trade_size(0.0).is_err(), "zero still refused");

        // Many large trades in a row: neither the daily-spend nor the
        // trade-count cap ever fires (both are 0 = unlimited).
        let ev = event();
        s.set_trade_size(50.0).unwrap();
        for _ in 0..25 {
            let plan = s.consider(&ev, Utc::now());
            assert!(plan.is_ok(), "no daily/count cap should ever deny: {plan:?}");
            let size = plan.unwrap().size;
            s.reserve(&ev.pool, size, Utc::now());
        }
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

    /// A dry-run bot holds no key, so withdraw must be refused before any
    /// The supply ceiling trims the EXCESS and nothing more. It is a ceiling
    /// on the position, not a reason to close it.
    #[test]
    fn the_supply_ceiling_sells_only_the_excess() {
        // Mirrors `enforce_supply_cap`.
        fn trim(held: f64, supply: f64, max_pct: f64) -> Option<u8> {
            let cap = supply * max_pct / 100.0;
            if held <= cap {
                return None;
            }
            Some(((held - cap) / held * 100.0).ceil().clamp(1.0, 100.0) as u8)
        }

        // At the ceiling exactly: untouched.
        assert_eq!(trim(20_000_000.0, 1e9, 2.0), None);
        // Under it: untouched.
        assert_eq!(trim(5_000_000.0, 1e9, 2.0), None);

        // 10% of supply against a 2% ceiling: sheds 80%, keeping 2%.
        let pct = trim(100_000_000.0, 1e9, 2.0).unwrap();
        assert_eq!(pct, 80);
        let left = 100_000_000.0 * (1.0 - pct as f64 / 100.0);
        assert!(left <= 1e9 * 2.0 / 100.0, "must land at or under the ceiling, left {left}");

        // Rounds UP, so a position can never sit fractionally over the ceiling
        // and be re-trimmed on every sweep forever.
        let pct = trim(2_000_001.0, 1e9, 0.2).unwrap();
        let left = 2_000_001.0 * (1.0 - pct as f64 / 100.0);
        assert!(left <= 1e9 * 0.2 / 100.0, "rounding must not leave it over");
    }

    /// network call — the armed-only gate that stops a leaked token on a
    /// dry-run bot from moving funds.
    #[tokio::test]
    async fn withdraw_is_refused_in_dry_run() {
        let s = mk(cfg()).unwrap(); // cfg() is armed=false → DryRun
        let out = s
            .withdraw("So11111111111111111111111111111111111111112", 0.1, None)
            .await;
        assert!(
            matches!(out, WithdrawOutcome::Refused { .. }),
            "dry run must refuse withdrawal (no key loaded)"
        );
    }

    #[test]
    fn market_cap_math_and_guards() {
        // 10 SOL quote / 1000 tokens = 0.01 SOL each; x 1M supply = 10,000 SOL;
        // x $200 = $2,000,000.
        let m = market_cap_usd(10.0, 1_000.0, 1_000_000.0, 200.0).unwrap();
        assert!((m - 2_000_000.0).abs() < 1.0, "got {m}");

        // A small-supply cheap token lands under a 50k ceiling.
        let m = market_cap_usd(21.0, 1_000_000_000.0, 1_000_000_000.0, 200.0).unwrap();
        assert!((m - 4_200.0).abs() < 1.0, "got {m}");

        // Uncomputable inputs must be None, never a fabricated number.
        assert_eq!(market_cap_usd(10.0, 0.0, 1.0, 200.0), None, "zero base reserve");
        assert_eq!(market_cap_usd(10.0, -5.0, 1.0, 200.0), None, "negative reserve");
        assert_eq!(market_cap_usd(10.0, 1.0, 1.0, 0.0), None, "no SOL price");
        assert_eq!(market_cap_usd(f64::NAN, 1.0, 1.0, 200.0), None, "NaN in");
    }

    /// Fail-closed: unknown mint safety (None — e.g. [safety] disabled or the
    /// read failed) must be refused for a buy, not trusted. This is the
    /// difference between the alert path (may emit on unknown) and spending.
    #[test]
    fn unverified_mint_is_refused() {
        let s = mk(cfg()).unwrap();

        let mut ev = event();
        ev.mint_authority_revoked = None;
        assert!(
            matches!(s.consider(&ev, Utc::now()), Err(Denial::UnsafeMint { .. })),
            "unknown mint authority must be refused, not trusted"
        );

        let mut ev = event();
        ev.freeze_authority_revoked = None;
        assert!(
            matches!(s.consider(&ev, Utc::now()), Err(Denial::UnsafeMint { .. })),
            "unknown freeze authority must be refused, not trusted"
        );
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
