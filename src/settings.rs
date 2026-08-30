//! Live trading settings: changed from Telegram, persisted across restarts.
//!
//! # Why this exists
//!
//! The working values used to live in a plain `Mutex<Tunable>` with no save
//! path. Every `/size` and `/slippage` was silently reverted to `config.toml`
//! on the next restart — the operator set a value, the bot acknowledged it, and
//! then quietly traded on a different one. A setting the bot forgets is worse
//! than one it never offered.
//!
//! # The two tiers
//!
//! ```text
//!   config.toml   HARD ENVELOPE — restart-only, host-side
//!                 the most risk this process may ever take
//!                        │
//!                        │   Telegram may only move INWARD
//!                        ▼
//!   settings.json LIVE SETTINGS — Telegram, persisted here
//! ```
//!
//! Telegram can tighten, never loosen past the envelope. This is deliberate and
//! is the reason the split exists: if the bot account is compromised, or a
//! command is fat-fingered at 3am, the worst case stays bounded by a file that
//! only host access can change. Raising a ceiling is a decision that should
//! require the same access as taking the keys.
//!
//! # Cap semantics
//!
//! `0` means "no cap of my own" in BOTH tiers, so the effective cap is the
//! tightest one that is actually set. A live cap of 0 inherits the envelope
//! rather than removing it — the only way to widen is on the host.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

/// Working values the operator can change at runtime.
///
/// Cheaply cloneable on purpose: a decision snapshots it once and works from
/// that copy, so a change arriving mid-decision cannot make the checks and the
/// resulting plan disagree about what the limits were.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveSettings {
    pub trade_size_sol: f64,
    pub slippage_bps: u16,
    /// Liquidity floor for AMM/POOL entries (Raydium, PumpSwap, …).
    pub min_liquidity_sol: f64,
    /// Liquidity floor for pump.fun BONDING-CURVE entries.
    ///
    /// Deliberately separate from `min_liquidity_sol`, and deliberately not
    /// clamped by it. The pool floor exists because a thin AMM pool is a rug
    /// surface: the deployer can pull it. A bonding curve has no LP to pull —
    /// its reserves are the program's, and a fresh curve is SUPPOSED to be
    /// small. Applying the pool floor to a curve does not make curve entries
    /// safer, it just refuses every early entry, which is the entire reason to
    /// trade the curve at all.
    ///
    /// 0 = no floor. Raise it from Telegram if curve entries prove too thin.
    #[serde(default)]
    pub curve_min_liquidity_sol: f64,
    /// `open` or `guard`. Stored as text so the file stays readable and this
    /// module does not depend on the sniper's types.
    pub snipe_mode: String,

    // --- caps. 0 = inherit the config envelope, never "unlimited".
    pub max_trade_size_sol: f64,
    pub daily_cap_sol: f64,
    pub max_trades_per_day: u32,
    pub max_market_cap_usd: f64,
    pub max_price_impact_bps: u32,

    /// When to sell a position. See `crate::exits`.
    #[serde(default)]
    pub exits: crate::exits::ExitRules,

    /// Buy automatically on smart-money conviction.
    ///
    /// A full Telegram switch, unlike the spend caps. The caps bound how much
    /// can be lost and so stay host-side; this only decides WHETHER to trade,
    /// and everything it can spend is already bounded by them. It defaults off
    /// and is never enabled by anything but a deliberate tap.
    #[serde(default)]
    pub auto_buy: bool,

    /// Buy size by market-cap band. Empty = always use `trade_size_sol`.
    ///
    /// A fixed size treats a $20k launch and a $2M token as the same bet, which
    /// they are not — the same SOL buys a very different share of each, and
    /// carries a very different risk. These override `trade_size_sol` for a
    /// token that falls inside one.
    ///
    /// A token matching NO band uses `trade_size_sol`, so the bands are an
    /// override rather than a table you must complete before the bot works.
    #[serde(default)]
    pub buy_tiers: Vec<BuyTier>,

    /// ALPHA — a conviction layer on the normal trigger. See `crate::alpha`.
    ///
    /// Alpha never opens a trade. Auto-buy decides WHETHER to buy; if a wallet
    /// with a qualifying track record is among that token's buyers, Alpha adds
    /// `alpha_buy_sol` on top of the size already chosen. One position, one
    /// ladder, one set of limits.
    ///
    /// The BAR a wallet must clear lives in `config.toml`, not here. Which
    /// wallets get trusted with money is a decision to make deliberately at the
    /// host, not a slider to move between trades.
    #[serde(default)]
    pub alpha_enabled: bool,
    /// Extra SOL added to a normal buy when a qualifying Alpha wallet is among
    /// the token's buyers.
    ///
    /// Applied AFTER the market-cap band has chosen the base size, so
    /// conviction cannot quietly move a token into a different band. The
    /// combined total is then what every limit is measured against — the
    /// ceiling, affordability, price impact, the supply share and the daily
    /// cap all see the amount actually leaving the wallet.
    #[serde(default)]
    pub alpha_buy_sol: f64,


    /// REBOUND — buy a token smart money already left, if it trades again.
    ///
    /// Fully independent of auto-buy and Alpha: its own trigger, own size, own
    /// exits and own position limit. See `crate::rebound`.
    #[serde(default)]
    pub rebound_enabled: bool,
    /// How long a touched token stays under observation, in hours.
    #[serde(default = "default_rebound_hours")]
    pub rebound_watch_hours: i64,
    /// Fresh SOL volume, in a short rolling window, that arms the entry.
    /// 0 = never triggers — see `ReboundPool::evaluate`.
    #[serde(default)]
    pub rebound_min_volume_sol: f64,
    /// SOL per rebound entry.
    #[serde(default)]
    pub rebound_buy_sol: f64,
    /// Whether Rebound actually BUYS, separate from whether it runs.
    ///
    /// Off means observe and alert only. The watchlist still fills, the alerts
    /// still fire, and nothing is spent — which is how the thresholds get
    /// chosen: by watching what the alerts would have bought. Kept apart from
    /// the amount so turning buying off does not lose the number you tuned.
    #[serde(default)]
    pub rebound_buy_enabled: bool,
    /// Exits for rebound positions — its own ladder, since it enters on
    /// different evidence from the normal trigger and is held differently.
    #[serde(default = "empty_rules")]
    pub rebound_exits: crate::exits::ExitRules,
    /// Most rebound positions open at once. 0 = unlimited.
    #[serde(default = "one_position")]
    pub rebound_max_open: u32,

    /// Most positions the bot may hold open at once. 0 = unlimited.
    ///
    /// One limit, because there is one kind of position: Alpha adds size to a
    /// normal entry rather than opening its own.
    ///
    /// Defaults to 1: concentration is the point. A bot that opens a position
    /// on every signal it likes spreads the same balance across trades it
    /// cannot then size properly, and on a small wallet it runs out of fees
    /// before it runs out of signals.
    #[serde(default = "one_position")]
    pub max_open_positions: u32,

    /// Enforce the supply-share ceiling. Separate from the percentage so the
    /// rule can be switched off without losing the number you tuned.
    #[serde(default)]
    pub supply_cap: bool,
    /// Most of a token's total supply one position may hold, as a percent.
    ///
    ///
    /// # A ceiling on the POSITION, not on the buy
    ///
    /// The buy always executes at its configured size — nothing here resizes
    /// it. Afterwards, the wallet's actual holding is measured against the
    /// token's supply, and any excess is sold back off.
    ///
    /// Enforced after the fill rather than before it because a quote is a
    /// prediction and a fill is a fact. Sizing the buy down from a quote leaves
    /// the position wherever the fill landed; measuring what was actually
    /// received is the only version that holds the line.
    ///
    /// # Why it matters as the trade size grows
    ///
    /// On an early token a fixed SOL size buys a wildly varying SHARE of the
    /// supply. At 0.01 SOL that share is negligible; at 0.5 SOL the same trade
    /// can take a double-digit percentage of everything that exists — a
    /// position that cannot be exited, because selling it moves the price the
    /// whole way down and nobody is bidding for a fifth of the token.
    ///
    /// Price impact does not catch this: impact measures the POOL, this
    /// measures the TOKEN.
    #[serde(default)]
    pub max_supply_pct: f64,

    /// SOL the tracked cohort must have put in, inside the signal window.
    /// 0 = not required.
    #[serde(default)]
    pub min_smart_sol_in: f64,
}

/// One market-cap band and the size to buy inside it.
///
/// Bands are half-open — `[min, max)` — so a token at exactly the boundary
/// falls in the upper band and nowhere else. Ambiguity here is not a cosmetic
/// problem: a token matching two rules would buy a different amount depending
/// on iteration order, which is the kind of bug that only shows up in the
/// audit log weeks later.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BuyTier {
    /// Inclusive lower bound, USD.
    pub min_usd: f64,
    /// Exclusive upper bound, USD. 0 = unbounded above.
    pub max_usd: f64,
    pub sol: f64,
}

impl BuyTier {
    pub fn contains(&self, mcap_usd: f64) -> bool {
        mcap_usd >= self.min_usd && (self.max_usd <= 0.0 || mcap_usd < self.max_usd)
    }

    /// Do two bands share any market cap at all?
    pub fn overlaps(&self, other: &BuyTier) -> bool {
        let a_hi = if self.max_usd <= 0.0 { f64::INFINITY } else { self.max_usd };
        let b_hi = if other.max_usd <= 0.0 { f64::INFINITY } else { other.max_usd };
        self.min_usd < b_hi && other.min_usd < a_hi
    }

    pub fn is_valid(&self) -> bool {
        self.min_usd >= 0.0
            && self.sol > 0.0
            && self.sol.is_finite()
            && (self.max_usd <= 0.0 || self.max_usd > self.min_usd)
    }
}

/// The config-side ceilings this process may never exceed.
#[derive(Debug, Clone, Copy)]
pub struct Envelope {
    pub max_trade_size_sol: f64,
    pub daily_cap_sol: f64,
    pub max_trades_per_day: u32,
    pub slippage_bps: u16,
    pub min_liquidity_sol: f64,
    /// Hard floor for CURVE entries. Separate from the pool floor above; see
    /// `LiveSettings::curve_min_liquidity_sol`. Defaults to 0 (no floor).
    pub curve_min_liquidity_sol: f64,
    pub max_market_cap_usd: f64,
    pub max_price_impact_bps: u32,
}

/// The tighter of two caps, where 0 means "not set by this tier".
///
/// Both unset is genuinely uncapped — and that is a real state the operator can
/// be in, so it is reported honestly rather than papered over with a default.
pub fn tightest(live: f64, hard: f64) -> f64 {
    match (live > 0.0, hard > 0.0) {
        (true, true) => live.min(hard),
        (true, false) => live,
        (false, true) => hard,
        (false, false) => 0.0,
    }
}

pub fn tightest_u32(live: u32, hard: u32) -> u32 {
    match (live > 0, hard > 0) {
        (true, true) => live.min(hard),
        (true, false) => live,
        (false, true) => hard,
        (false, false) => 0,
    }
}

impl LiveSettings {
    /// The size to buy a token at this market cap, in SOL.
    ///
    /// Falls back to `trade_size_sol` when no band matches — including when the
    /// market cap could not be computed at all, which must not silently stop
    /// the bot trading.
    pub fn size_for_mcap(&self, mcap_usd: Option<f64>) -> f64 {
        let Some(mc) = mcap_usd.filter(|m| *m > 0.0) else {
            return self.trade_size_sol;
        };
        self.buy_tiers
            .iter()
            .find(|t| t.is_valid() && t.contains(mc))
            .map(|t| t.sol)
            .unwrap_or(self.trade_size_sol)
    }

    /// Add a band, refusing one that overlaps an existing one.
    pub fn add_tier(&mut self, tier: BuyTier) -> Result<(), String> {
        if !tier.is_valid() {
            return Err("a band needs a positive size and max above min".into());
        }
        if let Some(clash) = self.buy_tiers.iter().find(|t| t.overlaps(&tier)) {
            return Err(format!(
                "overlaps the existing {} band — bands must not share any market cap",
                describe_tier(clash)
            ));
        }
        self.buy_tiers.push(tier);
        self.buy_tiers.sort_by(|a, b| a.min_usd.total_cmp(&b.min_usd));
        Ok(())
    }

    pub fn auto_buy_active(&self, _env: &Envelope) -> bool {
        self.auto_buy
    }

    /// Start from config: live values equal the envelope, capping nothing
    /// further, so behaviour before any command matches the file on disk.
    pub fn from_envelope(
        env: &Envelope,
        trade_size_sol: f64,
        snipe_mode: &str,
    ) -> Self {
        Self {
            trade_size_sol,
            slippage_bps: env.slippage_bps,
            min_liquidity_sol: env.min_liquidity_sol,
            curve_min_liquidity_sol: env.curve_min_liquidity_sol,
            snipe_mode: snipe_mode.to_string(),
            max_trade_size_sol: 0.0,
            daily_cap_sol: 0.0,
            max_trades_per_day: 0,
            max_market_cap_usd: 0.0,
            max_price_impact_bps: 0,
            exits: crate::exits::ExitRules::default(),
            auto_buy: false,
            buy_tiers: Vec::new(),
            alpha_enabled: false,
            alpha_buy_sol: 0.0,
            rebound_enabled: false,
            rebound_watch_hours: default_rebound_hours(),
            rebound_min_volume_sol: 0.0,
            rebound_buy_sol: 0.0,
            rebound_buy_enabled: false,
            rebound_exits: empty_rules(),
            rebound_max_open: one_position(),
            max_open_positions: one_position(),
            supply_cap: false,
            max_supply_pct: 0.0,
            min_smart_sol_in: 0.0,
        }
    }

    pub fn effective_max_trade_size(&self, env: &Envelope) -> f64 {
        tightest(self.max_trade_size_sol, env.max_trade_size_sol)
    }
    pub fn effective_daily_cap(&self, env: &Envelope) -> f64 {
        tightest(self.daily_cap_sol, env.daily_cap_sol)
    }
    pub fn effective_max_trades(&self, env: &Envelope) -> u32 {
        tightest_u32(self.max_trades_per_day, env.max_trades_per_day)
    }
    pub fn effective_max_market_cap(&self, env: &Envelope) -> f64 {
        tightest(self.max_market_cap_usd, env.max_market_cap_usd)
    }
    pub fn effective_max_impact_bps(&self, env: &Envelope) -> u32 {
        tightest_u32(self.max_price_impact_bps, env.max_price_impact_bps)
    }
}

/// Persisted settings. Every accepted change is written before the caller is
/// told it succeeded.
pub struct SettingsStore {
    path: String,
    env: Envelope,
    inner: Mutex<LiveSettings>,
}

impl SettingsStore {
    /// Load from disk, falling back to the config-derived defaults.
    ///
    /// A corrupt or unreadable file warns and falls back rather than refusing
    /// to start: settings are an operator convenience, and losing them must
    /// never take a running detector down with them. Anything the file does
    /// contain is still re-clamped to the envelope on load, so a hand-edited
    /// `settings.json` cannot widen a ceiling.
    pub fn load(path: &str, env: Envelope, defaults: LiveSettings) -> Self {
        let mut settings = match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<LiveSettings>(
                raw.strip_prefix('\u{feff}').unwrap_or(&raw),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(path, error = %e, "unreadable settings; using config defaults");
                    defaults
                }
            },
            Err(_) => defaults,
        };
        clamp(&mut settings, &env);
        Self { path: path.to_string(), env, inner: Mutex::new(settings) }
    }

    /// In-memory only. For tests and for callers with no persistence.
    pub fn ephemeral(env: Envelope, settings: LiveSettings) -> Self {
        Self { path: String::new(), env, inner: Mutex::new(settings) }
    }

    pub fn envelope(&self) -> Envelope {
        self.env
    }

    pub fn snapshot(&self) -> LiveSettings {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Apply a change, persist it, and return the caller's message.
    ///
    /// The mutation runs under the lock and is re-clamped before saving, so no
    /// path — not even a future one that forgets to validate — can leave a
    /// value outside the envelope in memory or on disk.
    pub fn update<F>(&self, f: F) -> Result<String, String>
    where
        F: FnOnce(&mut LiveSettings) -> Result<String, String>,
    {
        let (msg, snapshot) = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut candidate = g.clone();
            let msg = f(&mut candidate)?;
            clamp(&mut candidate, &self.env);
            *g = candidate.clone();
            (msg, candidate)
        };
        if let Err(e) = self.save(&snapshot) {
            // The change IS live; only the record of it failed. Say so rather
            // than implying it did not take, and rather than staying silent and
            // letting the next restart quietly undo it.
            tracing::warn!(path = %self.path, error = %e, "settings not persisted");
            return Ok(format!("{msg}\n⚠️ could not save — this will revert on restart"));
        }
        Ok(msg)
    }

    fn save(&self, s: &LiveSettings) -> std::io::Result<()> {
        if self.path.is_empty() {
            return Ok(());
        }
        // Write-then-rename: a crash mid-write leaves the previous settings
        // intact rather than a truncated file that fails to parse next boot.
        let tmp = format!("{}.tmp", self.path);
        if let Some(parent) = Path::new(&self.path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&tmp, serde_json::to_string_pretty(s)?)?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// Force every value back inside the envelope.
fn clamp(s: &mut LiveSettings, env: &Envelope) {

    if env.slippage_bps > 0 {
        s.slippage_bps = s.slippage_bps.min(env.slippage_bps);
    }
    s.min_liquidity_sol = s.min_liquidity_sol.max(env.min_liquidity_sol);
    // Against its OWN envelope, never the pool floor: the whole point of the
    // curve setting is that the pool floor must not reach it.
    s.curve_min_liquidity_sol = s.curve_min_liquidity_sol.max(env.curve_min_liquidity_sol);
    if !s.curve_min_liquidity_sol.is_finite() || s.curve_min_liquidity_sol < 0.0 {
        s.curve_min_liquidity_sol = 0.0;
    }
    let max_size = tightest(s.max_trade_size_sol, env.max_trade_size_sol);
    // Validity first, for the same reason as the Alpha amount below: NaN.min(x)
    // is x, so clamping first would promote a nonsense size to the ceiling —
    // the largest spend allowed — instead of disabling it.
    if !s.trade_size_sol.is_finite() || s.trade_size_sol <= 0.0 {
        s.trade_size_sol = 0.0;
    }
    if max_size > 0.0 {
        s.trade_size_sol = s.trade_size_sol.min(max_size);
    }
    // Alpha's amount lives under the same ceiling. Left unclamped, lowering the
    // host limit would not shrink it — it would make every Alpha buy fail the
    // size check instead, and an Alpha refusal is deliberately silent, so the
    // mode would simply stop trading with nothing said.
    // Validity BEFORE the ceiling: `f64::min` returns the other operand when
    // one side is NaN, so clamping first would turn a nonsense value into the
    // maximum permitted spend rather than into nothing.
    if !s.alpha_buy_sol.is_finite() || s.alpha_buy_sol < 0.0 {
        s.alpha_buy_sol = 0.0;
    }
    if max_size > 0.0 {
        s.alpha_buy_sol = s.alpha_buy_sol.min(max_size);
    }
    if !s.rebound_buy_sol.is_finite() || s.rebound_buy_sol < 0.0 {
        s.rebound_buy_sol = 0.0;
    }
    if max_size > 0.0 {
        s.rebound_buy_sol = s.rebound_buy_sol.min(max_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope {
            max_trade_size_sol: 1.0,
            daily_cap_sol: 5.0,
            max_trades_per_day: 10,
            slippage_bps: 300,
            min_liquidity_sol: 15.0,
            curve_min_liquidity_sol: 0.0,
            max_market_cap_usd: 50_000.0,
            max_price_impact_bps: 1000,
        }
    }

    fn live() -> LiveSettings {
        LiveSettings::from_envelope(&env(), 0.05, "open")
    }


    /// Auto-buy is a full Telegram switch, and it survives a restart. The
    /// spend caps stay host-side because they bound how much can be LOST;
    /// this only decides whether to trade, and what it can spend is already
    /// bounded by them.
    #[test]
    fn auto_buy_is_toggled_from_telegram_and_persists() {
        let dir = std::env::temp_dir().join(format!("volens-ab-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let store = SettingsStore::load(&p, env(), live());
        assert!(!store.snapshot().auto_buy, "off until deliberately enabled");
        store.update(|s| { s.auto_buy = true; Ok("on".into()) }).unwrap();

        let reloaded = SettingsStore::load(&p, env(), live());
        assert!(reloaded.snapshot().auto_buy_active(&env()), "must survive a restart");
        let _ = std::fs::remove_file(&p);
    }

    /// 0 means "this tier sets no cap", so the other tier decides. It must
    /// never be read as "unlimited" on the live side, or a Telegram command
    /// could remove a ceiling by setting it to zero.
    #[test]
    fn an_unset_live_cap_inherits_the_envelope() {
        assert_eq!(tightest(0.0, 5.0), 5.0);
        assert_eq!(tightest(2.0, 5.0), 2.0, "live is tighter");
        assert_eq!(tightest(9.0, 5.0), 5.0, "envelope still wins");
        assert_eq!(tightest(2.0, 0.0), 2.0, "live may cap where config did not");
        assert_eq!(tightest(0.0, 0.0), 0.0, "genuinely uncapped, reported as such");
    }

    #[test]
    fn effective_caps_take_the_tighter_side() {
        let e = env();
        let mut s = live();
        assert_eq!(s.effective_daily_cap(&e), 5.0);
        s.daily_cap_sol = 2.0;
        assert_eq!(s.effective_daily_cap(&e), 2.0);
        s.daily_cap_sol = 50.0;
        assert_eq!(s.effective_daily_cap(&e), 5.0, "cannot exceed the envelope");
        s.max_trades_per_day = 3;
        assert_eq!(s.effective_max_trades(&e), 3);
        s.max_trades_per_day = 999;
        assert_eq!(s.effective_max_trades(&e), 10);
    }

    /// The bug this module exists to fix: a value set from Telegram must still
    /// be there after a restart.
    #[test]
    fn settings_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("volens-set-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json").to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        let store = SettingsStore::load(&p, env(), live());
        store
            .update(|s| {
                s.trade_size_sol = 0.25;
                s.daily_cap_sol = 1.0;
                Ok("ok".into())
            })
            .unwrap();

        let reloaded = SettingsStore::load(&p, env(), live());
        let s = reloaded.snapshot();
        assert_eq!(s.trade_size_sol, 0.25);
        assert_eq!(s.daily_cap_sol, 1.0);
        let _ = std::fs::remove_file(&p);
    }

    /// A hand-edited file must not be able to widen the envelope either.
    #[test]
    fn a_file_cannot_widen_the_envelope() {
        let dir = std::env::temp_dir().join(format!("volens-set2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json").to_string_lossy().to_string();
        std::fs::write(
            &p,
            r#"{"trade_size_sol":99.0,"slippage_bps":5000,"min_liquidity_sol":0.0,
                "snipe_mode":"open","max_trade_size_sol":0.0,"daily_cap_sol":0.0,
                "max_trades_per_day":0,"max_market_cap_usd":0.0,"max_price_impact_bps":0}"#,
        )
        .unwrap();

        let s = SettingsStore::load(&p, env(), live()).snapshot();
        assert_eq!(s.trade_size_sol, 1.0, "clamped to max_trade_size_sol");
        assert_eq!(s.slippage_bps, 300, "clamped to the config ceiling");
        assert_eq!(s.min_liquidity_sol, 15.0, "raised back to the config floor");
        let _ = std::fs::remove_file(&p);
    }

    /// Corrupt settings must not stop the process starting.
    #[test]
    fn unreadable_settings_fall_back_rather_than_failing() {
        let dir = std::env::temp_dir().join(format!("volens-set3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json").to_string_lossy().to_string();
        std::fs::write(&p, "{ not json").unwrap();
        let s = SettingsStore::load(&p, env(), live()).snapshot();
        assert_eq!(s.trade_size_sol, 0.05, "fell back to the config default");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn an_update_that_is_refused_changes_nothing() {
        let store = SettingsStore::ephemeral(env(), live());
        let before = store.snapshot();
        let err = store.update(|s| {
            s.trade_size_sol = 0.9;
            Err("nope".to_string())
        });
        assert_eq!(err, Err("nope".into()));
        assert_eq!(store.snapshot(), before, "a refused update must not leak a partial write");
    }

    /// Bands must never be ambiguous: a token matching two would buy a
    /// different amount depending on iteration order.
    #[test]
    fn bands_may_not_overlap() {
        let mut s = live();
        s.buy_tiers.clear();
        s.add_tier(BuyTier { min_usd: 50e3, max_usd: 100e3, sol: 0.2 }).unwrap();
        // Straddles the existing band.
        let err = s
            .add_tier(BuyTier { min_usd: 75e3, max_usd: 200e3, sol: 0.3 })
            .unwrap_err();
        assert!(err.contains("overlaps"), "got: {err}");
        // Touching at the boundary is fine — bands are [min, max).
        s.add_tier(BuyTier { min_usd: 100e3, max_usd: 500e3, sol: 0.35 }).unwrap();
        assert_eq!(s.buy_tiers.len(), 2);
    }

    /// The boundary belongs to exactly one band.
    #[test]
    fn a_market_cap_matches_at_most_one_band() {
        let mut s = live();
        s.buy_tiers.clear();
        s.trade_size_sol = 0.2;
        s.add_tier(BuyTier { min_usd: 10e3, max_usd: 50e3, sol: 0.1 }).unwrap();
        s.add_tier(BuyTier { min_usd: 50e3, max_usd: 100e3, sol: 0.25 }).unwrap();

        assert_eq!(s.size_for_mcap(Some(20e3)), 0.1);
        assert_eq!(s.size_for_mcap(Some(50e3)), 0.25, "the boundary goes to the upper band");
        assert_eq!(s.size_for_mcap(Some(73e3)), 0.25, "the worked example");
    }

    /// No matching band, and no market cap at all, both fall back to the
    /// default. An unknown valuation must not stop the bot trading.
    #[test]
    fn an_unmatched_or_unknown_market_cap_uses_the_default() {
        let mut s = live();
        s.buy_tiers.clear();
        s.trade_size_sol = 0.2;
        s.add_tier(BuyTier { min_usd: 10e3, max_usd: 50e3, sol: 0.1 }).unwrap();

        assert_eq!(s.size_for_mcap(Some(75e3)), 0.2, "gap between bands");
        assert_eq!(s.size_for_mcap(None), 0.2, "market cap unknown");
        assert_eq!(s.size_for_mcap(Some(0.0)), 0.2, "market cap unusable");
    }

    /// An open-ended top band.
    #[test]
    fn a_band_with_no_upper_bound_catches_everything_above() {
        let mut s = live();
        s.buy_tiers.clear();
        s.add_tier(BuyTier { min_usd: 2e6, max_usd: 0.0, sol: 1.0 }).unwrap();
        assert_eq!(s.size_for_mcap(Some(50e6)), 1.0);
        assert_eq!(s.size_for_mcap(Some(1e6)), s.trade_size_sol, "below it, default");
        // And nothing may overlap it.
        assert!(s.add_tier(BuyTier { min_usd: 3e6, max_usd: 4e6, sol: 0.5 }).is_err());
    }
    /// Lowering the host ceiling must SHRINK the Alpha amount, not leave it
    /// oversized. An oversized amount fails the size check on every buy, and an
    /// Alpha refusal is silent — the mode would stop trading with nothing said.
    #[test]
    fn the_host_ceiling_shrinks_the_alpha_amount() {
        let mut env = env();
        env.max_trade_size_sol = 0.2;
        let mut s = LiveSettings::from_envelope(&env, 0.1, "guard");
        s.alpha_buy_sol = 0.75;
        clamp(&mut s, &env);
        assert_eq!(s.alpha_buy_sol, 0.2, "clamped to the ceiling, not refused later");
    }

    #[test]
    fn a_nonsense_alpha_amount_is_zeroed() {
        let env = env();
        let mut s = LiveSettings::from_envelope(&env, 0.1, "guard");
        s.alpha_buy_sol = f64::NAN;
        clamp(&mut s, &env);
        assert_eq!(s.alpha_buy_sol, 0.0);
    }

}

fn default_rebound_hours() -> i64 {
    72
}

/// Rebound starts with NO orders. `ExitRules::default()` carries the normal
/// lane's five-rung ladder, and inheriting it would mean Rebound silently
/// traded a strategy nobody chose for it.
fn empty_rules() -> crate::exits::ExitRules {
    crate::exits::ExitRules { orders: Vec::new(), ..Default::default() }
}

/// The exits a REBOUND position is governed by.
///
/// Falls back to the normal ladder when Rebound has no orders of its own: an
/// unconfigured mode must not leave a live position with no stop and no target.
pub fn rebound_exit_rules(
    live: &LiveSettings,
    base: &crate::exits::ExitRules,
) -> crate::exits::ExitRules {
    if !live.rebound_exits.orders.iter().any(|o| o.is_armed()) {
        return base.clone();
    }
    crate::exits::ExitRules {
        // Safety behaviour is not strategy: the master switch and the rug exit
        // come from the normal rules either way.
        enabled: base.enabled,
        exit_on_liquidity_pull: base.exit_on_liquidity_pull,
        orders: live.rebound_exits.orders.clone(),
        trailing_pct: live.rebound_exits.trailing_pct,
        breakeven: live.rebound_exits.breakeven,
    }
}

/// One concurrent position until the operator says otherwise.
fn one_position() -> u32 {
    1
}

/// A band as a reader would say it: "$50K–$100K".
pub fn describe_tier(t: &BuyTier) -> String {
    let f = |v: f64| {
        if v >= 1e9 {
            format!("${:.1}B", v / 1e9)
        } else if v >= 1e6 {
            format!("${:.1}M", v / 1e6)
        } else if v >= 1e3 {
            format!("${:.0}K", v / 1e3)
        } else {
            format!("${v:.0}")
        }
    };
    if t.max_usd <= 0.0 {
        format!("{}+", f(t.min_usd))
    } else {
        format!("{}–{}", f(t.min_usd), f(t.max_usd))
    }
}
