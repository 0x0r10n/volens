//! Configuration: layered TOML file + environment-variable overrides.
//!
//! Precedence (highest wins): environment variable > config.toml > built-in default.
//! Secrets (gRPC x-token, Telegram token/chat) should live in the environment,
//! never in the committed TOML.

use crate::model::Dex;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub grpc: GrpcConfig,
    #[serde(default)]
    pub filters: FilterConfig,
    #[serde(default)]
    pub alerts: AlertConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub rpc: RpcConfig,
    #[serde(default)]
    pub liquidity: LiquidityConfig,
    #[serde(default)]
    pub safety: SafetyConfig,
    #[serde(default)]
    pub watch: WatchConfig,
    #[serde(default)]
    pub sniper: SniperConfig,
    #[serde(default)]
    pub log: LogConfig,
}

/// Standard JSON-RPC endpoint used for post-detection enrichment (liquidity and
/// mint-safety reads). Separate from the gRPC stream.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcConfig {
    #[serde(default)]
    pub url: String,
    /// `confirmed` is more reliable than `processed` for freshly created accounts.
    #[serde(default = "default_rpc_commitment")]
    pub commitment: String,
    /// Wait this long before the first read, giving the account time to land.
    #[serde(default = "default_initial_delay")]
    pub initial_delay_ms: u64,
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_retry_delay")]
    pub retry_delay_ms: u64,
    /// Explicit WebSocket URL. Empty derives it from `url` by swapping the
    /// scheme (https->wss), which is correct for Helius, Triton and QuickNode.
    /// Set this only for a provider that serves WS on a different host or path.
    #[serde(default)]
    pub ws_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LiquidityConfig {
    /// Read the quote-side vault after detection and filter on it.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum quote-side liquidity, in UI units of the quote asset
    /// (i.e. SOL for WSOL pairs, USDC for USDC pairs).
    #[serde(default = "default_min_liquidity")]
    pub min_quote_liquidity: f64,
    /// If the balance cannot be read, emit the pool anyway (with unknown
    /// liquidity) rather than dropping it. Defaults to true: a missed real
    /// launch costs more than one noisy alert.
    #[serde(default = "default_true")]
    pub emit_on_unknown: bool,
}

/// Mint-authority checks on the launched token. These are the highest-signal
/// rug filters available from a single account read.
#[derive(Debug, Clone, Deserialize)]
pub struct SafetyConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Drop pools whose token can still be minted at will (infinite supply risk).
    #[serde(default = "default_true")]
    pub require_mint_authority_revoked: bool,
    /// Drop pools whose token can still be frozen — the classic honeypot: you
    /// can buy, then your account is frozen and you cannot sell.
    #[serde(default = "default_true")]
    pub require_freeze_authority_revoked: bool,
    /// Drop tokens carrying Token-2022 extensions that can tax or block a sale
    /// (transfer fees, transfer hooks, permanent delegate, ...).
    #[serde(default = "default_true")]
    pub reject_risky_extensions: bool,
    /// Emit anyway when the mint cannot be read, rather than dropping.
    #[serde(default = "default_true")]
    pub emit_on_unknown: bool,
}

/// Delayed follow-up re-check on a detected pool.
///
/// LP burn/lock is a LATER transaction than pool creation (measured: ~8 min on a
/// real PumpSwap pool), so it cannot be checked synchronously at detection.
#[derive(Debug, Clone, Deserialize)]
pub struct WatchConfig {
    #[serde(default)]
    pub enabled: bool,
    /// How long after detection to re-read the pool.
    #[serde(default = "default_watch_delay")]
    pub delay_secs: u64,
    /// Fraction of quote liquidity that must disappear to call it a pull.
    #[serde(default = "default_rug_drop")]
    pub rug_drop_pct: f64,
    /// Net quote-side growth (in SOL/USDC) within the window that counts as a
    /// "volume spike" — real buy inflow, the alpha/momentum signal. Because
    /// buyers add quote and take token, a rising quote vault IS net buy volume.
    /// 0 disables the signal.
    #[serde(default = "default_min_volume_growth")]
    pub min_volume_growth_sol: f64,
    /// Alert on every follow-up, not just notable ones (pull / burn / volume).
    /// Off by default so follow-ups don't become their own noise source.
    #[serde(default)]
    pub alert_on_all: bool,
}

/// Guarded auto-execution. Parsed even in builds without the `sniper` feature so
/// that enabling it in config without the feature can be reported rather than
/// silently ignored — hence the fields are unread in a default build.
#[cfg_attr(not(feature = "sniper"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct SniperConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Live execution. Currently refused at startup — see `sniper.rs`.
    #[serde(default)]
    pub armed: bool,
    #[serde(default = "default_trade_size")]
    pub trade_size_sol: f64,
    /// Hard per-trade ceiling; `trade_size_sol` may not exceed it.
    #[serde(default = "default_max_trade_size")]
    pub max_trade_size_sol: f64,
    #[serde(default = "default_daily_cap")]
    pub daily_cap_sol: f64,
    #[serde(default = "default_max_trades")]
    pub max_trades_per_day: u32,
    /// Refuse a second trade on the same pool within this window.
    ///
    /// The detector's `Dedup` suppresses duplicate *alerts*, but it is keyed on
    /// pool and expires; it is not a spend guard. A pool that re-enters the
    /// stream after the dedup TTL — a second `initialize` in the same pool, a
    /// reconnect replaying recent slots — would otherwise buy again. 0 disables.
    #[serde(default = "default_pool_cooldown")]
    pub pool_cooldown_secs: u64,
    /// Liquidity re-checked at execution time, independent of the alert filter.
    #[serde(default = "default_snipe_min_liq")]
    pub min_liquidity_sol: f64,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u16,
    /// If this file exists, all execution halts immediately. Checked per
    /// decision, so `touch` takes effect without a restart.
    #[serde(default = "default_kill_switch")]
    pub kill_switch_file: String,
    /// Append-only log of every decision, allowed or denied.
    #[serde(default = "default_audit_log")]
    pub audit_log: String,
    /// Keypair file (Solana CLI JSON array). REQUIRED to arm. Use a dedicated
    /// wallet, never your main one.
    #[serde(default)]
    pub keypair_path: String,
    /// Pubkey to build+simulate as while in dry run. No secret is involved, so
    /// a dry run still cannot sign. Without it, dry run cannot rehearse.
    #[serde(default)]
    pub simulate_as: String,
    /// Refuse trades whose own price impact exceeds this. A thin new pool can
    /// be moved 30%+ by a single buy.
    #[serde(default = "default_max_impact")]
    pub max_price_impact_bps: u32,
    /// Simulate before every send. Leave on.
    #[serde(default = "default_true")]
    pub preflight: bool,
    #[serde(default = "default_confirm_timeout")]
    pub confirm_timeout_secs: u64,
    #[serde(default = "default_unit_limit")]
    pub compute_unit_limit: u32,
    #[serde(default = "default_priority_fee")]
    pub priority_fee_micro_lamports: u64,
    /// Submit via a Jito bundle instead of plain RPC. Atomic and front-run
    /// resistant; the tip is only paid if the bundle lands.
    #[serde(default)]
    pub jito_enabled: bool,
    #[serde(default = "default_jito_url")]
    pub jito_block_engine_url: String,
    /// Tip paid to a Jito tip account, in lamports. Too low and the bundle
    /// simply never lands.
    #[serde(default = "default_jito_tip")]
    pub jito_tip_lamports: u64,
    /// Fall back to plain RPC submission if the bundle does not land.
    /// Off by default: a fallback can land a trade you thought had been skipped.
    #[serde(default)]
    pub jito_fallback_to_rpc: bool,
    /// Directory holding locally-generated test wallets (`/new-wallet`,
    /// `/wallets`, `/use`). The active one drives which key is used.
    #[serde(default = "default_wallet_dir")]
    pub wallet_dir: String,
    /// Alert on EVERY dry-run rehearsal, including ones that would succeed.
    ///
    /// Off by default: in steady state a "would-succeed" ping on every pool is
    /// noise. On for a live demo, where the point is to watch the bot decide to
    /// trade with nothing at risk. Only affects dry run — armed submissions
    /// always alert regardless.
    #[serde(default)]
    pub alert_on_all_rehearsals: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    /// gRPC endpoint, e.g. https://mainnet.helius-rpc.com or a Triton URL.
    #[serde(default)]
    pub endpoint: String,
    /// Auth token for the endpoint (prefer env GRPC_X_TOKEN).
    #[serde(default)]
    pub x_token: String,
    /// processed | confirmed | finalized
    #[serde(default = "default_commitment")]
    pub commitment: String,
    /// Reconnect backoff bounds (seconds).
    #[serde(default = "default_backoff_min")]
    pub backoff_min_secs: u64,
    #[serde(default = "default_backoff_max")]
    pub backoff_max_secs: u64,
    /// Fall back to the WebSocket source when gRPC is unavailable.
    ///
    /// gRPC stays the PREFERRED path whenever it is configured and working —
    /// this only decides what happens when it isn't. Turning it off makes a
    /// missing or broken gRPC endpoint a hard startup failure instead, which is
    /// the right choice if silently running seconds behind would be worse than
    /// not running at all.
    #[serde(default = "default_true")]
    pub fallback_to_websocket: bool,
    /// Consecutive gRPC connection failures before falling back.
    ///
    /// Not 1: a single blip should not demote a healthy gRPC setup to the
    /// slower path for the rest of the session. Once fallback happens it is
    /// permanent for the process lifetime — flapping between sources would make
    /// detection latency unpredictable and the logs unreadable.
    #[serde(default = "default_grpc_failures")]
    pub max_failures_before_fallback: u32,
}

impl GrpcConfig {
    /// Is a usable gRPC endpoint configured?
    ///
    /// The shipped `config.toml` and `.env.example` both carry a placeholder,
    /// and treating that as "configured" would mean every fresh install burns
    /// its retry budget resolving a domain that does not exist before falling
    /// back. Recognising it lets the WebSocket path start immediately.
    pub fn is_configured(&self) -> bool {
        let e = self.endpoint.trim();
        !e.is_empty()
            && !e.contains("your-grpc-endpoint")
            && !e.contains("example.com")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterConfig {
    /// Only emit pools whose pair includes a recognized quote asset (WSOL/USDC).
    #[serde(default = "default_true")]
    pub require_quote_pair: bool,
    /// Which DEXes are enabled (by config key: raydium_v4 | raydium_cpmm | pumpswap).
    #[serde(default = "default_programs")]
    pub programs: Vec<String>,
    /// Quote mints treated as "not the new token".
    #[serde(default = "default_quote_mints")]
    pub quote_mints: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertConfig {
    #[serde(default)]
    pub telegram_enabled: bool,
    /// Prefer env TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID.
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    /// Suppress duplicate alerts for the same pool within this window.
    #[serde(default = "default_dedup_ttl")]
    pub dedup_ttl_secs: u64,

    /// Accept inbound commands (/status, /metrics, /halt).
    ///
    /// Deliberately NOT auto-enabled by the presence of a bot token, unlike
    /// outbound alerts. Sending alerts and accepting remote control are
    /// different trust decisions, and the second must be made on purpose.
    #[serde(default)]
    pub commands_enabled: bool,

    /// Chat IDs allowed to issue commands. Required when `commands_enabled`;
    /// an empty list is a startup error, never "allow everyone".
    /// Prefer env TELEGRAM_AUTHORIZED_CHAT_IDS (comma-separated).
    #[serde(default)]
    pub authorized_chat_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// jsonl | sqlite | none
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

// ---- defaults ----
fn default_true() -> bool { true }
fn default_commitment() -> String { "processed".into() }
fn default_backoff_min() -> u64 { 1 }
fn default_backoff_max() -> u64 { 30 }
fn default_dedup_ttl() -> u64 { 300 }
fn default_storage_backend() -> String { "jsonl".into() }
fn default_min_liquidity() -> f64 { 5.0 }
fn default_rpc_commitment() -> String { "confirmed".into() }
fn default_initial_delay() -> u64 { 400 }
fn default_retries() -> u32 { 3 }
fn default_retry_delay() -> u64 { 500 }
fn default_watch_delay() -> u64 { 120 }
fn default_rug_drop() -> f64 { 0.5 }
fn default_min_volume_growth() -> f64 { 5.0 }
fn default_trade_size() -> f64 { 0.05 }
fn default_max_trade_size() -> f64 { 0.25 }
fn default_daily_cap() -> f64 { 1.0 }
fn default_grpc_failures() -> u32 { 3 }
fn default_max_trades() -> u32 { 10 }
/// One hour. Long enough that a stream replay or a re-detection cannot buy
/// twice, short enough to be irrelevant to normal operation (each pool is
/// launched once).
fn default_pool_cooldown() -> u64 { 3600 }
fn default_snipe_min_liq() -> f64 { 10.0 }
fn default_slippage_bps() -> u16 { 300 }
fn default_kill_switch() -> String { "HALT".into() }
fn default_audit_log() -> String { "sniper_audit.jsonl".into() }
fn default_wallet_dir() -> String { "wallets".into() }
fn default_max_impact() -> u32 { 1_000 }
fn default_confirm_timeout() -> u64 { 30 }
fn default_unit_limit() -> u32 { 300_000 }
fn default_priority_fee() -> u64 { 100_000 }
fn default_jito_url() -> String { "https://mainnet.block-engine.jito.wtf/api/v1/bundles".into() }
fn default_jito_tip() -> u64 { 100_000 }
fn default_storage_path() -> String { "detected_pools.jsonl".into() }
fn default_log_level() -> String { "info".into() }
fn default_programs() -> Vec<String> {
    Dex::all().iter().map(|d| d.config_key().to_string()).collect()
}
fn default_quote_mints() -> Vec<String> {
    vec![crate::model::WSOL_MINT.into(), crate::model::USDC_MINT.into()]
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            x_token: String::new(),
            commitment: default_commitment(),
            backoff_min_secs: default_backoff_min(),
            backoff_max_secs: default_backoff_max(),
            fallback_to_websocket: true,
            max_failures_before_fallback: default_grpc_failures(),
        }
    }
}
impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            require_quote_pair: true,
            programs: default_programs(),
            quote_mints: default_quote_mints(),
        }
    }
}
impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            telegram_enabled: false,
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            dedup_ttl_secs: default_dedup_ttl(),
            commands_enabled: false,
            authorized_chat_ids: Vec::new(),
        }
    }
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self { backend: default_storage_backend(), path: default_storage_path() }
    }
}
impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            commitment: default_rpc_commitment(),
            initial_delay_ms: default_initial_delay(),
            retries: default_retries(),
            retry_delay_ms: default_retry_delay(),
            ws_url: String::new(),
        }
    }
}
impl Default for SniperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            armed: false,
            trade_size_sol: default_trade_size(),
            max_trade_size_sol: default_max_trade_size(),
            daily_cap_sol: default_daily_cap(),
            max_trades_per_day: default_max_trades(),
            pool_cooldown_secs: default_pool_cooldown(),
            min_liquidity_sol: default_snipe_min_liq(),
            slippage_bps: default_slippage_bps(),
            kill_switch_file: default_kill_switch(),
            audit_log: default_audit_log(),
            keypair_path: String::new(),
            simulate_as: String::new(),
            max_price_impact_bps: default_max_impact(),
            preflight: true,
            confirm_timeout_secs: default_confirm_timeout(),
            compute_unit_limit: default_unit_limit(),
            priority_fee_micro_lamports: default_priority_fee(),
            jito_enabled: false,
            jito_block_engine_url: default_jito_url(),
            jito_tip_lamports: default_jito_tip(),
            jito_fallback_to_rpc: false,
            wallet_dir: default_wallet_dir(),
            alert_on_all_rehearsals: false,
        }
    }
}
impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            delay_secs: default_watch_delay(),
            rug_drop_pct: default_rug_drop(),
            min_volume_growth_sol: default_min_volume_growth(),
            alert_on_all: false,
        }
    }
}
impl Default for LiquidityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_quote_liquidity: default_min_liquidity(),
            emit_on_unknown: true,
        }
    }
}
impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_mint_authority_revoked: true,
            require_freeze_authority_revoked: true,
            reject_risky_extensions: true,
            emit_on_unknown: true,
        }
    }
}
impl Default for LogConfig {
    fn default() -> Self {
        Self { level: default_log_level() }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            grpc: GrpcConfig::default(),
            filters: FilterConfig::default(),
            alerts: AlertConfig::default(),
            storage: StorageConfig::default(),
            rpc: RpcConfig::default(),
            liquidity: LiquidityConfig::default(),
            safety: SafetyConfig::default(),
            watch: WatchConfig::default(),
            sniper: SniperConfig::default(),
            log: LogConfig::default(),
        }
    }
}

impl Config {
    /// Load from an optional TOML path, then apply environment overrides.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        // .env is best-effort; missing file is fine.
        let _ = dotenvy::dotenv();

        let mut cfg = match path {
            Some(p) if p.exists() => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                toml::from_str(&text).with_context(|| format!("parsing config {}", p.display()))?
            }
            _ => Config::default(),
        };

        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("GRPC_ENDPOINT") { self.grpc.endpoint = v; }
        if let Ok(v) = std::env::var("GRPC_X_TOKEN") { self.grpc.x_token = v; }
        if let Ok(v) = std::env::var("GRPC_COMMITMENT") { self.grpc.commitment = v; }
        if let Ok(v) = std::env::var("TELEGRAM_BOT_TOKEN") {
            self.alerts.telegram_bot_token = v;
            self.alerts.telegram_enabled = true;
        }
        if let Ok(v) = std::env::var("TELEGRAM_CHAT_ID") { self.alerts.telegram_chat_id = v; }
        // Note: unlike TELEGRAM_BOT_TOKEN above, this does NOT flip
        // commands_enabled. Supplying an allowlist says who may command the bot,
        // not that commands should be accepted at all.
        if let Ok(v) = std::env::var("TELEGRAM_AUTHORIZED_CHAT_IDS") {
            self.alerts.authorized_chat_ids =
                v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        if let Ok(v) = std::env::var("RPC_URL") {
            self.rpc.url = v;
            // A configured RPC endpoint turns on the enrichment filters.
            self.liquidity.enabled = true;
            self.safety.enabled = true;
            self.watch.enabled = true;
        }
        if let Ok(v) = std::env::var("RPC_WS_URL") { self.rpc.ws_url = v; }
        if let Ok(v) = std::env::var("MIN_QUOTE_LIQUIDITY") {
            if let Ok(f) = v.parse() { self.liquidity.min_quote_liquidity = f; }
        }
        if let Ok(v) = std::env::var("LOG_LEVEL") { self.log.level = v; }
    }

    fn validate(&self) -> Result<()> {
        // A transaction source is required, but it no longer has to be gRPC:
        // an RPC url alone is enough to run the WebSocket fallback. Requiring
        // gRPC unconditionally would make a standard-plan setup impossible.
        anyhow::ensure!(
            self.grpc.is_configured() || !self.rpc.url.trim().is_empty(),
            "no transaction source configured: set GRPC_ENDPOINT (fast path) or \
             RPC_URL (WebSocket fallback, seconds slower)"
        );
        anyhow::ensure!(
            matches!(self.grpc.commitment.as_str(), "processed" | "confirmed" | "finalized"),
            "invalid commitment '{}': expected processed|confirmed|finalized",
            self.grpc.commitment
        );
        // Enabling the sniper in a build that cannot execute must be loud, not
        // silently ignored — the operator believes trading is on.
        #[cfg(not(feature = "sniper"))]
        anyhow::ensure!(
            !self.sniper.enabled,
            "sniper.enabled = true but this binary was built without the `sniper` \
             feature; rebuild with --features sniper (or set enabled = false)"
        );
        if self.watch.enabled {
            anyhow::ensure!(
                self.watch.rug_drop_pct > 0.0 && self.watch.rug_drop_pct <= 1.0,
                "watch.rug_drop_pct must be in (0, 1]; got {}",
                self.watch.rug_drop_pct
            );
        }
        if self.liquidity.enabled || self.safety.enabled || self.watch.enabled {
            anyhow::ensure!(
                !self.rpc.url.is_empty(),
                "liquidity/safety/watch need an RPC url ([rpc].url or env RPC_URL)"
            );
        }
        if self.liquidity.enabled {
            anyhow::ensure!(
                self.liquidity.min_quote_liquidity >= 0.0,
                "min_quote_liquidity must be >= 0"
            );
        }
        if self.alerts.telegram_enabled {
            anyhow::ensure!(
                !self.alerts.telegram_bot_token.is_empty() && !self.alerts.telegram_chat_id.is_empty(),
                "telegram enabled but TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing"
            );
        }
        if self.alerts.commands_enabled {
            anyhow::ensure!(
                !self.alerts.telegram_bot_token.is_empty(),
                "telegram commands enabled but TELEGRAM_BOT_TOKEN missing"
            );
            // Fail at startup rather than silently accepting commands from
            // nobody — or worse, being changed later into accepting them from
            // anyone. /halt is a remote kill switch; its ACL is not optional.
            anyhow::ensure!(
                self.alerts.authorized_chat_ids.iter().any(|s| !s.trim().is_empty()),
                "telegram commands enabled but authorized_chat_ids is empty — \
                 set [alerts].authorized_chat_ids or TELEGRAM_AUTHORIZED_CHAT_IDS"
            );
        }
        Ok(())
    }

    /// Enabled DEXes, resolved from the string config keys.
    pub fn enabled_dexes(&self) -> Vec<Dex> {
        self.filters
            .programs
            .iter()
            .filter_map(|k| Dex::from_config_key(k))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grpc(endpoint: &str) -> GrpcConfig {
        GrpcConfig {
            endpoint: endpoint.into(),
            x_token: String::new(),
            commitment: "processed".into(),
            backoff_min_secs: 1,
            backoff_max_secs: 30,
            fallback_to_websocket: true,
            max_failures_before_fallback: 3,
        }
    }

    /// Placeholder endpoints must not count as configured, or every fresh
    /// install burns its gRPC retry budget resolving a domain that cannot exist
    /// before falling back to WebSocket.
    #[test]
    fn placeholder_grpc_endpoints_are_not_configured() {
        assert!(!grpc("").is_configured(), "empty");
        assert!(!grpc("   ").is_configured(), "whitespace");
        // Shipped in config.toml and .env.example.
        assert!(
            !grpc("https://your-grpc-endpoint.example.com:443").is_configured(),
            "the shipped placeholder must not be treated as real"
        );
        assert!(!grpc("https://anything.example.com").is_configured());

        for real in [
            "https://mainnet.helius-rpc.com",
            "https://x.rpcpool.com",
            "https://y.solana-mainnet.quiknode.pro",
        ] {
            assert!(grpc(real).is_configured(), "{real} should be configured");
        }
    }

    /// A source is required, but it no longer has to be gRPC — that is the
    /// whole point of the WebSocket fallback. Requiring gRPC unconditionally
    /// would make a standard-plan setup impossible.
    #[test]
    fn an_rpc_url_alone_is_a_valid_source() {
        let mut c = Config::default();
        c.grpc = grpc("");
        c.rpc.url = String::new();
        assert!(c.validate().is_err(), "no source at all must fail");

        c.rpc.url = "https://mainnet.helius-rpc.com/?api-key=k".into();
        assert!(
            c.validate().is_ok(),
            "an RPC url alone must be enough (WebSocket mode)"
        );

        // gRPC alone is also fine.
        c.grpc = grpc("https://mainnet.helius-rpc.com");
        c.rpc.url = String::new();
        assert!(c.validate().is_ok(), "gRPC alone must be enough");
    }
}
