//! Shared domain types, program IDs, and instruction discriminators.
//!
//! The discriminators / account-index maps here are the single trickiest part of
//! the whole detector. They are kept as plain constants with explicit indices so
//! they are easy to eyeball and tweak. `parser.rs` contains a unit test that
//! recomputes the two Anchor discriminators from their global method names, so a
//! wrong constant fails the test rather than silently mis-parsing on mainnet.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Program IDs (mainnet, confirmed)
// ---------------------------------------------------------------------------

/// Raydium Legacy AMM v4.
pub const RAYDIUM_V4_PROGRAM: &str = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
/// Raydium CPMM (CP-Swap).
pub const RAYDIUM_CPMM_PROGRAM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
/// PumpSwap (Pump AMM).
pub const PUMPSWAP_PROGRAM: &str = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";

/// Wrapped SOL mint — the canonical "quote" asset for most new pools.
pub const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
/// USDC mint — a secondary quote asset we also treat as "not the new token".
pub const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

// ---------------------------------------------------------------------------
// Instruction discriminators
// ---------------------------------------------------------------------------

/// Raydium AMM v4 uses a single-byte instruction tag (Borsh enum index).
/// `Initialize2` == 1 is the instruction that creates a tradable pool.
pub const RAYDIUM_V4_INITIALIZE2_TAG: u8 = 1;

/// Anchor 8-byte discriminator for Raydium CPMM `initialize`
/// = sha256("global:initialize")[..8]. Verified by unit test.
pub const RAYDIUM_CPMM_INITIALIZE_DISC: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];

/// Anchor 8-byte discriminator for PumpSwap `create_pool`
/// = sha256("global:create_pool")[..8]. Verified by unit test.
pub const PUMPSWAP_CREATE_POOL_DISC: [u8; 8] = [233, 146, 209, 142, 207, 104, 64, 188];

// ---------------------------------------------------------------------------
// DEX identity + account layouts
// ---------------------------------------------------------------------------

/// Which venue a detected pool belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dex {
    RaydiumV4,
    RaydiumCpmm,
    PumpSwap,
}

impl Dex {
    pub fn program_id(self) -> &'static str {
        match self {
            Dex::RaydiumV4 => RAYDIUM_V4_PROGRAM,
            Dex::RaydiumCpmm => RAYDIUM_CPMM_PROGRAM,
            Dex::PumpSwap => PUMPSWAP_PROGRAM,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Dex::RaydiumV4 => "Raydium AMM v4",
            Dex::RaydiumCpmm => "Raydium CPMM",
            Dex::PumpSwap => "PumpSwap",
        }
    }

    /// Config token used to enable/disable this DEX.
    pub fn config_key(self) -> &'static str {
        match self {
            Dex::RaydiumV4 => "raydium_v4",
            Dex::RaydiumCpmm => "raydium_cpmm",
            Dex::PumpSwap => "pumpswap",
        }
    }

    pub fn from_config_key(s: &str) -> Option<Dex> {
        match s {
            "raydium_v4" => Some(Dex::RaydiumV4),
            "raydium_cpmm" => Some(Dex::RaydiumCpmm),
            "pumpswap" => Some(Dex::PumpSwap),
            _ => None,
        }
    }

    pub fn all() -> [Dex; 3] {
        [Dex::RaydiumV4, Dex::RaydiumCpmm, Dex::PumpSwap]
    }
}

/// The account-index map for a pool-creation instruction, i.e. which entry in
/// the instruction's `accounts` array holds each field we care about.
///
/// Indices are into the *instruction-local* account list (already resolved
/// against the transaction's full account-key table, including ALT lookups).
#[derive(Debug, Clone, Copy)]
pub struct PoolAccountLayout {
    pub pool: usize,
    pub base_mint: usize,
    pub quote_mint: usize,
    /// Vault (SPL token account) holding the base side. Verified to hold
    /// `base_mint`; see the note on fee accounts below.
    pub base_vault: usize,
    /// Vault holding the quote side. Verified to hold `quote_mint`.
    pub quote_vault: usize,
    /// LP mint. Confirmed by cross-reference: in each verified creation tx a
    /// token account holding this mint is owned by the pool creator (v4/CPMM),
    /// and for PumpSwap the LP mint's own mint-authority is the pool itself.
    pub lp_mint: usize,
    /// Accounts needed to later BUILD A SWAP against this pool. They are only
    /// available here — a swap cannot be constructed from the pool address
    /// alone. Indices come from the same verified creation layouts.
    ///   * CPMM  : amm_config = 1, observation = 13
    ///   * v4    : amm_config = 13, open_orders = 6, target_orders = 12, market = 16
    pub amm_config: Option<usize>,
    pub observation: Option<usize>,
    pub open_orders: Option<usize>,
    pub target_orders: Option<usize>,
    pub market: Option<usize>,
    /// Minimum number of accounts the instruction must reference for the layout
    /// to be plausible — cheap guard against false positives.
    pub min_accounts: usize,
}

impl Dex {
    /// Account layout for this DEX's pool-creation instruction.
    ///
    /// VERIFIED against live mainnet transactions (2026-07-19). Each layout below
    /// was confirmed by decoding a real creation tx and checking every account's
    /// on-chain owner / type. See `parser::tests` for the captured fixtures.
    ///
    /// Raydium v4 `initialize2` — 21 accounts
    /// (tx 4kAcRNUt5UXPFGJVf22gv7ziNPosBQGZuvFto9RP9TGC1s8zoaqv9SR6qH8jeBDnthyFGk9vcGPfhggWVmCEkpP9):
    ///   0 token_program, 1 ata_program, 2 system, 3 rent, 4 amm(pool),
    ///   5 amm_authority, 6 open_orders, 7 lp_mint, 8 coin_mint(base),
    ///   9 pc_mint(quote), 10 coin_vault, 11 pc_vault, 12 target_orders,
    ///   13 amm_config, 14 create_fee_destination, 15 market_program, 16 market, ...
    ///
    /// Raydium CPMM `initialize` — 20 accounts
    /// (tx 4GEn5CmpSkbatXh2mnrLEy7NB3N63nfdp7sxhhhH5jooFNmtgDEpAieAcVuwusEYhGN7sfNMNYiYc8Q3PiyhLvbc):
    ///   0 creator, 1 amm_config, 2 authority, 3 pool_state, 4 token_0_mint,
    ///   5 token_1_mint, 6 lp_mint, 7 creator_lp, 8..11 vaults/creator atas,
    ///   12 create_pool_fee, 13 observation_state, ...
    ///
    /// PumpSwap `create_pool` — 18 accounts
    /// (tx 4owTBz32K9qiLvVDtnsCVgnCG3mdDnoPTxuBaHxghotVRrnzXYZBLwbYttZrz97ttZMxNJvJHQCyhnqfR5KSJHdb):
    ///   0 pool, 1 global_config, 2 creator, 3 base_mint, 4 quote_mint,
    ///   5 lp_mint, ...
    ///
    /// IMPORTANT — mint orientation is NOT consistent across venues. Observed:
    ///   * Raydium v4:  base = new token, quote = WSOL
    ///   * Raydium CPMM: base = WSOL,      quote = new token   (reversed!)
    ///   * PumpSwap:     base = WSOL,      quote = new token   (reversed!)
    /// Never assume the base side is the launched token — `Detector::classify`
    /// resolves this by testing BOTH mints against the known quote assets.
    ///
    /// VAULTS (verified 2026-07-19 by reading each account's on-chain `mint`
    /// and `owner`): Raydium vaults are owned by the AMM authority, PumpSwap's
    /// by the pool account itself. Vault at `base_vault` holds `base_mint`,
    /// `quote_vault` holds `quote_mint`.
    ///
    /// DO NOT locate vaults by scanning for "a token account holding WSOL".
    /// Both Raydium creation instructions also reference the protocol's
    /// create-pool FEE account, which is itself a WSOL token account holding
    /// hundreds-to-thousands of SOL (observed: 699 SOL at v4 index 14, 4598 SOL
    /// at CPMM index 12). A scan-based match reads the fee account and reports
    /// enormous liquidity for an empty pool. Fixed indices are required.
    pub fn layout(self) -> PoolAccountLayout {
        match self {
            Dex::RaydiumV4 => PoolAccountLayout {
                pool: 4,
                base_mint: 8,
                quote_mint: 9,
                base_vault: 10,
                quote_vault: 11,
                lp_mint: 7,
                amm_config: Some(13),
                observation: None,
                open_orders: Some(6),
                target_orders: Some(12),
                market: Some(16),
                min_accounts: 17,
            },
            Dex::RaydiumCpmm => PoolAccountLayout {
                pool: 3,
                base_mint: 4,
                quote_mint: 5,
                base_vault: 10,
                quote_vault: 11,
                lp_mint: 6,
                amm_config: Some(1),
                observation: Some(13),
                open_orders: None,
                target_orders: None,
                market: None,
                min_accounts: 13,
            },
            Dex::PumpSwap => PoolAccountLayout {
                pool: 0,
                base_mint: 3,
                quote_mint: 4,
                base_vault: 9,
                quote_vault: 10,
                lp_mint: 5,
                amm_config: Some(1), // global_config (index 2 is the CREATOR)
                observation: None,
                open_orders: None,
                target_orders: None,
                market: None,
                min_accounts: 11,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Detected pool event
// ---------------------------------------------------------------------------

/// Extra accounts, captured from the creation instruction, that a later swap
/// needs. Which fields are populated depends on the venue.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SwapAccounts {
    pub amm_config: Option<String>,
    pub observation: Option<String>,
    pub open_orders: Option<String>,
    pub target_orders: Option<String>,
    pub market: Option<String>,
    /// PumpSwap only. An account the deployed program requires as a
    /// `remaining_account` but its published IDL never documents. It cannot be
    /// derived (≈400 candidate PDA seeds failed); it is CAPTURED from the pool's
    /// own creation transaction, where the migration `buy` carries it.
    pub pool_v2: Option<String>,
}

/// A newly-detected tradable liquidity pool. This is the unit that flows from
/// the parser → filters → alerts + storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolEvent {
    pub dex: Dex,
    /// Pool / AMM account (base58).
    pub pool: String,
    /// The two mints in the pool (base58).
    pub base_mint: String,
    pub quote_mint: String,
    /// The mint that is *not* a known quote asset — i.e. the newly launched token.
    /// `None` if we could not classify (e.g. exotic pair).
    pub new_token_mint: Option<String>,
    /// The recognized quote asset (WSOL/USDC), if any.
    pub quote_asset: Option<String>,
    /// Vault holding the quote asset — the side that measures real committed
    /// capital. `None` when the pair has no recognized quote asset.
    pub quote_asset_vault: Option<String>,
    /// Quote-side liquidity in UI units (SOL or USDC), read shortly after
    /// creation. `None` if the check is disabled or the read failed.
    pub quote_liquidity: Option<f64>,
    /// Mint authority revoked on the launched token? `None` = not checked or
    /// unreadable. `Some(false)` means supply can still be inflated at will.
    pub mint_authority_revoked: Option<bool>,
    /// Freeze authority revoked? `Some(false)` is the classic honeypot shape:
    /// buyers can be frozen out of selling.
    pub freeze_authority_revoked: Option<bool>,
    /// Token-2022 extensions that can tax or block a sale. Empty when clean.
    #[serde(default)]
    pub risky_extensions: Vec<String>,
    /// LP mint for this pool.
    #[serde(default)]
    pub lp_mint: Option<String>,
    /// Pool vaults, in the pool's own (base, quote) order.
    #[serde(default)]
    pub base_vault: Option<String>,
    #[serde(default)]
    pub quote_vault: Option<String>,
    /// Accounts required to build a swap against this pool. Captured at
    /// detection because they cannot be recovered from the pool address alone.
    #[serde(default)]
    pub swap_accounts: SwapAccounts,
    /// LP supply observed at detection time. Compared against a later re-read to
    /// tell whether LP was burned. Burning is a LATER transaction, so this value
    /// alone says nothing about rug risk.
    #[serde(default)]
    pub lp_supply_at_detection: Option<f64>,
    /// Transaction signature that created the pool (base58).
    pub signature: String,
    /// Slot the creating transaction landed in.
    pub slot: u64,
    /// Detection timestamp (UTC).
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

impl PoolEvent {
    /// Vault addresses, kept on the event so the execution path does not have
    /// to re-derive orientation. Errors rather than guessing when absent.
    #[cfg(feature = "sniper")]
    pub fn base_vault_or_err(&self) -> anyhow::Result<String> {
        self.base_vault
            .clone()
            .ok_or_else(|| anyhow::anyhow!("event has no base vault recorded"))
    }
    #[cfg(feature = "sniper")]
    pub fn quote_vault_or_err(&self) -> anyhow::Result<String> {
        self.quote_vault
            .clone()
            .ok_or_else(|| anyhow::anyhow!("event has no quote vault recorded"))
    }

    /// Solscan links, handy for both logs and alerts.
    pub fn solscan_tx(&self) -> String {
        format!("https://solscan.io/tx/{}", self.signature)
    }
    pub fn solscan_pool(&self) -> String {
        format!("https://solscan.io/account/{}", self.pool)
    }
    pub fn solscan_token(&self) -> Option<String> {
        self.new_token_mint
            .as_ref()
            .map(|m| format!("https://solscan.io/token/{m}"))
    }
}
