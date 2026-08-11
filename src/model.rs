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
/// Meteora DAMM v2 (CP-AMM). Constant-product, so the existing quote math is
/// the right shape for it — unlike DLMM, which is bin-based.
pub const METEORA_DAMM_V2_PROGRAM: &str = "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG";
/// Meteora DBC (Dynamic Bonding Curve) — Meteora's launchpad. This is where new
/// tokens are actually MINTED: `initialize_virtual_pool_with_*` creates the mint
/// and two real SPL vaults in one instruction. (DAMM v2 pool creation, by
/// contrast, never mints a token — verified across every sampled creation — so
/// it is not a launch signal.) Also emits the graduation to DAMM v2.
pub const METEORA_DBC_PROGRAM: &str = "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN";
/// Meteora DLMM (LB CLMM). Bin-based concentrated liquidity: price comes from
/// the active bin, NOT from a reserve ratio, and there is no LP mint. Detection
/// only — the constant-product quote path must never be used for it.
pub const METEORA_DLMM_PROGRAM: &str = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";

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

/// Meteora DBC launch, classic SPL mint. sha256("global:\
/// initialize_virtual_pool_with_spl_token")[..8]. Verified by unit test AND
/// against mainnet tx 2WJXvS2x623aLoGgvLupBdzPkcwimPKsFkVxcGJTfJ1GyhAxmQNkKFYe5is7v74G5TbZNqDrXhmHkyCBMfdgTXL7.
pub const DBC_INIT_POOL_SPL_DISC: [u8; 8] = [0x8c, 0x55, 0xd7, 0xb0, 0x66, 0x36, 0x68, 0x4f];
/// Meteora DBC launch, Token-2022 mint. Same account layout at indices 0..=7 as
/// the SPL variant, so one layout serves both. Verified against mainnet tx
/// 66LvEhsHRiDEFZjoS2N7fyV5Rp3fSimBWEqvLWwL29Lj7mfjfDPZ7YTpZUfRyg4JfrU47p66KEaTfYYLD13ifMVc.
pub const DBC_INIT_POOL_T22_DISC: [u8; 8] = [0xa9, 0x76, 0x33, 0x4e, 0x91, 0x6e, 0xdc, 0x9b];
/// Meteora DBC graduation: the bonding curve fills and migrates to a DAMM v2
/// pool. HIGH signal — a token that graduated has proven real demand. Emitted by
/// the DBC program (not CP-AMM), so watching DBC alone catches launch AND
/// graduation. Verified against mainnet tx
/// 5TAQCfmz727hFKAs4c3ohfSNB6R66Q35ZwJ4c624JFbKKzTW7gjA3zHiBihqcJgFmrzKNgr9TeANLsEBhNymgq6D.
pub const DBC_MIGRATION_DAMM_V2_DISC: [u8; 8] = [0x9c, 0xa9, 0xe6, 0x67, 0x35, 0xe4, 0x50, 0x40];

/// Meteora DLMM pool creation — four variants, all live on mainnet. They share
/// an IDENTICAL account layout at indices 0..=6 (verified across 29 creation
/// transactions, 100% agreement), so one layout serves all four. Index 7 onward
/// differs per variant and is deliberately not used.
pub const DLMM_INIT_LB_PAIR_DISC: [u8; 8] = [0x2d, 0x9a, 0xed, 0xd2, 0xdd, 0x0f, 0xa6, 0x5c];
/// The variant current launchpad/migration flows use, and the only one
/// supporting Token-2022.
pub const DLMM_INIT_LB_PAIR2_DISC: [u8; 8] = [0x49, 0x3b, 0x24, 0x78, 0xed, 0x53, 0x6c, 0xc6];
pub const DLMM_INIT_CUSTOM_LB_PAIR_DISC: [u8; 8] =
    [0x2e, 0x27, 0x29, 0x87, 0x6f, 0xb7, 0xc8, 0x40];
pub const DLMM_INIT_CUSTOM_LB_PAIR2_DISC: [u8; 8] =
    [0xf3, 0x49, 0x81, 0x7e, 0x33, 0x13, 0xf1, 0x6b];

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
    MeteoraDammV2,
    MeteoraDlmm,
    /// Meteora DBC — the launchpad where new tokens are minted, plus their
    /// graduation to DAMM v2.
    MeteoraDbc,
}

impl Dex {
    pub fn program_id(self) -> &'static str {
        match self {
            Dex::RaydiumV4 => RAYDIUM_V4_PROGRAM,
            Dex::RaydiumCpmm => RAYDIUM_CPMM_PROGRAM,
            Dex::PumpSwap => PUMPSWAP_PROGRAM,
            Dex::MeteoraDammV2 => METEORA_DAMM_V2_PROGRAM,
            Dex::MeteoraDlmm => METEORA_DLMM_PROGRAM,
            Dex::MeteoraDbc => METEORA_DBC_PROGRAM,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Dex::RaydiumV4 => "Raydium AMM v4",
            Dex::RaydiumCpmm => "Raydium CPMM",
            Dex::PumpSwap => "PumpSwap",
            Dex::MeteoraDammV2 => "Meteora DAMM v2",
            Dex::MeteoraDlmm => "Meteora DLMM",
            Dex::MeteoraDbc => "Meteora DBC",
        }
    }

    /// Config token used to enable/disable this DEX.
    pub fn config_key(self) -> &'static str {
        match self {
            Dex::RaydiumV4 => "raydium_v4",
            Dex::RaydiumCpmm => "raydium_cpmm",
            Dex::PumpSwap => "pumpswap",
            Dex::MeteoraDammV2 => "meteora_damm_v2",
            Dex::MeteoraDlmm => "meteora_dlmm",
            Dex::MeteoraDbc => "meteora_dbc",
        }
    }

    pub fn from_config_key(s: &str) -> Option<Dex> {
        match s {
            "raydium_v4" => Some(Dex::RaydiumV4),
            "raydium_cpmm" => Some(Dex::RaydiumCpmm),
            "pumpswap" => Some(Dex::PumpSwap),
            "meteora_damm_v2" | "meteora_damm2" => Some(Dex::MeteoraDammV2),
            "meteora_dlmm" => Some(Dex::MeteoraDlmm),
            "meteora_dbc" | "meteora" => Some(Dex::MeteoraDbc),
            _ => None,
        }
    }

    pub fn all() -> [Dex; 6] {
        [
            Dex::RaydiumV4,
            Dex::RaydiumCpmm,
            Dex::PumpSwap,
            Dex::MeteoraDammV2,
            Dex::MeteoraDlmm,
            Dex::MeteoraDbc,
        ]
    }

    /// Can the hand-built execution path trade this venue?
    ///
    /// FALSE means detection and alerts only. The buy path assumes a
    /// constant-product pool priced by its reserve ratio; a venue that does not
    /// work that way (DLMM prices from the active bin) would be mispriced by
    /// every quote, so it must be refused rather than approximated.
    pub fn is_tradable(self) -> bool {
        match self {
            Dex::RaydiumV4 | Dex::RaydiumCpmm | Dex::PumpSwap => true,
            Dex::MeteoraDammV2 | Dex::MeteoraDlmm | Dex::MeteoraDbc => false,
        }
    }
}

/// Account map for a Meteora DBC GRADUATION (`migration_damm_v2`): the bonding
/// curve filled and a real DAMM v2 pool was created. Different shape from the
/// launch instruction — the pool is the new DAMM v2 pool at index 4, and the
/// mints/vaults sit much later. Base is A and quote is B here, unlike direct
/// DAMM v2 creations which have no reliable ordering.
pub const DBC_MIGRATION_LAYOUT: PoolAccountLayout = PoolAccountLayout {
    pool: 4,
    base_mint: 13,
    quote_mint: 14,
    base_vault: 15,
    quote_vault: 16,
    lp_mint: None,
    amm_config: None,
    observation: None,
    open_orders: None,
    target_orders: None,
    market: None,
    min_accounts: 26,
};

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
    /// LP mint, when the venue has one. `None` for venues that track liquidity
    /// with position NFTs or a bonding curve instead (Meteora DBC / DAMM v2 /
    /// DLMM) — verified on mainnet: their creation instructions reference no LP
    /// mint at all. A `None` here means the LP-burn signal is simply unavailable
    /// for that venue, which the watcher must treat as "unknown", not "unburnt".
    pub lp_mint: Option<usize>,
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
                lp_mint: Some(7),
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
                lp_mint: Some(6),
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
                lp_mint: Some(5),
                amm_config: Some(1), // global_config (index 2 is the CREATOR)
                observation: None,
                open_orders: None,
                target_orders: None,
                market: None,
                min_accounts: 11,
            },
            // NOT YET VERIFIED against mainnet transactions. `min_accounts:
            // usize::MAX` makes this layout impossible to match, so it cannot
            // silently mis-parse a pool while the real indices are still being
            // derived. Detection for these venues is separately gated off in
            // `parser::is_pool_creation`.
            // Meteora DBC LAUNCH (`initialize_virtual_pool_with_spl_token` /
            // `_with_token2022`). Indices 0..=7 are IDENTICAL across both
            // variants — the SPL form has 16 accounts and the Token-2022 form
            // 14, differing only in trailing metadata accounts — so one layout
            // serves both. Verified on mainnet: base_vault/quote_vault are real
            // SPL token accounts owned by the DBC pool_authority, and the base
            // mint is created in the same transaction.
            //
            // There is NO LP mint: liquidity lives in the bonding curve.
            Dex::MeteoraDbc => PoolAccountLayout {
                pool: 5,
                base_mint: 3,
                quote_mint: 4,
                base_vault: 6,
                quote_vault: 7,
                lp_mint: None,
                amm_config: None,
                observation: None,
                open_orders: None,
                target_orders: None,
                market: None,
                min_accounts: 14,
            },
            // Meteora DLMM. Indices 0..=6 verified identical across all four
            // creation variants. `reserve_x`/`reserve_y` are plain SPL token
            // accounts owned by the pair PDA and dedicated to it, so a normal
            // getTokenAccountBalance is a valid liquidity read — unlike DAMM v1,
            // whose reserves live in shared, lending-deployed vaults.
            //
            // CAVEAT: the reserve is total liquidity across ALL bins, including
            // bins far from the active price that are not tradable at spot. It
            // is an upper bound on real depth, so the liquidity filter is
            // looser here than on a constant-product venue.
            //
            // No LP mint: proven by exhaustively resolving every 32-byte window
            // of a 904-byte LbPair account — the only mints present are X and Y.
            Dex::MeteoraDlmm => PoolAccountLayout {
                pool: 0,
                base_mint: 2,
                quote_mint: 3,
                base_vault: 4,
                quote_vault: 5,
                lp_mint: None,
                amm_config: None,
                observation: None,
                open_orders: None,
                target_orders: None,
                market: None,
                min_accounts: 14,
            },
            Dex::MeteoraDammV2 => PoolAccountLayout {
                pool: 0,
                base_mint: 0,
                quote_mint: 0,
                base_vault: 0,
                quote_vault: 0,
                lp_mint: None,
                amm_config: None,
                observation: None,
                open_orders: None,
                target_orders: None,
                market: None,
                min_accounts: usize::MAX,
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
    /// Token name from on-chain metadata (Metaplex), when resolvable. Enrichment
    /// only — never gates a trade. Absent for tokens with no metadata account or
    /// when name resolution is disabled.
    #[serde(default)]
    pub token_name: Option<String>,
    /// Token symbol/ticker from metadata, when resolvable.
    #[serde(default)]
    pub token_symbol: Option<String>,
    /// Transaction signature that created the pool (base58).
    pub signature: String,
    /// Slot the creating transaction landed in.
    pub slot: u64,
    /// Detection timestamp (UTC).
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

impl PoolEvent {
    /// A human label for the token: `"Name (SYM)"`, or just one if only one is
    /// known, or None if neither was resolved. For alert headers so a pool is
    /// recognizable at a glance instead of a 44-char mint.
    pub fn token_label(&self) -> Option<String> {
        match (self.token_name.as_deref(), self.token_symbol.as_deref()) {
            (Some(n), Some(s)) if !n.is_empty() && !s.is_empty() => Some(format!("{n} ({s})")),
            (Some(n), _) if !n.is_empty() => Some(n.to_string()),
            (_, Some(s)) if !s.is_empty() => Some(s.to_string()),
            _ => None,
        }
    }

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
