//! Transaction construction for the execution path (step 2).
//!
//! Builds and signs transactions. It does **not** submit them — there is no
//! `sendTransaction` call anywhere in this module, by design. Submission is a
//! separate step behind the still-refused `armed` flag.
//!
//! # Why the Solana crates here, but not for RPC reads
//!
//! `rpc.rs` deliberately avoids `solana-client` — two JSON-RPC methods do not
//! justify the dependency. That reasoning does not transfer to transaction
//! building: PDA derivation (off-curve checks over curve25519), message
//! serialization, and signing are exactly the primitives you must not hand-roll
//! in code that moves money. So this module uses the official split crates,
//! all optional and gated behind the `sniper` feature so a detector-only build
//! pays nothing for them.

use anyhow::{Context, Result, bail};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spl_associated_token_account_interface::address::get_associated_token_address_with_program_id;
use spl_associated_token_account_interface::instruction::create_associated_token_account_idempotent;
use std::str::FromStr;

/// Wrapped SOL mint.
pub const WSOL: Pubkey =
    Pubkey::from_str_const("So11111111111111111111111111111111111111112");
/// SPL Token program.
pub const TOKEN_PROGRAM: Pubkey =
    Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// Raydium CPMM program.
pub const CPMM_PROGRAM: Pubkey =
    Pubkey::from_str_const("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
/// Raydium AMM v4 program.
pub const V4_PROGRAM: Pubkey =
    Pubkey::from_str_const("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");
/// OpenBook (Serum v3) program — v4 pools reference a market on it.
pub const OPENBOOK_PROGRAM: Pubkey =
    Pubkey::from_str_const("srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX");

/// Seed for the CPMM vault/LP-mint authority PDA. Asserted against the
/// authority observed in real swaps by unit test.
const CPMM_AUTH_SEED: &[u8] = b"vault_and_lp_mint_auth_seed";

/// A loaded signing keypair.
///
/// Constructing one is the only way to obtain signing capability; there is no
/// `Default` and no way to build it from thin air. Held only when the operator
/// has explicitly pointed at a key file.
pub struct Wallet {
    keypair: Keypair,
}

/// Manual `Debug` that prints ONLY the public key.
///
/// Deliberately not `#[derive(Debug)]`: a derived impl would render the secret
/// key bytes, and this type ends up inside error paths and structs that may be
/// logged. The private half must never be printable.
impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("pubkey", &self.pubkey())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Wallet {
    /// Load a Solana CLI keypair file (JSON array of 64 bytes).
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading keypair {path}"))?;
        let bytes: Vec<u8> =
            serde_json::from_str(&raw).with_context(|| format!("parsing keypair {path}"))?;
        if bytes.len() != 64 {
            bail!("keypair {path}: expected 64 bytes, got {}", bytes.len());
        }
        let keypair = Keypair::try_from(&bytes[..])
            .map_err(|e| anyhow::anyhow!("invalid keypair {path}: {e}"))?;
        Ok(Self { keypair })
    }

    pub fn pubkey(&self) -> Pubkey {
        self.keypair.pubkey()
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Generate a fresh keypair and write it to `path` in the Solana CLI format
    /// (`load` reads it back). Returns the new public address.
    ///
    /// # Safety properties
    ///
    /// * **The key is born here and is never transmitted.** This is the entire
    ///   point of generating locally rather than importing an existing key:
    ///   nothing carries the secret across a network, a chat, or a clipboard.
    /// * **Refuses to overwrite.** An existing file at `path` may be a funded
    ///   wallet; clobbering its key would destroy access to those funds. A
    ///   collision is a hard error, never a silent replace.
    /// * **Owner-only permissions (0600).** A private key must not be
    ///   world-readable. Set before the bytes are written, so there is no window
    ///   where the file exists with looser permissions.
    /// * **Only the PUBLIC address is ever returned or logged.** The secret
    ///   exists solely inside the file. Nothing in this function prints it.
    pub fn generate(path: &str) -> Result<Pubkey> {
        if std::path::Path::new(path).exists() {
            bail!(
                "refusing to overwrite existing keypair {path} — it may hold funds. \
                 Pick a new path or delete it deliberately first."
            );
        }

        let keypair = Keypair::new();
        let pubkey = keypair.pubkey();
        let json = serde_json::to_string(&keypair.to_bytes().to_vec())
            .context("serializing keypair")?;

        // Create with 0600 from the outset on unix, so the secret is never
        // briefly readable by others between create and chmod.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("creating keypair file {path}"))?;
            f.write_all(json.as_bytes())
                .with_context(|| format!("writing keypair file {path}"))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, json.as_bytes())
                .with_context(|| format!("writing keypair file {path}"))?;
        }

        Ok(pubkey)
    }
}

/// Associated token account address for `owner`/`mint` under the SPL Token program.
pub fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    get_associated_token_address_with_program_id(owner, mint, &TOKEN_PROGRAM)
}

/// The CPMM vault/LP authority PDA. Constant for the program.
pub fn cpmm_authority() -> Pubkey {
    Pubkey::find_program_address(&[CPMM_AUTH_SEED], &CPMM_PROGRAM).0
}

/// Compute-budget preamble: an explicit unit limit plus a priority fee.
///
/// Both matter for a sniper: without a raised limit the swap can exceed the
/// default budget and fail, and without a priority fee it will not land in a
/// contested block.
pub fn compute_budget(unit_limit: u32, priority_fee_micro_lamports: u64) -> Vec<Instruction> {
    vec![
        ComputeBudgetInstruction::set_compute_unit_limit(unit_limit),
        ComputeBudgetInstruction::set_compute_unit_price(priority_fee_micro_lamports),
    ]
}

/// Instructions to fund a WSOL account: create the ATA (idempotent), move
/// lamports into it, then `sync_native` so the token balance reflects them.
///
/// `sync_native` is essential — without it the account holds lamports but
/// reports a zero token balance and the swap fails.
pub fn wrap_sol(owner: &Pubkey, lamports: u64) -> Vec<Instruction> {
    let wsol_ata = ata(owner, &WSOL);
    vec![
        create_associated_token_account_idempotent(owner, owner, &WSOL, &TOKEN_PROGRAM),
        solana_system_interface::instruction::transfer(owner, &wsol_ata, lamports),
        spl_token_interface::instruction::sync_native(&TOKEN_PROGRAM, &wsol_ata)
            .expect("sync_native builder"),
    ]
}

/// Close the WSOL account, returning any unspent lamports to the owner.
///
/// Always append this: a partially filled swap otherwise strands SOL in a
/// wrapped account.
pub fn unwrap_sol(owner: &Pubkey) -> Result<Instruction> {
    let wsol_ata = ata(owner, &WSOL);
    spl_token_interface::instruction::close_account(&TOKEN_PROGRAM, &wsol_ata, owner, owner, &[])
        .map_err(|e| anyhow::anyhow!("close_account: {e}"))
}

/// Create the destination token ATA if it does not exist (classic SPL Token).
pub fn ensure_token_ata(owner: &Pubkey, mint: &Pubkey) -> Instruction {
    ensure_token_ata_with_program(owner, mint, &TOKEN_PROGRAM)
}

/// As above, but for a mint owned by a specific token program.
///
/// Token-2022 mints are common (most pump.fun launches), and creating their ATA
/// under the classic program fails with `IncorrectProgramId`. Always pass the
/// mint's actual owner rather than assuming.
pub fn ensure_token_ata_with_program(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    create_associated_token_account_idempotent(owner, owner, mint, token_program)
}

/// Token-2022 program.
pub const TOKEN_2022_PROGRAM: Pubkey =
    Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

// ---------------------------------------------------------------------------
// Raydium AMM v4
// ---------------------------------------------------------------------------

/// The fields of an OpenBook (Serum v3) market that a v4 swap must pass.
///
/// A v4 swap needs bids/asks/event-queue/market-vaults, and NONE of them appear
/// in the pool-creation instruction — they live inside the market account, so
/// they must be read and decoded.
///
/// Layout verified against a live market (388 bytes) by decoding it and
/// comparing every field to the accounts a real swap actually passed.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenBookMarket {
    pub vault_signer_nonce: u64,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub base_vault: Pubkey,
    pub quote_vault: Pubkey,
    pub event_queue: Pubkey,
    pub bids: Pubkey,
    pub asks: Pubkey,
}

impl OpenBookMarket {
    /// Serum v3 `MarketState` is a fixed 388-byte layout.
    pub const LEN: usize = 388;

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != Self::LEN {
            bail!("openbook market: expected {} bytes, got {}", Self::LEN, raw.len());
        }
        let key = |lo: usize| -> Pubkey {
            let mut b = [0u8; 32];
            b.copy_from_slice(&raw[lo..lo + 32]);
            Pubkey::new_from_array(b)
        };
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&raw[45..53]);

        Ok(Self {
            vault_signer_nonce: u64::from_le_bytes(nonce),
            base_mint: key(53),
            quote_mint: key(85),
            base_vault: key(117),
            quote_vault: key(165),
            event_queue: key(253),
            bids: key(285),
            asks: key(317),
        })
    }

    /// The market's vault signer, derived from the market address and its nonce.
    ///
    /// Uses `create_program_address` (not `find_program_address`): the nonce is
    /// stored in the market, so the exact seed is known and searching for a bump
    /// would produce a different, wrong address.
    pub fn vault_signer(&self, market: &Pubkey) -> Result<Pubkey> {
        Pubkey::create_program_address(
            &[market.as_ref(), &self.vault_signer_nonce.to_le_bytes()],
            &OPENBOOK_PROGRAM,
        )
        .map_err(|e| anyhow::anyhow!("market vault signer: {e}"))
    }
}

/// Accounts a Raydium v4 swap needs.
///
/// `coin`/`pc` follow the POOL's own ordering, which varies per pool — some
/// have WSOL as coin, others as pc. The swap direction is expressed purely
/// through `user_source` / `user_destination`, so these two are passed in
/// pool order regardless of which way the trade goes.
#[derive(Debug, Clone)]
pub struct V4SwapAccounts {
    pub amm: Pubkey,
    pub amm_open_orders: Pubkey,
    /// Optional. Including it produces the 18-account form and shifts every
    /// later index by one — see `swap::V4SwapShape`.
    pub amm_target_orders: Option<Pubkey>,
    pub pool_coin_vault: Pubkey,
    pub pool_pc_vault: Pubkey,
    pub market: Pubkey,
    pub market_state: OpenBookMarket,
    /// User account holding the asset being SPENT.
    pub user_source: Pubkey,
    /// User account receiving the asset being BOUGHT.
    pub user_destination: Pubkey,
    pub user_owner: Pubkey,
}

/// The Raydium v4 pool authority. A fixed PDA for the program.
pub fn v4_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"amm authority"], &V4_PROGRAM).0
}

/// Encode a Raydium v4 `swapBaseIn`: spend exactly `amount_in`, require at
/// least `minimum_amount_out`.
///
/// Emits the 17- or 18-account form depending on whether `amm_target_orders` is
/// supplied. Both occur in live traffic and the index map differs between them.
pub fn v4_swap_base_in(
    a: &V4SwapAccounts,
    amount_in: u64,
    minimum_amount_out: u64,
) -> Result<Instruction> {
    let mut data = Vec::with_capacity(17);
    data.push(crate::swap::RAYDIUM_V4_SWAP_BASE_IN_TAG);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());

    let vault_signer = a.market_state.vault_signer(&a.market)?;

    let mut accounts = vec![
        AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        AccountMeta::new(a.amm, false),
        AccountMeta::new_readonly(v4_authority(), false),
        AccountMeta::new(a.amm_open_orders, false),
    ];
    if let Some(target) = a.amm_target_orders {
        accounts.push(AccountMeta::new(target, false));
    }
    accounts.extend([
        AccountMeta::new(a.pool_coin_vault, false),
        AccountMeta::new(a.pool_pc_vault, false),
        AccountMeta::new_readonly(OPENBOOK_PROGRAM, false),
        AccountMeta::new(a.market, false),
        AccountMeta::new(a.market_state.bids, false),
        AccountMeta::new(a.market_state.asks, false),
        AccountMeta::new(a.market_state.event_queue, false),
        AccountMeta::new(a.market_state.base_vault, false),
        AccountMeta::new(a.market_state.quote_vault, false),
        AccountMeta::new_readonly(vault_signer, false),
        AccountMeta::new(a.user_source, false),
        AccountMeta::new(a.user_destination, false),
        AccountMeta::new_readonly(a.user_owner, true),
    ]);

    debug_assert_eq!(
        accounts.len(),
        if a.amm_target_orders.is_some() { 18 } else { 17 }
    );
    Ok(Instruction { program_id: V4_PROGRAM, accounts, data })
}

// ---------------------------------------------------------------------------
// PumpSwap — PDA derivations (verified) ; encoder NOT shipped, see below
// ---------------------------------------------------------------------------

/// PumpSwap (Pump AMM) program.
pub const PUMPSWAP_PROGRAM: Pubkey =
    Pubkey::from_str_const("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA");
/// Pump fee program, referenced by PumpSwap's newer swap tail.
pub const PUMP_FEE_PROGRAM: Pubkey =
    Pubkey::from_str_const("pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ");

/// PDA derivations for PumpSwap, each verified against accounts observed in
/// real mainnet swaps (see tests).
///
/// # PumpSwap status: encoder verified, one account short
///
/// Layouts, args and PDA seeds all come from the program's ON-CHAIN Anchor IDL
/// (account `5fLnXNNoZcZt9Qku6HARM3un3Ttm2cGsR7gN9Zp1R7h3`; Anchor stores it as
/// `8 disc + 32 authority + 4 len + zlib JSON`). `pumpswap_buy` reproduces a
/// real mainnet buy byte-for-byte — see `tx::tests`.
///
/// What the IDL settled that sampling could not:
///   * `buy` declares **23** accounts, `sell` **21**. The 25/26/27-account forms
///     seen on-chain pass the extras as Anchor `remaining_accounts`, which is
///     why the tail looked variable-length and underivable.
///   * `Pool.coin_creator` is at **offset 211**; it seeds
///     `creator_vault_authority` and is frequently all-zero, which is why one
///     authority appeared to serve many pools.
///   * `GlobalConfig.protocol_fee_recipients` is a fixed array of **8** pubkeys
///     at **offset 57**. A real buy used slot 3, another slot 1 — any is valid.
///   * The trailing `OptionBool` is `struct(bool)`, one byte.
///   * Only the **LP fee** is charged on the curve; protocol and creator fees
///     come off the output.
///
/// ## The undocumented trailing accounts — SOLVED
///
/// The deployed program is NEWER than its published IDL: the IDL's error list
/// ends at 6058, but a swap throws `InvalidPoolV2` (6062). Three accounts must
/// follow the declared list, none of them documented:
///
/// ```text
/// [ ...23 declared..., pool_v2, buyback_fee_recipient, buyback_recipient_ata ]
/// ```
///
/// * **`pool_v2`** — not derivable (~400 candidate PDA seeds failed) and usually
///   UNINITIALIZED, so it cannot be found from chain state either. It is carried
///   in the pool's own CREATION transaction, inside the migration `buy` that
///   runs in the same transaction, as that buy's first remaining account. A
///   detector that parses creations already sees it, so it is CAPTURED rather
///   than derived — see `parser::find_pumpswap_pool_v2`.
/// * **`buyback_fee_recipient`** — any live slot of
///   `GlobalConfig.buyback_fee_recipients` (offset 643, 8 slots). This is a
///   DIFFERENT set from `protocol_fee_recipients` (offset 57); passing one of
///   those here fails with `BuybackFeeRecipientNotAuthorized` (6053). Being a
///   registered set rather than PDAs is exactly why no seed reproduced them and
///   why the same few accounts recur across unrelated pools.
/// * **`buyback_recipient_ata`** — a plain `ata(recipient, quote_mint)`.
///
/// VERIFIED end-to-end: a PumpSwap buy built from a detection-shaped event
/// simulates with `err: null`.
pub mod pumpswap_pda {
    use super::*;

    /// `["global_config"]`
    pub fn global_config() -> Pubkey {
        Pubkey::find_program_address(&[b"global_config"], &PUMPSWAP_PROGRAM).0
    }
    /// `["__event_authority"]`
    pub fn event_authority() -> Pubkey {
        Pubkey::find_program_address(&[b"__event_authority"], &PUMPSWAP_PROGRAM).0
    }
    /// `["global_volume_accumulator"]` — buy only; absent from `sell`.
    pub fn global_volume_accumulator() -> Pubkey {
        Pubkey::find_program_address(&[b"global_volume_accumulator"], &PUMPSWAP_PROGRAM).0
    }
    /// `["user_volume_accumulator", user]` — buy only.
    pub fn user_volume_accumulator(user: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[b"user_volume_accumulator", user.as_ref()],
            &PUMPSWAP_PROGRAM,
        )
        .0
    }
    /// `["creator_vault", coin_creator]`.
    ///
    /// `coin_creator` lives in the pool account. Both sampled pools had it
    /// unset (all zeroes), which is why the same authority appeared for two
    /// different pools. The field's offset in the 301-byte pool account has NOT
    /// been located, so callers must not assume zero for arbitrary pools.
    pub fn creator_vault_authority(coin_creator: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[b"creator_vault", coin_creator.as_ref()],
            &PUMPSWAP_PROGRAM,
        )
        .0
    }
    /// `["fee_config", pumpswap_program]`, derived on the FEE program.
    pub fn fee_config() -> Pubkey {
        Pubkey::find_program_address(
            &[b"fee_config", PUMPSWAP_PROGRAM.as_ref()],
            &PUMP_FEE_PROGRAM,
        )
        .0
    }
}

/// Raydium CPMM `PoolState`, 637 bytes. Offsets verified by decoding real
/// pools and matching the vaults/mints against known values.
///
/// The fee fields matter enormously: the tradable reserve is the vault balance
/// MINUS the protocol and fund fees sitting inside it. Ignoring them
/// overestimated output by 26% on a sampled pool — see `quote.rs`.
#[derive(Debug, Clone, PartialEq)]
pub struct CpmmPoolState {
    pub amm_config: Pubkey,
    pub token_0_vault: Pubkey,
    pub token_1_vault: Pubkey,
    pub token_0_mint: Pubkey,
    pub token_1_mint: Pubkey,
    pub protocol_fees_token_0: u64,
    pub protocol_fees_token_1: u64,
    pub fund_fees_token_0: u64,
    pub fund_fees_token_1: u64,
}

impl CpmmPoolState {
    pub const LEN: usize = 637;

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != Self::LEN {
            bail!("cpmm pool: expected {} bytes, got {}", Self::LEN, raw.len());
        }
        let key = |lo: usize| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&raw[lo..lo + 32]);
            Pubkey::new_from_array(b)
        };
        let u64at = |lo: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[lo..lo + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Self {
            amm_config: key(8),
            token_0_vault: key(72),
            token_1_vault: key(104),
            token_0_mint: key(168),
            token_1_mint: key(200),
            protocol_fees_token_0: u64at(341),
            protocol_fees_token_1: u64at(349),
            fund_fees_token_0: u64at(357),
            fund_fees_token_1: u64at(365),
        })
    }

    /// Non-swappable amount held inside the token-0 / token-1 vault.
    pub fn unswappable(&self, token_0: bool) -> u64 {
        if token_0 {
            self.protocol_fees_token_0.saturating_add(self.fund_fees_token_0)
        } else {
            self.protocol_fees_token_1.saturating_add(self.fund_fees_token_1)
        }
    }

    /// Tradable reserves given raw vault balances and which side is the input.
    ///
    /// Always route reserve computation through this rather than using vault
    /// balances directly.
    pub fn reserves(
        &self,
        vault_0_balance: u64,
        vault_1_balance: u64,
        input_is_token_0: bool,
    ) -> crate::quote::Reserves {
        let r0 = vault_0_balance.saturating_sub(self.unswappable(true));
        let r1 = vault_1_balance.saturating_sub(self.unswappable(false));
        if input_is_token_0 {
            crate::quote::Reserves { input: r0, output: r1 }
        } else {
            crate::quote::Reserves { input: r1, output: r0 }
        }
    }
}

/// Raydium CPMM `AmmConfig`. Only the trade fee is needed for quoting, and it
/// varies per pool (2500 and 3000 both observed) so it must be read, not assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpmmAmmConfig {
    pub trade_fee_rate: u64,
    pub protocol_fee_rate: u64,
    pub fund_fee_rate: u64,
}

impl CpmmAmmConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < 36 {
            bail!("cpmm amm_config: too short ({} bytes)", raw.len());
        }
        let u64at = |lo: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[lo..lo + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Self {
            trade_fee_rate: u64at(12),
            protocol_fee_rate: u64at(20),
            fund_fee_rate: u64at(28),
        })
    }

    pub fn fee(&self) -> crate::quote::FeeRate {
        crate::quote::cpmm_fee(self.trade_fee_rate)
    }
}


// ---------------------------------------------------------------------------
// PumpSwap (pump_amm) — layouts and args taken from the program's ON-CHAIN IDL
// (account 5fLnXNNoZcZt9Qku6HARM3un3Ttm2cGsR7gN9Zp1R7h3), then confirmed against
// a real mainnet buy.
// ---------------------------------------------------------------------------

/// PumpSwap `Pool`. Offsets from the IDL's field order.
#[derive(Debug, Clone, PartialEq)]
pub struct PumpSwapPool {
    pub creator: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_token_account: Pubkey,
    pub pool_quote_token_account: Pubkey,
    /// Seeds `coin_creator_vault_authority`. Frequently all-zero, which is why
    /// one authority appeared to serve many pools.
    pub coin_creator: Pubkey,
}

impl PumpSwapPool {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        // 8 disc, 1 pool_bump, 2 index, then the pubkeys.
        if raw.len() < 243 {
            bail!("pumpswap pool: too short ({} bytes)", raw.len());
        }
        let key = |lo: usize| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&raw[lo..lo + 32]);
            Pubkey::new_from_array(b)
        };
        Ok(Self {
            creator: key(11),
            base_mint: key(43),
            quote_mint: key(75),
            pool_base_token_account: key(139),
            pool_quote_token_account: key(171),
            coin_creator: key(211),
        })
    }
}

/// PumpSwap `GlobalConfig`. Holds the fee rates and the fixed set of eight
/// protocol fee recipients a swap may name.
#[derive(Debug, Clone, PartialEq)]
pub struct PumpSwapGlobalConfig {
    pub lp_fee_basis_points: u64,
    pub protocol_fee_basis_points: u64,
    pub coin_creator_fee_basis_points: u64,
    /// Wallets that may be named as the swap's `protocol_fee_recipient`
    /// (declared account index 9). Offset 57.
    pub protocol_fee_recipients: [Pubkey; 8],
    /// A DIFFERENT set: fee-program-owned records that may be named as the
    /// buyback fee recipient in the trailing `remaining_accounts`. Offset 643.
    /// These are registered, not derived — which is why no PDA seed reproduces
    /// them and they appear as a small set reused across unrelated pools.
    pub buyback_fee_recipients: [Pubkey; 8],
}

impl PumpSwapGlobalConfig {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        // Must reach the buyback array at 643 + 8*32.
        if raw.len() < 899 {
            bail!("pumpswap global_config: too short ({} bytes)", raw.len());
        }
        let u64at = |lo: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[lo..lo + 8]);
            u64::from_le_bytes(b)
        };
        let read8 = |base: usize| {
            let mut out = [Pubkey::new_from_array([0u8; 32]); 8];
            for (i, slot) in out.iter_mut().enumerate() {
                let lo = base + i * 32;
                let mut b = [0u8; 32];
                b.copy_from_slice(&raw[lo..lo + 32]);
                *slot = Pubkey::new_from_array(b);
            }
            out
        };
        Ok(Self {
            lp_fee_basis_points: u64at(40),
            protocol_fee_basis_points: u64at(48),
            coin_creator_fee_basis_points: u64at(313),
            protocol_fee_recipients: read8(57),
            buyback_fee_recipients: read8(643),
        })
    }

    /// Total fee taken on a swap, in basis points.
    pub fn total_fee_bps(&self) -> u64 {
        self.lp_fee_basis_points
            .saturating_add(self.protocol_fee_basis_points)
            .saturating_add(self.coin_creator_fee_basis_points)
    }

    /// Pick a protocol fee recipient (declared account 9). Any of the eight is
    /// valid; real buys were observed using slots 1 and 3. Skips unset slots.
    pub fn pick_fee_recipient(&self, n: usize) -> Result<Pubkey> {
        Self::pick(&self.protocol_fee_recipients, n, "protocol")
    }

    /// Pick a BUYBACK fee recipient for the trailing remaining-accounts.
    ///
    /// Passing a protocol fee recipient here fails with
    /// `BuybackFeeRecipientNotAuthorized` (6053) — the two sets are distinct.
    pub fn pick_buyback_recipient(&self, n: usize) -> Result<Pubkey> {
        Self::pick(&self.buyback_fee_recipients, n, "buyback")
    }

    fn pick(set: &[Pubkey; 8], n: usize, what: &str) -> Result<Pubkey> {
        let zero = Pubkey::new_from_array([0u8; 32]);
        let live: Vec<&Pubkey> = set.iter().filter(|p| **p != zero).collect();
        if live.is_empty() {
            bail!("global_config lists no {what} fee recipients");
        }
        Ok(*live[n % live.len()])
    }
}

/// Accounts for a PumpSwap `buy` / `sell`. Both share indices 0..=18; `buy`
/// additionally passes the two volume accumulators before fee_config.
#[derive(Debug, Clone)]
pub struct PumpSwapSwapAccounts {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_token_account: Pubkey,
    pub pool_quote_token_account: Pubkey,
    pub protocol_fee_recipient: Pubkey,
    pub coin_creator: Pubkey,
    pub base_token_program: Pubkey,
    pub quote_token_program: Pubkey,
}

impl PumpSwapSwapAccounts {
    fn common(&self) -> Vec<AccountMeta> {
        let user_base = get_associated_token_address_with_program_id(
            &self.user, &self.base_mint, &self.base_token_program);
        let user_quote = get_associated_token_address_with_program_id(
            &self.user, &self.quote_mint, &self.quote_token_program);
        // Per the IDL these are ATAs derived with the QUOTE token program.
        let protocol_fee_ata = get_associated_token_address_with_program_id(
            &self.protocol_fee_recipient, &self.quote_mint, &self.quote_token_program);
        let creator_vault_authority = pumpswap_pda::creator_vault_authority(&self.coin_creator);
        let creator_vault_ata = get_associated_token_address_with_program_id(
            &creator_vault_authority, &self.quote_mint, &self.quote_token_program);

        vec![
            AccountMeta::new(self.pool, false),
            AccountMeta::new(self.user, true),
            AccountMeta::new_readonly(pumpswap_pda::global_config(), false),
            AccountMeta::new_readonly(self.base_mint, false),
            AccountMeta::new_readonly(self.quote_mint, false),
            AccountMeta::new(user_base, false),
            AccountMeta::new(user_quote, false),
            AccountMeta::new(self.pool_base_token_account, false),
            AccountMeta::new(self.pool_quote_token_account, false),
            AccountMeta::new_readonly(self.protocol_fee_recipient, false),
            AccountMeta::new(protocol_fee_ata, false),
            AccountMeta::new_readonly(self.base_token_program, false),
            AccountMeta::new_readonly(self.quote_token_program, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(pumpswap_pda::event_authority(), false),
            AccountMeta::new_readonly(PUMPSWAP_PROGRAM, false),
            AccountMeta::new(creator_vault_ata, false),
            AccountMeta::new_readonly(creator_vault_authority, false),
        ]
    }
}

/// Associated Token Account program.
pub const ATA_PROGRAM: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// PumpSwap `buy` — acquire exactly `base_amount_out` of the BASE mint, paying
/// at most `max_quote_amount_in` of the quote mint.
///
/// Note this is exact-OUT: slippage protection is the spend cap, not a minimum
/// received. 23 declared accounts; any trailing `remaining_accounts` seen
/// on-chain are optional extras and are not required.
pub fn pumpswap_buy(
    a: &PumpSwapSwapAccounts,
    base_amount_out: u64,
    max_quote_amount_in: u64,
    track_volume: bool,
) -> Instruction {
    pumpswap_buy_with_remaining(a, base_amount_out, max_quote_amount_in, track_volume, &[])
}

/// As `pumpswap_buy`, plus Anchor `remaining_accounts`.
///
/// The deployed program requires a `pool_v2` account here that its published IDL
/// does not document. Order observed on-chain:
///   `[pool_v2, fee_recipient, fee_recipient_token_account]`
pub fn pumpswap_buy_with_remaining(
    a: &PumpSwapSwapAccounts,
    base_amount_out: u64,
    max_quote_amount_in: u64,
    track_volume: bool,
    remaining: &[AccountMeta],
) -> Instruction {
    let mut data = Vec::with_capacity(25);
    data.extend_from_slice(&crate::swap::PUMPSWAP_BUY_DISC);
    data.extend_from_slice(&base_amount_out.to_le_bytes());
    data.extend_from_slice(&max_quote_amount_in.to_le_bytes());
    data.push(track_volume as u8); // OptionBool == struct(bool), 1 byte

    let mut accounts = a.common();
    accounts.push(AccountMeta::new_readonly(
        pumpswap_pda::global_volume_accumulator(), false));
    accounts.push(AccountMeta::new(
        pumpswap_pda::user_volume_accumulator(&a.user), false));
    accounts.push(AccountMeta::new_readonly(pumpswap_pda::fee_config(), false));
    accounts.push(AccountMeta::new_readonly(PUMP_FEE_PROGRAM, false));
    debug_assert_eq!(accounts.len(), 23);
    accounts.extend_from_slice(remaining);

    Instruction { program_id: PUMPSWAP_PROGRAM, accounts, data }
}

/// PumpSwap `sell` — spend `base_amount_in` of the BASE mint for at least
/// `min_quote_amount_out` of the quote mint. 21 declared accounts.
///
/// When a pool has WSOL as its BASE, this is the instruction that buys the
/// token: orientation decides which of buy/sell acquires the launched asset.
pub fn pumpswap_sell(
    a: &PumpSwapSwapAccounts,
    base_amount_in: u64,
    min_quote_amount_out: u64,
) -> Instruction {
    pumpswap_sell_with_remaining(a, base_amount_in, min_quote_amount_out, &[])
}

/// As `pumpswap_sell`, plus Anchor `remaining_accounts`
/// (`[pool_v2, fee_recipient, fee_recipient_ata]`).
pub fn pumpswap_sell_with_remaining(
    a: &PumpSwapSwapAccounts,
    base_amount_in: u64,
    min_quote_amount_out: u64,
    remaining: &[AccountMeta],
) -> Instruction {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&crate::swap::PUMPSWAP_SELL_DISC);
    data.extend_from_slice(&base_amount_in.to_le_bytes());
    data.extend_from_slice(&min_quote_amount_out.to_le_bytes());

    let mut accounts = a.common();
    accounts.push(AccountMeta::new_readonly(pumpswap_pda::fee_config(), false));
    accounts.push(AccountMeta::new_readonly(PUMP_FEE_PROGRAM, false));
    debug_assert_eq!(accounts.len(), 21);
    accounts.extend_from_slice(remaining);

    Instruction { program_id: PUMPSWAP_PROGRAM, accounts, data }
}

/// Accounts a Raydium CPMM swap needs. Field names follow the *verified*
/// semantics: input/output, never base/quote — see `swap.rs`.
#[derive(Debug, Clone)]
pub struct CpmmSwapAccounts {
    pub payer: Pubkey,
    pub amm_config: Pubkey,
    pub pool_state: Pubkey,
    pub user_input_ata: Pubkey,
    pub user_output_ata: Pubkey,
    /// Pool vault holding the mint being SPENT.
    pub input_vault: Pubkey,
    /// Pool vault holding the mint being RECEIVED.
    pub output_vault: Pubkey,
    pub input_mint: Pubkey,
    pub output_mint: Pubkey,
    pub observation_state: Pubkey,
}

/// Encode a CPMM `swap_base_input`: spend exactly `amount_in`, requiring at
/// least `minimum_amount_out` back.
///
/// `minimum_amount_out` is the only slippage protection there is. Passing 0
/// accepts any output including near-zero, which is what a sandwich bot wants
/// you to do. Real swaps observed on-chain do pass 0; do not copy them.
pub fn cpmm_swap_base_input(
    a: &CpmmSwapAccounts,
    amount_in: u64,
    minimum_amount_out: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&crate::swap::CPMM_SWAP_BASE_INPUT_DISC);
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());

    // Order and flags verified against a real mainnet swap; see the golden test.
    let accounts = vec![
        AccountMeta::new(a.payer, true),
        AccountMeta::new_readonly(cpmm_authority(), false),
        AccountMeta::new_readonly(a.amm_config, false),
        AccountMeta::new(a.pool_state, false),
        AccountMeta::new(a.user_input_ata, false),
        AccountMeta::new(a.user_output_ata, false),
        AccountMeta::new(a.input_vault, false),
        AccountMeta::new(a.output_vault, false),
        AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        AccountMeta::new_readonly(a.input_mint, false),
        AccountMeta::new_readonly(a.output_mint, false),
        AccountMeta::new(a.observation_state, false),
    ];

    Instruction { program_id: CPMM_PROGRAM, accounts, data }
}

/// Assemble the full instruction sequence for buying `output_mint` with SOL on
/// a CPMM pool. Returns instructions only — nothing is signed or sent here.
pub fn build_cpmm_buy(
    owner: &Pubkey,
    accounts: &CpmmSwapAccounts,
    lamports_in: u64,
    minimum_amount_out: u64,
    unit_limit: u32,
    priority_fee: u64,
) -> Vec<Instruction> {
    let mut ixs = compute_budget(unit_limit, priority_fee);
    ixs.extend(wrap_sol(owner, lamports_in));
    ixs.push(ensure_token_ata(owner, &accounts.output_mint));
    ixs.push(cpmm_swap_base_input(accounts, lamports_in, minimum_amount_out));
    if let Ok(close) = unwrap_sol(owner) {
        ixs.push(close);
    }
    ixs
}

/// Parse a base58 pubkey, with context on failure.
pub fn pk(s: &str) -> Result<Pubkey> {
    Pubkey::from_str(s).with_context(|| format!("invalid pubkey: {s}"))
}

#[cfg(test)]
mod tests {

    /// The single most important property of `generate`: what it writes, `load`
    /// reads back to the SAME pubkey. If these disagreed, the operator would
    /// fund one address and arm a different one — losing the money to a wallet
    /// whose key they think they have but don't.
    #[test]
    fn generate_round_trips_through_load() {
        let dir = std::env::temp_dir().join(format!("volens-genkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.json");
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);

        let generated = Wallet::generate(p).expect("generate");
        let loaded = Wallet::load(p).expect("load back");
        assert_eq!(generated, loaded.pubkey(), "funded address must equal armed address");

        // Two generations must not collide (real randomness, not a fixed seed).
        let path2 = dir.join("k2.json");
        let p2 = path2.to_str().unwrap();
        let _ = std::fs::remove_file(p2);
        let other = Wallet::generate(p2).expect("generate 2");
        assert_ne!(generated, other, "each generated key must be distinct");

        std::fs::remove_file(p).ok();
        std::fs::remove_file(p2).ok();
    }

    /// Overwriting a keypair file could destroy access to a funded wallet, so it
    /// must be refused — the funds would be unrecoverable.
    #[test]
    fn generate_refuses_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("volens-genkey-ow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.json");
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);

        Wallet::generate(p).expect("first generate");
        let err = Wallet::generate(p).unwrap_err().to_string();
        assert!(err.contains("refusing to overwrite"), "got: {err}");

        std::fs::remove_file(p).ok();
    }

    /// The key file must not be world- or group-readable: it is a private key.
    #[cfg(unix)]
    #[test]
    fn generated_keyfile_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("volens-genkey-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.json");
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);

        Wallet::generate(p).unwrap();
        let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keypair file must be 0600, got {mode:o}");

        std::fs::remove_file(p).ok();
    }

    use super::*;

    /// The CPMM authority is a fixed PDA. Deriving it must reproduce the
    /// authority seen in every real CPMM swap — if the seed were wrong, every
    /// swap we build would fail.
    #[test]
    fn cpmm_authority_pda_matches_mainnet() {
        assert_eq!(
            cpmm_authority().to_string(),
            "GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL"
        );
    }

    /// GOLDEN FIXTURE — a real mainnet CPMM buy (WSOL in, token out):
    /// tx 5JTUK2Se5XFaPNYJcvenq4uQ9eXUU7zAgTLzfCQSr7cPQMXDbBGg1myY72d3D94h2AS72GbaraPwmyP3yW5NHEi
    ///
    /// Asserts our encoder reproduces that instruction exactly — same account
    /// order, same signer/writable flags, same data bytes. This is what proves
    /// the layout knowledge is correctly encoded, without spending anything.
    #[test]
    fn cpmm_encoder_reproduces_real_mainnet_swap() {
        let a = CpmmSwapAccounts {
            payer: pk("GEUDKx63wXKrn7ognB2gkmy8YRNkVF1hgS4sBEg9nZVm").unwrap(),
            amm_config: pk("D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2").unwrap(),
            pool_state: pk("F613QHh9j8TA7uttEwKTPVnxguP5fQ3LEZN1yZKmRVez").unwrap(),
            user_input_ata: pk("FDA2o2DWbFhRHsETEzuty7M87JRLQ9XSfMowByyJr3eX").unwrap(),
            user_output_ata: pk("HFNue8UFaEiUqNWRZfGQrvFi2riEqk8wJHQ1cimP1dv2").unwrap(),
            input_vault: pk("Ddj6wgAmPiaatVbrQRvSnKHjtSV19AJtq75PGJMtRDqn").unwrap(),
            output_vault: pk("73HAh4ksFm1QuNGUomDsARoBaTs1hFdzc5x23et4psw7").unwrap(),
            input_mint: WSOL,
            output_mint: pk("27a5dUWm6MXzRXeyibGCy6dX1DYL6GKukGWA7hn1xqdX").unwrap(),
            observation_state: pk("991fAA2ojSRhypXMGqXiLyTXXSNvEy5QYn2DdMwPvVX").unwrap(),
        };

        // Real args: amount_in = 10000 lamports, minimum_amount_out = 0.
        let ix = cpmm_swap_base_input(&a, 10_000, 0);

        assert_eq!(ix.program_id, CPMM_PROGRAM);
        assert_eq!(
            hex(&ix.data),
            "8fbe5adac41e33de10270000000000000000000000000000",
            "instruction data must match the on-chain bytes exactly"
        );

        // (pubkey, is_signer, is_writable) exactly as observed on-chain.
        let expect = [
            ("GEUDKx63wXKrn7ognB2gkmy8YRNkVF1hgS4sBEg9nZVm", true, true),
            ("GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL", false, false),
            ("D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2", false, false),
            ("F613QHh9j8TA7uttEwKTPVnxguP5fQ3LEZN1yZKmRVez", false, true),
            ("FDA2o2DWbFhRHsETEzuty7M87JRLQ9XSfMowByyJr3eX", false, true),
            ("HFNue8UFaEiUqNWRZfGQrvFi2riEqk8wJHQ1cimP1dv2", false, true),
            ("Ddj6wgAmPiaatVbrQRvSnKHjtSV19AJtq75PGJMtRDqn", false, true),
            ("73HAh4ksFm1QuNGUomDsARoBaTs1hFdzc5x23et4psw7", false, true),
            ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", false, false),
            ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", false, false),
            ("So11111111111111111111111111111111111111112", false, false),
            ("27a5dUWm6MXzRXeyibGCy6dX1DYL6GKukGWA7hn1xqdX", false, false),
            ("991fAA2ojSRhypXMGqXiLyTXXSNvEy5QYn2DdMwPvVX", false, true),
        ];
        assert_eq!(ix.accounts.len(), expect.len(), "account count");
        for (i, (key, signer, writable)) in expect.iter().enumerate() {
            let got = &ix.accounts[i];
            assert_eq!(got.pubkey.to_string(), *key, "account {i} pubkey");
            assert_eq!(got.is_signer, *signer, "account {i} is_signer");
            assert_eq!(got.is_writable, *writable, "account {i} is_writable");
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn amount_and_slippage_are_little_endian() {
        let a = dummy_accounts();
        let ix = cpmm_swap_base_input(&a, 1, 2);
        assert_eq!(&ix.data[8..16], &1u64.to_le_bytes());
        assert_eq!(&ix.data[16..24], &2u64.to_le_bytes());
        assert_eq!(ix.data.len(), 24);
    }

    /// The buy sequence must wrap SOL, sync it, ensure the destination ATA,
    /// swap, then unwrap. A missing `sync_native` is the classic failure: the
    /// account holds lamports but reports a zero balance.
    #[test]
    fn buy_sequence_has_the_required_shape() {
        let owner = Pubkey::new_unique();
        let mut a = dummy_accounts();
        a.payer = owner;
        let ixs = build_cpmm_buy(&owner, &a, 1_000_000, 900, 200_000, 1);

        // 2 compute budget + 3 wrap + 1 ata + 1 swap + 1 close
        assert_eq!(ixs.len(), 8);
        let sync = spl_token_interface::instruction::sync_native(&TOKEN_PROGRAM, &ata(&owner, &WSOL))
            .unwrap();
        assert!(ixs.contains(&sync), "sync_native must be present after funding");
        assert_eq!(ixs.last().unwrap().program_id, TOKEN_PROGRAM, "must end by closing WSOL");
        assert!(ixs.iter().any(|i| i.program_id == CPMM_PROGRAM), "swap present");
    }

    /// The WSOL ATA the wrap funds must be the same one the swap spends from.
    #[test]
    fn wrapped_account_matches_swap_input() {
        let owner = Pubkey::new_unique();
        let mut a = dummy_accounts();
        a.payer = owner;
        a.user_input_ata = ata(&owner, &WSOL);
        let ixs = build_cpmm_buy(&owner, &a, 1_000, 0, 200_000, 1);
        let transfer_dest = ixs[3].accounts[1].pubkey; // system transfer -> WSOL ata
        assert_eq!(transfer_dest, a.user_input_ata);
    }

    #[test]
    fn ata_derivation_is_deterministic() {
        let owner = Pubkey::new_unique();
        assert_eq!(ata(&owner, &WSOL), ata(&owner, &WSOL));
        assert_ne!(ata(&owner, &WSOL), ata(&Pubkey::new_unique(), &WSOL));
    }

    #[test]
    fn wallet_rejects_malformed_keys() {
        let dir = std::env::temp_dir().join(format!("volens-kp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.json");
        std::fs::write(&p, b"[1,2,3]").unwrap();
        let err = Wallet::load(p.to_str().unwrap()).unwrap_err().to_string();
        assert!(err.contains("expected 64 bytes"), "got: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// LIVE: simulate the full buy against real mainnet state.
    ///
    /// The strongest verification available short of spending money.
    /// `sigVerify: false` + `replaceRecentBlockhash: true` means the node
    /// executes our instructions against a real account snapshot without any
    /// signature — no key, nothing submitted, nothing charged.
    ///
    /// CONFIRMED RUN (2026-07-20): `err: null`, CPMM consumed 22,321 CU, with
    /// the full sequence in the logs — ComputeBudget x2, CreateIdempotent
    /// (WSOL), system transfer, SyncNative, CreateIdempotent (token),
    /// `Instruction: SwapBaseInput` success, then close.
    ///
    /// Requires a payer that EXISTS on-chain. A fresh keypair has no account, so
    /// the node rejects with `AccountNotFound` before executing anything, which
    /// would make this test pass while proving nothing — hence the hard
    /// requirement rather than a silent degenerate mode.
    ///
    ///   VOLENS_SIM_PAYER=<funded-pubkey> \
    ///     cargo test --features sniper -- --ignored --nocapture live_simulate
    #[tokio::test]
    #[ignore = "hits public mainnet RPC; needs VOLENS_SIM_PAYER"]
    async fn live_simulate_cpmm_buy() {
        use solana_message::Message;
        use solana_transaction::Transaction;

        let Ok(payer) = std::env::var("VOLENS_SIM_PAYER") else {
            panic!(
                "set VOLENS_SIM_PAYER to a pubkey that exists on-chain.\n\
                 Without one the node returns AccountNotFound before executing \
                 anything, so this test would pass without verifying the swap. \
                 Simulation is read-only, unsigned and never submitted."
            );
        };
        let owner = pk(&payer).expect("VOLENS_SIM_PAYER must be a valid pubkey");

        let cfg = crate::config::RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            initial_delay_ms: 0,
            retries: 3,
            retry_delay_ms: 1500,
            ..Default::default()
        };
        let rpc = crate::rpc::RpcClient::new(&cfg);

        // The real pool from the golden fixture.
        let output_mint = pk("27a5dUWm6MXzRXeyibGCy6dX1DYL6GKukGWA7hn1xqdX").unwrap();
        let accounts = CpmmSwapAccounts {
            payer: owner,
            amm_config: pk("D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2").unwrap(),
            pool_state: pk("F613QHh9j8TA7uttEwKTPVnxguP5fQ3LEZN1yZKmRVez").unwrap(),
            user_input_ata: ata(&owner, &WSOL),
            user_output_ata: ata(&owner, &output_mint),
            input_vault: pk("Ddj6wgAmPiaatVbrQRvSnKHjtSV19AJtq75PGJMtRDqn").unwrap(),
            output_vault: pk("73HAh4ksFm1QuNGUomDsARoBaTs1hFdzc5x23et4psw7").unwrap(),
            input_mint: WSOL,
            output_mint,
            observation_state: pk("991fAA2ojSRhypXMGqXiLyTXXSNvEy5QYn2DdMwPvVX").unwrap(),
        };

        let ixs = build_cpmm_buy(&owner, &accounts, 10_000, 0, 200_000, 1_000);
        let msg = Message::new(&ixs, Some(&owner));
        let tx = Transaction::new_unsigned(msg);
        let bytes = bincode::serialize(&tx).expect("serialize");
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let sim = rpc.simulate_transaction(&b64).await.expect("simulation result");
        let logs = sim
            .get("logs")
            .and_then(|l| l.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let err = sim.get("err").cloned().unwrap_or(serde_json::Value::Null);
        let units = sim.get("unitsConsumed").and_then(|u| u.as_u64()).unwrap_or(0);
        println!("err={err}\nunitsConsumed={units}\nlogs:\n{logs}");

        assert_eq!(
            err,
            serde_json::Value::Null,
            "simulation must succeed; err={err}\nlogs:\n{logs}"
        );
        // Guard against a vacuous pass: the CPMM program must actually have run.
        assert!(units > 0, "no compute consumed — nothing executed");
        assert!(
            logs.contains("Instruction: SwapBaseInput"),
            "the CPMM swap itself must execute, not just the preamble.\nlogs:\n{logs}"
        );
        assert!(
            logs.contains(&format!("Program {CPMM_PROGRAM} success")),
            "CPMM swap must succeed.\nlogs:\n{logs}"
        );
        // The wrap must have happened, otherwise the swap had nothing to spend.
        assert!(logs.contains("SyncNative") || logs.contains("Program log: CreateIdempotent"));
    }

    // ---- Raydium v4 ----

    /// Real 388-byte OpenBook market `uYU15HD1VCeti8CkyVL5JY18mip8tVWNuvS35k1UCNy`,
    /// captured from mainnet. Embedded so the decode is regression-tested.
    const MARKET_B64: &str = concat!(
        "c2VydW0DAAAAAAAAAA11x7/OPzhkjc6khMTfSyPuD9LDRMxdG/4mEluA8wqeBQAAAAAAAAAGm4hX/quBhPtof2NGGMA12sQ53Brr",
        "O1WYoPAAAAAAAdNruCqYcLDxVmfwceCiNZGgl6wO+MwzF3vpL8065y8PIMujlXf+vWnhv8BTJVi+1JkP2PT0p8WWr/7HZ76DjmIA",
        "AAAAAAAAAAAAAAAAAAAANpR7aizVOwJ4xFOGwvNkn4PWNjo+YziDxaIR3A6F3e0AAAAAAAAAAAAAAAAAAAAAZAAAAAAAAAARwkEB",
        "rIRDKiZCf5YKyFV46qpB8MFb9oH3m3C7RepXqrNMdOkhXjCkdnHFeBAge4fWxvpYyeZGI7+Vw9V0+6Ow9GKRidI2kKtjrbls/HqK",
        "NATwnVhH67QSwurMeu5wVNON+bZt2Na7ac9rkUc+zUNOfHN01xnGGtuu2gdNbcrbVICWmAAAAAAAZAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAcGFkZGluZw=="
    );

    fn real_market() -> OpenBookMarket {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(MARKET_B64)
            .expect("fixture base64");
        OpenBookMarket::decode(&raw).expect("decode market")
    }

    /// Decoding the real market must reproduce exactly the accounts that live
    /// swaps pass. These do NOT appear in the pool-creation instruction, so a
    /// wrong offset here silently sends garbage accounts to the AMM.
    #[test]
    fn openbook_market_decode_matches_mainnet() {
        let m = real_market();
        assert_eq!(m.vault_signer_nonce, 5);
        assert_eq!(m.base_mint, WSOL);
        assert_eq!(
            m.quote_mint.to_string(),
            "FEJHveqBGjzMuAcukbpP9DciXfp1UMP5kt7PHfKypump"
        );
        assert_eq!(m.bids.to_string(), "HSyerpzTf7sUpDSzuqrk9cZdwaXx78BEU41W2Groiwh4");
        assert_eq!(m.asks.to_string(), "AZDLHUxL6Y2memS5aTaeBTBV9dgFUtznBuPuFA6n3Lmq");
        assert_eq!(m.event_queue.to_string(), "D4ubbtGTDqxtJwrCL65q8Pd1J4TD7kqz8Efc2Q5e7fLB");
        assert_eq!(m.base_vault.to_string(), "3D29T7DkrSj1TJqtVYE5dMxE9QUVZBDeK9WwdT6iEjnH");
        assert_eq!(m.quote_vault.to_string(), "4g4LNYh6pWmpGWiAzQLsEokz4PwNWZAPnXMcGDE4PBZ6");
    }

    /// The vault signer is derived, not stored. `create_program_address` with
    /// the market's own nonce must reproduce the account real swaps pass.
    #[test]
    fn market_vault_signer_derivation_matches_mainnet() {
        let market = pk("uYU15HD1VCeti8CkyVL5JY18mip8tVWNuvS35k1UCNy").unwrap();
        let signer = real_market().vault_signer(&market).unwrap();
        assert_eq!(signer.to_string(), "3TjyFxeihC87gh49xE3RgYjySCknCXRPTv1kcf47cEZj");
    }

    #[test]
    fn v4_authority_pda_matches_mainnet() {
        assert_eq!(
            v4_authority().to_string(),
            "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1"
        );
    }

    #[test]
    fn market_decode_rejects_wrong_length() {
        assert!(OpenBookMarket::decode(&[0u8; 100]).is_err());
        assert!(OpenBookMarket::decode(&[]).is_err());
    }

    fn real_v4_accounts() -> V4SwapAccounts {
        V4SwapAccounts {
            amm: pk("DKKzSyX6ErWcZcQM26u5FQYTL7o8fUpPcUy2Zpok6BJH").unwrap(),
            amm_open_orders: pk("7sZaWT4bLpDUYH7LHBAHGroHLjDB7V42a1YH7L5jdngN").unwrap(),
            amm_target_orders: None,
            pool_coin_vault: pk("65BegeSCZazBbM8TF2NmRbdhUB5oqUTckzhKhgMiJxpn").unwrap(),
            pool_pc_vault: pk("GYb4Sa8abriEe6JjYu3R5AodegUGZnDFDcZYGRMu59db").unwrap(),
            market: pk("uYU15HD1VCeti8CkyVL5JY18mip8tVWNuvS35k1UCNy").unwrap(),
            market_state: real_market(),
            user_source: pk("46do1yaJ29RpqCd3LxjXirfYaquvX7ETbhYX6F5E3gs4").unwrap(),
            user_destination: pk("9VZKSfYT8PTWf63TxoTWo1kjnMNY99aNiWAz8hGWg3Ai").unwrap(),
            user_owner: pk("Gs2fpjHEd6pJAjvnzGjouJvDwJZrim3QvB3pQYKvgjAB").unwrap(),
        }
    }

    /// GOLDEN FIXTURE — real mainnet 17-account `swapBaseIn`:
    /// tx 2L9WYeUC7hLtrU5pbrK6LwTU9Nvw4E2TqRJvF1bj8fBUcYPLiDmuoTFuYT4ufeB3btWr8cVe1sUEse5QYJahhCnk
    /// amount_in = 468294, minimum_amount_out = 1.
    #[test]
    fn v4_encoder_reproduces_real_mainnet_swap() {
        let ix = v4_swap_base_in(&real_v4_accounts(), 468_294, 1).unwrap();

        assert_eq!(ix.program_id, V4_PROGRAM);
        assert_eq!(hex(&ix.data), "0946250700000000000100000000000000");

        let expect = [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "DKKzSyX6ErWcZcQM26u5FQYTL7o8fUpPcUy2Zpok6BJH",
            "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
            "7sZaWT4bLpDUYH7LHBAHGroHLjDB7V42a1YH7L5jdngN",
            "65BegeSCZazBbM8TF2NmRbdhUB5oqUTckzhKhgMiJxpn",
            "GYb4Sa8abriEe6JjYu3R5AodegUGZnDFDcZYGRMu59db",
            "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",
            "uYU15HD1VCeti8CkyVL5JY18mip8tVWNuvS35k1UCNy",
            "HSyerpzTf7sUpDSzuqrk9cZdwaXx78BEU41W2Groiwh4",
            "AZDLHUxL6Y2memS5aTaeBTBV9dgFUtznBuPuFA6n3Lmq",
            "D4ubbtGTDqxtJwrCL65q8Pd1J4TD7kqz8Efc2Q5e7fLB",
            "3D29T7DkrSj1TJqtVYE5dMxE9QUVZBDeK9WwdT6iEjnH",
            "4g4LNYh6pWmpGWiAzQLsEokz4PwNWZAPnXMcGDE4PBZ6",
            "3TjyFxeihC87gh49xE3RgYjySCknCXRPTv1kcf47cEZj",
            "46do1yaJ29RpqCd3LxjXirfYaquvX7ETbhYX6F5E3gs4",
            "9VZKSfYT8PTWf63TxoTWo1kjnMNY99aNiWAz8hGWg3Ai",
            "Gs2fpjHEd6pJAjvnzGjouJvDwJZrim3QvB3pQYKvgjAB",
        ];
        assert_eq!(ix.accounts.len(), 17, "17-account form (no target orders)");
        for (i, key) in expect.iter().enumerate() {
            assert_eq!(ix.accounts[i].pubkey.to_string(), *key, "account {i}");
        }

        // Only the owner signs.
        for (i, m) in ix.accounts.iter().enumerate() {
            assert_eq!(m.is_signer, i == 16, "account {i} is_signer");
        }

        // NOTE on index 16: the on-chain message shows it writable, but that is
        // forced because the owner is ALSO the fee payer (verified:
        // accountKeys[0] == Gs2fpjH...). At instruction level the owner only
        // needs to sign, and the message builder re-marks the fee payer
        // writable anyway. Everything else must match exactly.
        let readonly = [0usize, 2, 6, 13, 16];
        for (i, m) in ix.accounts.iter().enumerate() {
            assert_eq!(m.is_writable, !readonly.contains(&i), "account {i} is_writable");
        }
    }

    /// The 18-account form must insert target_orders at index 4 and shift the
    /// rest — the single most dangerous difference in the v4 layout.
    #[test]
    fn v4_target_orders_shifts_every_later_index() {
        let target = Pubkey::new_unique();
        let mut a = real_v4_accounts();
        a.amm_target_orders = Some(target);
        let with = v4_swap_base_in(&a, 1, 1).unwrap();
        let without = v4_swap_base_in(&real_v4_accounts(), 1, 1).unwrap();

        assert_eq!(with.accounts.len(), 18);
        assert_eq!(without.accounts.len(), 17);
        assert_eq!(with.accounts[4].pubkey, target, "target orders sits at index 4");
        // Everything from the vaults onward shifts by exactly one.
        for i in 4..without.accounts.len() {
            assert_eq!(
                without.accounts[i].pubkey, with.accounts[i + 1].pubkey,
                "index {i} must shift to {}", i + 1
            );
        }
    }

    #[test]
    fn v4_data_is_tag_then_two_le_u64s() {
        let ix = v4_swap_base_in(&real_v4_accounts(), 7, 9).unwrap();
        assert_eq!(ix.data[0], 9, "swapBaseIn tag");
        assert_eq!(&ix.data[1..9], &7u64.to_le_bytes());
        assert_eq!(&ix.data[9..17], &9u64.to_le_bytes());
        assert_eq!(ix.data.len(), 17);
    }

    // ---- PumpSwap PDA derivations ----

    /// Each of these was confirmed by deriving it and matching an account that
    /// a real mainnet PumpSwap swap actually passed.
    #[test]
    fn pumpswap_pdas_match_mainnet() {
        use pumpswap_pda as p;
        assert_eq!(
            p::global_config().to_string(),
            "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw"
        );
        assert_eq!(
            p::event_authority().to_string(),
            "GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR"
        );
        assert_eq!(
            p::global_volume_accumulator().to_string(),
            "C2aFPdENg4A2HQsmrd5rTw5TaYBX5Ku887cWjbFKtZpw"
        );
        assert_eq!(
            p::fee_config().to_string(),
            "5PHirr8joyTMp9JMm6nW7hNDVyEYdkzDqazxPD7RaTjx"
        );
    }

    /// User-scoped PDA: verified against the buy sample's signer.
    #[test]
    fn pumpswap_user_volume_accumulator_matches_mainnet() {
        let user = pk("JAESemHQKmDwZ18tQw8H85c8Tuuki5m7sAAfFNoZNvPb").unwrap();
        assert_eq!(
            pumpswap_pda::user_volume_accumulator(&user).to_string(),
            "73fAVtLFrcU7PtB5teMHnGHxN4qemqTY13dpDkj9Xm6s"
        );
    }

    /// Both sampled pools had an unset (zero) coin creator, which is why one
    /// authority served two different pools. Documents that finding so a future
    /// change that assumes zero for ALL pools is caught.
    #[test]
    fn pumpswap_creator_vault_with_unset_creator() {
        let zero = Pubkey::new_from_array([0u8; 32]);
        assert_eq!(
            pumpswap_pda::creator_vault_authority(&zero).to_string(),
            "8N3GDaZ2iwN65oxVatKTLPNooAVUJTbfiVJ1ahyqwjSk"
        );
        // A real creator must produce a different vault authority.
        assert_ne!(
            pumpswap_pda::creator_vault_authority(&Pubkey::new_unique()),
            pumpswap_pda::creator_vault_authority(&zero)
        );
    }

    /// LIVE: simulate a Raydium v4 buy against real mainnet state.
    ///
    /// Same posture as the CPMM simulation: `sigVerify: false`, nothing signed,
    /// nothing submitted. Uses the real pool/market from the golden fixture and
    /// the caller-supplied payer's own ATAs.
    ///
    ///   VOLENS_SIM_PAYER=<funded-pubkey> \
    ///     cargo test --features sniper -- --ignored --nocapture live_simulate_v4
    #[tokio::test]
    #[ignore = "hits public mainnet RPC; needs VOLENS_SIM_PAYER"]
    async fn live_simulate_v4_buy() {
        use solana_message::Message;
        use solana_transaction::Transaction;

        let Ok(payer) = std::env::var("VOLENS_SIM_PAYER") else {
            panic!("set VOLENS_SIM_PAYER to a pubkey that exists on-chain");
        };
        let owner = pk(&payer).expect("valid pubkey");

        let cfg = crate::config::RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            initial_delay_ms: 0,
            retries: 3,
            retry_delay_ms: 1500,
            ..Default::default()
        };
        let rpc = crate::rpc::RpcClient::new(&cfg);

        // Pool's pc side is the token; coin side is WSOL (verified in fixture).
        let token = pk("FEJHveqBGjzMuAcukbpP9DciXfp1UMP5kt7PHfKypump").unwrap();
        let mut a = real_v4_accounts();
        a.user_owner = owner;
        a.user_source = ata(&owner, &WSOL);
        a.user_destination = ata(&owner, &token);

        let lamports = 10_000u64;
        let mut ixs = compute_budget(300_000, 1_000);
        ixs.extend(wrap_sol(&owner, lamports));
        ixs.push(ensure_token_ata(&owner, &token));
        ixs.push(v4_swap_base_in(&a, lamports, 1).unwrap());
        ixs.push(unwrap_sol(&owner).unwrap());

        let msg = Message::new(&ixs, Some(&owner));
        let tx = Transaction::new_unsigned(msg);
        let bytes = bincode::serialize(&tx).expect("serialize");
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let sim = rpc.simulate_transaction(&b64).await.expect("simulation result");
        let logs = sim
            .get("logs")
            .and_then(|l| l.as_array())
            .map(|x| x.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let err = sim.get("err").cloned().unwrap_or(serde_json::Value::Null);
        let units = sim.get("unitsConsumed").and_then(|u| u.as_u64()).unwrap_or(0);
        println!("err={err}\nunitsConsumed={units}\nlogs:\n{logs}");

        assert_eq!(err, serde_json::Value::Null, "simulation must succeed\nlogs:\n{logs}");
        assert!(units > 0, "nothing executed");
        assert!(
            logs.contains(&format!("Program {V4_PROGRAM} success")),
            "the v4 swap itself must execute and succeed.\nlogs:\n{logs}"
        );
    }

    /// LIVE: decode a real CPMM pool + its config and check every field
    /// against values known from the golden swap fixture.
    ///
    ///   cargo test --features sniper -- --ignored --nocapture live_cpmm_pool_decode
    #[tokio::test]
    #[ignore = "hits public mainnet RPC"]
    async fn live_cpmm_pool_decode_and_quote() {
        use base64::Engine;
        let cfg = crate::config::RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            initial_delay_ms: 0,
            retries: 3,
            retry_delay_ms: 1500,
            ..Default::default()
        };
        let client = reqwest::Client::new();
        let fetch = |addr: String| {
            let client = client.clone();
            let url = cfg.url.clone();
            async move {
                let body = serde_json::json!({
                    "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
                    "params":[addr, {"encoding":"base64"}]
                });
                let v: serde_json::Value =
                    client.post(&url).json(&body).send().await.ok()?.json().await.ok()?;
                let d = v.get("result")?.get("value")?.get("data")?.get(0)?.as_str()?.to_string();
                base64::engine::general_purpose::STANDARD.decode(d).ok()
            }
        };

        // The pool from the golden CPMM swap fixture.
        let raw = fetch("F613QHh9j8TA7uttEwKTPVnxguP5fQ3LEZN1yZKmRVez".into())
            .await
            .expect("pool account");
        let pool = CpmmPoolState::decode(&raw).expect("decode pool");
        println!("{pool:#?}");

        assert_eq!(
            pool.amm_config.to_string(),
            "D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2"
        );
        // The two vaults from the verified swap, in some order.
        let vaults = [pool.token_0_vault.to_string(), pool.token_1_vault.to_string()];
        assert!(vaults.contains(&"Ddj6wgAmPiaatVbrQRvSnKHjtSV19AJtq75PGJMtRDqn".to_string()));
        assert!(vaults.contains(&"73HAh4ksFm1QuNGUomDsARoBaTs1hFdzc5x23et4psw7".to_string()));
        let mints = [pool.token_0_mint.to_string(), pool.token_1_mint.to_string()];
        assert!(mints.contains(&WSOL.to_string()));
        assert!(mints.contains(&"27a5dUWm6MXzRXeyibGCy6dX1DYL6GKukGWA7hn1xqdX".to_string()));

        let craw = fetch(pool.amm_config.to_string()).await.expect("amm_config");
        let conf = CpmmAmmConfig::decode(&craw).expect("decode config");
        println!("{conf:#?}");
        // Observed live values are 2500 / 3000 (0.25% / 0.30%).
        assert!(
            (1..100_000).contains(&conf.trade_fee_rate),
            "implausible trade_fee_rate {}",
            conf.trade_fee_rate
        );

        // End-to-end: real reserves -> real quote.
        let bal = |v: &str| {
            let client = client.clone();
            let url = cfg.url.clone();
            let v = v.to_string();
            async move {
                let body = serde_json::json!({
                    "jsonrpc":"2.0","id":1,"method":"getTokenAccountBalance","params":[v]
                });
                let r: serde_json::Value =
                    client.post(&url).json(&body).send().await.ok()?.json().await.ok()?;
                r.get("result")?.get("value")?.get("amount")?.as_str()?.parse::<u64>().ok()
            }
        };
        let b0 = bal(&pool.token_0_vault.to_string()).await.expect("vault0");
        let b1 = bal(&pool.token_1_vault.to_string()).await.expect("vault1");
        let input_is_token_0 = pool.token_0_mint == WSOL;
        let reserves = pool.reserves(b0, b1, input_is_token_0);
        println!("vault0={b0} vault1={b1} reserves={reserves:?}");

        let q = crate::quote::quote(reserves, 10_000_000, conf.fee(), 300).unwrap();
        println!("quote for 0.01 SOL: {q:?}");
        assert!(q.expected_out > 0);
        assert!(q.minimum_out < q.expected_out);
        assert!(q.price_impact_bps < 10_000);
    }

    // ---- PumpSwap ----

    /// GOLDEN FIXTURE — real mainnet buy
    /// 64jY8X3HfNcVBBE2FuUspxsDsSUVRKJZfzVQm9toYrL4tU6z3Y7wS9jGV5xbXqzdCbY1UDXje4kvo1S1oaWv2nbh
    ///
    /// That transaction passed 25 accounts; the first 23 are the IDL's declared
    /// list and the trailing two are optional `remaining_accounts`. Our encoder
    /// must reproduce the 23 exactly — order, flags and data.
    #[test]
    fn pumpswap_buy_reproduces_real_mainnet_swap() {
        let a = PumpSwapSwapAccounts {
            pool: pk("Go9kNyWihHQCckhfjajsDYqRevwd6zGT7TkrP5JByRyD").unwrap(),
            user: pk("44YLaHHJDjgeTA4SV7YPgfoF5XKfwwjJJxvg298U1JSW").unwrap(),
            base_mint: WSOL,
            quote_mint: pk("C2MR2REsVxzqKnaMW3n3AWh6RnmXpo256dSffdzpL7JY").unwrap(),
            pool_base_token_account: pk("2DdrRHumextZ81CLWcTzxfkGxG7ziu7JQxebhtyNSYgh").unwrap(),
            pool_quote_token_account: pk("9o8QABU5bR1Az9QkQchPNqnyZCpj6e5cnS5vjXh3trkn").unwrap(),
            protocol_fee_recipient: pk("9rPYyANsfQZw3DnDmKE3YCQF5E8oD89UXoHn9JFEhJUz").unwrap(),
            // This pool's coin_creator is unset.
            coin_creator: Pubkey::new_from_array([0u8; 32]),
            base_token_program: TOKEN_PROGRAM,
            quote_token_program: TOKEN_PROGRAM,
        };
        let ix = pumpswap_buy(&a, 9_894_969_147, u64::MAX, true);

        assert_eq!(ix.program_id, PUMPSWAP_PROGRAM);
        assert_eq!(
            hex(&ix.data),
            "66063d1201daebea3b3fc94d02000000ffffffffffffffff01",
            "data must match the on-chain bytes exactly"
        );

        let expect: [(&str, bool, bool); 23] = [
            ("Go9kNyWihHQCckhfjajsDYqRevwd6zGT7TkrP5JByRyD", false, true),
            ("44YLaHHJDjgeTA4SV7YPgfoF5XKfwwjJJxvg298U1JSW", true, true),
            ("ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw", false, false),
            ("So11111111111111111111111111111111111111112", false, false),
            ("C2MR2REsVxzqKnaMW3n3AWh6RnmXpo256dSffdzpL7JY", false, false),
            ("6tzK55qRjkSvYgTjghS4swkNhP6eGrJTBrByW7UfSwhC", false, true),
            ("71YBbn4to4gvM34WmDA293k14skxErC9v5LqqHdFcShU", false, true),
            ("2DdrRHumextZ81CLWcTzxfkGxG7ziu7JQxebhtyNSYgh", false, true),
            ("9o8QABU5bR1Az9QkQchPNqnyZCpj6e5cnS5vjXh3trkn", false, true),
            ("9rPYyANsfQZw3DnDmKE3YCQF5E8oD89UXoHn9JFEhJUz", false, false),
            ("HLcavzRNraFtBCj6BULW5Y2BQdzVtZ1LFWMcXz4cPjGS", false, true),
            ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", false, false),
            ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", false, false),
            ("11111111111111111111111111111111", false, false),
            ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", false, false),
            ("GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR", false, false),
            ("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA", false, false),
            ("BrH9hY8wRfvSTuAiYjYo327HUHkL8FoUZjcsVb6XTqo9", false, true),
            ("8N3GDaZ2iwN65oxVatKTLPNooAVUJTbfiVJ1ahyqwjSk", false, false),
            ("C2aFPdENg4A2HQsmrd5rTw5TaYBX5Ku887cWjbFKtZpw", false, false),
            ("F71hAHAuHYX8xsiyeCc6iHB82Don22uYBswk3ddDbVcP", false, true),
            ("5PHirr8joyTMp9JMm6nW7hNDVyEYdkzDqazxPD7RaTjx", false, false),
            ("pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ", false, false),
        ];
        assert_eq!(ix.accounts.len(), 23, "IDL declares 23 accounts for buy");
        for (i, (key, sgn, w)) in expect.iter().enumerate() {
            let got = &ix.accounts[i];
            assert_eq!(got.pubkey.to_string(), *key, "account {i} pubkey");
            assert_eq!(got.is_signer, *sgn, "account {i} is_signer");
            assert_eq!(got.is_writable, *w, "account {i} is_writable");
        }
    }

    /// `sell` drops the two volume accumulators, so fee_config/fee_program move
    /// from 21/22 to 19/20 — matching what was observed on-chain.
    #[test]
    fn pumpswap_sell_has_21_accounts_and_shifted_fee_slots() {
        let a = PumpSwapSwapAccounts {
            pool: Pubkey::new_unique(),
            user: Pubkey::new_unique(),
            base_mint: WSOL,
            quote_mint: Pubkey::new_unique(),
            pool_base_token_account: Pubkey::new_unique(),
            pool_quote_token_account: Pubkey::new_unique(),
            protocol_fee_recipient: Pubkey::new_unique(),
            coin_creator: Pubkey::new_from_array([0u8; 32]),
            base_token_program: TOKEN_PROGRAM,
            quote_token_program: TOKEN_PROGRAM,
        };
        let sell = pumpswap_sell(&a, 1_000, 900);
        assert_eq!(sell.accounts.len(), 21);
        assert_eq!(sell.accounts[19].pubkey, pumpswap_pda::fee_config());
        assert_eq!(sell.accounts[20].pubkey, PUMP_FEE_PROGRAM);
        assert_eq!(sell.data.len(), 24, "no track_volume byte on sell");

        let buy = pumpswap_buy(&a, 1_000, 2_000, true);
        assert_eq!(buy.accounts.len(), 23);
        assert_eq!(buy.accounts[21].pubkey, pumpswap_pda::fee_config());
        assert_eq!(buy.accounts[22].pubkey, PUMP_FEE_PROGRAM);
        assert_eq!(buy.data.len(), 25, "buy carries the track_volume byte");
        // Indices 0..=18 are shared between the two.
        for i in 0..19 {
            assert_eq!(buy.accounts[i].pubkey, sell.accounts[i].pubkey, "index {i}");
        }
    }

    /// `coin_creator` sits at offset 211 — the field whose location previously
    /// blocked this encoder.
    #[test]
    fn pumpswap_pool_decode_offsets() {
        let mut raw = vec![0u8; 245];
        let creator = Pubkey::new_unique();
        let base = Pubkey::new_unique();
        let coin_creator = Pubkey::new_unique();
        raw[11..43].copy_from_slice(creator.as_ref());
        raw[43..75].copy_from_slice(base.as_ref());
        raw[211..243].copy_from_slice(coin_creator.as_ref());

        let p = PumpSwapPool::decode(&raw).unwrap();
        assert_eq!(p.creator, creator);
        assert_eq!(p.base_mint, base);
        assert_eq!(p.coin_creator, coin_creator);
        assert!(PumpSwapPool::decode(&[0u8; 10]).is_err());
    }

    /// The protocol and buyback recipient sets are DISTINCT. Confusing them
    /// fails on-chain with BuybackFeeRecipientNotAuthorized (6053).
    #[test]
    fn protocol_and_buyback_recipient_sets_are_distinct() {
        let mut raw = vec![0u8; 940];
        let proto = Pubkey::new_unique();
        let buyback = Pubkey::new_unique();
        raw[57..89].copy_from_slice(proto.as_ref());     // protocol set
        raw[643..675].copy_from_slice(buyback.as_ref()); // buyback set
        let g = PumpSwapGlobalConfig::decode(&raw).unwrap();

        assert_eq!(g.pick_fee_recipient(0).unwrap(), proto);
        assert_eq!(g.pick_buyback_recipient(0).unwrap(), buyback);
        assert_ne!(
            g.pick_fee_recipient(0).unwrap(),
            g.pick_buyback_recipient(0).unwrap()
        );
    }

    /// A config too short to reach the buyback array must be rejected, not
    /// silently decoded with zeroed recipients.
    #[test]
    fn global_config_requires_the_buyback_array() {
        assert!(PumpSwapGlobalConfig::decode(&vec![0u8; 400]).is_err());
        assert!(PumpSwapGlobalConfig::decode(&vec![0u8; 940]).is_ok());
    }

    /// Fee recipients come from a fixed set of 8; unset slots must be skipped.
    #[test]
    fn global_config_picks_only_live_fee_recipients() {
        let mut raw = vec![0u8; 940];
        let a = Pubkey::new_unique();
        let b = Pubkey::new_unique();
        raw[57..89].copy_from_slice(a.as_ref());
        raw[89..121].copy_from_slice(b.as_ref());
        // slots 2..8 left zeroed
        raw[40..48].copy_from_slice(&20u64.to_le_bytes());
        raw[48..56].copy_from_slice(&5u64.to_le_bytes());
        raw[313..321].copy_from_slice(&5u64.to_le_bytes());

        let g = PumpSwapGlobalConfig::decode(&raw).unwrap();
        assert_eq!(g.total_fee_bps(), 30, "lp + protocol + coin_creator");
        // Only the two live slots are ever chosen, whatever index is asked for.
        for n in 0..10 {
            let r = g.pick_fee_recipient(n).unwrap();
            assert!(r == a || r == b, "picked an unset slot at n={n}");
        }
    }

    fn dummy_accounts() -> CpmmSwapAccounts {
        CpmmSwapAccounts {
            payer: Pubkey::new_unique(),
            amm_config: Pubkey::new_unique(),
            pool_state: Pubkey::new_unique(),
            user_input_ata: Pubkey::new_unique(),
            user_output_ata: Pubkey::new_unique(),
            input_vault: Pubkey::new_unique(),
            output_vault: Pubkey::new_unique(),
            input_mint: WSOL,
            output_mint: Pubkey::new_unique(),
            observation_state: Pubkey::new_unique(),
        }
    }
}
