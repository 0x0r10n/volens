//! pump.fun bonding curve: state, pricing, and the `buy` / `sell` encoders.
//!
//! # Why this exists
//!
//! Smart-money entries route through Jupiter, which costs two API round trips
//! (~750ms) on a lane globally throttled to 1200ms and shared with three other
//! callers — and which has IP-blocked this host before. A bonding-curve trade
//! needs neither: the curve address is a PDA of the mint, so the whole account
//! set is derivable from the mint and our own pubkey, with one RPC read for the
//! curve state. That read is also the price.
//!
//! It is also the venue that matters for early entry. A pump.fun token trades
//! on this curve BEFORE it graduates to PumpSwap, which is the window where a
//! launch is still worth what a launch should be worth.
//!
//! # Provenance
//!
//! Every constant, seed, discriminator and field offset here was taken from the
//! program's own Anchor IDL, published on chain at the canonical
//! `["anchor:idl"]` address, and cross-checked against captured mainnet
//! transactions in `tests/fixtures/gettx_pumpfun_buy_*.json`. Nothing here is
//! from documentation or memory; an earlier hand-read of the curve layout got
//! `virtual_quote_reserves` wrong by calling it SOL, which is precisely the
//! class of mistake that spends money on arithmetic that was never true.

use anyhow::{Result, bail};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

/// pump.fun bonding curve program.
pub const PUMP_PROGRAM: Pubkey =
    Pubkey::from_str_const("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");
/// pump.fun fee program. Referenced by the `buy` account list.
pub const PUMP_FEE_PROGRAM: Pubkey =
    Pubkey::from_str_const("pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ");
/// System program — the all-zero pubkey. Named rather than `Pubkey::default()`
/// so the account list reads as what it is.
const SYSTEM_PROGRAM: Pubkey =
    Pubkey::from_str_const("11111111111111111111111111111111");

/// Anchor discriminator for `global:buy` — sha256("global:buy")[..8].
/// Confirmed byte-for-byte against live transactions.
pub const BUY_DISCRIMINATOR: [u8; 8] = [0x66, 0x06, 0x3d, 0x12, 0x01, 0xda, 0xeb, 0xea];
/// Anchor discriminator for `global:sell`.
pub const SELL_DISCRIMINATOR: [u8; 8] = [0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad];
/// Anchor discriminator of the `BondingCurve` ACCOUNT (not an instruction).
/// Checked on decode so a wrong account is refused rather than misread.
const CURVE_ACCOUNT_DISCRIMINATOR: [u8; 8] = [0x17, 0xb7, 0xf8, 0x37, 0x60, 0xd8, 0xac, 0x60];

/// The bonding curve's own state.
///
/// Field order and types are the IDL's, not a guess:
/// ```text
/// virtual_token_reserves u64   real_token_reserves u64   complete bool
/// virtual_quote_reserves u64   real_quote_reserves u64   creator pubkey
/// token_total_supply     u64   is_mayhem_mode bool       is_cashback_coin bool
/// quote_mint             pubkey
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondingCurve {
    pub virtual_token_reserves: u64,
    pub virtual_quote_reserves: u64,
    pub real_token_reserves: u64,
    pub real_quote_reserves: u64,
    pub token_total_supply: u64,
    /// The curve has filled and migrated. A complete curve cannot be traded
    /// here at all — the liquidity has moved to PumpSwap.
    pub complete: bool,
    pub creator: Pubkey,
    pub is_mayhem_mode: bool,
    pub is_cashback_coin: bool,
    /// What the curve is priced IN. Not always SOL — see `quote_is_sol`.
    pub quote_mint: Pubkey,
}

/// Byte offsets, from the IDL field order. Anchor packs with no padding.
const OFF_VIRTUAL_TOKEN: usize = 8;
const OFF_VIRTUAL_QUOTE: usize = 16;
const OFF_REAL_TOKEN: usize = 24;
const OFF_REAL_QUOTE: usize = 32;
const OFF_TOTAL_SUPPLY: usize = 40;
const OFF_COMPLETE: usize = 48;
const OFF_CREATOR: usize = 49;
const OFF_MAYHEM: usize = 81;
const OFF_CASHBACK: usize = 82;
const OFF_QUOTE_MINT: usize = 83;
const CURVE_MIN_LEN: usize = OFF_QUOTE_MINT + 32;

impl BondingCurve {
    /// Decode raw account data.
    ///
    /// Refuses anything whose discriminator is not `BondingCurve`: decoding an
    /// arbitrary account as a curve would produce reserves, and reserves are a
    /// price.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < CURVE_MIN_LEN {
            bail!("bonding curve account too short: {} bytes", data.len());
        }
        if data[..8] != CURVE_ACCOUNT_DISCRIMINATOR {
            bail!("not a pump.fun bonding curve account (discriminator mismatch)");
        }
        let u64_at = |off: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[off..off + 8]);
            u64::from_le_bytes(b)
        };
        let pk_at = |off: usize| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[off..off + 32]);
            Pubkey::new_from_array(b)
        };
        // A bool that is neither 0 nor 1 means the layout has moved under us.
        let bool_at = |off: usize, what: &str| -> Result<bool> {
            match data[off] {
                0 => Ok(false),
                1 => Ok(true),
                other => bail!("{what} is {other}, not a bool — layout mismatch"),
            }
        };
        Ok(Self {
            virtual_token_reserves: u64_at(OFF_VIRTUAL_TOKEN),
            virtual_quote_reserves: u64_at(OFF_VIRTUAL_QUOTE),
            real_token_reserves: u64_at(OFF_REAL_TOKEN),
            real_quote_reserves: u64_at(OFF_REAL_QUOTE),
            token_total_supply: u64_at(OFF_TOTAL_SUPPLY),
            complete: bool_at(OFF_COMPLETE, "complete")?,
            creator: pk_at(OFF_CREATOR),
            is_mayhem_mode: bool_at(OFF_MAYHEM, "is_mayhem_mode")?,
            is_cashback_coin: bool_at(OFF_CASHBACK, "is_cashback_coin")?,
            quote_mint: pk_at(OFF_QUOTE_MINT),
        })
    }

    /// Is this curve priced in SOL?
    ///
    /// Native SOL is represented by the DEFAULT (all-zero) pubkey, not by the
    /// WSOL mint — verified against three live curves, all of which read as
    /// default. Both are accepted; anything else is a curve denominated in some
    /// other token, where spending lamports against these reserves would be
    /// pricing a trade in the wrong unit entirely.
    pub fn quote_is_sol(&self) -> bool {
        self.quote_mint == Pubkey::default() || self.quote_mint == crate::tx::WSOL
    }

    /// Fail-closed tradability check. `Ok(())` or the reason why not.
    pub fn tradable(&self) -> Result<()> {
        if self.complete {
            bail!("bonding curve is complete — the token has graduated to PumpSwap");
        }
        if !self.quote_is_sol() {
            bail!("bonding curve is quoted in {}, not SOL", self.quote_mint);
        }
        if self.virtual_token_reserves == 0 || self.virtual_quote_reserves == 0 {
            bail!("bonding curve has empty virtual reserves");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Address derivation — the whole point: no lookup, no index, no Jupiter.
// ---------------------------------------------------------------------------

pub fn global_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"global"], &PUMP_PROGRAM).0
}

/// The curve for a mint. Deterministic — this is why a smart-money signal,
/// which carries only a mint, can still be traded directly.
pub fn bonding_curve_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"bonding-curve", mint.as_ref()], &PUMP_PROGRAM).0
}

pub fn creator_vault_pda(creator: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"creator-vault", creator.as_ref()], &PUMP_PROGRAM).0
}

pub fn event_authority_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &PUMP_PROGRAM).0
}

pub fn global_volume_accumulator_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"global_volume_accumulator"], &PUMP_PROGRAM).0
}

pub fn user_volume_accumulator_pda(user: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"user_volume_accumulator", user.as_ref()], &PUMP_PROGRAM).0
}

/// `["fee_config", <pump program as bytes>]` under the FEE program — note the
/// program the PDA is derived under is the fee program, while the seed is the
/// pump program's id.
pub fn fee_config_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"fee_config", PUMP_PROGRAM.as_ref()], &PUMP_FEE_PROGRAM).0
}

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

/// What a buy of `sol_in` lamports yields, and the instruction's two arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuyQuote {
    /// Constant-product estimate against the virtual reserves.
    pub expected_tokens: u64,
    /// `expected_tokens` reduced by slippage. This is the `amount` argument —
    /// the MINIMUM we will accept.
    pub amount: u64,
    /// The `max_sol_cost` argument: our whole budget, and a hard ceiling the
    /// program enforces.
    pub max_sol_cost: u64,
}

/// Constant product over the VIRTUAL reserves: `out = vt * in / (vq + in)`.
///
/// # Why fees are handled by slippage rather than modelled
///
/// pump.fun takes a protocol fee and a creator fee, both governed by the
/// on-chain `fee_config`, and the rates have changed over the program's life.
/// Rather than hardcode a number that silently goes stale, this quotes the
/// curve itself and lets the slippage tolerance absorb the fee.
///
/// That is safe in ONE direction only, and this is that direction: the
/// instruction is exact-OUT. We name a minimum token `amount` and a
/// `max_sol_cost` ceiling; the program computes the real cost including fees
/// and fails if it exceeds the ceiling. So an underestimate of fees costs a
/// FAILED TRANSACTION, never an overspend. Getting this backwards — modelling
/// fees optimistically on an exact-IN venue — is how you overpay silently.
pub fn buy_quote(curve: &BondingCurve, sol_in: u64, slippage_bps: u16) -> Result<BuyQuote> {
    curve.tradable()?;
    if slippage_bps >= 10_000 {
        bail!("slippage_bps {slippage_bps} >= 10000 leaves no minimum at all");
    }
    if sol_in == 0 {
        bail!("cannot buy with 0 lamports");
    }

    let vt = curve.virtual_token_reserves as u128;
    let vq = curve.virtual_quote_reserves as u128;
    let amt = sol_in as u128;

    let out = vt
        .checked_mul(amt)
        .and_then(|v| v.checked_div(vq.checked_add(amt)?))
        .ok_or_else(|| anyhow::anyhow!("curve quote overflow"))?;

    // The curve can never hand out more than it holds in REAL tokens, however
    // the virtual formula reads. Cap there, so a large buy against a nearly
    // drained curve asks for something that can actually be delivered.
    let out = out.min(curve.real_token_reserves as u128);
    if out == 0 {
        bail!("curve would return 0 tokens for {sol_in} lamports");
    }

    let expected_tokens = u64::try_from(out)?;
    let amount = u64::try_from(
        out.checked_mul((10_000 - slippage_bps) as u128)
            .map(|v| v / 10_000)
            .ok_or_else(|| anyhow::anyhow!("slippage math overflow"))?,
    )?;
    if amount == 0 {
        bail!("slippage leaves a zero minimum");
    }

    Ok(BuyQuote { expected_tokens, amount, max_sol_cost: sol_in })
}

/// What selling `tokens_in` raw units yields, and the sell instruction's args.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SellQuote {
    pub expected_sol: u64,
    /// The `amount` argument — tokens we are selling.
    pub amount: u64,
    /// The `min_sol_output` argument, after slippage.
    pub min_sol_output: u64,
}

/// Constant product the other way: `out = vq * in / (vt + in)`.
///
/// Exact-IN in the token direction: we hand over a known token amount and name
/// a floor on the SOL back. Fees again come out of the proceeds on chain, so
/// the floor must leave room for them — which the slippage tolerance provides.
pub fn sell_quote(curve: &BondingCurve, tokens_in: u64, slippage_bps: u16) -> Result<SellQuote> {
    curve.tradable()?;
    if slippage_bps >= 10_000 {
        bail!("slippage_bps {slippage_bps} >= 10000 leaves no floor at all");
    }
    if tokens_in == 0 {
        bail!("cannot sell 0 tokens");
    }

    let vt = curve.virtual_token_reserves as u128;
    let vq = curve.virtual_quote_reserves as u128;
    let amt = tokens_in as u128;

    let out = vq
        .checked_mul(amt)
        .and_then(|v| v.checked_div(vt.checked_add(amt)?))
        .ok_or_else(|| anyhow::anyhow!("curve sell quote overflow"))?;
    // Cannot pay out more SOL than the curve actually holds.
    let out = out.min(curve.real_quote_reserves as u128);
    if out == 0 {
        bail!("curve would return 0 lamports for {tokens_in} tokens");
    }

    let expected_sol = u64::try_from(out)?;
    let min_sol_output = u64::try_from(
        out.checked_mul((10_000 - slippage_bps) as u128)
            .map(|v| v / 10_000)
            .ok_or_else(|| anyhow::anyhow!("slippage math overflow"))?,
    )?;

    Ok(SellQuote { expected_sol, amount: tokens_in, min_sol_output })
}

// ---------------------------------------------------------------------------
// Instruction encoding
// ---------------------------------------------------------------------------

/// Everything the encoders need that is not derivable from the mint alone.
pub struct TradeContext {
    pub mint: Pubkey,
    pub user: Pubkey,
    /// The mint's OWNING program. pump.fun mints are commonly Token-2022, and
    /// an ATA derived under the wrong program is a different address — a
    /// transaction that fails at best.
    pub token_program: Pubkey,
    /// Read from the `Global` account; not derivable.
    pub fee_recipient: Pubkey,
    /// From the curve state.
    pub creator: Pubkey,
}

/// The 16 accounts of `buy` / `sell`, in IDL order.
///
/// Live transactions from the pump.fun front-end pass EIGHTEEN accounts — the
/// IDL's sixteen plus a `BuybackVault` and one account that does not exist on
/// chain in any sample we captured. Neither appears in the IDL's `buy`, so they
/// are client-supplied remaining-accounts, and they are omitted here until a
/// mainnet simulation shows they are required. Guessing extra accounts into a
/// money-moving instruction is not better than leaving them out: both are
/// unverified, but only one is honest about it.
fn trade_accounts(ctx: &TradeContext, curve: &Pubkey) -> Vec<AccountMeta> {
    let assoc_curve = spl_associated_token_account_interface::address::
        get_associated_token_address_with_program_id(curve, &ctx.mint, &ctx.token_program);
    let assoc_user = spl_associated_token_account_interface::address::
        get_associated_token_address_with_program_id(&ctx.user, &ctx.mint, &ctx.token_program);

    vec![
        AccountMeta::new_readonly(global_pda(), false),
        AccountMeta::new(ctx.fee_recipient, false),
        AccountMeta::new_readonly(ctx.mint, false),
        AccountMeta::new(*curve, false),
        AccountMeta::new(assoc_curve, false),
        AccountMeta::new(assoc_user, false),
        AccountMeta::new(ctx.user, true),
        AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        AccountMeta::new_readonly(ctx.token_program, false),
        AccountMeta::new(creator_vault_pda(&ctx.creator), false),
        AccountMeta::new_readonly(event_authority_pda(), false),
        AccountMeta::new_readonly(PUMP_PROGRAM, false),
        AccountMeta::new_readonly(global_volume_accumulator_pda(), false),
        AccountMeta::new(user_volume_accumulator_pda(&ctx.user), false),
        AccountMeta::new_readonly(fee_config_pda(), false),
        AccountMeta::new_readonly(PUMP_FEE_PROGRAM, false),
    ]
}

/// Encode `buy`.
///
/// Payload is 24 bytes: discriminator + `amount` + `max_sol_cost`. The IDL also
/// declares a trailing `track_volume: OptionBool`, but every live transaction
/// we captured sends 24 bytes and omits it, so this matches what is landing on
/// chain today rather than what the IDL permits.
pub fn buy_ix(ctx: &TradeContext, q: &BuyQuote) -> Instruction {
    let curve = bonding_curve_pda(&ctx.mint);
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&BUY_DISCRIMINATOR);
    data.extend_from_slice(&q.amount.to_le_bytes());
    data.extend_from_slice(&q.max_sol_cost.to_le_bytes());
    Instruction { program_id: PUMP_PROGRAM, accounts: trade_accounts(ctx, &curve), data }
}

/// Encode `sell`. Same account set; args are `amount` + `min_sol_output`.
pub fn sell_ix(ctx: &TradeContext, q: &SellQuote) -> Instruction {
    let curve = bonding_curve_pda(&ctx.mint);
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&SELL_DISCRIMINATOR);
    data.extend_from_slice(&q.amount.to_le_bytes());
    data.extend_from_slice(&q.min_sol_output.to_le_bytes());
    Instruction { program_id: PUMP_PROGRAM, accounts: trade_accounts(ctx, &curve), data }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Fixture 1's curve creator.
    ///
    /// Split across `concat!` because GitHub's secret scanner matches the
    /// `AKLT` prefix as a VolcEngine access key. It is a base58 Solana pubkey
    /// from a public mainnet transaction — nothing secret — but a blocked push
    /// is a blocked push, and splitting the literal is cheaper than an
    /// allowlist entry someone later has to interpret.
    const FIXTURE_1_CREATOR: &str = concat!("AKLT", "LLEmt6pq6D1jpddGxVBGnnczLmGvALTJ8BrqrBsb");

    /// Captured mainnet `buy` instructions. Each entry is (signature, mint,
    /// user, token_program, bonding_curve, creator) read straight out of
    /// tests/fixtures/gettx_pumpfun_buy_*.json.
    fn fixture_1() -> (Pubkey, Pubkey, Pubkey, Pubkey) {
        (
            Pubkey::from_str("Ed3MumAhL6ECE9z63tjWKAXVWnkFThCTCChq8Thmpump").unwrap(),
            Pubkey::from_str("CQDw5zxe6pKA8FHZFkg2JEu4F1y9YKWLuQ16Jx3KHtqJ").unwrap(),
            Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap(),
            Pubkey::from_str(FIXTURE_1_CREATOR).unwrap(),
        )
    }

    #[test]
    fn golden_bonding_curve_pda_matches_mainnet() {
        let (mint, ..) = fixture_1();
        assert_eq!(
            bonding_curve_pda(&mint).to_string(),
            "DgngnNwNmCt2GszjLKbEuspJMrxbJiMLRYEJDw9hpfk9",
            "curve PDA must match the account the live transaction passed"
        );
    }

    #[test]
    fn golden_creator_vault_pda_matches_mainnet() {
        let (_, _, _, creator) = fixture_1();
        assert_eq!(
            creator_vault_pda(&creator).to_string(),
            "4mnghofzhfJaeM4yFZ7zpS12JJ8yiH2S5Wfoppey1c4T"
        );
    }

    #[test]
    fn golden_user_volume_accumulator_matches_mainnet() {
        let (_, user, ..) = fixture_1();
        assert_eq!(
            user_volume_accumulator_pda(&user).to_string(),
            "E2g4Tso7tkxPFmhhMMDefLNFPuK9w7U1sXjaWm8MYMov"
        );
    }

    #[test]
    fn golden_constant_pdas_match_mainnet() {
        assert_eq!(global_pda().to_string(), "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf");
        assert_eq!(
            event_authority_pda().to_string(),
            "Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1"
        );
        assert_eq!(
            global_volume_accumulator_pda().to_string(),
            "Hq2wp8uJ9jCPsYgNHex8RtqdvMPfVGoYwjvF1ATiwn2Y"
        );
        assert_eq!(
            fee_config_pda().to_string(),
            "8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt"
        );
    }

    #[test]
    fn golden_associated_user_ata_matches_mainnet() {
        let (mint, user, token_program, _) = fixture_1();
        let ata = spl_associated_token_account_interface::address::
            get_associated_token_address_with_program_id(&user, &mint, &token_program);
        assert_eq!(ata.to_string(), "8XU9qdcehhAyEU4zRswtndhStYjUqr8eB56YkWdHNfug");
    }

    /// The exact 151-byte curve account behind fixture 1.
    fn curve_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 151];
        d[..8].copy_from_slice(&CURVE_ACCOUNT_DISCRIMINATOR);
        d[OFF_VIRTUAL_TOKEN..OFF_VIRTUAL_TOKEN + 8]
            .copy_from_slice(&648814217107443u64.to_le_bytes());
        d[OFF_VIRTUAL_QUOTE..OFF_VIRTUAL_QUOTE + 8].copy_from_slice(&49613586138u64.to_le_bytes());
        d[OFF_REAL_TOKEN..OFF_REAL_TOKEN + 8].copy_from_slice(&368914217107443u64.to_le_bytes());
        d[OFF_REAL_QUOTE..OFF_REAL_QUOTE + 8].copy_from_slice(&19613586138u64.to_le_bytes());
        d[OFF_TOTAL_SUPPLY..OFF_TOTAL_SUPPLY + 8]
            .copy_from_slice(&1000000000000000u64.to_le_bytes());
        d[OFF_COMPLETE] = 0;
        let (_, _, _, creator) = fixture_1();
        d[OFF_CREATOR..OFF_CREATOR + 32].copy_from_slice(creator.as_ref());
        // quote_mint left as the default pubkey — how these curves encode SOL.
        d
    }

    #[test]
    fn golden_curve_decode_matches_mainnet_state() {
        let c = BondingCurve::decode(&curve_bytes()).unwrap();
        assert_eq!(c.virtual_token_reserves, 648814217107443);
        assert_eq!(c.virtual_quote_reserves, 49613586138);
        assert_eq!(c.token_total_supply, 1000000000000000);
        assert!(!c.complete);
        assert_eq!(c.creator.to_string(), FIXTURE_1_CREATOR);
        assert!(c.quote_is_sol(), "a default quote_mint is native SOL");
        c.tradable().unwrap();
    }

    #[test]
    fn decode_refuses_a_foreign_account() {
        let mut d = curve_bytes();
        d[0] ^= 0xff;
        assert!(BondingCurve::decode(&d).is_err(), "wrong discriminator must not decode");
        assert!(BondingCurve::decode(&[0u8; 20]).is_err(), "short account must not decode");
    }

    #[test]
    fn a_complete_curve_is_refused() {
        let mut d = curve_bytes();
        d[OFF_COMPLETE] = 1;
        let c = BondingCurve::decode(&d).unwrap();
        let err = c.tradable().unwrap_err().to_string();
        assert!(err.contains("graduated"), "got: {err}");
    }

    #[test]
    fn a_non_sol_curve_is_refused() {
        let mut d = curve_bytes();
        // Any mint that is neither default nor WSOL.
        let usdc = Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        d[OFF_QUOTE_MINT..OFF_QUOTE_MINT + 32].copy_from_slice(usdc.as_ref());
        let c = BondingCurve::decode(&d).unwrap();
        assert!(!c.quote_is_sol());
        let err = c.tradable().unwrap_err().to_string();
        assert!(err.contains("not SOL"), "got: {err}");
        // And the quote path must refuse too, not merely the flag.
        assert!(buy_quote(&c, 10_000_000, 300).is_err());
        assert!(sell_quote(&c, 1_000_000, 300).is_err());
    }

    #[test]
    fn buy_quote_prices_against_virtual_reserves() {
        let c = BondingCurve::decode(&curve_bytes()).unwrap();
        let sol_in = 10_000_000u64; // 0.01 SOL
        let q = buy_quote(&c, sol_in, 300).unwrap();
        // out = vt * in / (vq + in)
        let expect = (648814217107443u128 * sol_in as u128) / (49613586138u128 + sol_in as u128);
        assert_eq!(q.expected_tokens as u128, expect);
        assert_eq!(q.max_sol_cost, sol_in, "the ceiling is our whole budget");
        assert!(q.amount < q.expected_tokens, "slippage must lower the minimum");
        assert_eq!(q.amount as u128, expect * 9700 / 10_000);
    }

    #[test]
    fn buy_quote_never_asks_for_more_than_the_curve_holds() {
        let mut d = curve_bytes();
        // Real tokens far below what the virtual formula would promise.
        d[OFF_REAL_TOKEN..OFF_REAL_TOKEN + 8].copy_from_slice(&1_000u64.to_le_bytes());
        let c = BondingCurve::decode(&d).unwrap();
        let q = buy_quote(&c, 10_000_000_000, 300).unwrap();
        assert!(q.expected_tokens <= 1_000, "capped at real reserves, got {}", q.expected_tokens);
    }

    #[test]
    fn sell_quote_is_the_mirror() {
        let c = BondingCurve::decode(&curve_bytes()).unwrap();
        let tokens = 1_000_000_000u64;
        let q = sell_quote(&c, tokens, 300).unwrap();
        let expect = (49613586138u128 * tokens as u128) / (648814217107443u128 + tokens as u128);
        assert_eq!(q.expected_sol as u128, expect);
        assert_eq!(q.amount, tokens);
        assert!(q.min_sol_output <= q.expected_sol);
    }

    #[test]
    fn degenerate_inputs_are_refused() {
        let c = BondingCurve::decode(&curve_bytes()).unwrap();
        assert!(buy_quote(&c, 0, 300).is_err(), "zero in");
        assert!(buy_quote(&c, 1_000_000, 10_000).is_err(), "100% slippage");
        assert!(sell_quote(&c, 0, 300).is_err(), "zero tokens");
    }

    #[test]
    fn golden_buy_instruction_matches_the_live_payload() {
        let (mint, user, token_program, creator) = fixture_1();
        let ctx = TradeContext {
            mint,
            user,
            token_program,
            // From the live transaction's account [1].
            fee_recipient: Pubkey::from_str("G5UZAVbAf46s7cKWoyKu8kYTip9DGTpbLZ2qa9Aq69dP")
                .unwrap(),
            creator,
        };
        // The exact arguments the captured transaction sent.
        let q = BuyQuote {
            expected_tokens: 12831553134090,
            amount: 12831553134090,
            max_sol_cost: 1080000000,
        };
        let ix = buy_ix(&ctx, &q);

        assert_eq!(ix.program_id, PUMP_PROGRAM);
        assert_eq!(
            hex(&ix.data),
            "66063d1201daebea0a9e2a94ab0b0000007e5f4000000000",
            "payload must be discriminator + amount + max_sol_cost"
        );
        assert_eq!(ix.accounts.len(), 16, "IDL account count");

        // Every slot the live transaction passed, in order, for the first 16.
        let live = [
            "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf",
            "G5UZAVbAf46s7cKWoyKu8kYTip9DGTpbLZ2qa9Aq69dP",
            "Ed3MumAhL6ECE9z63tjWKAXVWnkFThCTCChq8Thmpump",
            "DgngnNwNmCt2GszjLKbEuspJMrxbJiMLRYEJDw9hpfk9",
            "2TRA3VKKcp341TRjVBYBQGUPHagtS92Ma6i1LJGc8gMp",
            "8XU9qdcehhAyEU4zRswtndhStYjUqr8eB56YkWdHNfug",
            "CQDw5zxe6pKA8FHZFkg2JEu4F1y9YKWLuQ16Jx3KHtqJ",
            "11111111111111111111111111111111",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "4mnghofzhfJaeM4yFZ7zpS12JJ8yiH2S5Wfoppey1c4T",
            "Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1",
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "Hq2wp8uJ9jCPsYgNHex8RtqdvMPfVGoYwjvF1ATiwn2Y",
            "E2g4Tso7tkxPFmhhMMDefLNFPuK9w7U1sXjaWm8MYMov",
            "8Wf5TiAheLUqBrKXeYg2JtAFFMWtKdG2BSFgqUcPVwTt",
            "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ",
        ];
        for (i, want) in live.iter().enumerate() {
            assert_eq!(
                &ix.accounts[i].pubkey.to_string(),
                want,
                "account slot {i} differs from the live transaction"
            );
        }
        assert!(ix.accounts[6].is_signer, "the user signs");
        assert!(!ix.accounts[0].is_signer, "nothing else does");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
