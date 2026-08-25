//! Joins detection to execution: `PoolEvent` -> fresh state -> quote -> instructions.
//!
//! This is the composition layer. Every piece it calls is individually verified
//! (layouts, encoders, quote math); what happens here is putting them in the
//! right order with the right inputs.
//!
//! # Two rules this module exists to enforce
//!
//! 1. **State is re-read, never reused.** The reserves captured at detection are
//!    already stale by the time we could act on them — other buyers move the
//!    pool within the same second. A quote from stale reserves produces a wrong
//!    `minimum_amount_out`: too high and the swap reverts, too low and it is not
//!    protecting anything. So reserves, fees and market state are fetched fresh
//!    here, immediately before quoting.
//!
//! 2. **The venue must have a verified encoder.** PumpSwap is refused rather
//!    than approximated.

use crate::model::{Dex, PoolEvent};
use crate::quote::{self, Quote, Reserves};
use crate::rpc::RpcClient;
use crate::tx::{
    self, CpmmAmmConfig, CpmmPoolState, CpmmSwapAccounts, OpenBookMarket, PumpSwapGlobalConfig,
    PumpSwapPool, PumpSwapSwapAccounts, V4SwapAccounts, WSOL,
};
use anyhow::{Context, Result, bail};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

/// A fully built buy, ready to sign or simulate.
#[derive(Debug)]
pub struct ExecutionPlan {
    pub instructions: Vec<Instruction>,
    pub quote: Quote,
    pub venue: Dex,
}

/// Build a "buy the launched token with SOL" transaction for a detected pool.
///
/// `lamports_in` is the SOL to spend. Returns an error rather than a partial
/// plan whenever anything is missing or unverifiable.
#[allow(clippy::too_many_arguments)]
pub async fn build_buy(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    lamports_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let token_mint_str = event
        .new_token_mint
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no launched token identified"))?;
    let token_mint = tx::pk(token_mint_str)?;

    // Only SOL-quoted pools: we spend WSOL, so the quote asset must be WSOL.
    if event.quote_asset.as_deref() != Some(crate::model::WSOL_MINT) {
        bail!("only WSOL-quoted pools can be bought with SOL");
    }

    match event.dex {
        Dex::RaydiumCpmm => {
            build_cpmm(rpc, event, owner, token_mint, lamports_in, slippage_bps, unit_limit, priority_fee)
                .await
        }
        Dex::RaydiumV4 => {
            build_v4(rpc, event, owner, token_mint, lamports_in, slippage_bps, unit_limit, priority_fee)
                .await
        }
        Dex::PumpSwap => {
            build_pumpswap(rpc, event, owner, token_mint, lamports_in, slippage_bps, unit_limit, priority_fee)
                .await
        }
        // Detection-only venues. The builder below assumes a constant-product
        // pool priced by its reserve ratio; Meteora DLMM prices from the active
        // bin instead, so any quote built here would be wrong. Refusing is the
        // only correct behaviour — an approximate quote spends real money.
        dex @ (Dex::MeteoraDammV2 | Dex::MeteoraDlmm | Dex::MeteoraDbc) => {
            bail!("{} is detection-only — execution is not implemented for it", dex.label())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_cpmm(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_mint: Pubkey,
    lamports_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let pool_addr = &event.pool;
    let observation = event
        .swap_accounts
        .observation
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("cpmm pool has no observation account recorded"))?;

    // Fresh pool state: gives vaults, mints, and the accrued fees that must be
    // subtracted from the vault balances to get tradable reserves.
    let raw = rpc
        .account_data(pool_addr)
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read cpmm pool {pool_addr}"))?;
    let pool = CpmmPoolState::decode(&raw).context("decoding cpmm pool")?;

    let cfg_raw = rpc
        .account_data(&pool.amm_config.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read amm_config"))?;
    // Fee is per-pool; never assume a rate.
    let cfg = CpmmAmmConfig::decode(&cfg_raw).context("decoding amm_config")?;

    // We spend WSOL, so the input side is whichever side holds WSOL.
    let input_is_token_0 = pool.token_0_mint == WSOL;
    if !input_is_token_0 && pool.token_1_mint != WSOL {
        bail!("cpmm pool has no WSOL side");
    }

    let b0 = rpc
        .vault_balance_raw(&pool.token_0_vault.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read vault 0"))?;
    let b1 = rpc
        .vault_balance_raw(&pool.token_1_vault.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read vault 1"))?;

    let reserves = pool.reserves(b0, b1, input_is_token_0);
    let q = quote::quote(reserves, lamports_in, cfg.fee(), slippage_bps)
        .context("quoting cpmm swap")?;

    let (input_vault, output_vault) = if input_is_token_0 {
        (pool.token_0_vault, pool.token_1_vault)
    } else {
        (pool.token_1_vault, pool.token_0_vault)
    };

    let accounts = CpmmSwapAccounts {
        payer: *owner,
        amm_config: pool.amm_config,
        pool_state: tx::pk(pool_addr)?,
        user_input_ata: tx::ata(owner, &WSOL),
        user_output_ata: tx::ata(owner, &token_mint),
        input_vault,
        output_vault,
        input_mint: WSOL,
        output_mint: token_mint,
        observation_state: tx::pk(observation)?,
    };

    let instructions = tx::build_cpmm_buy(
        owner,
        &accounts,
        lamports_in,
        q.minimum_out,
        unit_limit,
        priority_fee,
    );
    Ok(ExecutionPlan { instructions, quote: q, venue: Dex::RaydiumCpmm })
}

#[allow(clippy::too_many_arguments)]
async fn build_v4(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_mint: Pubkey,
    lamports_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let sa = &event.swap_accounts;
    let open_orders = sa
        .open_orders
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("v4 pool has no open_orders recorded"))?;
    let market_addr = sa
        .market
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("v4 pool has no market recorded"))?;

    // The market holds bids/asks/event-queue/vaults, which exist nowhere else.
    let raw = rpc
        .account_data(market_addr)
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read openbook market {market_addr}"))?;
    let market_state = OpenBookMarket::decode(&raw).context("decoding openbook market")?;

    // v4 layout: base_* is the pool's coin side, quote_* the pc side.
    let coin_vault = tx::pk(&event.base_vault_or_err()?)?;
    let pc_vault = tx::pk(&event.quote_vault_or_err()?)?;

    // Reserves are the raw vault balances (v4 needs no fee subtraction).
    let coin_bal = rpc
        .vault_balance_raw(&coin_vault.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read coin vault"))?;
    let pc_bal = rpc
        .vault_balance_raw(&pc_vault.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read pc vault"))?;

    // We spend WSOL: the input reserve is the WSOL side.
    let coin_is_wsol = event.base_mint == crate::model::WSOL_MINT;
    let reserves = if coin_is_wsol {
        Reserves { input: coin_bal, output: pc_bal }
    } else {
        Reserves { input: pc_bal, output: coin_bal }
    };

    let q = quote::quote(reserves, lamports_in, quote::V4_FEE, slippage_bps)
        .context("quoting v4 swap")?;

    let accounts = V4SwapAccounts {
        amm: tx::pk(&event.pool)?,
        amm_open_orders: tx::pk(open_orders)?,
        // Emit the 17-account form; the 18-account variant is only needed when
        // target orders must be passed, and omitting it is always valid.
        amm_target_orders: None,
        pool_coin_vault: coin_vault,
        pool_pc_vault: pc_vault,
        market: tx::pk(market_addr)?,
        market_state,
        user_source: tx::ata(owner, &WSOL),
        user_destination: tx::ata(owner, &token_mint),
        user_owner: *owner,
    };

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    instructions.extend(tx::wrap_sol(owner, lamports_in));
    instructions.push(tx::ensure_token_ata(owner, &token_mint));
    instructions.push(tx::v4_swap_base_in(&accounts, lamports_in, q.minimum_out)?);
    instructions.push(tx::unwrap_sol(owner)?);

    Ok(ExecutionPlan { instructions, quote: q, venue: Dex::RaydiumV4 })
}

/// Everything a PumpSwap swap needs, in either direction.
///
/// Shared by the buy and sell paths deliberately: the fee source, the
/// Token-2022 program lookup and the three undocumented trailing accounts were
/// each established by experiment against the deployed program, and two copies
/// of that would drift.
#[cfg(feature = "sniper")]
struct PumpSwapCtx {
    pool: PumpSwapPool,
    accounts: PumpSwapSwapAccounts,
    remaining: Vec<solana_instruction::AccountMeta>,
    fee: crate::quote::FeeRate,
    base_bal: u64,
    quote_bal: u64,
    base_token_program: Pubkey,
    quote_token_program: Pubkey,
}

async fn pumpswap_ctx(rpc: &RpcClient, event: &PoolEvent, owner: &Pubkey) -> Result<PumpSwapCtx> {
    // Check the one prerequisite we cannot recover before doing any network
    // work: `pool_v2` is only observable in the pool's creation transaction, so
    // if it was not captured then no amount of fetching will help.
    let pool_v2 = event
        .swap_accounts
        .pool_v2
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!(
            "pumpswap pool has no pool_v2 recorded; it is only observable in the \
             pool's creation transaction, so this pool cannot be traded"
        ))?
        .to_string();

    let raw = rpc
        .account_data(&event.pool)
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read pumpswap pool {}", event.pool))?;
    let pool = PumpSwapPool::decode(&raw).context("decoding pumpswap pool")?;

    let gc_addr = tx::pumpswap_pda::global_config();
    let gc_raw = rpc
        .account_data(&gc_addr.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read pumpswap global_config"))?;
    let gc = PumpSwapGlobalConfig::decode(&gc_raw).context("decoding global_config")?;

    // Only the LP fee is taken on the constant-product curve; protocol and
    // creator fees come off the output. Empirically the LP-fee-only formula fit
    // a real swap to ~0.002%, far below any slippage tolerance.
    let fee = crate::quote::FeeRate {
        numerator: gc.lp_fee_basis_points,
        denominator: 10_000,
    };

    let base_bal = rpc
        .vault_balance_raw(&pool.pool_base_token_account.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read pool base vault"))?;
    let quote_bal = rpc
        .vault_balance_raw(&pool.pool_quote_token_account.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read pool quote vault"))?;

    // Token-2022 vs classic SPL Token is NOT interchangeable, and most pump.fun
    // mints are Token-2022. Read each mint's owner instead of assuming.
    let base_token_program = tx::pk(
        &rpc.account_owner(&pool.base_mint.to_string())
            .await
            .ok_or_else(|| anyhow::anyhow!("could not read base mint owner"))?,
    )?;
    let quote_token_program = tx::pk(
        &rpc.account_owner(&pool.quote_mint.to_string())
            .await
            .ok_or_else(|| anyhow::anyhow!("could not read quote mint owner"))?,
    )?;

    let accounts = PumpSwapSwapAccounts {
        pool: tx::pk(&event.pool)?,
        user: *owner,
        base_mint: pool.base_mint,
        quote_mint: pool.quote_mint,
        pool_base_token_account: pool.pool_base_token_account,
        pool_quote_token_account: pool.pool_quote_token_account,
        // Any of the eight listed recipients is valid.
        protocol_fee_recipient: gc.pick_fee_recipient(0)?,
        coin_creator: pool.coin_creator,
        base_token_program,
        quote_token_program,
    };

    // The deployed program requires these three trailing accounts. The second is
    // a BUYBACK fee recipient, a different set from the protocol fee recipients
    // — using the latter fails with BuybackFeeRecipientNotAuthorized (6053).
    let buyback = gc.pick_buyback_recipient(0)?;
    let remaining = vec![
        solana_instruction::AccountMeta::new(tx::pk(&pool_v2)?, false),
        solana_instruction::AccountMeta::new(buyback, false),
        solana_instruction::AccountMeta::new(
            spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
                &buyback, &pool.quote_mint, &quote_token_program),
            false,
        ),
    ];

    Ok(PumpSwapCtx {
        pool,
        accounts,
        remaining,
        fee,
        base_bal,
        quote_bal,
        base_token_program,
        quote_token_program,
    })
}

/// Build a PumpSwap buy.
///
/// Passes the three `remaining_accounts` the DEPLOYED program requires but its
/// published IDL never documents: `[pool_v2, fee_recipient, fee_recipient_ata]`.
/// `pool_v2` is captured at detection (see `parser::find_pumpswap_pool_v2`);
/// without it the program rejects the swap with `InvalidPoolV2` (6062).
///
/// Which instruction acquires the token depends on ORIENTATION:
///   * token is the pool's BASE  -> `buy`  (exact-out: name the tokens wanted,
///     cap the SOL spent)
///   * token is the pool's QUOTE -> `sell` (exact-in: spend WSOL as the base
///     side, require a minimum of the token back)
///
/// Getting this backwards would trade the wrong direction entirely.
#[allow(clippy::too_many_arguments)]
async fn build_pumpswap(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_mint: Pubkey,
    lamports_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let ctx = pumpswap_ctx(rpc, event, owner).await?;
    let PumpSwapCtx { pool, accounts, remaining, fee, base_bal, quote_bal,
                      base_token_program, quote_token_program } = ctx;

    let (swap_ix, q) = if pool.base_mint == token_mint && pool.quote_mint == WSOL {
        // Spend WSOL (quote) to receive the token (base): `buy`.
        let q = quote::quote(
            Reserves { input: quote_bal, output: base_bal },
            lamports_in,
            fee,
            slippage_bps,
        )?;
        // Exact-out: ask for the slippage-adjusted amount, cap the spend.
        (
            tx::pumpswap_buy_with_remaining(&accounts, q.minimum_out, lamports_in, false, &remaining),
            q,
        )
    } else if pool.quote_mint == token_mint && pool.base_mint == WSOL {
        // WSOL is the BASE here, so acquiring the token is a `sell`.
        let q = quote::quote(
            Reserves { input: base_bal, output: quote_bal },
            lamports_in,
            fee,
            slippage_bps,
        )?;
        (
            tx::pumpswap_sell_with_remaining(&accounts, lamports_in, q.minimum_out, &remaining),
            q,
        )
    } else {
        bail!(
            "pumpswap pool is not a WSOL/{token_mint} pair (base={}, quote={})",
            pool.base_mint,
            pool.quote_mint
        );
    };

    // The token's ATA must be created under ITS program, not the classic one.
    let token_program = if pool.base_mint == token_mint {
        base_token_program
    } else {
        quote_token_program
    };

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    instructions.extend(tx::wrap_sol(owner, lamports_in));
    instructions.push(tx::ensure_token_ata_with_program(owner, &token_mint, &token_program));
    instructions.push(swap_ix);
    instructions.push(tx::unwrap_sol(owner)?);

    Ok(ExecutionPlan { instructions, quote: q, venue: Dex::PumpSwap })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SwapAccounts;

    fn event(dex: Dex) -> PoolEvent {
        PoolEvent {
            dex,
            pool: "F613QHh9j8TA7uttEwKTPVnxguP5fQ3LEZN1yZKmRVez".into(),
            base_mint: crate::model::WSOL_MINT.into(),
            quote_mint: "27a5dUWm6MXzRXeyibGCy6dX1DYL6GKukGWA7hn1xqdX".into(),
            new_token_mint: Some("27a5dUWm6MXzRXeyibGCy6dX1DYL6GKukGWA7hn1xqdX".into()),
            quote_asset: Some(crate::model::WSOL_MINT.into()),
            quote_asset_vault: Some("Ddj6wgAmPiaatVbrQRvSnKHjtSV19AJtq75PGJMtRDqn".into()),
            quote_liquidity: Some(50.0),
            mint_authority_revoked: Some(true),
            freeze_authority_revoked: Some(true),
            risky_extensions: vec![],
            swap_accounts: SwapAccounts {
                amm_config: Some("D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2".into()),
                observation: Some("991fAA2ojSRhypXMGqXiLyTXXSNvEy5QYn2DdMwPvVX".into()),
                ..Default::default()
            },
            base_vault: Some("Ddj6wgAmPiaatVbrQRvSnKHjtSV19AJtq75PGJMtRDqn".into()),
            quote_vault: Some("73HAh4ksFm1QuNGUomDsARoBaTs1hFdzc5x23et4psw7".into()),
            lp_mint: None,
            lp_supply_at_detection: None,
            token_name: None,
            token_symbol: None,
            signature: "SIG".into(),
            slot: 1,
            detected_at: chrono::Utc::now(),
        }
    }

    fn rpc() -> RpcClient {
        RpcClient::new(&crate::config::RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            initial_delay_ms: 0,
            retries: 2,
            retry_delay_ms: 800,
            ..Default::default()
        })
    }

    /// A PumpSwap pool that is not a WSOL pair must be refused rather than
    /// traded in some arbitrary direction.
    #[tokio::test]
    async fn pumpswap_non_wsol_pool_is_refused() {
        let owner = Pubkey::new_unique();
        let mut ev = event(Dex::PumpSwap);
        // quote_asset drives the earlier WSOL gate.
        ev.quote_asset = Some(crate::model::USDC_MINT.into());
        assert!(build_buy(&rpc(), &ev, &owner, 1000, 300, 200_000, 1).await.is_err());
    }

    /// A pool with no recognized SOL side cannot be bought with SOL.
    #[tokio::test]
    async fn non_wsol_quote_is_refused() {
        let owner = Pubkey::new_unique();
        let mut ev = event(Dex::RaydiumCpmm);
        ev.quote_asset = Some(crate::model::USDC_MINT.into());
        let err = build_buy(&rpc(), &ev, &owner, 1000, 300, 200_000, 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("WSOL"), "got: {err}");
    }

    #[tokio::test]
    async fn missing_token_mint_is_refused() {
        let owner = Pubkey::new_unique();
        let mut ev = event(Dex::RaydiumCpmm);
        ev.new_token_mint = None;
        assert!(build_buy(&rpc(), &ev, &owner, 1000, 300, 200_000, 1).await.is_err());
    }

    /// v4 without a recorded market cannot be built — the market accounts exist
    /// nowhere else.
    #[tokio::test]
    async fn v4_without_market_is_refused() {
        let owner = Pubkey::new_unique();
        let mut ev = event(Dex::RaydiumV4);
        ev.swap_accounts.open_orders = Some("G7gL1j3XMhykfAfqN7KcPMUhGebrRyFu7TGy5KSysYgi".into());
        ev.swap_accounts.market = None;
        let err = build_buy(&rpc(), &ev, &owner, 1000, 300, 200_000, 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("market"), "got: {err}");
    }

    /// A PumpSwap pool whose creation we never saw has no `pool_v2`, and the
    /// program rejects the swap without it. Refuse with a reason that names it,
    /// rather than building a transaction guaranteed to fail.
    #[tokio::test]
    async fn pumpswap_without_pool_v2_is_refused() {
        let owner = Pubkey::new_unique();
        let mut ev = event(Dex::PumpSwap);
        ev.swap_accounts.pool_v2 = None;
        let err = build_buy(&rpc(), &ev, &owner, 1000, 300, 200_000, 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("pool_v2"), "reason must name the account: {err}");
    }

    /// LIVE: full PumpSwap path — detection-shaped event (with a captured
    /// `pool_v2`) through fresh state, quote, build, and simulation.
    ///
    ///   VOLENS_SIM_PAYER=<funded> \
    ///     cargo test --features sniper -- --ignored --nocapture live_execute_pumpswap
    #[tokio::test]
    #[ignore = "hits public mainnet RPC; needs VOLENS_SIM_PAYER"]
    async fn live_execute_pumpswap_end_to_end() {
        use base64::Engine;
        use solana_message::Message;
        use solana_transaction::Transaction;

        let Ok(payer) = std::env::var("VOLENS_SIM_PAYER") else {
            panic!("set VOLENS_SIM_PAYER to a pubkey that exists on-chain");
        };
        let owner = tx::pk(&payer).expect("valid pubkey");
        let rpc = rpc();

        let token = "wgwmoWeSe6cUcfafsTAqafNXU3RfyGNkWaBQiGqpump";
        let mut ev = event(Dex::PumpSwap);
        ev.pool = "HDMEBJbkTjR55L91aSCuPJvne99WQLzRBBy8Uxj23o2u".into();
        ev.base_mint = token.into();
        ev.quote_mint = crate::model::WSOL_MINT.into();
        ev.new_token_mint = Some(token.into());
        ev.quote_asset = Some(crate::model::WSOL_MINT.into());
        // As the parser would have captured it from the creation transaction.
        ev.swap_accounts.pool_v2 =
            Some("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB".into());

        let plan = build_buy(&rpc, &ev, &owner, 100_000_000, 300, 300_000, 1_000)
            .await
            .expect("pumpswap build should succeed");
        println!(
            "venue={:?} expected_out={} minimum_out={} impact_bps={}",
            plan.venue, plan.quote.expected_out, plan.quote.minimum_out,
            plan.quote.price_impact_bps
        );
        assert!(plan.quote.minimum_out > 0);

        let msg = Message::new(&plan.instructions, Some(&owner));
        let t = Transaction::new_unsigned(msg);
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&t).unwrap());
        let sim = rpc.simulate_transaction(&b64).await.expect("simulation");
        let logs = sim
            .get("logs").and_then(|l| l.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let err = sim.get("err").cloned().unwrap_or(serde_json::Value::Null);
        println!("err={err}");

        assert_eq!(err, serde_json::Value::Null, "pumpswap buy must simulate cleanly\n{logs}");
        assert!(logs.contains("Instruction: Buy"), "the Buy must execute\n{logs}");
    }

    /// LIVE: build a real CPMM buy end-to-end from a detection-shaped event,
    /// then simulate it. This is the composition test — every piece is
    /// individually verified, this proves they compose.
    ///
    ///   VOLENS_SIM_PAYER=<funded-pubkey> \
    ///     cargo test --features sniper -- --ignored --nocapture live_execute
    #[tokio::test]
    #[ignore = "hits public mainnet RPC; needs VOLENS_SIM_PAYER"]
    async fn live_execute_cpmm_end_to_end() {
        use base64::Engine;
        use solana_message::Message;
        use solana_transaction::Transaction;

        let Ok(payer) = std::env::var("VOLENS_SIM_PAYER") else {
            panic!("set VOLENS_SIM_PAYER to a pubkey that exists on-chain");
        };
        let owner = tx::pk(&payer).expect("valid pubkey");
        let rpc = rpc();

        let plan = build_buy(&rpc, &event(Dex::RaydiumCpmm), &owner, 10_000, 300, 250_000, 1_000)
            .await
            .expect("build should succeed");

        println!(
            "venue={:?} expected_out={} minimum_out={} impact_bps={}",
            plan.venue, plan.quote.expected_out, plan.quote.minimum_out, plan.quote.price_impact_bps
        );
        assert!(plan.quote.minimum_out > 0, "a real quote must protect the trade");
        assert!(plan.quote.minimum_out < plan.quote.expected_out);

        let msg = Message::new(&plan.instructions, Some(&owner));
        let t = Transaction::new_unsigned(msg);
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&t).unwrap());
        let sim = rpc.simulate_transaction(&b64).await.expect("simulation");
        let logs = sim
            .get("logs")
            .and_then(|l| l.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default();
        let err = sim.get("err").cloned().unwrap_or(serde_json::Value::Null);
        println!("err={err}\nlogs:\n{logs}");

        assert_eq!(err, serde_json::Value::Null, "composed buy must simulate cleanly");
        assert!(
            logs.contains("Instruction: SwapBaseInput"),
            "the swap must actually execute"
        );
    }
}

#[cfg(test)]
mod sell_tests {
    use super::*;
    use crate::model::{Dex, SwapAccounts};

    /// A real mint address: `build_sell` parses the mint before any venue
    /// check, so a placeholder would fail for the wrong reason.
    const TOKEN: &str = "AByynfTALEVQFkE3i52oiSbJNDV61PzrXMNffX4pump";

    fn route(dex: Dex) -> PoolEvent {
        PoolEvent {
            dex,
            pool: "POOL".into(),
            base_mint: TOKEN.into(),
            quote_mint: crate::model::WSOL_MINT.into(),
            new_token_mint: Some(TOKEN.into()),
            quote_asset: Some(crate::model::WSOL_MINT.into()),
            quote_asset_vault: None,
            quote_liquidity: Some(20.0),
            mint_authority_revoked: Some(true),
            freeze_authority_revoked: Some(true),
            risky_extensions: Vec::new(),
            lp_mint: None,
            base_vault: Some("BASEV".into()),
            quote_vault: Some("QUOTEV".into()),
            swap_accounts: SwapAccounts::default(),
            lp_supply_at_detection: None,
            token_name: None,
            token_symbol: None,
            signature: "SIG".into(),
            slot: 1,
            detected_at: chrono::Utc::now(),
        }
    }

    fn rpc() -> RpcClient {
        RpcClient::new(&crate::config::RpcConfig::default())
    }

    /// A venue with no verified encoder must refuse rather than approximate.
    /// The caller then falls back — which is right for a venue we cannot build,
    /// where a guessed `minimum_out` would spend real money on a wrong number.
    #[tokio::test]
    async fn detection_only_venues_refuse_to_build_a_sell() {
        for dex in [Dex::MeteoraDammV2, Dex::MeteoraDlmm, Dex::MeteoraDbc] {
            let e = build_sell(&rpc(), &route(dex), &Pubkey::new_unique(), 1_000, 300, 200_000, 0)
                .await
                .expect_err("must refuse");
            assert!(
                format!("{e:#}").contains("detection-only"),
                "expected a detection-only refusal, got: {e:#}"
            );
        }
    }

    /// The refusal must happen before any network work: `pool_v2` exists only
    /// in the pool's creation transaction, so no amount of fetching recovers it.
    #[tokio::test]
    async fn a_pumpswap_route_without_pool_v2_refuses_early() {
        let e = build_sell(&rpc(), &route(Dex::PumpSwap), &Pubkey::new_unique(), 1_000, 300, 200_000, 0)
            .await
            .expect_err("must refuse without pool_v2");
        assert!(format!("{e:#}").contains("pool_v2"), "got: {e:#}");
    }

    /// Selling nothing is a caller bug, not a trade.
    #[tokio::test]
    async fn selling_zero_is_refused() {
        let e = build_sell(&rpc(), &route(Dex::RaydiumV4), &Pubkey::new_unique(), 0, 300, 200_000, 0)
            .await
            .expect_err("must refuse");
        assert!(format!("{e:#}").contains("nothing to sell"), "got: {e:#}");
    }

    /// We can only pay out in SOL from a WSOL-quoted pool.
    #[tokio::test]
    async fn a_non_wsol_pool_cannot_be_sold_for_sol() {
        let mut r = route(Dex::RaydiumV4);
        r.quote_asset = Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into());
        let e = build_sell(&rpc(), &r, &Pubkey::new_unique(), 1_000, 300, 200_000, 0)
            .await
            .expect_err("must refuse");
        assert!(format!("{e:#}").contains("WSOL-quoted"), "got: {e:#}");
    }
}

/// Build a "sell the held token back to SOL" transaction for a known pool.
///
/// The mirror of [`build_buy`]: same freshly-read state, same verified
/// encoders, direction reversed. `token_amount_in` is in RAW token units.
///
/// This exists so an exit does not depend on a third-party quote API. Jupiter
/// has IP-blocked this box repeatedly; a stop-loss that routes through it would
/// fail exactly when it is needed, and be trusted while doing so.
///
/// Refuses rather than approximating, for the same reason `build_buy` does —
/// the caller falls back to Jupiter, which is the right answer for a venue we
/// cannot encode, but a wrong `minimum_out` is not.
#[allow(clippy::too_many_arguments)]
pub async fn build_sell(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_amount_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    if token_amount_in == 0 {
        bail!("nothing to sell");
    }
    let token_mint_str = event
        .new_token_mint
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("route has no token mint"))?;
    let token_mint = tx::pk(token_mint_str)?;
    if event.quote_asset.as_deref() != Some(crate::model::WSOL_MINT) {
        bail!("only WSOL-quoted pools can be sold for SOL");
    }

    match event.dex {
        Dex::RaydiumCpmm => {
            sell_cpmm(rpc, event, owner, token_mint, token_amount_in, slippage_bps, unit_limit, priority_fee).await
        }
        Dex::RaydiumV4 => {
            sell_v4(rpc, event, owner, token_mint, token_amount_in, slippage_bps, unit_limit, priority_fee).await
        }
        Dex::PumpSwap => {
            sell_pumpswap(rpc, event, owner, token_mint, token_amount_in, slippage_bps, unit_limit, priority_fee).await
        }
        dex @ (Dex::MeteoraDammV2 | Dex::MeteoraDlmm | Dex::MeteoraDbc) => {
            bail!("{} is detection-only — no verified sell encoder", dex.label())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn sell_cpmm(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_mint: Pubkey,
    amount_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let pool_addr = &event.pool;
    let observation = event
        .swap_accounts
        .observation
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("cpmm pool has no observation account recorded"))?;

    let raw = rpc
        .account_data(pool_addr)
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read cpmm pool {pool_addr}"))?;
    let pool = CpmmPoolState::decode(&raw).context("decoding cpmm pool")?;
    let cfg_raw = rpc
        .account_data(&pool.amm_config.to_string())
        .await
        .ok_or_else(|| anyhow::anyhow!("could not read amm_config"))?;
    let cfg = CpmmAmmConfig::decode(&cfg_raw).context("decoding amm_config")?;

    // Selling: the INPUT side is now the token, not WSOL. Getting this the
    // wrong way round would quote against the wrong reserve and set a
    // `minimum_out` that either reverts or protects nothing.
    let input_is_token_0 = pool.token_0_mint == token_mint;
    if !input_is_token_0 && pool.token_1_mint != token_mint {
        bail!("cpmm pool does not hold this token");
    }

    let b0 = rpc.vault_balance_raw(&pool.token_0_vault.to_string()).await
        .ok_or_else(|| anyhow::anyhow!("could not read vault 0"))?;
    let b1 = rpc.vault_balance_raw(&pool.token_1_vault.to_string()).await
        .ok_or_else(|| anyhow::anyhow!("could not read vault 1"))?;

    let reserves = pool.reserves(b0, b1, input_is_token_0);
    let q = quote::quote(reserves, amount_in, cfg.fee(), slippage_bps)
        .context("quoting cpmm sell")?;

    let (input_vault, output_vault) = if input_is_token_0 {
        (pool.token_0_vault, pool.token_1_vault)
    } else {
        (pool.token_1_vault, pool.token_0_vault)
    };

    let accounts = CpmmSwapAccounts {
        payer: *owner,
        amm_config: pool.amm_config,
        pool_state: tx::pk(pool_addr)?,
        user_input_ata: tx::ata(owner, &token_mint),
        user_output_ata: tx::ata(owner, &WSOL),
        input_vault,
        output_vault,
        input_mint: token_mint,
        output_mint: WSOL,
        observation_state: tx::pk(observation)?,
    };

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    // The WSOL account must exist to receive, and is closed afterwards so the
    // proceeds land as native SOL rather than sitting wrapped.
    instructions.push(tx::ensure_token_ata(owner, &WSOL));
    instructions.push(tx::cpmm_swap_base_input(&accounts, amount_in, q.minimum_out));
    instructions.push(tx::unwrap_sol(owner)?);
    Ok(ExecutionPlan { instructions, quote: q, venue: Dex::RaydiumCpmm })
}

#[allow(clippy::too_many_arguments)]
async fn sell_v4(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_mint: Pubkey,
    amount_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let sa = &event.swap_accounts;
    let open_orders = sa.open_orders.as_deref()
        .ok_or_else(|| anyhow::anyhow!("v4 route has no open_orders recorded"))?;
    let market_addr = sa.market.as_deref()
        .ok_or_else(|| anyhow::anyhow!("v4 route has no market recorded"))?;

    let raw = rpc.account_data(market_addr).await
        .ok_or_else(|| anyhow::anyhow!("could not read openbook market {market_addr}"))?;
    let market_state = OpenBookMarket::decode(&raw).context("decoding openbook market")?;

    let coin_vault = tx::pk(&event.base_vault_or_err()?)?;
    let pc_vault = tx::pk(&event.quote_vault_or_err()?)?;
    let coin_bal = rpc.vault_balance_raw(&coin_vault.to_string()).await
        .ok_or_else(|| anyhow::anyhow!("could not read coin vault"))?;
    let pc_bal = rpc.vault_balance_raw(&pc_vault.to_string()).await
        .ok_or_else(|| anyhow::anyhow!("could not read pc vault"))?;

    // Selling the token: the input reserve is the TOKEN side, the mirror of the
    // buy path where it is the WSOL side.
    let coin_is_wsol = event.base_mint == crate::model::WSOL_MINT;
    let reserves = if coin_is_wsol {
        Reserves { input: pc_bal, output: coin_bal }
    } else {
        Reserves { input: coin_bal, output: pc_bal }
    };

    let q = quote::quote(reserves, amount_in, quote::V4_FEE, slippage_bps)
        .context("quoting v4 sell")?;

    // Direction on v4 is expressed ONLY through source/destination, so the same
    // encoder serves both ways round.
    let accounts = V4SwapAccounts {
        amm: tx::pk(&event.pool)?,
        amm_open_orders: tx::pk(open_orders)?,
        amm_target_orders: None,
        pool_coin_vault: coin_vault,
        pool_pc_vault: pc_vault,
        market: tx::pk(market_addr)?,
        market_state,
        user_source: tx::ata(owner, &token_mint),
        user_destination: tx::ata(owner, &WSOL),
        user_owner: *owner,
    };

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    instructions.push(tx::ensure_token_ata(owner, &WSOL));
    instructions.push(tx::v4_swap_base_in(&accounts, amount_in, q.minimum_out)?);
    instructions.push(tx::unwrap_sol(owner)?);
    Ok(ExecutionPlan { instructions, quote: q, venue: Dex::RaydiumV4 })
}

#[allow(clippy::too_many_arguments)]
async fn sell_pumpswap(
    rpc: &RpcClient,
    event: &PoolEvent,
    owner: &Pubkey,
    token_mint: Pubkey,
    amount_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let PumpSwapCtx { pool, accounts, remaining, fee, base_bal, quote_bal, .. } =
        pumpswap_ctx(rpc, event, owner).await?;

    // The mirror of the buy path's orientation check. Which instruction SELLS
    // depends on which side the token sits on, and getting it backwards would
    // trade the wrong direction entirely.
    let (swap_ix, q) = if pool.base_mint == token_mint && pool.quote_mint == WSOL {
        // Token is base, WSOL is quote: spend the token, receive WSOL — `sell`.
        let q = quote::quote(
            Reserves { input: base_bal, output: quote_bal },
            amount_in,
            fee,
            slippage_bps,
        )?;
        (tx::pumpswap_sell_with_remaining(&accounts, amount_in, q.minimum_out, &remaining), q)
    } else if pool.quote_mint == token_mint && pool.base_mint == WSOL {
        // WSOL is base, so disposing of the quote token is a `buy`: name the
        // WSOL wanted, cap the tokens spent.
        let q = quote::quote(
            Reserves { input: quote_bal, output: base_bal },
            amount_in,
            fee,
            slippage_bps,
        )?;
        (tx::pumpswap_buy_with_remaining(&accounts, q.minimum_out, amount_in, false, &remaining), q)
    } else {
        bail!(
            "pumpswap pool is not a WSOL/{token_mint} pair (base={}, quote={})",
            pool.base_mint,
            pool.quote_mint
        );
    };

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    // Receive into WSOL, then close the account so the proceeds land as native
    // SOL rather than sitting wrapped in an ATA the operator has to notice.
    instructions.push(tx::ensure_token_ata(owner, &WSOL));
    instructions.push(swap_ix);
    instructions.push(tx::unwrap_sol(owner)?);
    Ok(ExecutionPlan { instructions, quote: q, venue: Dex::PumpSwap })
}

// ---------------------------------------------------------------------------
// pump.fun bonding curve
// ---------------------------------------------------------------------------

/// What a curve trade needs beyond the mint: read once, used by both directions.
///
/// Two RPC reads and one owner lookup. Compare with the Jupiter path's two API
/// round trips on a globally throttled lane — this is the whole reason the
/// direct path exists.
async fn curve_context(
    rpc: &RpcClient,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<(crate::pumpfun::BondingCurve, crate::pumpfun::Global, crate::pumpfun::TradeContext)> {
    let curve_addr = crate::pumpfun::bonding_curve_pda(mint).to_string();
    let global_addr = crate::pumpfun::global_pda().to_string();
    let mint_str = mint.to_string();

    // Independent reads — the curve, the fee config, and the mint's owning
    // program have no ordering between them.
    let (curve_raw, global_raw, mint_owner) = tokio::join!(
        rpc.account_data(&curve_addr),
        rpc.account_data(&global_addr),
        rpc.account_owner(&mint_str),
    );

    let curve = crate::pumpfun::BondingCurve::decode(
        &curve_raw.ok_or_else(|| anyhow::anyhow!("no pump.fun bonding curve for {mint_str}"))?,
    )?;
    let global = crate::pumpfun::Global::decode(
        &global_raw.ok_or_else(|| anyhow::anyhow!("could not read pump.fun global account"))?,
    )?;
    // Fails CLOSED. pump.fun mints are commonly Token-2022, and an ATA derived
    // under the wrong program is a DIFFERENT ADDRESS — the transaction fails,
    // or worse, initialises an account we then cannot spend from.
    let token_program = tx::pk(
        &mint_owner.ok_or_else(|| anyhow::anyhow!("could not read the owning program of {mint_str}"))?,
    )?;

    Ok((
        curve,
        global,
        crate::pumpfun::TradeContext {
            mint: *mint,
            user: *owner,
            token_program,
            // NOT `global.fee_recipient` — mainnet rejects it as NotAuthorized.
            // See `Global::authorized_fee_recipient`. Spread across the set by
            // the mint, so trades do not all pin one account.
            fee_recipient: global.authorized_fee_recipient(mint.as_ref()[0] as usize)?,
            creator: curve.creator,
        },
    ))
}

/// The curve's current price in SOL per whole token, for guards and logging.
pub fn curve_price_sol(curve: &crate::pumpfun::BondingCurve, decimals: u8) -> f64 {
    let vq = curve.virtual_quote_reserves as f64 / 1e9;
    let vt = curve.virtual_token_reserves as f64 / 10f64.powi(decimals as i32);
    if vt <= 0.0 { 0.0 } else { vq / vt }
}

/// Buy a pump.fun token DIRECTLY on its bonding curve.
///
/// No pool lookup and no quote API: the curve address is a PDA of the mint, so
/// a smart-money signal — which carries only a mint — is enough.
///
/// `min_curve_liquidity_sol` is the CURVE floor, not the pool floor. A curve
/// has no LP for a deployer to pull, so the pool guard's reasoning does not
/// transfer and applying it would refuse every early entry. 0 disables.
#[allow(clippy::too_many_arguments)]
pub async fn build_pumpfun_buy(
    rpc: &RpcClient,
    mint: &Pubkey,
    owner: &Pubkey,
    lamports_in: u64,
    slippage_bps: u16,
    min_curve_liquidity_sol: f64,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    let (curve, global, ctx) = curve_context(rpc, mint, owner).await?;

    // `tradable()` already refuses a completed or non-SOL-quoted curve; this is
    // the operator's own floor on top.
    if min_curve_liquidity_sol > 0.0 {
        let real_sol = curve.real_quote_reserves as f64 / 1e9;
        if real_sol < min_curve_liquidity_sol {
            bail!(
                "curve liquidity {real_sol:.4} SOL below the {min_curve_liquidity_sol} SOL floor"
            );
        }
    }

    let q = crate::pumpfun::buy_quote(&curve, &global, lamports_in, slippage_bps)?;

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    // The curve takes native SOL, NOT wrapped — so no wrap/unwrap here, unlike
    // every AMM path in this module. Only the token side needs an account.
    instructions.push(tx::ensure_token_ata_with_program(owner, mint, &ctx.token_program));
    instructions.push(crate::pumpfun::buy_ix(&ctx, &q));

    Ok(ExecutionPlan {
        instructions,
        quote: Quote {
            expected_out: q.expected_tokens,
            minimum_out: q.amount,
            // Share of the quote reserve this trade consumes — the same meaning
            // the AMM paths give it, so the impact guard reads it correctly.
            // Reporting 0 here would hand every curve trade a free pass.
            price_impact_bps: curve_impact_bps(&curve, lamports_in),
        },
        venue: Dex::PumpSwap,
    })
}

/// How far this buy moves the curve, in basis points of the quote reserve.
fn curve_impact_bps(curve: &crate::pumpfun::BondingCurve, lamports_in: u64) -> u32 {
    let vq = curve.virtual_quote_reserves as u128;
    if vq == 0 {
        return u32::MAX;
    }
    let bps = (lamports_in as u128)
        .saturating_mul(10_000)
        .checked_div(vq.saturating_add(lamports_in as u128))
        .unwrap_or(0);
    u32::try_from(bps).unwrap_or(u32::MAX)
}

/// Sell a pump.fun token DIRECTLY on its bonding curve.
///
/// The exit half matters more than the entry: a token we can buy and cannot
/// sell is strictly worse than one we skipped. This deliberately does not
/// depend on Jupiter, which has IP-blocked this box before and would therefore
/// fail exactly when a stop-loss needs it.
#[allow(clippy::too_many_arguments)]
pub async fn build_pumpfun_sell(
    rpc: &RpcClient,
    mint: &Pubkey,
    owner: &Pubkey,
    token_amount_in: u64,
    slippage_bps: u16,
    unit_limit: u32,
    priority_fee: u64,
) -> Result<ExecutionPlan> {
    if token_amount_in == 0 {
        bail!("nothing to sell");
    }
    let (curve, _global, ctx) = curve_context(rpc, mint, owner).await?;
    let q = crate::pumpfun::sell_quote(&curve, token_amount_in, slippage_bps)?;

    let mut instructions = tx::compute_budget(unit_limit, priority_fee);
    // No ATA creation: we are selling a balance we already hold, so the account
    // exists by definition. No unwrap either — the curve pays native SOL.
    instructions.push(crate::pumpfun::sell_ix(&ctx, &q));

    Ok(ExecutionPlan {
        instructions,
        quote: Quote {
            expected_out: q.expected_sol,
            minimum_out: q.min_sol_output,
            price_impact_bps: 0,
        },
        venue: Dex::PumpSwap,
    })
}

#[cfg(test)]
mod pumpfun_sim {
    use super::*;

    /// Simulate a REAL pump.fun bonding-curve buy and sell against mainnet.
    ///
    /// This is the gate the encoder has to pass before anything is allowed to
    /// trade through it. Golden fixtures prove we reproduce an instruction that
    /// once landed; only the node can tell us the instruction we build TODAY,
    /// against today's accounts, actually executes.
    ///
    /// `sigVerify: false` — nothing is signed, nothing is submitted, and a
    /// pubkey cannot sign, so this adds no capability.
    ///
    ///   VOLENS_SIM_PAYER=<funded-pubkey> VOLENS_SIM_MINT=<live-curve-mint> \
    ///     cargo test --features sniper -- --ignored --nocapture pumpfun_sim
    #[tokio::test]
    #[ignore = "hits mainnet RPC; needs VOLENS_SIM_PAYER and VOLENS_SIM_MINT"]
    async fn live_simulate_pumpfun_buy_and_sell() {
        use solana_message::Message;
        use solana_transaction::Transaction;

        let payer = std::env::var("VOLENS_SIM_PAYER")
            .expect("set VOLENS_SIM_PAYER to a pubkey that EXISTS on-chain");
        let mint_str = std::env::var("VOLENS_SIM_MINT")
            .expect("set VOLENS_SIM_MINT to a pump.fun mint whose curve is still live");
        let owner = tx::pk(&payer).expect("VOLENS_SIM_PAYER must be a valid pubkey");
        let mint = tx::pk(&mint_str).expect("VOLENS_SIM_MINT must be a valid pubkey");

        let url = std::env::var("RPC_URL")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".into());
        let cfg = crate::config::RpcConfig {
            url,
            initial_delay_ms: 0,
            retries: 3,
            retry_delay_ms: 1500,
            ..Default::default()
        };
        let rpc = crate::rpc::RpcClient::new(&cfg);

        let simulate = |plan: ExecutionPlan, label: &'static str| {
            let rpc = &rpc;
            async move {
                let msg = Message::new(&plan.instructions, Some(&owner));
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
                println!(
                    "\n===== {label} =====\nexpected_out={} minimum_out={}\nerr={err}\nunits={units}\nlogs:\n{logs}\n",
                    plan.quote.expected_out, plan.quote.minimum_out
                );
                (err, units, logs)
            }
        };

        // --- Which fee recipient does the program actually accept? ---
        // Mainnet rejected both the `fee_recipient` field and array[0] with
        // NotAuthorized, so rather than guess again, ask the node about every
        // candidate. Whatever passes here is the ground truth the encoder uses.
        if std::env::var("VOLENS_SIM_PROBE_FEE").is_ok() {
            let g_raw = rpc
                .account_data(&crate::pumpfun::global_pda().to_string())
                .await
                .expect("global");
            let g = crate::pumpfun::Global::decode(&g_raw).expect("decode global");
            let mut cands = vec![("field", g.fee_recipient)];
            for (i, r) in g.fee_recipients.iter().enumerate() {
                cands.push((Box::leak(format!("array[{i}]").into_boxed_str()), *r));
            }
            for (label, cand) in cands {
                let mut plan =
                    build_pumpfun_buy(&rpc, &mint, &owner, 10_000_000, 300, 0.0, 300_000, 100_000)
                        .await
                        .expect("build buy");
                let last = plan.instructions.len() - 1;
                plan.instructions[last].accounts[1].pubkey = cand;
                let msg = Message::new(&plan.instructions, Some(&owner));
                let txn = Transaction::new_unsigned(msg);
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD
                    .encode(bincode::serialize(&txn).unwrap());
                let sim = rpc.simulate_transaction(&b64).await.expect("sim");
                let err = sim.get("err").cloned().unwrap_or(serde_json::Value::Null);
                println!("FEE PROBE {label:10} {cand}  -> {}",
                    if err.is_null() { "ACCEPTED".to_string() } else { format!("{err}") });
            }
            return;
        }

        // --- BUY ---
        let buy = build_pumpfun_buy(&rpc, &mint, &owner, 10_000_000, 300, 0.0, 300_000, 100_000)
            .await
            .expect("build buy");
        let (err, units, logs) = simulate(buy, "BUY").await;
        assert_eq!(err, serde_json::Value::Null, "buy must simulate clean\nlogs:\n{logs}");
        assert!(units > 0, "no compute consumed — nothing executed");
        assert!(
            logs.contains("Instruction: Buy"),
            "the pump.fun buy instruction must have run\nlogs:\n{logs}"
        );

        // --- SELL ---
        // Sells whatever the payer already holds. A payer with no balance
        // proves nothing about the sell path, so that is called out rather than
        // passing quietly.
        let held = rpc
            .token_balance_raw(&payer, &mint_str)
            .await
            .map(|(raw, _)| raw)
            .unwrap_or(0);
        if held == 0 {
            println!("SELL SKIPPED: payer holds none of {mint_str} — fund it to prove the exit");
            return;
        }
        let sell = build_pumpfun_sell(&rpc, &mint, &owner, held, 500, 300_000, 100_000)
            .await
            .expect("build sell");
        let (err, units, logs) = simulate(sell, "SELL").await;
        assert_eq!(err, serde_json::Value::Null, "sell must simulate clean\nlogs:\n{logs}");
        assert!(units > 0, "no compute consumed on the sell");
        assert!(
            logs.contains("Instruction: Sell"),
            "the pump.fun sell instruction must have run\nlogs:\n{logs}"
        );
    }
}
