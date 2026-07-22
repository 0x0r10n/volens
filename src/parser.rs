//! Instruction decoding: turn a streamed transaction into zero or more
//! `ParsedPool`s (a pool-creation instruction was found and its accounts read).
//!
//! Classification (which mint is "new", quote-pair filtering) happens later in
//! `detector` so this module stays a pure, testable decode step.

use crate::model::{
    Dex, PUMPSWAP_CREATE_POOL_DISC, RAYDIUM_CPMM_INITIALIZE_DISC, RAYDIUM_V4_INITIALIZE2_TAG,
};
use yellowstone_grpc_proto::prelude::{SubscribeUpdateTransactionInfo, TransactionStatusMeta};

/// A pool-creation instruction successfully decoded from a transaction.
#[derive(Debug, Clone)]
pub struct ParsedPool {
    pub dex: Dex,
    pub pool: String,
    pub base_mint: String,
    pub quote_mint: String,
    /// Vault holding `base_mint`.
    pub base_vault: String,
    /// Vault holding `quote_mint`.
    pub quote_vault: String,
    pub lp_mint: String,
    /// Venue-dependent accounts a swap will need.
    pub swap_accounts: crate::model::SwapAccounts,
}

/// A target program the parser should recognize: its raw 32-byte pubkey and the
/// DEX it maps to. Precomputed once at startup so the hot path does no base58.
#[derive(Debug, Clone)]
pub struct TargetProgram {
    pub key: [u8; 32],
    pub dex: Dex,
}

impl TargetProgram {
    pub fn new(dex: Dex) -> Self {
        let mut key = [0u8; 32];
        bs58::decode(dex.program_id())
            .onto(&mut key)
            .expect("valid hardcoded program id");
        Self { key, dex }
    }
}

/// Scan a transaction (top-level + inner instructions) for pool creations.
pub fn parse_transaction(
    tx_info: &SubscribeUpdateTransactionInfo,
    targets: &[TargetProgram],
) -> Vec<ParsedPool> {
    let mut out = Vec::new();

    let Some(tx) = tx_info.transaction.as_ref() else { return out };
    let Some(msg) = tx.message.as_ref() else { return out };

    // Resolve the full account-key table: static keys ++ ALT writable ++ ALT readonly.
    let keys = resolve_account_keys(&msg.account_keys, tx_info.meta.as_ref());

    // Flatten every instruction once: pool creation is frequently a CPI (routers,
    // the Pump migration), and PumpSwap additionally needs an account that lives
    // in a SIBLING instruction of the same transaction.
    let mut all: Vec<(&[u8], &[u8], u32)> = Vec::new();
    for ix in &msg.instructions {
        all.push((&ix.accounts, &ix.data, ix.program_id_index));
    }
    if let Some(meta) = tx_info.meta.as_ref() {
        for inner in &meta.inner_instructions {
            for ix in &inner.instructions {
                all.push((&ix.accounts, &ix.data, ix.program_id_index));
            }
        }
    }

    for (accounts, data, pidx) in &all {
        if let Some(mut p) = decode_ix(*pidx, accounts, data, &keys, targets) {
            if p.dex == Dex::PumpSwap {
                p.swap_accounts.pool_v2 = find_pumpswap_pool_v2(&all, &keys, &p.pool);
            }
            out.push(p);
        }
    }

    out
}

/// Recover PumpSwap's undocumented `pool_v2` from a sibling instruction.
///
/// A PumpSwap pool is created by a migration transaction that also performs the
/// first `buy`; that buy carries `pool_v2` as its FIRST `remaining_account`
/// (index 23 for buy, 21 for sell — the counts the IDL declares). The account is
/// usually uninitialized, so it cannot be found by inspecting chain state, and
/// it is not derivable — capturing it here is the only reliable route.
fn find_pumpswap_pool_v2(
    all: &[(&[u8], &[u8], u32)],
    keys: &[[u8; 32]],
    pool: &str,
) -> Option<String> {
    let program = TargetProgram::new(Dex::PumpSwap).key;
    for (accounts, data, pidx) in all {
        if keys.get(*pidx as usize) != Some(&program) || data.len() < 8 {
            continue;
        }
        let declared = if data[..8] == crate::swap::PUMPSWAP_BUY_DISC {
            23
        } else if data[..8] == crate::swap::PUMPSWAP_SELL_DISC {
            21
        } else {
            continue;
        };
        // Must be the same pool, and must actually carry a remaining account.
        let same_pool = accounts
            .first()
            .and_then(|i| keys.get(*i as usize))
            .map(|k| bs58::encode(k).into_string())
            .is_some_and(|p| p == pool);
        if !same_pool || accounts.len() <= declared {
            continue;
        }
        return keys
            .get(accounts[declared] as usize)
            .map(|k| bs58::encode(k).into_string());
    }
    None
}

/// Build the combined account-key list an instruction's indices refer to.
fn resolve_account_keys(
    static_keys: &[Vec<u8>],
    meta: Option<&TransactionStatusMeta>,
) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(static_keys.len() + 8);
    for k in static_keys {
        keys.push(to_key(k));
    }
    if let Some(meta) = meta {
        for k in &meta.loaded_writable_addresses {
            keys.push(to_key(k));
        }
        for k in &meta.loaded_readonly_addresses {
            keys.push(to_key(k));
        }
    }
    keys
}

/// Decode a single instruction if it targets one of our programs and matches the
/// pool-creation discriminator for that DEX.
fn decode_ix(
    program_id_index: u32,
    accounts: &[u8],
    data: &[u8],
    keys: &[[u8; 32]],
    targets: &[TargetProgram],
) -> Option<ParsedPool> {
    let program = keys.get(program_id_index as usize)?;
    let dex = targets.iter().find(|t| &t.key == program)?.dex;

    if !matches_creation(dex, data) {
        return None;
    }

    let layout = dex.layout();
    if accounts.len() < layout.min_accounts {
        return None;
    }

    let account_at = |ix_local: usize| -> Option<String> {
        let global = *accounts.get(ix_local)? as usize;
        keys.get(global).map(|k| bs58::encode(k).into_string())
    };

    Some(ParsedPool {
        dex,
        pool: account_at(layout.pool)?,
        base_mint: account_at(layout.base_mint)?,
        quote_mint: account_at(layout.quote_mint)?,
        base_vault: account_at(layout.base_vault)?,
        quote_vault: account_at(layout.quote_vault)?,
        lp_mint: account_at(layout.lp_mint)?,
        swap_accounts: crate::model::SwapAccounts {
            amm_config: layout.amm_config.and_then(&account_at),
            observation: layout.observation.and_then(&account_at),
            open_orders: layout.open_orders.and_then(&account_at),
            target_orders: layout.target_orders.and_then(&account_at),
            market: layout.market.and_then(&account_at),
            // Filled by the caller from a sibling instruction (PumpSwap only).
            pool_v2: None,
        },
    })
}

/// Does this instruction's data match the DEX's pool-creation discriminator?
fn matches_creation(dex: Dex, data: &[u8]) -> bool {
    match dex {
        // Borsh single-byte tag; `Initialize2` == 1.
        Dex::RaydiumV4 => data.first() == Some(&RAYDIUM_V4_INITIALIZE2_TAG),
        Dex::RaydiumCpmm => data.len() >= 8 && data[..8] == RAYDIUM_CPMM_INITIALIZE_DISC,
        Dex::PumpSwap => data.len() >= 8 && data[..8] == PUMPSWAP_CREATE_POOL_DISC,
    }
}

fn to_key(bytes: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    let n = bytes.len().min(32);
    k[..n].copy_from_slice(&bytes[..n]);
    k
}

/// Convenience: base58 signature of the transaction.
pub fn signature_b58(tx_info: &SubscribeUpdateTransactionInfo) -> String {
    bs58::encode(&tx_info.signature).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn anchor_disc(name: &str) -> [u8; 8] {
        let mut h = Sha256::new();
        h.update(format!("global:{name}").as_bytes());
        let out = h.finalize();
        let mut d = [0u8; 8];
        d.copy_from_slice(&out[..8]);
        d
    }

    #[test]
    fn cpmm_discriminator_is_correct() {
        assert_eq!(anchor_disc("initialize"), RAYDIUM_CPMM_INITIALIZE_DISC);
    }

    #[test]
    fn pumpswap_discriminator_is_correct() {
        assert_eq!(anchor_disc("create_pool"), PUMPSWAP_CREATE_POOL_DISC);
    }

    #[test]
    fn target_program_keys_decode() {
        for dex in Dex::all() {
            let t = TargetProgram::new(dex);
            assert_eq!(bs58::encode(t.key).into_string(), dex.program_id());
        }
    }

    #[test]
    fn v4_matches_only_tag_1() {
        assert!(matches_creation(Dex::RaydiumV4, &[1, 0, 0]));
        assert!(!matches_creation(Dex::RaydiumV4, &[9, 0, 0])); // swap, not init
        assert!(!matches_creation(Dex::RaydiumV4, &[]));
    }

    // -----------------------------------------------------------------------
    // Golden fixtures captured from real mainnet creation transactions
    // (2026-07-19). These lock in the account-index layouts: if a program
    // upgrade shifts an index, these fail instead of silently reporting the
    // wrong mint.
    // -----------------------------------------------------------------------

    /// Build (keys, accounts) where `keys[0]` is the program and the
    /// instruction references the remaining accounts in order.
    fn fixture(program: &str, accts: &[&str]) -> (Vec<[u8; 32]>, Vec<u8>) {
        let mut keys = vec![decode_key(program)];
        keys.extend(accts.iter().map(|a| decode_key(a)));
        let idxs: Vec<u8> = (1..=accts.len() as u8).collect();
        (keys, idxs)
    }

    fn decode_key(s: &str) -> [u8; 32] {
        let mut k = [0u8; 32];
        bs58::decode(s).onto(&mut k).expect("valid base58 pubkey");
        k
    }

    const WSOL: &str = "So11111111111111111111111111111111111111112";

    #[test]
    fn golden_raydium_v4_initialize2() {
        // tx 4kAcRNUt5UXPFGJVf22gv7ziNPosBQGZuvFto9RP9TGC1s8zoaqv9SR6qH8jeBDnthyFGk9vcGPfhggWVmCEkpP9
        let accts = [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "11111111111111111111111111111111",
            "SysvarRent111111111111111111111111111111111",
            "FkaEYE8zVdx5eR3LwFsQmPhvXafgHyUmPYCDVSwfijCc", // 4 pool
            "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
            "G7gL1j3XMhykfAfqN7KcPMUhGebrRyFu7TGy5KSysYgi",
            "CSkEnvFTBQUU5VxfNngK3kvmpCzacRtknpGcyj1uyM85", // 7 lp mint
            "2eVuXmkpZKR4mEwL92myU7h77j3znNC2b76XVAtRyQSn", // 8 base = NEW TOKEN
            WSOL,                                           // 9 quote = WSOL
            "FW2eAuRM5wc7ANYNGJwRiS3KMPVj3P6wMmhHy9w2dYug",
            "5pCXd5sDvaKvFYo1QtXQqiJEQcRHQdYxDceK7CMHmDYz",
            "AHYLpimKrUpxi7JvooBMx3yy7HsoGEdgrT8GVrJ3YRnW",
            "9DCxsMizn3H1hprZ7xWe6LDzeUeZBksYFpBWBtSf1PQX",
            "7YttLkHDoNj9wyDur5pM1ejNaAvT9X4eqaYcHQqtj2G5", // 14 create fee dest
            "srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX",
            "97n8to3sgdxjYbgbR8hqeDhcptoD9J4hABYFRnJfP8ci",
            "HYDGYCtdnt9oYs9m1AzNrvfC6Sn8v6dgJE4waqqk9jJt",
            "Hdpa3SXJDVUs6G1RFS4jcEQmRRYxtKxvfvCeox9epcd4",
            "7QMihYdzsh4zcuWBP4iAkRS7gUL1eyHkGrADhzeCxhy9",
            "Hz2SkQ6XEFGc6o3Vbk1VGwnSkJUtNq6ANjojKb5eE3M7",
        ];
        let (keys, idxs) = fixture(Dex::RaydiumV4.program_id(), &accts);
        let targets = [TargetProgram::new(Dex::RaydiumV4)];
        let p = decode_ix(0, &idxs, &[1, 0, 0, 0], &keys, &targets)
            .expect("v4 initialize2 should decode");

        assert_eq!(p.dex, Dex::RaydiumV4);
        assert_eq!(p.pool, "FkaEYE8zVdx5eR3LwFsQmPhvXafgHyUmPYCDVSwfijCc");
        assert_eq!(p.base_mint, "2eVuXmkpZKR4mEwL92myU7h77j3znNC2b76XVAtRyQSn");
        assert_eq!(p.quote_mint, WSOL);
        // Vaults verified on-chain: each holds the mint at the paired index.
        assert_eq!(p.base_vault, "FW2eAuRM5wc7ANYNGJwRiS3KMPVj3P6wMmhHy9w2dYug");
        assert_eq!(p.quote_vault, "5pCXd5sDvaKvFYo1QtXQqiJEQcRHQdYxDceK7CMHmDYz");
        assert_eq!(p.lp_mint, "CSkEnvFTBQUU5VxfNngK3kvmpCzacRtknpGcyj1uyM85");
        // Accounts a later swap needs, from the same verified transaction.
        let sa = &p.swap_accounts;
        assert_eq!(sa.open_orders.as_deref(), Some("G7gL1j3XMhykfAfqN7KcPMUhGebrRyFu7TGy5KSysYgi"));
        assert_eq!(sa.target_orders.as_deref(), Some("AHYLpimKrUpxi7JvooBMx3yy7HsoGEdgrT8GVrJ3YRnW"));
        assert_eq!(sa.amm_config.as_deref(), Some("9DCxsMizn3H1hprZ7xWe6LDzeUeZBksYFpBWBtSf1PQX"));
        assert_eq!(sa.market.as_deref(), Some("97n8to3sgdxjYbgbR8hqeDhcptoD9J4hABYFRnJfP8ci"));
        // v4 has no observation account.
        assert_eq!(sa.observation, None);
        // NOT the fee account at index 14 (a WSOL acct holding ~699 SOL).
        assert_ne!(p.quote_vault, "7YttLkHDoNj9wyDur5pM1ejNaAvT9X4eqaYcHQqtj2G5");
    }

    #[test]
    fn golden_raydium_cpmm_initialize() {
        // tx 4GEn5CmpSkbatXh2mnrLEy7NB3N63nfdp7sxhhhH5jooFNmtgDEpAieAcVuwusEYhGN7sfNMNYiYc8Q3PiyhLvbc
        // NOTE: base is WSOL here — orientation is reversed vs Raydium v4.
        let accts = [
            "7eyBHoXW5XUyUiEdGaDokg3fcr5BPaika9Y1p5hMCz27",
            "D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2",
            "GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL",
            "BaUzoNfp76c6Y2GAkSJAiSufSp6jFofe9zrAVeemaasf", // 3 pool
            WSOL,                                           // 4 token_0 = WSOL
            "8wUqUf6RgVVDNZgEvToa5H7ovTpkpWmAoMAw7Tvoe3kA", // 5 token_1 = NEW TOKEN
            "5HEmY4QV1NaYfNPVoMMf4LqcdorSAer49oRMrkBkJaNY", // 6 lp mint
            "8dChiewmQJXtzQsMAhoUZrYuzSQtnAu4Yy4vQ9dJ86J8",
            "36Exn8Uiqyg7KgnE3RU56PtXh77XWfUCATaM76E1RxzW",
            "HKLmiYz1PWhr6RNneddEKkvDU3fgfw9JSwjgSPmr74TE",
            "AwNcrnAhstiij69TKdkZGmPe7eECnyLPJcDFBVQq95Qn",
            "AYiMT3p5XVgakVmFmwxEACDCjoQTxKCK3mvvVLGVQBVu",
            "DNXgeM9EiiaAbaWvwjHj9fQQLAX5ZsfHyvmYUNRAdNC8", // 12 create pool fee
            "HVhFfr5q114XMJtn4XzfMpB1UNWtvA1Mm4UpMhuA93Ys", // 13 observation
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "11111111111111111111111111111111",
            "SysvarRent111111111111111111111111111111111",
        ];
        let (keys, idxs) = fixture(Dex::RaydiumCpmm.program_id(), &accts);
        let targets = [TargetProgram::new(Dex::RaydiumCpmm)];
        let mut data = RAYDIUM_CPMM_INITIALIZE_DISC.to_vec();
        data.extend_from_slice(&[0u8; 24]);
        let p = decode_ix(0, &idxs, &data, &keys, &targets)
            .expect("cpmm initialize should decode");

        assert_eq!(p.pool, "BaUzoNfp76c6Y2GAkSJAiSufSp6jFofe9zrAVeemaasf");
        assert_eq!(p.base_mint, WSOL);
        assert_eq!(p.quote_mint, "8wUqUf6RgVVDNZgEvToa5H7ovTpkpWmAoMAw7Tvoe3kA");
        assert_eq!(p.base_vault, "AwNcrnAhstiij69TKdkZGmPe7eECnyLPJcDFBVQq95Qn");
        assert_eq!(p.quote_vault, "AYiMT3p5XVgakVmFmwxEACDCjoQTxKCK3mvvVLGVQBVu");
        assert_eq!(p.lp_mint, "5HEmY4QV1NaYfNPVoMMf4LqcdorSAer49oRMrkBkJaNY");
        let sa = &p.swap_accounts;
        assert_eq!(sa.amm_config.as_deref(), Some("D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2"));
        assert_eq!(sa.observation.as_deref(), Some("HVhFfr5q114XMJtn4XzfMpB1UNWtvA1Mm4UpMhuA93Ys"));
        // CPMM has no OpenBook market.
        assert_eq!(sa.market, None);
        assert_eq!(sa.open_orders, None);
        // NOT the fee account at index 12 (a WSOL acct holding ~4598 SOL).
        assert_ne!(p.base_vault, "DNXgeM9EiiaAbaWvwjHj9fQQLAX5ZsfHyvmYUNRAdNC8");
    }

    #[test]
    fn golden_pumpswap_create_pool() {
        // tx 4owTBz32K9qiLvVDtnsCVgnCG3mdDnoPTxuBaHxghotVRrnzXYZBLwbYttZrz97ttZMxNJvJHQCyhnqfR5KSJHdb
        // NOTE: base is WSOL here too — orientation reversed vs Raydium v4.
        let accts = [
            "GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM", // 0 pool
            "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw",
            "B7zDRn2UTNdoSpHu3SskSD7dGLYp1JzMBMewv4P585Hg",
            WSOL,                                           // 3 base = WSOL
            "6wgnjrUfZEt24TntGeAaVehsxccxAZQeS6atBapiqQoq", // 4 quote = NEW TOKEN
            "kJVxe4Ywe1PcZoVS9EemS3HFHybBZvy37CgV6a7zcLx",  // 5 lp mint
            "9EzGQYkjGbeochcAYfxcdeomQeWhzJ5JdX9ite2xFk9H",
            "5JeZinpKDQbNDUZ7AQg61Z1BHCDaSPKcyyxZ53EyioSk",
            "2kgjufxdPeX18cQVLE2rjEbbYhqbeSsnEKCUV6rmbxNr",
            "8GC4CydqvsjVpZmALdvhUR5S1i3iHwJBdfCyNAvioXN1",
            "41fHdK5y4LEXMehEcwkTk7jCcVx5A9TJykU6NPZEAGuK",
            "11111111111111111111111111111111",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR",
            "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
        ];
        let (keys, idxs) = fixture(Dex::PumpSwap.program_id(), &accts);
        let targets = [TargetProgram::new(Dex::PumpSwap)];
        let mut data = PUMPSWAP_CREATE_POOL_DISC.to_vec();
        data.extend_from_slice(&[0u8; 16]);
        let p = decode_ix(0, &idxs, &data, &keys, &targets)
            .expect("pumpswap create_pool should decode");

        assert_eq!(p.pool, "GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM");
        assert_eq!(p.base_mint, WSOL);
        assert_eq!(p.quote_mint, "6wgnjrUfZEt24TntGeAaVehsxccxAZQeS6atBapiqQoq");
        // Both vaults verified owned by the pool account itself.
        assert_eq!(p.base_vault, "8GC4CydqvsjVpZmALdvhUR5S1i3iHwJBdfCyNAvioXN1");
        assert_eq!(p.quote_vault, "41fHdK5y4LEXMehEcwkTk7jCcVx5A9TJykU6NPZEAGuK");
        assert_eq!(p.lp_mint, "kJVxe4Ywe1PcZoVS9EemS3HFHybBZvy37CgV6a7zcLx");
        // Creation alone carries no pool_v2 — it lives in a sibling instruction.
        assert_eq!(p.swap_accounts.pool_v2, None);
        // PumpSwap's "amm_config" slot is its global_config.
        assert_eq!(
            p.swap_accounts.amm_config.as_deref(),
            Some("ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw")
        );
    }

    /// Swap instructions on a target program must NOT decode as creations.
    /// LIVE: run a REAL mainnet transaction through the detector's entry point.
    ///
    /// Every other parser test uses hand-built fixtures. This one fetches an
    /// actual pool-creation transaction, converts it into the same protobuf
    /// shape the gRPC stream delivers, and runs `parse_transaction` — the real
    /// entry point. Closest thing to running the detector without a Yellowstone
    /// endpoint.
    ///
    ///   cargo test -- --ignored --nocapture live_parse_real_transaction
    #[tokio::test]
    #[ignore = "hits public mainnet RPC"]
    async fn live_parse_real_transaction() {
        use yellowstone_grpc_proto::prelude::{
            CompiledInstruction, InnerInstruction, InnerInstructions, Message, MessageHeader,
            SubscribeUpdateTransactionInfo, Transaction, TransactionStatusMeta,
        };

        // A real PumpSwap pool creation (a pump.fun migration).
        let sig = "3G8G2ppFFNRzBRhM72UANUBwogdkmTekURXMmv4Ya3tpQ51sFNCBjgjHkc7cqMFVw2rD4zcSEDTttBZw1wbUn7yB";
        let body = serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"getTransaction",
            "params":[sig, {"encoding":"json","maxSupportedTransactionVersion":0,
                            "commitment":"confirmed"}]
        });
        let v: serde_json::Value = reqwest::Client::new()
            .post("https://api.mainnet-beta.solana.com")
            .json(&body).send().await.expect("rpc").json().await.expect("json");
        let r = v.get("result").expect("transaction should be available");

        let b58 = |s: &str| bs58::decode(s).into_vec().expect("base58");
        let msg_json = &r["transaction"]["message"];
        let account_keys: Vec<Vec<u8>> = msg_json["accountKeys"].as_array().unwrap()
            .iter().map(|k| b58(k.as_str().unwrap())).collect();

        let compile = |ix: &serde_json::Value| CompiledInstruction {
            program_id_index: ix["programIdIndex"].as_u64().unwrap() as u32,
            accounts: ix["accounts"].as_array().unwrap()
                .iter().map(|a| a.as_u64().unwrap() as u8).collect(),
            data: b58(ix["data"].as_str().unwrap()),
        };
        let instructions: Vec<CompiledInstruction> =
            msg_json["instructions"].as_array().unwrap().iter().map(compile).collect();

        let meta_json = &r["meta"];
        let inner_instructions: Vec<InnerInstructions> = meta_json["innerInstructions"]
            .as_array().cloned().unwrap_or_default().iter().map(|g| InnerInstructions {
                index: g["index"].as_u64().unwrap() as u32,
                instructions: g["instructions"].as_array().unwrap().iter().map(|ix| {
                    let c = compile(ix);
                    InnerInstruction {
                        program_id_index: c.program_id_index,
                        accounts: c.accounts,
                        data: c.data,
                        stack_height: None,
                    }
                }).collect(),
            }).collect();

        let loaded = &meta_json["loadedAddresses"];
        let take = |k: &str| -> Vec<Vec<u8>> {
            loaded[k].as_array().cloned().unwrap_or_default()
                .iter().map(|a| b58(a.as_str().unwrap())).collect()
        };

        let tx_info = SubscribeUpdateTransactionInfo {
            signature: b58(sig),
            is_vote: false,
            transaction: Some(Transaction {
                signatures: vec![b58(sig)],
                message: Some(Message {
                    header: Some(MessageHeader::default()),
                    account_keys,
                    instructions,
                    ..Default::default()
                }),
            }),
            meta: Some(TransactionStatusMeta {
                inner_instructions,
                loaded_writable_addresses: take("writable"),
                loaded_readonly_addresses: take("readonly"),
                ..Default::default()
            }),
            index: 0,
        };

        let targets: Vec<TargetProgram> = Dex::all().into_iter().map(TargetProgram::new).collect();
        let pools = parse_transaction(&tx_info, &targets);

        println!("parsed {} pool(s) from the real transaction", pools.len());
        for p in &pools {
            println!("  dex={:?}\n  pool={}\n  base={}\n  quote={}\n  base_vault={}\n  quote_vault={}\n  pool_v2={:?}",
                p.dex, p.pool, p.base_mint, p.quote_mint, p.base_vault, p.quote_vault,
                p.swap_accounts.pool_v2);
        }

        let p = pools.first().expect("must detect the pool creation");
        assert_eq!(p.dex, Dex::PumpSwap);
        assert_eq!(p.pool, "HDMEBJbkTjR55L91aSCuPJvne99WQLzRBBy8Uxj23o2u");
        assert_eq!(p.base_mint, "wgwmoWeSe6cUcfafsTAqafNXU3RfyGNkWaBQiGqpump");
        assert_eq!(p.quote_mint, crate::model::WSOL_MINT);
        assert_eq!(
            p.swap_accounts.pool_v2.as_deref(),
            Some("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB"),
            "pool_v2 must be captured from the sibling buy in the same transaction"
        );
    }

    /// `pool_v2` is recovered from a sibling `buy` in the same transaction, and
    /// only when that buy is for the SAME pool.
    #[test]
    fn pool_v2_is_captured_from_a_sibling_buy() {
        let program = decode_key(Dex::PumpSwap.program_id());
        let pool = decode_key("GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM");
        let pool_v2 = decode_key("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB");
        let filler = decode_key("So11111111111111111111111111111111111111112");
        let keys = vec![program, pool, pool_v2, filler];
        let buy_data = crate::swap::PUMPSWAP_BUY_DISC.to_vec();
        const POOL: &str = "GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM";

        // 24 accounts: 23 declared (index 0 = pool) + pool_v2 at index 23.
        let mut accts: Vec<u8> = vec![1];
        accts.extend(std::iter::repeat_n(3u8, 22));
        accts.push(2);
        assert_eq!(accts.len(), 24);
        let all: Vec<(&[u8], &[u8], u32)> = vec![(&accts, &buy_data, 0)];
        assert_eq!(
            find_pumpswap_pool_v2(&all, &keys, POOL).as_deref(),
            Some("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB")
        );

        // A buy for a DIFFERENT pool must not contribute its pool_v2.
        let mut wrong: Vec<u8> = vec![3];
        wrong.extend(std::iter::repeat_n(3u8, 22));
        wrong.push(2);
        let all2: Vec<(&[u8], &[u8], u32)> = vec![(&wrong, &buy_data, 0)];
        assert_eq!(find_pumpswap_pool_v2(&all2, &keys, POOL), None);

        // A buy carrying no remaining accounts must yield nothing rather than
        // reading past the declared list.
        let short: Vec<u8> = std::iter::repeat_n(1u8, 23).collect();
        let all3: Vec<(&[u8], &[u8], u32)> = vec![(&short, &buy_data, 0)];
        assert_eq!(find_pumpswap_pool_v2(&all3, &keys, POOL), None);
    }

    /// `sell` declares 21, so its first remaining account sits at 21, not 23.
    #[test]
    fn pool_v2_offset_differs_for_sell() {
        let program = decode_key(Dex::PumpSwap.program_id());
        let pool = decode_key("GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM");
        let pool_v2 = decode_key("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB");
        let keys = vec![program, pool, pool_v2];

        let mut accts: Vec<u8> = vec![1];
        accts.extend(std::iter::repeat_n(1u8, 20));
        accts.push(2);
        assert_eq!(accts.len(), 22);
        let sell_data = crate::swap::PUMPSWAP_SELL_DISC.to_vec();
        let all: Vec<(&[u8], &[u8], u32)> = vec![(&accts, &sell_data, 0)];
        assert_eq!(
            find_pumpswap_pool_v2(&all, &keys, "GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM")
                .as_deref(),
            Some("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB")
        );
    }

    #[test]
    fn pumpswap_swaps_are_not_creations() {
        let (keys, idxs) = fixture(Dex::PumpSwap.program_id(), &[WSOL; 18]);
        let targets = [TargetProgram::new(Dex::PumpSwap)];
        // Verified by recomputation, not memory: sha256("global:buy")[..8] and
        // sha256("global:sell")[..8]. (These two are easy to transpose — the
        // sell discriminator is the one commonly seen first on-chain.)
        let buy = [102u8, 6, 61, 18, 1, 218, 235, 234];
        let sell = [51u8, 230, 133, 164, 1, 127, 131, 173];
        assert!(decode_ix(0, &idxs, &buy, &keys, &targets).is_none());
        assert!(decode_ix(0, &idxs, &sell, &keys, &targets).is_none());
    }

    /// Guard the swap discriminators themselves, so a future swap-execution
    /// path cannot inherit a transposed constant.
    #[test]
    fn swap_discriminators_are_correct() {
        assert_eq!(anchor_disc("buy"), [102, 6, 61, 18, 1, 218, 235, 234]);
        assert_eq!(anchor_disc("sell"), [51, 230, 133, 164, 1, 127, 131, 173]);
        assert_eq!(anchor_disc("swap_base_input"), [143, 190, 90, 218, 196, 30, 51, 222]);
        assert_eq!(anchor_disc("swap_base_output"), [55, 217, 98, 86, 163, 74, 180, 173]);
    }
}
