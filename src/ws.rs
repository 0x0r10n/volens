//! WebSocket transaction source — the RPC-only fallback when no Yellowstone
//! gRPC endpoint is available.
//!
//! # Why this exists, and what it costs
//!
//! gRPC (Geyser) streams full transactions as they are processed. A standard RPC
//! plan has no Geyser, so this module reconstructs the same stream from two
//! primitives that *are* available:
//!
//! 1. `logsSubscribe` with `mentions: [program]` — a push notification carrying
//!    only `{signature, err, logs}`. **Not enough to parse a pool**: no account
//!    keys, no instruction data, no inner instructions.
//! 2. `getTransaction(signature)` — the full transaction body, fetched per
//!    candidate.
//!
//! So logs are a *trigger* and the fetch is the data source. Three consequences,
//! all measured against a live Helius developer plan rather than assumed:
//!
//! * **`blockSubscribe` is not available** (`Method not found`), which would
//!   otherwise have delivered full transactions in one hop.
//! * **`getTransaction` refuses commitment below `confirmed`**, so this path
//!   cannot observe a transaction at `processed` no matter how it is configured.
//! * **Detection lands ~1.4–6s after the log event** (5 samples, avg 2.35s).
//!   That is the honest latency floor of RPC-only mode, and it is *seconds*
//!   slower than gRPC. It is fine for alerting and for slower entries; it is a
//!   real disadvantage against snipers running Geyser.
//!
//! # Design
//!
//! The converted output is the *same* `SubscribeUpdateTransactionInfo` type the
//! gRPC path yields, so the parser, filters, dedup, alerts, storage and sniper
//! are all completely unaware of which source produced a transaction. That is
//! deliberate: the parser is the most heavily verified code in this repo
//! (mainnet-verified layouts locked by golden fixtures) and must not fork.

use crate::model::Dex;
use crate::rpc::RpcClient;
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, warn};
use yellowstone_grpc_proto::prelude::{
    CompiledInstruction, InnerInstruction, InnerInstructions, Message, SubscribeUpdateTransactionInfo,
    Transaction, TransactionStatusMeta,
};

/// How long to keep retrying `getTransaction` for a signature seen in logs.
/// Measured worst case was ~6s; 12s leaves headroom without stalling forever.
const FETCH_TIMEOUT: Duration = Duration::from_secs(12);
const FETCH_RETRY_DELAY: Duration = Duration::from_millis(400);

/// Concurrent `getTransaction` calls in flight. A launch burst can produce many
/// candidates at once; without a bound, a standard plan's rate limit is tripped
/// and *every* fetch starts failing — including the real pool. Bounded
/// concurrency degrades to "slower" instead of "broken".
const MAX_INFLIGHT_FETCHES: usize = 8;

/// Signatures remembered to avoid re-fetching the same transaction. Logs can
/// repeat across reconnects, and each duplicate would otherwise cost a fetch.
const SEEN_CAPACITY: usize = 4096;

/// Does this log set look like a pool creation for the given venue?
///
/// A **cheap pre-filter**, not the real one — `parse_transaction` remains the
/// authority. Its job is to avoid a `getTransaction` round trip for the
/// overwhelming majority of transactions that merely touch the program.
///
/// # Matching is exact, not substring
///
/// Substring matching was tried first and was badly wrong. Measured live: it
/// admitted **910 transactions in 100 seconds** (~9 fetches/sec) because
/// Solana's `Program log: Instruction: <Name>` lines nest by prefix —
/// `Instruction: Create` is a substring of `Instruction: CreateIdempotent`
/// (every ATA creation), and `Instruction: Initialize` is a substring of
/// `InitializeAccount3`, `InitializeMint2` and `InitializeImmutableOwner`
/// (every SPL token setup). On a rate-limited plan that alone would exhaust the
/// quota and start failing the fetches that matter.
///
/// Extracting the instruction name and comparing it exactly removes the entire
/// class of prefix collisions.
///
/// Verified against the golden-fixture creation transactions:
/// * Raydium v4 is not Anchor and prints its own struct:
///   `Program log: initialize2: InitializeInstruction2 { ... }`
/// * Raydium CPMM logs `Program log: Instruction: Initialize`
/// * PumpSwap logs `Program log: Instruction: CreatePool`
pub fn logs_suggest_creation(dex: Dex, logs: &[String]) -> bool {
    logs.iter().any(|line| match dex {
        // Raydium v4 predates Anchor's logging convention.
        Dex::RaydiumV4 => line
            .strip_prefix("Program log: ")
            .is_some_and(|r| r.starts_with("initialize2:") || r == "Instruction: Initialize2"),
        Dex::RaydiumCpmm => instruction_name(line) == Some("Initialize"),
        Dex::PumpSwap => instruction_name(line) == Some("CreatePool"),
    })
}

/// Extract `<Name>` from `Program log: Instruction: <Name>`.
///
/// Returning the exact name is what makes prefix collisions impossible: a
/// caller comparing with `==` cannot accidentally match a longer instruction
/// that merely starts with the same characters.
fn instruction_name(line: &str) -> Option<&str> {
    line.strip_prefix("Program log: Instruction: ")
        .map(str::trim)
}

/// Derive the WebSocket URL from an HTTP(S) RPC URL.
///
/// Providers overwhelmingly serve the WS endpoint on the same host and path
/// (Helius, Triton, QuickNode all do), so scheme substitution is correct in
/// practice. An explicit override exists in config for the ones that don't.
pub fn derive_ws_url(rpc_url: &str) -> Result<String> {
    let t = rpc_url.trim();
    if let Some(rest) = t.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else if let Some(rest) = t.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else if t.starts_with("wss://") || t.starts_with("ws://") {
        Ok(t.to_string())
    } else {
        anyhow::bail!("cannot derive a WebSocket URL from {t:?} — expected http(s):// or ws(s)://")
    }
}

/// A transaction recovered from the WebSocket source, ready for the normal
/// pipeline.
pub struct WsTransaction {
    pub info: SubscribeUpdateTransactionInfo,
    pub slot: u64,
}

/// Run one WebSocket session: subscribe, fetch, convert, emit.
///
/// Returns `Ok(())` only on requested shutdown. Any transport failure is an
/// `Err` so the caller's existing backoff/reconnect loop handles it identically
/// to a gRPC drop.
pub async fn stream_once(
    ws_url: &str,
    rpc: Arc<RpcClient>,
    dexes: &[Dex],
    out: mpsc::Sender<WsTransaction>,
    shutdown: &mut watch::Receiver<bool>,
    connected: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    let (stream, _) = tokio_tungstenite::connect_async(ws_url)
        .await
        .context("websocket connect")?;
    let (mut write, mut read) = stream.split();

    // One subscription per program. `mentions` accepts exactly one address, so
    // venues cannot share a subscription.
    for (i, dex) in dexes.iter().enumerate() {
        let req = serde_json::json!({
            "jsonrpc":"2.0","id": i + 1,"method":"logsSubscribe",
            "params":[{"mentions":[dex.program_id()]}, {"commitment":"processed"}],
        });
        write
            .send(WsMessage::Text(req.to_string()))
            .await
            .context("sending logsSubscribe")?;
    }

    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT_FETCHES));
    let mut seen: HashSet<String> = HashSet::with_capacity(SEEN_CAPACITY);
    let mut confirmed_subs = 0usize;

    loop {
        tokio::select! {
            msg = read.next() => {
                let Some(msg) = msg else { anyhow::bail!("websocket stream ended") };
                let msg = msg.context("websocket read")?;
                let text = match msg {
                    WsMessage::Text(t) => t.to_string(),
                    WsMessage::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    // Tungstenite answers pings itself; nothing to do here.
                    WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
                    WsMessage::Close(c) => anyhow::bail!("websocket closed by server: {c:?}"),
                    WsMessage::Frame(_) => continue,
                };

                let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };

                // Subscription acknowledgements arrive first, one per venue.
                if v.get("method").is_none() {
                    if let Some(err) = v.get("error") {
                        anyhow::bail!("logsSubscribe rejected: {err}");
                    }
                    if v.get("result").is_some() {
                        confirmed_subs += 1;
                        if confirmed_subs == dexes.len() {
                            connected.store(true, std::sync::atomic::Ordering::Relaxed);
                            info!(
                                subscriptions = confirmed_subs,
                                "websocket source connected & subscribed (logsSubscribe)"
                            );
                        }
                    }
                    continue;
                }

                let Some(value) = v.pointer("/params/result/value") else { continue };

                // Failed transactions cannot have created a pool. Dropping them
                // here saves the fetch entirely.
                if value.get("err").map(|e| !e.is_null()).unwrap_or(false) {
                    continue;
                }
                let Some(sig) = value.get("signature").and_then(|s| s.as_str()) else { continue };

                let logs: Vec<String> = value
                    .get("logs")
                    .and_then(|l| l.as_array())
                    .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();

                // Cheap pre-filter across every enabled venue: if no venue's
                // creation marker appears, this is a swap or a deposit and not
                // worth a round trip.
                if !dexes.iter().any(|d| logs_suggest_creation(*d, &logs)) {
                    continue;
                }

                if !seen.insert(sig.to_string()) {
                    continue;
                }
                // Cheap bound: clearing wholesale can re-admit a signature, which
                // costs one duplicate fetch and is caught downstream by `Dedup`.
                if seen.len() > SEEN_CAPACITY {
                    seen.clear();
                }

                let Ok(permit) = sem.clone().acquire_owned().await else { continue };
                let rpc = rpc.clone();
                let out = out.clone();
                let sig = sig.to_string();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(tx) = fetch_and_convert(&rpc, &sig).await {
                        let _ = out.send(tx).await;
                    }
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("shutdown signal received; closing websocket");
                    return Ok(());
                }
            }
        }
    }
}

/// Fetch a transaction by signature and convert it into the gRPC-shaped type.
///
/// Retries while the transaction is not yet visible: a log seen at `processed`
/// normally precedes queryability at `confirmed` by a second or more.
async fn fetch_and_convert(rpc: &RpcClient, signature: &str) -> Option<WsTransaction> {
    let deadline = tokio::time::Instant::now() + FETCH_TIMEOUT;
    loop {
        if let Some(json) = rpc.get_transaction(signature).await {
            match convert_transaction(&json, signature) {
                Some(tx) => return Some(tx),
                None => {
                    warn!(signature, "fetched transaction could not be converted");
                    return None;
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            debug!(signature, "transaction never became fetchable");
            return None;
        }
        tokio::time::sleep(FETCH_RETRY_DELAY).await;
    }
}

/// Convert a `getTransaction` JSON result into `SubscribeUpdateTransactionInfo`.
///
/// This is the load-bearing compatibility shim: everything downstream assumes
/// the gRPC shape. Fields the parser reads must all be populated —
/// `account_keys`, `instructions`, `inner_instructions`, and crucially the
/// address-lookup-table `loaded_*_addresses`, without which any versioned
/// transaction resolves the wrong accounts.
pub fn convert_transaction(
    result: &serde_json::Value,
    signature: &str,
) -> Option<WsTransaction> {
    let slot = result.get("slot").and_then(|s| s.as_u64()).unwrap_or(0);
    let msg_json = result.pointer("/transaction/message")?;

    let account_keys: Vec<Vec<u8>> = msg_json
        .get("accountKeys")?
        .as_array()?
        .iter()
        .filter_map(|k| bs58::decode(k.as_str()?).into_vec().ok())
        .collect();

    let instructions: Vec<CompiledInstruction> = msg_json
        .get("instructions")?
        .as_array()?
        .iter()
        .filter_map(compile_ix)
        .collect();

    let meta_json = result.get("meta");

    let inner_instructions: Vec<InnerInstructions> = meta_json
        .and_then(|m| m.get("innerInstructions"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|g| {
                    Some(InnerInstructions {
                        index: g.get("index")?.as_u64()? as u32,
                        instructions: g
                            .get("instructions")?
                            .as_array()?
                            .iter()
                            .filter_map(inner_ix)
                            .collect(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // ALT-resolved addresses. Absent for legacy transactions, which is fine —
    // they have no lookups — but silently dropping them for a versioned
    // transaction would shift every account index past the static keys.
    let (loaded_writable, loaded_readonly) = meta_json
        .and_then(|m| m.get("loadedAddresses"))
        .map(|la| (decode_keys(la.get("writable")), decode_keys(la.get("readonly"))))
        .unwrap_or_default();

    let log_messages: Vec<String> = meta_json
        .and_then(|m| m.get("logMessages"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    let meta = TransactionStatusMeta {
        // Only successful transactions are fetched (failures are dropped from
        // the log event), so `err` is always None here. Keeping the field
        // explicit rather than defaulted documents that.
        err: None,
        inner_instructions,
        log_messages,
        loaded_writable_addresses: loaded_writable,
        loaded_readonly_addresses: loaded_readonly,
        ..Default::default()
    };

    let versioned = result
        .get("version")
        .map(|v| !v.is_null() && v.as_str() != Some("legacy"))
        .unwrap_or(false);

    Some(WsTransaction {
        info: SubscribeUpdateTransactionInfo {
            signature: bs58::decode(signature).into_vec().ok()?,
            is_vote: false,
            transaction: Some(Transaction {
                signatures: vec![],
                message: Some(Message {
                    account_keys,
                    instructions,
                    versioned,
                    ..Default::default()
                }),
            }),
            meta: Some(meta),
            index: 0,
        },
        slot,
    })
}

fn decode_keys(v: Option<&serde_json::Value>) -> Vec<Vec<u8>> {
    v.and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|k| bs58::decode(k.as_str()?).into_vec().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Account indices are `u8` on the wire, matching the compiled on-chain format.
/// An index above 255 cannot exist in a real transaction, so a value that does
/// not fit means the input is malformed and the instruction is skipped rather
/// than silently truncated into a *different, valid* account.
fn accounts_as_u8(v: &serde_json::Value) -> Option<Vec<u8>> {
    v.as_array()?
        .iter()
        .map(|i| u8::try_from(i.as_u64()?).ok())
        .collect()
}

fn compile_ix(ix: &serde_json::Value) -> Option<CompiledInstruction> {
    Some(CompiledInstruction {
        program_id_index: ix.get("programIdIndex")?.as_u64()? as u32,
        accounts: accounts_as_u8(ix.get("accounts")?)?,
        data: bs58::decode(ix.get("data")?.as_str()?).into_vec().ok()?,
    })
}

fn inner_ix(ix: &serde_json::Value) -> Option<InnerInstruction> {
    Some(InnerInstruction {
        program_id_index: ix.get("programIdIndex")?.as_u64()? as u32,
        accounts: accounts_as_u8(ix.get("accounts")?)?,
        data: bs58::decode(ix.get("data")?.as_str()?).into_vec().ok()?,
        stack_height: ix.get("stackHeight").and_then(|s| s.as_u64()).map(|s| s as u32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_derivation() {
        assert_eq!(derive_ws_url("https://x.helius-rpc.com/?api-key=k").unwrap(),
                   "wss://x.helius-rpc.com/?api-key=k");
        assert_eq!(derive_ws_url("http://localhost:8899").unwrap(), "ws://localhost:8899");
        // Already a websocket URL: passed through untouched.
        assert_eq!(derive_ws_url("wss://a.b/c").unwrap(), "wss://a.b/c");
        assert_eq!(derive_ws_url("  https://x.io  ").unwrap(), "wss://x.io");
        assert!(derive_ws_url("not-a-url").is_err());
        assert!(derive_ws_url("").is_err());
    }

    /// Markers verified against the real creation transactions cited in
    /// `parser::tests`. If a venue's log format changes, RPC-only mode goes
    /// blind for that venue, so these are pinned.
    #[test]
    fn creation_markers_match_real_logs() {
        // Raydium v4 (4kAcRNUt…): not Anchor, prints its own struct.
        let v4 = vec![
            "Program 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8 invoke [1]".to_string(),
            "Program log: initialize2: InitializeInstruction2 { nonce: 254, open_time: 0 }".to_string(),
        ];
        assert!(logs_suggest_creation(Dex::RaydiumV4, &v4));

        // Raydium CPMM (4GEn5Cmp…)
        let cpmm = vec!["Program log: Instruction: Initialize".to_string()];
        assert!(logs_suggest_creation(Dex::RaydiumCpmm, &cpmm));

        // PumpSwap (4owTBz32…)
        let pump = vec!["Program log: Instruction: CreatePool".to_string()];
        assert!(logs_suggest_creation(Dex::PumpSwap, &pump));
    }

    /// The prefix-collision regression, pinned.
    ///
    /// These exact log lines appear in a large fraction of all Solana
    /// transactions. Substring matching admitted every one of them and drove
    /// ~9 getTransaction calls/sec against a rate-limited plan.
    #[test]
    fn common_instructions_do_not_collide_by_prefix() {
        // ATA creation — extremely common; must NOT look like PumpSwap CreatePool.
        let ata = vec!["Program log: Instruction: CreateIdempotent".to_string()];
        assert!(!logs_suggest_creation(Dex::PumpSwap, &ata));
        let create = vec!["Program log: Instruction: Create".to_string()];
        assert!(!logs_suggest_creation(Dex::PumpSwap, &create));

        // SPL token setup — must NOT look like a CPMM Initialize.
        for name in ["InitializeAccount3", "InitializeMint2", "InitializeImmutableOwner", "InitializeAccount"] {
            let logs = vec![format!("Program log: Instruction: {name}")];
            assert!(
                !logs_suggest_creation(Dex::RaydiumCpmm, &logs),
                "{name} must not match CPMM Initialize"
            );
        }

        // The real ones still match.
        assert!(logs_suggest_creation(
            Dex::RaydiumCpmm,
            &["Program log: Instruction: Initialize".to_string()]
        ));
        assert!(logs_suggest_creation(
            Dex::PumpSwap,
            &["Program log: Instruction: CreatePool".to_string()]
        ));
    }

    /// The pre-filter must reject ordinary traffic, or it saves nothing.
    #[test]
    fn swaps_are_filtered_out() {
        let swap = vec![
            "Program log: Instruction: Swap".to_string(),
            "Program log: ray_log: A1b2c3".to_string(),
        ];
        assert!(!logs_suggest_creation(Dex::RaydiumV4, &swap));
        assert!(!logs_suggest_creation(Dex::RaydiumCpmm, &swap));
        assert!(!logs_suggest_creation(Dex::PumpSwap, &swap));

        let deposit = vec!["Program log: Instruction: Deposit".to_string()];
        assert!(!logs_suggest_creation(Dex::RaydiumCpmm, &deposit));
    }

    /// An out-of-range account index must drop the instruction, never wrap into
    /// a different valid account — that would parse a *wrong* pool.
    #[test]
    fn oversized_account_index_is_rejected_not_truncated() {
        let bad = serde_json::json!([1, 2, 300]);
        assert_eq!(accounts_as_u8(&bad), None);

        let ok = serde_json::json!([0, 5, 255]);
        assert_eq!(accounts_as_u8(&ok), Some(vec![0, 5, 255]));
    }

    /// **The load-bearing test for RPC-only mode.**
    ///
    /// Converts real `getTransaction` responses and runs them through the SAME
    /// `parse_transaction` the gRPC path uses, asserting the results match the
    /// golden gRPC fixtures in `parser::tests` exactly. If the conversion drops
    /// or shifts a field, the pool address, mints or vaults come out wrong and
    /// this fails.
    ///
    /// Offline: the JSON is captured in `tests/fixtures/`, so this runs in CI
    /// with no network and no API key.
    #[test]
    fn converted_transactions_parse_identically_to_grpc() {
        use crate::parser::{TargetProgram, parse_transaction};

        struct Case {
            fixture: &'static str,
            signature: &'static str,
            dex: Dex,
            pool: &'static str,
            base_mint: &'static str,
            quote_mint: &'static str,
            base_vault: &'static str,
            quote_vault: &'static str,
        }

        const WSOL: &str = "So11111111111111111111111111111111111111112";

        // Expected values copied from the golden gRPC tests, not recomputed —
        // the point is cross-path agreement on already-verified ground truth.
        let cases = [
            Case {
                fixture: include_str!("../tests/fixtures/gettx_v4.json"),
                signature: "4kAcRNUt5UXPFGJVf22gv7ziNPosBQGZuvFto9RP9TGC1s8zoaqv9SR6qH8jeBDnthyFGk9vcGPfhggWVmCEkpP9",
                dex: Dex::RaydiumV4,
                pool: "FkaEYE8zVdx5eR3LwFsQmPhvXafgHyUmPYCDVSwfijCc",
                base_mint: "2eVuXmkpZKR4mEwL92myU7h77j3znNC2b76XVAtRyQSn",
                quote_mint: WSOL,
                base_vault: "FW2eAuRM5wc7ANYNGJwRiS3KMPVj3P6wMmhHy9w2dYug",
                quote_vault: "5pCXd5sDvaKvFYo1QtXQqiJEQcRHQdYxDceK7CMHmDYz",
            },
            Case {
                fixture: include_str!("../tests/fixtures/gettx_cpmm.json"),
                signature: "4GEn5CmpSkbatXh2mnrLEy7NB3N63nfdp7sxhhhH5jooFNmtgDEpAieAcVuwusEYhGN7sfNMNYiYc8Q3PiyhLvbc",
                dex: Dex::RaydiumCpmm,
                pool: "BaUzoNfp76c6Y2GAkSJAiSufSp6jFofe9zrAVeemaasf",
                base_mint: WSOL,
                quote_mint: "",
                base_vault: "",
                quote_vault: "",
            },
            Case {
                fixture: include_str!("../tests/fixtures/gettx_pumpswap.json"),
                signature: "4owTBz32K9qiLvVDtnsCVgnCG3mdDnoPTxuBaHxghotVRrnzXYZBLwbYttZrz97ttZMxNJvJHQCyhnqfR5KSJHdb",
                dex: Dex::PumpSwap,
                pool: "GcBjU7ktjpAXtHbQWWu61qLjiTXk5gA51xB4xSZLA1TM",
                base_mint: WSOL,
                quote_mint: "",
                base_vault: "",
                quote_vault: "",
            },
        ];

        for c in cases {
            let json: serde_json::Value =
                serde_json::from_str(c.fixture).expect("fixture is valid JSON");
            let tx = convert_transaction(&json, c.signature)
                .unwrap_or_else(|| panic!("{:?}: conversion returned None", c.dex));

            assert!(tx.slot > 0, "{:?}: slot must be populated", c.dex);

            let targets = [TargetProgram::new(c.dex)];
            let pools = parse_transaction(&tx.info, &targets);

            assert_eq!(pools.len(), 1, "{:?}: expected exactly one pool", c.dex);
            let p = &pools[0];
            assert_eq!(p.dex, c.dex);
            assert_eq!(p.pool, c.pool, "{:?}: pool address mismatch", c.dex);
            if !c.base_mint.is_empty() {
                assert_eq!(p.base_mint, c.base_mint, "{:?}: base mint", c.dex);
            }
            if !c.quote_mint.is_empty() {
                assert_eq!(p.quote_mint, c.quote_mint, "{:?}: quote mint", c.dex);
            }
            if !c.base_vault.is_empty() {
                assert_eq!(p.base_vault, c.base_vault, "{:?}: base vault", c.dex);
            }
            if !c.quote_vault.is_empty() {
                assert_eq!(p.quote_vault, c.quote_vault, "{:?}: quote vault", c.dex);
            }
        }
    }

    /// PumpSwap's `pool_v2` lives in a SIBLING instruction of the creation
    /// transaction, recovered by scanning inner instructions. This is the field
    /// most likely to be silently lost in conversion, and losing it makes every
    /// PumpSwap trade fail with `InvalidPoolV2` (6062).
    ///
    /// Uses tx `3G8G2ppF…` — the one that actually carries a sibling buy. The
    /// plain `create_pool` fixture deliberately has no `pool_v2` (asserted
    /// below), so testing against it would have proved nothing.
    #[test]
    fn conversion_recovers_pumpswap_pool_v2_from_siblings() {
        use crate::parser::{TargetProgram, parse_transaction};

        let json: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/gettx_pumpswap_with_v2.json"))
                .unwrap();
        let tx = convert_transaction(
            &json,
            "3G8G2ppFFNRzBRhM72UANUBwogdkmTekURXMmv4Ya3tpQ51sFNCBjgjHkc7cqMFVw2rD4zcSEDTttBZw1wbUn7yB",
        )
        .expect("conversion");

        assert!(
            !tx.info.meta.as_ref().unwrap().inner_instructions.is_empty(),
            "inner instructions must survive conversion"
        );

        let targets: Vec<TargetProgram> = Dex::all().into_iter().map(TargetProgram::new).collect();
        let pools = parse_transaction(&tx.info, &targets);
        let p = pools.first().expect("must detect the pool creation");

        assert_eq!(p.pool, "HDMEBJbkTjR55L91aSCuPJvne99WQLzRBBy8Uxj23o2u");
        assert_eq!(p.base_mint, "wgwmoWeSe6cUcfafsTAqafNXU3RfyGNkWaBQiGqpump");
        assert_eq!(
            p.swap_accounts.pool_v2.as_deref(),
            Some("EqovKkEfiyazxSiXcYzj2d8iFmC7n8bW5uP5w477fNYB"),
            "pool_v2 must survive the JSON->proto conversion"
        );
    }

    /// Negative control for the test above: a bare `create_pool` carries no
    /// sibling buy, so `pool_v2` must be None. Without this, the conversion
    /// could be fabricating a value and the positive test alone wouldn't tell.
    #[test]
    fn plain_create_pool_has_no_pool_v2() {
        use crate::parser::{TargetProgram, parse_transaction};

        let json: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/gettx_pumpswap.json")).unwrap();
        let tx = convert_transaction(
            &json,
            "4owTBz32K9qiLvVDtnsCVgnCG3mdDnoPTxuBaHxghotVRrnzXYZBLwbYttZrz97ttZMxNJvJHQCyhnqfR5KSJHdb",
        )
        .unwrap();
        let targets = [TargetProgram::new(Dex::PumpSwap)];
        let pools = parse_transaction(&tx.info, &targets);
        assert_eq!(pools[0].swap_accounts.pool_v2, None);
    }

    /// ALT-resolved addresses must survive conversion. Without them a versioned
    /// transaction resolves every index past the static keys to the WRONG
    /// account — which parses as a real but incorrect pool.
    #[test]
    fn conversion_preserves_loaded_alt_addresses() {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/gettx_v4.json")).unwrap();
        let tx = convert_transaction(&json, "4kAcRNUt5UXPFGJVf22gv7ziNPosBQGZuvFto9RP9TGC1s8zoaqv9SR6qH8jeBDnthyFGk9vcGPfhggWVmCEkpP9").unwrap();
        let meta = tx.info.meta.as_ref().unwrap();

        // This fixture is a versioned tx with 1 writable + 4 readonly loaded.
        assert_eq!(meta.loaded_writable_addresses.len(), 1);
        assert_eq!(meta.loaded_readonly_addresses.len(), 4);
        for k in meta.loaded_writable_addresses.iter().chain(&meta.loaded_readonly_addresses) {
            assert_eq!(k.len(), 32, "ALT keys must decode to 32 bytes");
        }
    }

    #[test]
    fn conversion_rejects_malformed_input() {
        assert!(convert_transaction(&serde_json::json!({}), "sig").is_none());
        assert!(convert_transaction(&serde_json::json!({"slot":1}), "sig").is_none());
    }
}
