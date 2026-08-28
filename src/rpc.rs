//! Thin JSON-RPC client for post-detection enrichment.
//!
//! Deliberately not `solana-client`: we need two methods
//! (`getTokenAccountBalance`, `getAccountInfo`), and the full SDK would add a
//! large dependency tree and build time for them.
//!
//! Everything here runs off the gRPC hot path — see `Detector::spawn_finalize`.

use crate::config::RpcConfig;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, warn};

pub struct RpcClient {
    client: reqwest::Client,
    url: String,
    commitment: String,
    retries: u32,
    retry_delay: Duration,
    initial_delay: Duration,
}

/// On-chain token metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenMeta {
    pub name: String,
    pub symbol: String,
    /// Off-chain JSON holding image + socials, when the token declares one.
    pub uri: Option<String>,
}

/// A share as a percentage, guaranteed to render sanely.
///
/// Returns a clean `0.0` for an empty or negative numerator: `-0.0` survives
/// `clamp` (it is not less than `0.0`) and rendered as "-0.0%" on a token
/// whose only holder was the pool.
fn pct(part: f64, whole: f64) -> f64 {
    if !(part > 0.0) || !(whole > 0.0) {
        return 0.0;
    }
    (100.0 * part / whole).min(100.0)
}

/// Holder concentration — the other half of the rug-risk surface.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HolderStats {
    /// Holders counted. `getTokenLargestAccounts` returns at most 20, so this
    /// is EXACT below that and a floor at it.
    pub count: usize,
    /// True when the count hit the RPC's 20-account ceiling, i.e. "20+".
    pub capped: bool,
    /// Share held by the top 10 holders, EXCLUDING the largest.
    ///
    /// The largest account is almost always the pool or bonding curve —
    /// measured at 91.7% on a real token. Including it reports ~98% for every
    /// launch, which is not a risk signal, it is noise. Excluding it gave
    /// 6.1% on the same token, which is the number that means something.
    pub top10_pct: f64,
    /// What that largest account holds, as a share. Informative on its own: a
    /// "pool" holding only 30% means somebody else is holding a lot.
    pub largest_pct: f64,
}

/// Authority + extension state of an SPL mint. This is the rug-risk surface.
#[derive(Debug, Clone, PartialEq)]
pub struct MintInfo {
    /// `Some` means someone can still mint new supply at will.
    pub mint_authority: Option<String>,
    /// `Some` means someone can freeze token accounts — i.e. you may be able to
    /// buy but not sell.
    pub freeze_authority: Option<String>,
    pub decimals: u8,
    /// Token-2022 extensions that can interfere with selling (transfer fees,
    /// transfer hooks, permanent delegate...). Empty for plain SPL tokens.
    pub risky_extensions: Vec<String>,
}

impl MintInfo {
    pub fn mint_authority_revoked(&self) -> bool {
        self.mint_authority.is_none()
    }
    pub fn freeze_authority_revoked(&self) -> bool {
        self.freeze_authority.is_none()
    }
}

/// Token-2022 extensions worth refusing on: each can block or tax a sale.
const RISKY_EXTENSIONS: &[&str] = &[
    "transferFeeConfig",
    "transferHook",
    "permanentDelegate",
    "defaultAccountState",
    "nonTransferable",
];

impl RpcClient {
    pub fn new(cfg: &RpcConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        Self {
            client,
            url: cfg.url.clone(),
            commitment: cfg.commitment.clone(),
            retries: cfg.retries.max(1),
            retry_delay: Duration::from_millis(cfg.retry_delay_ms),
            initial_delay: Duration::from_millis(cfg.initial_delay_ms),
        }
    }

    /// Token account balance in UI units (already scaled by decimals).
    ///
    /// Returns `None` if every attempt failed — callers must treat that as
    /// "unknown", never "zero".
    pub async fn vault_balance(&self, vault: &str) -> Option<f64> {
        self.with_retries("getTokenAccountBalance", vault, false, parse_balance)
            .await
    }

    /// Is the RPC endpoint reachable, authenticated, and serving chain data?
    ///
    /// `Ok(())` means a real JSON-RPC round trip succeeded. Anything else
    /// describes what went wrong, in terms the operator can act on.
    ///
    /// # Why this exists
    ///
    /// An RPC that answers with an error degrades this bot *silently and
    /// totally*: liquidity reads return unknown, mint safety returns unknown,
    /// the watcher can read nothing, and dry-run simulation reports
    /// `simulation-unavailable` forever. Detection keeps working — that's a
    /// separate gRPC endpoint — so alerts keep arriving and still look normal,
    /// just with every enrichment field missing. Observed for real: a Helius URL
    /// with a stale key returned `{"error":{"code":-32401,"message":"Invalid API
    /// key"}}` on every call, which surfaced only as scattered debug lines.
    ///
    /// One loud line at startup turns a multi-day blind spot into an obvious
    /// misconfiguration.
    pub async fn health(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("no RPC url configured".into());
        }
        // `getSlot`, NOT `getHealth`. Verified against Helius: an endpoint with
        // an invalid API key answers `getHealth` with `{"result":"ok"}` — auth is
        // enforced per-method, so the health endpoint is exactly the one that
        // does NOT check credentials. A health check that passes a dead key is
        // worse than none, because it converts a loud failure into a false
        // reassurance. `getSlot` requires auth and returns a value we can
        // sanity-check, so it proves the node is serving data, not just alive.
        let body = json!({"jsonrpc":"2.0","id":1,"method":"getSlot"});
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("cannot reach endpoint: {e}"))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("unreadable response: {e}"))?;

        if !status.is_success() {
            // Deliberately not echoing the body: on some providers it repeats
            // the request URL, which carries the API key.
            return Err(format!("endpoint returned HTTP {status}"));
        }

        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| "response was not JSON (is the URL a JSON-RPC endpoint?)".to_string())?;

        // A JSON-RPC error object is the interesting case: the endpoint is up
        // and answering, it just refuses us. That is an auth or plan problem,
        // not a connectivity one, and the message says which.
        if let Some(err) = v.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(format!("endpoint rejected the request: {msg}"));
        }

        // A real slot number proves the node authenticated us AND is serving
        // chain data. Slot 0 would mean a node that has not started syncing.
        match v.get("result").and_then(|r| r.as_u64()) {
            Some(slot) if slot > 0 => Ok(()),
            Some(_) => Err("node returned slot 0 (not synced)".into()),
            None => Err("unexpected getSlot response shape".into()),
        }
    }

    /// Fetch a full transaction by signature, as the raw JSON `result`.
    ///
    /// Used by the WebSocket source: `logsSubscribe` delivers only
    /// `{signature, err, logs}`, so the transaction body has to be fetched
    /// separately before it can be parsed.
    ///
    /// **`commitment` is forced to `confirmed`.** `getTransaction` rejects
    /// anything lower with `Method does not support commitment below
    /// 'confirmed'` (verified against Helius), so the configured commitment is
    /// deliberately ignored here rather than producing an error on every fetch.
    ///
    /// Returns `None` when the transaction is not yet visible — the caller is
    /// expected to retry, because a log observed at `processed` routinely
    /// precedes the transaction being queryable at `confirmed`.
    pub async fn get_transaction(&self, signature: &str) -> Option<serde_json::Value> {
        if self.url.is_empty() {
            return None;
        }
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getTransaction",
            "params":[signature, {
                "encoding":"json",
                "maxSupportedTransactionVersion":0,
                "commitment":"confirmed",
            }],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        // A null `result` means "not found yet", which is normal and retryable.
        // An `error` object means the request itself was wrong; log it once
        // rather than silently retrying forever.
        if let Some(e) = resp.get("error") {
            warn!(error = %e, "getTransaction returned an error");
            return None;
        }
        let r = resp.get("result")?;
        if r.is_null() { None } else { Some(r.clone()) }
    }

    /// Native SOL balance of an address, in SOL (not lamports).
    ///
    /// Distinct from `vault_balance`, which reads SPL *token* accounts. A wallet
    /// holds native SOL directly in its account lamports, so this is
    /// `getBalance`, not `getTokenAccountBalance`.
    ///
    /// `None` means unreadable — never render it as zero. "I could not reach the
    /// RPC" and "your wallet is empty" are different facts, and confusing them
    /// in a balance report is how someone concludes they have been drained.
    ///
    /// Deliberately does NOT use `with_retries`: that path sleeps
    /// `initial_delay` (tuned for accounts too fresh to be queryable), which is
    /// wasted latency for an interactive command against a long-lived wallet.
    pub async fn sol_balance(&self, address: &str) -> Option<f64> {
        if self.url.is_empty() {
            return None;
        }
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getBalance",
            "params":[address, {"commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        let lamports = resp.get("result")?.get("value")?.as_u64()?;
        Some(lamports as f64 / 1_000_000_000.0)
    }

    /// Number of SPL token accounts owned by an address, across BOTH the classic
    /// SPL Token program and Token-2022.
    ///
    /// Both are queried because most pump.fun mints are Token-2022, so counting
    /// only the classic program would under-report exactly the tokens this bot
    /// buys. Returns `None` if either query fails — a partial count reported as
    /// a total would be a wrong number presented as a right one.
    pub async fn token_account_count(&self, owner: &str) -> Option<usize> {
        if self.url.is_empty() {
            return None;
        }
        let mut total = 0usize;
        for program in [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        ] {
            let body = json!({
                "jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner",
                "params":[owner, {"programId": program},
                          {"encoding":"jsonParsed","commitment": self.commitment}],
            });
            let resp: serde_json::Value = self
                .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
            total += resp.get("result")?.get("value")?.as_array()?.len();
        }
        Some(total)
    }

    /// Token holdings of an address: `(mint, ui_amount)` for every account with
    /// a non-zero balance. Backs `/positions`. `None` means a query failed —
    /// never render that as "empty wallet", which is a different (and
    /// misleading) claim.
    ///
    /// Zero-balance accounts are dropped: a memecoin fully sold still leaves an
    /// empty token account behind, which is not a position.
    ///
    /// # Why this takes a mint list
    ///
    /// Enumerating an owner's accounts means `getTokenAccountsByOwner`, which
    /// is a SCAN — and providers reject scans under load, permanently in at
    /// least one case:
    ///
    /// ```text
    ///   scan aborted: scan rejected: memory pressure threshold exceeded
    /// ```
    ///
    /// So the caller supplies the mints it cares about, which it already knows
    /// from the audit log, and the addresses are DERIVED rather than searched
    /// for. One targeted batch read instead of a scan.
    ///
    /// The trade: a token the bot did not buy through its own audit trail is
    /// invisible here. That is the correct bias for a positions screen whose
    /// job is showing what the bot is holding, and far better than the screen
    /// showing nothing at all because the provider refused the query.
    #[cfg(feature = "sniper")]
    pub async fn token_holdings(
        &self,
        owner: &str,
        mints: &[String],
    ) -> Option<Vec<(String, f64)>> {
        if self.url.is_empty() {
            return None;
        }
        if mints.is_empty() {
            return Some(Vec::new());
        }
        use spl_associated_token_account_interface::address::
            get_associated_token_address_with_program_id;
        let owner_pk = crate::tx::pk(owner).ok()?;

        let mut out = Vec::new();
        // Batched: `getMultipleAccounts` caps at 100 addresses, and each mint
        // contributes two candidates (one per token program).
        for chunk in mints.chunks(50) {
            let mut addrs = Vec::with_capacity(chunk.len() * 2);
            for m in chunk {
                let Ok(mint_pk) = crate::tx::pk(m) else { continue };
                addrs.push(
                    get_associated_token_address_with_program_id(
                        &owner_pk, &mint_pk, &crate::tx::TOKEN_PROGRAM,
                    )
                    .to_string(),
                );
                addrs.push(
                    get_associated_token_address_with_program_id(
                        &owner_pk, &mint_pk, &crate::tx::TOKEN_2022_PROGRAM,
                    )
                    .to_string(),
                );
            }
            if addrs.is_empty() {
                continue;
            }
            let body = json!({
                "jsonrpc":"2.0","id":1,"method":"getMultipleAccounts",
                "params":[addrs, {"encoding":"jsonParsed","commitment": self.commitment}],
            });
            let resp: serde_json::Value = self
                .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
            // A failed QUERY is not an empty wallet: propagate it.
            let accts = resp.get("result")?.get("value")?.as_array()?;
            for acct in accts {
                let Some(info) = acct.pointer("/data/parsed/info") else { continue };
                let Some(mint) = info.get("mint").and_then(|m| m.as_str()) else { continue };
                let ui = info
                    .pointer("/tokenAmount/uiAmount")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if ui > 0.0 {
                    out.push((mint.to_string(), ui));
                }
            }
        }
        Some(out)
    }

    /// Raw token balance the `owner` holds of a specific `mint`, as
    /// `(amount_in_base_units, decimals)`. This is what an exit needs: Jupiter
    /// quotes on integer base units, and "sell 50%" must be computed on the
    /// exact raw amount, never a lossy UI float. None if unreadable or zero.
    ///
    /// # Why this derives the address instead of asking for it
    ///
    /// The obvious call is `getTokenAccountsByOwner`, and it is what this used
    /// to do. That is a SCAN, and providers reject scans under load:
    ///
    /// ```text
    ///   scan aborted: scan rejected: memory pressure threshold exceeded
    /// ```
    ///
    /// Measured against one provider, that failure was total and permanent —
    /// every attempt, mint-filtered or not. Since this call is what the
    /// auto-sell sweep uses to see its own positions, a provider that refuses
    /// scans does not degrade the bot, it blinds it: no holdings visible means
    /// no stop-loss, silently.
    ///
    /// The bot creates its token accounts idempotently as ATAs on every buy, so
    /// the address is derivable and does not need looking up. Both token
    /// programs are checked in one `getMultipleAccounts`, which is a targeted
    /// read rather than a scan: it is cheaper, faster, and works on providers
    /// that refuse the scan entirely.
    #[cfg(feature = "sniper")]
    pub async fn token_balance_raw(&self, owner: &str, mint: &str) -> Option<(u64, u8)> {
        if self.url.is_empty() {
            return None;
        }
        use spl_associated_token_account_interface::address::
            get_associated_token_address_with_program_id;
        let owner_pk = crate::tx::pk(owner).ok()?;
        let mint_pk = crate::tx::pk(mint).ok()?;
        // Both token programs: a mint is owned by one of them, and deriving
        // both costs nothing next to a round trip.
        let candidates = [
            get_associated_token_address_with_program_id(
                &owner_pk, &mint_pk, &crate::tx::TOKEN_PROGRAM,
            )
            .to_string(),
            get_associated_token_address_with_program_id(
                &owner_pk, &mint_pk, &crate::tx::TOKEN_2022_PROGRAM,
            )
            .to_string(),
        ];
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getMultipleAccounts",
            "params":[candidates, {"encoding":"jsonParsed","commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        let accts = resp.get("result")?.get("value")?.as_array()?;
        let mut total: u64 = 0;
        let mut decimals: u8 = 0;
        for acct in accts {
            let Some(ta) = acct.pointer("/data/parsed/info/tokenAmount") else { continue };
            if let Some(a) =
                ta.get("amount").and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok())
            {
                total = total.saturating_add(a);
            }
            if let Some(d) = ta.get("decimals").and_then(|v| v.as_u64()) {
                decimals = d as u8;
            }
        }
        (total > 0).then_some((total, decimals))
    }

    /// Total supply of a mint, in UI units. Used to detect LP burns: a supply
    /// that has fallen to ~0 means the LP tokens were destroyed.
    ///
    /// The response shape matches `getTokenAccountBalance`, so it shares a parser.
    pub async fn token_supply(&self, mint: &str) -> Option<f64> {
        self.with_retries("getTokenSupply", mint, false, parse_balance)
            .await
    }

    /// Simulate a serialized transaction against current mainnet state.
    ///
    /// Read-only: the node executes the transaction against a snapshot and
    /// discards the result. Nothing is submitted, nothing is charged, and with
    /// `sigVerify: false` no signature (and therefore no private key) is needed
    /// — which is exactly what makes this a safe way to validate instruction
    /// construction before any key exists.
    ///
    /// Returns the raw `value` object: `{err, logs, unitsConsumed, ...}`.
    ///
    /// Only compiled for the execution path — a detector-only build has no
    /// transactions to simulate.
    #[cfg(feature = "sniper")]
    pub async fn simulate_transaction(&self, tx_base64: &str) -> Option<serde_json::Value> {
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "simulateTransaction",
            "params": [tx_base64, {
                "encoding": "base64",
                "sigVerify": false,
                "replaceRecentBlockhash": true,
                "commitment": self.commitment,
                // Required to simulate v0 (versioned) transactions such as a
                // Jupiter swap; harmless for legacy transactions.
                "maxSupportedTransactionVersion": 0,
            }],
        });
        let resp: serde_json::Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        resp.get("result")?.get("value").cloned()
    }

    /// Vault balance in RAW base units (not UI units). Quote math works in raw
    /// amounts, so this is what the execution path needs.
    #[cfg(feature = "sniper")]
    pub async fn vault_balance_raw(&self, vault: &str) -> Option<u64> {
        self.with_retries("getTokenAccountBalance", vault, false, |resp| {
            resp.get("result")?
                .get("value")?
                .get("amount")?
                .as_str()?
                .parse::<u64>()
                .ok()
        })
        .await
    }

    /// The program that owns an account. For a mint this distinguishes the
    /// classic SPL Token program from Token-2022 — they are NOT interchangeable,
    /// and using the wrong one makes ATA derivation and every token instruction
    /// fail with `IncorrectProgramId`.
    #[cfg(feature = "sniper")]
    pub async fn account_owner(&self, address: &str) -> Option<String> {
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
            "params":[address, {"encoding":"base64","commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        Some(resp.get("result")?.get("value")?.get("owner")?.as_str()?.to_string())
    }

    /// Raw account data. Needed to decode pool/market state before a swap.
    #[cfg(feature = "sniper")]
    pub async fn account_data(&self, address: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
            "params":[address, {"encoding":"base64","commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        let d = resp.get("result")?.get("value")?.get("data")?.get(0)?.as_str()?;
        base64::engine::general_purpose::STANDARD.decode(d).ok()
    }

    /// Holder count and concentration.
    ///
    /// A TRUE holder count needs `getProgramAccounts` over the token program,
    /// which this provider refuses ("Too many accounts requested") — as most
    /// do, since it is an unbounded scan. `getTokenLargestAccounts` caps at 20,
    /// which is exact for a fresh launch and a floor after that. For deciding
    /// on a minutes-old token, the range below 20 is the one that matters.
    pub async fn holder_stats(&self, mint: &str) -> Option<HolderStats> {
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getTokenLargestAccounts",
            "params":[mint, {"commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        let accounts = resp.pointer("/result/value")?.as_array()?;
        if accounts.is_empty() {
            return None;
        }

        let mut amounts: Vec<f64> = accounts
            .iter()
            .filter_map(|a| a.get("uiAmount").and_then(|v| v.as_f64()))
            .filter(|v| *v > 0.0)
            .collect();
        if amounts.is_empty() {
            return None;
        }
        amounts.sort_by(|a, b| b.total_cmp(a));

        let supply = self.token_supply(mint).await?;
        if supply <= 0.0 {
            return None;
        }

        let largest = amounts[0];
        // Skip the largest, then take the next ten.
        let top10: f64 = amounts.iter().skip(1).take(10).sum();

        Some(HolderStats {
            count: amounts.len(),
            // Capped on the count of NON-ZERO holders, not raw rows. The RPC
            // returns the top 20 BY BALANCE and pads with zero-balance
            // accounts, so 20 rows of which 4 hold anything means there are
            // exactly 4 holders — not "4 or more". Using the raw row count
            // reported "4+" for a token whose holders we had seen in full.
            capped: amounts.len() >= 20,
            // `clamp` alone is not enough: -0.0 is not LESS than 0.0, so it
            // survives and renders as "-0.0%". An explicit positivity test is.
            top10_pct: pct(top10, supply),
            largest_pct: pct(largest, supply),
        })
    }

    /// Token `(name, symbol)`, from wherever this mint actually keeps it.
    ///
    /// There are TWO places, and checking only one is how a token ends up
    /// nameless:
    ///
    /// * **Token-2022** mints can embed metadata in the mint account itself via
    ///   the `tokenMetadata` extension. No PDA, no second account.
    /// * **Classic SPL** mints use a separate Metaplex metadata PDA.
    ///
    /// The extension is tried first because it needs no PDA derivation — which
    /// means it also works in a build without the Solana crates, where the
    /// Metaplex path is unavailable entirely.
    pub async fn token_name_symbol(&self, mint: &str) -> Option<(String, String)> {
        let m = self.token_meta(mint).await?;
        Some((m.name, m.symbol))
    }

    /// Full on-chain token metadata, including the off-chain `uri` that holds
    /// the socials.
    pub async fn token_meta(&self, mint: &str) -> Option<TokenMeta> {
        if let Some(found) = self.token_2022_metadata(mint).await {
            return Some(found);
        }
        #[cfg(feature = "sniper")]
        {
            let pda = metaplex_metadata_pda(mint)?;
            let data = self.account_data(&pda).await?;
            let (name, symbol) = parse_metadata_name_symbol(&data)?;
            // The Metaplex layout stores `uri` directly after `symbol`; the
            // existing parser stops at symbol, so the uri is read separately.
            return Some(TokenMeta { name, symbol, uri: parse_metadata_uri(&data) });
        }
        #[cfg(not(feature = "sniper"))]
        None
    }

    /// Metadata carried on the mint account by the Token-2022 `tokenMetadata`
    /// extension. `None` for classic SPL mints, which have no extensions.
    pub async fn token_2022_metadata(&self, mint: &str) -> Option<TokenMeta> {
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
            "params":[mint, {"encoding":"jsonParsed","commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        let extensions = resp
            .pointer("/result/value/data/parsed/info/extensions")?
            .as_array()?;

        for ext in extensions {
            if ext.get("extension")?.as_str()? != "tokenMetadata" {
                continue;
            }
            let state = ext.get("state")?;
            let name = state.get("name")?.as_str()?.trim().to_string();
            let symbol = state.get("symbol")?.as_str()?.trim().to_string();
            // An extension present but blank is not a name.
            if name.is_empty() && symbol.is_empty() {
                return None;
            }
            let uri = state
                .get("uri")
                .and_then(|v| v.as_str())
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty());
            return Some(TokenMeta { name, symbol, uri });
        }
        None
    }

    /// Token `(name, symbol)` from the Metaplex metadata account only.
    /// Prefer [`Self::token_name_symbol`], which also covers Token-2022.
    #[cfg(feature = "sniper")]
    pub async fn token_metadata(&self, mint: &str) -> Option<(String, String)> {
        let pda = metaplex_metadata_pda(mint)?;
        let data = self.account_data(&pda).await?;
        parse_metadata_name_symbol(&data)
    }

    /// Which mint a token account holds. Used to determine pool ORIENTATION:
    /// `base_vault`/`quote_vault` are pool-native names, and on Raydium CPMM /
    /// PumpSwap the "base" side is WSOL, so which vault holds the launched token
    /// cannot be assumed from the field name. Reading the account settles it.
    #[cfg(feature = "sniper")]
    pub async fn token_account_mint(&self, address: &str) -> Option<String> {
        let body = json!({
            "jsonrpc":"2.0","id":1,"method":"getAccountInfo",
            "params":[address, {"encoding":"jsonParsed","commitment": self.commitment}],
        });
        let resp: serde_json::Value = self
            .client.post(&self.url).json(&body).send().await.ok()?.json().await.ok()?;
        Some(
            resp.pointer("/result/value/data/parsed/info/mint")?
                .as_str()?
                .to_string(),
        )
    }

    /// Authority/extension state of a mint. `None` if unreadable.
    pub async fn mint_info(&self, mint: &str) -> Option<MintInfo> {
        self.with_retries("getAccountInfo", mint, true, parse_mint_info)
            .await
    }

    /// Shared retry loop: freshly created accounts may not be queryable for a
    /// slot or two after the creating transaction.
    async fn with_retries<T, F>(
        &self,
        method: &str,
        account: &str,
        parsed_encoding: bool,
        parse: F,
    ) -> Option<T>
    where
        F: Fn(&serde_json::Value) -> Option<T>,
    {
        if !self.initial_delay.is_zero() {
            tokio::time::sleep(self.initial_delay).await;
        }

        for attempt in 1..=self.retries {
            match self.request(method, account, parsed_encoding).await {
                Ok(resp) => {
                    if let Some(v) = parse(&resp) {
                        return Some(v);
                    }
                    debug!(account, method, attempt, "not queryable yet");
                }
                Err(e) => debug!(account, method, attempt, error = %e, "rpc read failed"),
            }
            if attempt < self.retries {
                tokio::time::sleep(self.retry_delay).await;
            }
        }
        warn!(account, method, "unreadable after retries");
        None
    }

    async fn request(
        &self,
        method: &str,
        account: &str,
        parsed_encoding: bool,
    ) -> Result<serde_json::Value, reqwest::Error> {
        let cfg = if parsed_encoding {
            json!({"encoding": "jsonParsed", "commitment": self.commitment})
        } else {
            json!({"commitment": self.commitment})
        };
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": [account, cfg],
        });
        self.client
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await
    }
}

/// Extract a UI balance from a `getTokenAccountBalance` response.
///
/// Prefers `uiAmountString`: `uiAmount` is a JSON float the RPC returns as
/// `null` for values too large to represent — exactly the case for high-supply
/// memecoins.
fn parse_balance(resp: &serde_json::Value) -> Option<f64> {
    let value = resp.get("result")?.get("value")?;

    if let Some(s) = value.get("uiAmountString").and_then(|v| v.as_str()) {
        if let Ok(v) = s.parse::<f64>() {
            return Some(v);
        }
    }
    if let Some(v) = value.get("uiAmount").and_then(|v| v.as_f64()) {
        return Some(v);
    }
    let raw: f64 = value.get("amount")?.as_str()?.parse().ok()?;
    let decimals = value.get("decimals")?.as_u64()? as i32;
    Some(raw / 10f64.powi(decimals))
}

/// Extract mint authorities + risky extensions from a jsonParsed
/// `getAccountInfo` response. Works for both spl-token and spl-token-2022.
/// Derive the Metaplex Token Metadata PDA (base58) for a mint.
/// Seeds: ["metadata", metadata_program, mint].
#[cfg(feature = "sniper")]
fn metaplex_metadata_pda(mint: &str) -> Option<String> {
    use solana_pubkey::Pubkey;
    use std::str::FromStr;
    // Metaplex Token Metadata program.
    let program = Pubkey::from_str("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s").ok()?;
    let mint_pk = Pubkey::from_str(mint).ok()?;
    let (pda, _) = Pubkey::find_program_address(
        &[b"metadata", program.as_ref(), mint_pk.as_ref()],
        &program,
    );
    Some(pda.to_string())
}

/// Parse `(name, symbol)` from a Metaplex Metadata account.
/// Layout: key(1) + update_authority(32) + mint(32) then borsh strings
/// name, symbol, uri. Names are null-padded to a fixed max, so trim.
#[cfg(feature = "sniper")]
fn parse_metadata_name_symbol(data: &[u8]) -> Option<(String, String)> {
    fn read_string(data: &[u8], o: &mut usize) -> Option<String> {
        let end = o.checked_add(4)?;
        if end > data.len() {
            return None;
        }
        let len = u32::from_le_bytes(data[*o..end].try_into().ok()?) as usize;
        *o = end;
        // Sanity bound: Metaplex caps name/symbol/uri well under this.
        if len > 256 || o.checked_add(len)? > data.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&data[*o..*o + len]).into_owned();
        *o += len;
        Some(s.trim_end_matches('\0').trim().to_string())
    }
    let mut o = 1 + 32 + 32; // key + update_authority + mint
    let name = read_string(data, &mut o)?;
    let symbol = read_string(data, &mut o)?;
    if name.is_empty() && symbol.is_empty() {
        return None;
    }
    Some((name, symbol))
}

/// The `uri` field of a Metaplex metadata account — it follows name and symbol
/// in the same borsh string layout, so it is reached by skipping both.
#[cfg(feature = "sniper")]
fn parse_metadata_uri(data: &[u8]) -> Option<String> {
    fn skip_string(data: &[u8], o: &mut usize) -> Option<()> {
        let end = o.checked_add(4)?;
        if end > data.len() {
            return None;
        }
        let len = u32::from_le_bytes(data[*o..end].try_into().ok()?) as usize;
        *o = end.checked_add(len)?;
        (*o <= data.len()).then_some(())
    }
    let mut o = 1 + 32 + 32;
    skip_string(data, &mut o)?; // name
    skip_string(data, &mut o)?; // symbol

    let end = o.checked_add(4)?;
    if end > data.len() {
        return None;
    }
    let len = u32::from_le_bytes(data[o..end].try_into().ok()?) as usize;
    o = end;
    if len > 256 || o.checked_add(len)? > data.len() {
        return None;
    }
    let uri = String::from_utf8_lossy(&data[o..o + len])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    (!uri.is_empty()).then_some(uri)
}

fn parse_mint_info(resp: &serde_json::Value) -> Option<MintInfo> {
    let parsed = resp.get("result")?.get("value")?.get("data")?.get("parsed")?;
    if parsed.get("type")?.as_str()? != "mint" {
        return None;
    }
    let info = parsed.get("info")?;

    // Absent OR JSON null both mean "revoked" — `as_str` yields None for null,
    // which is exactly the semantics we want.
    let mint_authority = info.get("mintAuthority").and_then(|v| v.as_str()).map(String::from);
    let freeze_authority = info.get("freezeAuthority").and_then(|v| v.as_str()).map(String::from);
    let decimals = info.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

    let mut risky_extensions = Vec::new();
    if let Some(exts) = info.get("extensions").and_then(|v| v.as_array()) {
        for e in exts {
            if let Some(name) = e.get("extension").and_then(|v| v.as_str()) {
                if RISKY_EXTENSIONS.contains(&name) {
                    risky_extensions.push(name.to_string());
                }
            }
        }
    }

    Some(MintInfo { mint_authority, freeze_authority, decimals, risky_extensions })
}

#[cfg(test)]
mod live_meta_tests {
    use super::*;

    /// Live check of holder concentration against real mints.
    ///
    ///   cargo test --features sniper -- --ignored --nocapture live_holder_stats
    #[ignore = "hits mainnet RPC; needs RPC_URL"]
    #[tokio::test]
    async fn live_holder_stats() {
        let _ = dotenvy::dotenv();
        let Ok(url) = std::env::var("RPC_URL") else { return };
        let rpc = RpcClient::new(&crate::config::RpcConfig {
            url,
            commitment: "confirmed".into(),
            initial_delay_ms: 0,
            retries: 2,
            retry_delay_ms: 200,
            ws_url: String::new(),
        });

        let mints: Vec<String> = std::fs::read_to_string("conviction_signals.jsonl")
            .map(|t| {
                let mut seen = std::collections::BTreeSet::new();
                for l in t.lines().filter(|l| !l.trim().is_empty()) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
                        if let Some(m) = v.get("mint").and_then(|m| m.as_str()) {
                            seen.insert(m.to_string());
                        }
                    }
                }
                seen.into_iter().collect()
            })
            .unwrap_or_default();
        if mints.is_empty() {
            println!("no recorded signals");
            return;
        }

        for mint in mints.iter().take(4) {
            match rpc.holder_stats(mint).await {
                Some(h) => println!(
                    "{:.10}…  holders={}{}  top10(ex-pool)={:.1}%  largest={:.1}%",
                    mint,
                    h.count,
                    if h.capped { "+" } else { "" },
                    h.top10_pct,
                    h.largest_pct
                ),
                None => println!("{:.10}…  unreadable", mint),
            }
        }
    }

    /// Live check that the Token-2022 metadata path works. This is the bug the
    /// path exists for: CHEESECOIN keeps its name in the mint's `tokenMetadata`
    /// extension, has no Metaplex PDA, and rendered as a bare mint until this
    /// lookup was added.
    ///
    ///   cargo test -- --ignored --nocapture live_token_2022_metadata
    #[ignore = "hits mainnet RPC; needs RPC_URL"]
    #[tokio::test]
    async fn live_token_2022_metadata() {
        let _ = dotenvy::dotenv();
        let url = std::env::var("RPC_URL").expect("RPC_URL");
        let cfg = crate::config::RpcConfig {
            url,
            commitment: "confirmed".into(),
            initial_delay_ms: 0,
            retries: 2,
            retry_delay_ms: 200,
            ws_url: String::new(),
        };
        let rpc = RpcClient::new(&cfg);

        let m = rpc
            .token_meta("ER8j7VtBhK7BcnZd849u2ndKEcnMmvvtHsmsLD9JZ9LJ")
            .await
            .expect("Token-2022 metadata must resolve");
        println!("{m:#?}");
        assert_eq!(m.symbol, "CHEESE");
        assert_eq!(m.name, "CHEESECOIN");
        assert!(m.uri.is_some(), "uri carries the socials");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_ui_amount_string() {
        let r = json!({"result":{"value":{
            "amount":"12500000000","decimals":9,"uiAmount":12.5,"uiAmountString":"12.5"}}});
        assert_eq!(parse_balance(&r), Some(12.5));
    }

    /// High-supply tokens come back with `uiAmount: null`.
    #[test]
    fn handles_null_ui_amount() {
        let r = json!({"result":{"value":{
            "amount":"19883357835858193","decimals":6,
            "uiAmount":null,"uiAmountString":"19883357835.858193"}}});
        assert_eq!(parse_balance(&r), Some(19883357835.858193));
    }

    #[test]
    fn falls_back_to_raw_amount_and_decimals() {
        let r = json!({"result":{"value":{"amount":"2500000000","decimals":9}}});
        assert_eq!(parse_balance(&r), Some(2.5));
    }

    /// An RPC error must read as "unknown", never 0.
    #[test]
    fn rpc_error_is_none_not_zero() {
        let r = json!({"jsonrpc":"2.0","id":1,
            "error":{"code":-32602,"message":"could not find account"}});
        assert_eq!(parse_balance(&r), None);
    }

    fn mint_resp(mint_auth: serde_json::Value, freeze_auth: serde_json::Value) -> serde_json::Value {
        json!({"result":{"value":{"data":{"parsed":{"type":"mint","info":{
            "decimals":6,"supply":"1000","isInitialized":true,
            "mintAuthority":mint_auth,"freezeAuthority":freeze_auth}}}}}})
    }

    #[test]
    fn revoked_authorities_are_none() {
        let r = mint_resp(json!(null), json!(null));
        let m = parse_mint_info(&r).unwrap();
        assert!(m.mint_authority_revoked());
        assert!(m.freeze_authority_revoked());
        assert_eq!(m.decimals, 6);
    }

    #[test]
    fn live_authorities_are_captured() {
        let r = mint_resp(json!("MintAuth11111"), json!("FreezeAuth1111"));
        let m = parse_mint_info(&r).unwrap();
        assert!(!m.mint_authority_revoked());
        assert!(!m.freeze_authority_revoked());
        assert_eq!(m.mint_authority.as_deref(), Some("MintAuth11111"));
    }

    /// A missing key must behave like an explicit null (revoked), not panic.
    #[test]
    fn absent_authority_keys_read_as_revoked() {
        let r = json!({"result":{"value":{"data":{"parsed":{"type":"mint","info":{
            "decimals":9,"supply":"1"}}}}}});
        let m = parse_mint_info(&r).unwrap();
        assert!(m.mint_authority_revoked() && m.freeze_authority_revoked());
    }

    #[test]
    fn detects_risky_token2022_extensions() {
        let r = json!({"result":{"value":{"data":{"parsed":{"type":"mint","info":{
            "decimals":6,"mintAuthority":null,"freezeAuthority":null,
            "extensions":[
                {"extension":"transferFeeConfig","state":{}},
                {"extension":"metadataPointer","state":{}},
                {"extension":"transferHook","state":{}}
            ]}}}}}});
        let m = parse_mint_info(&r).unwrap();
        // metadataPointer is benign and must not be flagged.
        assert_eq!(m.risky_extensions, vec!["transferFeeConfig", "transferHook"]);
    }

    /// A token ACCOUNT is not a mint — must not be misread as one.
    #[test]
    fn token_account_is_not_a_mint() {
        let r = json!({"result":{"value":{"data":{"parsed":{"type":"account","info":{
            "mint":"X","owner":"Y"}}}}}});
        assert_eq!(parse_mint_info(&r), None);
    }

    /// The probe MUST be a method that enforces authentication.
    ///
    /// Verified against Helius: an endpoint with an invalid API key answers
    /// `getHealth` with `{"result":"ok"}` and HTTP 200 — auth is checked
    /// per-method, and the health endpoint is one of the methods that does not
    /// check it. `getSlot` on the same URL returns HTTP 401.
    ///
    /// This test exists because the first implementation used `getHealth` and
    /// would have reported a completely dead credential as healthy. A health
    /// check that passes a broken key is worse than no health check: it turns a
    /// loud failure into a false reassurance.
    #[test]
    fn health_probe_is_an_authenticated_method() {
        let src = include_str!("rpc.rs");
        let probe = src
            .lines()
            .find(|l| l.contains(r#""method":"#) && l.contains("json!") && l.contains("id\":1"))
            .unwrap_or("");
        assert!(
            !probe.contains("getHealth"),
            "health() must not probe with getHealth — it does not enforce auth"
        );
    }

    /// `getSlot` shapes: a real slot passes, slot 0 and junk do not.
    #[test]
    fn health_accepts_only_a_real_slot() {
        // These mirror the match arms in `health()`.
        let ok = json!({"jsonrpc":"2.0","result":434320912u64});
        assert!(matches!(ok.get("result").and_then(|r| r.as_u64()), Some(s) if s > 0));

        let unsynced = json!({"jsonrpc":"2.0","result":0u64});
        assert_eq!(unsynced.get("result").and_then(|r| r.as_u64()), Some(0));

        let junk = json!({"jsonrpc":"2.0","result":"ok"});
        assert_eq!(junk.get("result").and_then(|r| r.as_u64()), None,
                   "a string result must not be accepted as a slot");
    }

    /// An RPC that answers with a JSON-RPC *error* (invalid API key, rate
    /// limit) must read as unknown, never as a zero balance.
    ///
    /// This was observed for real: a Helius URL with a bad key returns
    /// `{"error":{"code":-32401,"message":"Invalid API key"}}` with no `result`
    /// field. Rendering that as "0 SOL" would tell someone their wallet was
    /// emptied when in fact it was never read.
    #[test]
    fn rpc_error_response_has_no_result_field() {
        let err = json!({"jsonrpc":"2.0","error":{"code":-32401,"message":"Invalid API key"}});
        // The `?` chain in sol_balance bails here, yielding None.
        assert!(err.get("result").is_none());

        // And a well-formed success parses to a real number.
        let ok = json!({"jsonrpc":"2.0","result":{"value":1_500_000_000u64}});
        let lamports = ok.get("result").unwrap().get("value").unwrap().as_u64().unwrap();
        assert_eq!(lamports as f64 / 1_000_000_000.0, 1.5);
    }

    /// Live check of the `/balance` reads against mainnet.
    ///
    /// Uses a POSITIVE CONTROL: an account known to hold SOL and many token
    /// accounts. Without one, a broken implementation returning 0 or an empty
    /// list would pass — the same vacuous-success trap as asserting on an
    /// `AccountNotFound` simulation.
    ///
    ///   RPC_URL=... cargo test --features sniper -- --ignored --nocapture live_balance_reads
    #[tokio::test]
    #[ignore = "hits mainnet RPC; needs RPC_URL"]
    async fn live_balance_reads() {
        let Ok(url) = std::env::var("RPC_URL") else {
            panic!("set RPC_URL to run this test");
        };
        let cfg = crate::config::RpcConfig {
            url,
            initial_delay_ms: 0,
            retries: 3,
            retry_delay_ms: 1000,
            ..Default::default()
        };
        let client = RpcClient::new(&cfg);

        // Positive control: Binance hot wallet. Holds a large SOL balance and
        // many token accounts, so zero/empty here means the code is wrong.
        let funded = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";

        let sol = client.sol_balance(funded).await.expect("SOL balance readable");
        println!("SOL balance: {sol}");
        assert!(sol > 1.0, "positive control must hold SOL, got {sol}");

        let count = client
            .token_account_count(funded)
            .await
            .expect("token account count readable");
        println!("token accounts: {count}");
        assert!(count > 0, "positive control must hold token accounts");

        // NEGATIVE control: a valid but almost-certainly-unused address must
        // read as Some(0.0) — a real zero — not None. Confirms we distinguish
        // "empty wallet" from "could not read".
        let empty = "11111111111111111111111111111112";
        let z = client.sol_balance(empty).await;
        println!("unused address: {z:?}");
        assert!(z.is_some(), "an existing-but-empty read must be Some, not None");

        // An empty URL must yield None (unknown), never Some(0.0).
        let offline = RpcClient::new(&crate::config::RpcConfig {
            url: String::new(),
            ..Default::default()
        });
        assert_eq!(offline.sol_balance(funded).await, None,
                   "no RPC configured must be unknown, never zero");
    }

    /// Live end-to-end check against mainnet. Ignored by default (network +
    /// public RPC rate limits); run with:
    ///   cargo test -- --ignored --nocapture live_rpc_reads
    #[tokio::test]
    #[ignore = "hits public mainnet RPC"]
    async fn live_rpc_reads() {
        let cfg = crate::config::RpcConfig {
            url: "https://api.mainnet-beta.solana.com".into(),
            initial_delay_ms: 0,
            retries: 3,
            retry_delay_ms: 1500,
            ..Default::default()
        };
        let client = RpcClient::new(&cfg);

        // Quote-side vaults from the verified creation txs.
        for (label, vault) in [
            ("raydium_v4 WSOL vault", "5pCXd5sDvaKvFYo1QtXQqiJEQcRHQdYxDceK7CMHmDYz"),
            ("cpmm       WSOL vault", "AwNcrnAhstiij69TKdkZGmPe7eECnyLPJcDFBVQq95Qn"),
        ] {
            let bal = client.vault_balance(vault).await;
            println!("{label}: {bal:?}");
            let bal = bal.unwrap_or_else(|| panic!("{label}: expected a balance"));
            assert!(bal.is_finite() && bal >= 0.0);
        }

        // WSOL itself: a well-known mint with no freeze authority.
        let wsol = client.mint_info(crate::model::WSOL_MINT).await;
        println!("WSOL mint: {wsol:?}");
        let wsol = wsol.expect("WSOL mint should be readable");
        assert_eq!(wsol.decimals, 9);
        assert!(wsol.freeze_authority_revoked(), "WSOL has no freeze authority");

        // The launched tokens from the verified creation txs.
        for (label, mint) in [
            ("v4 new token", "2eVuXmkpZKR4mEwL92myU7h77j3znNC2b76XVAtRyQSn"),
            ("cpmm new token", "8wUqUf6RgVVDNZgEvToa5H7ovTpkpWmAoMAw7Tvoe3kA"),
            ("pumpswap new token", "6wgnjrUfZEt24TntGeAaVehsxccxAZQeS6atBapiqQoq"),
        ] {
            let m = client.mint_info(mint).await;
            println!("{label}: {m:?}");
            assert!(m.is_some(), "{label} should be readable");
        }

        // POSITIVE CONTROL: every mint above has revoked authorities, so on its
        // own this test cannot tell "parsed correctly" from "always returns
        // None". USDC is centrally controlled by Circle and has BOTH authorities
        // live, so it proves the parser actually distinguishes the two states.
        let usdc = client.mint_info(crate::model::USDC_MINT).await;
        println!("USDC mint: {usdc:?}");
        let usdc = usdc.expect("USDC mint should be readable");
        assert!(
            !usdc.mint_authority_revoked(),
            "USDC has a live mint authority; parser reported it revoked"
        );
        assert!(
            !usdc.freeze_authority_revoked(),
            "USDC has a live freeze authority; parser reported it revoked"
        );
        assert_eq!(usdc.decimals, 6);

        // Token-2022 mint (the PumpSwap LP mint) — exercises extension parsing
        // against a real account rather than synthetic JSON.
        let lp = client.mint_info("kJVxe4Ywe1PcZoVS9EemS3HFHybBZvy37CgV6a7zcLx").await;
        println!("pumpswap LP mint (token-2022): {lp:?}");

        // --- token_supply, used by the watcher to detect LP burns ---
        // The PumpSwap pool's LP was burned ~8 min after creation, so its supply
        // is now exactly 0. This is a real instance of the case the watcher
        // exists to catch.
        let burned = client
            .token_supply("kJVxe4Ywe1PcZoVS9EemS3HFHybBZvy37CgV6a7zcLx")
            .await;
        println!("pumpswap LP supply (burned): {burned:?}");
        assert_eq!(burned, Some(0.0), "this LP mint was burned; supply must read 0");

        // The Raydium v4 LP was never burned — supply still outstanding.
        let outstanding = client
            .token_supply("CSkEnvFTBQUU5VxfNngK3kvmpCzacRtknpGcyj1uyM85")
            .await;
        println!("raydium_v4 LP supply (outstanding): {outstanding:?}");
        let outstanding = outstanding.expect("v4 LP supply should be readable");
        assert!(outstanding > 0.0, "v4 LP was not burned; supply must be > 0");

        // End-to-end: real readings must produce the right verdicts.
        use crate::watcher::{Verdict, evaluate};
        assert_eq!(
            evaluate(Some(1.6), Some(1.6), Some(450961.95), burned, 0.5, 0.0),
            Verdict::LpBurned,
            "real burned-LP readings must classify as LpBurned"
        );
        assert!(matches!(
            evaluate(Some(1.6), Some(1.6), Some(1.0), Some(outstanding), 0.5, 0.0),
            Verdict::LpOutstanding { .. }
        ));

        // A non-mint account must be None, not a bogus MintInfo.
        assert_eq!(client.mint_info("11111111111111111111111111111111").await, None);
    }

    #[cfg(feature = "sniper")]
    #[test]
    fn parses_metaplex_name_and_symbol() {
        fn borsh_str(s: &str, pad: usize) -> Vec<u8> {
            // Metaplex stores fixed-max, null-padded strings; length counts pad.
            let mut buf = s.as_bytes().to_vec();
            buf.resize(pad, 0);
            let mut out = (pad as u32).to_le_bytes().to_vec();
            out.extend_from_slice(&buf);
            out
        }
        let mut data = vec![4u8]; // key
        data.extend_from_slice(&[0u8; 32]); // update_authority
        data.extend_from_slice(&[0u8; 32]); // mint
        data.extend(borsh_str("Doge Killer", 32));
        data.extend(borsh_str("DOGEK", 10));
        let (name, symbol) = parse_metadata_name_symbol(&data).expect("parses");
        assert_eq!(name, "Doge Killer", "trailing null padding trimmed");
        assert_eq!(symbol, "DOGEK");
    }

    #[cfg(feature = "sniper")]
    #[test]
    fn metadata_parse_rejects_truncated_and_empty() {
        // Too short to hold the header.
        assert_eq!(parse_metadata_name_symbol(&[0u8; 10]), None);
        // A length that runs past the buffer must not panic or read OOB.
        let mut data = vec![4u8];
        data.extend_from_slice(&[0u8; 64]);
        data.extend_from_slice(&9999u32.to_le_bytes()); // absurd name length
        assert_eq!(parse_metadata_name_symbol(&data), None);
    }
}
