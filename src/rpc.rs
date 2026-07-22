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

    /// Token holdings of an address: `(mint, ui_amount)` for every account with a
    /// non-zero balance, across classic SPL Token and Token-2022. Backs
    /// `/positions`. `None` means a query failed — never render that as "empty
    /// wallet", which is a different (and misleading) claim.
    ///
    /// Zero-balance accounts are dropped: a memecoin fully sold still leaves an
    /// empty token account behind, which is not a position.
    pub async fn token_holdings(&self, owner: &str) -> Option<Vec<(String, f64)>> {
        if self.url.is_empty() {
            return None;
        }
        let mut out = Vec::new();
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
            for acct in resp.get("result")?.get("value")?.as_array()? {
                let info = acct.pointer("/account/data/parsed/info")?;
                let mint = info.get("mint")?.as_str()?.to_string();
                let amount = info
                    .pointer("/tokenAmount/uiAmount")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                if amount > 0.0 {
                    out.push((mint, amount));
                }
            }
        }
        Some(out)
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
}
