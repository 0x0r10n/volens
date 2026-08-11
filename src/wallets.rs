//! Tracked ("smart money") wallets, and detecting when one of them buys.
//!
//! # Why balance deltas instead of parsing swaps
//!
//! A tracked wallet can buy through Raydium, PumpSwap, Meteora, Jupiter, an
//! aggregator, or a venue that did not exist last week. Parsing each venue's
//! swap instruction would mean a discriminator + account layout per venue, and
//! silent blindness to anything not yet coded.
//!
//! Every transaction already carries `preTokenBalances` / `postTokenBalances`.
//! A buy is visible in the arithmetic:
//!
//! ```text
//!     token balance UP   and   SOL balance DOWN   =>   bought
//! ```
//!
//! That is venue-agnostic by construction — it cannot go stale when a DEX ships
//! a new program version, and it sees routes through venues volens does not
//! support at all. Less code, strictly more coverage.
//!
//! # What it deliberately does NOT detect
//!
//! * **Non-SOL buys.** A USDC-denominated buy shows a token increase with no
//!   SOL decrease and is skipped. Tracking it would need per-quote accounting.
//! * **Transfers and airdrops.** Tokens arriving without SOL leaving are not a
//!   conviction signal — somebody sent them.
//! * **Sells.** Only increases count here.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use yellowstone_grpc_proto::prelude::SubscribeUpdateTransactionInfo;

/// Lamports per SOL.
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

/// Quote assets. A wallet "buying" one of these is moving cash, not taking a
/// position, so they are never the token side of a tracked buy.
const QUOTE_MINTS: &[&str] = &[
    crate::model::WSOL_MINT,
    crate::model::USDC_MINT,
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT
];

/// One wallet worth following.
#[derive(Debug, Clone, PartialEq)]
pub struct TrackedWallet {
    pub address: String,
    /// Display name, already sanitized for Telegram.
    pub name: String,
}

/// The tracker-export format (Axiom/Photon style). Only two fields are read;
/// the rest of the export (emoji, sounds, per-surface alert toggles) describes
/// a different tool's UI and is ignored.
#[derive(Debug, Deserialize)]
struct ExportedWallet {
    #[serde(rename = "trackedWalletAddress")]
    address: String,
    #[serde(default)]
    name: String,
}

/// Address -> wallet. Lookup is per transaction on a hot path, so it is a map.
#[derive(Debug, Clone, Default)]
pub struct WalletBook {
    by_address: HashMap<String, TrackedWallet>,
}

impl WalletBook {
    /// Parse a tracker export. Malformed entries are skipped rather than fatal:
    /// one bad row in a 700-entry list must not cost the other 699.
    pub fn from_export_json(json: &str) -> anyhow::Result<Self> {
        let raw: Vec<ExportedWallet> =
            serde_json::from_str(json).map_err(|e| anyhow::anyhow!("parsing wallet export: {e}"))?;

        let mut by_address = HashMap::with_capacity(raw.len());
        for w in raw {
            let addr = w.address.trim().to_string();
            // Base58 pubkeys are 32-44 chars. Anything else is not an address.
            if !(32..=44).contains(&addr.len()) {
                continue;
            }
            let name = sanitize_name(&w.name, &addr);
            by_address.insert(addr.clone(), TrackedWallet { address: addr, name });
        }
        Ok(Self { by_address })
    }

    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    pub fn get(&self, address: &str) -> Option<&TrackedWallet> {
        self.by_address.get(address)
    }

    /// Addresses for the gRPC `account_include` filter.
    pub fn addresses(&self) -> Vec<String> {
        self.by_address.keys().cloned().collect()
    }
}

/// Terms that must never reach a shared chat. Wallet names come from a
/// third-party export written by strangers, and they are rendered verbatim into
/// Telegram messages that land in a group.
///
/// A moderation list has to name what it blocks; that is what this is. Matching
/// is substring-on-lowercase, so a hit replaces the WHOLE name rather than
/// masking part of it — partial masking of a slur is still recognisably a slur.
const BLOCKED_TERMS: &[&str] = &[
    "nigg", "nigr", "negro", "faggot", "fag ", "tranny", "kike", "spic ", "chink",
    "retard", "rape", "pedo", "cunt",
];

/// Make a tracker-supplied name safe to render in Telegram HTML.
///
/// Three separate hazards, all of which must be handled:
///
/// 1. **Slurs** — the export contains them; they would post to a group chat.
///    A blocked name falls back to the shortened address.
/// 2. **HTML injection** — `<`/`&` in a name would corrupt or break the
///    message body, which is sent with `parse_mode=HTML`.
/// 3. **Layout** — newlines and control characters let a name forge extra
///    lines in an alert; length is capped so one name cannot dominate.
pub fn sanitize_name(raw: &str, address: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_lowercase();

    if trimmed.is_empty() || BLOCKED_TERMS.iter().any(|t| lower.contains(t)) {
        return short_address(address);
    }

    let cleaned: String = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .take(24)
        .collect();

    let escaped = cleaned
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    if escaped.trim().is_empty() {
        short_address(address)
    } else {
        escaped
    }
}

/// `5R4RJo…SpLfcW` — enough to identify, short enough to sit inline.
pub fn short_address(address: &str) -> String {
    if address.len() <= 12 {
        return address.to_string();
    }
    format!("{}…{}", &address[..6], &address[address.len() - 6..])
}

/// A tracked wallet buying a token.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrackedBuy {
    pub wallet: String,
    pub wallet_name: String,
    pub mint: String,
    /// Tokens gained (UI units).
    pub token_amount: f64,
    /// SOL that left the wallet, net of the token side.
    pub sol_spent: f64,
    pub signature: String,
    pub slot: u64,
}

/// Extract every tracked-wallet buy in one transaction.
///
/// `min_sol` filters out dust and fee-only movement: every signer's lamports
/// drop by the transaction fee, so a threshold of zero would report a "buy" for
/// any tracked wallet that merely signed something.
pub fn detect_buys(
    tx_info: &SubscribeUpdateTransactionInfo,
    book: &WalletBook,
    min_sol: f64,
    signature: &str,
    slot: u64,
) -> Vec<TrackedBuy> {
    let Some(meta) = tx_info.meta.as_ref() else {
        return Vec::new();
    };

    // (owner, mint) -> ui amount, before and after.
    let mut before: HashMap<(&str, &str), f64> = HashMap::new();
    for b in &meta.pre_token_balances {
        if let Some(amt) = b.ui_token_amount.as_ref() {
            before.insert((b.owner.as_str(), b.mint.as_str()), amt.ui_amount);
        }
    }

    // SOL deltas, keyed by owner. Computed lazily: most transactions touch no
    // tracked wallet at all and the key decode is pure waste for those.
    let mut sol_out: Option<HashMap<String, f64>> = None;

    let mut out = Vec::new();
    for b in &meta.post_token_balances {
        let Some(amt) = b.ui_token_amount.as_ref() else { continue };
        let owner = b.owner.as_str();
        let mint = b.mint.as_str();

        let Some(tracked) = book.get(owner) else { continue };
        if QUOTE_MINTS.contains(&mint) {
            continue;
        }

        // Absent from `pre` means the token account was created by this
        // transaction — the normal shape of a FIRST buy, and the case that
        // matters most. Treat missing as zero, not as unknown.
        let prev = before.get(&(owner, mint)).copied().unwrap_or(0.0);
        let gained = amt.ui_amount - prev;
        if gained <= 0.0 {
            continue;
        }

        let deltas = sol_out.get_or_insert_with(|| sol_deltas(tx_info, meta));
        let spent = deltas.get(owner).copied().unwrap_or(0.0);
        if spent < min_sol {
            continue;
        }

        out.push(TrackedBuy {
            wallet: tracked.address.clone(),
            wallet_name: tracked.name.clone(),
            mint: mint.to_string(),
            token_amount: gained,
            sol_spent: spent,
            signature: signature.to_string(),
            slot,
        });
    }
    out
}

/// Lamports each account LOST in this transaction, as SOL, keyed by address.
/// Negative movement (accounts that gained) is dropped — only spending matters.
fn sol_deltas(
    tx_info: &SubscribeUpdateTransactionInfo,
    meta: &yellowstone_grpc_proto::prelude::TransactionStatusMeta,
) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    let Some(tx) = tx_info.transaction.as_ref() else { return out };
    let Some(msg) = tx.message.as_ref() else { return out };

    for (i, key) in msg.account_keys.iter().enumerate() {
        let (Some(pre), Some(post)) = (meta.pre_balances.get(i), meta.post_balances.get(i)) else {
            continue;
        };
        if pre > post {
            let spent = (pre - post) as f64 / LAMPORTS_PER_SOL;
            out.insert(bs58::encode(key).into_string(), spent);
        }
    }
    out
}

/// Append one buy to the day-one log.
///
/// Deliberately unconditional and lossy-on-error: this file is the raw material
/// for scoring which wallets are worth following, and that data can only be
/// collected going forward. A write failure warns but must never interrupt
/// detection.
pub async fn append_buy(path: &str, buy: &TrackedBuy) {
    if let Err(e) = append_buy_inner(path, buy).await {
        tracing::warn!(error = %e, path, "failed to log tracked buy");
    }
}

async fn append_buy_inner(path: &str, buy: &TrackedBuy) -> anyhow::Result<()> {
    let mut value = serde_json::to_value(buy)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "observed_at".into(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );
    }
    let mut line = serde_json::to_string(&value)?;
    line.push('\n');

    use tokio::io::AsyncWriteExt;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
    }
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    f.write_all(line.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "5R4RJojpoKNwBcJNgVYGtwXdmhyEHWXGDBQqUnSpLfcW";

    #[test]
    fn parses_tracker_export() {
        let json = format!(
            r#"[{{"trackedWalletAddress":"{ADDR}","name":"Andy?","emoji":"🧄","groups":["Main"]}}]"#
        );
        let book = WalletBook::from_export_json(&json).unwrap();
        assert_eq!(book.len(), 1);
        assert_eq!(book.get(ADDR).unwrap().name, "Andy?");
    }

    #[test]
    fn skips_malformed_addresses_without_failing_the_batch() {
        let json = format!(
            r#"[{{"trackedWalletAddress":"short","name":"bad"}},
                {{"trackedWalletAddress":"{ADDR}","name":"good"}}]"#
        );
        let book = WalletBook::from_export_json(&json).unwrap();
        assert_eq!(book.len(), 1, "the valid row survives the invalid one");
    }

    /// The export really does contain slurs, and these names are rendered into
    /// a group chat. A blocked name must be replaced ENTIRELY.
    #[test]
    fn slurs_are_replaced_with_the_address() {
        let n = sanitize_name("Nigger Sniper Dev", ADDR);
        assert_eq!(n, short_address(ADDR));
        assert!(!n.to_lowercase().contains("nig"));

        assert_eq!(sanitize_name("Rape Mode", ADDR), short_address(ADDR));
        assert_eq!(sanitize_name("retard whale", ADDR), short_address(ADDR));
    }

    #[test]
    fn html_is_escaped_not_passed_through() {
        assert_eq!(sanitize_name("<b>bold</b>", ADDR), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(sanitize_name("A & B", ADDR), "A &amp; B");
    }

    /// A name carrying newlines could forge extra lines in an alert body.
    #[test]
    fn control_characters_and_length_are_contained() {
        assert_eq!(sanitize_name("evil\nInjected: line", ADDR), "evilInjected: line");
        assert_eq!(sanitize_name(&"x".repeat(200), ADDR).len(), 24);
    }

    #[test]
    fn empty_name_falls_back_to_address() {
        assert_eq!(sanitize_name("", ADDR), short_address(ADDR));
        assert_eq!(sanitize_name("   ", ADDR), short_address(ADDR));
    }

    #[test]
    fn short_address_is_recognisable() {
        assert_eq!(short_address(ADDR), "5R4RJo…SpLfcW");
        assert_eq!(short_address("tiny"), "tiny");
    }
}

#[cfg(test)]
mod real_list_tests {
    use super::*;

    /// Run the sanitizer over the operator's ACTUAL list, if present. The whole
    /// point of the filter is this file's contents; a unit test on invented
    /// names proves nothing about it.
    ///
    ///   WALLETS_JSON=tracked_wallets.json cargo test -- --ignored --nocapture real_list
    #[ignore = "needs the operator's wallet export"]
    #[test]
    fn real_list_has_no_blocked_names_after_sanitizing() {
        let path = std::env::var("WALLETS_JSON").unwrap_or_else(|_| "tracked_wallets.json".into());
        let raw = std::fs::read_to_string(&path).expect("read wallet export");
        let book = WalletBook::from_export_json(&raw).expect("parse");
        println!("loaded {} wallets from {path}", book.len());

        let mut redacted = 0;
        for (addr, w) in book.by_address.iter() {
            let lower = w.name.to_lowercase();
            for term in BLOCKED_TERMS {
                assert!(
                    !lower.contains(term),
                    "blocked term {term:?} survived sanitizing in {:?}",
                    w.name
                );
            }
            assert!(!w.name.contains('<'), "unescaped '<' in {:?}", w.name);
            assert!(!w.name.contains('\n'), "newline in {:?}", w.name);
            if w.name == short_address(addr) {
                redacted += 1;
            }
        }
        println!("{redacted} names replaced with their address");
    }
}
