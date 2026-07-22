//! Transaction submission — the irreversible step.
//!
//! Everything else in this crate can be verified before it costs anything:
//! layouts against real transactions, encoders byte-for-byte, quote math against
//! real swap outputs, whole transactions via simulation. **Submission cannot.**
//! There is no way to confirm a send works except by sending, so this module
//! compensates with runtime guards instead of pre-verification.
//!
//! # Guards
//!
//! 1. **Mandatory preflight.** Every send simulates first and refuses on
//!    failure. A sniper that skips preflight is faster and will happily burn
//!    fees on transactions that were never going to land; the default here is
//!    safety, and disabling it is explicit and logged.
//! 2. **Fresh blockhash per attempt.** A stale blockhash is the most common
//!    cause of a transaction silently never landing.
//! 3. **Signing requires `SigningCapability`**, which requires a loaded wallet.
//!    Dry-run holds none, so it cannot reach this module at all.
//! 4. **Confirmation is polled and reported honestly** — "submitted" is not
//!    "confirmed", and a timeout is reported as unknown, never as success.

use crate::config::RpcConfig;
use crate::jito::{BundleStatus, JitoClient};
use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_json::json;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::str::FromStr;
use std::time::Duration;
use tracing::{info, warn};

/// Outcome of a submission attempt. Deliberately distinguishes "we know it
/// landed" from "we stopped waiting" — conflating them is how a bot ends up
/// double-buying.
#[derive(Debug, Clone, PartialEq)]
pub enum Submission {
    /// Confirmed on-chain at the configured commitment.
    Confirmed { signature: String, slot: u64 },
    /// Accepted by the node but not observed confirming before the timeout.
    /// The transaction MAY still land. Do not retry blindly.
    Unconfirmed { signature: String },
    /// Preflight simulation failed; nothing was sent.
    RejectedByPreflight { reason: String },
    /// Submitted as a Jito bundle and observed on-chain.
    BundleLanded { bundle: String, slot: u64 },
    /// Bundle submitted but not observed landing. Nothing executed and NO tip
    /// was paid — the tip rides inside the bundle. Safe to retry, unlike an
    /// unconfirmed plain transaction.
    BundleNotLanded { bundle: String, last: String },
    /// The node refused the transaction outright.
    Failed { reason: String },
}

impl Submission {
    pub fn signature(&self) -> Option<&str> {
        match self {
            Submission::Confirmed { signature, .. } | Submission::Unconfirmed { signature } => {
                Some(signature)
            }
            _ => None,
        }
    }
    /// True only when the trade is known to have landed.
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            Submission::Confirmed { .. } | Submission::BundleLanded { .. }
        )
    }
    /// True when we know for certain nothing executed. A plain `Unconfirmed`
    /// does NOT qualify — that transaction may still land.
    pub fn definitely_did_not_execute(&self) -> bool {
        matches!(
            self,
            Submission::RejectedByPreflight { .. } | Submission::BundleNotLanded { .. }
        )
    }
}

pub struct Submitter {
    client: reqwest::Client,
    url: String,
    commitment: String,
    /// Simulate before sending. Leave on unless you have a specific reason.
    preflight: bool,
    confirm_timeout: Duration,
    poll_interval: Duration,
}

impl Submitter {
    pub fn new(rpc: &RpcConfig, preflight: bool, confirm_timeout_secs: u64) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .expect("reqwest client"),
            url: rpc.url.clone(),
            commitment: rpc.commitment.clone(),
            preflight,
            confirm_timeout: Duration::from_secs(confirm_timeout_secs.max(1)),
            poll_interval: Duration::from_millis(500),
        }
    }

    async fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: serde_json::Value = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{method} request"))?
            .json()
            .await
            .with_context(|| format!("{method} decode"))?;
        if let Some(e) = resp.get("error") {
            bail!("{method}: {e}");
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{method}: no result"))
    }

    /// Fetch a blockhash. Must be done immediately before signing — a stale one
    /// means the transaction expires and silently never lands.
    pub async fn latest_blockhash(&self) -> Result<Hash> {
        let r = self
            .rpc(
                "getLatestBlockhash",
                json!([{"commitment": self.commitment}]),
            )
            .await?;
        let s = r
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("malformed getLatestBlockhash response"))?;
        Hash::from_str(s).map_err(|e| anyhow::anyhow!("bad blockhash {s}: {e}"))
    }

    /// Build and sign. Separated from sending so the signed bytes can be
    /// inspected or simulated without any possibility of submission.
    pub fn sign(
        &self,
        ixs: &[Instruction],
        payer: &Pubkey,
        keypair: &Keypair,
        blockhash: Hash,
    ) -> Result<Transaction> {
        let msg = Message::new_with_blockhash(ixs, Some(payer), &blockhash);
        let mut tx = Transaction::new_unsigned(msg);
        tx.try_sign(&[keypair], blockhash)
            .context("signing transaction")?;
        Ok(tx)
    }

    pub fn encode(tx: &Transaction) -> Result<String> {
        let bytes = bincode::serialize(tx).context("serializing transaction")?;
        Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// Simulate; returns `Err` with the program logs when the transaction would
    /// fail. This is the last chance to catch a bad transaction for free.
    pub async fn preflight(&self, tx_b64: &str) -> Result<()> {
        let r = self
            .rpc(
                "simulateTransaction",
                json!([tx_b64, {
                    "encoding":"base64",
                    "sigVerify": false,
                    "replaceRecentBlockhash": true,
                    "commitment": self.commitment,
                }]),
            )
            .await?;
        let value = r.get("value").cloned().unwrap_or(serde_json::Value::Null);
        let err = value.get("err").cloned().unwrap_or(serde_json::Value::Null);
        if !err.is_null() {
            let logs = value
                .get("logs")
                .and_then(|l| l.as_array())
                .map(|a| {
                    a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" | ")
                })
                .unwrap_or_default();
            bail!("preflight failed: {err} :: {logs}");
        }
        Ok(())
    }

    /// Sign, preflight, send, and poll for confirmation.
    ///
    /// THIS SPENDS REAL MONEY. It is only reachable with a loaded wallet.
    pub async fn send(
        &self,
        ixs: &[Instruction],
        payer: &Pubkey,
        keypair: &Keypair,
    ) -> Result<Submission> {
        let blockhash = self.latest_blockhash().await?;
        let tx = self.sign(ixs, payer, keypair, blockhash)?;
        let b64 = Self::encode(&tx)?;

        if self.preflight {
            if let Err(e) = self.preflight(&b64).await {
                warn!(error = %e, "preflight rejected; not sending");
                return Ok(Submission::RejectedByPreflight { reason: e.to_string() });
            }
        } else {
            warn!("preflight DISABLED — sending unsimulated transaction");
        }

        // `skipPreflight: true` because we already simulated (or deliberately
        // chose not to); letting the node redo it only adds latency.
        let sent = self
            .rpc(
                "sendTransaction",
                json!([b64, {
                    "encoding":"base64",
                    "skipPreflight": true,
                    "maxRetries": 3,
                }]),
            )
            .await;

        let signature = match sent {
            Ok(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None => return Ok(Submission::Failed { reason: "no signature returned".into() }),
            },
            Err(e) => return Ok(Submission::Failed { reason: e.to_string() }),
        };
        info!(%signature, "transaction submitted");

        self.confirm(signature).await
    }

    /// Sign, simulate, then submit as an atomic Jito bundle.
    ///
    /// Jito performs NO preflight of its own, so the normal RPC simulation is
    /// kept as a mandatory gate — a malformed transaction would otherwise be
    /// discovered only by never landing.
    pub async fn send_bundle(
        &self,
        ixs: &[Instruction],
        payer: &Pubkey,
        keypair: &Keypair,
        jito: &JitoClient,
        timeout: Duration,
    ) -> Result<Submission> {
        // Tip rides inside the bundle: unlanded bundles cost nothing.
        let mut all = ixs.to_vec();
        all.push(jito.tip_instruction(payer)?);

        let blockhash = self.latest_blockhash().await?;
        let tx = self.sign(&all, payer, keypair, blockhash)?;
        let b64 = Self::encode(&tx)?;

        if self.preflight {
            if let Err(e) = self.preflight(&b64).await {
                warn!(error = %e, "preflight rejected; not bundling");
                return Ok(Submission::RejectedByPreflight { reason: e.to_string() });
            }
        } else {
            warn!("preflight DISABLED — bundling an unsimulated transaction");
        }

        let bundle = match jito.send_bundle(&[b64]).await {
            Ok(id) => id,
            Err(e) => return Ok(Submission::Failed { reason: e.to_string() }),
        };

        match jito.await_bundle(&bundle, timeout).await {
            BundleStatus::Landed { slot } => {
                info!(%bundle, slot, "bundle landed");
                Ok(Submission::BundleLanded { bundle, slot })
            }
            other => {
                warn!(%bundle, ?other, "bundle did not land; nothing executed, no tip paid");
                Ok(Submission::BundleNotLanded { bundle, last: format!("{other:?}") })
            }
        }
    }

    /// Poll until confirmed or the timeout elapses.
    ///
    /// A timeout yields `Unconfirmed`, never `Confirmed`. The transaction may
    /// still land later, so callers must not treat this as a failure and retry.
    pub async fn confirm(&self, signature: String) -> Result<Submission> {
        let deadline = tokio::time::Instant::now() + self.confirm_timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                warn!(%signature, "confirmation timed out; transaction may still land");
                return Ok(Submission::Unconfirmed { signature });
            }
            let r = self
                .rpc(
                    "getSignatureStatuses",
                    json!([[signature], {"searchTransactionHistory": false}]),
                )
                .await;
            if let Ok(v) = r {
                if let Some(st) = v.get("value").and_then(|v| v.get(0)) {
                    if !st.is_null() {
                        if let Some(e) = st.get("err") {
                            if !e.is_null() {
                                return Ok(Submission::Failed {
                                    reason: format!("transaction failed on-chain: {e}"),
                                });
                            }
                        }
                        let confirmed = st
                            .get("confirmationStatus")
                            .and_then(|c| c.as_str())
                            .map(|c| c == "confirmed" || c == "finalized")
                            .unwrap_or(false);
                        if confirmed {
                            let slot = st.get("slot").and_then(|s| s.as_u64()).unwrap_or(0);
                            return Ok(Submission::Confirmed { signature, slot });
                        }
                    }
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct blockhash per call, so signature-difference tests are meaningful.
    fn some_hash() -> Hash {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(1);
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&N.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        Hash::new_from_array(b)
    }

    fn dummy_ix(payer: &Pubkey) -> Instruction {
        solana_system_interface::instruction::transfer(payer, &Pubkey::new_unique(), 1)
    }

    /// A signed transaction must verify against its own signature. This is the
    /// one part of submission verifiable offline, so it is worth asserting.
    #[test]
    fn signed_transaction_verifies() {
        let kp = Keypair::new();
        let payer = kp.pubkey();
        let s = Submitter::new(&RpcConfig::default(), true, 5);
        let tx = s.sign(&[dummy_ix(&payer)], &payer, &kp, some_hash()).unwrap();

        assert_eq!(tx.signatures.len(), 1);
        assert!(tx.verify().is_ok(), "signature must verify");
        assert!(!tx.signatures[0].to_string().is_empty());
    }

    /// Signing with the wrong key must not produce a valid transaction.
    #[test]
    fn wrong_signer_is_rejected() {
        let payer = Keypair::new();
        let other = Keypair::new();
        let s = Submitter::new(&RpcConfig::default(), true, 5);
        // `other` is not the payer, so it cannot sign for it.
        let err = s.sign(
            &[dummy_ix(&payer.pubkey())],
            &payer.pubkey(),
            &other,
            some_hash(),
        );
        assert!(err.is_err(), "signing with a non-payer key must fail");
    }

    #[test]
    fn encoded_transaction_round_trips() {
        let kp = Keypair::new();
        let payer = kp.pubkey();
        let s = Submitter::new(&RpcConfig::default(), true, 5);
        let tx = s.sign(&[dummy_ix(&payer)], &payer, &kp, some_hash()).unwrap();
        let b64 = Submitter::encode(&tx).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        let back: Transaction = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, tx);
    }

    /// "Submitted" must never read as "confirmed".
    #[test]
    fn unconfirmed_is_not_success() {
        let u = Submission::Unconfirmed { signature: "sig".into() };
        assert!(!u.is_confirmed());
        assert_eq!(u.signature(), Some("sig"));

        let c = Submission::Confirmed { signature: "sig".into(), slot: 1 };
        assert!(c.is_confirmed());

        let r = Submission::RejectedByPreflight { reason: "boom".into() };
        assert!(!r.is_confirmed());
        assert_eq!(r.signature(), None, "nothing was sent, so there is no signature");
    }

    /// A blockhash must be signed over: two different blockhashes must yield
    /// different signatures, or replay protection is broken.
    #[test]
    fn blockhash_is_covered_by_the_signature() {
        let kp = Keypair::new();
        let payer = kp.pubkey();
        let s = Submitter::new(&RpcConfig::default(), true, 5);
        let ix = dummy_ix(&payer);
        let a = s.sign(std::slice::from_ref(&ix), &payer, &kp, some_hash()).unwrap();
        let b = s.sign(&[ix], &payer, &kp, some_hash()).unwrap();
        assert_ne!(a.signatures[0], b.signatures[0]);
    }
}
