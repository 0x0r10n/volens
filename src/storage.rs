//! Persistence of detected pools.
//!
//! Two backends:
//!   * `jsonl`  — append one JSON object per line (always available, no C deps).
//!   * `sqlite` — insert into a `pools` table (behind the `sqlite` feature).
//!   * `none`   — disabled.
//!
//! SQLite is feature-gated because the bundled build needs a C compiler; the
//! JSONL backend keeps a zero-friction default.

use crate::config::StorageConfig;
use crate::model::PoolEvent;
use anyhow::{Context, Result};
use tracing::warn;

pub enum Storage {
    Jsonl { path: String },
    #[cfg(feature = "sqlite")]
    Sqlite { db: std::sync::Mutex<rusqlite::Connection> },
    Null,
}

impl Storage {
    pub fn from_config(cfg: &StorageConfig) -> Result<Self> {
        match cfg.backend.as_str() {
            "jsonl" => Ok(Storage::Jsonl { path: cfg.path.clone() }),
            "none" => Ok(Storage::Null),
            #[cfg(feature = "sqlite")]
            "sqlite" => {
                if let Some(parent) = std::path::Path::new(&cfg.path).parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).ok();
                    }
                }
                let conn = rusqlite::Connection::open(&cfg.path)
                    .with_context(|| format!("opening sqlite db {}", cfg.path))?;
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS pools (
                        pool            TEXT PRIMARY KEY,
                        dex             TEXT NOT NULL,
                        base_mint       TEXT NOT NULL,
                        quote_mint      TEXT NOT NULL,
                        new_token_mint  TEXT,
                        quote_asset     TEXT,
                        signature       TEXT NOT NULL,
                        slot            INTEGER NOT NULL,
                        detected_at     TEXT NOT NULL,
                        quote_liquidity REAL,
                        record          TEXT NOT NULL DEFAULT 'detected',
                        updated_at      TEXT
                    );",
                )
                .context("creating pools table")?;
                Ok(Storage::Sqlite { db: std::sync::Mutex::new(conn) })
            }
            #[cfg(not(feature = "sqlite"))]
            "sqlite" => anyhow::bail!(
                "storage backend 'sqlite' requires building with --features sqlite"
            ),
            other => anyhow::bail!("unknown storage backend '{other}' (jsonl|sqlite|none)"),
        }
    }

    /// Persist a detected pool. Errors are logged and swallowed so a storage
    /// hiccup never takes down the detector.
    pub async fn record(&self, ev: &PoolEvent) {
        if let Err(e) = self.record_inner(ev, "detected").await {
            warn!(error = %e, pool = %ev.pool, "failed to persist pool");
        }
    }

    /// Persist a delayed follow-up observation (LP burned, liquidity pulled...)
    /// as its own record, so the log keeps the pool's lifecycle rather than only
    /// its launch moment.
    pub async fn record_followup(&self, ev: &PoolEvent, verdict: &str) {
        if let Err(e) = self.record_inner(ev, verdict).await {
            warn!(error = %e, pool = %ev.pool, "failed to persist follow-up");
        }
    }

    async fn record_inner(&self, ev: &PoolEvent, kind: &str) -> Result<()> {
        match self {
            Storage::Null => Ok(()),
            Storage::Jsonl { path } => {
                // Tag each line so detections and follow-ups are distinguishable.
                let mut value = serde_json::to_value(ev)?;
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("record".into(), serde_json::Value::String(kind.into()));
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
                    .await
                    .with_context(|| format!("opening {path}"))?;
                f.write_all(line.as_bytes()).await?;
                Ok(())
            }
            #[cfg(feature = "sqlite")]
            Storage::Sqlite { db } => {
                let conn = db.lock().unwrap();
                // Upsert rather than INSERT OR IGNORE: a follow-up arrives for a
                // pool that already exists, and must update its verdict instead
                // of being silently dropped.
                conn.execute(
                    "INSERT INTO pools
                       (pool, dex, base_mint, quote_mint, new_token_mint, quote_asset,
                        signature, slot, detected_at, quote_liquidity, record, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(pool) DO UPDATE SET
                        quote_liquidity = excluded.quote_liquidity,
                        record          = excluded.record,
                        updated_at      = excluded.updated_at",
                    rusqlite::params![
                        ev.pool,
                        format!("{:?}", ev.dex),
                        ev.base_mint,
                        ev.quote_mint,
                        ev.new_token_mint,
                        ev.quote_asset,
                        ev.signature,
                        ev.slot as i64,
                        ev.detected_at.to_rfc3339(),
                        ev.quote_liquidity,
                        kind,
                        chrono::Utc::now().to_rfc3339(),
                    ],
                )?;
                Ok(())
            }
        }
    }
}
