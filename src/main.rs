//! volens — real-time Solana new liquidity pool detector.
//!
//! Streams transactions on Raydium AMM v4, Raydium CPMM, and PumpSwap via a
//! Yellowstone gRPC endpoint, detects pool-creation instructions the moment
//! tradable liquidity is added, filters to quote-asset pairs, and dispatches
//! structured logs + Telegram alerts + persistence.

mod alerts;
mod bot;
mod config;
mod dedup;
mod detector;
#[cfg(feature = "sniper")]
mod execute;
#[cfg(feature = "sniper")]
mod jito;
mod metrics;
mod model;
mod parser;
#[cfg(feature = "sniper")]
mod positions;
#[cfg(feature = "sniper")]
mod quote;
mod rpc;
#[cfg(feature = "sniper")]
mod sniper;
mod storage;
#[cfg(feature = "sniper")]
mod submit;
mod swap;
#[cfg(feature = "sniper")]
mod tx;
#[cfg(feature = "sniper")]
mod walletstore;
mod watcher;
mod ws;

use crate::alerts::Alerter;
use crate::config::Config;
use crate::detector::Detector;
use crate::storage::Storage;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    // Subcommands are handled before the normal detector path. Keep this list
    // short — volens is a long-running daemon, not a CLI toolkit.
    let arg1 = std::env::args().nth(1);
    if let Some(cmd) = arg1.as_deref() {
        match cmd {
            "gen-wallet" | "new-wallet" => return gen_wallet(),
            "help" | "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            _ => {}
        }
    }

    // Config path: first CLI arg, else ./config.toml if present.
    let cfg_path = arg1
        .map(PathBuf::from)
        .or_else(|| {
            let p = PathBuf::from("config.toml");
            p.exists().then_some(p)
        });

    #[allow(unused_mut)]
    let mut cfg = Config::load(cfg_path.as_deref())?;
    init_tracing(&cfg.log.level);

    info!(version = env!("CARGO_PKG_VERSION"), "volens starting");
    info!(targets = %detector::describe_targets(&cfg), "watching programs");

    // The active wallet from the store drives which key is used: its file
    // becomes `keypair_path` when armed, and its address becomes `simulate_as`
    // for dry-run rehearsal. Resolved here, before the sniper is built, so the
    // whole run uses one consistent identity. Selecting a wallet over Telegram
    // only changes this at the NEXT startup — never mid-session.
    #[cfg(feature = "sniper")]
    let store = std::sync::Arc::new(walletstore::WalletStore::new(&cfg.sniper.wallet_dir));
    #[cfg(feature = "sniper")]
    if let (Some(name), Some(path), Some(pk)) =
        (store.active(), store.active_path(), store.active_pubkey())
    {
        if cfg.sniper.armed {
            cfg.sniper.keypair_path = path.to_string_lossy().into_owned();
        }
        cfg.sniper.simulate_as = pk.to_string();
        info!(active_wallet = %name, pubkey = %pk, "active wallet selected from store");
    }

    let cfg = Arc::new(cfg);
    let alerter = Arc::new(Alerter::new(&cfg.alerts));
    let storage = Arc::new(Storage::from_config(&cfg.storage)?);
    let detector = Detector::new(cfg.clone(), alerter, storage)?;

    // Graceful shutdown: broadcast `true` on Ctrl-C / SIGTERM.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_handler(shutdown_tx);

    // Inbound command bot. Constructed before the detector runs so a bad
    // allowlist is a startup failure, not a surprise an hour in.
    if cfg.alerts.commands_enabled {
        let bot = bot::Bot::new(
            cfg.alerts.telegram_bot_token.clone(),
            &cfg.alerts.authorized_chat_ids,
            detector.metrics(),
            cfg.sniper.kill_switch_file.clone(),
        )?
        .with_rpc(detector.rpc());
        #[cfg(feature = "sniper")]
        let bot = bot
            .with_wallet_store(store.clone())
            .with_audit_log(cfg.sniper.audit_log.clone())
            .with_sniper(detector.sniper());
        info!(
            authorized_chats = bot.authorized_count(),
            "telegram commands enabled (/status /metrics /halt)"
        );
        tokio::spawn(bot.run(shutdown_rx.clone()));
    }

    if let Err(e) = detector.run(shutdown_rx).await {
        error!(error = %format!("{e:#}"), "detector exited with error");
        return Err(e);
    }

    info!("volens stopped cleanly");
    Ok(())
}

fn init_tracing(level: &str) {
    // RUST_LOG wins if set; otherwise use the configured level for our crate.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("volens={level},warn"))
    });
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();
}

fn spawn_signal_handler(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => info!("received Ctrl-C"),
                _ = term.recv() => info!("received SIGTERM"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            info!("received Ctrl-C");
        }
        let _ = shutdown_tx.send(true);
    });
}

fn print_usage() {
    eprintln!(
        "volens — Solana new-liquidity-pool detector\n\n\
         USAGE:\n  \
           volens [CONFIG_PATH]      run the detector (default: ./config.toml)\n  \
           volens gen-wallet [PATH]  generate a fresh test keypair (default: ./test-wallet.json)\n  \
           volens help               show this message\n"
    );
}

/// Generate a fresh keypair for a supervised test, writing it locally.
///
/// The key is created on this machine and written to a 0600 file; only the
/// PUBLIC address is printed. Nothing transmits the secret anywhere. This is the
/// safe way to stand up a throwaway trading wallet: fund the printed address
/// with a small amount, point `keypair_path` at the file, and arm.
#[cfg(feature = "sniper")]
fn gen_wallet() -> Result<()> {
    let path = std::env::args().nth(2).unwrap_or_else(|| "test-wallet.json".to_string());

    let pubkey = tx::Wallet::generate(&path)?;

    // Plain println, not tracing: this is interactive CLI output the operator
    // needs to read and act on, not a log line.
    println!("\n✅ New test wallet created.\n");
    println!("   Address : {pubkey}");
    println!("   Keyfile : {path}  (permissions 0600 — keep it private)\n");
    println!("Next steps:");
    println!("  1. Fund this address with a SMALL amount of SOL (e.g. 0.05).");
    println!("     This wallet's key lives in the file above, on THIS machine.");
    println!("     Treat anything you put in as already spent.");
    println!("  2. In config.toml [sniper], set:");
    println!("       keypair_path = \"{path}\"");
    println!("       simulate_as  = \"{pubkey}\"");
    println!("  3. Dry-run first and confirm a `would-succeed`, THEN arm.");
    println!("     See the First Armed Trade Checklist in the README.\n");
    Ok(())
}

/// Without the `sniper` feature the Solana key crates are not compiled in, so
/// there is no way to make a keypair. Fail loudly with the fix rather than
/// pretending to succeed.
#[cfg(not(feature = "sniper"))]
fn gen_wallet() -> Result<()> {
    anyhow::bail!(
        "gen-wallet needs the `sniper` feature (it uses the Solana key crates). \
         Rebuild with:  cargo run --features sniper -- gen-wallet"
    );
}
