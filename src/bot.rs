//! Inbound Telegram command handling.
//!
//! Outbound alerts live in `alerts.rs`. This module is the other direction:
//! a long-poll loop over `getUpdates` that lets you query state and halt
//! execution from your phone.
//!
//! # Security model
//!
//! Accepting commands turns the bot into a control surface, so the rules are
//! deliberately narrow:
//!
//! * **Allowlist enforced per update.** Telegram has no session to authenticate
//!   once — every update carries its own `chat.id`, so every update is checked.
//!   An empty allowlist is a startup error, never "allow all".
//! * **Unauthorized senders get silence.** Not an error reply. Replying confirms
//!   the bot exists and that the token is live, which is useful to a prober and
//!   useless to you. The attempt is logged locally instead.
//! * **Commands can pause/unpause and tune — but never ARM or move funds.**
//!   `/halt` and `/resume` toggle the kill switch. `/slippage` and
//!   `/min-liquidity` are tighten-only; `/size` can raise the trade size up to
//!   `max_trade_size_sol` (unbounded when that ceiling is 0), so an authorized
//!   chat can increase spend. What no command can do: arm a dry-run
//!   bot, or withdraw/transfer funds — there is no such primitive. So the worst
//!   a compromised token achieves is un-pausing an *already host-armed* bot,
//!   bounded by the daily caps, with no exfiltration path. Going live in the
//!   first place always requires host access.
//! * **Resume is NOT arm.** Clearing the kill switch re-enables an already-armed
//!   bot; it can never turn a dry-run bot live. The button flow confirms first,
//!   so it is a deliberate two-tap, while halt stays a one-tap fast stop.
//! * **Halt is a file, not a flag.** `Sniper::kill_switch_engaged` stats the
//!   file before each trade, so writing it takes effect immediately without a
//!   restart, needs no shared mutable state, and survives a crash — a halted bot
//!   stays halted across a reboot.

use crate::metrics::Metrics;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Long-poll timeout. Telegram holds the request open this long when idle, so
/// this is a near-free way to stay responsive without hammering the API.
const LONG_POLL_SECS: u64 = 30;

/// Must exceed `LONG_POLL_SECS` or every idle poll aborts as a client timeout.
const HTTP_TIMEOUT_SECS: u64 = LONG_POLL_SECS + 15;

/// Backoff bounds for API errors (network down, Telegram 5xx, rate limit).
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

pub struct Bot {
    client: reqwest::Client,
    bot_token: String,
    /// Chat IDs permitted to issue commands. Never empty — see `new`.
    allowed: HashSet<i64>,
    metrics: Arc<Metrics>,
    kill_switch_file: PathBuf,
    started: Instant,
    /// Highest update id seen; the offset that acknowledges it to Telegram.
    offset: i64,
    /// For `/balance`. Absent means the command reports "not configured"
    /// rather than a misleading zero.
    rpc: Option<Arc<crate::rpc::RpcClient>>,
    /// Local wallet store for `/new-wallet`, `/wallets`, `/use`. `None` disables
    /// those commands (reports not configured).
    #[cfg(feature = "sniper")]
    store: Option<Arc<crate::walletstore::WalletStore>>,
    /// Sniper audit-log path, for `/positions` cost basis. Empty = untracked.
    #[cfg(feature = "sniper")]
    audit_log: String,
    #[cfg(feature = "sniper")]
    sniper: Option<Arc<crate::sniper::Sniper>>,
}

impl Bot {
    /// Build a command bot.
    ///
    /// Fails if the allowlist is empty. An unrestricted command bot with a
    /// `/halt` would let anyone who discovers the token stop your trading, so
    /// this refuses to start rather than defaulting to open.
    pub fn new(
        bot_token: String,
        allowed_chat_ids: &[String],
        metrics: Arc<Metrics>,
        kill_switch_file: impl Into<PathBuf>,
    ) -> Result<Self> {
        if bot_token.is_empty() {
            anyhow::bail!("telegram command bot enabled but no bot token set");
        }

        let mut allowed = HashSet::new();
        for raw in allowed_chat_ids {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            let id: i64 = s
                .parse()
                .with_context(|| format!("invalid chat id {s:?} — expected an integer"))?;
            allowed.insert(id);
        }
        if allowed.is_empty() {
            anyhow::bail!(
                "telegram command bot enabled but authorized_chat_ids is empty — \
                 refusing to accept commands from anyone. Set [alerts].authorized_chat_ids \
                 (or TELEGRAM_AUTHORIZED_CHAT_IDS) to your own chat id."
            );
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .context("building telegram http client")?;

        Ok(Self {
            client,
            bot_token,
            allowed,
            metrics,
            kill_switch_file: kill_switch_file.into(),
            started: Instant::now(),
            offset: 0,
            rpc: None,
            #[cfg(feature = "sniper")]
            store: None,
            #[cfg(feature = "sniper")]
            audit_log: String::new(),
            #[cfg(feature = "sniper")]
            sniper: None,
        })
    }

    /// Path to the sniper audit log, enabling `/positions` cost basis + PnL.
    #[cfg(feature = "sniper")]
    pub fn with_audit_log(mut self, path: impl Into<String>) -> Self {
        self.audit_log = path.into();
        self
    }

    /// Attach an RPC client, enabling `/balance`. Without it the command
    /// reports that no RPC is configured.
    pub fn with_rpc(mut self, rpc: Arc<crate::rpc::RpcClient>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Attach the wallet store, enabling `/new-wallet`, `/wallets`, `/use`.
    #[cfg(feature = "sniper")]
    pub fn with_wallet_store(mut self, store: Arc<crate::walletstore::WalletStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Attach the sniper so `/balance` knows which wallet to report on.
    #[cfg(feature = "sniper")]
    pub fn with_sniper(mut self, sniper: Arc<crate::sniper::Sniper>) -> Self {
        self.sniper = Some(sniper);
        self
    }

    pub fn authorized_count(&self) -> usize {
        self.allowed.len()
    }

    /// Poll for commands until `shutdown` flips true.
    ///
    /// Never returns an error for transient API problems — it backs off and
    /// retries. A dead command channel must not take the detector down with it.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            authorized = self.allowed.len(),
            "telegram command bot listening"
        );

        // Register the "/" menu so commands are always visible, not just in an
        // old message. Best-effort.
        self.register_commands().await;

        // Discard anything queued before startup. Otherwise a `/halt` sent
        // hours ago, or replayed from a previous run, executes on boot.
        if let Err(e) = self.drain_backlog().await {
            warn!(error = %e, "could not drain telegram backlog; starting from live updates");
        }

        let mut backoff = BACKOFF_MIN;

        loop {
            if *shutdown.borrow() {
                break;
            }

            let poll = tokio::select! {
                r = self.poll_once() => r,
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                    continue;
                }
            };

            match poll {
                Ok(updates) => {
                    backoff = BACKOFF_MIN;
                    for u in updates {
                        self.handle_update(u).await;
                    }
                }
                Err(e) => {
                    warn!(error = %e, backoff_secs = backoff.as_secs(), "telegram poll failed");
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { break; }
                        }
                    }
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
        }

        info!("telegram command bot stopped");
    }

    /// Acknowledge pending updates without acting on them, so stale commands
    /// queued while we were down don't fire at startup.
    async fn drain_backlog(&mut self) -> Result<()> {
        let updates = self.get_updates(0).await?;
        if let Some(max) = updates.iter().map(|u| u.update_id).max() {
            self.offset = max + 1;
            debug!(count = updates.len(), "discarded telegram backlog");
        }
        Ok(())
    }

    async fn poll_once(&mut self) -> Result<Vec<Update>> {
        let updates = self.get_updates(LONG_POLL_SECS).await?;
        if let Some(max) = updates.iter().map(|u| u.update_id).max() {
            self.offset = max + 1;
        }
        Ok(updates)
    }

    async fn get_updates(&self, timeout_secs: u64) -> Result<Vec<Update>> {
        let url = format!("https://api.telegram.org/bot{}/getUpdates", self.bot_token);
        let body = serde_json::json!({
            "offset": self.offset,
            "timeout": timeout_secs,
            // Messages (typed commands) and callback_query (inline-button taps).
            "allowed_updates": ["message", "callback_query"],
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("getUpdates request")?;

        let status = resp.status();
        let text = resp.text().await.context("reading getUpdates body")?;
        if !status.is_success() {
            // Deliberately not logging the body at error level: Telegram echoes
            // request context on some failures.
            anyhow::bail!("getUpdates returned {status}");
        }

        let parsed: UpdatesResponse =
            serde_json::from_str(&text).context("parsing getUpdates response")?;
        if !parsed.ok {
            anyhow::bail!("getUpdates: telegram reported not-ok");
        }
        Ok(parsed.result)
    }

    async fn handle_update(&self, update: Update) {
        if let Some(cb) = update.callback_query {
            self.handle_callback(cb).await;
        } else if let Some(msg) = update.message {
            self.handle_message(msg).await;
        }
    }

    /// A typed command message. Authorized by chat id.
    async fn handle_message(&self, msg: Message) {
        let Some(text) = msg.text.as_deref() else { return };
        let chat_id = msg.chat.id;

        // Authorization first, before parsing or acting on anything.
        if !self.allowed.contains(&chat_id) {
            // Log the id so a legitimate user who got the config wrong can find
            // theirs; stay silent to the sender.
            warn!(
                chat_id,
                command = truncate(text, 32),
                "ignoring telegram command from unauthorized chat"
            );
            return;
        }

        let Some(cmd) = Command::parse(text) else {
            return;
        };

        info!(chat_id, command = cmd.name(), "telegram command");
        let reply = self.execute(cmd).await;
        self.reply(chat_id, reply).await;
    }

    /// An inline-button tap. Authorized by the tapping USER's id (in a group,
    /// this is the individual who tapped, not the group as a whole — stricter
    /// and correct). The callback is always answered so the button stops
    /// spinning, even when ignored.
    ///
    /// The tapped message is EDITED IN PLACE rather than replied to, so the menu
    /// navigates within one message instead of stacking new ones on every tap.
    async fn handle_callback(&self, cb: CallbackQuery) {
        let from = cb.from.id;
        if !self.allowed.contains(&from) {
            warn!(user_id = from, "ignoring inline-button tap from unauthorized user");
            self.answer_callback(&cb.id, Some("Not authorized")).await;
            return;
        }
        self.answer_callback(&cb.id, None).await;

        let Some(data) = cb.data.as_deref() else { return };
        let Some(msg) = cb.message.as_ref() else { return };
        info!(user_id = from, action = data, "telegram button");

        let Some((text, keyboard)) = self.screen_for(data).await else {
            return;
        };
        self.edit_message(msg.chat.id, msg.message_id, text, keyboard).await;
    }

    /// Resolve a callback payload into the next screen: `(text, keyboard)`.
    ///
    /// Two payload kinds:
    /// * `nav:<menu>` — pure navigation. Swaps the keyboard to that menu's
    ///   buttons with a short title; runs no command.
    /// * `cmd:<name>` — executes the action and shows its result, with a Back
    ///   button to the menu it belongs to.
    async fn screen_for(&self, data: &str) -> Option<(String, serde_json::Value)> {
        // Per-wallet "set active" taps: `use:<name>`. Re-renders the list so the
        // new ✅ active marker is visible immediately.
        if let Some(name) = data.strip_prefix("use:") {
            self.render_use(Some(name));
            return Some((self.render_wallets().await, self.wallets_keyboard()));
        }
        // The wallets LIST: text + a "set active" button per wallet.
        if data == "cmd:wallets" {
            return Some((self.render_wallets().await, self.wallets_keyboard()));
        }
        if let Some(menu) = data.strip_prefix("nav:") {
            return Some(self.menu_screen(menu).await);
        }
        if let Some(cmd) = Command::from_callback(data) {
            let group = back_group(data);
            let text = self.execute(cmd).await;
            return Some((text, back_keyboard(group)));
        }
        None
    }

    /// The (title, keyboard) for a navigation menu.
    async fn menu_screen(&self, menu: &str) -> (String, serde_json::Value) {
        match menu {
            "wallet" => (
                "👛 <b>Wallet</b> — pick an action:".to_string(),
                Self::wallet_menu(),
            ),
            // Resume confirmation: a deliberate two-tap, because clearing the
            // kill switch re-enables live spending (bounded by caps; never arms).
            "resume" => (
                "▶️ <b>Resume trading?</b>\n\
                 This clears the kill switch. Trading resumes only if the bot was \
                 armed on the host — it never arms a dry-run bot.".to_string(),
                serde_json::json!({
                    "inline_keyboard": [[
                        {"text": "✅ Yes, resume", "callback_data": "cmd:resume"},
                        {"text": "◀️ Cancel", "callback_data": "nav:main"},
                    ]]
                }),
            ),
            // "main" and anything unrecognized fall back to the top menu.
            _ => (
                "<b>volens</b> — choose an action, or type <b>/</b> for all commands.".to_string(),
                self.main_menu(),
            ),
        }
    }

    /// Run a parsed command and produce its reply text. Shared by typed
    /// commands and button taps.
    async fn execute(&self, cmd: Command) -> String {
        match cmd {
            Command::Status => self.render_status(),
            Command::Metrics => self.render_metrics(),
            Command::Halt => self.do_halt(),
            Command::Resume => self.do_resume(),
            Command::Balance => self.render_balance().await,
            Command::Positions => self.render_positions().await,
            Command::Settings => self.render_settings(),
            Command::NewWallet(name) => self.render_new_wallet(name.as_deref()),
            Command::Wallets => self.render_wallets().await,
            Command::Use(name) => self.render_use(name.as_deref()),
            Command::SetSize(arg) => self.render_set(Tunable::Size, arg.as_deref()),
            Command::SetSlippage(arg) => self.render_set(Tunable::Slippage, arg.as_deref()),
            Command::SetMinLiquidity(arg) => self.render_set(Tunable::MinLiquidity, arg.as_deref()),
            Command::Help => Self::render_help(),
        }
    }

    fn render_status(&self) -> String {
        let s = self.metrics.snapshot();
        let halted = self.halt_engaged();
        let state = if halted {
            "🛑 <b>HALTED</b> (kill switch engaged)"
        } else {
            "🟢 running"
        };
        format!(
            "<b>volens status</b>\n\
             {state}\n\
             <b>Uptime:</b> {uptime}\n\
             <b>Detected:</b> {detected}\n\
             <b>Tx seen:</b> {tx_seen}",
            state = state,
            uptime = format_uptime(self.started.elapsed()),
            detected = s.detected,
            tx_seen = s.tx_seen,
        )
    }

    fn render_metrics(&self) -> String {
        let s = self.metrics.snapshot();
        format!(
            "<b>volens metrics</b>\n\
             <code>tx_seen        {tx_seen}\n\
             parsed         {parsed}\n\
             filtered_out   {filtered_out}\n\
             duplicates     {duplicates}\n\
             low_liquidity  {low_liquidity}\n\
             unsafe_mint    {unsafe_mint}\n\
             detected       {detected}\n\
             volume_spike   {volume_confirmed}\n\
             rug_detected   {rug_detected}\n\
             lp_burned      {lp_burned}</code>",
            tx_seen = s.tx_seen,
            parsed = s.parsed,
            filtered_out = s.filtered_out,
            duplicates = s.duplicates,
            low_liquidity = s.low_liquidity,
            unsafe_mint = s.unsafe_mint,
            detected = s.detected,
            rug_detected = s.rug_detected,
            lp_burned = s.lp_burned,
            volume_confirmed = s.volume_confirmed,
        )
    }

    /// Report the trading wallet's balance.
    ///
    /// Read-only, but not consequence-free: this reveals financial state to
    /// everyone in the allowlist. In a group chat that is every member.
    ///
    /// Three states are reported distinctly, and conflating them would mislead:
    /// no wallet configured, wallet configured but unreadable, and a real
    /// balance. An unreadable balance must never render as 0.
    async fn render_balance(&self) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            return "⚪ <b>No trading wallet</b>\n\
                    This build has no execution support (built without the \
                    <code>sniper</code> feature), so there is no wallet to report."
                .to_string();
        }

        #[cfg(feature = "sniper")]
        {
            use crate::sniper::WalletRole;

            let Some(sniper) = &self.sniper else {
                return "⚪ <b>No trading wallet</b>\nThe sniper is not configured."
                    .to_string();
            };
            let Some((address, role)) = sniper.trading_identity() else {
                return "⚪ <b>No trading wallet</b>\n\
                        Neither <code>keypair_path</code> (armed) nor \
                        <code>simulate_as</code> (dry run) is set, so there is no \
                        account to report on."
                    .to_string();
            };
            let Some(rpc) = &self.rpc else {
                return format!(
                    "⚠️ <b>No RPC configured</b>\n\
                     Wallet <code>{}</code> is set, but <code>[rpc].url</code> is \
                     empty so its balance cannot be read.",
                    escape_html(&address)
                );
            };

            let role_line = match role {
                WalletRole::Armed => "🔴 <b>ARMED</b> — this process can spend from it",
                WalletRole::Rehearsal => {
                    "🧪 <b>Dry run</b> — simulation only; no key is held for this address"
                }
            };

            let sol = rpc.sol_balance(&address).await;
            let tokens = rpc.token_account_count(&address).await;

            // Unreadable is reported as unknown, never as zero. Someone reading
            // "0 SOL" concludes they were drained; "could not read" is the truth.
            let sol_line = match sol {
                Some(v) => format!("<b>SOL:</b> {v:.4}"),
                None => "<b>SOL:</b> ⚠️ could not read (RPC error — not zero)".to_string(),
            };
            let token_line = match tokens {
                Some(n) => format!("<b>Token accounts:</b> {n}"),
                None => "<b>Token accounts:</b> ⚠️ could not read".to_string(),
            };

            format!(
                "💰 <b>Trading wallet</b>\n\
                 {role_line}\n\
                 <code>{address}</code>\n\n\
                 {sol_line}\n\
                 {token_line}\n\n\
                 <a href=\"https://solscan.io/account/{address}\">view on Solscan</a>",
                role_line = role_line,
                address = escape_html(&address),
                sol_line = sol_line,
                token_line = token_line,
            )
        }
    }

    /// Positions + PnL for the active wallet.
    ///
    /// Combines live holdings (real) with cost basis from the bot's own executed
    /// buys (audit log). PnL is shown only where BOTH a cost basis and a current
    /// mid-price mark exist. Holdings the bot didn't open, or can't price, are
    /// listed honestly as untracked rather than given a fabricated number.
    async fn render_positions(&self) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            return "⚪ <b>No positions</b>\nThis build has no execution support.".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            use crate::positions::{cost_basis_from_audit, unrealized};

            let Some(sniper) = &self.sniper else {
                return "⚪ <b>Sniper not configured</b>".to_string();
            };
            let Some((address, _role)) = sniper.trading_identity() else {
                return "⚪ <b>No trading wallet</b>\nSet an active wallet first.".to_string();
            };
            let Some(rpc) = &self.rpc else {
                return "⚠️ <b>No RPC configured</b>\nCannot read holdings.".to_string();
            };

            let holdings = match rpc.token_holdings(&address).await {
                Some(h) => h,
                None => {
                    return "⚠️ <b>Could not read holdings</b> (RPC error — not \"empty\")."
                        .to_string();
                }
            };

            // Cost basis from the bot's own executed buys.
            let basis = if self.audit_log.is_empty() {
                Default::default()
            } else {
                match tokio::fs::read_to_string(&self.audit_log).await {
                    Ok(s) => cost_basis_from_audit(&s),
                    Err(_) => Default::default(),
                }
            };

            if holdings.is_empty() {
                return format!(
                    "📭 <b>No token positions</b>\n\
                     Wallet <code>{}</code> holds no tokens.\n\n\
                     <i>No live trade has executed yet — positions and PnL fill in \
                     once the bot buys.</i>",
                    escape_html(&address)
                );
            }

            let mut out = format!(
                "📈 <b>Positions</b> — <code>{}</code>\n",
                escape_html(&address)
            );
            let mut total_cost = 0.0;
            let mut total_value = 0.0;
            let mut priced_any = false;

            for (mint, amount) in &holdings {
                let short = format!("{}…{}", &mint[..4.min(mint.len())], &mint[mint.len().saturating_sub(4)..]);
                match basis.get(mint) {
                    Some(cb) => {
                        // Try to mark it: read both vaults now, mid-price it.
                        let value = self.mark_position(rpc, cb, *amount).await;
                        match value {
                            Some(v) => {
                                let p = unrealized(cb.sol_spent, v);
                                priced_any = true;
                                total_cost += p.cost;
                                total_value += p.value;
                                let sign = if p.abs >= 0.0 { "🟢 +" } else { "🔴 " };
                                out.push_str(&format!(
                                    "\n<b>{short}</b> — {amt:.2} tokens\n\
                                     cost {cost:.4} → est {val:.4} SOL  ({sign}{abs:.4}, {pct:+.1}%)\n",
                                    short = escape_html(&short),
                                    amt = amount,
                                    cost = p.cost,
                                    val = p.value,
                                    sign = sign,
                                    abs = p.abs.abs(),
                                    pct = p.pct,
                                ));
                            }
                            None => out.push_str(&format!(
                                "\n<b>{short}</b> — {amt:.2} tokens\n\
                                 cost {cost:.4} SOL · <i>price unavailable</i>\n",
                                short = escape_html(&short),
                                amt = amount,
                                cost = cb.sol_spent,
                            )),
                        }
                    }
                    None => out.push_str(&format!(
                        "\n<b>{short}</b> — {amt:.2} tokens · <i>untracked (not bought by this bot)</i>\n",
                        short = escape_html(&short),
                        amt = amount,
                    )),
                }
            }

            if priced_any {
                let p = unrealized(total_cost, total_value);
                let sign = if p.abs >= 0.0 { "🟢 +" } else { "🔴 " };
                out.push_str(&format!(
                    "\n<b>Total (tracked):</b> {cost:.4} → {val:.4} SOL  ({sign}{abs:.4}, {pct:+.1}%)\n\
                     <i>est. = mid-price, excludes slippage on exit.</i>",
                    cost = p.cost, val = p.value, sign = sign, abs = p.abs.abs(), pct = p.pct,
                ));
            } else {
                out.push_str(
                    "\n<i>No tracked cost basis yet — PnL fills in once the bot's own \
                     buys execute. Untracked holdings can't be priced without a cost basis.</i>",
                );
            }
            out
        }
    }

    /// Mid-price mark of a position: read both pool vaults now and value the
    /// holding at `quote_reserve / base_reserve`. `None` if either vault can't
    /// be read or the reserves can't price it.
    #[cfg(feature = "sniper")]
    async fn mark_position(
        &self,
        rpc: &crate::rpc::RpcClient,
        cb: &crate::positions::CostBasis,
        held: f64,
    ) -> Option<f64> {
        let base_vault = cb.base_vault.as_deref()?;
        let quote_vault = cb.quote_vault.as_deref()?;
        let base_reserve = rpc.vault_balance(base_vault).await?;
        let quote_reserve = rpc.vault_balance(quote_vault).await?;
        crate::positions::mid_price_value(quote_reserve, base_reserve, held)
    }

    fn halt_engaged(&self) -> bool {
        !self.kill_switch_file.as_os_str().is_empty() && self.kill_switch_file.exists()
    }

    /// Engage the kill switch by creating the file the sniper checks before
    /// every trade. Idempotent: halting an already-halted bot is a no-op that
    /// still reports success, because the caller's intent is satisfied.
    fn do_halt(&self) -> String {
        if self.kill_switch_file.as_os_str().is_empty() {
            return "⚠️ No kill switch file configured — nothing to halt.\n\
                    Set <code>[sniper].kill_switch_file</code> to enable <code>/halt</code>."
                .to_string();
        }

        if self.halt_engaged() {
            return format!(
                "🛑 Already halted.\nKill switch <code>{}</code> is engaged.",
                escape_html(&self.kill_switch_file.display().to_string())
            );
        }

        match std::fs::write(&self.kill_switch_file, b"halted via telegram\n") {
            Ok(()) => {
                warn!(
                    file = %self.kill_switch_file.display(),
                    "kill switch ENGAGED via telegram command"
                );
                "🛑 <b>HALTED.</b>\nNo further trades will execute until resumed.".to_string()
            }
            Err(e) => {
                // Loud: the user believes they stopped trading and they have not.
                warn!(error = %e, "FAILED to engage kill switch via telegram");
                format!(
                    "⚠️ <b>HALT FAILED</b> — could not write kill switch: <code>{}</code>\n\
                     <b>Trading may still be active.</b> Stop the process manually.",
                    escape_html(&e.to_string())
                )
            }
        }
    }

    /// Clear the kill switch — the counterpart to `do_halt`.
    ///
    /// # Safety
    ///
    /// This does NOT arm the bot. Arming (going live at all) is a host-side
    /// config change + restart, unchanged. Resume only lifts the kill-switch
    /// pause on a bot that was *already armed on the host*, so the worst a
    /// resumed session can do is bounded by the daily caps, with no withdrawal
    /// path. A dry-run bot resumed is still dry run. The button flow confirms
    /// first (see `menu_screen`), so it is never a single accidental tap.
    fn do_resume(&self) -> String {
        if self.kill_switch_file.as_os_str().is_empty() {
            return "⚠️ No kill switch file configured.".to_string();
        }
        if !self.halt_engaged() {
            return "🟢 Not halted — trading is already active (subject to arming)."
                .to_string();
        }
        match std::fs::remove_file(&self.kill_switch_file) {
            Ok(()) => {
                warn!(
                    file = %self.kill_switch_file.display(),
                    "kill switch CLEARED via telegram — trading re-enabled (if armed)"
                );
                "🟢 <b>RESUMED.</b>\nKill switch cleared. Trading is re-enabled — \
                 but only actually trades if the bot was armed on the host."
                    .to_string()
            }
            Err(e) => format!(
                "⚠️ <b>RESUME FAILED</b> — could not clear kill switch: <code>{}</code>",
                escape_html(&e.to_string())
            ),
        }
    }

    /// Generate a fresh test wallet, or report the existing one's address.
    ///
    /// # Security
    ///
    /// Replies with the **public address only**. The private key is written to a
    /// local `0600` file and is NEVER included in the message — sending key
    /// material over Telegram would leak it to Telegram's servers and every
    /// device in the chat, permanently. This command creates or reports a wallet;
    /// it can never reveal the secret, and it cannot arm or trade.
    ///
    /// Generating a wallet does not make the bot trade with it: the running
    /// sniper loaded its keypair at startup, so using this wallet needs a
    /// deliberate local restart with `keypair_path` set — the arming step stays
    /// on the host, never on Telegram.
    fn render_new_wallet(&self, name: Option<&str>) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            let _ = name;
            return "⚪ <b>Not available</b>\nThis build has no wallet support \
                    (built without the <code>sniper</code> feature)."
                .to_string();
        }

        #[cfg(feature = "sniper")]
        {
            let Some(store) = &self.store else {
                return "⚪ <b>Wallet store not configured</b>".to_string();
            };
            // Default name keeps the one-wallet case a single tap.
            let name = name.unwrap_or("primary");

            // Re-check existing: report ITS address rather than failing, and never
            // overwrite (that file may already hold funds).
            if store.exists(name) {
                return match store.pubkey_of(name) {
                    Some(addr) => format!(
                        "💼 <b>Wallet <code>{n}</code> already exists</b>\n\
                         <b>Address:</b> <code>{addr}</code>\n\n\
                         Fund it, then <code>/use {n}</code> to make it active.\n\
                         <a href=\"https://solscan.io/account/{addr}\">view on Solscan</a>",
                        n = escape_html(name),
                        addr = escape_html(&addr.to_string()),
                    ),
                    None => format!(
                        "⚠️ Wallet <code>{}</code> exists but could not be read.",
                        escape_html(name)
                    ),
                };
            }

            match store.generate(name) {
                Ok(pubkey) => {
                    let active = store.active().as_deref() == Some(name);
                    format!(
                        "✅ <b>New wallet <code>{n}</code></b>\n\
                         <b>Address:</b> <code>{addr}</code>\n\n\
                         <b>Fund this address with a SMALL amount of SOL</b> (e.g. 0.05).\n\
                         The private key is stored on the host — treat anything you \
                         send as already spent.\n\n\
                         {active_line}\
                         Trading does not start from here: the operator arms it on \
                         the host while watching.\n\
                         <a href=\"https://solscan.io/account/{addr}\">view on Solscan</a>",
                        n = escape_html(name),
                        addr = escape_html(&pubkey.to_string()),
                        active_line = if active {
                            "This is now the <b>active</b> wallet.\n"
                        } else {
                            ""
                        },
                    )
                }
                Err(e) => format!(
                    "⚠️ <b>Could not create wallet</b>\n<code>{}</code>",
                    escape_html(&e.to_string())
                ),
            }
        }
    }

    /// List stored wallets with addresses and (if RPC available) balances,
    /// marking the active one. Addresses only — never key material.
    async fn render_wallets(&self) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            return "⚪ <b>Not available</b> (no <code>sniper</code> feature).".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            let Some(store) = &self.store else {
                return "⚪ <b>Wallet store not configured</b>".to_string();
            };
            let wallets = store.list();
            if wallets.is_empty() {
                return "📭 <b>No wallets yet</b>\nCreate one with <code>/new-wallet [name]</code>."
                    .to_string();
            }
            let active = store.active();
            let mut out = String::from("👛 <b>Wallets</b>\n");
            for (name, addr) in wallets {
                let mark = if active.as_deref() == Some(&name) { " ✓ active" } else { "" };
                let bal = match &self.rpc {
                    Some(rpc) => match rpc.sol_balance(&addr.to_string()).await {
                        Some(v) => format!(" — {v:.4} SOL"),
                        None => " — (balance unknown)".into(),
                    },
                    None => String::new(),
                };
                out.push_str(&format!(
                    "<b>{}</b>{mark}\n<code>{}</code>{bal}\n",
                    escape_html(&name),
                    escape_html(&addr.to_string()),
                ));
            }
            out.push_str("\nSet active with <code>/use &lt;name&gt;</code> (takes effect on the next host restart).");
            out
        }
    }

    /// Set the active wallet. Selection only records which key the NEXT run
    /// loads — it does not redirect a running armed sniper, so a Telegram
    /// command can never move live funds to a different wallet mid-session.
    fn render_use(&self, name: Option<&str>) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            let _ = name;
            return "⚪ <b>Not available</b> (no <code>sniper</code> feature).".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            let Some(store) = &self.store else {
                return "⚪ <b>Wallet store not configured</b>".to_string();
            };
            let Some(name) = name else {
                return "Usage: <code>/use &lt;name&gt;</code>\nSee <code>/wallets</code>."
                    .to_string();
            };
            match store.set_active(name) {
                Ok(()) => format!(
                    "✅ Active wallet set to <b>{}</b>.\n\n\
                     This applies to trading on the <b>next host restart</b> — \
                     selecting a wallet here never redirects a live session.",
                    escape_html(name)
                ),
                Err(e) => format!("⚠️ {}", escape_html(&e.to_string())),
            }
        }
    }

    /// Apply a tunable parameter change. Slippage and min-liquidity are
    /// tighten-only (clamp toward safer); `/size` can be raised up to the
    /// configured `max_trade_size_sol` ceiling — unbounded when that is 0.
    fn render_set(&self, which: Tunable, arg: Option<&str>) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            let _ = (which, arg);
            return "⚪ <b>Not available</b> (no <code>sniper</code> feature).".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            let Some(sniper) = &self.sniper else {
                return "⚪ <b>Sniper not configured</b>".to_string();
            };
            let Some(arg) = arg else {
                return format!("Usage: <code>/{} &lt;value&gt;</code>", which.cmd());
            };

            let result = match which {
                Tunable::Size => arg.parse::<f64>().map_err(|_| "not a number".to_string())
                    .and_then(|v| sniper.set_trade_size(v)),
                Tunable::MinLiquidity => arg.parse::<f64>().map_err(|_| "not a number".to_string())
                    .and_then(|v| sniper.set_min_liquidity(v)),
                Tunable::Slippage => arg.parse::<u16>().map_err(|_| "not an integer (bps)".to_string())
                    .and_then(|v| sniper.set_slippage_bps(v)),
            };
            match result {
                Ok(msg) => format!("✅ {}", escape_html(&msg)),
                Err(e) => format!("⚠️ {}", escape_html(&e)),
            }
        }
    }

    /// Read-only view of the current trading settings.
    fn render_settings(&self) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            return "⚪ <b>No sniper</b>\nThis build has no execution support.".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            let Some(sniper) = &self.sniper else {
                return "⚪ <b>Sniper not configured</b>".to_string();
            };
            let mut out = String::from("⚙️ <b>Trading settings</b>\n");
            for (label, value) in sniper.settings_rows() {
                out.push_str(&format!("{}: <b>{}</b>\n", escape_html(label), escape_html(&value)));
            }
            out.push_str(
                "\nLines marked <code>— hard cap</code> are set on the host and \
                 cannot be changed from here.",
            );
            out
        }
    }

    fn render_help() -> String {
        "<b>volens</b>\n\
         Tap a button below, or use the <b>/</b> menu (bottom-left) for all \
         commands.\n\n\
         <b>Buttons:</b> Status · Settings · Balance · Positions · Wallets · \
         New wallet · Metrics · Halt.\n\n\
         <b>Typed (take a value):</b>\n\
         • <code>/use name</code> — pick the active wallet (applies on restart)\n\
         • <code>/size 0.01</code> — set the trade size (SOL)\n\
         • <code>/slippage 200</code> — tighten slippage\n\
         • <code>/min-liquidity 25</code> — raise the liquidity floor\n\n\
         <code>/halt</code> and <code>/resume</code> toggle the kill switch.\n\n\
         <code>/slippage</code> and <code>/min-liquidity</code> are \
         <b>tighten-only</b>. <code>/size</code> can be raised (up to the host \
         ceiling), so it can increase spend. <code>/resume</code> clears the \
         pause but does NOT arm — there is no <code>/arm</code> and no withdraw. \
         Going live (arming) requires host access."
            .to_string()
    }

    /// Send a fresh message with a keyboard. Used for typed commands (you can't
    /// edit a message the user typed) — the reply carries the main menu so they
    /// can navigate from there.
    async fn reply(&self, chat_id: i64, text: String) {
        self.reply_with(chat_id, text, self.main_menu()).await;
    }

    async fn reply_with(&self, chat_id: i64, text: String, keyboard: serde_json::Value) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let body = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": keyboard,
        });

        match self.client.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => debug!("telegram reply sent"),
            Ok(r) => {
                let status = r.status();
                warn!(%status, "telegram reply failed");
            }
            Err(e) => warn!(error = %e, "telegram reply error"),
        }
    }

    /// Edit a message in place (used for button navigation). Telegram returns an
    /// error if the new text+markup are identical to the current — that is
    /// harmless (a double-tap) and ignored.
    async fn edit_message(
        &self,
        chat_id: i64,
        message_id: i64,
        text: String,
        keyboard: serde_json::Value,
    ) {
        let url = format!("https://api.telegram.org/bot{}/editMessageText", self.bot_token);
        let body = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": keyboard,
        });
        match self.client.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => debug!("telegram message edited"),
            Ok(_) => debug!("telegram edit no-op (unchanged) or failed"),
            Err(e) => warn!(error = %e, "telegram edit error"),
        }
    }

    /// Top-level menu. Leaf actions (Status/Settings/Metrics) execute in place;
    /// "👛 Wallet ▸" drills into the wallet submenu. The last row toggles: it
    /// shows HALT while running, or Resume (guarded by a confirm step) while
    /// halted — so the control you need is always the one on screen.
    fn main_menu(&self) -> serde_json::Value {
        let control = if self.halt_engaged() {
            serde_json::json!({"text": "▶️ Resume trading", "callback_data": "nav:resume"})
        } else {
            serde_json::json!({"text": "🛑 HALT trading", "callback_data": "cmd:halt"})
        };
        serde_json::json!({
            "inline_keyboard": [
                [{"text": "📊 Status", "callback_data": "cmd:status"},
                 {"text": "📈 Metrics", "callback_data": "cmd:metrics"}],
                [{"text": "👛 Wallet ▸", "callback_data": "nav:wallet"},
                 {"text": "⚙️ Settings", "callback_data": "cmd:settings"}],
                [control],
            ]
        })
    }

    /// Wallet submenu: reached from the top menu, returns via "◀️ Back".
    fn wallet_menu() -> serde_json::Value {
        serde_json::json!({
            "inline_keyboard": [
                [{"text": "💰 Balance", "callback_data": "cmd:balance"},
                 {"text": "📈 Positions", "callback_data": "cmd:positions"}],
                [{"text": "👛 List wallets", "callback_data": "cmd:wallets"},
                 {"text": "🆕 New wallet", "callback_data": "cmd:new-wallet"}],
                [{"text": "◀️ Back", "callback_data": "nav:main"}],
            ]
        })
    }

    /// Keyboard for the wallets list: one "set active" button per wallet (the
    /// active one marked ✅), plus New wallet and Back. Tapping a wallet runs
    /// `use:<name>` — which only records the selection; the wallet trades live
    /// only after a host restart, so a tap here never redirects a running
    /// session's funds.
    #[cfg(feature = "sniper")]
    fn wallets_keyboard(&self) -> serde_json::Value {
        let mut rows: Vec<serde_json::Value> = Vec::new();
        if let Some(store) = &self.store {
            let active = store.active();
            for (name, _addr) in store.list() {
                let is_active = active.as_deref() == Some(&name);
                let label = if is_active {
                    format!("✅ {name} (active)")
                } else {
                    format!("Set active: {name}")
                };
                rows.push(serde_json::json!([
                    {"text": label, "callback_data": format!("use:{name}")}
                ]));
            }
        }
        rows.push(serde_json::json!([
            {"text": "🆕 New wallet", "callback_data": "cmd:new-wallet"}
        ]));
        rows.push(serde_json::json!([
            {"text": "◀️ Wallet", "callback_data": "nav:wallet"},
            {"text": "🏠 Menu", "callback_data": "nav:main"},
        ]));
        serde_json::json!({ "inline_keyboard": rows })
    }

    /// Without the sniper feature there is no wallet store; just a Back button.
    #[cfg(not(feature = "sniper"))]
    fn wallets_keyboard(&self) -> serde_json::Value {
        serde_json::json!({
            "inline_keyboard": [[{"text": "◀️ Menu", "callback_data": "nav:main"}]]
        })
    }

    /// Acknowledge a callback so the button stops showing a loading spinner. An
    /// optional short text is shown as a toast to the user.
    async fn answer_callback(&self, callback_id: &str, text: Option<&str>) {
        let url = format!("https://api.telegram.org/bot{}/answerCallbackQuery", self.bot_token);
        let mut body = serde_json::json!({ "callback_query_id": callback_id });
        if let Some(t) = text {
            body["text"] = serde_json::Value::String(t.to_string());
        }
        let _ = self.client.post(&url).json(&body).send().await;
    }

    /// Register the command list with Telegram (`setMyCommands`), so the "/"
    /// menu shows them persistently — not just in a message the user has to
    /// scroll back to. Best-effort: a failure here is cosmetic, not fatal.
    async fn register_commands(&self) {
        let url = format!("https://api.telegram.org/bot{}/setMyCommands", self.bot_token);
        // Telegram command names must be lowercase `[a-z0-9_]`, 1..32 chars —
        // NO hyphens (setMyCommands rejects the whole list with 400 otherwise).
        // The parser still accepts the hyphenated spellings; these underscore
        // forms are just what the "/" menu shows.
        let commands = serde_json::json!({
            "commands": [
                {"command": "status", "description": "running state, uptime, detections"},
                {"command": "settings", "description": "trade size, slippage, caps, mode"},
                {"command": "balance", "description": "active wallet SOL + token accounts"},
                {"command": "positions", "description": "token positions + PnL"},
                {"command": "wallets", "description": "list wallets, mark active"},
                {"command": "new_wallet", "description": "create a wallet to fund (optional name)"},
                {"command": "use", "description": "pick active wallet: /use name"},
                {"command": "size", "description": "set trade size: /size 0.01"},
                {"command": "slippage", "description": "tighten slippage: /slippage 200"},
                {"command": "min_liquidity", "description": "raise liquidity floor: /min_liquidity 25"},
                {"command": "metrics", "description": "full counter breakdown"},
                {"command": "halt", "description": "engage kill switch, stop all trading"},
                {"command": "resume", "description": "clear kill switch (does not arm)"},
                {"command": "help", "description": "show commands"},
            ]
        });
        match self.client.post(&url).json(&commands).send().await {
            Ok(r) if r.status().is_success() => info!("telegram command menu registered"),
            Ok(r) => warn!(status = %r.status(), "setMyCommands failed"),
            Err(e) => warn!(error = %e, "setMyCommands error"),
        }
    }
}

/// Which menu a command result should offer "Back" to.
fn back_group(callback_data: &str) -> &'static str {
    match callback_data {
        // Wallet-group actions return to the wallet submenu.
        "cmd:balance" | "cmd:positions" | "cmd:wallets" | "cmd:new-wallet" => "wallet",
        _ => "main",
    }
}

/// A "Back" keyboard shown under a command result, pointing at the menu the
/// action belongs to (plus a shortcut home from a submenu).
fn back_keyboard(group: &str) -> serde_json::Value {
    if group == "wallet" {
        serde_json::json!({
            "inline_keyboard": [[
                {"text": "◀️ Wallet", "callback_data": "nav:wallet"},
                {"text": "🏠 Menu", "callback_data": "nav:main"},
            ]]
        })
    } else {
        serde_json::json!({
            "inline_keyboard": [[{"text": "◀️ Menu", "callback_data": "nav:main"}]]
        })
    }
}

/// Which tunable a `/size` / `/slippage` / `/min-liquidity` command targets.
#[derive(Clone, Copy)]
enum Tunable {
    Size,
    Slippage,
    MinLiquidity,
}

impl Tunable {
    fn cmd(self) -> &'static str {
        match self {
            Tunable::Size => "size",
            Tunable::Slippage => "slippage",
            Tunable::MinLiquidity => "min-liquidity",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Status,
    Metrics,
    Halt,
    Resume,
    Balance,
    Positions,
    Settings,
    NewWallet(Option<String>),
    Wallets,
    Use(Option<String>),
    SetSize(Option<String>),
    SetSlippage(Option<String>),
    SetMinLiquidity(Option<String>),
    Help,
}

impl Command {
    /// Parse a command and its (single) optional argument from message text.
    ///
    /// Handles the `/cmd@BotName` form Telegram uses in groups. Only the first
    /// argument token is captured; validation of that argument happens in the
    /// handler, so a bad value produces a helpful reply rather than a silent drop.
    fn parse(text: &str) -> Option<Command> {
        let mut it = text.split_whitespace();
        let first = it.next()?;
        let cmd = first.strip_prefix('/')?.split('@').next()?.to_ascii_lowercase();
        let arg = it.next().map(str::to_string);
        Some(match cmd.as_str() {
            "status" => Command::Status,
            "metrics" | "stats" => Command::Metrics,
            "halt" | "stop" | "kill" => Command::Halt,
            "resume" | "unhalt" => Command::Resume,
            "balance" => Command::Balance,
            "positions" | "pnl" | "pos" => Command::Positions,
            "settings" | "config" | "params" => Command::Settings,
            "new-wallet" | "newwallet" | "new_wallet" | "genwallet" => Command::NewWallet(arg),
            "wallets" | "list" => Command::Wallets,
            "use" | "active" | "select" => Command::Use(arg),
            "size" | "trade-size" | "amount" => Command::SetSize(arg),
            "slippage" | "slip" => Command::SetSlippage(arg),
            "min-liquidity" | "min_liquidity" | "minliq" | "minliquidity" => {
                Command::SetMinLiquidity(arg)
            }
            "help" | "start" => Command::Help,
            _ => return None,
        })
    }

    fn name(&self) -> &'static str {
        match self {
            Command::Status => "status",
            Command::Metrics => "metrics",
            Command::Halt => "halt",
            Command::Resume => "resume",
            Command::Balance => "balance",
            Command::Positions => "positions",
            Command::Settings => "settings",
            Command::NewWallet(_) => "new-wallet",
            Command::Wallets => "wallets",
            Command::Use(_) => "use",
            Command::SetSize(_) => "size",
            Command::SetSlippage(_) => "slippage",
            Command::SetMinLiquidity(_) => "min-liquidity",
            Command::Help => "help",
        }
    }

    /// Map an inline-button payload (`cmd:<name>`) to a command. Only the
    /// no-argument commands are reachable by button; arg-taking ones (`/size`,
    /// `/use`, …) are typed. `NewWallet` uses its default name.
    fn from_callback(data: &str) -> Option<Command> {
        match data.strip_prefix("cmd:")? {
            "status" => Some(Command::Status),
            "metrics" => Some(Command::Metrics),
            "halt" => Some(Command::Halt),
            "resume" => Some(Command::Resume),
            "balance" => Some(Command::Balance),
            "positions" => Some(Command::Positions),
            "settings" => Some(Command::Settings),
            "wallets" => Some(Command::Wallets),
            "new-wallet" => Some(Command::NewWallet(None)),
            "help" => Some(Command::Help),
            _ => None,
        }
    }
}

// --- Telegram API shapes (only the fields we use) ---

#[derive(serde::Deserialize)]
struct UpdatesResponse {
    ok: bool,
    #[serde(default)]
    result: Vec<Update>,
}

#[derive(serde::Deserialize)]
struct Update {
    update_id: i64,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(serde::Deserialize)]
struct Message {
    #[serde(default)]
    message_id: i64,
    chat: Chat,
    #[serde(default)]
    text: Option<String>,
}

#[derive(serde::Deserialize)]
struct Chat {
    id: i64,
}

/// A tap on an inline-keyboard button. `data` is the button's callback payload;
/// `from` is the user who tapped (used for authorization — in a group this is
/// the individual, not the group).
#[derive(serde::Deserialize)]
struct CallbackQuery {
    id: String,
    from: User,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(serde::Deserialize)]
struct User {
    id: i64,
}

/// Escape text for Telegram HTML parse mode.
///
/// Anything interpolated into a message that did not originate here must go
/// through this. Filesystem paths and OS error strings can contain `<`, and an
/// unescaped `<` makes Telegram reject the whole message with a 400 — so the
/// failure mode is a *lost alert*, not just a cosmetic glitch.
pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect::<String>() + "…"
}

fn format_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bot(allowed: &[&str], kill: &str) -> Result<Bot> {
        let ids: Vec<String> = allowed.iter().map(|s| s.to_string()).collect();
        Bot::new(
            "token".to_string(),
            &ids,
            Arc::new(Metrics::default()),
            kill,
        )
    }

    /// `unwrap_err` requires `Debug` on the Ok type, and `Bot` deliberately does
    /// not implement it — a derived `Debug` would print the bot token, which is
    /// the same class of leak `Wallet`'s manual redacted Debug exists to
    /// prevent. Extract the error without demanding Debug on the success value.
    fn expect_err(r: Result<Bot>) -> String {
        match r {
            Ok(_) => panic!("expected an error, got a constructed Bot"),
            Err(e) => e.to_string(),
        }
    }

    /// The central safety property: an empty allowlist must not mean "allow
    /// everyone". A `/halt` reachable by anyone who finds the token is a remote
    /// kill switch for strangers.
    #[test]
    fn empty_allowlist_refuses_to_start() {
        let err = expect_err(bot(&[], "HALT"));
        assert!(err.contains("authorized_chat_ids is empty"), "got: {err}");

        // Whitespace-only entries are empty too.
        let err = expect_err(bot(&["", "  "], "HALT"));
        assert!(err.contains("authorized_chat_ids is empty"), "got: {err}");
    }

    #[test]
    fn missing_token_refuses_to_start() {
        let err = expect_err(Bot::new(
            String::new(),
            &["123".to_string()],
            Arc::new(Metrics::default()),
            "HALT",
        ));
        assert!(err.contains("no bot token"), "got: {err}");
    }

    #[test]
    fn malformed_chat_id_is_an_error_not_a_skip() {
        // Silently skipping an unparseable id could empty the allowlist in a way
        // the empty-check would then have to catch, or worse, drop one id from a
        // list of several and leave the bot quietly unreachable for that user.
        let err = expect_err(bot(&["not-a-number"], "HALT"));
        assert!(err.contains("invalid chat id"), "got: {err}");
    }

    #[test]
    fn negative_chat_ids_parse() {
        // Telegram group chat ids are negative; supergroups are large negatives.
        let b = bot(&["-1001234567890", "42"], "HALT").unwrap();
        assert_eq!(b.authorized_count(), 2);
        assert!(b.allowed.contains(&-1001234567890));
        assert!(b.allowed.contains(&42));
    }

    /// Navigation payloads produce a menu screen (title + keyboard), not a
    /// command execution. The wallet-group results point Back to the wallet
    /// submenu; everything else to the main menu.
    #[tokio::test]
    async fn nav_and_back_routing() {
        let b = bot(&["1"], "").unwrap();
        // Menu screens.
        let (title, _) = b.menu_screen("main").await;
        assert!(title.contains("volens"), "got: {title}");
        let (title, _) = b.menu_screen("wallet").await;
        assert!(title.contains("Wallet"), "got: {title}");
        // Unknown menu falls back to main (never a blank screen).
        let (title, _) = b.menu_screen("bogus").await;
        assert!(title.contains("volens"), "got: {title}");

        // Back grouping: wallet actions return to wallet, others to main.
        assert_eq!(back_group("cmd:balance"), "wallet");
        assert_eq!(back_group("cmd:positions"), "wallet");
        assert_eq!(back_group("cmd:status"), "main");
        assert_eq!(back_group("cmd:halt"), "main");
    }

    #[test]
    fn callback_payloads_map_to_no_arg_commands() {
        assert_eq!(Command::from_callback("cmd:status"), Some(Command::Status));
        assert_eq!(Command::from_callback("cmd:halt"), Some(Command::Halt));
        assert_eq!(Command::from_callback("cmd:new-wallet"), Some(Command::NewWallet(None)));
        // Unknown / malformed payloads yield nothing (never a wrong command).
        assert_eq!(Command::from_callback("cmd:arm"), None);
        assert_eq!(Command::from_callback("status"), None);
        assert_eq!(Command::from_callback("cmd:size"), None); // arg-taking, not a button
        assert_eq!(Command::from_callback(""), None);
    }

    /// An unauthorized button tap must not execute — same guarantee as a typed
    /// command, but keyed on the tapping USER's id. Drive the real handler and
    /// confirm no side effect (the kill switch is not written).
    #[tokio::test]
    async fn unauthorized_button_tap_does_not_execute() {
        let dir = std::env::temp_dir().join(format!("volens-cb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-cb");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1000"], kill.to_str().unwrap()).unwrap();
        // Stranger taps the HALT button.
        b.handle_callback(CallbackQuery {
            id: "x".into(),
            from: User { id: 999 },
            message: Some(Message { message_id: 1, chat: Chat { id: 999 }, text: None }),
            data: Some("cmd:halt".into()),
        })
        .await;
        assert!(!kill.exists(), "unauthorized tap must not engage the kill switch");
        let _ = std::fs::remove_file(&kill);
    }

    #[test]
    fn command_parsing() {
        assert_eq!(Command::parse("/status"), Some(Command::Status));
        assert_eq!(Command::parse("  /status  "), Some(Command::Status));
        assert_eq!(Command::parse("/STATUS"), Some(Command::Status));
        // Group form: Telegram appends the bot username.
        assert_eq!(Command::parse("/status@volens_bot"), Some(Command::Status));
        // Trailing args ignored.
        assert_eq!(Command::parse("/halt now please"), Some(Command::Halt));
        assert_eq!(Command::parse("/metrics"), Some(Command::Metrics));
        assert_eq!(Command::parse("/help"), Some(Command::Help));

        // Non-commands.
        assert_eq!(Command::parse("status"), None);
        assert_eq!(Command::parse("hello there"), None);
        assert_eq!(Command::parse(""), None);
        assert_eq!(Command::parse("/"), None);
        assert_eq!(Command::parse("/unknown"), None);
    }

    /// The line that must never be crossed: a command that ARMS the bot or moves
    /// funds. `/resume` now exists (it toggles the kill switch — see below), but
    /// it can only un-pause a bot that was *already armed on the host*; it cannot
    /// arm a dry-run bot, and there is no withdraw/send/trade primitive at all.
    #[test]
    fn no_arming_or_fund_moving_commands() {
        for c in ["/arm", "/trade", "/buy", "/sell", "/withdraw", "/send", "/transfer", "/export"] {
            assert_eq!(Command::parse(c), None, "{c} must not be a command");
        }
    }

    /// `/resume` and `/halt` are the two sides of the kill-switch toggle. Resume
    /// is deliberately allowed but is NOT arming — it clears the pause on an
    /// already-armed bot, bounded by the daily caps, with no withdrawal path.
    #[test]
    fn halt_and_resume_are_the_kill_switch_toggle() {
        assert_eq!(Command::parse("/halt"), Some(Command::Halt));
        assert_eq!(Command::parse("/resume"), Some(Command::Resume));
        assert_eq!(Command::parse("/unhalt"), Some(Command::Resume));
        // `/start` stays the menu (Telegram's default), not resume.
        assert_eq!(Command::parse("/start"), Some(Command::Help));
    }

    /// `/size` etc. parse (they are tighten-only, not absent). The clamping that
    /// makes them safe is enforced in the sniper, tested there.
    #[test]
    fn tuning_commands_parse_with_their_argument() {
        assert_eq!(Command::parse("/size 0.01"), Some(Command::SetSize(Some("0.01".into()))));
        assert_eq!(Command::parse("/slippage 200"), Some(Command::SetSlippage(Some("200".into()))));
        assert_eq!(
            Command::parse("/min-liquidity 25"),
            Some(Command::SetMinLiquidity(Some("25".into())))
        );
        // Missing argument still parses; the handler replies with usage.
        assert_eq!(Command::parse("/size"), Some(Command::SetSize(None)));
    }

    #[test]
    fn halt_writes_kill_switch_file() {
        let dir = std::env::temp_dir().join(format!("volens-bot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-test");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1"], kill.to_str().unwrap()).unwrap();
        assert!(!b.halt_engaged());

        let reply = b.do_halt();
        assert!(kill.exists(), "kill switch file must exist after /halt");
        assert!(b.halt_engaged());
        assert!(reply.contains("HALTED"), "got: {reply}");

        // Idempotent: second halt reports already-halted, file still there.
        let reply2 = b.do_halt();
        assert!(reply2.contains("Already halted"), "got: {reply2}");
        assert!(kill.exists());

        std::fs::remove_file(&kill).unwrap();
    }

    #[test]
    fn halt_with_no_configured_file_says_so() {
        let b = bot(&["1"], "").unwrap();
        let reply = b.do_halt();
        assert!(reply.contains("No kill switch file configured"), "got: {reply}");
        // Must not claim success.
        assert!(!reply.contains("HALTED."), "got: {reply}");
    }

    /// Resume clears the kill switch — the counterpart to halt. It must only
    /// clear the pause, and its message must be explicit that it does not arm.
    #[test]
    fn resume_clears_the_kill_switch() {
        let dir = std::env::temp_dir().join(format!("volens-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-resume");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1"], kill.to_str().unwrap()).unwrap();
        b.do_halt();
        assert!(b.halt_engaged());

        let reply = b.do_resume();
        assert!(!kill.exists(), "resume must remove the kill switch file");
        assert!(!b.halt_engaged());
        assert!(reply.contains("RESUMED"), "got: {reply}");
        // Must not imply it armed anything.
        assert!(reply.contains("armed on the host"), "must clarify it doesn't arm: {reply}");

        // Resuming when not halted is a harmless no-op, clearly reported.
        let reply2 = b.do_resume();
        assert!(reply2.contains("Not halted"), "got: {reply2}");
    }

    /// The main menu's control row must reflect state: HALT while running,
    /// Resume while halted — so the operator always sees the action they need.
    #[test]
    fn main_menu_control_toggles_with_halt_state() {
        let dir = std::env::temp_dir().join(format!("volens-menu-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-menu");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1"], kill.to_str().unwrap()).unwrap();
        let running = b.main_menu().to_string();
        assert!(running.contains("HALT"), "running menu must offer HALT");
        assert!(!running.contains("Resume"));

        b.do_halt();
        let halted = b.main_menu().to_string();
        assert!(halted.contains("Resume"), "halted menu must offer Resume");
        // Resume goes through the confirm nav, never a direct one-tap.
        assert!(halted.contains("nav:resume"), "resume must route via confirm");

        let _ = std::fs::remove_file(&kill);
    }

    #[test]
    fn status_reflects_halt_state() {
        let dir = std::env::temp_dir().join(format!("volens-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-status");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1"], kill.to_str().unwrap()).unwrap();
        assert!(b.render_status().contains("running"));

        b.do_halt();
        let s = b.render_status();
        assert!(s.contains("HALTED"), "got: {s}");
        assert!(!s.contains("🟢 running"), "got: {s}");

        std::fs::remove_file(&kill).unwrap();
    }

    fn update(id: i64, chat_id: i64, text: &str) -> Update {
        Update {
            update_id: id,
            message: Some(Message {
                message_id: id,
                chat: Chat { id: chat_id },
                text: Some(text.to_string()),
            }),
            callback_query: None,
        }
    }

    /// The authorization check must live in `handle_update` itself, ahead of any
    /// dispatch. Testing `Command::parse` and `do_halt` in isolation would pass
    /// even if the check were moved below dispatch, so drive the real entry
    /// point: an unauthorized `/halt` must not write the kill switch.
    ///
    /// No HTTP happens here — an unauthorized update returns before any reply,
    /// which is precisely the property under test.
    #[tokio::test]
    async fn unauthorized_halt_does_not_engage_kill_switch() {
        let dir = std::env::temp_dir().join(format!("volens-authz-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-authz");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1000"], kill.to_str().unwrap()).unwrap();

        // Stranger tries to halt.
        b.handle_update(update(1, 999, "/halt")).await;
        assert!(
            !kill.exists(),
            "unauthorized /halt must NOT engage the kill switch"
        );
        assert!(!b.halt_engaged());

        // Same command, near-miss id (off by one) — still refused.
        b.handle_update(update(2, 1001, "/halt")).await;
        assert!(!kill.exists(), "chat id 1001 is not 1000");

        // Negative of the allowed id must not pass either.
        b.handle_update(update(3, -1000, "/halt")).await;
        assert!(!kill.exists(), "-1000 is not 1000");

        let _ = std::fs::remove_file(&kill);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Positive control for the test above: without it, the previous test would
    /// still pass if `/halt` were broken for everyone, or if `handle_update`
    /// dropped every message. This proves the path works when authorized, so the
    /// refusals above are attributable to authorization and nothing else.
    #[tokio::test]
    async fn authorized_halt_does_engage_kill_switch() {
        let dir = std::env::temp_dir().join(format!("volens-authz-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kill = dir.join("HALT-authz-ok");
        let _ = std::fs::remove_file(&kill);

        let b = bot(&["1000"], kill.to_str().unwrap()).unwrap();
        assert!(!kill.exists());

        // The authorized path calls `reply`, which will fail against the fake
        // token — that's fine and intentional: the halt is written before the
        // reply is attempted, and a failed reply must not undo it.
        b.handle_update(update(1, 1000, "/halt")).await;

        assert!(
            kill.exists(),
            "authorized /halt must engage the kill switch even if the reply fails"
        );
        assert!(b.halt_engaged());

        let _ = std::fs::remove_file(&kill);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Non-command chatter from an authorized user must be ignored quietly, and
    /// a message with no text at all (photo, sticker) must not panic.
    #[tokio::test]
    async fn non_commands_and_empty_messages_are_ignored() {
        let b = bot(&["1000"], "").unwrap();
        b.handle_update(update(1, 1000, "hello")).await;
        b.handle_update(Update {
            update_id: 2,
            message: Some(Message {
                message_id: 1,
                chat: Chat { id: 1000 },
                text: None,
            }),
            callback_query: None,
        })
        .await;
        b.handle_update(Update { update_id: 3, message: None, callback_query: None }).await;
    }

    #[test]
    fn balance_is_a_command() {
        assert_eq!(Command::parse("/balance"), Some(Command::Balance));
        assert_eq!(Command::parse("/balance@volens_bot"), Some(Command::Balance));
        // `/wallet` (singular) is NOT balance — `/wallets` (plural) lists them.
        assert_eq!(Command::parse("/wallets"), Some(Command::Wallets));
    }

    /// `/balance` is read-only, so it must remain reachable — but it must not
    /// have acquired any ability to MOVE funds. This is the tripwire against
    /// someone later adding /withdraw or /send next to it.
    #[test]
    fn positions_is_a_command() {
        assert_eq!(Command::parse("/positions"), Some(Command::Positions));
        assert_eq!(Command::parse("/pnl"), Some(Command::Positions));
        assert_eq!(Command::from_callback("cmd:positions"), Some(Command::Positions));
    }

    /// With no sniper/wallet, /positions must say so, not fabricate.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn positions_without_wallet_says_so() {
        let b = bot(&["1"], "").unwrap();
        let msg = b.render_positions().await;
        assert!(msg.contains("Sniper not configured") || msg.contains("No trading wallet"),
                "got: {msg}");
    }

    #[test]
    fn settings_is_a_command() {
        assert_eq!(Command::parse("/settings"), Some(Command::Settings));
        assert_eq!(Command::parse("/config"), Some(Command::Settings));
        assert_eq!(Command::parse("/settings@volens_bot"), Some(Command::Settings));
    }

    /// `/settings` is read-only and must never expose secrets. It reports config,
    /// which contains no key material, but pin the property regardless.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn settings_shows_caps_and_no_secrets() {
        use crate::config::{RpcConfig, SniperConfig};
        // Minimal armed-less sniper in dry run.
        let mut sc = SniperConfig::default();
        sc.enabled = true;
        sc.trade_size_sol = 0.02;
        sc.max_trade_size_sol = 0.1;
        let rpc = Arc::new(crate::rpc::RpcClient::new(&RpcConfig::default()));
        let sniper = Arc::new(crate::sniper::Sniper::new(sc, rpc.clone(), &RpcConfig::default()).unwrap());

        let b = bot(&["1"], "").unwrap().with_sniper(sniper);
        let msg = b.render_settings();
        assert!(msg.contains("Trading settings"), "got: {msg}");
        assert!(msg.contains("0.02"), "must show working trade size");
        assert!(msg.contains("hard cap"), "must label the local caps");
        assert!(msg.contains("0.1"), "must show the max trade cap");
    }

    #[test]
    fn new_wallet_is_a_command() {
        assert_eq!(Command::parse("/new-wallet"), Some(Command::NewWallet(None)));
        assert_eq!(Command::parse("/new-wallet alpha"),
                   Some(Command::NewWallet(Some("alpha".into()))));
        assert_eq!(Command::parse("/genwallet"), Some(Command::NewWallet(None)));
    }

    #[cfg(feature = "sniper")]
    fn store_bot(dir: &std::path::Path) -> Bot {
        let store = Arc::new(crate::walletstore::WalletStore::new(dir));
        bot(&["1"], "").unwrap().with_wallet_store(store)
    }

    #[cfg(feature = "sniper")]
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("volens-botnw-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// `/new-wallet` must reply with the PUBLIC ADDRESS only. Key material in a
    /// Telegram message would leak to Telegram's servers and every device in the
    /// chat, permanently. Drives the real handler and scans the reply for the
    /// secret bytes.
    #[cfg(feature = "sniper")]
    #[test]
    fn new_wallet_reply_never_contains_key_material() {
        let dir = tmp_dir("secret");
        let b = store_bot(&dir);
        let reply = b.render_new_wallet(Some("alpha"));

        let keyfile = dir.join("alpha.json");
        let raw = std::fs::read_to_string(&keyfile).unwrap();
        assert!(reply.contains("New wallet"), "got: {reply}");
        assert!(!reply.contains(&raw), "reply must not contain the key file contents");

        let bytes: Vec<u8> = serde_json::from_str(&raw).unwrap();
        let secret_frag = format!("{:?}", &bytes[..8]);
        assert!(!reply.contains(&secret_frag), "reply leaked secret-byte prefix");

        let w = crate::tx::Wallet::load(keyfile.to_str().unwrap()).unwrap();
        assert!(reply.contains(&w.pubkey().to_string()), "reply must show the address");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Re-invoking must report the existing address, not overwrite (the file may
    /// be funded).
    #[cfg(feature = "sniper")]
    #[test]
    fn new_wallet_is_idempotent_and_never_overwrites() {
        let dir = tmp_dir("idem");
        let b = store_bot(&dir);
        let first = b.render_new_wallet(Some("alpha"));
        let keyfile = dir.join("alpha.json");
        let addr1 = crate::tx::Wallet::load(keyfile.to_str().unwrap()).unwrap().pubkey().to_string();
        let bytes1 = std::fs::read(&keyfile).unwrap();

        let second = b.render_new_wallet(Some("alpha"));
        let bytes2 = std::fs::read(&keyfile).unwrap();

        assert!(first.contains("New wallet"));
        assert!(second.contains("already exists"), "got: {second}");
        assert_eq!(bytes1, bytes2, "the key file must be untouched on re-invoke");
        assert!(second.contains(&addr1), "must report the same address");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `/use` sets active; a missing wallet is refused, not silently accepted.
    #[cfg(feature = "sniper")]
    #[test]
    fn use_selects_only_existing_wallets() {
        let dir = tmp_dir("use");
        let b = store_bot(&dir);
        b.render_new_wallet(Some("alpha"));
        b.render_new_wallet(Some("beta"));

        assert!(b.render_use(Some("beta")).contains("Active wallet set to"));
        assert!(b.render_use(Some("ghost")).contains("no wallet named"));
        assert!(b.render_use(None).contains("Usage"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn balance_did_not_open_a_funds_moving_command() {
        for c in ["/withdraw", "/send", "/transfer", "/sweep", "/export", "/seed"] {
            assert_eq!(Command::parse(c), None, "{c} must not be a command");
        }
    }

    /// With no sniper attached there is no wallet, and the reply must say so
    /// rather than showing a zero balance.
    #[tokio::test]
    async fn balance_without_a_wallet_says_so() {
        let b = bot(&["1"], "").unwrap();
        let msg = b.render_balance().await;
        assert!(msg.contains("No trading wallet"), "got: {msg}");
        // Must not fabricate a number.
        assert!(!msg.contains("0.0000"), "got: {msg}");
    }

    #[test]
    fn html_escaping() {
        assert_eq!(escape_html("a<b>c"), "a&lt;b&gt;c");
        assert_eq!(escape_html("a&b"), "a&amp;b");
        // & first, so already-escaped output isn't double-escaped wrongly.
        assert_eq!(escape_html("<&>"), "&lt;&amp;&gt;");
    }

    #[test]
    fn uptime_formatting() {
        assert_eq!(format_uptime(Duration::from_secs(45)), "45s");
        assert_eq!(format_uptime(Duration::from_secs(125)), "2m 5s");
        assert_eq!(format_uptime(Duration::from_secs(3700)), "1h 1m");
    }

    #[test]
    fn truncate_is_char_safe() {
        // Byte slicing here would panic on a multi-byte boundary. Unauthorized
        // command text is attacker-controlled and gets logged through this.
        let s = "日本語のテキストです".repeat(10);
        let t = truncate(&s, 5);
        assert_eq!(t.chars().count(), 6); // 5 + ellipsis
        assert!(t.ends_with('…'));
    }
}
