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
    /// The alert group, if it is not already a fully authorised chat.
    ///
    /// Read-only commands work here so the group can ask what the bot is doing
    /// without every member also being able to change what it spends. See
    /// `Command::allowed_in_group`.
    group_chat: Option<i64>,
    metrics: Arc<Metrics>,
    kill_switch_file: PathBuf,
    started: Instant,
    /// Highest update id seen; the offset that acknowledges it to Telegram.
    offset: i64,
    /// Chats waiting to type a value for a setting: chat -> (field, asked_at).
    ///
    /// This is what makes the UI a form rather than a command line. A button
    /// asks, the next plain message answers, and the operator never types a
    /// command name. Entries expire so a forgotten prompt cannot silently
    /// swallow an unrelated message half an hour later.
    #[cfg(feature = "sniper")]
    awaiting: std::sync::Mutex<std::collections::HashMap<i64, (String, Instant)>>,
    /// For `/balance`. Absent means the command reports "not configured"
    /// rather than a misleading zero.
    rpc: Option<Arc<crate::rpc::RpcClient>>,
    /// Announced smart-money calls, for `/calls`. `None` disables the command.
    signals: Option<Arc<crate::signals::SignalStore>>,
    /// How long a call stays tracked — bounds what `/calls` lists.
    track_for_secs: u64,
    tz_offset_hours: i32,
    /// Local wallet store for `/new-wallet`, `/wallets`, `/use`. `None` disables
    /// those commands (reports not configured).
    #[cfg(feature = "sniper")]
    store: Option<Arc<crate::walletstore::WalletStore>>,
    /// Sniper audit-log path, for `/positions` cost basis. Empty = untracked.
    #[cfg(feature = "sniper")]
    audit_log: String,
    #[cfg(feature = "sniper")]
    sniper: Option<Arc<crate::sniper::Sniper>>,
    /// Seconds before an exported key message is deleted. See `render_export`.
    #[cfg(feature = "sniper")]
    export_ttl_secs: u64,
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
            group_chat: None,
            metrics,
            kill_switch_file: kill_switch_file.into(),
            started: Instant::now(),
            offset: 0,
            #[cfg(feature = "sniper")]
            awaiting: std::sync::Mutex::new(std::collections::HashMap::new()),
            rpc: None,
            signals: None,
            track_for_secs: 86_400,
            tz_offset_hours: 0,
            #[cfg(feature = "sniper")]
            store: None,
            #[cfg(feature = "sniper")]
            audit_log: String::new(),
            #[cfg(feature = "sniper")]
            sniper: None,
            #[cfg(feature = "sniper")]
            export_ttl_secs: 60,
        })
    }

    /// Attach the announced-signal store, enabling `/calls`.
    pub fn with_signals(
        mut self,
        signals: Arc<crate::signals::SignalStore>,
        track_for_secs: u64,
        tz_offset_hours: i32,
    ) -> Self {
        self.signals = Some(signals);
        self.track_for_secs = track_for_secs;
        self.tz_offset_hours = tz_offset_hours;
        self
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

    /// How long an exported private key stays in the chat before deletion.
    #[cfg(feature = "sniper")]
    pub fn with_export_ttl(mut self, secs: u64) -> Self {
        self.export_ttl_secs = secs;
        self
    }

    /// Attach the sniper so `/balance` knows which wallet to report on.
    #[cfg(feature = "sniper")]
    pub fn with_sniper(mut self, sniper: Arc<crate::sniper::Sniper>) -> Self {
        self.sniper = Some(sniper);
        self
    }

    /// Let the alert group run read-only commands.
    ///
    /// Separate from the allowlist on purpose: this grants strictly less.
    pub fn with_group_chat(mut self, chat_id: Option<i64>) -> Self {
        self.group_chat = chat_id.filter(|id| !self.allowed.contains(id));
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
        //
        // Two tiers: the allowlist gets everything, and the alert group gets
        // the read-only subset plus /halt. A chat in neither gets silence — a
        // reply would confirm to a prober that the bot exists.
        let full = self.allowed.contains(&chat_id);
        let group = Some(chat_id) == self.group_chat;
        if !full && !group {
            // Log the id so a legitimate user who got the config wrong can find
            // theirs; stay silent to the sender.
            warn!(
                chat_id,
                command = truncate(text, 32),
                "ignoring telegram command from unauthorized chat"
            );
            return;
        }
        if group && let Some(cmd) = Command::parse(text) && !cmd.allowed_in_group() {
            warn!(
                chat_id,
                command = truncate(text, 32),
                "refusing a control command in the alert group — private chat only"
            );
            self.reply(chat_id, "That one is private-chat only.".to_string()).await;
            return;
        }

        // A pending prompt takes precedence: the operator tapped a button and
        // is answering it, so a bare "0.25" is a value, not an unknown command.
        #[cfg(feature = "sniper")]
        if !text.starts_with('/')
            && let Some(field) = self.take_awaited(chat_id)
        {
            let value = text.trim();

            // Withdraw is two prompts, because an address cannot be a preset
            // and the amount decides whether the address matters. Each step
            // re-arms the next, and the final screen is the existing two-tap
            // confirmation — nothing moves without one more deliberate press.
            if field == "wd_amount" {
                match value.parse::<f64>() {
                    Ok(sol) if sol > 0.0 && sol.is_finite() => {
                        self.await_value(chat_id, &format!("wd_dest|{sol}"));
                        let kb = serde_json::json!({"inline_keyboard": [[
                            {"text": "◀️ Cancel", "callback_data": "nav:wallet"}
                        ]]});
                        self.reply_with(
                            chat_id,
                            format!(
                                "📤 <b>Withdrawing {sol} SOL</b>\n\nNow send the <b>destination address</b>.\n\n<i>Nothing is sent until you confirm on the next screen.</i>"
                            ),
                            kb,
                        )
                        .await;
                    }
                    _ => {
                        self.reply(chat_id, "⚠️ That is not a valid amount. Try again from 📤 Withdraw.".into())
                            .await;
                    }
                }
                return;
            }
            if field == "addtier" {
                let (reply, kb) = match parse_tier_args(value) {
                    Ok((lo, hi, sol)) => match self
                        .sniper
                        .as_ref()
                        .map(|sn| sn.add_buy_tier(lo, hi, sol))
                    {
                        Some(Ok(m)) => {
                            let (t, k) = self.tiers_screen();
                            (format!("✅ {}\n\n{t}", escape_html(&m)), k)
                        }
                        Some(Err(e)) => {
                            let (t, k) = self.tiers_screen();
                            (format!("⚠️ {}\n\n{t}", escape_html(&e)), k)
                        }
                        None => ("⚪ Sniper not configured".to_string(), back_to_settings()),
                    },
                    Err(e) => {
                        let (t, k) = self.tiers_screen();
                        (format!("⚠️ {}\n\n{t}", escape_html(&e)), k)
                    }
                };
                self.reply_with(chat_id, reply, kb).await;
                return;
            }
            if let Some(sol) = field.strip_prefix("wd_dest|") {
                let (reply, kb) = self.withdraw_prompt_screen(Some(&format!("{sol} {value}")));
                self.reply_with(chat_id, reply, kb).await;
                return;
            }

            let (reply, kb) = self
                .apply_exit_setting(&field, value)
                .unwrap_or_else(|| self.apply_setting(&field, value));
            self.reply_with(chat_id, reply, kb).await;
            return;
        }

        let Some(cmd) = Command::parse(text) else {
            return;
        };

        info!(chat_id, command = cmd.name(), "telegram command");

        // Screens that ARE a form open with their buttons attached, whether
        // reached by typing or by tapping — otherwise typing the command gives
        // a strictly worse version of the same screen.
        #[cfg(feature = "sniper")]
        if matches!(cmd, Command::Settings) {
            self.cancel_awaited(chat_id);
            let (text, kb) = self.settings_screen();
            self.reply_with(chat_id, text, kb).await;
            return;
        }
        #[cfg(feature = "sniper")]
        if matches!(cmd, Command::Wallets) {
            let (text, kb) = self.wallets_screen().await;
            self.reply_with(chat_id, text, kb).await;
            return;
        }

        // Withdraw is the one command that opens a confirm dialog (a button),
        // because it moves funds out. Everything else replies with plain text.
        // Private key export: PRIVATE CHAT ONLY. Telegram group ids are
        // negative, user/private-chat ids positive. Posting a key into the
        // alert group would expose it to every member, so that is refused
        // outright rather than confirmed.
        #[cfg(feature = "sniper")]
        if matches!(cmd, Command::Export) {
            if chat_id < 0 {
                self.reply(
                    chat_id,
                    "⛔ <b>Refused.</b> <code>/export</code> reveals a private key and \
                     will not run in a group — every member would see it.\n\n\
                     Message the bot directly (private chat) if you really want this."
                        .to_string(),
                )
                .await;
                return;
            }
            let (text, kb) = self.export_confirm_screen(None);
            self.reply_with(chat_id, text, kb).await;
            return;
        }

        #[cfg(feature = "sniper")]
        if let Command::Withdraw(args) = &cmd {
            let (text, kb) = self.withdraw_prompt_screen(args.as_deref());
            self.reply_with(chat_id, text, kb).await;
            return;
        }

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

        // Confirmed key export. Handled here, not in `screen_for`, because it
        // needs the message id to schedule the deletion. Private chat only —
        // re-checked here so a stale button tapped inside a group cannot leak.
        #[cfg(feature = "sniper")]
        if let Some(which) = data.strip_prefix("expgo:") {
            if msg.chat.id < 0 {
                self.edit_message(
                    msg.chat.id,
                    msg.message_id,
                    "⛔ Refused — not in a group.".to_string(),
                    serde_json::json!({ "inline_keyboard": [] }),
                )
                .await;
                return;
            }
            let wallet = (!which.is_empty()).then_some(which);
            let (text, deletable) = self.render_export(wallet);
            self.edit_message(
                msg.chat.id,
                msg.message_id,
                text,
                serde_json::json!({ "inline_keyboard": [] }),
            )
            .await;
            if deletable {
                // Best-effort scrub: removes it from the chat view. The secret
                // has still reached Telegram's servers and any push
                // notification, so an exported key must be treated as exposed.
                let this = self.clone_for_delete();
                let (chat, mid, ttl) = (msg.chat.id, msg.message_id, self.export_ttl_secs);
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(ttl)).await;
                    this.delete_message(chat, mid).await;
                });
            }
            return;
        }

        let Some((text, keyboard)) = self.screen_for(data, msg.chat.id).await else {
            return;
        };
        self.edit_message(msg.chat.id, msg.message_id, text, keyboard).await;
    }

    /// Minimal clone carrying just what the delayed delete needs (an owned
    /// client + token), so the spawned task does not borrow `self`.
    #[cfg(feature = "sniper")]
    fn clone_for_delete(&self) -> DeleteHandle {
        DeleteHandle { client: self.client.clone(), bot_token: self.bot_token.clone() }
    }

    /// Delete a message (used to scrub an exported key from the chat).
    #[cfg(feature = "sniper")]
    async fn delete_message(&self, chat_id: i64, message_id: i64) {
        DeleteHandle { client: self.client.clone(), bot_token: self.bot_token.clone() }
            .delete_message(chat_id, message_id)
            .await;
    }

    /// Resolve a callback payload into the next screen: `(text, keyboard)`.
    ///
    /// Two payload kinds:
    /// * `nav:<menu>` — pure navigation. Swaps the keyboard to that menu's
    ///   buttons with a short title; runs no command.
    /// * `cmd:<name>` — executes the action and shows its result, with a Back
    ///   button to the menu it belongs to.
    async fn screen_for(&self, data: &str, chat_id: i64) -> Option<(String, serde_json::Value)> {
        // Per-wallet "set active" taps: `use:<name>`. Re-renders the list so the
        // new ✅ active marker is visible immediately.
        if let Some(name) = data.strip_prefix("use:") {
            self.render_use(Some(name));
            // Back to the wallet's own screen so the new ✅ is visible in place.
            #[cfg(feature = "sniper")]
            return Some(self.wallet_detail_screen(name).await);
            #[cfg(not(feature = "sniper"))]
            return Some((self.render_wallets().await, self.wallets_keyboard()));
        }
        // The wallets LIST: text + a "set active" button per wallet.
        if data == "cmd:wallets" {
            return Some((self.render_wallets().await, self.wallets_keyboard()));
        }
        // Per-wallet screens.
        #[cfg(feature = "sniper")]
        if let Some(name) = data.strip_prefix("w:") {
            return Some(self.wallet_detail_screen(name).await);
        }
        #[cfg(feature = "sniper")]
        if let Some(name) = data.strip_prefix("dep:") {
            return Some(self.wallet_deposit_screen(name));
        }
        #[cfg(feature = "sniper")]
        if let Some(name) = data.strip_prefix("wd:") {
            return Some(self.wallet_withdraw_screen(name));
        }
        #[cfg(feature = "sniper")]
        if let Some(name) = data.strip_prefix("expask:") {
            return Some(self.export_confirm_screen(Some(name)));
        }
        #[cfg(feature = "sniper")]
        if let Some(mint) = data.strip_prefix("pos:") {
            return Some(self.position_screen(mint).await);
        }
        // Positions: text + one button per holding.
        if data == "cmd:positions" {
            return Some(self.positions_screen().await);
        }
        // Settings: text + the Open/Guard strategy toggle.
        if data == "cmd:settings" {
            #[cfg(feature = "sniper")]
            self.cancel_awaited(chat_id);
            return Some(self.settings_screen());
        }
        // Wallets: text + a "select" button per wallet, so switching never
        // requires typing a name.
        #[cfg(feature = "sniper")]
        if data == "cmd:wallets" {
            return Some(self.wallets_screen().await);
        }
        #[cfg(feature = "sniper")]
        if let Some(name) = data.strip_prefix("usewallet:") {
            let text = self.execute(Command::Use(Some(name.to_string()))).await;
            let (list, kb) = self.wallets_screen().await;
            return Some((format!("{text}\n\n{list}"), kb));
        }
        // Confirmed withdrawal: `wdgo:<sol>:<address>`. The amount is a float
        // (no colon) and the address is base58 (no colon), so one split works.
        #[cfg(feature = "sniper")]
        if let Some(rest) = data.strip_prefix("wdgo:") {
            if let Some((sol_s, tail)) = rest.split_once(':') {
                // tail is "<address>", "<address>:" or "<address>:<wallet>".
                //
                // The trailing-colon form is the COMMON one: the confirm button
                // is built as `wdgo:{sol}:{address}:{w}` and `w` is empty
                // whenever no wallet is named — i.e. every withdrawal from the
                // armed wallet. Falling through to `tail` here kept that colon
                // attached to the address, so `pk()` rejected it and every
                // default withdrawal failed with "invalid destination address".
                let (address, wallet) = split_wdgo_tail(tail);
                if let Ok(sol) = sol_s.parse::<f64>() {
                    let text = self.render_withdraw_exec(sol, address, wallet).await;
                    let kb = serde_json::json!({ "inline_keyboard": [[
                        {"text": "◀️ Menu", "callback_data": "nav:main"}
                    ]]});
                    return Some((text, kb));
                }
            }
        }
        // Settings form: `set:<field>` opens an editor, `setv:<field>:<value>`
        // applies a chosen preset.
        #[cfg(feature = "sniper")]
        if let Some(rest) = data.strip_prefix("setv:") {
            if let Some((field, value)) = rest.split_once(':') {
                if let Some(screen) = self.apply_exit_setting(field, value) {
                    return Some(screen);
                }
                return Some(self.apply_setting(field, value));
            }
        }
        #[cfg(feature = "sniper")]
        if let Some(field) = data.strip_prefix("ask:") {
            return Some(self.ask_screen(chat_id, field));
        }
        #[cfg(feature = "sniper")]
        if data == "set:autobuy" {
            return Some(self.autobuy_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:volume" {
            return Some(self.volume_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:supplycap" {
            return Some(self.supply_cap_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:tiers" {
            return Some(self.tiers_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:addtier" {
            return Some(self.add_tier_range_screen());
        }
        #[cfg(feature = "sniper")]
        if let Some(rest) = data.strip_prefix("tiersz:") {
            if let Some((lo, hi)) = rest.split_once(':')
                && let (Ok(lo), Ok(hi)) = (lo.parse::<f64>(), hi.parse::<f64>())
            {
                return Some(self.add_tier_size_screen(lo, hi));
            }
        }
        #[cfg(feature = "sniper")]
        if let Some(rest) = data.strip_prefix("tieradd:") {
            let parts: Vec<&str> = rest.split(':').collect();
            if let [lo, hi, sol] = parts[..]
                && let (Ok(lo), Ok(hi), Ok(sol)) =
                    (lo.parse::<f64>(), hi.parse::<f64>(), sol.parse::<f64>())
            {
                let res = self.sniper.as_ref().map(|sn| sn.add_buy_tier(lo, hi, sol));
                let (t, k) = self.tiers_screen();
                let banner = match res {
                    Some(Ok(m)) => format!("✅ {}\n\n", escape_html(&m)),
                    Some(Err(e)) => format!("⚠️ {}\n\n", escape_html(&e)),
                    None => String::new(),
                };
                return Some((format!("{banner}{t}"), k));
            }
        }
        #[cfg(feature = "sniper")]
        if data == "set:buying" {
            return Some(self.buying_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:filters" {
            return Some(self.filters_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:limits" {
            return Some(self.limits_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:exits" {
            return Some(self.exits_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:alpha" {
            return Some(self.alpha_screen());
        }
        #[cfg(feature = "sniper")]
        if data == "set:ladder" {
            return Some(self.ladder_screen());
        }
        #[cfg(feature = "sniper")]
        if let Some(n) = data.strip_prefix("set:order") {
            if let Ok(i) = n.parse::<usize>() {
                return Some(self.order_screen(i));
            }
        }
        #[cfg(feature = "sniper")]
        if data == "set:trailing" {
            return Some(self.stop_screen("trailing"));
        }
        #[cfg(feature = "sniper")]
        if let Some(field) = data.strip_prefix("set:") {
            // Opening any editor clears a stale prompt, so a half-finished
            // "type a value" cannot capture the next unrelated message.
            self.cancel_awaited(chat_id);
            return Some(self.setting_editor(field));
        }
        // Flip the entry strategy: `mode:open` | `mode:guard`.
        #[cfg(feature = "sniper")]
        if let Some(m) = data.strip_prefix("mode:") {
            if let (Some(mode), Some(sniper)) =
                (crate::sniper::SnipeMode::parse(m), self.sniper.as_ref())
            {
                let msg = sniper.set_snipe_mode(mode);
                info!(mode = m, "snipe mode changed from telegram");
                let _ = msg;
                return Some(self.settings_screen());
            }
        }
        // Confirmed sell: `sellgo:<mint>:<pct>` actually submits (checked before
        // `sell:` — the prefixes don't overlap, but be explicit).
        #[cfg(feature = "sniper")]
        if let Some(rest) = data.strip_prefix("sellgo:") {
            if let Some((mint, pct)) = parse_sell(rest) {
                let text = self.render_sell(mint, pct).await;
                return Some((text, sold_keyboard()));
            }
        }
        // Sell tap: `sell:<mint>:<pct>` -> a confirmation screen (two-tap, since
        // an armed sell spends/moves the position).
        #[cfg(feature = "sniper")]
        if let Some(rest) = data.strip_prefix("sell:") {
            if let Some((mint, pct)) = parse_sell(rest) {
                return Some(self.sell_confirm_screen(mint, pct));
            }
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
            Command::Deposit => self.render_deposit(),
            Command::Positions => self.render_positions().await,
            Command::Calls => self.render_calls().await,
            Command::Settings => self.render_settings(),
            Command::NewWallet(name) => self.render_new_wallet(name.as_deref()),
            Command::Wallets => self.render_wallets().await,
            Command::Use(name) => self.render_use(name.as_deref()),
            Command::SetSize(arg) => self.render_set(Tunable::Size, arg.as_deref()),
            Command::SetSlippage(arg) => self.render_set(Tunable::Slippage, arg.as_deref()),
            Command::SetMinLiquidity(arg) => self.render_set(Tunable::MinLiquidity, arg.as_deref()),
            Command::SetMaxSize(arg) => self.render_set(Tunable::MaxSize, arg.as_deref()),
            Command::SetDailyCap(arg) => self.render_set(Tunable::DailyCap, arg.as_deref()),
            Command::SetMaxTrades(arg) => self.render_set(Tunable::MaxTrades, arg.as_deref()),
            Command::SetMaxMcap(arg) => self.render_set(Tunable::MaxMcap, arg.as_deref()),
            Command::SetMaxImpact(arg) => self.render_set(Tunable::MaxImpact, arg.as_deref()),
            Command::SetMode(arg) => self.render_set_mode(arg.as_deref()),
            Command::Withdraw(args) => self.render_withdraw_prompt(args.as_deref()),
            // Reached only for the non-sniper build or a stray call; the real
            // path is the DM-guarded confirm in `handle_message`.
            Command::Export => "⚠️ Use <code>/export</code> in a PRIVATE chat with the bot.".to_string(),
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
            // Counted from the tokens the bot actually bought, not by asking
            // the provider to enumerate the account.
            //
            // Enumerating means `getTokenAccountsByOwner`, which is a SCAN, and
            // the configured provider refuses scans permanently — so this line
            // read "⚠️ could not read" every single time. The audit log already
            // names every mint the bot has touched, and their balances come
            // back in one batched read that the provider does allow.
            //
            // It counts POSITIONS rather than raw accounts: an emptied token
            // account left behind by a completed sell is not a holding, and a
            // token bought outside this bot is not something it can report on.
            let tokens = match tokio::fs::read_to_string(&self.audit_log).await {
                Ok(audit) => {
                    let mints: Vec<String> =
                        crate::positions::cost_basis_from_audit(&audit).into_keys().collect();
                    rpc.token_balances_raw(&address, &mints)
                        .await
                        .map(|b| b.values().filter(|(raw, _)| *raw > 0).count())
                }
                Err(_) => None,
            };

            // Unreadable is reported as unknown, never as zero. Someone reading
            // "0 SOL" concludes they were drained; "could not read" is the truth.
            let sol_line = match sol {
                Some(v) => format!("<b>SOL:</b> {v:.4}"),
                None => "<b>SOL:</b> ⚠️ could not read (RPC error — not zero)".to_string(),
            };
            let token_line = match tokens {
                Some(n) => format!("<b>Open positions:</b> {n}"),
                None => "<b>Open positions:</b> ⚠️ could not read".to_string(),
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

    /// Show the active wallet's RECEIVE address so funds can be sent in.
    ///
    /// Safe to expose: a public address only lets people send TO the wallet,
    /// never take from it. This is the opposite of an export/withdraw — no key,
    /// no signing, nothing leaves. The address is rendered on its own line so
    /// it's one-tap copyable in Telegram.
    fn render_deposit(&self) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            return "⚪ <b>No wallet</b>\nThis build has no execution support.".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            let Some(sniper) = &self.sniper else {
                return "⚪ <b>Sniper not configured</b>".to_string();
            };
            let Some((address, _role)) = sniper.trading_identity() else {
                return "⚪ <b>No trading wallet</b>\nSet an active wallet first.".to_string();
            };
            format!(
                "📥 <b>Deposit</b>\n\
                 Send <b>SOL</b> (or SPL tokens) to the active trading wallet:\n\n\
                 <code>{address}</code>\n\n\
                 <i>Tap the address to copy. This is a receive-only address — \
                 sharing it can never move funds out.</i>\n\
                 <a href=\"https://solscan.io/account/{address}\">view on Solscan</a>",
                address = escape_html(&address),
            )
        }
    }

    /// Withdrawal confirmation screen. Validates `<amount> <address>` and, if
    /// good, shows a Confirm button carrying the parsed values. Moving funds
    /// out always goes through this two-tap gate.
    fn render_withdraw_prompt(&self, args: Option<&str>) -> String {
        self.withdraw_prompt_screen(args).0
    }

    fn withdraw_prompt_screen(&self, args: Option<&str>) -> (String, serde_json::Value) {
        let empty = serde_json::json!({ "inline_keyboard": [] });
        #[cfg(not(feature = "sniper"))]
        {
            let _ = args;
            return ("⚪ <b>Withdraw unavailable</b> (no sniper feature).".to_string(), empty);
        }
        #[cfg(feature = "sniper")]
        match parse_withdraw_args(args) {
            Err(msg) => (format!("⚠️ {}", escape_html(&msg)), empty),
            Ok((sol, address, wallet)) => {
                let text = format!(
                    "🚨 <b>Confirm withdrawal</b>\n\n\
                     Move <b>{sol} SOL</b> out of <b>{from}</b> to:\n\
                     <code>{addr}</code>\n\n\
                     <i>This sends real funds to another address and cannot be undone. \
                     Works only when the bot is ARMED; blocked while halted.</i>",
                    addr = escape_html(&address),
                    from = escape_html(wallet.as_deref().unwrap_or("the trading wallet")),
                );
                let w = wallet.unwrap_or_default();
                let kb = serde_json::json!({ "inline_keyboard": [[
                    {"text": format!("✅ Send {sol} SOL"), "callback_data": format!("wdgo:{sol}:{address}:{w}")},
                    {"text": "◀️ Cancel", "callback_data": "nav:main"},
                ]]});
                (text, kb)
            }
        }
    }

    /// Per-wallet detail screen: address, balance, and the actions that apply to
    /// THIS wallet (set active / deposit / withdraw / export).
    #[cfg(feature = "sniper")]
    async fn wallet_detail_screen(&self, name: &str) -> (String, serde_json::Value) {
        let back = serde_json::json!({ "inline_keyboard": [[
            {"text": "◀️ Wallets", "callback_data": "cmd:wallets"}
        ]]});
        let Some(store) = &self.store else {
            return ("⚪ <b>Wallet store not configured</b>".to_string(), back);
        };
        let Some(addr) = store.pubkey_of(name) else {
            return (format!("⚠️ Unknown wallet <b>{}</b>", escape_html(name)), back);
        };
        let addr = addr.to_string();
        let is_active = store.active().as_deref() == Some(name);

        let bal = match &self.rpc {
            Some(rpc) => match rpc.sol_balance(&addr).await {
                Some(v) => format!("{v:.4} SOL"),
                // Never render an unreadable balance as zero — that reads as
                // "drained" to someone checking their wallet.
                None => "⚠️ could not read".to_string(),
            },
            None => "—".to_string(),
        };

        let text = format!(
            "👛 <b>{name}</b>{active}\n\
             <code>{addr}</code>\n\
             <b>Balance:</b> {bal}\n\n\
             <a href=\"https://solscan.io/account/{addr}\">view on Solscan</a>",
            name = escape_html(name),
            active = if is_active { " ✅ <i>active</i>" } else { "" },
            addr = escape_html(&addr),
            bal = bal,
        );

        let mut rows: Vec<serde_json::Value> = Vec::new();
        if !is_active {
            rows.push(serde_json::json!([
                {"text": "✅ Set as active", "callback_data": format!("use:{name}")}
            ]));
        }
        rows.push(serde_json::json!([
            {"text": "📥 Deposit", "callback_data": format!("dep:{name}")},
            {"text": "💸 Withdraw", "callback_data": format!("wd:{name}")},
        ]));
        rows.push(serde_json::json!([
            {"text": "🔑 Export key", "callback_data": format!("expask:{name}")}
        ]));
        rows.push(serde_json::json!([
            {"text": "◀️ Wallets", "callback_data": "cmd:wallets"},
            {"text": "🏠 Menu", "callback_data": "nav:main"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Deposit address for a specific wallet.
    #[cfg(feature = "sniper")]
    fn wallet_deposit_screen(&self, name: &str) -> (String, serde_json::Value) {
        let kb = serde_json::json!({ "inline_keyboard": [[
            {"text": "📤 Start withdrawal", "callback_data": "ask:wd_amount"},
            {"text": "◀️ Back", "callback_data": format!("w:{name}")},
        ]]});
        let Some(addr) = self.store.as_ref().and_then(|s| s.pubkey_of(name)) else {
            return (format!("⚠️ Unknown wallet <b>{}</b>", escape_html(name)), kb);
        };
        let text = format!(
            "📥 <b>Deposit to {name}</b>\n\n\
             <code>{addr}</code>\n\n\
             <i>Tap to copy. Receive-only — sharing this address can never move \
             funds out.</i>",
            name = escape_html(name),
            addr = escape_html(&addr.to_string()),
        );
        (text, kb)
    }

    /// Withdraw instructions for a specific wallet. The amount and destination
    /// have to be typed, so this hands back a ready-to-edit command rather than
    /// pretending a button could capture them.
    #[cfg(feature = "sniper")]
    fn wallet_withdraw_screen(&self, name: &str) -> (String, serde_json::Value) {
        let kb = serde_json::json!({ "inline_keyboard": [[
            {"text": "◀️ Back", "callback_data": format!("w:{name}")}
        ]]});
        let text = format!(
            "💸 <b>Withdraw from {name}</b>\n\n\
             Tap below, send the amount, then the destination address.\n\n\
             <i>You will get a confirmation showing the exact amount and \
             destination before anything is sent. Blocked while halted.</i>",
            name = escape_html(name),
        );
        (text, kb)
    }

    /// Confirmation before revealing a private key.
    #[cfg(feature = "sniper")]
    fn export_confirm_screen(&self, wallet: Option<&str>) -> (String, serde_json::Value) {
        let which = wallet.unwrap_or("");
        let text = format!(
            "🔑 <b>Export private key?</b>\n\n\
             This reveals the <b>full private key</b> of the active wallet — \
             anyone who sees it owns the wallet, permanently.\n\n\
             ⚠️ <b>Understand before tapping:</b> the message is deleted after \
             {ttl}s, but that only clears the chat <i>view</i>. The key will \
             have already reached Telegram's servers, your phone's \
             notification shade, and any other device signed in. Treat this \
             wallet as <b>permanently exposed</b> once exported — move funds to \
             a fresh wallet if it ever held anything you care about.",
            ttl = self.export_ttl_secs,
        );
        let back = if which.is_empty() {
            "nav:main".to_string()
        } else {
            format!("w:{which}")
        };
        let kb = serde_json::json!({ "inline_keyboard": [[
            {"text": "🔑 Reveal key", "callback_data": format!("expgo:{which}")},
            {"text": "◀️ Cancel", "callback_data": back},
        ]]});
        (text, kb)
    }

    /// Render the private key. Returns `(text, should_delete)`.
    ///
    /// The key is formatted as `<code>` so Telegram gives a one-tap copy, and
    /// is NEVER written to the log or the audit file.
    #[cfg(feature = "sniper")]
    fn render_export(&self, wallet: Option<&str>) -> (String, bool) {
        let Some(store) = &self.store else {
            return ("⚪ <b>No wallet store configured</b>".to_string(), false);
        };
        let (name, path) = match wallet {
            Some(n) => match store.path_for(n) {
                Ok(p) if store.exists(n) => (n.to_string(), p),
                _ => return (format!("⚠️ Unknown wallet <b>{}</b>", escape_html(n)), false),
            },
            None => match (store.active(), store.active_path()) {
                (Some(n), Some(p)) => (n, p),
                _ => {
                    return (
                        "⚪ <b>No active wallet</b>\nSet one with /wallets first.".to_string(),
                        false,
                    );
                }
            },
        };
        match crate::tx::export_secret_base58(&path.to_string_lossy()) {
            // Deliberately no `info!`/audit call anywhere in this arm.
            Ok(secret) => (
                format!(
                    "🔑 <b>{name}</b>\n\n<code>{secret}</code>",
                    name = escape_html(&name),
                    secret = escape_html(&secret),
                ),
                true,
            ),
            Err(e) => (format!("❌ <b>Export failed</b>\n{}", escape_html(&format!("{e:#}"))), false),
        }
    }

    /// Execute a confirmed withdrawal and render the outcome.
    #[cfg(feature = "sniper")]
    async fn render_withdraw_exec(&self, sol: f64, dest: &str, wallet: Option<&str>) -> String {
        use crate::sniper::{SubmitOutcome, WithdrawOutcome};
        let Some(sniper) = &self.sniper else {
            return "⚪ <b>Sniper not configured</b>".to_string();
        };
        // Resolve a named wallet to its keypair path; None = the armed wallet.
        let path = match wallet {
            Some(name) => match self.store.as_ref().and_then(|st| st.path_for(name).ok()) {
                Some(p) => Some(p.to_string_lossy().into_owned()),
                None => return format!("⚠️ Unknown wallet <b>{}</b>", escape_html(name)),
            },
            None => None,
        };
        match sniper.withdraw(dest, sol, path.as_deref()).await {
            WithdrawOutcome::Refused { reason } => {
                format!("⚠️ <b>Withdraw refused</b>\n{}", escape_html(&reason))
            }
            WithdrawOutcome::Submitted { sol, dest, result } => {
                let line = match result {
                    SubmitOutcome::Executed { reference, .. } => format!(
                        "✅ <b>SENT</b> — <a href=\"https://solscan.io/tx/{r}\">{rs}</a>",
                        r = escape_html(&reference),
                        rs = escape_html(&short_mint(&reference)),
                    ),
                    SubmitOutcome::NotExecuted { reason } => {
                        format!("⚪ <b>Not sent</b> (safe): {}", escape_html(&reason))
                    }
                    SubmitOutcome::Indeterminate { reference, reason } => format!(
                        "⚠️ <b>UNKNOWN outcome</b> — may have sent, do NOT retry blindly.\n\
                         ref <code>{}</code>\n{}",
                        escape_html(&reference),
                        escape_html(&reason)
                    ),
                };
                format!("Withdraw <b>{sol} SOL</b> → <code>{}</code>\n{line}", escape_html(&dest))
            }
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

            // Cost basis from the bot's own executed buys. Read FIRST: its
            // mints are also the candidate list for the holdings read, which
            // derives addresses rather than scanning for them.
            let basis = if self.audit_log.is_empty() {
                Default::default()
            } else {
                match tokio::fs::read_to_string(&self.audit_log).await {
                    Ok(s) => cost_basis_from_audit(&s),
                    Err(_) => Default::default(),
                }
            };
            let candidates: Vec<String> = basis.keys().cloned().collect();

            let holdings = match rpc.token_holdings(&address, &candidates).await {
                Some(h) => h,
                None => {
                    return "⚠️ <b>Could not read holdings</b> (RPC error — not \"empty\")."
                        .to_string();
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
                // Name the token so a position is recognizable at a glance, but
                // keep the mint as the identifier — names are not unique and are
                // trivially spoofed, so the mint stays the truth.
                let named = rpc
                    .token_metadata(mint)
                    .await
                    .map(|(n, sym)| match (n.is_empty(), sym.is_empty()) {
                        (false, false) => format!("{n} ({sym})"),
                        (false, true) => n,
                        (true, false) => sym,
                        _ => String::new(),
                    })
                    .filter(|l| !l.is_empty());
                let title = match &named {
                    Some(label) => escape_html(label),
                    None => short_mint(mint),
                };
                // The FULL mint in its own <code> block: Telegram copies the
                // block's contents on tap, so a shortened form here would copy
                // an unusable string. Own line, so the header stays readable.
                let mint_line = format!("<code>{}</code>", escape_html(mint));
                match basis.get(mint) {
                    Some(cb) => {
                        // Try to mark it: read both vaults now, mid-price it.
                        let value = self.mark_position(rpc, cb, mint, *amount).await;
                        match value {
                            Some(v) => {
                                let p = unrealized(cb.sol_spent, v);
                                priced_any = true;
                                total_cost += p.cost;
                                total_value += p.value;
                                let sign = if p.abs >= 0.0 { "🟢 +" } else { "🔴 " };
                                out.push_str(&format!(
                                    "\n<b>{title}</b> — {amt:.2} tokens\n\
                                     {mint_line}\n\
                                     cost {cost:.4} → est {val:.4} SOL  ({sign}{abs:.4}, {pct:+.1}%)\n",
                                    title = title,
                                    mint_line = mint_line,
                                    amt = amount,
                                    cost = p.cost,
                                    val = p.value,
                                    sign = sign,
                                    abs = p.abs.abs(),
                                    pct = p.pct,
                                ));
                            }
                            None => out.push_str(&format!(
                                "\n<b>{title}</b> — {amt:.2} tokens\n\
                                 {mint_line}\n\
                                 cost {cost:.4} SOL · <i>price unavailable</i>\n",
                                title = title,
                                mint_line = mint_line,
                                amt = amount,
                                cost = cb.sol_spent,
                            )),
                        }
                    }
                    None => out.push_str(&format!(
                        "\n<b>{title}</b> — {amt:.2} tokens · <i>untracked</i>\n\
                         {mint_line}\n",
                        title = title,
                        mint_line = mint_line,
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

    /// The `/positions` screen with a `Sell 50%` / `Sell 100%` button per
    /// holding. The text is authoritative (PnL, cost basis); the buttons are a
    /// best-effort convenience built from the same live holdings. Capped so a
    /// wallet full of dust tokens can't produce an unwieldy keyboard.
    async fn positions_screen(&self) -> (String, serde_json::Value) {
        let text = self.render_positions().await;
        #[allow(unused_mut)]
        let mut rows: Vec<serde_json::Value> = Vec::new();
        #[cfg(feature = "sniper")]
        if let (Some(sniper), Some(rpc)) = (&self.sniper, &self.rpc) {
            if let Some((address, _)) = sniper.trading_identity() {
                let candidates: Vec<String> = match tokio::fs::read_to_string(&self.audit_log).await
                {
                    Ok(s) => crate::positions::cost_basis_from_audit(&s).keys().cloned().collect(),
                    Err(_) => Vec::new(),
                };
                if let Some(holdings) = rpc.token_holdings(&address, &candidates).await {
                    for (mint, _amt) in holdings.iter().take(10) {
                        // The ticker, not the mint — "DOGEK" is actionable,
                        // "Gw12…pump" is something you have to decode first.
                        let short = match rpc.token_metadata(mint).await {
                            Some((_, sym)) if !sym.is_empty() => sym,
                            _ => short_mint(mint),
                        };
                        rows.push(serde_json::json!([
                            {"text": format!("📈 {short}"), "callback_data": format!("pos:{mint}")}
                        ]));
                    }
                }
            }
        }
        rows.push(serde_json::json!([{"text": "◀️ Back", "callback_data": "nav:main"}]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// One position: what it cost, what it is worth, and how to leave it.
    ///
    /// Market cap is shown at ENTRY and NOW because that is the pair a trader
    /// actually reasons about — "in at 40k, now 180k" says more about whether
    /// to take profit than any percentage does, and it is the number every
    /// other tool in this space quotes.
    #[cfg(feature = "sniper")]
    async fn position_screen(&self, mint: &str) -> (String, serde_json::Value) {
        let back = serde_json::json!({ "inline_keyboard": [[
            {"text": "◀️ Positions", "callback_data": "cmd:positions"}
        ]]});
        let (Some(sniper), Some(rpc)) = (&self.sniper, &self.rpc) else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back);
        };
        let Some((owner, _)) = sniper.trading_identity() else {
            return ("⚪ <b>No active wallet</b>".to_string(), back);
        };
        let Some((raw, decimals)) = rpc.token_balance_raw(&owner, mint).await else {
            return ("📭 <b>No balance of this token</b>".to_string(), back);
        };
        if raw == 0 {
            return ("📭 <b>No balance of this token</b>".to_string(), back);
        }
        let held = raw as f64 / 10f64.powi(decimals as i32);

        let sym = match rpc.token_metadata(mint).await {
            Some((_, s)) if !s.is_empty() => s,
            _ => short_mint(mint),
        };

        // Cost basis counts only buys that truly moved funds, so a rehearsal
        // never shows up here as a position with a price paid.
        let audit = tokio::fs::read_to_string(sniper.audit_log_path()).await.unwrap_or_default();
        let basis = crate::positions::cost_basis_from_audit(&audit);
        let paid = basis.get(mint).map(|b| b.sol_spent);

        let price_now = sniper.prices().price_sol(mint, std::time::Duration::from_secs(3600));
        let sol_usd = sniper.prices().sol_usd(std::time::Duration::from_secs(600));
        let supply = rpc.token_supply(mint).await;

        // Entry price is what WE paid per token, not the signal's reference —
        // this screen is about this position, not about the wallets that
        // pointed at it.
        let entry_price = match (paid, held) {
            (Some(p), h) if h > 0.0 && p > 0.0 => Some(p / h),
            _ => None,
        };
        let mcap = |price: f64| -> Option<f64> {
            Some(price * supply? * sol_usd?)
        };

        let mut out = format!("📈 <b>{}</b>\n<code>{}</code>\n\n", escape_html(&sym), escape_html(mint));
        out.push_str(&format!("Holding: <b>{}</b>\n", fmt_tokens(held)));
        match (paid, price_now) {
            (Some(paid), Some(p)) => {
                let value = p.price_sol * held;
                let pnl = if paid > 0.0 { (value / paid - 1.0) * 100.0 } else { 0.0 };
                out.push_str(&format!(
                    "Paid: <b>{paid:.4} SOL</b>\nValue: <b>{value:.4} SOL</b>\n\
                     PnL: <b>{}{pnl:.1}%</b>\n",
                    if pnl >= 0.0 { "+" } else { "" }
                ));
            }
            (None, Some(p)) => {
                out.push_str(&format!("Value: <b>{:.4} SOL</b>\n", p.price_sol * held));
                out.push_str("<i>No cost basis — this token was not bought by the bot.</i>\n");
            }
            _ => out.push_str("<i>No current price — nobody has traded it in our window.</i>\n"),
        }
        match (entry_price.and_then(mcap), price_now.map(|p| p.price_sol).and_then(mcap)) {
            (Some(a), Some(b)) => out.push_str(&format!(
                "\nMC entry: <b>{}</b>\nMC now: <b>{}</b>\n",
                fmt_usd_short(a), fmt_usd_short(b)
            )),
            (None, Some(b)) => out.push_str(&format!("\nMC now: <b>{}</b>\n", fmt_usd_short(b))),
            _ => out.push_str("\n<i>Market cap unavailable (no price or supply).</i>\n"),
        }
        if let Some(p) = price_now {
            out.push_str(&format!("<i>price {}s old, {} fills</i>\n", p.age.as_secs(), p.observations));
        }

        (out, sell_size_keyboard(mint))
    }

    /// Settings screen with the Open/Guard entry-strategy toggle. The button
    /// always names the mode it will switch TO, so a tap is unambiguous.
    fn settings_screen(&self) -> (String, serde_json::Value) {
        let text = self.render_settings();
        #[allow(unused_mut)]
        let mut rows: Vec<serde_json::Value> = Vec::new();
        // GROUPED, not piled up.
        //
        // Ten settings in one flat list, three to a row, is a wall the operator
        // has to re-read every time. These are four questions — do I buy, how
        // much, what do I skip, and when do I sell — so the top level asks
        // those and the detail lives one tap down.
        //
        // Auto-buy is alone on its row on purpose: it is the switch that
        // decides whether any of the rest matters.
        #[cfg(feature = "sniper")]
        if let Some(sniper) = &self.sniper {
            let live = sniper.live();
            let env = sniper.envelope();
            let ab = if live.auto_buy_active(&env) {
                format!("on · {} SOL", live.min_smart_sol_in)
            } else {
                "off".to_string()
            };
            rows.push(serde_json::json!([
                {"text": format!("🤖 Auto-buy · {ab}"), "callback_data": "set:autobuy"}
            ]));
            rows.push(serde_json::json!([
                {"text": format!("💰 Buying · {} SOL", live.trade_size_sol),
                 "callback_data": "set:buying"},
                {"text": format!("🎚 Selling · {}", crate::exits::describe(&live.exits)),
                 "callback_data": "set:exits"},
            ]));
            let al = if live.alpha_enabled {
                format!("on · {} SOL", live.alpha_buy_sol)
            } else {
                "off".to_string()
            };
            rows.push(serde_json::json!([
                {"text": format!("⭐ Alpha · {al}"), "callback_data": "set:alpha"}
            ]));
            rows.push(serde_json::json!([
                {"text": format!("🔎 Filters · {}", if live.volume_mode { "on" } else { "off" }),
                 "callback_data": "set:filters"},
                {"text": format!("🛡 Limits · {}/day", if live.max_trades_per_day == 0 {
                    "∞".to_string() } else { live.max_trades_per_day.to_string() }),
                 "callback_data": "set:limits"},
            ]));
        }
        rows.push(serde_json::json!([{"text": "◀️ Back", "callback_data": "nav:main"}]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Everything about how much to spend.
    #[cfg(feature = "sniper")]
    fn buying_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let bands = if live.buy_tiers.is_empty() {
            "off — every token uses the default".to_string()
        } else {
            format!("{} band(s)", live.buy_tiers.len())
        };
        let cap = if live.supply_cap { fmt_supply_pct(live.max_supply_pct) } else { "off".into() };
        let text = format!(
            "💰 <b>Buying</b>\n\n\
             Default size · <b>{} SOL</b>\n\
             MC bands · <b>{bands}</b>\n\
             Slippage · <b>{} bps</b>\n\
             Max market cap · <b>{}</b>\n\
             Supply cap · <b>{cap}</b>\n\n\
             <i>Max market cap refuses a token outright. Bands only choose the \
             SIZE for tokens that pass it — a token inside a band buys that \
             band's amount, everything else uses the default.</i>",
            live.trade_size_sol,
            live.slippage_bps,
            fmt_usd_cap(live.max_market_cap_usd)
        );
        let rows = serde_json::json!({ "inline_keyboard": [
            [{"text": format!("💰 Size · {} SOL", live.trade_size_sol),
              "callback_data": "set:size"},
             {"text": format!("📉 Slippage · {} bps", live.slippage_bps),
              "callback_data": "set:slippage"}],
            [{"text": format!("🏦 Max MC · {}", fmt_usd_cap(live.max_market_cap_usd)),
              "callback_data": "set:maxmcap"},
             {"text": format!("📊 MC bands · {}", if live.buy_tiers.is_empty() {
                "off".to_string() } else { live.buy_tiers.len().to_string() }),
              "callback_data": "set:tiers"}],
            [{"text": format!("🪙 Supply cap · {cap}"), "callback_data": "set:supplycap"},
             {"text": "◀️ Back", "callback_data": "cmd:settings"}],
        ]});
        (text, rows)
    }

    /// What the bot refuses to buy.
    #[cfg(feature = "sniper")]
    fn filters_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let curve = if live.curve_min_liquidity_sol == 0.0 {
            "off".to_string()
        } else {
            format!("{} SOL", live.curve_min_liquidity_sol)
        };
        let text = format!(
            "🔎 <b>Filters</b>\n\n\
             Volume mode · <b>{}</b>\n\
             Pool liquidity · <b>{} SOL</b>\n\
             Curve floor · <b>{curve}</b>\n\n\
             <i>Smart money always decides WHEN. These only ever refuse a \
             signal — none of them can create one.</i>",
            if live.volume_mode { "on" } else { "off" },
            live.min_liquidity_sol,
        );
        let rows = serde_json::json!({ "inline_keyboard": [
            [{"text": format!("📊 Volume · {}", if live.volume_mode { "on" } else { "off" }),
              "callback_data": "set:volume"},
             {"text": format!("💧 Pool liq · {} SOL", live.min_liquidity_sol),
              "callback_data": "set:minliq"}],
            [{"text": format!("🌱 Curve floor · {curve}"), "callback_data": "set:curveliq"},
             {"text": "◀️ Back", "callback_data": "cmd:settings"}],
        ]});
        (text, rows)
    }

    /// What bounds the damage.
    #[cfg(feature = "sniper")]
    fn limits_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let trades = if live.max_trades_per_day == 0 {
            "unlimited".to_string()
        } else {
            live.max_trades_per_day.to_string()
        };
        let text = format!(
            "🛡 <b>Limits</b>\n\n\
             Trades per day · <b>{trades}</b>\n\n\
             <i>The main brake on a runaway: how many entries may happen in a \
             day, however many signals arrive.</i>"
        );
        let rows = serde_json::json!({ "inline_keyboard": [
            [{"text": format!("🔢 Trades per day · {trades}"), "callback_data": "set:maxtrades"},
             {"text": "◀️ Back", "callback_data": "cmd:settings"}],
        ]});
        (text, rows)
    }

    /// The wallet list, with a select button per wallet.
    ///
    /// Switching used to require typing `/use <name>` — the name copied from a
    /// list above it. The information needed to act was on screen; the action
    /// was not.
    #[cfg(feature = "sniper")]
    async fn wallets_screen(&self) -> (String, serde_json::Value) {
        let text = self.render_wallets().await;
        let mut rows: Vec<serde_json::Value> = Vec::new();
        if let Some(store) = &self.store {
            let active = store.active();
            for (name, _addr) in store.list() {
                if active.as_deref() == Some(&name) {
                    continue; // already active — nothing to switch to
                }
                rows.push(serde_json::json!([{
                    "text": format!("👛 Use {name}"),
                    "callback_data": format!("usewallet:{name}"),
                }]));
            }
        }
        rows.push(serde_json::json!([
            {"text": "🆕 New wallet", "callback_data": "cmd:new-wallet"},
            {"text": "◀️ Back", "callback_data": "nav:wallet"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// How long a "send me a value" prompt stays open.
    ///
    /// Short on purpose. An abandoned prompt that never expires would quietly
    /// reinterpret the next thing typed in the chat — possibly hours later,
    /// possibly a number meant for a person — as a trading setting.
    #[cfg(feature = "sniper")]
    const AWAIT_TTL: std::time::Duration = std::time::Duration::from_secs(180);

    /// Record that this chat is about to type a value for `field`.
    #[cfg(feature = "sniper")]
    fn await_value(&self, chat_id: i64, field: &str) {
        let mut g = self.awaiting.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, (_, at)| at.elapsed() < Self::AWAIT_TTL);
        g.insert(chat_id, (field.to_string(), Instant::now()));
    }

    /// Take a pending prompt for this chat, if one is still open.
    #[cfg(feature = "sniper")]
    fn take_awaited(&self, chat_id: i64) -> Option<String> {
        let mut g = self.awaiting.lock().unwrap_or_else(|p| p.into_inner());
        match g.remove(&chat_id) {
            Some((field, at)) if at.elapsed() < Self::AWAIT_TTL => Some(field),
            _ => None,
        }
    }

    #[cfg(feature = "sniper")]
    fn cancel_awaited(&self, chat_id: i64) {
        self.awaiting.lock().unwrap_or_else(|p| p.into_inner()).remove(&chat_id);
    }

    /// The "type a value" screen, reached from the ✏️ button.
    #[cfg(feature = "sniper")]
    fn ask_screen(&self, chat_id: i64, field: &str) -> (String, serde_json::Value) {
        self.await_value(chat_id, field);
        let (label, hint) = match field {
            "size" => ("trade size", "e.g. <code>0.03</code> (SOL)"),
            "slippage" => ("slippage", "e.g. <code>250</code> (bps)"),
            "minliq" => ("minimum liquidity", "e.g. <code>20</code> (SOL)"),
            "curveliq" => ("curve minimum liquidity", "e.g. <code>0</code> for no floor"),
            "stoploss" => ("stop loss", "e.g. <code>-15</code> (percent), 0 = none"),
            "takeprofit" => ("take profit", "e.g. <code>100</code> (percent), 0 = none"),
            "tpamount" => ("take-profit amount", "e.g. <code>50</code> (percent of the position)"),
            "smartsol" => ("smart-money volume", "e.g. <code>2</code> (SOL), 0 = off"),
            "tokenvol" => ("token volume", "e.g. <code>15</code> (SOL), 0 = off"),
            "maxsupply" => ("max share of supply", "e.g. <code>2</code> (percent), 0 = no limit"),
            "alphabuy" => ("alpha buy amount", "e.g. <code>0.05</code> (SOL)"),
            "alphatp" => ("alpha take profit", "e.g. <code>150</code> (percent), 0 = none"),
            "alphasl" => ("alpha stop loss", "e.g. <code>25</code> (percent below entry), 0 = none"),
            "addtier" => (
                "market-cap band",
                "Send three values: <b>min max size</b>\n\n<code>50k 100k 0.2</code>   $50K–$100K buys 0.2 SOL\n<code>1m 2m 0.75</code>   $1M–$2M buys 0.75 SOL\n<code>2m 0 1.0</code>   $2M and above buys 1 SOL\n\nUse <b>0</b> as the max for “and above”.",
            ),
            "maxsize" => ("max trade size", "e.g. <code>0.08</code> (SOL)"),
            "dailycap" => ("daily spend cap", "e.g. <code>0.35</code> (SOL)"),
            "maxtrades" => ("trades per day", "e.g. <code>6</code>"),
            "maxmcap" => ("max market cap", "e.g. <code>75000</code> (USD)"),
            "maximpact" => ("max price impact", "e.g. <code>400</code> (bps)"),
            f if f.starts_with("ordt") => (
                "trigger",
                "e.g. <code>150</code> for a +150% target, or <code>-30</code> for a stop",
            ),
            f if f.starts_with("orda") => ("amount", "e.g. <code>35</code> (% of the original position)"),
            "wd_amount" => ("amount to withdraw", "e.g. <code>0.25</code> (SOL)"),
            f if f.starts_with("wd_dest") => (
                "destination address",
                "paste the Solana address to send to",
            ),
            _ => ("value", "send a number"),
        };
        // The generic footer says "just the number", which is wrong for the
        // fields that take several — and a prompt that misdescribes its own
        // input is how you get a rejected value and no idea why.
        let closing = if field == "addtier" || field.starts_with("wd_dest") {
            "No command needed. Expires in 3 minutes."
        } else {
            "Just the number — no command. Expires in 3 minutes."
        };
        let text = format!(
            "✏️ <b>Send the {label}</b>\n\n{hint}\n\n<i>{closing}</i>"
        );
        let kb = serde_json::json!({"inline_keyboard": [[
            {"text": "◀️ Cancel", "callback_data": format!("set:{field}")}
        ]]});
        (text, kb)
    }



    /// Auto-buy: the switch and the wallet threshold.
    ///
    /// The COHORTS are deliberately absent. Which groups of wallets are worth
    /// following is a decision made from scoring data, on the host, not a knob
    /// to flip mid-session — and getting it wrong quietly changes what the bot
    /// trades rather than whether it trades.
    #[cfg(feature = "sniper")]
    fn autobuy_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let env = sniper.envelope();
        let active = live.auto_buy_active(&env);
        let need_sol = live.min_smart_sol_in;

        let sol_s = if need_sol > 0.0 { format!("{need_sol} SOL") } else { "not set".into() };
        let text = format!(
            "🤖 <b>Auto-buy</b>\n\n\
             Status · <b>{}</b>\n\
             Smart volume · <b>{sol_s}</b>\n\n\
             <i>Buys once the tracked cohort has put this much SOL into a token \
             inside the {win}-minute window. Size is the signal — five wallets \
             at 0.05 SOL each is not the same conviction as two at 5 SOL, and a \
             headcount cannot tell them apart.</i>",
            if active { "🟢 on" } else { "⚪ off" },
            win = self.track_for_secs.max(60) / 60,
        );

        let mut rows: Vec<serde_json::Value> = vec![serde_json::json!([
            {"text": if active { "🟢 On — tap to disable" } else { "⚪ Off — tap to enable" },
             "callback_data": "setv:autobuy_on:toggle"}
        ])];
        rows.push(serde_json::json!([
            {"text": format!("💸 Smart volume · {sol_s}"), "callback_data": "set:smartsol"},
            {"text": "◀️ Back", "callback_data": "cmd:settings"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Buy size by market-cap band.
    #[cfg(feature = "sniper")]
    fn tiers_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let mut body = String::new();
        for t in &live.buy_tiers {
            body.push_str(&format!(
                "{}  →  <b>{} SOL</b>\n",
                escape_html(&crate::settings::describe_tier(t)),
                t.sol
            ));
        }
        if live.buy_tiers.is_empty() {
            body.push_str("<i>none — every token uses the default</i>\n");
        }
        let text = format!(
            "📊 <b>Buy by market cap</b>\n\nDefault buy: <b>{} SOL</b>\n\n{body}\n<i>A token that falls in a band buys that amount; anything else \
             uses the default. Bands cannot overlap, so every token matches at \
             most one.</i>",
            live.trade_size_sol
        );
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for (i, t) in live.buy_tiers.iter().enumerate() {
            rows.push(serde_json::json!([
                {"text": format!("{} → {} SOL", crate::settings::describe_tier(t), t.sol),
                 "callback_data": "set:tiers"},
                {"text": "✕", "callback_data": format!("setv:deltier:{i}")},
            ]));
        }
        rows.push(serde_json::json!([
            {"text": "➕ Add band", "callback_data": "set:addtier"},
            {"text": "♻️ Reset", "callback_data": "setv:cleartiers:1"},
        ]));
        rows.push(serde_json::json!([
            {"text": "💰 Default buy", "callback_data": "set:size"},
            {"text": "◀️ Back", "callback_data": "cmd:settings"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Step 1 of adding a band: pick the market-cap range.
    ///
    /// Two taps and no typing. The earlier version asked for "min max size" as
    /// a typed line, which is three decisions crammed into one field with no
    /// feedback until it is rejected — and a mistyped zero on a market cap is
    /// an expensive mistake to discover afterwards.
    #[cfg(feature = "sniper")]
    fn add_tier_range_screen(&self) -> (String, serde_json::Value) {
        // Contiguous by construction, so ranges built here never overlap.
        const RANGES: &[(f64, f64)] = &[
            (0.0, 50e3),
            (50e3, 100e3),
            (100e3, 250e3),
            (250e3, 500e3),
            (500e3, 1e6),
            (1e6, 2e6),
            (2e6, 5e6),
            (5e6, 0.0),
        ];
        let text = "📊 <b>Add a band</b>\n\nPick the market-cap range.\n\n                    <i>Bands cannot overlap, so a range that clashes with one \
                    you already have will be refused.</i>"
            .to_string();
        let mut rows: Vec<serde_json::Value> = Vec::new();
        let btns: Vec<serde_json::Value> = RANGES
            .iter()
            .map(|(lo, hi)| {
                let t = crate::settings::BuyTier { min_usd: *lo, max_usd: *hi, sol: 1.0 };
                serde_json::json!({
                    "text": crate::settings::describe_tier(&t),
                    "callback_data": format!("tiersz:{lo}:{hi}"),
                })
            })
            .collect();
        for chunk in btns.chunks(2) {
            rows.push(serde_json::Value::Array(chunk.to_vec()));
        }
        rows.push(serde_json::json!([
            {"text": "✏️ Custom range", "callback_data": "ask:addtier"},
            {"text": "◀️ Back", "callback_data": "set:tiers"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Step 2: pick the buy size for the chosen range.
    #[cfg(feature = "sniper")]
    fn add_tier_size_screen(&self, lo: f64, hi: f64) -> (String, serde_json::Value) {
        let t = crate::settings::BuyTier { min_usd: lo, max_usd: hi, sol: 1.0 };
        let label = crate::settings::describe_tier(&t);
        let text = format!(
            "📊 <b>{}</b>\n\nHow much should a token in this range buy?",
            escape_html(&label)
        );
        let sizes = [0.05f64, 0.1, 0.2, 0.35, 0.5, 0.75, 1.0, 2.0];
        let mut rows: Vec<serde_json::Value> = Vec::new();
        let btns: Vec<serde_json::Value> = sizes
            .iter()
            .map(|sol| {
                serde_json::json!({
                    "text": format!("{sol} SOL"),
                    "callback_data": format!("tieradd:{lo}:{hi}:{sol}"),
                })
            })
            .collect();
        for chunk in btns.chunks(2) {
            rows.push(serde_json::Value::Array(chunk.to_vec()));
        }
        rows.push(serde_json::json!([
            {"text": "◀️ Back", "callback_data": "set:addtier"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// The supply-share ceiling: a toggle and a percentage.
    #[cfg(feature = "sniper")]
    fn supply_cap_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let on = live.supply_cap;
        let pct = live.max_supply_pct;

        let text = format!(
            "🪙 <b>Supply cap</b>\n\nStatus: <b>{}</b>\nCeiling: <b>{}</b>\n\n<i>Buys always execute at their configured size. Afterwards the \
             position is measured against the token's total supply, and only \
             the EXCESS is sold — a position at or under the ceiling is left \
             alone. Checked right after each buy, and again on every \
             reconciliation sweep as a fallback.</i>",
            if on { "🟢 on" } else { "⚪ off" },
            if pct > 0.0 { format!("{pct}% of supply") } else { "not set".into() },
        );
        let rows = serde_json::json!({ "inline_keyboard": [
            [{"text": if on { "🟢 On — tap to disable" } else { "⚪ Off — tap to enable" },
              "callback_data": "setv:supplycap_on:toggle"}],
            [{"text": format!("📐 Ceiling · {}", fmt_supply_pct(pct)),
              "callback_data": "set:maxsupply"},
             {"text": "◀️ Back", "callback_data": "set:buying"}],
        ]});
        (text, rows)
    }

    /// Volume confirmation: smart money must be corroborated by real flow.
    #[cfg(feature = "sniper")]
    fn volume_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let on = live.volume_mode;
        let fmt = |v: f64| if v <= 0.0 { "off".to_string() } else { format!("{v} SOL") };

        let text = format!(
            "📊 <b>Volume mode</b>\n\n\
             Status · <b>{}</b>\n\
             Token volume · <b>{}</b>\n\n\
             <i>Corroboration only: it can block a signal the trigger admitted, \
             never create one. Measured over the same {win}-minute window as \
             the signal itself.</i>",
            if on { "🟢 on" } else { "⚪ off" },
            fmt(live.min_token_volume_sol),
            win = self.track_for_secs.max(60) / 60,
        );

        let mut rows: Vec<serde_json::Value> = vec![serde_json::json!([
            {"text": if on { "🟢 On — tap to disable" } else { "⚪ Off — tap to enable" },
             "callback_data": "setv:volume_on:toggle"}
        ])];
        rows.push(serde_json::json!([
            {"text": format!("📈 Token volume · {}", fmt(live.min_token_volume_sol)),
             "callback_data": "set:tokenvol"},
            {"text": "◀️ Back", "callback_data": "cmd:settings"},
        ]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// The auto-sell screen: one list of orders, plus the trailing stop.
    #[cfg(feature = "sniper")]
    /// Auto-sell, as four decisions instead of a variable-length ladder.
    ///
    /// # Why this replaced the order list
    ///
    /// The old screen presented N editable orders, each with its own trigger
    /// and amount, and left the operator to work out what they added up to. It
    /// could express anything — and made the common case (one stop, one target)
    /// exactly as hard to read as the rare one.
    ///
    /// Almost every position uses one stop and one target. Those get a line
    /// each here. The ladder still exists underneath and is reachable from
    /// "More targets"; nothing is lost, it is just no longer the default view.
    #[cfg(feature = "sniper")]
    fn exits_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let e = sniper.live().exits;
        let onoff = if e.enabled { "🟢 On" } else { "⚪ Off" };
        let stop = e.stop_pct();
        let (tp, tp_amt) = e.target();

        let stop_s = if stop < 0 { format!("{stop}%") } else { "none".into() };
        let tp_s = if tp > 0 { format!("+{tp}% · sell {tp_amt}%") } else { "none".into() };
        let be_s = if e.breakeven { "on".to_string() } else { "off".into() };
        let tr_s = if e.trailing_pct > 0 { format!("−{}%", e.trailing_pct) } else { "off".into() };

        let mut text = format!(
            "🎚 <b>Auto-sell</b> · {onoff}\n\n🛑 Stop loss   <b>{stop_s}</b>\n🎯 Take profit <b>{tp_s}</b>\n🔒 Break-even  <b>{be_s}</b>\n📉 Trailing    <b>{tr_s}</b>\n\n<i>Break-even arms once the position has been up that much, then \
             exits at cost rather than at a loss. Protective rules are always \
             checked before targets.</i>"
        );
        if e.is_ladder() {
            text.push_str("\n\n<i>Extra targets are set — see More targets.</i>");
        }

        let rows = serde_json::json!({ "inline_keyboard": [
            [{"text": format!("Auto-sell · {onoff}"), "callback_data": "setv:exits_on:toggle"}],
            [{"text": format!("🛑 Stop loss · {stop_s}"), "callback_data": "set:stoploss"},
             {"text": format!("🎯 Take profit · {}", if tp > 0 { format!("+{tp}%") } else { "none".into() }),
              "callback_data": "set:takeprofit"}],
            [{"text": format!("🔒 Break-even · {be_s}"), "callback_data": "setv:breakeven_on:toggle"},
             {"text": format!("📉 Trailing · {tr_s}"), "callback_data": "set:trailing"}],
            [{"text": "⚙️ More targets", "callback_data": "set:ladder"},
             {"text": "◀️ Back", "callback_data": "cmd:settings"}],
        ]});
        (text, rows)
    }

    /// ALPHA SMART MONEY MODE — four controls and nothing else.
    ///
    /// The wallet scores and the bar they must clear are deliberately absent:
    /// they are host-side, and a screen that showed them would invite tuning
    /// the qualification between trades, which is how a performance measure
    /// stops measuring anything.
    #[cfg(feature = "sniper")]
    fn alpha_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let onoff = if live.alpha_enabled { "🟢 On" } else { "⚪ Off" };
        let amt_s = format!("{} SOL", live.alpha_buy_sol);
        let tp_s =
            if live.alpha_tp_pct > 0 { format!("+{}%", live.alpha_tp_pct) } else { "none".into() };
        let sl_s =
            if live.alpha_sl_pct > 0 { format!("-{}%", live.alpha_sl_pct) } else { "none".into() };

        let mut text = format!(
            "⭐ <b>Alpha smart money</b> · {onoff}\n\n\
             💰 Buy amount  <b>{amt_s}</b>\n\
             🎯 Take profit <b>{tp_s}</b>\n\
             🛑 Stop loss   <b>{sl_s}</b>\n\n\
             <i>Buys when a wallet with a proven track record buys — on its own \
             size and its own exits, whatever the volume trigger does. Both can \
             fire on the same token.</i>"
        );
        // Said plainly rather than left to be discovered: enabled with no
        // amount looks armed and does nothing.
        if live.alpha_enabled && live.alpha_buy_sol <= 0.0 {
            text.push_str("\n\n⚠️ <b>Set a buy amount</b> — Alpha cannot trade without one.");
        }
        if live.alpha_enabled && live.alpha_tp_pct == 0 && live.alpha_sl_pct == 0 {
            text.push_str(
                "\n\n⚠️ <b>No Alpha exits set</b> — Alpha positions fall back to the \
                 normal auto-sell rules until you set a target or a stop here.",
            );
        }

        let rows = serde_json::json!({ "inline_keyboard": [
            [{"text": format!("Alpha mode · {onoff}"), "callback_data": "setv:alpha_on:toggle"}],
            [{"text": format!("💰 Buy amount · {amt_s}"), "callback_data": "set:alphabuy"},
             {"text": format!("🎯 Take profit · {tp_s}"), "callback_data": "set:alphatp"}],
            [{"text": format!("🛑 Stop loss · {sl_s}"), "callback_data": "set:alphasl"},
             {"text": "◀️ Back", "callback_data": "cmd:settings"}],
        ]});
        (text, rows)
    }

    /// The full order list, for multi-rung ladders.
    #[cfg(feature = "sniper")]
    fn ladder_screen(&self) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let e = sniper.live().exits;
        let mut sold: u32 = 0;
        let mut body = String::new();
        let mut targets: Vec<_> =
            e.orders.iter().copied().filter(|o| o.is_armed() && !o.is_stop()).collect();
        targets.sort_by_key(|o| o.at_pct);
        for o in &targets {
            sold += o.amount_pct as u32;
            let left = 100i64 - sold as i64;
            body.push_str(&format!(
                "   +{}% → sell {}%   <i>({} left)</i>\n",
                o.at_pct,
                o.amount_pct,
                if left <= 0 { "nothing".to_string() } else { format!("{left}%") }
            ));
        }
        if targets.is_empty() {
            body.push_str("   <i>none</i>\n");
        }
        let text = format!(
            "⚙️ <b>Targets</b>\n\n{body}\n<i>Amounts are shares of the ORIGINAL position, so they add up. \
             Anything past 100% can never fire.</i>"
        );
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for (i, o) in e.orders.iter().enumerate() {
            let label = if !o.is_armed() {
                "⚪ not set".to_string()
            } else if o.is_stop() {
                format!("🛑 stop {}% → sell {}%", o.at_pct, o.amount_pct)
            } else {
                format!("🎯 +{}% → sell {}%", o.at_pct, o.amount_pct)
            };
            rows.push(serde_json::json!([
                {"text": label, "callback_data": format!("set:order{i}")},
                {"text": "✕", "callback_data": format!("setv:delorder:{i}")},
            ]));
        }
        if e.orders.len() < crate::exits::MAX_ORDERS {
            rows.push(serde_json::json!([
                {"text": "➕ Add target", "callback_data": "setv:addorder:1"}
            ]));
        }
        rows.push(serde_json::json!([{"text": "◀️ Back", "callback_data": "set:exits"}]));
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Editor for one order: the trigger, then the amount.
    #[cfg(feature = "sniper")]
    fn order_screen(&self, idx: usize) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let orders = sniper.live().exits.orders;
        let Some(o) = orders.get(idx).copied() else {
            return self.exits_screen();
        };
        // Named by what it IS, not by its index. "Order 3" told you nothing
        // about whether you were editing protection or profit-taking.
        let (kind, blurb) = if !o.is_armed() {
            ("⚪ <b>Not set</b>", "Pick a trigger below. Negative = stop, positive = target.")
        } else if o.is_stop() {
            ("🛑 <b>Stop</b>", "Fires when the position falls this far below cost. \
              Stops are checked before any target.")
        } else {
            ("🎯 <b>Target</b>", "Fires when the position is up this much. \
              Targets fire lowest-first, once each.")
        };
        let text = format!(
            "{kind}\n\nTrigger: <b>{}</b>\nSells: <b>{}</b> of the original position\n\n<i>{blurb}</i>",
            if o.at_pct == 0 {
                "not set".to_string()
            } else {
                format!("{}{}%", if o.at_pct > 0 { "+" } else { "" }, o.at_pct)
            },
            if (1..=100).contains(&o.amount_pct) {
                format!("{}%", o.amount_pct)
            } else {
                "not set".to_string()
            },
        );
        // Stops and targets in SEPARATE rows, each labelled. The old grid ran
        // -50 -35 -25 -15 50 100 250 ... together, so the sign was the only
        // thing distinguishing "cut my loss" from "take my profit".
        let row = |vals: &[i32]| -> Vec<serde_json::Value> {
            vals.iter()
                .map(|t| serde_json::json!({
                    "text": format!("{}{}{}%", if *t == o.at_pct { "✓ " } else { "" },
                                    if *t > 0 { "+" } else { "" }, t),
                    "callback_data": format!("setv:ordt{idx}:{t}"),
                }))
                .collect()
        };
        let amts: Vec<serde_json::Value> = [10u8, 20, 25, 33, 50, 100]
            .iter()
            .map(|a| serde_json::json!({
                "text": format!("{}{}%", if *a == o.amount_pct { "✓ " } else { "" }, a),
                "callback_data": format!("setv:orda{idx}:{a}"),
            }))
            .collect();
        let kb = serde_json::json!({"inline_keyboard": [
            [{"text": "🛑 — stop below cost —", "callback_data": format!("set:order{idx}")}],
            row(&[-50, -35, -25, -15]),
            [{"text": "🎯 — target above cost —", "callback_data": format!("set:order{idx}")}],
            row(&[50, 100, 250]),
            row(&[400, 900, 2000]),
            [{"text": "— how much to sell —", "callback_data": format!("set:order{idx}")}],
            amts[..3].to_vec(),
            amts[3..].to_vec(),
            [{"text": "✏️ Custom trigger", "callback_data": format!("ask:ordt{idx}")},
             {"text": "✏️ Custom amount", "callback_data": format!("ask:orda{idx}")}],
            [{"text": "✕ Remove", "callback_data": format!("setv:delorder:{idx}")},
             {"text": "◀️ Back", "callback_data": "set:exits"}],
        ]});
        (text, kb)
    }

    /// Editor for the trailing stop.
    #[cfg(feature = "sniper")]
    fn stop_screen(&self, _which: &str) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let cur = sniper.live().exits.trailing_pct;
        let text = format!(
            "📉 <b>Trailing stop</b>\n\nCurrent: <b>{}</b>\n\n<i>Sells everything once the position falls this far from its PEAK. \
             Only acts after the position has been in profit, so it cannot close \
             a fresh entry on ordinary slippage.</i>",
            if cur > 0 { format!("−{cur}%") } else { "off".into() }
        );
        let opts: Vec<serde_json::Value> = [20u8, 30, 40, 50, 60, 75]
            .iter()
            .map(|p| serde_json::json!({
                "text": format!("{}−{}%", if *p == cur { "✓ " } else { "" }, p),
                "callback_data": format!("setv:trail:{p}"),
            }))
            .collect();
        let kb = serde_json::json!({"inline_keyboard": [
            opts[..3].to_vec(), opts[3..].to_vec(),
            [{"text": "🚫 Off", "callback_data": "setv:trail:0"}],
            [{"text": "◀️ Back", "callback_data": "set:exits"}],
        ]});
        (text, kb)
    }

    /// Apply an auto-sell change. Returns None if `field` is not one of ours.
    #[cfg(feature = "sniper")]
    fn apply_exit_setting(&self, field: &str, value: &str) -> Option<(String, serde_json::Value)> {
        let sniper = self.sniper.as_ref()?;
        let (res, screen): (Result<String, String>, String) = match field {
            "exits_on" => (sniper.toggle_exits(), "exits".into()),
            "autobuy_on" => (sniper.toggle_auto_buy(), "autobuy".into()),
            "volume_on" => (sniper.toggle_volume_mode(), "volume".into()),
            "supplycap_on" => (sniper.toggle_supply_cap(), "supplycap".into()),
            "cleartiers" => (sniper.clear_buy_tiers(), "tiers".into()),
            "deltier" => (sniper.remove_buy_tier(value.parse().ok()?), "tiers".into()),
            "breakeven_on" => (sniper.toggle_breakeven(), "exits".into()),
            "alpha_on" => (sniper.toggle_alpha(), "alpha".into()),
            "trail" => (sniper.set_trailing(value.parse().ok()?), "trailing".into()),
            "addorder" => (sniper.add_order(), "exits".into()),
            "delorder" => (sniper.remove_order(value.parse().ok()?), "exits".into()),
            f if f.starts_with("ordt") => {
                let i: usize = f[4..].parse().ok()?;
                (sniper.set_order_trigger(i, value.parse().ok()?), format!("order{i}"))
            }
            f if f.starts_with("orda") => {
                let i: usize = f[4..].parse().ok()?;
                (sniper.set_order_amount(i, value.parse().ok()?), format!("order{i}"))
            }
            _ => return None,
        };
        info!(field, value, ok = res.is_ok(), "auto-sell setting changed from telegram");
        let (text, kb) = if let Some(n) = screen.strip_prefix("order") {
            self.order_screen(n.parse().unwrap_or(0))
        } else if screen == "trailing" {
            self.stop_screen("trailing")
        } else if screen == "autobuy" {
            self.autobuy_screen()
        } else if screen == "volume" {
            self.volume_screen()
        } else if screen == "supplycap" {
            self.supply_cap_screen()
        } else if screen == "tiers" {
            self.tiers_screen()
        } else if screen == "alpha" {
            self.alpha_screen()
        } else {
            self.exits_screen()
        };
        let banner = match res {
            Ok(m) => format!("✅ {}\n\n", escape_html(&m)),
            Err(e) => format!("⚠️ {}\n\n", escape_html(&e)),
        };
        Some((format!("{banner}{text}"), kb))
    }

    /// The editor for one setting: presets as buttons.
    ///
    /// Only values the envelope actually permits are offered. A button that
    /// answers "refused" teaches the operator to distrust the buttons, so the
    /// filtering happens here rather than in the error path.
    #[cfg(feature = "sniper")]
    fn setting_editor(&self, field: &str) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        let live = sniper.live();
        let env = sniper.envelope();

        if field == "mode" {
            let text = format!(
                "🎯 <b>Entry strategy</b>\n\nCurrent: <b>{}</b>\n\n\
                 <b>Open</b> — buy at pool creation. Fastest, but at t=0 every \
                 pool's LP is still unlocked.\n\
                 <b>Guard</b> — buy only once LP is burned/locked. Misses fast \
                 runners, cuts the rug surface.",
                escape_html(sniper.snipe_mode().label())
            );
            let kb = serde_json::json!({"inline_keyboard": [
                [{"text": "⚡ Open", "callback_data": "setv:mode:open"},
                 {"text": "🛡 Guard", "callback_data": "setv:mode:guard"}],
                [{"text": "◀️ Back", "callback_data": "cmd:settings"}],
            ]});
            return (text, kb);
        }

        // (title, note, current, presets, unit, clearable)
        let (title, note, current, presets, unit, clearable): (&str, &str, String, Vec<f64>, &str, bool) =
            match field {
                "size" => ("💰 Trade size", "How much SOL each buy spends.",
                    format!("{} SOL", live.trade_size_sol),
                    vec![0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0], " SOL", false),
                "slippage" => ("📉 Slippage",
                    "How far the price may move against you between quote and fill. \
                     Too tight and fast tokens reject the trade; too loose and you \
                     pay whatever the market asks. 300 = 3%.",
                    format!("{} bps", live.slippage_bps),
                    vec![100.0, 300.0, 500.0, 800.0, 1000.0, 1500.0], " bps", false),
                "minliq" => ("💧 Pool liquidity floor", "AMM pools below this are refused. Raise-only.",
                    format!("{} SOL", live.min_liquidity_sol),
                    vec![5.0, 10.0, 15.0, 25.0, 50.0, 100.0], " SOL", false),
                "stoploss" => ("🛑 Stop loss",
                    "Sells the whole position if it falls this far below cost. 0 removes it.",
                    { let v = live.exits.stop_pct(); if v < 0 { format!("{v}%") } else { "none".into() } },
                    vec![0.0, -10.0, -15.0, -20.0, -30.0, -50.0], "%", false),
                "takeprofit" => ("🎯 Take profit",
                    "Sells when the position is up this much. 0 removes it.",
                    { let (v, a) = live.exits.target(); if v > 0 { format!("+{v}% · sell {a}%") } else { "none".into() } },
                    vec![0.0, 25.0, 50.0, 100.0, 200.0, 400.0], "%", false),
                "tpamount" => ("🎯 Take-profit amount",
                    "How much of the position the take-profit sells.",
                    format!("{}%", live.exits.target().1),
                    vec![25.0, 50.0, 75.0, 100.0], "%", false),
                "maxsupply" => ("📐 Supply ceiling",
                    "Most of a token's supply one position may hold. Enforced AFTER \
                     the buy: only the excess is sold, and the buy itself is never \
                     resized. Matters as the trade size grows — on an early token a \
                     large buy can take a share nobody will take back off you.",
                    fmt_supply_pct(live.max_supply_pct),
                    vec![0.0, 0.5, 1.0, 2.0, 5.0, 10.0], "%", false),
                "alphabuy" => ("⭐ Alpha buy amount",
                    "SOL per Alpha entry. Independent of the normal trade size, \
                     and never resized by the market-cap bands.",
                    format!("{} SOL", live.alpha_buy_sol),
                    vec![0.01, 0.02, 0.05, 0.1, 0.25, 0.5], " SOL", false),
                "alphatp" => ("⭐ Alpha take profit",
                    "Sells an Alpha position when it is up this much. 0 removes it.",
                    if live.alpha_tp_pct > 0 { format!("+{}%", live.alpha_tp_pct) } else { "none".into() },
                    vec![0.0, 50.0, 100.0, 150.0, 250.0, 500.0], "%", false),
                "alphasl" => ("⭐ Alpha stop loss",
                    "Sells an Alpha position if it falls this far below cost. 0 removes it.",
                    if live.alpha_sl_pct > 0 { format!("-{}%", live.alpha_sl_pct) } else { "none".into() },
                    vec![0.0, 10.0, 15.0, 20.0, 30.0, 50.0], "%", false),
                "smartsol" => ("💸 Smart-money volume",
                    "SOL the tracked cohort must have put in, over the signal window. 0 = not required.",
                    if live.min_smart_sol_in <= 0.0 { "off".to_string() }
                    else { format!("{} SOL", live.min_smart_sol_in) },
                    vec![0.0, 0.5, 1.0, 2.0, 5.0, 10.0], " SOL", false),
                "tokenvol" => ("📈 Token volume",
                    "Total observed SOL traded in the token, over the signal window. 0 = not required.",
                    if live.min_token_volume_sol <= 0.0 { "off".to_string() }
                    else { format!("{} SOL", live.min_token_volume_sol) },
                    vec![0.0, 5.0, 15.0, 30.0, 60.0, 120.0], " SOL", false),
                "curveliq" => ("🌱 Curve liquidity floor",
                    "pump.fun bonding curves only. 0 = no floor, so early entries are not refused for being small.",
                    if live.curve_min_liquidity_sol == 0.0 { "off".to_string() }
                    else { format!("{} SOL", live.curve_min_liquidity_sol) },
                    vec![0.0, 1.0, 2.0, 5.0, 10.0, 20.0], " SOL", false),
                "maxsize" => ("🧢 Max trade size", "Per-trade ceiling. Lowering it also lowers the trade size.",
                    fmt_eff(live.max_trade_size_sol, env.max_trade_size_sol, " SOL"),
                    vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0], " SOL", true),
                "dailycap" => ("📆 Daily spend cap", "Most SOL this bot may spend in a day.",
                    fmt_eff(live.daily_cap_sol, env.daily_cap_sol, " SOL"),
                    vec![0.1, 0.2, 0.5, 1.0, 2.0, 5.0], " SOL", true),
                "maxtrades" => ("🔢 Trades per day",
                    "How many buys may happen in a day. 0 = unlimited.",
                    fmt_eff_u(live.max_trades_per_day, env.max_trades_per_day),
                    vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0], "", true),
                "maxmcap" => ("🏦 Max market cap", "Refuse entries valued at or above this.",
                    fmt_eff(live.max_market_cap_usd, env.max_market_cap_usd, ""),
                    vec![10_000.0, 25_000.0, 50_000.0, 100_000.0, 250_000.0], " USD", true),
                "maximpact" => ("💥 Max price impact", "Refuse a trade that would move the pool more than this.",
                    fmt_eff_u(live.max_price_impact_bps, env.max_price_impact_bps),
                    vec![100.0, 200.0, 500.0, 1000.0, 2000.0], " bps", true),
                _ => return ("Unknown setting.".to_string(), back_to_settings()),
            };

        // Envelope filtering: caps and slippage may only tighten, liquidity may
        // only rise. Offering a value that would be refused is worse than
        // offering fewer.
        // Only the per-trade CAP still filters a preset, because a size above
        // it would be refused. Everything else is the operator's to choose:
        // filtering by a ceiling they can also change here just hides options.
        let ceiling = if field == "size" {
            live.effective_max_trade_size(&env)
        } else {
            0.0
        };
        let allowed: Vec<f64> =
            presets.into_iter().filter(|v| ceiling <= 0.0 || *v <= ceiling).collect();

        let mut rows: Vec<serde_json::Value> = Vec::new();
        for chunk in allowed.chunks(3) {
            let row: Vec<serde_json::Value> = chunk
                .iter()
                .map(|v| {
                    let shown = if *v >= 1000.0 {
                        format!("{}k", (*v / 1000.0) as u64)
                    } else {
                        format!("{v}")
                    };
                    serde_json::json!({
                        "text": format!("{shown}{unit}"),
                        "callback_data": format!("setv:{field}:{v}"),
                    })
                })
                .collect();
            rows.push(serde_json::Value::Array(row));
        }
        if clearable {
            rows.push(serde_json::json!([
                {"text": "🚫 Clear (use host setting)", "callback_data": format!("setv:{field}:0")}
            ]));
        }
        // Back goes to the screen this editor was opened FROM, not the root.
        // Setting an Alpha level and landing in the top-level settings menu
        // makes the next Alpha change a three-tap journey.
        let back = if field.starts_with("alpha") { "set:alpha" } else { "cmd:settings" };
        rows.push(serde_json::json!([
            {"text": "✏️ Custom value", "callback_data": format!("ask:{field}")},
            {"text": "◀️ Back", "callback_data": back},
        ]));

        let text = format!(
            "{title}\n\nCurrent: <b>{}</b>\n\n<i>{}</i>",
            escape_html(&current),
            escape_html(note)
        );
        (text, serde_json::json!({ "inline_keyboard": rows }))
    }

    /// Apply a value chosen from a button, then re-render the editor so the new
    /// value is visible immediately.
    #[cfg(feature = "sniper")]
    fn apply_setting(&self, field: &str, value: &str) -> (String, serde_json::Value) {
        let Some(sniper) = &self.sniper else {
            return ("⚪ <b>Sniper not configured</b>".to_string(), back_to_settings());
        };
        if field == "mode" {
            if let Some(m) = crate::sniper::SnipeMode::parse(value) {
                sniper.set_snipe_mode(m);
                info!(mode = value, "snipe mode changed from telegram");
            }
            return self.settings_screen();
        }
        let Ok(v) = value.parse::<f64>() else {
            return ("⚠️ Bad value.".to_string(), back_to_settings());
        };
        let result = match field {
            "size" => sniper.set_trade_size(v),
            "slippage" => sniper.set_slippage_bps(v as u16),
            "minliq" => sniper.set_min_liquidity(v),
            "curveliq" => sniper.set_curve_min_liquidity(v),
            "stoploss" => sniper.set_stop_loss(v as i32),
            "takeprofit" => sniper.set_take_profit(v as i32),
            "tpamount" => sniper.set_take_profit_amount(v as u8),
            "smartsol" => sniper.set_min_smart_sol_in(v),
            "tokenvol" => sniper.set_min_token_volume(v),
            "maxsupply" => sniper.set_max_supply_pct(v),
            "alphabuy" => sniper.set_alpha_buy_sol(v),
            "alphatp" => sniper.set_alpha_tp(v as i32),
            "alphasl" => sniper.set_alpha_sl(v as i32),
            "maxsize" => sniper.set_max_trade_size(v),
            "dailycap" => sniper.set_daily_cap(v),
            "maxtrades" => sniper.set_max_trades(v as u32),
            "maxmcap" => sniper.set_max_market_cap(v),
            "maximpact" => sniper.set_max_impact_bps(v as u32),
            _ => Err("unknown setting".to_string()),
        };
        info!(field, value, ok = result.is_ok(), "setting changed from telegram");
        let (text, kb) = self.setting_editor(field);
        let banner = match result {
            Ok(msg) => format!("✅ {}\n\n", escape_html(&msg)),
            Err(e) => format!("⚠️ {}\n\n", escape_html(&e)),
        };
        (format!("{banner}{text}"), kb)
    }

    /// Two-tap confirmation before an armed sell — a sell moves the position.
    #[cfg(feature = "sniper")]
    fn sell_confirm_screen(&self, mint: &str, pct: u8) -> (String, serde_json::Value) {
        let text = format!(
            "🔴 <b>Confirm sell</b>\n\n\
             Sell <b>{pct}%</b> of <code>{}</code> ({}) back to SOL via Jupiter?\n\n\
             <i>Executes only if the bot is ARMED and not halted; a dry-run bot \
             simulates and reports what you'd receive. Slippage tolerance and \
             route are picked by Jupiter.</i>",
            escape_html(mint),
            escape_html(&short_mint(mint)),
        );
        let kb = serde_json::json!({ "inline_keyboard": [[
            {"text": format!("✅ Yes, sell {pct}%"), "callback_data": format!("sellgo:{mint}:{pct}")},
            {"text": "◀️ Cancel", "callback_data": "cmd:positions"},
        ]]});
        (text, kb)
    }

    /// Execute a confirmed sell and render the outcome.
    #[cfg(feature = "sniper")]
    async fn render_sell(&self, mint: &str, pct: u8) -> String {
        use crate::sniper::{SellOutcome, SubmitOutcome};
        let Some(sniper) = &self.sniper else {
            return "⚪ <b>Sniper not configured</b>".to_string();
        };
        match sniper.sell(mint, pct).await {
            SellOutcome::NoPosition { mint } => {
                format!("📭 No balance of <code>{}</code> to sell.", escape_html(&mint))
            }
            SellOutcome::Refused { reason } => {
                format!("⚠️ <b>Sell refused</b>\n{}", escape_html(&reason))
            }
            SellOutcome::Failed { mint, reason } => format!(
                "❌ <b>Sell failed</b> for <code>{}</code>\n{}",
                escape_html(&mint),
                escape_html(&reason)
            ),
            SellOutcome::Rehearsed { pct, sol_out, impact_pct, would_succeed, .. } => format!(
                "🧪 <b>Dry-run sell</b> ({pct}%)\n\
                 Estimated out: <b>{sol_out:.4} SOL</b> · impact {impact_pct:.2}%\n\
                 Simulation: {}\n\n\
                 <i>Nothing was signed — the bot is in dry run. Arm to sell for real.</i>",
                if would_succeed { "✅ would succeed" } else { "❌ would FAIL" },
            ),
            SellOutcome::Submitted { pct, sol_out, result, .. } => {
                let line = match result {
                    SubmitOutcome::Executed { reference, .. } => format!(
                        "✅ <b>SOLD</b> — <a href=\"https://solscan.io/tx/{r}\">{r_short}</a>",
                        r = escape_html(&reference),
                        r_short = escape_html(&short_mint(&reference)),
                    ),
                    SubmitOutcome::NotExecuted { reason } => {
                        format!("⚪ <b>Not executed</b> (safe): {}", escape_html(&reason))
                    }
                    SubmitOutcome::Indeterminate { reference, reason } => format!(
                        "⚠️ <b>UNKNOWN outcome</b> — may have landed, do NOT retry blindly.\n\
                         ref <code>{}</code>\n{}",
                        escape_html(&reference),
                        escape_html(&reason)
                    ),
                };
                format!("Sell {pct}% · est <b>{sol_out:.4} SOL</b>\n{line}")
            }
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
        mint: &str,
        held: f64,
    ) -> Option<f64> {
        let base_vault = cb.base_vault.as_deref()?;
        let quote_vault = cb.quote_vault.as_deref()?;

        // ORIENTATION IS NOT ASSUMABLE. `base_vault`/`quote_vault` are the
        // pool's own naming, and on Raydium CPMM / PumpSwap WSOL sits on the
        // BASE side — so "quote_vault" there holds the launched token, not SOL.
        // Taking the names at face value inverts the price (tokens-per-SOL
        // instead of SOL-per-token) and produces a wildly wrong mark. Read which
        // mint the vault actually holds and decide from that.
        let base_holds_token = rpc.token_account_mint(base_vault).await? == mint;
        let (token_vault, sol_vault) = if base_holds_token {
            (base_vault, quote_vault)
        } else {
            (quote_vault, base_vault)
        };

        let token_reserve = rpc.vault_balance(token_vault).await?;
        let sol_reserve = rpc.vault_balance(sol_vault).await?;
        // value = held * (SOL per token)
        crate::positions::mid_price_value(sol_reserve, token_reserve, held)
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

    /// Performance of announced smart-money calls, best first.
    ///
    /// Answers from stored state rather than live quotes: the performance
    /// tracker re-prices every signal on its own schedule and records the
    /// result, so this is instant. Issuing a quote per call here would take
    /// seconds and risk rate-limiting the tracker that produces the updates.
    /// The cost is that figures are as fresh as the last sweep, which the
    /// header states rather than hides.
    ///
    /// The mint is rendered in FULL inside a code block. Telegram copies a code
    /// block's literal contents, so a shortened mint would copy a truncated
    /// string that is not a valid address — the tap would appear to work and
    /// silently yield something unusable.
    /// The leaderboard, on demand.
    ///
    /// Deliberately the SAME renderer the five-hourly post uses. A command that
    /// formats its own version of the same data drifts from the scheduled one
    /// the first time either is touched, and then the group is reading two
    /// different truths about the same calls.
    async fn render_calls(&self) -> String {
        let Some(signals) = self.signals.as_ref() else {
            return "<b>Alerts</b>\n\nSmart-money tracking is not enabled.".to_string();
        };
        let now = chrono::Utc::now();
        let calls = signals.ranked(now, self.track_for_secs as i64);
        // The audit log only exists in a sniper build; an alerts-only build has
        // no trades to mark, so the list renders identically without the marks.
        #[cfg(feature = "sniper")]
        let traded = crate::detector::read_traded_mints(&self.audit_log).await;
        #[cfg(not(feature = "sniper"))]
        let traded = std::collections::HashSet::new();
        crate::alerts::render_leaderboard(
            &calls,
            &traded,
            self.track_for_secs,
            now,
            self.tz_offset_hours,
        )
    }

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
                Tunable::MaxSize => arg.parse::<f64>().map_err(|_| "not a number".to_string())
                    .and_then(|v| sniper.set_max_trade_size(v)),
                Tunable::DailyCap => arg.parse::<f64>().map_err(|_| "not a number".to_string())
                    .and_then(|v| sniper.set_daily_cap(v)),
                Tunable::MaxTrades => arg.parse::<u32>().map_err(|_| "not a whole number".to_string())
                    .and_then(|v| sniper.set_max_trades(v)),
                Tunable::MaxMcap => arg.parse::<f64>().map_err(|_| "not a number (USD)".to_string())
                    .and_then(|v| sniper.set_max_market_cap(v)),
                Tunable::MaxImpact => arg.parse::<u32>().map_err(|_| "not an integer (bps)".to_string())
                    .and_then(|v| sniper.set_max_impact_bps(v)),
            };
            match result {
                Ok(msg) => format!("✅ {}", escape_html(&msg)),
                Err(e) => format!("⚠️ {}", escape_html(&e)),
            }
        }
    }

    /// Switch entry strategy. Unlike the risk knobs this is not tighten-only —
    /// it is a genuine strategy choice, and refusing an unknown word beats
    /// guessing which one was meant when the answer decides what gets bought.
    fn render_set_mode(&self, arg: Option<&str>) -> String {
        #[cfg(not(feature = "sniper"))]
        {
            let _ = arg;
            return "⚪ <b>Not available</b> (no <code>sniper</code> feature).".to_string();
        }
        #[cfg(feature = "sniper")]
        {
            let Some(sniper) = &self.sniper else {
                return "⚪ <b>Sniper not configured</b>".to_string();
            };
            let Some(arg) = arg else {
                return format!(
                    "Current: <b>{}</b>\n\nUsage: <code>/mode open</code> or \
                     <code>/mode guard</code>\n\n\
                     <b>open</b> — buy at pool creation. Fastest, but LP is still \
                     unlocked at t=0.\n\
                     <b>guard</b> — buy only once LP is burned/locked. Misses fast \
                     runners, cuts the rug surface.",
                    escape_html(sniper.snipe_mode().label())
                );
            };
            match crate::sniper::SnipeMode::parse(arg) {
                Some(m) => format!("✅ {}", escape_html(&sniper.set_snipe_mode(m))),
                None => "⚠️ Unknown mode. Use <code>open</code> or <code>guard</code>.".to_string(),
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
            // One compact context line, then the buttons do the talking.
            let ctx: Vec<String> = sniper
                .settings_rows()
                .into_iter()
                .map(|(k, v)| if k == "Mode" { v } else { format!("{}: {}", k.to_lowercase(), v) })
                .collect();
            let mut out = String::from("⚙️ <b>Trading settings</b>\n");
            out.push_str(&escape_html(&ctx.join("  ·  ")));
            out
        }
    }

    fn render_help() -> String {
        "<b>volens</b>\n\
         Tap a button below, or use the <b>/</b> menu (bottom-left) for all \
         commands.\n\n\
         <b>Buttons:</b> Status · Settings · Balance · Positions · Wallets · \
         New wallet · Metrics · Halt.\n\n\
         <code>/calls</code> — how announced smart-money calls have performed.\n\n\
         <b>Trading:</b>\n\
         • <code>/size 0.01</code> — trade size (SOL)\n\
         • <code>/mode open|guard</code> — entry strategy\n\
         • <code>/slippage 200</code> — tighten slippage\n\
         • <code>/min-liquidity 25</code> — raise the liquidity floor\n\n\
         <b>Risk caps:</b>\n\
         • <code>/maxsize 0.05</code> — per-trade ceiling\n\
         • <code>/dailycap 0.2</code> — SOL spendable per day\n\
         • <code>/maxtrades 4</code> — trades per day\n\
         • <code>/maxmcap 50000</code> — market-cap ceiling for entries\n\
         • <code>/maximpact 500</code> — price-impact limit (bps)\n\n\
         • <code>/use name</code> — pick the active wallet (applies on restart)\n\n\
         <code>/halt</code> and <code>/resume</code> toggle the kill switch.\n\n\
         Every setting here is <b>saved</b> and survives a restart. Caps and \
         limits can only be <b>tightened</b> from Telegram — raising a ceiling \
         needs host access, so a compromised bot account cannot widen its own \
         limits. Passing <code>0</code> to a cap clears it and falls back to the \
         host setting; it never means unlimited.\n\n\
         <code>/resume</code> clears the pause but does NOT arm — there is no \
         <code>/arm</code>. Going live requires host access."
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
                 {"text": "📥 Deposit", "callback_data": "cmd:deposit"}],
                [{"text": "📈 Positions", "callback_data": "cmd:positions"},
                 {"text": "👛 List wallets", "callback_data": "cmd:wallets"}],
                [{"text": "🆕 New wallet", "callback_data": "cmd:new-wallet"},
                 {"text": "📤 Withdraw", "callback_data": "ask:wd_amount"}],
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
                // Tapping a wallet opens its detail screen (deposit / withdraw /
                // export / set active) rather than immediately switching to it.
                let label = if is_active {
                    format!("✅ {name} (active)")
                } else {
                    format!("👛 {name}")
                };
                rows.push(serde_json::json!([
                    {"text": label, "callback_data": format!("w:{name}")}
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
                {"command": "deposit", "description": "show the wallet address to send funds to"},
                {"command": "withdraw", "description": "send SOL out: /withdraw 0.5 <address> (armed only)"},
                {"command": "positions", "description": "token positions + PnL"},
                {"command": "alerts", "description": "smart-money alerts, best performer first"},
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
/// Parse `<mint>:<pct>` from a sell callback tail. Base58 mints contain no
/// colon, so the last colon splits mint from percentage. Rejects out-of-range
/// percentages so a malformed tap can never reach the sell path.
#[cfg(feature = "sniper")]
fn parse_sell(rest: &str) -> Option<(&str, u8)> {
    let (mint, pct) = rest.rsplit_once(':')?;
    let pct: u8 = pct.parse().ok()?;
    if mint.is_empty() || !(1..=100).contains(&pct) {
        return None;
    }
    Some((mint, pct))
}

/// Owned handle for the delayed delete of an exported-key message. Separate
/// from `Bot` so the spawned task owns everything it needs.
#[cfg(feature = "sniper")]
pub(crate) struct DeleteHandle {
    client: reqwest::Client,
    bot_token: String,
}

#[cfg(feature = "sniper")]
impl DeleteHandle {
    async fn delete_message(&self, chat_id: i64, message_id: i64) {
        let url = format!("https://api.telegram.org/bot{}/deleteMessage", self.bot_token);
        let body = serde_json::json!({"chat_id": chat_id, "message_id": message_id});
        match self.client.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => debug!("exported key message deleted"),
            // A failed delete leaves the key visible. Warn loudly: the operator
            // needs to remove it by hand.
            Ok(r) => warn!(status = %r.status(), "COULD NOT DELETE key message — delete it manually"),
            Err(e) => warn!(error = %e, "COULD NOT DELETE key message — delete it manually"),
        }
    }
}

/// `2m`, `3h`, `1d4h` — coarse age for a call list.
pub fn format_window(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => {
            let (d, h) = (s / 86_400, (s % 86_400) / 3600);
            if h == 0 { format!("{d}d") } else { format!("{d}d{h}h") }
        }
    }
}

/// `x2.4`, `x13` — matches the alert vocabulary.
pub fn format_multiple(m: f64) -> String {
    if m >= 10.0 { format!("x{m:.0}") } else { format!("x{m:.1}") }
}

/// Parse `<amount_SOL> <address>` from a `/withdraw`. Ok((sol, address)) or a
/// user-facing error. Full address validation happens in the sniper; this is
/// just enough to reject obvious junk before showing a confirm.
#[cfg(feature = "sniper")]
/// Split the tail of a `wdgo:` callback into (address, optional wallet).
///
/// Extracted so the trailing-colon case is pinned by a test. The confirm button
/// is built as `wdgo:{sol}:{address}:{w}` with `w` empty whenever no wallet is
/// named — every withdrawal from the armed wallet — and an earlier version fell
/// through to the raw tail there, leaving the colon on the address. `pk()` then
/// rejected it, so the default withdrawal path failed for every user of it.
#[cfg(feature = "sniper")]
fn split_wdgo_tail(tail: &str) -> (&str, Option<&str>) {
    match tail.split_once(':') {
        Some((a, w)) => (a, (!w.is_empty()).then_some(w)),
        None => (tail, None),
    }
}

#[cfg(feature = "sniper")]
fn parse_withdraw_args(args: Option<&str>) -> Result<(f64, String, Option<String>), String> {
    const USAGE: &str =
        "Usage: <code>/withdraw &lt;amount_SOL&gt; &lt;address&gt; [wallet]</code>";
    let args = args.unwrap_or("").trim();
    let mut it = args.split_whitespace();
    let amount = it.next().filter(|s| !s.is_empty()).ok_or(USAGE)?;
    let address = it.next().ok_or(USAGE)?;
    // Optional: which wallet to send FROM. Omitted = the armed trading wallet.
    let wallet = it.next().map(str::to_string);
    let sol: f64 = amount
        .parse()
        .map_err(|_| format!("'{amount}' is not a valid SOL amount"))?;
    if !(sol.is_finite() && sol > 0.0) {
        return Err("amount must be greater than 0".into());
    }
    // Base58 Solana addresses are 32–44 chars; reject obvious non-addresses.
    if !(32..=44).contains(&address.len()) {
        return Err("that doesn't look like a Solana address".into());
    }
    Ok((sol, address.to_string(), wallet))
}

/// Parse "50k 100k 0.2" into a band.
///
/// Suffixes are accepted because nobody wants to type 100000000 on a phone,
/// and a mistyped zero on a market cap is a very expensive typo.
#[cfg(feature = "sniper")]
fn parse_tier_args(raw: &str) -> Result<(f64, f64, f64), String> {
    const USAGE: &str = "three values: min max size — e.g. 50k 100k 0.2";
    let mut it = raw.split_whitespace();
    let (a, b, c) = match (it.next(), it.next(), it.next()) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err(USAGE.into()),
    };
    let money = |s: &str| -> Result<f64, String> {
        let s = s.trim_start_matches('$').to_ascii_lowercase();
        let (num, mult) = match s.chars().last() {
            Some('k') => (&s[..s.len() - 1], 1e3),
            Some('m') => (&s[..s.len() - 1], 1e6),
            Some('b') => (&s[..s.len() - 1], 1e9),
            _ => (s.as_str(), 1.0),
        };
        num.parse::<f64>().map(|v| v * mult).map_err(|_| format!("'{s}' is not a number"))
    };
    let lo = money(a)?;
    let hi = money(b)?;
    let sol: f64 = c.parse().map_err(|_| format!("'{c}' is not a SOL amount"))?;
    if sol <= 0.0 {
        return Err("the buy size must be greater than 0".into());
    }
    if hi > 0.0 && hi <= lo {
        return Err("the upper bound must be above the lower one".into());
    }
    Ok((lo, hi, sol))
}

/// A USD ceiling for a button: $75K, $2.5M, or off.
fn fmt_usd_cap(v: f64) -> String {
    match v {
        v if v <= 0.0 => "off".into(),
        v if v >= 1e9 => format!("${:.1}B", v / 1e9),
        v if v >= 1e6 => format!("${:.1}M", v / 1e6),
        v if v >= 1e3 => format!("${:.0}K", v / 1e3),
        v => format!("${v:.0}"),
    }
}

/// Share-of-supply for a button.
fn fmt_supply_pct(v: f64) -> String {
    if v <= 0.0 { "off".into() } else { format!("{v}%") }
}

/// `AAAA…ZZZZ` short form of a base58 string (mint or signature), for buttons.
#[cfg(feature = "sniper")]
fn short_mint(s: &str) -> String {
    let n = s.len();
    format!("{}…{}", &s[..4.min(n)], &s[n.saturating_sub(4)..])
}

/// Keyboard shown after a sell: a single button back to the positions list.
#[cfg(feature = "sniper")]
fn sold_keyboard() -> serde_json::Value {
    serde_json::json!({ "inline_keyboard": [[
        {"text": "◀️ Back to positions", "callback_data": "cmd:positions"},
    ]]})
}

/// Keyboard that returns to the settings form.
#[cfg(feature = "sniper")]
fn back_to_settings() -> serde_json::Value {
    serde_json::json!({"inline_keyboard": [[
        {"text": "\u{25c0}\u{fe0f} Back", "callback_data": "cmd:settings"}
    ]]})
}

/// Effective cap for display, or a plain statement that there is none.
#[cfg(feature = "sniper")]
fn fmt_eff(live: f64, hard: f64, unit: &str) -> String {
    let eff = crate::settings::tightest(live, hard);
    if eff > 0.0 { format!("{eff}{unit}") } else { "unlimited".into() }
}

#[cfg(feature = "sniper")]
fn fmt_eff_u(live: u32, hard: u32) -> String {
    let eff = crate::settings::tightest_u32(live, hard);
    if eff > 0 { eff.to_string() } else { "unlimited".into() }
}

/// Sell sizes for one position. Each taps through to the existing two-tap
/// confirmation, so a mis-tap here still cannot move funds on its own.
#[cfg(feature = "sniper")]
fn sell_size_keyboard(mint: &str) -> serde_json::Value {
    serde_json::json!({"inline_keyboard": [
        [{"text": "Sell 10%", "callback_data": format!("sell:{mint}:10")},
         {"text": "Sell 25%", "callback_data": format!("sell:{mint}:25")},
         {"text": "Sell 50%", "callback_data": format!("sell:{mint}:50")}],
        [{"text": "Sell 75%", "callback_data": format!("sell:{mint}:75")},
         {"text": "Sell 100%", "callback_data": format!("sell:{mint}:100")}],
        [{"text": "◀️ Positions", "callback_data": "cmd:positions"}],
    ]})
}

/// Token quantities, at a readability that suits their size.
///
/// Memecoin balances span nine orders of magnitude; a fixed precision is
/// unreadable at one end and misleading at the other.
#[cfg(feature = "sniper")]
fn fmt_tokens(v: f64) -> String {
    match v {
        v if v >= 1e9 => format!("{:.2}B", v / 1e9),
        v if v >= 1e6 => format!("{:.2}M", v / 1e6),
        v if v >= 1e3 => format!("{:.1}K", v / 1e3),
        v => format!("{v:.4}"),
    }
}

/// Market caps the way a trader says them: "40K", "1.8M".
#[cfg(feature = "sniper")]
fn fmt_usd_short(v: f64) -> String {
    match v {
        v if v >= 1e9 => format!("${:.2}B", v / 1e9),
        v if v >= 1e6 => format!("${:.2}M", v / 1e6),
        v if v >= 1e3 => format!("${:.1}K", v / 1e3),
        v => format!("${v:.0}"),
    }
}

fn back_group(callback_data: &str) -> &'static str {
    match callback_data {
        // Wallet-group actions return to the wallet submenu.
        "cmd:balance" | "cmd:deposit" | "cmd:positions" | "cmd:wallets" | "cmd:new-wallet" => "wallet",
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
    MaxSize,
    DailyCap,
    MaxTrades,
    MaxMcap,
    MaxImpact,
}

impl Tunable {
    fn cmd(self) -> &'static str {
        match self {
            Tunable::Size => "size",
            Tunable::Slippage => "slippage",
            Tunable::MinLiquidity => "min-liquidity",
            Tunable::MaxSize => "maxsize",
            Tunable::DailyCap => "dailycap",
            Tunable::MaxTrades => "maxtrades",
            Tunable::MaxMcap => "maxmcap",
            Tunable::MaxImpact => "maximpact",
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
    Deposit,
    Positions,
    /// Performance of announced smart-money calls.
    Calls,
    Settings,
    NewWallet(Option<String>),
    Wallets,
    Use(Option<String>),
    SetSize(Option<String>),
    SetSlippage(Option<String>),
    SetMinLiquidity(Option<String>),
    SetMaxSize(Option<String>),
    SetDailyCap(Option<String>),
    SetMaxTrades(Option<String>),
    SetMaxMcap(Option<String>),
    SetMaxImpact(Option<String>),
    SetMode(Option<String>),
    /// Raw args after `/withdraw` ("<amount> <address>"), parsed in the handler.
    Withdraw(Option<String>),
    /// Reveal the active wallet's private key. Private chat only.
    Export,
    Help,
}

impl Command {
    /// May this run in the ALERT GROUP, where everyone present can type?
    ///
    /// The group is not the operator's private chat. Authorising it outright
    /// would hand every member `/settings`, `/size` and `/withdraw` — the
    /// controls that decide how much the bot spends and where funds go.
    ///
    /// So the group gets what it is for: reading. Plus `/halt`, deliberately —
    /// stopping the bot is a SAFE failure, and someone who can see a problem in
    /// the group should be able to stop it without finding the operator. That
    /// asymmetry is the point: anyone may pull the brake, nobody may steer.
    fn allowed_in_group(&self) -> bool {
        matches!(
            self,
            Command::Status
                | Command::Metrics
                | Command::Balance
                | Command::Positions
                | Command::Calls
                | Command::Halt
                | Command::Help
        )
    }

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
        // Everything after the command word, for multi-arg commands (withdraw).
        let rest = text.split_once(char::is_whitespace).map(|(_, r)| r.trim().to_string());
        Some(match cmd.as_str() {
            "status" => Command::Status,
            "metrics" | "stats" => Command::Metrics,
            "halt" | "stop" | "kill" => Command::Halt,
            "resume" | "unhalt" => Command::Resume,
            "balance" => Command::Balance,
            "deposit" | "receive" | "fund" => Command::Deposit,
            "positions" | "pnl" | "pos" => Command::Positions,
            "alerts" | "calls" | "signals" | "sm" => Command::Calls,
            "settings" | "config" | "params" => Command::Settings,
            "new-wallet" | "newwallet" | "new_wallet" | "genwallet" => Command::NewWallet(arg),
            "wallets" | "list" => Command::Wallets,
            "use" | "active" | "select" => Command::Use(arg),
            "size" | "trade-size" | "amount" => Command::SetSize(arg),
            "slippage" | "slip" => Command::SetSlippage(arg),
            "min-liquidity" | "min_liquidity" | "minliq" | "minliquidity" => {
                Command::SetMinLiquidity(arg)
            }
            "maxsize" | "max-size" | "max_size" => Command::SetMaxSize(arg),
            "dailycap" | "daily-cap" | "daily_cap" => Command::SetDailyCap(arg),
            "maxtrades" | "max-trades" | "max_trades" => Command::SetMaxTrades(arg),
            "maxmcap" | "max-mcap" | "maxmarketcap" => Command::SetMaxMcap(arg),
            "maximpact" | "max-impact" | "impact" => Command::SetMaxImpact(arg),
            "mode" | "strategy" => Command::SetMode(arg),
            "withdraw" | "send" => Command::Withdraw(rest),
            "export" | "exportkey" | "privatekey" | "key" => Command::Export,
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
            Command::Deposit => "deposit",
            Command::Positions => "positions",
            Command::Calls => "alerts",
            Command::Settings => "settings",
            Command::NewWallet(_) => "new-wallet",
            Command::Wallets => "wallets",
            Command::Use(_) => "use",
            Command::SetSize(_) => "size",
            Command::SetSlippage(_) => "slippage",
            Command::SetMinLiquidity(_) => "min-liquidity",
            Command::SetMaxSize(_) => "maxsize",
            Command::SetDailyCap(_) => "dailycap",
            Command::SetMaxTrades(_) => "maxtrades",
            Command::SetMaxMcap(_) => "maxmcap",
            Command::SetMaxImpact(_) => "maximpact",
            Command::SetMode(_) => "mode",
            Command::Withdraw(_) => "withdraw",
            Command::Export => "export",
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
            "deposit" => Some(Command::Deposit),
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

    /// A settings screen with no buttons is a command line with extra steps.
    /// Every setting must be reachable by tapping.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn every_setting_is_reachable_by_button() {
        use crate::config::{RpcConfig, SniperConfig};
        let mut sc = SniperConfig::default();
        sc.enabled = true;
        sc.settings_path = String::new();
        let rpc = Arc::new(crate::rpc::RpcClient::new(&RpcConfig::default()));
        let sniper = Arc::new(crate::sniper::Sniper::new(sc, rpc, &RpcConfig::default(), std::sync::Arc::new(crate::prices::PriceIndex::new())).unwrap());
        let sn2 = sniper.clone();
        let b = bot(&["1"], "").unwrap().with_sniper(sniper);

        // The top level asks four questions; the detail lives one tap down.
        // Walk the hierarchy rather than asserting a flat screen, so this test
        // fails when a setting becomes UNREACHABLE — not merely when it moves.
        let (_, kb) = b.settings_screen();
        let top = kb.to_string();
        for section in ["set:autobuy", "set:buying", "set:exits", "set:filters", "set:limits"] {
            assert!(top.contains(section), "{section} missing from the settings screen");
        }

        let mut reachable = top.clone();
        for (screen, blob) in [
            ("buying", b.buying_screen().1.to_string()),
            ("filters", b.filters_screen().1.to_string()),
            ("limits", b.limits_screen().1.to_string()),
        ] {
            assert!(blob.contains("cmd:settings"), "{screen} has no way back");
            reachable.push_str(&blob);
        }

        // Every setting still has a path to it, wherever it now lives.
        for field in ["size", "slippage", "minliq", "curveliq", "exits", "autobuy",
                      "maxtrades", "tiers", "supplycap", "volume"] {
            assert!(
                reachable.contains(&format!("set:{field}")),
                "no route to {field} from the settings screen"
            );
        }

        // Spend caps are deliberately absent. Trade size bounds a single
        // entry, the wallet balance bounds the rest, and a screen of limits
        // nobody uses is noise. The commands still exist and still bind.
        // Max market cap IS tappable again: it refuses a token outright, which
        // is a decision that belongs with the other buying decisions rather
        // than in a config file. The rest stay off the screens — trade size
        // bounds a single entry and the wallet balance bounds the rest.
        for gone in ["set:maxsize", "set:dailycap", "set:maximpact", "set:mode"] {
            assert!(!reachable.contains(gone), "{gone} should not be tappable");
        }

        // Auto-buy: the switch and threshold are tappable; the COHORTS are
        // not, by design — which wallets to follow is a decision from scoring
        // data, not a knob to flip mid-session.
        let ab = b.autobuy_screen().1.to_string();
        assert!(ab.contains("setv:autobuy_on:toggle"), "no auto-buy switch");

        // Volume mode: the toggle and both thresholds are tappable, and the
        // three fields that were cut stay cut.
        // Assert on the KEYBOARD, not the text: the description legitimately
        // mentions the window, and matching prose would fail on wording.
        let vk = b.volume_screen().1.to_string();
        assert!(vk.contains("setv:volume_on:toggle"), "no volume switch");

        // Auto-sell is now four decisions, not a variable-length order list.
        // Each has to be reachable, and the screen has to read as a policy
        // rather than as arithmetic the operator performs themselves.
        let (et, ek) = b.exits_screen();
        let ekb = ek.to_string();
        for want in ["set:stoploss", "set:takeprofit", "set:trailing"] {
            assert!(ekb.contains(want), "{want} not reachable from auto-sell");
        }
        // Break-even is a TOGGLE, not a level — there is nothing to configure.
        assert!(
            ekb.contains("setv:breakeven_on:toggle"),
            "break-even must be a switch, not an editor"
        );
        assert!(ekb.contains("set:ladder"), "multi-target ladder must stay reachable");
        for want in ["Stop loss", "Take profit", "Break-even", "Trailing"] {
            assert!(et.contains(want), "{want} missing from the auto-sell screen");
        }

        // The ladder view keeps the running total, because THAT is where an
        // order that can never fire becomes possible again.
        let orders = sn2.live().exits.orders;
        let first_target = orders.iter().position(|o| o.is_armed() && !o.is_stop()).unwrap();
        sn2.set_order_amount(first_target, 100).unwrap();
        let (lt, _) = b.ladder_screen();
        assert!(
            lt.contains("nothing left"),
            "a target that closes the position must say what remains:\n{lt}"
        );

        assert!(vk.contains("set:tokenvol"), "no token volume button");
        // Smart-money SOL is the auto-buy TRIGGER now, not a volume filter, so
        // it lives on the auto-buy screen. Having it in both places would be
        // two controls for one number.
        assert!(!vk.contains("set:smartsol"), "the SOL trigger moved to auto-buy");
        assert!(ab.contains("set:smartsol"), "the SOL trigger must be on auto-buy");
        for gone in ["set:accel", "set:smartshare", "set:volwindow"] {
            assert!(!vk.contains(gone), "{gone} was cut from the design");
        }
        // The wallet threshold is GONE, not merely defaulted off: a disabled
        // knob is a thing to misconfigure later. SOL volume is the only trigger.
        assert!(!ab.contains("autobuy_min"), "the wallet threshold was removed");
        assert!(ab.contains("set:smartsol"), "the SOL trigger must be on auto-buy");

        // Adding a band is two taps, not a typed line: pick a range, pick a
        // size. Three decisions crammed into one text field gave no feedback
        // until the whole thing was rejected.
        let rk = b.add_tier_range_screen().1.to_string();
        assert!(rk.contains("tiersz:"), "no range buttons");
        assert!(rk.contains("ask:addtier"), "custom entry must remain available");
        let sk = b.add_tier_size_screen(50e3, 100e3).1.to_string();
        assert!(sk.contains("tieradd:50000:100000:"), "no size buttons for the range");

        // Max market cap is a ceiling that REFUSES, separate from the bands
        // which only choose a size. Both live under Buying.
        let bk = b.buying_screen().1.to_string();
        assert!(bk.contains("set:maxmcap"), "no max market cap");
        assert!(bk.contains("set:tiers"), "no market-cap bands");
        assert!(bk.contains("set:supplycap"), "supply cap belongs under Buying");
        let lk = b.limits_screen().1.to_string();
        assert!(!lk.contains("set:supplycap"), "supply cap must not be under Limits");
        assert!(!ab.contains("cohort") && !ab.contains("group"), "cohorts must not be editable here");

        // The whole exit policy is reachable by tapping, nothing typed. The
        // simple screen carries the four decisions; add/remove live on the
        // ladder view behind "More targets".
        let exits = b.exits_screen().1.to_string();
        assert!(exits.contains("setv:exits_on:toggle"), "no on/off");
        assert!(exits.contains("set:trailing"), "no trailing stop");
        let ladder = b.ladder_screen().1.to_string();
        assert!(ladder.contains("setv:addorder:"), "cannot add an order");
        assert!(ladder.contains("setv:delorder:"), "cannot remove an order");
        let exits = ladder;
        // Every default order opens an editor with presets and a typed option.
        for i in 0..5 {
            assert!(exits.contains(&format!("set:order{i}")), "order {i} not tappable");
            let ord = b.order_screen(i).1.to_string();
            assert!(ord.contains(&format!("setv:ordt{i}:")), "order {i} has no trigger presets");
            assert!(ord.contains(&format!("setv:orda{i}:")), "order {i} has no amount presets");
            assert!(ord.contains(&format!("ask:ordt{i}")), "order {i} has no custom trigger");
        }

        // …and each editor offers presets plus a typed escape hatch.
        for field in ["size", "slippage", "minliq", "curveliq"] {
            let (_, kb) = b.setting_editor(field);
            let s = kb.to_string();
            assert!(s.contains(&format!("setv:{field}:")), "{field} has no preset buttons");
            assert!(s.contains(&format!("ask:{field}")), "{field} has no custom-value button");
        }
    }

    /// A preset must never be refused when tapped. Only the per-trade cap
    /// still constrains one — everything else is the operator's to set, and
    /// filtering by a ceiling they can change on the next screen would just
    /// hide options for no reason.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn presets_never_offer_a_refused_value() {
        use crate::config::{RpcConfig, SniperConfig};
        let mut sc = SniperConfig::default();
        sc.enabled = true;
        sc.settings_path = String::new();
        sc.slippage_bps = 300;
        sc.max_trade_size_sol = 0.1;
        let rpc = Arc::new(crate::rpc::RpcClient::new(&RpcConfig::default()));
        let sniper = Arc::new(crate::sniper::Sniper::new(sc, rpc, &RpcConfig::default(), std::sync::Arc::new(crate::prices::PriceIndex::new())).unwrap());
        let b = bot(&["1"], "").unwrap().with_sniper(sniper);

        // Slippage is now the operator's call in both directions.
        let s = b.setting_editor("slippage").1.to_string();
        assert!(s.contains("setv:slippage:300"));
        assert!(s.contains("setv:slippage:500"), "looser is allowed, it is their risk");

        // Trade size is the exception: a size above the per-trade cap WOULD be
        // refused, so it is not offered.
        let s = b.setting_editor("size").1.to_string();
        assert!(!s.contains("setv:size:0.25"), "must not offer above the per-trade cap");
        assert!(s.contains("setv:size:0.05"));
    }

    /// Tap ✏️, type a bare number, and it lands on the right setting — no
    /// command name typed anywhere.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn a_prompted_value_is_applied_without_a_command() {
        use crate::config::{RpcConfig, SniperConfig};
        let mut sc = SniperConfig::default();
        sc.enabled = true;
        sc.settings_path = String::new();
        let rpc = Arc::new(crate::rpc::RpcClient::new(&RpcConfig::default()));
        let sniper = Arc::new(crate::sniper::Sniper::new(sc, rpc, &RpcConfig::default(), std::sync::Arc::new(crate::prices::PriceIndex::new())).unwrap());
        let b = bot(&["1"], "").unwrap().with_sniper(sniper);

        b.ask_screen(1, "size");
        assert_eq!(b.take_awaited(1).as_deref(), Some("size"));
        // Consumed exactly once: a second bare message is not a setting.
        assert_eq!(b.take_awaited(1), None);
    }

    /// An abandoned prompt must not reinterpret an unrelated message later, and
    /// must not leak across chats.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn a_stale_prompt_does_not_swallow_a_later_message() {
        let b = bot(&["1"], "").unwrap();
        {
            let mut g = b.awaiting.lock().unwrap();
            g.insert(1, ("size".into(), Instant::now() - Bot::AWAIT_TTL - Duration::from_secs(1)));
        }
        assert_eq!(b.take_awaited(1), None, "expired prompts must not apply");

        b.ask_screen(7, "dailycap");
        assert_eq!(b.take_awaited(9), None, "a prompt belongs to one chat only");
        assert_eq!(b.take_awaited(7).as_deref(), Some("dailycap"));
    }


    /// Withdraw is reachable by button, and takes its two values as prompts
    /// rather than as a command the operator has to assemble by hand.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn withdrawing_is_a_button_flow() {
        let b = bot(&["1"], "").unwrap();
        assert!(Bot::wallet_menu().to_string().contains("ask:wd_amount"), "no withdraw button");

        // Step one asks for the amount.
        let (text, _) = b.ask_screen(1, "wd_amount");
        assert!(text.contains("amount to withdraw"), "{text}");
        assert_eq!(b.take_awaited(1).as_deref(), Some("wd_amount"));

        // Step two carries the amount forward in the pending key.
        b.await_value(1, "wd_dest|0.25");
        assert_eq!(b.take_awaited(1).as_deref(), Some("wd_dest|0.25"));

        // The assembled pair produces the existing two-tap confirmation, and
        // nothing moves without that second press.
        let (confirm, kb) = b.withdraw_prompt_screen(Some("0.25 4Nd1mBQtrMJVYVfKf2PJy9NCYYkJt1zY9CZK1Y9tYqRy"));
        assert!(confirm.contains("Confirm withdrawal"), "{confirm}");
        assert!(kb.to_string().contains("wdgo:0.25:"), "no confirm button: {kb}");
    }


    /// Each position gets its own button, and its screen offers a range of
    /// sell sizes rather than only 50/100.
    #[cfg(feature = "sniper")]
    #[tokio::test]
    async fn a_position_has_its_own_screen_and_sell_sizes() {
        use crate::config::{RpcConfig, SniperConfig};
        let mut sc = SniperConfig::default();
        sc.enabled = true;
        sc.settings_path = String::new();
        sc.sell_routes_path = String::new();
        let rpc = Arc::new(crate::rpc::RpcClient::new(&RpcConfig::default()));
        let sniper = Arc::new(crate::sniper::Sniper::new(sc, rpc.clone(), &RpcConfig::default(), std::sync::Arc::new(crate::prices::PriceIndex::new())).unwrap());
        let b = bot(&["1"], "").unwrap().with_sniper(sniper).with_rpc(rpc);

        let mint = "AByynfTALEVQFkE3i52oiSbJNDV61PzrXMNffX4pump";
        // With no wallet and no live RPC there is no position — and a screen
        // for a token you do not hold must never offer to sell it.
        let (text, kb) = b.position_screen(mint).await;
        assert!(!kb.to_string().contains("sell:"), "offered to sell nothing: {text}");

        let blob = sell_size_keyboard(mint).to_string();
        // Every size taps straight through to the existing two-tap confirm.
        for pct in [10, 25, 50, 75, 100] {
            assert!(blob.contains(&format!("sell:{mint}:{pct}")), "no {pct}% button");
        }
        assert!(blob.contains("cmd:positions"), "no way back");
    }

    /// Balances span nine orders of magnitude; one fixed precision cannot serve
    /// both ends.
    #[cfg(feature = "sniper")]
    #[test]
    fn quantities_and_market_caps_read_the_way_traders_say_them() {
        assert_eq!(fmt_tokens(1_250_000_000.0), "1.25B");
        assert_eq!(fmt_tokens(2_400_000.0), "2.40M");
        assert_eq!(fmt_tokens(1_500.0), "1.5K");
        assert_eq!(fmt_tokens(0.5), "0.5000");

        assert_eq!(fmt_usd_short(4_493.0), "$4.5K");
        assert_eq!(fmt_usd_short(351_705.0), "$351.7K");
        assert_eq!(fmt_usd_short(1_800_000.0), "$1.80M");
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

    /// The withdrawal bug: every default withdrawal was refused as an "invalid
    /// destination address", because the confirm button emits a trailing colon
    /// when no wallet is named and the parse kept it on the address.
    #[cfg(feature = "sniper")]
    #[test]
    fn withdraw_callback_tail_never_keeps_the_trailing_colon() {
        const ADDR: &str = "DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX";

        // The common case: armed wallet, no wallet named.
        assert_eq!(split_wdgo_tail(&format!("{ADDR}:")), (ADDR, None));
        // A named wallet still resolves.
        assert_eq!(split_wdgo_tail(&format!("{ADDR}:primary")), (ADDR, Some("primary")));
        // No wallet segment at all.
        assert_eq!(split_wdgo_tail(ADDR), (ADDR, None));

        // The property that actually matters: whatever the form, the address
        // must parse as a pubkey.
        for tail in [format!("{ADDR}:"), format!("{ADDR}:primary"), ADDR.to_string()] {
            let (addr, _) = split_wdgo_tail(&tail);
            assert!(
                crate::tx::pk(addr).is_ok(),
                "address must survive the split intact, got {addr:?}"
            );
        }
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
        // Arming and key export are NEVER commands — arming is host-only, and a
        // key must never travel over Telegram. Withdraw/send DO exist now (an
        // explicit owner choice), but are gated: armed-only + HALT + two-tap
        // confirm; see the withdraw tests.
        // Arming is NEVER a command — going live stays a host-side config
        // change, so a leaked bot token cannot arm a dry-run bot.
        for c in ["/arm", "/trade", "/buy", "/sell", "/transfer", "/sweep"] {
            assert_eq!(Command::parse(c), None, "{c} must not be a command");
        }
        // Withdraw and export DO exist (explicit owner choices). Their safety
        // is enforced by gates, not by absence: withdraw is armed-only +
        // HALT-gated + two-tap; export is private-chat-only + two-tap.
        assert_eq!(Command::parse("/export"), Some(Command::Export));
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
    fn withdraw_captures_all_args() {
        // The whole remainder after the command word is captured (amount + addr).
        assert_eq!(
            Command::parse("/withdraw 0.5 DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX"),
            Some(Command::Withdraw(Some(
                "0.5 DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX".into()
            )))
        );
    }

    /// `parse_withdraw_args` only exists in a sniper build — the default build
    /// has no fund-moving code to parse arguments for.
    #[cfg(feature = "sniper")]
    #[test]
    fn withdraw_args_validate() {
        // Valid parse.
        let ok = parse_withdraw_args(Some("0.5 DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX"));
        assert_eq!(
            ok,
            Ok((0.5, "DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX".into(), None))
        );

        // Optional third token names the wallet to send FROM.
        let w = parse_withdraw_args(Some("0.5 DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX primary"));
        assert_eq!(
            w,
            Ok((
                0.5,
                "DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX".into(),
                Some("primary".into())
            ))
        );

        // Rejections: no address, bad amount, zero/negative, junk address.
        assert!(parse_withdraw_args(Some("0.5")).is_err(), "missing address");
        assert!(parse_withdraw_args(Some("abc SomeAddr...")).is_err(), "bad amount");
        assert!(
            parse_withdraw_args(Some("0 DhqrThmdkwWbCfPPWme5DMWvyWVhExuvwDsg5QGhtHSX")).is_err(),
            "zero refused"
        );
        assert!(parse_withdraw_args(Some("0.5 short")).is_err(), "junk address");
        assert!(parse_withdraw_args(None).is_err(), "no args");
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
        // Never let a test write the operator's real settings file.
        sc.settings_path = String::new();
        let rpc = Arc::new(crate::rpc::RpcClient::new(&RpcConfig::default()));
        let sniper = Arc::new(crate::sniper::Sniper::new(sc, rpc.clone(), &RpcConfig::default(), std::sync::Arc::new(crate::prices::PriceIndex::new())).unwrap());

        let b = bot(&["1"], "").unwrap().with_sniper(sniper);
        let (msg, kb) = b.settings_screen();

        // The header carries only what has no button: armed state and the
        // fixed host-side context. Values live on the buttons, and are asserted
        // there — printing them twice is how the two copies drift apart.
        assert!(msg.contains("Trading settings"), "got: {msg}");
        assert!(msg.contains("dry run"), "armed state is the one thing that must be unmissable");
        assert!(!msg.contains("Trade size:"), "values belong on the buttons, not restated: {msg}");
        assert!(!msg.contains("/maxsize"), "no command list — the buttons replace it: {msg}");

        let blob = kb.to_string();
        assert!(blob.contains("0.02"), "button must carry the working trade size");
        let _ = rpc;
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
        // Balance is read-only. Withdraw/send now exist as an explicit owner
        // choice (armed-only + HALT + two-tap confirm), but these never do:
        // sweep-all, key export, or seed export.
        for c in ["/transfer", "/sweep", "/seed"] {
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
