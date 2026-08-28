# volens — operator manual (static site)

The Telegram bot's user-facing guide. Plain HTML, no build step, no
dependencies: one file, one stylesheet inlined, fonts from Google Fonts.

## Deploying on Vercel

Import the repository. Nothing to configure — the `vercel.json` at the repo
root pins the framework to none and the output directory to `site/`.

That file exists because of a real trap: Vercel autodetects **Zola** from a
`config.toml` in the repo root, and volens has one — the bot's own config. Left
to autodetection the build fails with *"A base URL is required in config.toml
with key `base_url`"*, which is Zola complaining about a file that has nothing
to do with the website. Pinning `framework: null` stops the guessing.

Every push to `main` redeploys. The manual is therefore updated the same way
everything else in this repo is: edit, commit, push.

## Why it lives in the repo

The manual describes controls that exist in the code. Keeping it beside the
code means a setting cannot be renamed, or a guard removed, without the file
that documents it sitting in the same diff.

When you change behaviour that the manual describes, change the manual in the
same commit. The sections most likely to go stale:

| Section | Tracks |
|---|---|
| Reading the settings screen | `bot.rs` — `settings_screen` and its four sub-screens |
| What triggers a buy         | `detector.rs` — the smart-SOL gate; `bot.rs` — `autobuy_screen` |
| Selling                     | `exits.rs` — `evaluate`; `bot.rs` — `exits_screen` |
| Sizing by market cap        | `settings.rs` — `BuyTier`; `bot.rs` — `tiers_screen` |
| What runs before every buy  | `sniper.rs` — `buy_mint` guards |
| Reading the alerts          | `alerts.rs` — `render_smart_buy`, `render_auto_sell`, `render_leaderboard` |
| What the signal is worth    | `tools/score_wallets.py` — re-run to refresh the figures |

## Contents

No secrets, no wallet addresses, no server details — it explains how to operate
the bot, not how to reach any particular instance of it.
