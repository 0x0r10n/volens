# volens — operator manual (static site)

The Telegram bot's user-facing guide. Plain HTML, no build step, no
dependencies: one file, one stylesheet inlined, fonts from Google Fonts.

## Deploying on Vercel

Import the repository, then set **Root Directory** to `site`. Framework preset
is **Other**; leave build and output commands empty — Vercel serves the
directory as static files.

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
| Reading the settings screen | `bot.rs` — `settings_screen` |
| Selling: stops and targets  | `bot.rs` — `exits_screen`, `order_screen` |
| Volume mode                 | `bot.rs` — `volume_screen` |
| What runs before every buy  | `sniper.rs` — `buy_mint` guards |
| Reading the alerts          | `alerts.rs` — `render_smart_buy`, `render_auto_sell` |

## Contents

No secrets, no wallet addresses, no server details — it explains how to operate
the bot, not how to reach any particular instance of it.
