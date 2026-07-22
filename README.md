# volens

Real-time Solana **new liquidity pool detector**. Streams transactions over
Yellowstone gRPC — or plain WebSocket on a standard RPC plan — and fires the
moment a tradable pool is created on:

| Venue | Program ID | Creation instruction |
|---|---|---|
| Raydium AMM v4 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | `initialize2` (tag `1`) |
| Raydium CPMM | `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C` | `initialize` (Anchor disc) |
| PumpSwap | `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` | `create_pool` (Anchor disc) |

It detects **actual pool creation**, not Pump.fun bonding-curve launches — i.e.
the real liquidity moment.

## Quick start

```bash
cp .env.example .env       # fill in ONE transaction source (below)
cargo run --release
```

Config resolution order (highest wins): **env var → `config.toml` → default**.
Pass an explicit config path as the first argument: `volens /path/config.toml`.

## Transaction source: gRPC or WebSocket

volens needs one source. gRPC is preferred and used whenever configured;
WebSocket is the automatic fallback so a **standard RPC plan works with no
Geyser at all**.

### A) Standard RPC plan (no Geyser) — e.g. $50 Helius developer

```bash
# .env
GRPC_ENDPOINT=                                  # leave EMPTY
RPC_URL=https://mainnet.helius-rpc.com/?api-key=<your-key>
```

That is the whole setup. volens derives the `wss://` URL from `RPC_URL`,
subscribes with `logsSubscribe`, and fetches each candidate with
`getTransaction`. All filters, alerts, dry-run and sniper functionality are
identical — the source is invisible to everything downstream.

### B) Geyser plan — the fast path

```bash
GRPC_ENDPOINT=https://mainnet.helius-rpc.com
GRPC_X_TOKEN=<your-key>
RPC_URL=https://mainnet.helius-rpc.com/?api-key=<your-key>
```

`RPC_URL` is still wanted: it powers the liquidity and mint-safety filters, the
watcher, `/balance`, and dry-run simulation.

### What WebSocket mode costs

**Detection lands 1.4–6s after the log event (avg 2.35s, measured live).** This
is a floor, not a tuning problem:

- `blockSubscribe` — which would deliver full transactions in one hop — returns
  **`Method not found`** on a standard plan.
- `logsSubscribe` delivers only `{signature, err, logs}` — no account keys, no
  instruction data, no inner instructions. It is a *trigger*, not a data source.
- The follow-up `getTransaction` **refuses any commitment below `confirmed`**
  (`Method does not support commitment below 'confirmed'`), so this path cannot
  observe a transaction at `processed` no matter how it is configured.

That is fine for alerting and for deliberate entries. It is a real disadvantage
against a sniper running Geyser, and you should not expect to win a race for the
first block on this path.

| | gRPC (Geyser) | WebSocket (standard plan) |
|---|---|---|
| Commitment | `processed` | `confirmed` (forced) |
| Latency | sub-second | **1.4–6s** (measured) |
| RPC calls per pool | 0 | 1 × `getTransaction` |
| Plan cost | Geyser tier | standard |
| Filters / alerts / sniper | identical | identical |

### Fallback behaviour

- gRPC configured and healthy → used, **no behaviour change whatsoever**.
- gRPC not configured → WebSocket from startup, with a loud warning.
- gRPC configured but failing to **connect** 3 times consecutively → falls back
  to WebSocket, loudly, and stays there for the process lifetime.

Only a failure to *establish* counts. A session that connected and later dropped
is a normal reconnect, not evidence gRPC is unavailable. Fallback is permanent
per process on purpose — flapping between sources would make latency
unpredictable and the logs unreadable. Restart once gRPC is fixed.

Set `fallback_to_websocket = false` to make a broken gRPC endpoint a hard
failure instead, which is the right call if running seconds behind silently
would be worse for you than not running.

## What an alert looks like

Structured log line plus an HTML Telegram message with the new mint, quote
asset, pool address, slot, and Solscan links for both the tx and the pool.
Alerts are deduplicated per pool for `dedup_ttl_secs` (default 300s), so a pool
touched repeatedly won't spam you.

Telegram auto-enables when `TELEGRAM_BOT_TOKEN` is set. Get a token from
[@BotFather](https://t.me/BotFather) and your chat id from
[@userinfobot](https://t.me/userinfobot).

## Configuration highlights

```toml
[filters]
require_quote_pair = true                       # only WSOL/USDC-paired pools
programs = ["raydium_v4", "raydium_cpmm", "pumpswap"]
quote_mints = ["So111...112", "EPjFW...Dt1v"]   # never treated as "the new token"
```

- `require_quote_pair = true` is the main noise filter. Turning it off surfaces
  every pool creation including exotic pairs.
- `commitment = "processed"` is fastest (best for detection). Use `confirmed`
  if you'd rather not see the occasional forked-away pool.

## Storage

| backend | notes |
|---|---|
| `jsonl` (default) | one JSON object per line, no C toolchain needed |
| `sqlite` | `cargo build --features sqlite`; needs a C compiler |
| `none` | logs/alerts only |

## Docker

```bash
cp .env.example .env       # fill in
docker compose up -d --build
docker compose logs -f
```

Set `path = "data/detected_pools.jsonl"` in `config.toml` so output lands in the
mounted `./data` volume. Parent directories are created automatically.

## Architecture

```
main.rs      orchestration, tracing, graceful shutdown (SIGINT/SIGTERM)
config.rs    layered TOML + env config, validated at startup
detector.rs  source selection (gRPC | WebSocket), reconnect+backoff, dispatch
ws.rs        WebSocket fallback: logsSubscribe -> getTransaction -> proto shape
parser.rs    instruction decoding -> ParsedPool  (pure, unit-tested)
rpc.rs       JSON-RPC enrichment: vault balance, token supply, mint authorities
liquidity  ->  quote-side size filter        (in detector::spawn_finalize)
safety     ->  mint/freeze authority filter  (in detector::spawn_finalize)
watcher.rs   delayed re-check: LP burn + liquidity-pull detection
dedup.rs     TTL dedup, above both storage and alerts
metrics.rs   counters + periodic summary line
alerts.rs    Telegram sendMessage
storage.rs   jsonl / sqlite / none
model.rs     program IDs, discriminators, account layouts, PoolEvent
```

Pipeline: `source → parse → classify/quote-pair → dedup → [spawned task:
liquidity → safety → emit → schedule watcher]`. Everything after dedup runs off
the hot path so no network read can stall stream consumption.

Design notes:

- **Inner instructions are scanned.** Pool creation is frequently a CPI (routers,
  migrations), so top-level-only parsing misses real launches.
- **Address lookup tables are resolved.** Instruction account indices are
  resolved against `account_keys ++ loaded_writable ++ loaded_readonly`, so
  versioned transactions parse correctly.
- **Backoff resets after a healthy session**, so a long-lived connection that
  drops reconnects fast instead of inheriting old backoff growth.
- **Both sources produce the same type.** `ws.rs` converts `getTransaction` JSON
  into the identical `SubscribeUpdateTransactionInfo` the gRPC path yields, so
  the parser, filters, dedup, alerts, storage and sniper are unaware of which
  source produced a transaction. The parser is the most heavily verified code
  here (mainnet-verified layouts, golden fixtures) and must not fork.
- **The WebSocket pre-filter matches instruction names exactly, not by
  substring.** Substring matching was tried and admitted 1,169 transactions in
  120s instead of 6, because `Instruction: Create` is a prefix of
  `CreateIdempotent` (every ATA creation) and `Instruction: Initialize` is a
  prefix of `InitializeAccount3` / `InitializeMint2`. That is ~195x the RPC
  spend, enough to exhaust a standard plan's quota.

## Parsing correctness

Both risky parts are now verified against mainnet, and `cargo test` locks them in.

**Discriminators** are self-verifying — the tests recompute them from
`sha256("global:<method>")`. They were additionally confirmed live: the
create-pool **fee accounts** for Raydium v4 (`7YttLkHD…`) and CPMM (`DNXgeM9E…`)
receive a payment on every single pool creation, so their transaction histories
are pure creations. Every recent tx on those accounts carries exactly the
discriminators we match.

**Account layouts** were confirmed by decoding a real creation tx per venue and
checking each account's on-chain owner and type. All three layouts were correct
as written; the transactions are cited in `Dex::layout` and captured as golden
fixtures in `parser::tests`, so a program upgrade that shifts an index fails a
test instead of silently reporting the wrong mint.

### ⚠️ Mint orientation is not consistent across venues

Verified on mainnet:

| Venue | base side | quote side |
|---|---|---|
| Raydium v4 | new token | WSOL |
| Raydium CPMM | **WSOL** | **new token** |
| PumpSwap | **WSOL** | **new token** |

Two of three venues put WSOL on the *base* side. Any detector that assumes
"base = the launched token" will report **WSOL as the new token** for most
Raydium CPMM and PumpSwap pools. `Detector::classify` avoids this by testing
both mints against the known quote assets rather than trusting position.

```bash
cargo test                              # 45 offline tests
cargo test --features sniper            # 112, incl. guards, encoding, quotes, signing, arming, bundles
cargo test -- --ignored --nocapture     # + live mainnet RPC checks
```

The live test includes a **positive control**: every token from the verified
creation txs has revoked authorities, so on its own the suite couldn't tell
"parses correctly" from "always returns None". It therefore also reads USDC,
which is centrally controlled and has both authorities live, proving the parser
actually distinguishes the two states.

## Liquidity filter

After a pool is detected, volens reads the vault holding the **quote asset** and
drops pools that launched thin — the highest-signal noise filter available.

```toml
[rpc]
url = "https://your-rpc"            # or env RPC_URL (auto-enables the filters)

[liquidity]
enabled = true
min_quote_liquidity = 5.0           # SOL for WSOL pairs, USDC for USDC pairs
emit_on_unknown = true              # can't read it? emit rather than drop
```

Three decisions worth knowing about:

**Only the quote side is measured.** Summing both vaults is meaningless — the
token side can hold a billion units of something worthless. Only SOL/USDC
measures committed capital.

**Vaults come from fixed instruction indices, never by searching.** Both Raydium
creation instructions also reference the protocol's create-pool *fee* account,
which is itself a WSOL token account holding **699 SOL** (v4) and **4,598 SOL**
(CPMM) at time of verification. Any "find the token account holding WSOL"
approach reads the fee account and reports thousands of SOL for an empty pool.
The indices are verified and locked by fixtures.

**Which vault is the quote vault depends on the venue.** Because orientation
flips (see above), the WSOL vault is the *quote* vault on Raydium v4 but the
*base* vault on CPMM and PumpSwap. `classify_pool` follows the classification
rather than the position; `detector::tests` covers both directions.

The read runs in a spawned task, so the RPC round-trip and its retries never
stall consumption of the gRPC stream. A failed read is recorded as *unknown*,
never as zero — otherwise an unreadable vault would look like an empty pool and
be silently filtered as low-liquidity.

Watch `low_liquidity_filtered` in the metrics line to tune the threshold.

## Mint-safety filter

The highest-signal noise reduction available from a single account read. After
detection, volens reads the launched token's mint and can drop it on:

| Check | Why it matters |
|---|---|
| `require_mint_authority_revoked` | A live mint authority means supply can be inflated at will — your position gets diluted to nothing. |
| `require_freeze_authority_revoked` | A live freeze authority is the classic **honeypot**: you buy freely, then your token account is frozen and you cannot sell. |
| `reject_risky_extensions` | Token-2022 extensions that tax or block a sale: `transferFeeConfig`, `transferHook`, `permanentDelegate`, `defaultAccountState`, `nonTransferable`. |

```toml
[safety]
enabled = true
require_mint_authority_revoked = true
require_freeze_authority_revoked = true
reject_risky_extensions = true
emit_on_unknown = true     # unreadable mint => emit, don't silently drop
```

Alerts render authorities as `mint ✅ · freeze ⚠️ LIVE`. The line is **omitted
entirely when the check didn't run** — absence means "not checked", which must
never be read as "checked and clean".

Watch `unsafe_mint_filtered` alongside `low_liquidity_filtered` in the metrics
line to see which filter is doing the work.

## Delayed follow-up (LP burn + rug detection)

LP burn/lock **cannot be checked at detection time**. It is almost always a
separate, later transaction. Measured on mainnet:

| Pool | LP mint txs | Outcome |
|---|---|---|
| Raydium CPMM | 1 (creation only) | never burned — creator still holds LP |
| PumpSwap | 3 | burned, but **479 s (~8 min) after creation** |
| Raydium v4 | — | never burned; 450,961 LP still outstanding |

A synchronous LP filter would therefore reject legitimate launches that burn
moments later. Instead volens re-reads the pool after a delay:

```toml
[watch]
enabled = true
delay_secs = 120
rug_drop_pct = 0.5      # quote liquidity vanishing by this fraction = pull
alert_on_all = false    # only alert on notable outcomes
```

Verdicts, in precedence order:

- **🚨 LIQUIDITY PULLED** — quote-side liquidity fell by `rug_drop_pct` or more.
  Ranked first: if both a pull and a burn happened, the money already left.
- **🔥 LP burned** — LP supply fell to zero (requires a baseline reading taken at
  detection; an LP mint that was always empty is not evidence of a burn).
- **LP outstanding** / **unknown** — routine, not alerted unless `alert_on_all`.

Follow-ups are written to storage as their own tagged record (`"record"` field
in JSONL, upserted in SQLite), so the log keeps each pool's lifecycle rather than
only its launch moment.

This is the filter that catches rugs the mint-safety checks structurally cannot:
a token with both authorities revoked can still be drained by pulling liquidity.

## Sniper (auto-execution)

> **Dry run by default. Arming spends real funds.** The trade path is built and
> verified by mainnet simulation on all three venues, but **no live trade has
> ever been executed by this code** — signing, submission, and confirmation
> cannot be verified without sending. See the
> [First Armed Trade Checklist](#first-armed-trade-checklist).

```bash
cargo build --features sniper    # off by default — a normal build cannot trade
```

Safety model, in order of strength:

1. **Compiled out by default.** Setting `sniper.enabled = true` without the
   feature is a *startup error*, never a silent no-op — the operator must not
   believe trading is on when it isn't.
2. **Dry-run is inert, not flag-guarded.** `Mode::DryRun` carries no signing
   capability, so execution is a *type error* rather than a runtime check. A
   `if dry_run {}` guard is one bad merge away from spending funds; this is not.
   No key material is loaded or held in memory at all.
3. **Arming requires a keypair file.** No path, or an unreadable one, is a
   startup error — never a silent fallback to dry run.
4. **Every decision is audited** — allowed or denied — to an append-only log.
5. **Kill switch is checked per decision**, so `touch HALT` halts instantly with
   no restart, and survives a crash because it's a file rather than a flag.

```toml
[sniper]
enabled = false
armed = false               # true = spends real funds; read the checklist first
trade_size_sol = 0.05
max_trade_size_sol = 0.25   # hard ceiling; trade_size may not exceed it
daily_cap_sol = 1.0
max_trades_per_day = 10
pool_cooldown_secs = 3600   # same pool cannot be bought twice in this window
min_liquidity_sol = 10.0    # re-checked at execution, stricter than alerts
kill_switch_file = "HALT"   # touch it to halt instantly, no restart
audit_log = "sniper_audit.jsonl"
```

**The cooldown is not the alert dedup.** Dedup suppresses duplicate
*notifications* and expires; it is not a spend guard. A gRPC reconnect can
replay recent slots, and a pool re-entering detection after the dedup TTL would
otherwise be bought again. The cooldown is recorded when budget is reserved —
so a trade that failed to build does not lock the pool out, and a trade that
proceeded cannot repeat.

Pre-trade re-checks run against the event at execution time, not the detection
snapshot: live mint or freeze authority, risky Token-2022 extensions, and
liquidity below `min_liquidity_sol` all refuse the trade.

**Unknown liquidity is refused**, even though the alert path emits it. Notifying
about an unverified pool and spending money on one are different risk postures.

Run with a **dedicated wallet**, never your main one.

## Swap layouts (verified — reference only)

`swap.rs` holds mainnet-verified swap instruction layouts. It **builds no
transactions**; it exists so the layouts are locked down before any code signs
anything. Verification method identical to the creation layouts: decode real
swaps, resolve every account's on-chain owner/type/mint.

Three traps found, all of which would produce a silently wrong instruction:

**1. Raydium v4's swap layout is variable-length.** `swapBaseIn` appears live
with both 17 and 18 accounts (sampled 5×17, 1×18). The 18-account form inserts
`amm_target_orders` at index 4, shifting the vaults from `(4, 5)` to `(5, 6)`.
Nothing in the instruction *data* distinguishes the two — you must branch on
account count. Reading `(4, 5)` on an 18-account instruction returns the
open-orders and target-orders accounts instead of the vaults.

**2. v4 market accounts can be placeholders.** On a pool with no OpenBook
market, indices 1/3/4/7 were all the *same* account (the pool itself), so
"does index 3 look like an OpenBook account?" cannot detect the variant either.

**3. Raydium CPMM positions are INPUT/OUTPUT, not base/quote.** Verified with
two swaps in opposite directions: the same index holds WSOL or the token
depending on trade direction. To buy a token with SOL the *input* vault is
whichever vault holds WSOL — which, given the orientation flip, is CPMM's
**base** vault. Mapping a stored `base_vault` onto the input position by
convention spends the wrong side of the pool.

PumpSwap is the tidiest: indices 0..=8 are identical for `buy` and `sell`
(pool, user, config, both mints, both user ATAs, both pool vaults), and only the
tail differs — buy carries two extra volume-accumulator accounts (25 vs 23) and
one extra data byte.

Also corrected during this work: the `buy`/`sell` discriminators are easy to
transpose, and an earlier comment in `parser.rs` had them swapped. Both are now
asserted by recomputation from `sha256("global:<method>")`.

## Transaction path (built, simulated, never submitted)

`tx.rs` builds and signs transactions. There is **no `sendTransaction` call
anywhere in it** — submission is a separate step behind the still-refused
`armed` flag.

Verified end-to-end by **simulating against real mainnet state**
(`sigVerify: false` + `replaceRecentBlockhash: true` — no key, nothing
submitted, nothing charged). Confirmed run:

```
err: null      unitsConsumed: 33267
ComputeBudget x2 -> CreateIdempotent (WSOL) -> transfer -> SyncNative
  -> CreateIdempotent (token) -> Instruction: SwapBaseInput  SUCCESS -> close
```

Plus a golden test asserting the encoder reproduces a real mainnet swap
byte-for-byte — same account order, same signer/writable flags, same data — and
a test deriving the CPMM authority PDA and matching it against the authority
every live swap uses.

### Per-venue status

| Venue | Encoder | Verified by |
|---|---|---|
| Raydium CPMM | ✅ complete | golden fixture (byte-for-byte) + live simulation `err=null` |
| Raydium v4 | ✅ complete | golden fixture + OpenBook market decode + live simulation `err=null` |
| PumpSwap | ✅ complete | golden fixture (byte-for-byte) + live simulation `err=null` |

**Raydium v4** needs the OpenBook market decoded — bids, asks, event queue,
market vaults and vault signer appear in no creation instruction. The 388-byte
`MarketState` layout is verified field-by-field against a live market, the
vault signer is derived with `create_program_address` using the market's own
nonce, and both the 17- and 18-account forms are covered (a test asserts every
index after 4 shifts when `amm_target_orders` is present).

**PumpSwap** required the most work. `pumpswap_buy` reproduces a real mainnet
buy byte-for-byte, and layouts came from the program's **on-chain Anchor IDL**,
which settled several things sampling could not:

- `buy` declares **23** accounts, `sell` **21**. The 25/26/27-account forms seen
  on-chain pass extras as Anchor `remaining_accounts` — which is why the tail
  looked variable-length and underivable from transaction samples alone.
- `Pool.coin_creator` is at **offset 211** (seeds `creator_vault_authority`, and
  is frequently all-zero — hence one authority appearing to serve many pools).
- Only the **LP fee** is charged on the curve; protocol and creator fees come
  off the output.

### The undocumented trailing accounts

**The deployed program is newer than its published IDL** — the IDL's errors stop
at 6058, but a swap throws `InvalidPoolV2` (6062). Three accounts must follow the
declared list, none of them documented:

```
[ ...23 declared..., pool_v2, buyback_fee_recipient, buyback_recipient_ata ]
```

- **`pool_v2`** — not derivable (~400 candidate PDA seeds failed) and usually
  *uninitialized*, so it can't be found from chain state either. It is carried in
  the pool's own **creation transaction**, inside the migration `buy` that runs
  in the same tx. The detector already parses that transaction, so it is
  **captured, not derived**. Pools whose creation we never saw are refused, with
  a reason that says so — before any network work.
- **`buyback_fee_recipient`** — any live slot of
  `GlobalConfig.buyback_fee_recipients` (offset 643). This is a **different set**
  from `protocol_fee_recipients` (offset 57); passing one of those fails with
  `BuybackFeeRecipientNotAuthorized` (6053). Being a *registered set* rather than
  PDAs is exactly why no seed reproduced them, and why the same few accounts
  recur across unrelated pools.
- **`buyback_recipient_ata`** — a plain `ata(recipient, quote_mint)`.

### Getting a program's IDL

Anchor publishes IDLs on-chain at a deterministic address:
`base = find_program_address([], program_id)`, then
`create_with_seed(base, "anchor:idl", program_id)`. The account is
`8-byte disc + 32 authority + 4-byte len + zlib-compressed JSON`. With the Anchor
CLI it is just `anchor idl fetch <program_id>`.

| Program | IDL account |
|---|---|
| PumpSwap | `5fLnXNNoZcZt9Qku6HARM3un3Ttm2cGsR7gN9Zp1R7h3` |
| Pump fee | `6hgWp61YgGzJ9QmvxyFtLnGfA8MYgx93Hby6fdq8gG31` |
| Raydium CPMM | `3HD1FNEKoNh5aYfvw3VrNWy6WwrEtS6JYx1RmFTE7DMC` |

Verify the IDL is current before trusting it — comparing its error-code range
against errors the program actually throws is a quick check.

### Token-2022 is not optional

Most pump.fun mints are **Token-2022**, not classic SPL Token. The two are not
interchangeable: deriving an ATA or building a token instruction with the wrong
program fails with `IncorrectProgramId`. Mint owners are read at build time,
never assumed.

### Dependency decision, reversed on purpose

`rpc.rs` avoids `solana-client` because two JSON-RPC methods don't justify it.
That reasoning does **not** transfer to transaction building: PDA derivation
(off-curve checks over curve25519), message serialization, and signing must not
be hand-rolled in code that moves money. So `tx.rs` uses the official split
crates — all `optional`, all gated behind the `sniper` feature, so a
detector-only build pays nothing for them.

### Two safety details

`Wallet` implements `Debug` **manually**, printing only the pubkey. A derived
impl would render secret key bytes into any log line that formats it.

`minimum_amount_out` is the only slippage protection that exists. The real
mainnet swap used as the fixture passed **0** — accepting any output, including
near-zero. That is what a sandwich bot wants you to do; the encoder takes it as
a required parameter rather than defaulting it.

## Submission — built, but never exercised

`submit.rs` signs, preflights, sends, and polls for confirmation.

Everything else in this project was verifiable before it cost anything. **This
is not.** There is no way to confirm a send works except by sending, so the
module compensates with runtime guards rather than pre-verification:

- **Mandatory preflight.** Every send simulates first and refuses on failure.
  Snipers often skip preflight for speed; the default here is safety, and
  disabling it is explicit and logged.
- **Fresh blockhash per attempt** — a stale one is the most common reason a
  transaction silently never lands.
- **`Unconfirmed` is not `Confirmed`.** A timeout reports the signature as
  unknown, never as success. Conflating the two is how a bot double-buys.
  `RejectedByPreflight` carries no signature at all, because nothing was sent.

What *is* verified offline: signatures verify against their transaction, signing
with a non-payer key fails, the encoding round-trips, and the blockhash is
covered by the signature (replay protection).

## The execute path

`execute.rs` joins detection to execution: `PoolEvent` → fresh state → quote →
instructions. Verified end-to-end by building a real CPMM buy from a
detection-shaped event and simulating it (`err: null`, `SwapBaseInput` executing,
a real non-zero `minimum_out`).

Two rules it exists to enforce:

**State is re-read, never reused.** Reserves captured at detection are already
stale — other buyers move the pool within the same second. A quote from stale
reserves misprices the guard: too high and the swap reverts, too low and it
protects nothing. Pool state, fees, vault balances and market state are all
fetched fresh immediately before quoting.

**Unsupported venues are refused, not approximated.** PumpSwap returns an error.

### Dry run is a real rehearsal

With `simulate_as` set, a dry run builds the **actual** transaction and simulates
it against live mainnet, logging `would-succeed` or `would-FAIL: <reason>`. A
pubkey cannot sign, so this adds no capability — `Mode::DryRun` still holds no
wallet. This is the safest way to validate the whole chain before arming: run it
against live detections and watch what it *would* have done.

#### Dry-run config block

Copy this into `config.toml` for the rehearsal period:

```toml
[sniper]
enabled = true
armed = false

# REQUIRED. Without it the sniper refuses with NoSimulationIdentity *before
# building anything* — you get a log full of skips and learn nothing. Use the
# FUNDED wallet you intend to arm with: simulation runs against real on-chain
# state, so an unfunded address can report a clean result that proves nothing.
simulate_as = "<pubkey you control, funded>"

trade_size_sol = 0.01        # rehearse the size you'll actually arm with
max_trade_size_sol = 0.05
daily_cap_sol = 0.05
max_trades_per_day = 5
min_liquidity_sol = 10.0
slippage_bps = 300           # do NOT widen this; see below
max_price_impact_bps = 1000
pool_cooldown_secs = 3600
preflight = true
kill_switch_file = "HALT"
audit_log = "sniper_audit.jsonl"

# Off during rehearsal: Jito does not simulate bundles, so bundling adds
# nothing to a dry run and only removes the RPC error messages you want to see.
jito_enabled = false
```

Rehearse at the **same `trade_size_sol` you intend to arm with**. Price impact
and slippage are size-dependent, so a rehearsal at 0.01 tells you little about a
live trade at 0.5.

> **On slippage.** 300 bps (3%) is the default for a reason. Widening it to
> "get filled" on thin new pools is self-defeating: `minimum_out` is public in
> the transaction, and a sandwich bot will move the price to just inside your
> tolerance and take the difference. Wide slippage does not buy you speed — it
> pre-authorises your own loss.

#### What dry run does and does not verify

| Verified | **Not** verified |
| --- | --- |
| Account layouts, discriminators, ALT resolution | Signing |
| Quote math and the `minimum_out` guard | Submission |
| Price-impact refusal | Confirmation polling |
| Cooldown, daily caps, mint-safety gates | Jito bundle acceptance |
| That the trade *would* have succeeded on-chain | Actual fill and price |

Simulation verifies **construction**. The send path cannot be verified without
sending — which is what makes the first armed trade a genuine first run rather
than a confirmation.

#### Acceptance bar before arming

Don't run dry "for a bit" — run it until you have seen `would-succeed` on **all
three venues**: Raydium v4, Raydium CPMM, and PumpSwap. They have different
account layouts and different failure modes (PumpSwap in particular needs
`pool_v2` captured from the creation transaction). If you have only ever seen
CPMM rehearsals, you have verified roughly one third of the path.

Check the audit log for what actually happened:

```bash
# Outcomes by venue
jq -r 'select(.plan) | "\(.plan.dex)\t\(.outcome)"' sniper_audit.jsonl | sort | uniq -c

# Any rehearsal that would have failed, with the reason
jq -r 'select(.outcome | tostring | startswith("would-FAIL")) | .outcome' sniper_audit.jsonl
```

A `would-FAIL` also sends a Telegram alert with the simulation error. Those are
the highest-value output of the rehearsal period — read every one before arming.

### Arming

```toml
[sniper]
armed = true
keypair_path = "/path/to/dedicated-wallet.json"   # REQUIRED; no default
max_price_impact_bps = 1000                        # refuse self-inflicted 10%+ moves
preflight = true
```

`Mode::Armed` is constructible **only** by loading a keypair file. No path, or a
missing file, is a startup error — never a silent fallback to dry run. Arming
logs a loud warning naming the wallet, the caps, and the kill-switch path.

Budget is consumed only by trades that actually proceed; a run of refusals does
not silently exhaust the daily cap.

> **No live trade has ever been executed by this code.** Construction is verified
> extensively; the send path cannot be verified without sending. Run dry with
> `simulate_as` first, then make the first armed trade a supervised one at
> minimum size.

## Generating a test wallet

For a supervised live test you need a throwaway wallet. Rather than importing an
existing key — which risks exposing it — generate a fresh one locally:

```bash
cargo run --features sniper -- gen-wallet            # -> ./test-wallet.json
# or: volens gen-wallet /path/to/wallet.json
```

It prints only the **public address** and writes the key to a `0600` file on
this machine. The key is created here and never transmitted anywhere.

- **Fund the printed address** with a small amount (0.05 SOL is plenty for a
  0.01 SOL test trade). The key lives in the file, on this machine, so whoever
  runs the bot is the wallet's custodian — fund it only with throwaway amounts.
- Point config at it: `keypair_path` = the file, `simulate_as` = the address.
- It refuses to overwrite an existing file (that file may hold funds).

This is the safe path when the person funding the wallet is not the person
running the bot: they send SOL to an address, never a key.

## First Armed Trade Checklist

The first armed run is the highest-risk moment in this project: signing,
submission, and confirmation have never executed. Treat it as a supervised
experiment with a known blast radius, not as a config change.

**Do not skip step 1.** `touch HALT` before arming means the process cannot
trade while you are still editing config or reading logs — it removes the window
where the bot goes live before you are watching.

### Before

- [ ] **1. `touch HALT`** — engage the kill switch *first*, while still disarmed.
- [ ] **2. Dry run passed the acceptance bar** — `would-succeed` seen on all
      three venues, every `would-FAIL` read and understood.
- [ ] **3. Dedicated wallet.** A fresh keypair used for nothing else. Never your
      main wallet, never one holding funds you would mind losing entirely.
- [ ] **4. Fund it minimally** — enough for one trade plus fees. ~0.05 SOL total
      for a 0.01 SOL trade. The wallet's balance *is* your real maximum loss,
      regardless of what the caps say.
- [ ] **5. `simulate_as` matches the armed wallet's pubkey**, so the rehearsal
      you validated is the account that will actually trade.
- [ ] **6. Constrain the blast radius:**
      ```toml
      trade_size_sol     = 0.01   # minimum that clears rent + fees
      max_trade_size_sol = 0.01   # hard ceiling equal to the trade size
      daily_cap_sol      = 0.01   # exactly one trade's worth
      max_trades_per_day = 1      # one trade, then it stops on its own
      ```
      With these, a bug that fires repeatedly still costs one minimum trade.
- [ ] **7. `preflight = true`** — simulate before every send. Leave it on.
- [ ] **8. `jito_enabled = false`** for the first trade. Bundles are not
      simulated by Jito and failures surface as "did not land" rather than a
      readable error. Add them once plain submission is proven.
- [ ] **8b. `/balance` reads correctly** — run it once before arming and
      confirm the address is your throwaway wallet and the SOL figure matches
      what you funded. If it says "could not read", fix the RPC first: an
      unreadable balance during a live run is a blind spot, not a cosmetic bug.
- [ ] **9. Telegram alerts working** — send yourself a test. You want the
      execution alert to arrive, especially the `⚠️ OUTCOME UNKNOWN` one.
- [ ] **10. `/halt` reachable from your phone** if you enabled commands. Test it
      *before* arming, not during.

### Arming

- [ ] **11. Set `armed = true`, `keypair_path = "..."`, and restart.**
- [ ] **12. Confirm the startup warning** names the right pubkey and caps:
      `*** SNIPER ARMED — THIS WILL SPEND REAL FUNDS ***`
      If the pubkey is not your throwaway wallet, stop.
- [ ] **13. `rm HALT`** — only now, and only with your hand on the keyboard.

### During

- [ ] **14. Watch the first detection through.** Do not walk away.
- [ ] **15. On any surprise, `touch HALT`.** It takes effect on the next
      decision; nothing in flight is interrupted, nothing new starts.

### After

- [ ] **16. `touch HALT` again** once the trade completes, before analysing.
- [ ] **17. Verify on-chain.** Open the Solscan link from the alert and confirm
      the fill matches `minimum_out` and the expected size.
- [ ] **18. Read the audit record:**
      ```bash
      jq 'select(.mode == "armed")' sniper_audit.jsonl | tail -1
      ```
- [ ] **19. Reconcile the wallet balance** against what you believe was spent.

### If the alert says `⚠️ OUTCOME UNKNOWN`

This is the one outcome that needs a human, and the natural reaction is the
wrong one.

**Do not retry. Do not re-arm.** An unknown outcome means the transaction may
have landed — an RPC transport error can occur *after* the node accepted it, and
an unconfirmed transaction can still confirm later. Retrying buys twice.

1. `touch HALT`.
2. Check the wallet on Solscan for a transaction in the last few minutes.
3. Reconcile the balance before doing anything else.

Only `⚪ Not executed` guarantees no funds moved — that outcome is reserved for
preflight rejection and non-landed bundles, where nothing could have executed.
`Submission::definitely_did_not_execute()` is the single source of truth for
that distinction, and a test pins the alert wording to it.

### Failure is a normal result

A first armed trade that fails cleanly — preflight rejection, a non-landed
bundle, a slippage refusal — is a **good** outcome. It exercised the path and
cost nothing. What you are buying with this checklist is not a successful trade;
it is an *understood* one.

## Jito bundles

Optional atomic submission through Jito's block engine, bypassing the public
mempool.

```toml
[sniper]
jito_enabled = true
jito_tip_lamports = 100000     # too low and the bundle never lands
```

**The tip rides inside the bundle.** A bundle that does not land pays no tip,
burns no fee, and executes nothing — so `BundleNotLanded` is genuinely safe to
retry. That is a real difference from plain submission, where an `Unconfirmed`
transaction may still land and retrying risks double-buying. The two outcomes
are distinct types, and `definitely_did_not_execute()` is true only for the
bundle case.

**Jito does not simulate bundles.** There is no preflight on their side, so the
normal RPC simulation stays mandatory before bundling — otherwise a malformed
transaction is discovered only by never landing.

Verified against the live block engine:

- **Tip accounts are fetched** via `getTipAccounts` (8 at time of writing), never
  hardcoded — they are operational infrastructure and can rotate. Tipping is
  refused outright if the list has not loaded, because an untipped bundle is
  silently ignored. Tips rotate across accounts to avoid write-lock contention.
- **Max 5 transactions per bundle**, enforced locally before sending (the engine
  rejects 6 with an explicit error).
- **`getBundleStatuses` returns an empty array for an unknown bundle**, not an
  error. That is reported as `Unknown` — never as landed, and never as failed,
  since a bundle can still be in flight.

## Endpoint requirements (don't skip this)

Sustained gRPC streaming is genuinely demanding, and public endpoints are not
viable for it — expect frequent disconnects, missed slots during congestion, and
enough added latency to lose the detection edge entirely. The reconnect logic
will keep the process alive on a bad endpoint, but silently missed pools are the
failure you won't notice. Budget for a paid provider (Helius / Triton /
QuickNode) before trusting output. Public RPC is fine for poking at history, not
for the live stream.

## Status / roadmap

Working today: gRPC streaming, three venues, ALT + CPI-aware parsing, mainnet-
verified layouts and vaults with golden fixtures, orientation-agnostic token
classification, quote-pair filtering, quote-side liquidity filter, mint-safety
filter (mint/freeze authority + Token-2022 extensions), Telegram alerts,
detector-level TTL dedup, periodic metrics, JSONL/SQLite persistence, reconnect
with backoff, graceful shutdown, Docker.

All three venues build and simulate cleanly; there are no refused paths left.

Not done yet: a first supervised live trade. Also volume/attention signals,
multi-chain, dashboard.

Known limitations:

- Liquidity is read as a raw quote-asset amount. A USDC-paired pool at
  `min_quote_liquidity = 5.0` means 5 USDC, not 5 SOL worth — there is no price
  conversion between quote assets yet.
- Each detection spawns an unbounded task. Fine at observed creation rates (a
  handful per minute after dedup), but a sustained burst against a slow RPC
  would accumulate in-flight reads. Add a semaphore if that ever shows up.
- Fixtures prove the decoder against historical RPC data. The live gRPC path
  uses the same proto shapes, but that equivalence is reasoned, not observed —
  sanity-check the first few live detections against Solscan.
- Token-2022 extension *rejection* is only tested against synthetic JSON; no
  real mint carrying a risky extension has been run through it yet. The
  authority checks are verified live in both directions.
- The watcher takes a single reading at `delay_secs`. A pool rugged at +10 min
  with `delay_secs = 120` is missed; there is no repeated polling schedule.
- LP "burned" is inferred from supply going to zero. LP *locked* in a third-party
  locker (Streamflow, Team Finance) still reads as outstanding — it is not
  distinguished from creator-held.
