#!/usr/bin/env python3
"""Score tracked wallets on how the tokens they bought actually performed.

    python3 tools/score_wallets.py [--buys tracked_buys.jsonl]
                                   [--outcomes token_outcomes.jsonl]
                                   [--min-buys 3] [--top 25]

WHAT THIS MEASURES

"Did the token rise after they bought", NOT "did this wallet make money".
volens logs buys, not sells, so a wallet that takes profit at 3x and lets the
rest bleed scores badly here. For a follow signal the first question is still
the right one: their exit is not a trade you can copy after the fact.

TWO SOURCES, IN ORDER OF PREFERENCE

  1. token_outcomes.jsonl — sampled at fixed horizons (1h/6h/24h) by the
     running detector. Gives PEAK and per-horizon performance, and marks
     tokens that stopped routing. This is the good data.

  2. A live Jupiter quote per token — end-state only. Used for tokens with no
     samples yet. It conflates "ran 5x then died" with "never moved", which is
     most of what wallet quality means, so treat these numbers as provisional.

Sample size is the thing to watch. A wallet with two buys tells you nothing;
--min-buys exists to stop the leaderboard filling with noise.
"""
import argparse, collections, json, os, sys, time, urllib.request

WSOL = "So11111111111111111111111111111111111111112"
JUP = "https://lite-api.jup.ag/swap/v1/quote"


def load_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # a torn final line during a live append is normal
    return out


def quote_sol(mint, raw, timeout=12):
    """(sol, status) with status "ok" | "unroutable" | "unknown".

    The tri-state is the whole point. An earlier version returned None for both
    "this token has no market" and "the endpoint refused us", and the caller
    scored both as rugs — so one rate-limited run reported 196 of 196 tokens
    dead. A refusal is our problem, not the token's, and must never be written
    into the dataset as an outcome.

    Only an explicit 400 is read as unroutable: that is what the quote API
    returns for a token with no route, and we control the other parameters. A
    429, a 5xx or a timeout is us being throttled or offline.
    """
    url = f"{JUP}?inputMint={mint}&outputMint={WSOL}&amount={int(raw)}&slippageBps=100"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as f:
            return int(json.load(f)["outAmount"]) / 1e9, "ok"
    except urllib.error.HTTPError as e:
        return None, "unroutable" if e.code == 400 else "unknown"
    except Exception:
        return None, "unknown"


def outcomes_by_mint(samples):
    """mint -> {peak, final, horizons{secs: mult}, rugged}."""
    by = collections.defaultdict(list)
    for s in samples:
        by[s["mint"]].append(s)
    out = {}
    for mint, rows in by.items():
        rows.sort(key=lambda r: r["horizon_secs"])
        mults = [r["multiple"] for r in rows]
        out[mint] = {
            "peak": max(mults) if mults else 0.0,
            "final": mults[-1] if mults else 0.0,
            "horizons": {r["horizon_secs"]: r["multiple"] for r in rows},
            # Rugged = the latest sample could not be routed at all.
            "rugged": not rows[-1]["routed"],
            "n": len(rows),
        }
    return out


def groups_by_wallet(path):
    """address -> [group]. Absent file or untagged wallets yield nothing."""
    if not os.path.exists(path):
        return {}
    try:
        # utf-8-sig: exports arrive with a BOM often enough to be worth handling.
        with open(path, encoding="utf-8-sig") as f:
            rows = json.load(f)
    except Exception:
        return {}
    return {r["trackedWalletAddress"]: r.get("groups") or []
            for r in rows if r.get("trackedWalletAddress")}


def report_groups(W, wallets_path):
    """Compare cohorts — an imported leaderboard against the hand-built list.

    A wallet in several groups is counted in each, so the rows overlap and do
    not sum to the aggregate. That is the right trade: the question is how a
    cohort performs, not how to apportion credit between overlapping labels.
    """
    tags = groups_by_wallet(wallets_path)
    if not tags:
        print(f"\n(no group tags found in {wallets_path})")
        return

    G = collections.defaultdict(lambda: {
        "wallets": 0, "n": 0, "paid": 0.0, "peak_w": 0.0, "final_w": 0.0, "rugs": 0, "wins": 0})
    for addr, v in W.items():
        if v["n"] == 0 or v["paid"] <= 0:
            continue
        for g in tags.get(addr) or ["(untagged)"]:
            r = G[g]
            r["wallets"] += 1
            for k in ("n", "paid", "peak_w", "final_w", "rugs", "wins"):
                r[k] += v[k]

    print(f"\nBY GROUP  (wallets in several groups count in each)\n")
    print(f"{'group':<20}{'wlt':>5}{'buys':>6}{'paid':>9}{'peak':>7}{'final':>7}{'2x+':>7}{'rug':>7}")
    print("-" * 68)
    for g, r in sorted(G.items(), key=lambda kv: -kv[1]["peak_w"] / kv[1]["paid"]):
        print(f"{g[:20]:<20}{r['wallets']:>5}{r['n']:>6}{r['paid']:>9.2f}"
              f"{r['peak_w']/r['paid']:>6.2f}x{r['final_w']/r['paid']:>6.2f}x"
              f"{r['wins']:>6}/{r['n']}{r['rugs']:>6}/{r['n']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--buys", default="tracked_buys.jsonl")
    ap.add_argument("--outcomes", default="token_outcomes.jsonl")
    ap.add_argument("--wallets", default="tracked_wallets.json",
                    help="source of the per-wallet `groups` tags used by --by-group")
    ap.add_argument("--since", default=None, metavar="YYYY-MM-DD",
                    help="ignore buys observed before this date (outcomes follow, "
                         "since they are looked up per mint)")
    ap.add_argument("--min-buys", type=int, default=3)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--no-quotes", action="store_true",
                    help="skip live quotes; use sampled outcomes only")
    ap.add_argument("--sort", choices=["peak", "final"], default="peak",
                    help="rank by best price reached (peak) or by where the "
                         "position actually ended (final). Peak flatters: a "
                         "wallet that touches 30x and gives it all back "
                         "outranks one that holds 3x")
    ap.add_argument("--window", choices=["24h", "7d", "30d", "all"], default=None,
                    help="convenience for --since, relative to now")
    ap.add_argument("--by-group", action="store_true",
                    help="aggregate by wallet group instead of listing wallets")
    args = ap.parse_args()
    if args.window and args.window != "all":
        import datetime as _dt
        days = {"24h": 1, "7d": 7, "30d": 30}[args.window]
        args.since = (_dt.date.today() - _dt.timedelta(days=days)).isoformat()

    buys = load_jsonl(args.buys)
    if args.since:
        # Data collected before the pricing rebuild recorded unpriced tokens as
        # unroutable, i.e. as rugs. Mixing it with current data would understate
        # every wallet in the file, so an epoch is a real analytical need rather
        # than tidiness.
        before = len(buys)
        buys = [b for b in buys if (b.get("observed_at") or "") >= args.since]
        print(f"since {args.since}: {len(buys)} of {before} buys")
    if not buys:
        sys.exit(f"no buys in {args.buys}"
                 + (f" after {args.since}" if args.since else ""))
    samples = load_jsonl(args.outcomes)
    outcomes = outcomes_by_mint(samples)

    mints = {b["mint"] for b in buys}
    covered = mints & set(outcomes)
    print(f"{len(buys)} buys · {len(mints)} tokens · "
          f"{len(covered)} with sampled outcomes ({100*len(covered)//max(len(mints),1)}%)")
    if samples:
        hs = sorted({s["horizon_secs"] for s in samples})
        print(f"horizons sampled: {[f'{h//3600}h' for h in hs]}")

    # Fill the gaps with live quotes, unless asked not to.
    missing = sorted(mints - set(outcomes))
    live = {}
    if missing and not args.no_quotes:
        print(f"\nquoting {len(missing)} tokens with no samples yet…")
        # Older rows predate `token_amount_raw`; they can still be scored from
        # sampled outcomes, they just cannot be re-quoted.
        raw_by_mint = {}
        for b in buys:
            raw = b.get("token_amount_raw")
            if raw:
                raw_by_mint[b["mint"]] = max(raw_by_mint.get(b["mint"], 0), raw)
        quotable = [m for m in missing if m in raw_by_mint]
        skipped = len(missing) - len(quotable)
        if skipped:
            print(f"  {skipped} tokens have no raw amount recorded; using samples only")

        # Give up after a run of failures rather than grinding through
        # thousands: a quote endpoint that refuses us will refuse them all.
        fails = 0
        refused = 0
        for i, mint in enumerate(quotable, 1):
            quoted_raw = raw_by_mint[mint]
            v, status = quote_sol(mint, quoted_raw)
            if status == "unknown":
                # Leave the mint absent from `live`: absent means unknown, and
                # unknown buys are excluded from scoring rather than counted.
                refused += 1
                fails += 1
                if fails >= 15:
                    print(f"  quote endpoint refusing us ({fails} in a row) — stopping at {i}."
                          f"\n  {len(quotable) - i} tokens left unquoted; they are recorded as"
                          f" UNKNOWN, not as rugs.")
                    break
                time.sleep(0.35)
                continue
            if status == "unroutable":
                live[mint] = None  # genuinely no market
                fails = 0
                time.sleep(0.35)
                continue
            # Store SOL per RAW UNIT, not the total. One quote per token keeps
            # the request count sane, but the figure it returns belongs to the
            # quantity we asked about — so every buy must be valued by its OWN
            # size. Dividing one wallet's proceeds by another's outlay scored
            # every small buyer as if they held the largest buyer's position.
            #
            # Scaling one quote across sizes ignores price impact, which flatters
            # buys larger than the quoted one. Sampled outcomes do not have this
            # problem; this path is provisional by design.
            live[mint] = v / quoted_raw
            fails = 0
            if i % 25 == 0:
                print(f"  {i}/{len(quotable)}…")
            time.sleep(0.35)

        if refused:
            print(f"  {refused} tokens the endpoint would not answer for — excluded, not scored")

    W = collections.defaultdict(lambda: {
        "name": "", "n": 0, "paid": 0.0, "peak_w": 0.0, "final_w": 0.0,
        "rugs": 0, "wins": 0, "sampled": 0, "unknown": 0,
    })
    for b in buys:
        w = W[b["wallet"]]
        w["name"] = b.get("wallet_name") or b["wallet"][:8]
        paid = b["sol_spent"]

        o = outcomes.get(b["mint"])
        if o:
            w["sampled"] += 1
            peak, final, rugged = o["peak"], o["final"], o["rugged"]
        else:
            v = live.get(b["mint"], "unknown")
            if v == "unknown":
                # No sample AND no quote: we do not know. Excluded rather than
                # counted as a rug — "we did not look" is not "it died".
                w["unknown"] += 1
                continue
            if v is None:
                peak = final = 0.0
                rugged = True
            else:
                # `v` is SOL per raw unit; value THIS buy's own quantity.
                raw = b.get("token_amount_raw")
                if not raw:
                    w["unknown"] += 1
                    continue
                ref = b["sol_spent"]
                m = (v * raw / ref) if ref > 0 else 0.0
                peak = final = m
                rugged = False
        # Counted only once we know an outcome, so the denominator matches the
        # numerator and an unscored buy cannot dilute the average.
        w["n"] += 1
        w["paid"] += paid
        # Weight by size: a 40 SOL call should count for more than a 0.05 dust buy.
        w["peak_w"] += peak * paid
        w["final_w"] += final * paid
        if rugged:
            w["rugs"] += 1
        if peak >= 2.0:
            w["wins"] += 1

    ranked = [v for v in W.values() if v["n"] >= args.min_buys and v["paid"] > 0]
    # Peak is what a wallet touched; final is what it kept. Ranking on peak
    # rewards a wallet that hit 30x and round-tripped it over one that held 3x,
    # which is backwards for deciding who to follow.
    key = "final_w" if args.sort == "final" else "peak_w"
    ranked.sort(key=lambda v: v[key] / v["paid"], reverse=True)

    print(f"\n{len(ranked)} wallets with >= {args.min_buys} buys\n")
    print(f"{'wallet':<24}{'buys':>5}{'paid':>9}{'peak':>7}{'final':>7}{'2x+':>6}{'rug':>6}{'smp':>5}{'?':>5}")
    print("-" * 69)
    for v in ranked[: args.top]:
        print(f"{v['name'][:24]:<24}{v['n']:>5}{v['paid']:>9.2f}"
              f"{v['peak_w']/v['paid']:>6.2f}x{v['final_w']/v['paid']:>6.2f}x"
              f"{v['wins']:>5}/{v['n']}{v['rugs']:>5}/{v['n']}{v['sampled']:>5}{v['unknown']:>5}")

    tp = sum(v["paid"] for v in ranked)
    if tp:
        print(f"\nAGGREGATE  paid {tp:.1f} SOL  "
              f"peak {sum(v['peak_w'] for v in ranked)/tp:.2f}x  "
              f"final {sum(v['final_w'] for v in ranked)/tp:.2f}x  "
              f"rugged {sum(v['rugs'] for v in ranked)}/{sum(v['n'] for v in ranked)}")

    if args.by_group:
        report_groups(W, args.wallets)

    if len(covered) < len(mints) * 0.5:
        print("\nNOTE: most tokens have no sampled outcomes yet, so peak is\n"
              "      end-state only and understates anything that spiked and\n"
              "      faded. Re-run once the sampler has a day of history.")


if __name__ == "__main__":
    main()
