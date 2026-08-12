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
    """SOL the given raw quantity fetches now, or None if unroutable."""
    url = f"{JUP}?inputMint={mint}&outputMint={WSOL}&amount={int(raw)}&slippageBps=100"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as f:
            return int(json.load(f)["outAmount"]) / 1e9
    except Exception:
        return None


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--buys", default="tracked_buys.jsonl")
    ap.add_argument("--outcomes", default="token_outcomes.jsonl")
    ap.add_argument("--min-buys", type=int, default=3)
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--no-quotes", action="store_true",
                    help="skip live quotes; use sampled outcomes only")
    args = ap.parse_args()

    buys = load_jsonl(args.buys)
    if not buys:
        sys.exit(f"no buys in {args.buys}")
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
        for i, mint in enumerate(quotable, 1):
            v = quote_sol(mint, raw_by_mint[mint])
            live[mint] = v
            fails = 0 if v is not None else fails + 1
            if fails >= 15:
                print(f"  quote endpoint failing ({fails} in a row) — stopping at {i};"
                      f" remaining tokens scored from samples only")
                break
            if i % 25 == 0:
                print(f"  {i}/{len(quotable)}…")
            time.sleep(0.35)

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
                ref = b["sol_spent"]
                m = (v / ref) if ref > 0 else 0.0
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
    ranked.sort(key=lambda v: v["peak_w"] / v["paid"], reverse=True)

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

    if len(covered) < len(mints) * 0.5:
        print("\nNOTE: most tokens have no sampled outcomes yet, so peak is\n"
              "      end-state only and understates anything that spiked and\n"
              "      faded. Re-run once the sampler has a day of history.")


if __name__ == "__main__":
    main()
