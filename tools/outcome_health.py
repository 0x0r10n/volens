#!/usr/bin/env python3
"""Is outcome sampling actually working?

    python3 tools/outcome_health.py [--outcomes token_outcomes.jsonl]

Answers the three questions worth asking before trusting a scoring run:

  ARE THE MARKS LANDING     A horizon with no samples is a horizon that is
                            never going to inform anything.

  ARE THEY ON TIME          A sample is a claim about a token N seconds after
                            the first buy. Taken late it describes a different
                            moment while carrying the original label, so
                            lateness is a measure of how true the labels are.
                            The sampler skips anything past its grace window,
                            so persistent lateness here means the window is too
                            generous, not that data is missing.

  ARE THE PRICES SANE       Multiples in the thousands mean the price index is
                            mis-reading a fill rather than a token mooning. That
                            failure has happened; it is worth a standing check.

`unpriced` is not a rug. It means no trade was observed in the pricing window —
a distinction that has poisoned this dataset twice by being ignored.
"""
import argparse, collections, datetime as dt, json, os, statistics, sys


def load(path):
    if not os.path.exists(path):
        sys.exit(f"no such file: {path}")
    rows = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # a torn final line during a live append is normal
    return rows


def ts(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def label(secs):
    if secs % 3600 == 0:
        return f"{secs // 3600}h"
    return f"{secs // 60}m"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outcomes", default="token_outcomes.jsonl")
    ap.add_argument("--worst", type=int, default=0, metavar="N",
                    help="dump the N largest multiples in full, to judge whether "
                         "they are tokens or artifacts")
    args = ap.parse_args()

    rows = load(args.outcomes)
    if not rows:
        sys.exit(f"{args.outcomes} is empty — nothing sampled yet")

    span = f"{ts(rows[0]['at']):%H:%M} -> {ts(rows[-1]['at']):%H:%M}"
    print(f"{len(rows)} samples · {len({r['mint'] for r in rows})} tokens · {span} UTC\n")

    by = collections.defaultdict(list)
    for r in rows:
        by[r["horizon_secs"]].append(r)

    print(f"{'horizon':>8}{'n':>6}{'priced':>8}{'late(s)':>9}{'median':>9}{'max':>9}")
    print("-" * 49)
    for h in sorted(by):
        rs = by[h]
        priced = [r for r in rs if r["routed"]]
        late = [(ts(r["at"]) - ts(r["first_buy_utc"])).total_seconds() - h for r in rs]
        mult = [r["multiple"] for r in priced]
        print(f"{label(h):>8}{len(rs):>6}{f'{len(priced)}/{len(rs)}':>8}"
              f"{statistics.median(late):>9.0f}"
              f"{(statistics.median(mult) if mult else 0):>8.2f}x"
              f"{(max(mult) if mult else 0):>8.2f}x")

    allmult = [r["multiple"] for r in rows if r["routed"]]
    if allmult:
        top = max(allmult)
        print(f"\nlargest multiple seen: {top:.2f}x")
        if top > 100:
            worst = max((r for r in rows if r["routed"]), key=lambda r: r["multiple"])
            print(f"  !! {worst['mint']} at {label(worst['horizon_secs'])} — "
                  f"above 100x is far more likely a pricing artifact than a token.\n"
                  f"     The index credits a swap's SOL leg to one token only; a\n"
                  f"     number this size means something is getting past that.")

    if args.worst:
        # FDV is the tell. A token really up 200x has a market cap to match; an
        # artifact usually shows an FDV no token has, or none at all. The other
        # tell is `reference_sol`: a first buy of a few hundredths of a SOL
        # divides into a large number very easily.
        print(f"\nlargest {args.worst} multiples in full:")
        for r in sorted((r for r in rows if r["routed"]),
                        key=lambda r: -r["multiple"])[: args.worst]:
            fdv = r.get("fdv_usd")
            fdv = f"${fdv:,.0f}" if fdv else "unknown"
            print(f"\n  {r['mint']}  {label(r['horizon_secs'])}  {r['multiple']:.2f}x")
            print(f"    ref {r['reference_sol']:.4f} SOL -> now {r['sol_value']:.4f} SOL"
                  f"   fdv {fdv}   price age {r.get('price_age_secs', '?')}s")
            print(f"    first buy {r['first_buy_utc']} by {r.get('first_wallet', '?')[:12]}")

    worst_late = max((ts(r["at"]) - ts(r["first_buy_utc"])).total_seconds() - r["horizon_secs"]
                     for r in rows)
    if worst_late > 600:
        print(f"\nnote: worst lateness {worst_late:.0f}s — a sample this far past its mark\n"
              f"      is describing a different moment than its label claims.")


if __name__ == "__main__":
    main()
