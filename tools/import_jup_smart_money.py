#!/usr/bin/env python3
"""Import Jupiter's smart-money leaderboards into tracked_wallets.json.

    python3 tools/import_jup_smart_money.py                 # dry run
    python3 tools/import_jup_smart_money.py --apply
    python3 tools/import_jup_smart_money.py --apply --categories topPnl,influencer

WHERE THE DATA COMES FROM

  /smart-money/v1/top?category=<c>&window=<w>   ranked wallets, 100 max
  /smart-money/v1/cards?limit=50                wallets buying right now

Live categories are topPnl, influencer and whale; windows are 1d/7d/30d. The
other category names the UI hints at return empty and are not requested.

WHY EVERY IMPORT IS TAGGED

Each imported wallet gets `groups: ["jup:<category>"]`. The loader ignores that
field, so it costs nothing at runtime, but it survives in the file and lets
score_wallets.py --by-group answer the question that actually matters: is a
cohort worth following, or are we averaging a good one against a bad one?

Provenance is not a formality here. `topPnl` ranks by realised profit, and the
biggest number on that board belongs to a wallet an app trades out of on behalf
of its users. It is not a trader, and its buys are not a signal. Sorting by PnL
cannot tell those apart, so imports are recorded, never merged anonymously.

Existing entries are never modified — name, emoji and groups are left exactly as
they are, and only genuinely new addresses are appended.
"""
import argparse, json, os, re, shutil, sys, time, urllib.error, urllib.request

API = "https://datapi.jup.ag/smart-money/v1"
CATEGORIES = ("topPnl", "influencer", "whale")
WINDOWS = ("1d", "7d", "30d")
# The endpoint 403s on urllib's default agent and 400s on cards limit > 50.
HEADERS = {"User-Agent": "curl/8.5.0", "Accept": "application/json"}
CARDS_MAX = 50
BASE58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")


def get(url, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=20) as f:
                return json.load(f)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            print(f"  ! {e.code} on {url}", file=sys.stderr)
            return {}
        except Exception as e:
            print(f"  ! {e} on {url}", file=sys.stderr)
            return {}
    return {}


def harvest(categories):
    """address -> {cats, twitter, pnl, win}."""
    W = {}

    def note(addr, cat=None, twitter=None, pnl=None, win=None):
        if not BASE58.fullmatch(addr or ""):
            return
        r = W.setdefault(addr, {"cats": set(), "twitter": None, "pnl": 0.0, "win": None})
        if cat:
            r["cats"].add(cat)
        if twitter and not r["twitter"]:
            r["twitter"] = twitter
        # Windows overlap, so keep the best figure rather than the last one seen.
        if pnl:
            r["pnl"] = max(r["pnl"], pnl)
        if win is not None and r["win"] is None:
            r["win"] = win

    for cat in categories:
        for win in WINDOWS:
            d = get(f"{API}/top?category={cat}&window={win}&limit=100")
            rows = d.get("wallets", [])
            print(f"  top/{cat}/{win}: {len(rows)}")
            for w in rows:
                note(w.get("walletId"), cat=cat, twitter=w.get("twitterUsername"),
                     pnl=w.get("pnlUsd") or 0.0, win=w.get("winRate"))
            time.sleep(0.2)

    d = get(f"{API}/cards?limit={CARDS_MAX}")
    cards = d.get("cards", [])
    print(f"  cards: {len(cards)}")
    for c in cards:
        for t in c.get("traders", []):
            note(t.get("walletId"), twitter=t.get("twitterUsername"),
                 pnl=t.get("pnl7d") or 0.0, win=t.get("winRate7d"))
            for cat in t.get("categories", []):
                note(t.get("walletId"), cat=cat)
    return W


def display_name(addr, rec):
    """A name that means something in a Telegram alert.

    A bare handle when we have one. Otherwise the category plus a fragment of
    the address, which at least says where the wallet came from — the detector
    falls back to a short address for anything blank.
    """
    if rec["twitter"]:
        return rec["twitter"][:32]
    cat = sorted(rec["cats"])[0] if rec["cats"] else "jup"
    return f"{cat} {addr[:4]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="tracked_wallets.json")
    ap.add_argument("--apply", action="store_true", help="write the file (default is a dry run)")
    ap.add_argument("--categories", default=",".join(CATEGORIES))
    ap.add_argument("--min-pnl", type=float, default=0.0,
                    help="skip wallets below this window PnL in USD")
    ap.add_argument("--min-win-rate", type=float, default=0.0, help="0..1")
    args = ap.parse_args()

    cats = [c.strip() for c in args.categories.split(",") if c.strip()]
    print(f"harvesting {cats} x {list(WINDOWS)} + cards")
    W = harvest(cats)
    print(f"\n{len(W)} unique wallets harvested")

    # A BOM here is fatal to the Rust loader, so read tolerantly and write clean.
    with open(args.file, encoding="utf-8-sig") as f:
        current = json.load(f)
    have = {w["trackedWalletAddress"] for w in current}

    added, skipped = [], 0
    for addr, rec in sorted(W.items(), key=lambda kv: -kv[1]["pnl"]):
        if addr in have:
            continue
        if rec["pnl"] < args.min_pnl:
            skipped += 1
            continue
        if args.min_win_rate and (rec["win"] or 0) < args.min_win_rate:
            skipped += 1
            continue
        added.append({
            "trackedWalletAddress": addr,
            "name": display_name(addr, rec),
            "emoji": "",
            "alertsOnToast": True,
            "alertsOnBubble": True,
            "alertsOnFeed": True,
            "groups": [f"jup:{c}" for c in sorted(rec["cats"])] or ["jup"],
            "sound": "default",
        })

    print(f"already tracked: {len(W) - len(added) - skipped}   "
          f"below thresholds: {skipped}   new: {len(added)}")
    print(f"{len(current)} -> {len(current) + len(added)} wallets")

    for w in added[:15]:
        print(f"  + {w['name'][:24]:<24} {w['trackedWalletAddress'][:8]}  {','.join(w['groups'])}")
    if len(added) > 15:
        print(f"  … {len(added) - 15} more")

    if not args.apply:
        print("\ndry run — pass --apply to write")
        return
    if not added:
        print("\nnothing to add")
        return

    backup = f"{args.file}.bak"
    shutil.copy2(args.file, backup)
    tmp = f"{args.file}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(current + added, f, indent=2, ensure_ascii=False)
    os.replace(tmp, args.file)
    print(f"\nwrote {args.file} ({len(current) + len(added)} wallets), backup at {backup}")
    print("redeploy: scp the file to the VPS and restart, then check the loaded count in the log")


if __name__ == "__main__":
    main()
