//! Fee capture: what a trade actually cost beyond the token price.
//!
//! # What this measures
//!
//! The fees paid **in the transactions volens observed** — network fee, Jito
//! tip, and trading-platform fee — for tracked-wallet buys of a token.
//!
//! It is NOT the token's all-time trading fees. That figure is
//! `cumulative_volume x venue_rate`, and volens has no cumulative volume for a
//! token: it sees the buys of 700 wallets, not the whole market. Deriving one
//! from the other would require an external volume feed.
//!
//! What it IS, is exact for what it covers. Every lamport is read from the
//! transaction's own balance deltas, so there is no rate assumption and no
//! sampling — unlike a volume-times-rate estimate, which is only as good as the
//! venue's published rate (and Meteora DBC's rate is per-pool config, not
//! fixed).
//!
//! # Why it is worth showing
//!
//! Two reasons beyond cost. A large tip means someone paid for priority, which
//! is what conviction looks like in lamports. And the platform label says which
//! terminal the money came through — several wallets arriving via the same
//! front-end is a weaker, more correlated signal than the same count arriving
//! independently.

use std::collections::HashMap;
use std::sync::OnceLock;
use yellowstone_grpc_proto::prelude::{SubscribeUpdateTransactionInfo, TransactionStatusMeta};

const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

/// Jito tip accounts (docs.jito.wtf/lowlatencytxnsend).
const JITO_TIP_ACCOUNTS: &[&str] = &[
    "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5",
    "HFqU5x63VTqvQss8hp11i4wVV8bD44PvwucfZ2bU7gRe",
    "Cw8CFyM9FkoMi7K7Crf6HNQqf4uEMzpKw6QNghXLvLkY",
    "ADaUMid9yfUytqMBgopwjb2DTLSokTSzL1zt6iGPaS49",
    "DfXygSm4jCyNCybVYYK6DwvWqjKee8pbDmJGcLWNDXjh",
    "ADuUkR4vqLUMWXxW9gh6D6L8pMSawimctcNZ5pGwDcEt",
    "DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL",
    "3AVi9Tg9Uo68tJfuvoKvqKNWKkC5wPdSSdeBnizKZ6jT",
];

/// Trading-platform fee wallets, `(address, label)`.
///
/// `7LCZckF6…` appears in both the Axiom and Trojan lists upstream; it is
/// assigned to Axiom here and omitted from Trojan so the map has one owner.
const PLATFORM_FEE_WALLETS: &[(&str, &str)] = &[
    // Axiom (axiom.trade)
    ("7LCZckF6XXGQ1hDY6HFXBKWAtiUgL9QY5vj1C4Bn1Qjj", "axiom"),
    ("4V65jvcDG9DSQioUVqVPiUcUY9v6sb6HKtMnsxSKEz5S", "axiom"),
    ("CeA3sPZfWWToFEBmw5n1Y93tnV66Vmp8LacLzsVprgxZ", "axiom"),
    ("AaG6of1gbj1pbDumvbSiTuJhRCRkkUNaWVxijSbWvTJW", "axiom"),
    ("7oi1L8U9MRu5zDz5syFahsiLUric47LzvJBQX6r827ws", "axiom"),
    ("9kPrgLggBJ69tx1czYAbp7fezuUmL337BsqQTKETUEhP", "axiom"),
    ("DKyUs1xXMDy8Z11zNsLnUg3dy9HZf6hYZidB6WodcaGy", "axiom"),
    ("4FobGn5ZWYquoJkxMzh2VUAWvV36xMgxQ3M7uG1pGGhd", "axiom"),
    ("76sxKrPtgoJHDJvxwFHqb3cAXWfRHFLe3VpKcLCAHSEf", "axiom"),
    ("H2cDR3EkJjtTKDQKk8SJS48du9mhsdzQhy8xJx5UMqQK", "axiom"),
    ("8m5GkL7nVy95G4YVUbs79z873oVKqg2afgKRmqxsiiRm", "axiom"),
    ("4kuG6NsAFJNwqEkac8GFDMMheCGKUPEbaRVHHyFHSwWz", "axiom"),
    ("8vFGAKdwpn4hk7kc1cBgfWZzpyW3MEMDATDzVZhddeQb", "axiom"),
    ("86Vh4XGLW2b6nvWbRyDs4ScgMXbuvRCHT7WbUT3RFxKG", "axiom"),
    ("DZfEurFKFtSbdWZsKSDTqpqsQgvXxmESpvRtXkAdgLwM", "axiom"),
    ("5L2QKqDn5ukJSWGyqR4RPvFvwnBabKWqAqMzH4heaQNB", "axiom"),
    ("DYVeNgXGLAhZdeLMMYnCw1nPnMxkBN7fJnNpHmizTrrF", "axiom"),
    ("Hbj6XdxX6eV4nfbYTseysibp4zZJtVRRPn2J3BhGRuK9", "axiom"),
    ("846ah7iBSu9ApuCyEhA5xpnjHHX7d4QJKetWLbwzmJZ8", "axiom"),
    ("5BqYhuD4q1YD3DMAYkc1FeTu9vqQVYYdfBAmkZjamyZg", "axiom"),
    // BullX (bullx.io)
    ("9RYJ3qr5eU5xAooqVcbmdeusjcViL5Nkiq7Gske3tiKq", "bullx"),
    ("F4hJ3Ee3c5UuaorKAMfELBjYCjiiLH75haZTKqTywRP3", "bullx"),
    // GMGN (gmgn.ai)
    ("BB5dnY55FXS1e1NXqZDwCzgdYJdMCj3B92PU6Q5Fb6DT", "gmgn"),
    ("7sHXjs1j7sDJGVSMSPjD1b4v3FD6uRSvRWfhRdfv5BiA", "gmgn"),
    ("HeZVpHj9jLwTVtMMbzQRf6mLtFPkWNSg11o68qrbUBa3", "gmgn"),
    ("ByRRgnZenY6W2sddo1VJzX9o4sMU4gPDUkcmgrpGBxRy", "gmgn"),
    ("DXfkEGoo6WFsdL7x6gLZ7r6Hw2S6HrtrAQVPWYx2A1s9", "gmgn"),
    ("3t9EKmRiAUcQUYzTZpNojzeGP1KBAVEEbDNmy6wECQpK", "gmgn"),
    ("DymeoWc5WLNiQBaoLuxrxDnDRvLgGZ1QGsEoCAM7Jsrx", "gmgn"),
    ("dBhdrmwBkRa66XxBuAK4WZeZnsZ6bHeHCCLXa3a8bTJ", "gmgn"),
    ("6TxjC5wJzuuZgTtnTMipwwULEbMPx5JPW3QwWkdTGnrn", "gmgn"),
    // Photon (photon-sol.tinyastro.io)
    ("AVUCZyuT35YSuj4RH7fwiyPu82Djn2Hfg7y2ND2XcnZH", "photon"),
    // Trojan (t.me/paris_trojanbot)
    ("9yMwSPk9mrXSN7yDHUuZurAh1sjbJsfpUqjZ7SvVtdco", "trojan"),
    ("92Med3qeK7duC5iiYsHX38H2f2twJfRsSx93oNrza2VH", "trojan"),
    ("2jwHNxavSoMZMEDbT1eV9PcPt5dDcayCqM6MkgaPpmWQ", "trojan"),
    ("65gDv7pZQCZELsNpNYSFEBtNFpWZAbxmRFB6BGMqFkHH", "trojan"),
    ("BWgb8wR1FEGiu1jCDSKuHKf752W27b4iN6SvoNCiK4qp", "trojan"),
    ("8jgg7moFJkHyTtAv9M6RBSPMp2oXeXhuiUMKW8YbYCWn", "trojan"),
    // Maestro (t.me/MaestroSniperBot)
    //
    // Two rows from the upstream list are NOT here, both invalid pubkeys:
    //   "x2CDF4CAdF2272B77475732446Ba664443277E8C1" — Ethereum-format (already
    //      excluded upstream)
    //   "TXNP92LYmnPZzqnXwwsmotizTcNyPGxxEv"       — decodes to 25 bytes, not
    //      32; caught by `every_fee_address_is_a_valid_solana_pubkey`. Looks
    //      like a TRON address, which is base58 but a different length.
    // Neither could ever match an account key, so keeping them would only have
    // made Maestro's fees silently read as zero.
    ("MaestroUL88UBnZr3wfoN7hqmNWFi3ZYCGqZoJJHE36", "maestro"),
    ("FRMxAnZgkW58zbYcE7Bxqsg99VWpJh6sMP5xLzAWNabN", "maestro"),
    // Padre / Lab Terminal (trade.padre.gg)
    ("Eno27Pu6ok2nNwLTgNCLnFmY2YxQsAXecmrnnLvJeFYh", "padre"),
    ("3VZjDxp8grQbocYwEisZxSpvpw4XURL1CBwii5gkoAw6", "padre"),
    // Bloom (t.me/BloomSolana_bot)
    ("7HeD6sLLqAnKVRuSfc1Ko3BSPMNKWgGTiWLKXJF31vKM", "bloom"),
    // 0slot (transaction accelerator)
    ("6fQaVhYZA4w3MBSXjJ81Vf6W1EDYeUPXpgVQ6UQyU1Av", "0slot"),
    ("DiTmWENJsHQdawVUUKnUXkconcpW4Jv52TnMWhkncF6t", "0slot"),
    ("HRyRhQ86t3H4aAtgvHVpUJmw64BDrb61gRiKcdKUXs5c", "0slot"),
    ("Eb2KpSC8uMt9GmzyAEm5Eb1AAAgTjRaXWFjKyFXHZxF3", "0slot"),
    ("FCjUJZ1qozm1e8romw216qyfQMaaWKxWsuySnumVCCNe", "0slot"),
    ("7y4whZmw388w1ggjToDLSBLv47drw5SUXcLk6jtmwixd", "0slot"),
    ("J9BMEWFbCBEjtQ1fG5Lo9kouX1HfrKQxeUxetwXrifBw", "0slot"),
    ("8U1JPQh3mVQ4F5jwRdFTBzvNRQaYFQppHQYoH38DJGSQ", "0slot"),
    ("ENxTEjSQ1YabmUpXAdCgevnHQ9MHdLv8tzFiuiYJqa13", "0slot"),
    ("6rYLG55Q9RpsPGvqdPNJs4z5WTxJVatMB8zV3WJhs5EK", "0slot"),
    ("Cix2bHfqPcKcM233mzxbLk14kSggUUiz2A87fJtGivXr", "0slot"),
    ("4HiwLEP2Bzqj3hM2ENxJuzhcPCdsafwiet3oGkMkuQY4", "0slot"),
    ("7toBU3inhmrARGngC7z6SjyP85HgGMmCTEwGNRAcYnEK", "0slot"),
    ("8mR3wB1nh4D6J9RUCugxUpc6ya8w38LPxZ3ZjcBhgzws", "0slot"),
    ("6SiVU5WEwqfFapRuYCndomztEwDjvS5xgtEof3PLEGm9", "0slot"),
    ("TpdxgNJBWZRL8UXF5mrEsyWxDWx9HQexA9P1eTWQ42p", "0slot"),
    ("D8f3WkQu6dCF33cZxuAsrKHrGsqGP2yvAHf8mX6RXnwf", "0slot"),
    ("GQPFicsy3P3NXxB5piJohoxACqTvWE9fKpLgdsMduoHE", "0slot"),
    ("Ey2JEr8hDkgN8qKJGrLf2yFjRhW7rab99HVxwi5rcvJE", "0slot"),
    ("4iUgjMT8q2hNZnLuhpqZ1QtiV8deFPy2ajvvjEpKKgsS", "0slot"),
    ("3Rz8uD83QsU8wKvZbgWAPvCNDU6Fy8TSZTMcPm3RB6zt", "0slot"),
    // Helius Sender tip accounts (forwarded to Jito internally; disjoint from
    // JITO_TIP_ACCOUNTS above).
    ("4ACfpUFoaSD9bfPdeu6DBt89gB6ENTeHBXCAi87NhDEE", "helius-sender"),
    ("D2L6yPZ2FmmmTKPgzaMKdhu6EWZcTpLy1Vhx8uvZe7NZ", "helius-sender"),
    ("9bnz4RShgq1hAnLnZbP8kbgBg1kEmcJBYQq3gQbmnSta", "helius-sender"),
    ("5VY91ws6B2hMmBFRsXkoAAdsPHBJwRfBht4DXox3xkwn", "helius-sender"),
    ("2nyhqdwKcJZR2vcqCyrYsaPVdAnFoJjiksCXJ7hfEYgD", "helius-sender"),
    ("2q5pghRs6arqVjRvT5gfgWfWcHWmw1ZuCzphgd5KfWGJ", "helius-sender"),
    ("wyvPkWjVZz1M8fHQnMMCDTQDbkManefNNhweYk5WkcF", "helius-sender"),
    ("3KCKozbAaF75qEU33jtzozcJ29yJuaLJTy2jFdzUY8bT", "helius-sender"),
    ("4vieeGHPYPG2MmyPRcYjdiDmmhN3ww7hsFNap8pVN3Ey", "helius-sender"),
    ("4TQLFNWK8AovT1gFvda5jfw2oJeRMKEmw7aH6MGBJ3or", "helius-sender"),
    // pump.fun protocol/creator fee recipients (normal set)
    ("62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV", "pumpfun"),
    ("7VtfL8fvgNfhz17qKRMjzQEXgbdpnHHHQRh54R9jP2RJ", "pumpfun"),
    ("7hTckgnGnLQR6sdH7YkqFTAA7VwTfYFaZ6EhEsU3saCX", "pumpfun"),
    ("9rPYyANsfQZw3DnDmKE3YCQF5E8oD89UXoHn9JFEhJUz", "pumpfun"),
    ("AVmoTthdrX6tKt4nDjco2D775W2YK3sDhxPcMmzUAmTY", "pumpfun"),
    ("CebN5WGQ4jvEPvsVU4EoHEpgzq1VV7AbicfhtW4xC9iM", "pumpfun"),
    ("FWsW1xNtWscwNmKv6wVsU1iTzRN6wmmk3MjxRP5tT7hz", "pumpfun"),
    ("G5UZAVbAf46s7cKWoyKu8kYTip9DGTpbLZ2qa9Aq69dP", "pumpfun"),
    // pump.fun reserved fee recipients (mayhem-mode)
    ("GesfTA3X2arioaHp8bbKdjG9vJtskViWACZoYvxp4twS", "pumpfun"),
    ("4budycTjhs9fD6xw62VBducVTNgMgJJ5BgtKq7mAZwn6", "pumpfun"),
    ("8SBKzEQU4nLSzcwF4a74F2iaUDQyTfjGndn6qUWBnrpR", "pumpfun"),
    ("4UQeTP1T39KZ9Sfxzo3WR5skgsaP6NZa87BAkuazLEKH", "pumpfun"),
    ("8sNeir4QsLsJdYpc9RZacohhK1Y5FLU3nC5LXgYB4aa6", "pumpfun"),
    ("Fh9HmeLNUMVCvejxCtCL2DbYaRyBFVJ5xrWkLnMH6fdk", "pumpfun"),
    ("463MEnMeGyJekNZFQSTUABBEbLnvMTALbT6ZmsxAbAdq", "pumpfun"),
    ("6AUH3WEHucYZyC61hqpqYUWVto5qA5hjHuNQ32GNnNxA", "pumpfun"),
    // pump.fun buyback fee recipients (all coins)
    ("5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD", "pumpfun_buyback"),
    ("9M4giFFMxmFGXtc3feFzRai56WbBqehoSeRE5GK7gf7", "pumpfun_buyback"),
    ("GXPFM2caqTtQYC2cJ5yJRi9VDkpsYZXzYdwYpGnLmtDL", "pumpfun_buyback"),
    ("3BpXnfJaUTiwXnJNe7Ej1rcbzqTTQUvLShZaWazebsVR", "pumpfun_buyback"),
    ("5cjcW9wExnJJiqgLjq7DEG75Pm6JBgE1hNv4B2vHXUW6", "pumpfun_buyback"),
    ("EHAAiTxcdDwQ3U4bU6YcMsQGaekdzLS3B5SmYo46kJtL", "pumpfun_buyback"),
    ("5eHhjP8JaYkz83CWwvGU2uMUXefd3AazWGx4gpcuEEYD", "pumpfun_buyback"),
    ("A7hAgCzFw14fejgCp387JUJRMNyz4j89JKnhtKU8piqW", "pumpfun_buyback"),
];

/// address -> label, built once. `jito` is folded in so one lookup covers both.
fn fee_wallets() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m: HashMap<&'static str, &'static str> =
            PLATFORM_FEE_WALLETS.iter().copied().collect();
        for a in JITO_TIP_ACCOUNTS {
            m.insert(a, "jito");
        }
        m
    })
}

/// Look up a fee wallet's label.
pub fn label_for(address: &str) -> Option<&'static str> {
    fee_wallets().get(address).copied()
}

/// What one transaction cost, split by where the lamports went.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Fees {
    /// Base + priority fee burned/paid to validators.
    pub network_sol: f64,
    /// Jito / Helius Sender / 0slot tips — paid for inclusion priority.
    pub tip_sol: f64,
    /// Trading terminal + protocol fees (Axiom, pump.fun, …).
    pub platform_sol: f64,
}

impl Fees {
    pub fn total_sol(&self) -> f64 {
        self.network_sol + self.tip_sol + self.platform_sol
    }

    /// Test-only: the running bot reads `total_sol` directly.
    #[cfg(test)]
    pub fn is_zero(&self) -> bool {
        self.total_sol() <= 0.0
    }

}

/// Labels treated as inclusion priority rather than a trading fee.
///
/// `0slot` and `helius-sender` are accelerators: their "platform fee" is a tip
/// forwarded for block priority, so counting it as a trading fee would
/// overstate what the terminal charged.
const TIP_LABELS: &[&str] = &["jito", "0slot", "helius-sender"];

/// Read the fees out of one transaction.
///
/// Every figure comes from the transaction's own balance deltas — no rate is
/// assumed. A fee wallet is credited only when its lamports actually INCREASED:
/// appearing in the account list is not evidence it was paid.
pub fn capture(tx_info: &SubscribeUpdateTransactionInfo, meta: &TransactionStatusMeta) -> Fees {
    let mut fees = Fees {
        network_sol: meta.fee as f64 / LAMPORTS_PER_SOL,
        ..Default::default()
    };

    let Some(tx) = tx_info.transaction.as_ref() else { return fees };
    let Some(msg) = tx.message.as_ref() else { return fees };

    for (i, key) in msg.account_keys.iter().enumerate() {
        let (Some(pre), Some(post)) = (meta.pre_balances.get(i), meta.post_balances.get(i)) else {
            continue;
        };
        if post <= pre {
            continue;
        }
        let addr = bs58::encode(key).into_string();
        let Some(label) = label_for(&addr) else { continue };

        let gained = (post - pre) as f64 / LAMPORTS_PER_SOL;
        if TIP_LABELS.contains(&label) {
            fees.tip_sol += gained;
        } else {
            fees.platform_sol += gained;
        }
    }
    fees
}

/// Which trading terminal a transaction went through, if any is recognisable.
///
/// Accelerator labels are skipped: paying 0slot says how the transaction was
/// delivered, not which front-end placed it.
pub fn platform_of(
    tx_info: &SubscribeUpdateTransactionInfo,
    meta: &TransactionStatusMeta,
) -> Option<String> {
    let tx = tx_info.transaction.as_ref()?;
    let msg = tx.message.as_ref()?;
    for (i, key) in msg.account_keys.iter().enumerate() {
        let (Some(pre), Some(post)) = (meta.pre_balances.get(i), meta.post_balances.get(i)) else {
            continue;
        };
        if post <= pre {
            continue;
        }
        let addr = bs58::encode(key).into_string();
        if let Some(label) = label_for(&addr) {
            if !TIP_LABELS.contains(&label) {
                return Some(label.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mistyped fee address does not fail loudly — it simply never matches,
    /// and the fee silently reads as zero forever. Decoding every entry is the
    /// only way that error surfaces. This list already shipped one bad row
    /// upstream (an Ethereum-format Maestro address), so the risk is real.
    #[test]
    fn every_fee_address_is_a_valid_solana_pubkey() {
        let mut checked = 0;
        let all: Vec<(&str, &str)> = PLATFORM_FEE_WALLETS
            .iter()
            .copied()
            .chain(JITO_TIP_ACCOUNTS.iter().map(|a| (*a, "jito")))
            .collect();
        // Collected, not asserted one at a time: a panic on the first bad row
        // hides how many others are wrong, and this table is transcribed by
        // hand from another project.
        let mut bad = Vec::new();
        for (addr, label) in &all {
            match bs58::decode(addr).into_vec() {
                Ok(d) if d.len() == 32 => checked += 1,
                Ok(d) => bad.push(format!("{label} {addr:?}: {} bytes, not 32", d.len())),
                Err(e) => bad.push(format!("{label} {addr:?}: not base58 ({e})")),
            }
        }
        assert!(bad.is_empty(), "invalid fee addresses:\n  {}", bad.join("\n  "));
        println!("validated {checked} fee addresses");
        assert!(checked > 100, "expected the full table, got {checked}");
    }

    /// One address appears under two owners upstream. The map must resolve it
    /// to exactly one, or lookups depend on iteration order.
    #[test]
    fn duplicate_addresses_resolve_to_one_owner() {
        assert_eq!(label_for("7LCZckF6XXGQ1hDY6HFXBKWAtiUgL9QY5vj1C4Bn1Qjj"), Some("axiom"));

        let mut seen = std::collections::HashSet::new();
        for (addr, _) in PLATFORM_FEE_WALLETS {
            assert!(seen.insert(*addr), "{addr} listed twice in PLATFORM_FEE_WALLETS");
        }
    }

    #[test]
    fn jito_accounts_are_labelled_as_tips_not_platforms() {
        for a in JITO_TIP_ACCOUNTS {
            assert_eq!(label_for(a), Some("jito"), "{a}");
        }
    }

    /// Accelerators must not be counted as trading fees — their charge buys
    /// block priority, not execution.
    #[test]
    fn accelerators_count_as_tips() {
        for label in ["jito", "0slot", "helius-sender"] {
            assert!(TIP_LABELS.contains(&label), "{label} should be a tip");
        }
        assert!(!TIP_LABELS.contains(&"axiom"));
        assert!(!TIP_LABELS.contains(&"pumpfun"));
    }

    #[test]
    fn unknown_addresses_are_not_fees() {
        assert_eq!(label_for("So11111111111111111111111111111111111111112"), None);
        assert_eq!(label_for(""), None);
    }

    #[test]
    fn totals_add_up() {
        let f = Fees { network_sol: 0.000005, tip_sol: 0.001, platform_sol: 0.01 };
        assert!((f.total_sol() - 0.011005).abs() < 1e-12);
        assert!(!f.is_zero());
        assert!(Fees::default().is_zero());
    }
}
