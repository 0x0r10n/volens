//! On-disk store of local test wallets, with an "active" selection.
//!
//! Backs the `/new-wallet`, `/wallets`, and `/use` Telegram commands and the
//! CLI. Every key is generated locally (see `tx::Wallet::generate`) and never
//! transmitted; this module only manages naming, listing, and which one is
//! active.
//!
//! # Security
//!
//! * **Names are strictly sanitized.** A wallet name becomes a filename, so an
//!   unsanitized `../../etc/cron.d/x` or an absolute path would let a Telegram
//!   command write a keypair — or read/point at — an arbitrary location. Only
//!   `[A-Za-z0-9_-]`, length-bounded, is accepted; everything else is rejected
//!   before it touches the filesystem. The active-pointer file is re-validated
//!   on read, so a hand-edited pointer cannot smuggle a path through either.
//! * **The active selection is not the arm switch.** Choosing a wallet here only
//!   records which key the *next* run will load. A running armed sniper is not
//!   redirected — that would let a Telegram command move live funds to a
//!   different wallet mid-session. Live trading always requires a local restart.

use crate::tx::Wallet;
use anyhow::{Context, Result, bail};
use solana_pubkey::Pubkey;
use std::path::PathBuf;
#[cfg(test)]
use std::path::Path;

/// Max wallet-name length. Generous for human labels, bounded so a name can't
/// be used to blow up path lengths.
const MAX_NAME_LEN: usize = 32;

/// File under the store dir naming the active wallet.
const ACTIVE_FILE: &str = ".active";

pub struct WalletStore {
    dir: PathBuf,
}

impl WalletStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Validate a wallet name. This is the single choke point that keeps a name
    /// from ever becoming a path traversal or an absolute path.
    ///
    /// Accepts only `[A-Za-z0-9_-]`, 1..=32 chars. Rejects `.`/`..`, slashes,
    /// and anything else. Returning the owned name (rather than borrowing)
    /// signals it has passed the gate.
    fn sanitize(name: &str) -> Result<String> {
        let n = name.trim();
        if n.is_empty() {
            bail!("wallet name is empty");
        }
        if n.len() > MAX_NAME_LEN {
            bail!("wallet name too long (max {MAX_NAME_LEN})");
        }
        if !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            bail!("wallet name may only contain letters, digits, '_' and '-'");
        }
        // `-` and `_` only would still be a valid filename, but names like "."
        // or ".." are already excluded by the charset (they contain '.').
        Ok(n.to_string())
    }

    fn path_for(&self, name: &str) -> Result<PathBuf> {
        let clean = Self::sanitize(name)?;
        Ok(self.dir.join(format!("{clean}.json")))
    }

    /// Ensure the store directory exists, owner-only on unix (it holds keys).
    fn ensure_dir(&self) -> Result<()> {
        if self.dir.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating wallet dir {}", self.dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    /// Generate a new wallet under `name`. Errors if it already exists (a funded
    /// key must never be clobbered — see `Wallet::generate`).
    ///
    /// If no wallet was active yet, the new one becomes active: the common case
    /// of "make one wallet" then just works without a separate `/use`.
    pub fn generate(&self, name: &str) -> Result<Pubkey> {
        self.ensure_dir()?;
        let path = self.path_for(name)?;
        let pubkey = Wallet::generate(path.to_str().context("non-utf8 wallet path")?)?;
        if self.active().is_none() {
            let _ = self.set_active(name);
        }
        Ok(pubkey)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path_for(name).map(|p| p.exists()).unwrap_or(false)
    }

    /// Public address of a stored wallet, or `None` if absent/unreadable.
    pub fn pubkey_of(&self, name: &str) -> Option<Pubkey> {
        let path = self.path_for(name).ok()?;
        Wallet::load(path.to_str()?).ok().map(|w| w.pubkey())
    }

    /// All stored wallets as `(name, address)`, sorted by name. Unreadable files
    /// are skipped rather than failing the whole listing.
    pub fn list(&self) -> Vec<(String, Pubkey)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // Only surface well-formed names; ignore anything hand-dropped in.
            if Self::sanitize(stem).is_err() {
                continue;
            }
            if let Ok(w) = Wallet::load(path.to_str().unwrap_or_default()) {
                out.push((stem.to_string(), w.pubkey()));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Mark `name` active. Refuses if that wallet does not exist, so the active
    /// pointer can never dangle.
    pub fn set_active(&self, name: &str) -> Result<()> {
        let clean = Self::sanitize(name)?;
        if !self.exists(&clean) {
            bail!("no wallet named {clean:?}");
        }
        self.ensure_dir()?;
        std::fs::write(self.dir.join(ACTIVE_FILE), clean.as_bytes())
            .context("writing active pointer")?;
        Ok(())
    }

    /// The active wallet name, if set and still valid. The pointer is
    /// re-sanitized on read: a hand-edited `.active` cannot inject a path.
    pub fn active(&self) -> Option<String> {
        let raw = std::fs::read_to_string(self.dir.join(ACTIVE_FILE)).ok()?;
        let name = Self::sanitize(&raw).ok()?;
        self.exists(&name).then_some(name)
    }

    pub fn active_path(&self) -> Option<PathBuf> {
        let name = self.active()?;
        self.path_for(&name).ok()
    }

    pub fn active_pubkey(&self) -> Option<Pubkey> {
        self.pubkey_of(&self.active()?)
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> WalletStore {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("volens-store-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        WalletStore::new(dir)
    }

    /// The security-critical test: a name must never escape the store dir.
    #[test]
    fn names_that_traverse_or_escape_are_rejected() {
        for bad in [
            "../evil",
            "../../etc/passwd",
            "/absolute",
            "a/b",
            "a\\b",
            "..",
            ".",
            "with space",
            "dot.dot",
            "semi;colon",
            "",
            "   ",
            &"x".repeat(33),
        ] {
            assert!(
                WalletStore::sanitize(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        // And the store surface refuses them too, never touching the fs.
        let s = store();
        assert!(s.generate("../evil").is_err());
        assert!(s.set_active("../../x").is_err());
        assert!(!s.exists("../evil"));
    }

    #[test]
    fn good_names_are_accepted() {
        for ok in ["alpha", "beta-1", "test_wallet", "W2", "a", &"z".repeat(32)] {
            assert_eq!(WalletStore::sanitize(ok).unwrap(), ok.trim());
        }
    }

    #[test]
    fn generate_list_and_activate() {
        let s = store();
        let a = s.generate("alpha").unwrap();
        // First wallet auto-activates.
        assert_eq!(s.active().as_deref(), Some("alpha"));
        assert_eq!(s.active_pubkey(), Some(a));

        let b = s.generate("beta").unwrap();
        // Second does NOT steal active.
        assert_eq!(s.active().as_deref(), Some("alpha"));
        assert_ne!(a, b, "distinct wallets");

        let list = s.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "alpha"); // sorted
        assert_eq!(list[1].0, "beta");

        // Switch active.
        s.set_active("beta").unwrap();
        assert_eq!(s.active().as_deref(), Some("beta"));
        assert_eq!(s.active_pubkey(), Some(b));

        let _ = std::fs::remove_dir_all(s.dir());
    }

    #[test]
    fn cannot_activate_a_missing_wallet() {
        let s = store();
        s.generate("alpha").unwrap();
        assert!(s.set_active("ghost").is_err());
        // Active stays valid.
        assert_eq!(s.active().as_deref(), Some("alpha"));
        let _ = std::fs::remove_dir_all(s.dir());
    }

    #[test]
    fn generate_refuses_to_overwrite() {
        let s = store();
        s.generate("alpha").unwrap();
        assert!(s.generate("alpha").is_err(), "must not clobber an existing key");
        let _ = std::fs::remove_dir_all(s.dir());
    }

    /// A hand-edited `.active` containing a traversal must not resolve.
    #[test]
    fn poisoned_active_pointer_is_ignored() {
        let s = store();
        s.generate("alpha").unwrap();
        std::fs::write(s.dir().join(ACTIVE_FILE), b"../../etc/passwd").unwrap();
        assert_eq!(s.active(), None, "a traversal in the pointer must not resolve");
        assert_eq!(s.active_path(), None);
        let _ = std::fs::remove_dir_all(s.dir());
    }
}
