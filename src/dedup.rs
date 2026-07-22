//! TTL dedup set, keyed by pool address.
//!
//! Lives at the detector level rather than inside the alerter, because a pool
//! can legitimately be parsed twice from a *single* transaction (the creation
//! appears as both a top-level instruction and an inner CPI), and on gRPC
//! replay/reconnect the same slot can be delivered again. Deduping only at the
//! alert layer would still write duplicates to storage.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Dedup {
    ttl: Duration,
    seen: Mutex<HashMap<String, Instant>>,
}

impl Dedup {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, seen: Mutex::new(HashMap::new()) }
    }

    /// Returns true if `key` is new (and records it); false if seen within TTL.
    pub fn check_and_insert(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.seen.lock().unwrap();
        map.retain(|_, t| now.duration_since(*t) < self.ttl);
        if map.contains_key(key) {
            return false;
        }
        map.insert(key.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_is_new_repeat_is_not() {
        let d = Dedup::new(Duration::from_secs(60));
        assert!(d.check_and_insert("pool1"));
        assert!(!d.check_and_insert("pool1"));
        assert!(d.check_and_insert("pool2"));
    }

    #[test]
    fn entries_expire_after_ttl() {
        let d = Dedup::new(Duration::from_millis(50));
        assert!(d.check_and_insert("pool1"));
        std::thread::sleep(Duration::from_millis(80));
        // Expired, so it counts as new again.
        assert!(d.check_and_insert("pool1"));
    }
}
