//! A per-IP sliding-window throttle for tenant signup.
//!
//! Legitimate tenant signup is rare per source address (a person signs up
//! once), so a low ceiling over a long window stops signup floods without
//! troubling real users. This is the signup-throttling the threat model records
//! as a gap; it lives here because the gateway is where the client IP is
//! visible (the account TCP service never sees it).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default ceiling: signups allowed per IP within the window.
const MAX_PER_WINDOW: usize = 5;

/// The most distinct callers the limiter will hold.
///
/// The key comes from a request header, so without a cap an unauthenticated
/// caller varying it would add a permanent entry per request. Same shape as
/// the accounts limiter's cap.
const MAX_KEYS: usize = 64 * 1024;
/// Default window, in seconds (one hour).
const WINDOW_SECS: u64 = 60 * 60;

/// Recent signup timestamps (unix seconds) per client IP.
pub struct IpRateLimiter {
    seen: HashMap<String, Vec<u64>>,
    max: usize,
    window: u64,
}

impl Default for IpRateLimiter {
    fn default() -> IpRateLimiter {
        IpRateLimiter {
            seen: HashMap::new(),
            max: MAX_PER_WINDOW,
            window: WINDOW_SECS,
        }
    }
}

impl IpRateLimiter {
    /// A limiter with its own ceiling per window: the signup default is
    /// [`Default`]; the websocket carriage's directory upgrades use a looser
    /// one.
    pub fn with_limit(max: usize) -> IpRateLimiter {
        IpRateLimiter {
            max,
            ..IpRateLimiter::default()
        }
    }

    /// Record a signup attempt from `ip` and report whether it is **over** the
    /// limit (should be refused). A refused attempt is not recorded, so being
    /// blocked does not itself push the window forward. Uses the system clock.
    pub fn check_and_record(&mut self, ip: &str) -> bool {
        self.check_and_record_at(ip, now())
    }

    /// [`check_and_record`](Self::check_and_record) with an explicit clock, for
    /// deterministic tests.
    pub fn check_and_record_at(&mut self, ip: &str, now: u64) -> bool {
        let window = self.window;
        let entry = self.seen.entry(ip.to_owned()).or_default();
        entry.retain(|&t| t.saturating_add(window) >= now);
        if entry.len() >= self.max {
            return true;
        }
        entry.push(now);
        shed(&mut self.seen, window, now);
        false
    }
}

/// Drop callers who can no longer be blocked, then cap what remains.
///
/// The same two steps as the accounts limiter, for the same reason and with the
/// same trade: eviction takes the oldest last-seen first, so a caller being
/// actively throttled keeps refreshing its timestamps and stays at the young
/// end while a flood is shed around it.
fn shed(seen: &mut HashMap<String, Vec<u64>>, window: u64, now: u64) {
    seen.retain(|_, ts| ts.iter().any(|&t| t.saturating_add(window) >= now));
    if seen.len() <= MAX_KEYS {
        return;
    }
    let mut newest: Vec<(u64, String)> = seen
        .iter()
        .map(|(k, ts)| (ts.iter().copied().max().unwrap_or(0), k.clone()))
        .collect();
    newest.sort_unstable();
    let excess = seen.len() - MAX_KEYS;
    for (_, key) in newest.into_iter().take(excess) {
        seen.remove(&key);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_the_ceiling_and_recovers_after_the_window() {
        let mut rl = IpRateLimiter::default();
        // Five allowed at t=1000, the sixth blocked.
        for _ in 0..MAX_PER_WINDOW {
            assert!(!rl.check_and_record_at("192.0.2.4", 1000));
        }
        assert!(rl.check_and_record_at("192.0.2.4", 1000));
        // A different IP is independent.
        assert!(!rl.check_and_record_at("192.0.2.8", 1000));
        // Once the window passes, the first IP is allowed again.
        assert!(!rl.check_and_record_at("192.0.2.4", 1000 + WINDOW_SECS + 1));
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    /// The key comes from a request header, so an unauthenticated caller can
    /// vary it freely. Entries that can no longer block must not be kept.
    #[test]
    fn varying_the_key_does_not_grow_the_map_without_bound() {
        let mut limiter = IpRateLimiter::default();
        for i in 0..10_000u64 {
            limiter.check_and_record_at(&format!("10.0.0.{i}"), 1_000);
        }
        limiter.check_and_record_at("10.0.0.fresh", 1_000 + WINDOW_SECS * 100);
        assert_eq!(
            limiter.seen.len(),
            1,
            "callers that can no longer be blocked must be shed"
        );
    }

    #[test]
    fn a_sustained_flood_is_capped() {
        let mut limiter = IpRateLimiter::default();
        for i in 0..(MAX_KEYS + 2_000) {
            limiter.check_and_record_at(&format!("10.0.{i}"), 1_000);
        }
        assert!(limiter.seen.len() <= MAX_KEYS);
    }
}
