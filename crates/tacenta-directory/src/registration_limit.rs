//! A per-source sliding-window throttle on new handle registrations (
//! decision 0079).
//!
//! On an open self-service deployment, registering a recipient handle is what
//! lets a party occupy relay memory (sends to unregistered addresses are already
//! refused). The relay's byte budgets bound *memory* but not *fairness*: at
//! the node ceiling refusal is global backpressure, so cheap mass registration can
//! still crowd everyone out. This bounds the *rate* of new registrations per
//! source, which is the load-bearing lever — fairness only matters once the number
//! of principals is bounded, and bounding it is admission control, not a queue.
//!
//! Same shape as the gateway's proven signup limiter
//! (`tacenta-gateway::ratelimit`), including its map-growth defence: the key is a
//! client address, so an attacker varying it would otherwise add a permanent map
//! entry per attempt. Callers who can no longer be blocked are shed, then the map
//! is capped, evicting the oldest last-seen first so a live flood is shed around
//! an actively-throttled caller.
//!
//! **The limit, see decision 0079:** per-source throttling is defeated by an attacker with
//! many source addresses. It makes mass registration cost "one source per N per
//! hour," not impossible. A hard bound on the handle count needs a stronger gate
//! (invite / account-gated registration), deferred to a deployment that requires
//! it. A note on NAT: many legitimate users can share one source address, so the
//! ceiling is tunable and set with that headroom in mind.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default ceiling: new registrations allowed per source within the window.
/// Low, because a source registers rarely; raised per deployment via
/// `TACENTA_REGISTRATION_MAX_PER_HOUR` for NAT headroom.
pub const DEFAULT_MAX_PER_WINDOW: usize = 20;

/// The most distinct sources the limiter will hold, bounding its own memory
/// against a key-varying attacker (same defence as the gateway limiter).
const MAX_KEYS: usize = 64 * 1024;

/// Window length, in seconds (one hour), matching the gateway limiter.
const WINDOW_SECS: u64 = 60 * 60;

/// Recent new-registration timestamps (unix seconds) per source address.
pub struct RegistrationLimiter {
    seen: HashMap<String, Vec<u64>>,
    max: usize,
    window: u64,
}

impl Default for RegistrationLimiter {
    fn default() -> RegistrationLimiter {
        RegistrationLimiter::with_max(DEFAULT_MAX_PER_WINDOW)
    }
}

impl RegistrationLimiter {
    /// A limiter with an explicit per-window ceiling (the deployment's tuned
    /// value); the window is fixed at one hour.
    pub fn with_max(max: usize) -> RegistrationLimiter {
        RegistrationLimiter {
            seen: HashMap::new(),
            max: max.max(1),
            window: WINDOW_SECS,
        }
    }

    /// Record a **new registration** from `source` and report whether it is
    /// **over** the ceiling (should be refused). A refused attempt is not
    /// recorded, so being blocked does not push the window forward. Call this
    /// *only* when a registration would create a new binding — never for a
    /// re-confirm of an existing handle (0079). Uses the system clock.
    pub fn over_limit(&mut self, source: &str) -> bool {
        self.over_limit_at(source, now())
    }

    /// [`over_limit`](Self::over_limit) with an explicit clock, for deterministic
    /// tests.
    pub fn over_limit_at(&mut self, source: &str, now: u64) -> bool {
        let window = self.window;
        let entry = self.seen.entry(source.to_owned()).or_default();
        entry.retain(|&t| t.saturating_add(window) >= now);
        if entry.len() >= self.max {
            return true;
        }
        entry.push(now);
        shed(&mut self.seen, window, now);
        false
    }
}

/// Drop sources that can no longer be blocked, then cap what remains — oldest
/// last-seen first, so a caller being actively throttled stays resident while a
/// key-varying flood is shed around it.
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
        let mut rl = RegistrationLimiter::with_max(3);
        for _ in 0..3 {
            assert!(!rl.over_limit_at("192.0.2.4", 1000));
        }
        // The fourth new registration from the same source is refused.
        assert!(rl.over_limit_at("192.0.2.4", 1000));
        // A different source is independent.
        assert!(!rl.over_limit_at("192.0.2.8", 1000));
        // Once the window passes, the first source is allowed again.
        assert!(!rl.over_limit_at("192.0.2.4", 1000 + WINDOW_SECS + 1));
    }

    /// A refused attempt is not recorded, so a blocked source does not keep
    /// itself blocked forever by its own rejected tries — it recovers exactly one
    /// window after its last *accepted* registration.
    #[test]
    fn a_refused_attempt_does_not_extend_the_block() {
        let mut rl = RegistrationLimiter::with_max(1);
        assert!(!rl.over_limit_at("192.0.2.4", 1000)); // accepted at 1000
        assert!(rl.over_limit_at("192.0.2.4", 1500)); // refused, not recorded
        // One window after the accepted one (not the refused one), it recovers.
        assert!(!rl.over_limit_at("192.0.2.4", 1000 + WINDOW_SECS + 1));
    }

    /// The key is a client address; a varying-key flood must not grow the map
    /// without bound. Sources that can no longer block are shed.
    #[test]
    fn varying_the_source_does_not_grow_the_map_without_bound() {
        let mut rl = RegistrationLimiter::default();
        for i in 0..10_000u64 {
            rl.over_limit_at(&format!("10.0.0.{i}"), 1_000);
        }
        rl.over_limit_at("10.0.0.fresh", 1_000 + WINDOW_SECS * 100);
        assert_eq!(
            rl.seen.len(),
            1,
            "sources that can no longer block are shed"
        );
    }

    #[test]
    fn a_sustained_flood_is_capped() {
        let mut rl = RegistrationLimiter::default();
        for i in 0..(MAX_KEYS + 2_000) {
            rl.over_limit_at(&format!("10.0.{i}"), 1_000);
        }
        assert!(rl.seen.len() <= MAX_KEYS);
    }
}
