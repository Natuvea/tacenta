//! A sliding-window failed-attempt limiter for the authentication path.
//!
//! Online password guessing is otherwise throttled only by argon2's per-attempt
//! cost (`docs/threat-model.md`). This limiter caps the number of *failed*
//! sign-in attempts for a given key within a time window: once the ceiling is
//! reached, further attempts are refused (`AuthError::RateLimited`) without even
//! running the credential check, until enough failures age out of the window.
//!
//! The key is `(tenant, identifier)` (see `ratelimit_key` in `lib.rs`), chosen so
//! that (a) guessing one account's password cannot lock a *different* account
//! out, and (b) the limit applies whether or not the identifier names a real
//! account — so, like the dummy-verify, it is not an account-existence oracle.
//! A successful sign-in clears the key.
//!
//! Time is passed in explicitly (`now`, unix seconds) rather than read from the
//! clock here, so the policy is deterministically testable; `Accounts::sign_in`
//! supplies the system clock and `Accounts::sign_in_at` takes an explicit one.

use std::collections::HashMap;

/// Default ceiling: this many failed attempts within the window blocks further
/// attempts. Five wrong passwords in a minute is well past honest mistyping.
const MAX_FAILURES: usize = 5;

/// Default window, in seconds. Failures older than this no longer count, so a
/// blocked key recovers on its own after a quiet window.
const WINDOW_SECS: u64 = 60;

/// The most keys the limiter will hold.
///
/// **The map is keyed on an attacker-chosen identifier**, so without a cap an
/// unauthenticated caller cycling identifiers would add a permanent entry per
/// attempt. Sixty-four thousand keys is far above any honest failure volume
/// and bounds the structure absolutely.
const MAX_KEYS: usize = 64 * 1024;

/// Failures per tenant per window above which the credential check is skipped
/// entirely.
///
/// **This exists because two correct defences combine into a lever.** Every
/// failed sign-in runs argon2 at 19 MiB, including for identifiers that do not
/// exist -- deliberately, since the dummy verify is what stops response time
/// leaking whether an account exists. The per-identifier limiter cannot
/// intervene, because a caller cycling identifiers never reaches the ceiling on
/// any single key. So an unauthenticated flood costs 19 MiB of allocation per
/// request, and neither defence is at fault alone.
///
/// Two hundred failures a minute for one tenant is far past honest mistyping
/// and is the point at which the trade below becomes the better one.
const TENANT_FLOOD_CEILING: usize = 200;

/// A per-key sliding window of recent failed-attempt timestamps (unix seconds).
pub(crate) struct RateLimiter {
    failures: HashMap<String, Vec<u64>>,
    max_failures: usize,
    window_secs: u64,
}

impl Default for RateLimiter {
    fn default() -> RateLimiter {
        RateLimiter {
            failures: HashMap::new(),
            max_failures: MAX_FAILURES,
            window_secs: WINDOW_SECS,
        }
    }
}

impl RateLimiter {
    /// The number of failures recorded for `key` that fall within the window
    /// ending at `now`.
    fn recent_failures(&self, key: &str, now: u64) -> usize {
        self.failures.get(key).map_or(0, |ts| {
            ts.iter().filter(|&&t| self.within_window(t, now)).count()
        })
    }

    /// A failure at `t` still counts at `now` if it happened no more than the
    /// window ago. Written as an addition to avoid underflow when `now` is
    /// small (e.g. in tests); real unix timestamps never underflow anyway.
    fn within_window(&self, t: u64, now: u64) -> bool {
        t.saturating_add(self.window_secs) >= now
    }

    /// Whether `key` has reached the failed-attempt ceiling within the window
    /// ending at `now`. Checked before the credential check, so a blocked key
    /// never reaches argon2.
    pub(crate) fn is_blocked(&self, key: &str, now: u64) -> bool {
        self.recent_failures(key, now) >= self.max_failures
    }

    /// Record a failed attempt at `now`, pruning entries that have aged out of
    /// the window so the per-key vector cannot grow without bound.
    pub(crate) fn record_failure(&mut self, key: &str, now: u64) {
        let window = self.window_secs;
        let entry = self.failures.entry(key.to_string()).or_default();
        entry.retain(|&t| t.saturating_add(window) >= now);
        entry.push(now);

        self.shed(now);
    }

    /// Drop what can no longer block, and cap what remains.
    ///
    /// Two steps, in this order. **Expired entries first**: an entry whose
    /// every timestamp is outside the window can never block again, so it is
    /// pure residue and dropping it is free of consequence. That alone bounds
    /// the map for any attacker who pauses.
    ///
    /// **Then a hard cap**, for one who does not. When the map is still over
    /// `MAX_KEYS`, the entries with the oldest most-recent failure are removed
    /// until it fits.
    ///
    /// **The eviction has a consequence and it is not hidden**: removing a key
    /// clears its block, so a flood can in principle unblock someone. Oldest
    /// first is what makes that acceptable rather than merely tolerable -- the
    /// entries nearest eviction are the ones nearest expiry anyway, while a
    /// live attack against one account keeps refreshing its own timestamps and
    /// stays at the young end. An attacker who floods to clear a block has to
    /// out-wait the window they were trying to escape.
    fn shed(&mut self, now: u64) {
        let window = self.window_secs;
        self.failures
            .retain(|_, ts| ts.iter().any(|&t| t.saturating_add(window) >= now));

        if self.failures.len() <= MAX_KEYS {
            return;
        }

        let mut newest: Vec<(u64, String)> = self
            .failures
            .iter()
            .map(|(k, ts)| (ts.iter().copied().max().unwrap_or(0), k.clone()))
            .collect();
        newest.sort_unstable();
        let excess = self.failures.len() - MAX_KEYS;
        for (_, key) in newest.into_iter().take(excess) {
            self.failures.remove(&key);
        }
    }

    /// Whether this tenant is failing so fast that the credential check should
    /// be skipped rather than run.
    ///
    /// **This trades enumeration resistance for availability, and only while
    /// the flood lasts.** Above the ceiling the caller returns the same generic
    /// error without running argon2 at all -- so response time stops masking
    /// whether the account exists, and an observer who can sustain two hundred
    /// failures a minute against one tenant can learn which identifiers are
    /// real. That is a worse position than the dummy verify gives, and a far
    /// better one than exhausting the host's memory, which is the alternative
    /// on offer. Below the ceiling nothing changes.
    pub(crate) fn tenant_is_flooded(&self, tenant_prefix: &str, now: u64) -> bool {
        let count: usize = self
            .failures
            .iter()
            .filter(|(k, _)| k.starts_with(tenant_prefix))
            .map(|(_, ts)| ts.iter().filter(|&&t| self.within_window(t, now)).count())
            .sum();
        count >= TENANT_FLOOD_CEILING
    }

    /// Clear a key's failures — called after a successful authentication, so an
    /// honest user who eventually types the right password is not left blocked.
    pub(crate) fn record_success(&mut self, key: &str) {
        self.failures.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_the_ceiling_then_recovers_when_failures_age_out() {
        let mut rl = RateLimiter::default();
        let key = "tenant\0alice";

        // Four failures at t=0 do not block (ceiling is 5).
        for _ in 0..4 {
            assert!(!rl.is_blocked(key, 0));
            rl.record_failure(key, 0);
        }
        assert!(!rl.is_blocked(key, 0));

        // The fifth failure reaches the ceiling; now blocked.
        rl.record_failure(key, 0);
        assert!(rl.is_blocked(key, 0));
        assert!(rl.is_blocked(key, WINDOW_SECS)); // still within the window

        // Once all five have aged past the window, the key recovers.
        assert!(!rl.is_blocked(key, WINDOW_SECS + 1));
    }

    #[test]
    fn success_clears_the_key() {
        let mut rl = RateLimiter::default();
        let key = "tenant\0bob";
        for _ in 0..5 {
            rl.record_failure(key, 10);
        }
        assert!(rl.is_blocked(key, 10));
        rl.record_success(key);
        assert!(!rl.is_blocked(key, 10));
    }

    #[test]
    fn keys_are_independent() {
        let mut rl = RateLimiter::default();
        for _ in 0..5 {
            rl.record_failure("tenant\0victim", 0);
        }
        // The victim's key is blocked, but a different account is untouched —
        // one account's failures cannot lock out another.
        assert!(rl.is_blocked("tenant\0victim", 0));
        assert!(!rl.is_blocked("tenant\0other", 0));
    }
}

#[cfg(test)]
mod limiter_tests {
    use super::*;

    /// **Dead entries are shed, so cycling identifiers cannot grow the map.**
    ///
    /// `record_failure` prunes timestamps inside an entry and also removes
    /// entries that can no longer block; pruning alone would leave ten
    /// thousand distinct identifiers as ten thousand permanent entries. The
    /// key is `(tenant, identifier)` and the identifier is attacker-chosen, so
    /// that is reachable without authenticating.
    #[test]
    fn cycling_identifiers_does_not_grow_the_map_without_bound() {
        let mut limiter = RateLimiter::default();
        for i in 0..10_000u64 {
            limiter.record_failure(&format!("tenant:{i}"), 1_000);
        }
        assert_eq!(
            limiter.failures.len(),
            10_000,
            "all still inside the window"
        );

        // One failure well past the window sheds every entry that can no longer
        // block, which is all of them.
        let later = 1_000 + WINDOW_SECS * 100;
        limiter.record_failure("tenant:fresh", later);
        assert_eq!(
            limiter.failures.len(),
            1,
            "entries that can never block again must not be held"
        );
    }

    /// An attacker who never pauses is capped rather than pruned.
    #[test]
    fn a_sustained_flood_is_capped() {
        let mut limiter = RateLimiter::default();
        for i in 0..(MAX_KEYS + 5_000) {
            limiter.record_failure(&format!("tenant:{i}"), 1_000);
        }
        assert!(
            limiter.failures.len() <= MAX_KEYS,
            "the map must not exceed its cap, found {}",
            limiter.failures.len()
        );
    }

    /// Eviction takes the oldest first, so a key under live attack keeps its
    /// block while a flood is running: its timestamps stay young.
    #[test]
    fn eviction_takes_the_oldest_and_spares_a_key_under_live_attack() {
        let mut limiter = RateLimiter::default();
        let victim = "tenant:victim";

        // The victim is being attacked *now*, alongside the flood.
        for _ in 0..MAX_FAILURES {
            limiter.record_failure(victim, 2_000);
        }
        assert!(limiter.is_blocked(victim, 2_000));

        for i in 0..(MAX_KEYS + 1_000) {
            limiter.record_failure(&format!("flood:{i}"), 1_999);
        }

        assert!(
            limiter.is_blocked(victim, 2_000),
            "a flood must not clear the block on a key it is not attacking"
        );
    }

    /// The flood gate counts across identifiers, which is what the
    /// per-identifier ceiling cannot do.
    #[test]
    fn a_tenant_flood_across_many_identifiers_is_detected() {
        let mut limiter = RateLimiter::default();
        let prefix = "acme\u{0}";

        // Well under the per-key ceiling on every key, so `is_blocked` never
        // fires -- which is exactly the shape that reached argon2 unthrottled.
        for i in 0..TENANT_FLOOD_CEILING {
            limiter.record_failure(&format!("{prefix}user{i}"), 1_000);
            assert!(!limiter.is_blocked(&format!("{prefix}user{i}"), 1_000));
        }
        assert!(limiter.tenant_is_flooded(prefix, 1_000));
    }

    /// One tenant's flood must not gate another's sign-ins.
    #[test]
    fn a_flood_does_not_reach_across_tenants() {
        let mut limiter = RateLimiter::default();
        for i in 0..(TENANT_FLOOD_CEILING * 2) {
            limiter.record_failure(&format!("acme\u{0}user{i}"), 1_000);
        }
        assert!(limiter.tenant_is_flooded("acme\u{0}", 1_000));
        assert!(!limiter.tenant_is_flooded("other\u{0}", 1_000));
    }

    /// It recovers on its own, like the per-key ceiling.
    #[test]
    fn the_flood_gate_reopens_after_the_window() {
        let mut limiter = RateLimiter::default();
        for i in 0..TENANT_FLOOD_CEILING {
            limiter.record_failure(&format!("acme\u{0}user{i}"), 1_000);
        }
        assert!(limiter.tenant_is_flooded("acme\u{0}", 1_000));
        assert!(!limiter.tenant_is_flooded("acme\u{0}", 1_000 + WINDOW_SECS + 1));
    }
}
