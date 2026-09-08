//! The service-document cache: `~/.cache/tacenta/service.toml`, honouring
//! `XDG_CACHE_HOME`. Separate from the config file on purpose: that file
//! holds API keys and is written only by explicit `context` commands, while
//! this one is scratch that `try` and `chat` rewrite as they go. Losing it
//! costs one fetch; it is written atomically so a crash mid-write leaves the
//! old entry rather than a torn file, and a file that does not parse is
//! treated as absent.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tacenta_client::ServiceDocument;

/// A service document and where and when it was fetched.
#[derive(Serialize, Deserialize, Clone)]
pub struct CachedService {
    pub url: String,
    /// Seconds since the Unix epoch.
    pub fetched_at: u64,
    pub document: ServiceDocument,
}

impl CachedService {
    /// The gateway serves the document with `max-age=300`; honour that.
    pub const MAX_AGE_SECS: u64 = 300;

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Whether this entry still answers for `url`: same URL, fetched within
    /// the lifetime, and not from the future (a clock set back would
    /// otherwise keep it fresh until the clock caught up).
    pub fn is_fresh_for(&self, url: &str) -> bool {
        self.is_fresh_for_at(url, CachedService::now())
    }

    fn is_fresh_for_at(&self, url: &str, now: u64) -> bool {
        self.url == url && self.fetched_at <= now && now - self.fetched_at < Self::MAX_AGE_SECS
    }
}

/// `~/.cache/tacenta/service.toml`, honouring `XDG_CACHE_HOME`.
pub fn path() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    base.join("tacenta").join("service.toml")
}

/// The cached entry, if there is one and it parses.
pub fn load() -> Option<CachedService> {
    let s = std::fs::read_to_string(path()).ok()?;
    toml::from_str(&s).ok()
}

/// Write the entry atomically: to a sibling file, then renamed into place.
pub fn save(entry: &CachedService) -> Result<(), String> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let body = toml::to_string_pretty(entry).map_err(|e| format!("cannot serialize: {e}"))?;
    let tmp = p.with_extension(format!("toml.{}", std::process::id()));
    std::fs::write(&tmp, body).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("cannot rename into {}: {e}", p.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fetched_at: u64) -> CachedService {
        CachedService {
            url: "https://tacenta.example/.well-known/tacenta".into(),
            fetched_at,
            document: ServiceDocument::hosted("tacenta.example"),
        }
    }

    #[test]
    fn freshness_is_by_url_age_and_not_from_the_future() {
        let url = "https://tacenta.example/.well-known/tacenta";
        assert!(entry(1_000).is_fresh_for_at(url, 1_000));
        assert!(entry(1_000).is_fresh_for_at(url, 1_299));
        assert!(!entry(1_000).is_fresh_for_at(url, 1_300));
        assert!(!entry(1_000).is_fresh_for_at("https://other.example/x", 1_000));
        // Fetched "in the future": stale, not fresh-until-the-clock-catches-up.
        assert!(!entry(2_000).is_fresh_for_at(url, 1_000));
    }
}
