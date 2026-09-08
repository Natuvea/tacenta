//! On-disk credential store for the CLI: named contexts, each holding a tenant
//! API key, in `~/.config/tacenta/config.toml`. The file is written owner-only
//! (0600) where the platform supports it, since it holds keys.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct Config {
    /// Name of the context `try` uses when no key is given inline or in the
    /// environment. Omitted from the file when nothing is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_context: Option<String>,
    #[serde(default)]
    pub contexts: Vec<Context>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Context {
    pub name: String,
    pub api_key: String,
}

impl Config {
    pub fn get(&self, name: &str) -> Option<&Context> {
        self.contexts.iter().find(|c| c.name == name)
    }

    /// The active context, if one is set and still exists.
    pub fn active(&self) -> Option<&Context> {
        self.get(self.active_context.as_deref()?)
    }
}

/// `~/.config/tacenta/config.toml`, honouring `XDG_CONFIG_HOME`.
pub fn path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("tacenta").join("config.toml")
}

/// Load the config, or a default if it is missing or unreadable. A malformed
/// file is treated as empty rather than an error, so a `context create` can
/// always recover.
pub fn load() -> Config {
    match std::fs::read_to_string(path()) {
        Ok(s) => toml::from_str(&s).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

pub fn save(cfg: &Config) -> Result<(), String> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let body = toml::to_string_pretty(cfg).map_err(|e| format!("cannot serialize config: {e}"))?;
    std::fs::write(&p, body).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
    restrict(&p);
    Ok(())
}

/// Keep the file owner-only; it holds API keys.
#[cfg(unix)]
fn restrict(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_p: &Path) {}
