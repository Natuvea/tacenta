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
    save_to(&path(), cfg)
}

fn save_to(p: &Path, cfg: &Config) -> Result<(), String> {
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let body = toml::to_string_pretty(cfg).map_err(|e| format!("cannot serialize config: {e}"))?;
    write_private(p, body.as_bytes()).map_err(|e| format!("cannot write {}: {e}", p.display()))
}

/// Write `body` to `p`, which holds API keys, so that only its owner can open
/// it: [`open_private`] makes the file owner-only before anything is written.
fn write_private(p: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    open_private(p)?.write_all(body)
}

/// Open `p` for writing, creating it if needed and emptying it if not, as a
/// file only its owner can open (mode `0600` on Unix).
///
/// A new file is created with that mode in the `open` call, whatever the
/// umask, so there is no moment at which it exists with wider access. A file
/// that already exists, from an earlier version or by hand, keeps the mode it
/// has when it is opened, so the mode is set on the open file, after it is
/// emptied and before the keys are written to it. Failing to set it is an
/// error and nothing is written. On other platforms the file gets the
/// platform's default access.
fn open_private(p: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    const CHILD_DIR: &str = "TACENTA_CLI_CONFIG_TEST_DIR";

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tacenta-cli-config-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn config(key: &str) -> Config {
        Config {
            active_context: Some("work".into()),
            contexts: vec![Context {
                name: "work".into(),
                api_key: key.into(),
            }],
        }
    }

    /// Runs only under [`the_config_file_is_owner_only_whatever_the_umask`],
    /// which starts it under `umask 000`.
    #[test]
    #[ignore = "started by the_config_file_is_owner_only_whatever_the_umask under umask 000"]
    fn config_child() {
        let dir = PathBuf::from(std::env::var_os(CHILD_DIR).expect("run by the parent test"));
        // What a plain create yields under this umask, so the parent can check
        // the relaxed umask took effect and its `0600` is not vacuous.
        std::fs::File::create(dir.join("probe")).unwrap();
        // Opened and left empty: the file as it is before any key is written.
        drop(open_private(&dir.join("empty")).unwrap());
        save_to(&dir.join("nested").join("fresh.toml"), &config("new-key")).unwrap();
        // A file an earlier version created with a wide mode, then saved over.
        std::fs::write(dir.join("old.toml"), "old-key").unwrap();
        save_to(&dir.join("old.toml"), &config("new-key")).unwrap();
    }

    /// The config file, which holds API keys, is `0600` from the moment it
    /// exists, and a wider file from an earlier version is made `0600` before
    /// the keys go into it, whatever the umask.
    #[test]
    fn the_config_file_is_owner_only_whatever_the_umask() {
        let dir = tempdir();
        let child = format!(
            "{}::config_child",
            module_path!().split_once("::").unwrap().1
        );
        let out = Command::new("sh")
            .arg("-c")
            .arg(r#"umask 000; exec "$0" --exact "$1" --ignored"#)
            .arg(std::env::current_exe().unwrap())
            .arg(&child)
            .env(CHILD_DIR, &dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert_eq!(mode(&dir.join("probe")), 0o666, "the umask was not relaxed");
        assert_eq!(mode(&dir.join("empty")), 0o600);
        for name in ["nested/fresh.toml", "old.toml"] {
            let file = dir.join(name);
            assert_eq!(mode(&file), 0o600, "{name}");
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(
                text.contains("new-key") && !text.contains("old-key"),
                "{name}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
