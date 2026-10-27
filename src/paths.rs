//! Where mcpx keeps its state: `~/.config/mcpx` on Linux/macOS,
//! `%APPDATA%\mcpx` on Windows (or `$MCPX_HOME` anywhere).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    /// `$MCPX_HOME`, else `$XDG_CONFIG_HOME/mcpx`, else `%APPDATA%\mcpx`
    /// (Windows only), else `~/.config/mcpx`.
    pub fn from_env() -> Self {
        if let Some(h) = std::env::var_os("MCPX_HOME") {
            return Self { home: h.into() };
        }
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
            return Self {
                home: PathBuf::from(x).join("mcpx"),
            };
        }
        #[cfg(windows)]
        if let Some(a) = std::env::var_os("APPDATA") {
            return Self {
                home: PathBuf::from(a).join("mcpx"),
            };
        }
        Self {
            home: user_home().join(".config").join("mcpx"),
        }
    }

    pub fn at(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    pub fn config(&self) -> PathBuf {
        self.home.join("mcp.json")
    }
    pub fn tokens(&self) -> PathBuf {
        self.home.join("tokens.json")
    }
    pub fn gateway(&self) -> PathBuf {
        self.home.join("gateway.json")
    }
}

/// `$HOME`; on Windows falls back to `%USERPROFILE%`.
pub fn user_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| {
            if cfg!(windows) {
                std::env::var_os("USERPROFILE")
            } else {
                None
            }
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Write `data` to `path` with mode 0600, atomically (tmp + rename).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}
