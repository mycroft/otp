use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use otp_core::store::Backend;
use serde::Deserialize;

/// `~/.config/otp/config.toml` (or `$OTP_CONFIG`).
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Store used when neither `--pass` nor `--native` is given. Unset: search both
    /// stores, insert into the database.
    pub backend: Option<BackendChoice>,
    /// Native database path. `$OTP_DB` takes precedence.
    pub database: Option<PathBuf>,
    /// Command printing the master password on stdout, e.g. `["pass", "show", "otp/master"]`.
    pub password_command: Option<Vec<String>>,
    /// Screenshot command for `insert --qrcode`; `{file}` is the PNG path to write.
    pub capture_command: Vec<String>,
    /// Command receiving the code on stdin for `--clip`.
    pub clipboard_command: Vec<String>,
    /// pass store directory. Defaults to `$PASSWORD_STORE_DIR` or `~/.password-store`.
    pub password_store_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            backend: None,
            database: None,
            password_command: None,
            capture_command: otp_core::qr::DEFAULT_CAPTURE_COMMAND
                .iter()
                .map(|s| s.to_string())
                .collect(),
            clipboard_command: vec!["wl-copy".into()],
            password_store_dir: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendChoice {
    Pass,
    Database,
}

impl Config {
    pub fn backend(&self) -> Option<Backend> {
        self.backend.map(|choice| match choice {
            BackendChoice::Pass => Backend::Pass,
            BackendChoice::Database => Backend::Native,
        })
    }

    pub fn load() -> Result<Self> {
        let path = match std::env::var_os("OTP_CONFIG") {
            Some(path) => PathBuf::from(path),
            None => match dirs::config_dir() {
                Some(dir) => dir.join("otp/config.toml"),
                None => return Ok(Config::default()),
            },
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.database = config.database.map(|p| expand_tilde(&p));
        config.password_store_dir = config.password_store_dir.map(|p| expand_tilde(&p));
        Ok(config)
    }

    pub fn database_path(&self) -> Result<PathBuf> {
        if let Some(path) = std::env::var_os("OTP_DB") {
            return Ok(PathBuf::from(path));
        }
        if let Some(path) = &self.database {
            return Ok(path.clone());
        }
        let dir = dirs::data_dir().context("cannot determine the data directory; set OTP_DB")?;
        Ok(dir.join("otp/otp.db"))
    }
}

fn expand_tilde(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), dirs::home_dir()) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}
