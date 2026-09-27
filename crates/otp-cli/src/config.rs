use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use otp_core::store::Backend;
use serde::Deserialize;

/// `~/.config/otp/config.toml`, or the file given with `--config` or `$OTP_CONFIG_FILE`.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Store used when neither `--pass` nor `--native` is given. Unset: search both
    /// stores, insert into the database.
    pub backend: Option<BackendChoice>,
    /// Native database path. `$OTP_DB` takes precedence.
    pub database: Option<PathBuf>,
    /// Refuse new master passwords that zxcvbn finds guessable (score below 4). With false,
    /// only the minimum length of 12 characters is required.
    pub password_score_check: bool,
    /// Command printing the master password on stdout, e.g. `["pass", "show", "otp/master"]`.
    pub password_command: Option<Vec<String>>,
    /// Screenshot command for `insert --qrcode`; `{file}` is the PNG path to write.
    pub capture_command: Vec<String>,
    /// Viewer for `otp --qrcode NAME`, given a PNG as `{file}`, e.g. `["chafa", "{file}"]`.
    /// Unset: the QR code is drawn in the terminal.
    pub qrcode_viewer_command: Option<Vec<String>>,
    /// Command receiving the code on stdin for `--clip`.
    pub clipboard_command: Vec<String>,
    /// Seconds after which a copied value is cleared from the clipboard, if it is still
    /// there. 0 keeps it.
    pub clipboard_timeout: u64,
    /// Command printing the clipboard, to check it still holds what otp copied.
    pub clipboard_paste_command: Vec<String>,
    /// Command clearing the clipboard.
    pub clipboard_clear_command: Vec<String>,
    /// pass store directory. Defaults to `$PASSWORD_STORE_DIR` or `~/.password-store`.
    pub password_store_dir: Option<PathBuf>,
    /// `[tui]` section. Accepted even without the `tui` feature, so one config file
    /// works with every build.
    pub tui: TuiConfig,
    /// The file this configuration was read from, if any.
    #[serde(skip)]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[cfg_attr(not(feature = "tui"), allow(dead_code))]
pub struct TuiConfig {
    /// Show codes as `123 456` instead of `123456`. Off by default so that selecting a
    /// code with the mouse copies it without a space.
    pub group_digits: bool,
    /// Start with codes and secrets hidden, as if Ctrl-H had been pressed.
    pub hidden: bool,
    /// Switch to hidden mode after this many seconds without a key press. 0 never does.
    pub hide_after: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        TuiConfig {
            group_digits: false,
            hidden: false,
            hide_after: 30,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            backend: None,
            database: None,
            password_score_check: true,
            password_command: None,
            capture_command: otp_core::qr::DEFAULT_CAPTURE_COMMAND
                .iter()
                .map(|s| s.to_string())
                .collect(),
            qrcode_viewer_command: None,
            // --sensitive asks clipboard managers (e.g. cliphist) not to keep a history.
            clipboard_command: vec!["wl-copy".into(), "--sensitive".into()],
            clipboard_timeout: 45,
            clipboard_paste_command: vec!["wl-paste".into(), "--no-newline".into()],
            clipboard_clear_command: vec!["wl-copy".into(), "--clear".into()],
            password_store_dir: None,
            tui: TuiConfig::default(),
            file: None,
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

    /// Loads the configuration file: `explicit` (`--config`), else `$OTP_CONFIG_FILE`, else
    /// `~/.config/otp/config.toml`. A file named with `--config` or `$OTP_CONFIG_FILE` must
    /// exist; the default one is optional.
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let (path, required) = match explicit {
            Some(path) => (path.to_path_buf(), true),
            None => match std::env::var_os("OTP_CONFIG_FILE") {
                Some(path) => (PathBuf::from(path), true),
                None => match dirs::config_dir() {
                    Some(dir) => (dir.join("otp/config.toml"), false),
                    None => return Ok(Config::default()),
                },
            },
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
                return Ok(Config::default());
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.database = config.database.map(|p| expand_tilde(&p));
        config.password_store_dir = config.password_store_dir.map(|p| expand_tilde(&p));
        config.file = Some(path);
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
