//! pass(1) store.
//!
//! Entry `NAME` is stored as the pass entry `NAME-otp`. Its first line is the
//! `otpauth://` URI, so pass-otp and other tools can read it; the lines after it hold the
//! entry's [`Metadata`] as JSON:
//!
//! ```text
//! otpauth://totp/google.com:alice?secret=...&issuer=google.com&algorithm=SHA1&digits=6&period=30
//! {
//!   "created_at": "2026-09-25T10:00:00Z",
//!   "updated_at": "2026-09-25T10:00:00Z"
//! }
//! ```
//!
//! Entries created by other tools (URI only, or followed by free-form notes) can be read
//! too. When such an entry is rewritten, its trailing lines are kept as they are.

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use super::{Backend, Store};
use crate::{Entry, Error, Metadata, OtpSecret, Result, validate_name};

pub const SUFFIX: &str = "-otp";

pub struct PassStore {
    program: OsString,
    store_dir: PathBuf,
    envs: Vec<(OsString, OsString)>,
    interactive: bool,
}

impl PassStore {
    /// Uses `store_dir`, or like pass itself, `$PASSWORD_STORE_DIR` or `~/.password-store`.
    pub fn new(store_dir: Option<PathBuf>) -> Self {
        let store_dir = store_dir
            .or_else(|| std::env::var_os("PASSWORD_STORE_DIR").map(PathBuf::from))
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME").unwrap_or_default();
                PathBuf::from(home).join(".password-store")
            });
        PassStore {
            program: "pass".into(),
            store_dir,
            envs: Vec::new(),
            interactive: true,
        }
    }

    /// Overrides the pass executable.
    pub fn program(mut self, program: impl Into<OsString>) -> Self {
        self.program = program.into();
        self
    }

    /// Sets an environment variable for pass invocations (e.g. `GNUPGHOME`).
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Keeps `pass show` and `pass insert` away from the terminal: no stdin for `show`,
    /// and gpg's stderr is captured into the error message instead of being printed.
    /// For full-screen interfaces.
    pub fn non_interactive(mut self) -> Self {
        self.interactive = false;
        self
    }

    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// The pass entry name for an OTP entry name.
    pub fn pass_name(name: &str) -> String {
        format!("{name}{SUFFIX}")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(args)
            .env("PASSWORD_STORE_DIR", &self.store_dir)
            .envs(self.envs.iter().map(|(k, v)| (k, v)));
        cmd
    }

    fn spawn_error(&self, e: std::io::Error) -> Error {
        if e.kind() == ErrorKind::NotFound {
            Error::Pass(format!(
                "{} not found; is pass installed?",
                self.program.to_string_lossy()
            ))
        } else {
            Error::Io(e)
        }
    }

    fn show(&self, name: &str) -> Result<Zeroizing<String>> {
        let pass_name = Self::pass_name(name);
        // When interactive, stderr is inherited so gpg/pass diagnostics reach the user.
        let (stdin, stderr) = if self.interactive {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::piped())
        };
        let output = self
            .command(&["show", "--", &pass_name])
            .stdin(stdin)
            .stderr(stderr)
            .output()
            .map_err(|e| self.spawn_error(e))?;
        let stdout = Zeroizing::new(output.stdout);
        if !output.status.success() {
            return Err(failure(
                &format!("pass show {pass_name}"),
                output.status,
                &output.stderr,
            ));
        }
        String::from_utf8(stdout.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| Error::Pass(format!("{pass_name} is not valid UTF-8")))
    }

    fn insert(&self, name: &str, contents: &str) -> Result<()> {
        let pass_name = Self::pass_name(name);
        let mut child = self
            .command(&["insert", "--multiline", "--force", "--", &pass_name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(if self.interactive {
                Stdio::inherit()
            } else {
                Stdio::piped()
            })
            .spawn()
            .map_err(|e| self.spawn_error(e))?;
        {
            let mut stdin = child.stdin.take().expect("stdin is piped");
            stdin.write_all(contents.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(failure(
                &format!("pass insert {pass_name}"),
                output.status,
                &output.stderr,
            ));
        }
        Ok(())
    }

    fn collect(&self, dir: &Path, prefix: &str, names: &mut Vec<String>) -> Result<()> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if file_name.starts_with('.') {
                continue;
            }
            // Follow symlinks, as pass does.
            let path = entry.path();
            if path.is_dir() {
                self.collect(&path, &format!("{prefix}{file_name}/"), names)?;
            } else if let Some(name) = file_name
                .strip_suffix(".gpg")
                .and_then(|stem| stem.strip_suffix(SUFFIX))
            {
                let name = format!("{prefix}{name}");
                if validate_name(&name).is_ok() {
                    names.push(name);
                }
            }
        }
        Ok(())
    }
}

impl Store for PassStore {
    fn backend(&self) -> Backend {
        Backend::Pass
    }

    fn list(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        self.collect(&self.store_dir, "", &mut names)?;
        names.sort();
        Ok(names)
    }

    fn contains(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        let file = format!("{}.gpg", Self::pass_name(name));
        Ok(self.store_dir.join(file).is_file())
    }

    fn get(&self, name: &str) -> Result<Option<Entry>> {
        if !self.contains(name)? {
            return Ok(None);
        }
        let contents = self.show(name)?;
        parse(&contents).map(Some)
    }

    fn put(&mut self, name: &str, entry: &Entry) -> Result<()> {
        validate_name(name)?;
        let trailer = if self.contains(name)? {
            let existing = self.show(name)?;
            let (_, rest) = split(&existing);
            let rest = rest.trim();
            let is_ours = rest.is_empty() || serde_json::from_str::<Metadata>(rest).is_ok();
            (!is_ours).then(|| Zeroizing::new(rest.to_string()))
        } else {
            None
        };
        let contents = Zeroizing::new(format(entry, trailer.as_deref().map(|s| s.as_str()))?);
        self.insert(name, &contents)
    }

    fn remove(&mut self, name: &str) -> Result<bool> {
        if !self.contains(name)? {
            return Ok(false);
        }
        let pass_name = Self::pass_name(name);
        let status = self
            .command(&["rm", "--force", "--", &pass_name])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| self.spawn_error(e))?;
        if !status.success() {
            return Err(Error::Pass(format!(
                "`pass rm {pass_name}` failed ({status})"
            )));
        }
        Ok(true)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<bool> {
        validate_name(to)?;
        if !self.contains(from)? {
            return Ok(false);
        }
        let (from, to) = (Self::pass_name(from), Self::pass_name(to));
        // pass re-encrypts for the destination's .gpg-id and commits when using git.
        let status = self
            .command(&["mv", "--force", "--", &from, &to])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| self.spawn_error(e))?;
        if !status.success() {
            return Err(Error::Pass(format!(
                "`pass mv {from} {to}` failed ({status})"
            )));
        }
        Ok(true)
    }
}

/// A failed pass command, explained by the last line of its stderr when captured.
fn failure(command: &str, status: std::process::ExitStatus, stderr: &[u8]) -> Error {
    let stderr = String::from_utf8_lossy(stderr);
    Error::Pass(match stderr.lines().rev().find(|l| !l.trim().is_empty()) {
        Some(detail) => format!("`{command}` failed: {}", detail.trim()),
        None => format!("`{command}` failed ({status})"),
    })
}

fn split(contents: &str) -> (&str, &str) {
    contents.split_once('\n').unwrap_or((contents, ""))
}

/// Parses the contents of a pass entry.
pub(crate) fn parse(contents: &str) -> Result<Entry> {
    let (uri, rest) = split(contents);
    let otp = OtpSecret::from_uri(uri)?;
    // Free-form trailing lines (e.g. notes from other tools) mean no metadata.
    let meta = serde_json::from_str(rest.trim()).unwrap_or_default();
    Ok(Entry { otp, meta })
}

/// Formats an entry as pass contents. `trailer` replaces the JSON metadata.
pub(crate) fn format(entry: &Entry, trailer: Option<&str>) -> Result<String> {
    let rest = match trailer {
        Some(trailer) => trailer.to_string(),
        None => serde_json::to_string_pretty(&entry.meta)?,
    };
    Ok(format!("{}\n{rest}\n", entry.otp.to_uri()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;

    const URI: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\
                       &algorithm=SHA1&digits=6&period=30";

    #[test]
    fn format_and_parse_round_trip() {
        let entry = Entry::new(OtpSecret::from_uri(URI).unwrap());
        let contents = format(&entry, None).unwrap();
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some(URI));
        assert_eq!(lines.next(), Some("{"));
        assert!(contents.contains("\"created_at\""));
        assert_eq!(parse(&contents).unwrap(), entry);
    }

    #[test]
    fn parses_foreign_entries() {
        let entry = parse(&format!("{URI}\n")).unwrap();
        assert_eq!(entry.meta, Metadata::default());
        let entry = parse(&format!("{URI}\nrecovery codes: 1234 5678\n")).unwrap();
        assert_eq!(entry.meta, Metadata::default());
        assert_eq!(entry.otp.kind, Kind::Totp { period: 30 });
        assert!(parse("not a uri\n").is_err());
    }

    #[test]
    fn lists_only_otp_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for file in [
            "google.com/alice-otp.gpg",
            "google.com/alice.gpg",
            "github-otp.gpg",
            "work/aws/root-otp.gpg",
            ".git/objects-otp.gpg",
            ".gpg-id",
        ] {
            let path = root.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"").unwrap();
        }
        let store = PassStore::new(Some(root.to_path_buf()));
        assert_eq!(
            store.list().unwrap(),
            ["github", "google.com/alice", "work/aws/root"]
        );
        assert!(store.contains("google.com/alice").unwrap());
        assert!(!store.contains("google.com/bob").unwrap());
        assert!(store.contains("../etc").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_interactive_failures_explain_themselves() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("pass");
        fs::write(
            &script,
            "#!/bin/sh\necho 'gpg: public key not found' >&2\nexit 2\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut store = PassStore::new(Some(dir.path().join("store")))
            .program(&script)
            .non_interactive();
        let entry = Entry::new(OtpSecret::from_uri(URI).unwrap());
        let error = store.put("x", &entry).unwrap_err().to_string();
        assert!(
            error.contains("`pass insert x-otp` failed: gpg: public key not found"),
            "{error}"
        );
    }

    #[test]
    fn missing_store_dir_lists_nothing() {
        let store = PassStore::new(Some("/nonexistent/password-store".into()));
        assert!(store.list().unwrap().is_empty());
    }
}
