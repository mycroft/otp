use std::io::{BufRead, IsTerminal, Write};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Reads a secret value: a hidden prompt on a terminal, otherwise the first line of stdin.
pub fn secret(prompt: &str) -> Result<Zeroizing<String>> {
    let value = if std::io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password(prompt)?)
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().read_line(&mut line)?;
        line
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("no input given");
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

/// Asks a yes/no question on the terminal. Defaults to no.
pub fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("refusing to ask for confirmation without a terminal; use --force");
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// Where the master password comes from.
pub enum PasswordSource<'a> {
    Env(Zeroizing<String>),
    Command(&'a [String]),
    Prompt,
}

/// `OTP_PASSWORD`, moved out of the environment by [`take_env_password`].
static ENV_PASSWORD: OnceLock<Option<Zeroizing<String>>> = OnceLock::new();

/// Reads `OTP_PASSWORD` and removes it from the environment, so that no child process
/// (pass, gpg, the capture tool, the viewer, a clipboard tool that keeps running in the
/// background) inherits the master password.
///
/// # Safety
///
/// Must be called before any other thread is started, as it modifies the environment.
pub unsafe fn take_env_password() {
    let password = std::env::var_os("OTP_PASSWORD")
        .map(|password| Zeroizing::new(password.to_string_lossy().into_owned()));
    // SAFETY: the caller guarantees no other thread reads or writes the environment.
    unsafe { std::env::remove_var("OTP_PASSWORD") };
    let _ = ENV_PASSWORD.set(password);
}

impl<'a> PasswordSource<'a> {
    pub fn new(command: Option<&'a [String]>) -> Self {
        if let Some(Some(password)) = ENV_PASSWORD.get() {
            return PasswordSource::Env(password.clone());
        }
        match command {
            Some(command) if !command.is_empty() => PasswordSource::Command(command),
            _ => PasswordSource::Prompt,
        }
    }

    /// Gets the master password of an existing database.
    pub fn existing(&self) -> Result<Zeroizing<String>> {
        match self {
            PasswordSource::Env(password) => Ok(password.clone()),
            PasswordSource::Command(command) => run_password_command(command, true),
            PasswordSource::Prompt => Ok(Zeroizing::new(rpassword::prompt_password(
                "Master password: ",
            )?)),
        }
    }

    /// Gets the master password without touching the terminal, if the source allows it.
    pub fn non_interactive(&self) -> Option<Result<Zeroizing<String>>> {
        match self {
            PasswordSource::Env(password) => Some(Ok(password.clone())),
            PasswordSource::Command(command) => Some(run_password_command(command, false)),
            PasswordSource::Prompt => None,
        }
    }

    /// Gets a password for a new database, asking twice when prompting.
    pub fn new_password(&self, what: &str) -> Result<Zeroizing<String>> {
        let PasswordSource::Prompt = self else {
            return self.existing();
        };
        let password = Zeroizing::new(rpassword::prompt_password(format!("{what}: "))?);
        if password.is_empty() {
            bail!("the master password must not be empty");
        }
        let again = Zeroizing::new(rpassword::prompt_password(format!("Repeat {what}: "))?);
        if password != again {
            bail!("passwords do not match");
        }
        Ok(password)
    }
}

fn run_password_command(command: &[String], interactive: bool) -> Result<Zeroizing<String>> {
    let terminal = || {
        if interactive {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    };
    let output = Command::new(&command[0])
        .args(&command[1..])
        .stdin(terminal())
        .stderr(terminal())
        .output()
        .with_context(|| format!("running password command {:?}", command[0]))?;
    let stdout = Zeroizing::new(output.stdout);
    if !output.status.success() {
        bail!(
            "password command {:?} failed ({})",
            command[0],
            output.status
        );
    }
    let text = std::str::from_utf8(&stdout).context("password command output is not UTF-8")?;
    Ok(Zeroizing::new(
        text.lines().next().unwrap_or("").to_string(),
    ))
}
