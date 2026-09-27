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
    /// Whether the password is typed at a prompt (not from OTP_PASSWORD or a command).
    pub fn is_prompt(&self) -> bool {
        matches!(self, PasswordSource::Prompt)
    }

    /// Gets a password for a new database, asking twice when prompting. It must pass
    /// [`check_strength`], wherever it comes from.
    pub fn new_password(&self, what: &str, check_score: bool) -> Result<Zeroizing<String>> {
        let PasswordSource::Prompt = self else {
            let password = self.existing()?;
            check_strength(&password, check_score)?;
            return Ok(password);
        };
        let password = Zeroizing::new(rpassword::prompt_password(format!("{what}: "))?);
        // Checked before asking again, so a weak password is not typed twice.
        check_strength(&password, check_score)?;
        let again = Zeroizing::new(rpassword::prompt_password(format!("Repeat {what}: "))?);
        if password != again {
            bail!("passwords do not match");
        }
        Ok(password)
    }
}

/// Minimum length of a new master password, in characters.
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Checks a new master password: at least [`MIN_PASSWORD_LENGTH`] characters and, with
/// `check_score` (the `password_score_check` setting), the top zxcvbn score, 4: more
/// than 10^10 estimated guesses. A stolen database file can be attacked offline; score 3
/// starts at 10^8 guesses and admits "correct horse".
pub fn check_strength(password: &str, check_score: bool) -> Result<()> {
    let length = password.chars().count();
    if length < MIN_PASSWORD_LENGTH {
        bail!(
            "the master password must be at least {MIN_PASSWORD_LENGTH} characters long \
             (it has {length}); a passphrase of 4 or more random words is easy to remember"
        );
    }
    if !check_score {
        return Ok(());
    }
    let estimate = zxcvbn::zxcvbn(password, &["otp"]);
    if estimate.score() < zxcvbn::Score::Four {
        let mut message = "the master password is too easy to guess".to_string();
        if let Some(feedback) = estimate.feedback() {
            if let Some(warning) = feedback.warning() {
                message.push_str(&format!(": {warning}"));
            }
            for suggestion in feedback.suggestions() {
                message.push_str(&format!("\n  {suggestion}"));
            }
        }
        message
            .push_str("\n  A passphrase of 4 or more random words is strong and easy to remember.");
        bail!(message);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::check_strength;

    #[test]
    fn rejects_short_and_guessable_passwords() {
        // zxcvbn scores these 0 to 3 (at most 10^8.2 estimated guesses).
        for weak in [
            "",
            "hunter2",
            "correct horse",
            "Summer2026!!",
            "password1234",
            "Password123!",
            "123456789012",
            "otp-password",
            "aaaaaaaaaaaaaaaa",
        ] {
            assert!(
                check_strength(weak, true).is_err(),
                "{weak:?} should be refused"
            );
        }
        let error = check_strength("short", true).unwrap_err().to_string();
        assert!(error.contains("at least 12 characters"), "{error}");
        let error = check_strength("password1234", true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("too easy to guess"), "{error}");
        assert!(error.contains("random words"), "{error}");
    }

    #[test]
    fn score_check_can_be_disabled_but_not_the_length() {
        assert!(check_strength("correct horse", false).is_ok());
        assert!(check_strength("password1234", false).is_ok());
        let error = check_strength("hunter2", false).unwrap_err().to_string();
        assert!(error.contains("at least 12 characters"), "{error}");
    }

    #[test]
    fn accepts_passphrases() {
        for strong in [
            "violet anchor rhythm quartz",
            "correct horse battery staple",
            "Tr0ub4dor&3-plus-length",
            "k7#Qm2!vX9pL",
        ] {
            assert!(
                check_strength(strong, true).is_ok(),
                "{strong:?} should be accepted"
            );
        }
    }
}
