mod complete;
mod config;
mod prompt;
mod stores;
#[cfg(feature = "tui")]
mod tui;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{ArgValueCompleter, CompleteEnv};
use otp_core::store::{Backend, PassStore};
use otp_core::{Algorithm, Entry, Kind, OtpSecret, qr, validate_name};
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::prompt::PasswordSource;
use crate::stores::Stores;

/// Store MFA secrets and generate one-time passwords.
#[derive(Parser)]
#[command(name = "otp", version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    code: CodeArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Print the current code for an entry (never lists, unlike `otp NAME`)
    #[command(alias = "get")]
    Code(CodeArgs),
    /// Add a secret from an otpauth:// URI, a QR code or a base32 secret
    Insert(InsertArgs),
    /// List entries
    #[command(alias = "ls")]
    List {
        /// Only list entries whose name starts with PREFIX
        #[arg(add = ArgValueCompleter::new(complete::entry_names))]
        prefix: Option<String>,
        /// Show which store holds each entry
        #[arg(short, long)]
        long: bool,
        #[command(flatten)]
        only: BackendArgs,
    },
    /// Show an entry's parameters
    Show {
        #[arg(add = ArgValueCompleter::new(complete::entry_names))]
        name: String,
        /// Print the otpauth:// URI instead (it contains the secret)
        #[arg(long)]
        uri: bool,
        #[command(flatten)]
        only: BackendArgs,
    },
    /// Remove an entry
    #[command(alias = "remove")]
    Rm {
        #[arg(add = ArgValueCompleter::new(complete::entry_names))]
        name: String,
        /// Do not ask for confirmation
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        only: BackendArgs,
    },
    /// Rename or move an entry, within its store
    #[command(alias = "rename")]
    Mv {
        /// Entry to move
        #[arg(add = ArgValueCompleter::new(complete::entry_names))]
        from: String,
        /// New name; ending with `/` moves the entry into that folder, keeping its name
        #[arg(add = ArgValueCompleter::new(complete::entry_folders))]
        to: String,
        /// Replace an existing entry named TO
        #[arg(short, long)]
        force: bool,
        #[command(flatten)]
        only: BackendArgs,
    },
    /// Change the master password of the native database
    Passwd,
    /// Clears the clipboard after SECONDS if it still holds the value hashed on stdin
    #[command(name = "__clear-clipboard", hide = true)]
    ClearClipboard { seconds: u64 },
    /// Browse entries interactively; Enter copies the selected code
    #[cfg(feature = "tui")]
    Tui {
        /// Start with codes and secrets hidden (Ctrl-H shows them)
        #[arg(long)]
        hidden: bool,
        #[command(flatten)]
        only: BackendArgs,
    },
}

#[derive(Args)]
struct CodeArgs {
    /// Entry to print a code for; without an exact match, list entries starting with it
    #[arg(add = ArgValueCompleter::new(complete::entry_names))]
    name: Option<String>,
    /// Copy the output to the clipboard instead of printing it
    #[arg(short, long, requires = "name")]
    clip: bool,
    /// Output the base32 secret instead of a code
    #[arg(long, requires = "name", conflicts_with = "otpauth")]
    secret: bool,
    /// Output the otpauth:// URI instead of a code
    #[arg(long, requires = "name")]
    otpauth: bool,
    /// Show the otpauth QR code instead of a code, or write it to --qrcode=FILE (a PNG)
    #[arg(
        long,
        value_name = "FILE",
        require_equals = true,
        requires = "name",
        conflicts_with_all = ["clip", "secret", "otpauth"]
    )]
    qrcode: Option<Option<PathBuf>>,
    #[command(flatten)]
    only: BackendArgs,
}

#[cfg(feature = "tui")]
impl CodeArgs {
    /// Arguments of `otp -c [--secret|--otpauth] NAME`, restricted to `backend`.
    fn copy(name: String, backend: Backend, output: tui::Output) -> Self {
        CodeArgs {
            name: Some(name),
            clip: true,
            secret: output == tui::Output::Secret,
            otpauth: output == tui::Output::Uri,
            qrcode: None,
            only: BackendArgs {
                pass: backend == Backend::Pass,
                native: backend == Backend::Native,
            },
        }
    }
}

#[derive(Args)]
struct BackendArgs {
    /// Only look in the pass store
    #[arg(long, conflicts_with = "native")]
    pass: bool,
    /// Only look in the native database
    #[arg(long)]
    native: bool,
}

impl BackendArgs {
    /// The store to restrict to: the flags, else the configured `backend`.
    fn only(&self, default: Option<Backend>) -> Option<Backend> {
        match (self.pass, self.native) {
            (true, _) => Some(Backend::Pass),
            (_, true) => Some(Backend::Native),
            _ => default,
        }
    }
}

#[derive(Args)]
struct InsertArgs {
    /// Entry name, e.g. google.com/alice@gmail.com
    #[arg(add = ArgValueCompleter::new(complete::entry_folders))]
    name: String,
    /// Store in pass(1) as NAME-otp instead of the native database
    #[arg(long, conflicts_with = "native")]
    pass: bool,
    /// Store in the native database, overriding `backend = "pass"` in the config
    #[arg(long)]
    native: bool,
    /// Read the secret from a QR code: capture a screen area, or decode --qrcode=IMAGE
    #[arg(
        short,
        long,
        value_name = "IMAGE",
        require_equals = true,
        conflicts_with = "secret"
    )]
    qrcode: Option<Option<PathBuf>>,
    /// Enter a base32 secret instead of an otpauth:// URI
    #[arg(short, long)]
    secret: bool,
    /// Number of digits
    #[arg(long, requires = "secret", default_value_t = 6)]
    digits: u32,
    /// TOTP period in seconds
    #[arg(long, requires = "secret", default_value_t = 30)]
    period: u32,
    /// HMAC algorithm
    #[arg(long, requires = "secret", value_enum, default_value_t = AlgorithmArg::Sha1)]
    algorithm: AlgorithmArg,
    /// Create an HOTP (counter-based) entry starting at this counter
    #[arg(long, requires = "secret", conflicts_with = "period")]
    counter: Option<u64>,
    /// Issuer label (defaults to the name's directory with --secret)
    #[arg(long)]
    issuer: Option<String>,
    /// Account label (defaults to the name's last component with --secret)
    #[arg(long)]
    account: Option<String>,
    /// Overwrite an existing entry
    #[arg(short, long)]
    force: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

impl From<AlgorithmArg> for Algorithm {
    fn from(arg: AlgorithmArg) -> Self {
        match arg {
            AlgorithmArg::Sha1 => Algorithm::Sha1,
            AlgorithmArg::Sha256 => Algorithm::Sha256,
            AlgorithmArg::Sha512 => Algorithm::Sha512,
        }
    }
}

fn main() -> ExitCode {
    // SAFETY: first thing in main, before any thread exists.
    unsafe { prompt::take_env_password() };
    // Answers shell completion requests (`COMPLETE=fish otp`) and exits.
    CompleteEnv::with_factory(Cli::command).complete();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("otp: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let config = Config::load()?;
    let db_path = config.database_path()?;
    let password = PasswordSource::new(config.password_command.as_deref());
    let pass = PassStore::new(config.password_store_dir.clone());
    #[cfg(feature = "tui")]
    // gpg output would corrupt the screen; errors are shown in the TUI instead.
    let pass = match cli.command {
        Some(Command::Tui { .. }) => pass.non_interactive(),
        _ => pass,
    };
    let mut stores = Stores::new(db_path, password, pass);
    let default = config.backend();

    match cli.command {
        Some(Command::Code(args)) => code(&mut stores, &config, args),
        None => code_or_list(&mut stores, &config, cli.code),
        Some(Command::Insert(args)) => insert(&mut stores, &config, args),
        Some(Command::List { prefix, long, only }) => {
            let prefix = prefix.as_deref().unwrap_or("");
            list(&mut stores, prefix, long, only.only(default)).map(|_| ())
        }
        Some(Command::Show { name, uri, only }) => {
            show(&mut stores, &name, uri, only.only(default))
        }
        Some(Command::Rm { name, force, only }) => {
            remove(&mut stores, &name, force, only.only(default))
        }
        Some(Command::Mv {
            from,
            to,
            force,
            only,
        }) => move_entry(&mut stores, &from, &to, force, only.only(default)),
        Some(Command::Passwd) => passwd(&mut stores),
        Some(Command::ClearClipboard { seconds }) => clear_clipboard_later(&config, seconds),
        #[cfg(feature = "tui")]
        Some(Command::Tui { hidden, only }) => {
            let hidden = hidden || config.tui.hidden;
            match tui::run(&mut stores, only.only(default), &config, hidden)? {
                // Copying goes through `otp -c` so HOTP counters are persisted the same way.
                Some((name, backend, output)) => {
                    code(&mut stores, &config, CodeArgs::copy(name, backend, output))
                }
                None => Ok(()),
            }
        }
    }
}

/// `otp [NAME]`: like pass(1), print the code of an exact entry, otherwise list the
/// entries starting with NAME.
fn code_or_list(stores: &mut Stores, config: &Config, args: CodeArgs) -> Result<()> {
    let only = args.only.only(config.backend());
    let Some(name) = &args.name else {
        list(stores, "", false, only)?;
        return Ok(());
    };
    if validate_name(name).is_ok() && stores.find(name, only)?.is_some() {
        return code(stores, config, args);
    }
    let exporting = args.clip || args.secret || args.otpauth || args.qrcode.is_some();
    if exporting || list(stores, name, false, only)? == 0 {
        // Report the lookup failure.
        stores.locate(name, only)?;
    }
    Ok(())
}

fn code(stores: &mut Stores, config: &Config, args: CodeArgs) -> Result<()> {
    let name = args.name.context("missing entry name")?;
    validate_name(&name)?;
    let backend = stores.locate(&name, args.only.only(config.backend()))?;
    let store = stores.get(backend)?.expect("located store exists");
    let entry = store.get(&name)?.context("entry disappeared")?;
    // Exporting the secret, URI or QR code leaves an HOTP counter untouched.
    if let Some(file) = &args.qrcode {
        let uri = Zeroizing::new(entry.otp.to_uri());
        return show_qrcode(config, &uri, file.as_deref());
    }
    let (output, what) = if args.secret {
        (Zeroizing::new(entry.otp.secret_base32()), "secret")
    } else if args.otpauth {
        (Zeroizing::new(entry.otp.to_uri()), "otpauth URI")
    } else if let Kind::Hotp { .. } = entry.otp.kind {
        // Generate from the counter as stored now, not from the copy read earlier (a TUI
        // may have read it long ago), and save the advanced counter in the same step.
        let mut code = None;
        store.update(&name, &mut |entry| {
            code = Some(entry.otp.generate(SystemTime::now()));
            entry.touch();
        })?;
        (Zeroizing::new(code.expect("update ran").value), "code")
    } else {
        let mut otp = entry.otp.clone();
        (
            Zeroizing::new(otp.generate(SystemTime::now()).value),
            "code",
        )
    };
    if args.clip {
        copy_to_clipboard(config, &output)?;
        match config.clipboard_timeout {
            0 => eprintln!("Copied the {what} for {name} to the clipboard."),
            seconds => eprintln!(
                "Copied the {what} for {name} to the clipboard; it will be cleared in \
                 {seconds} seconds."
            ),
        }
    } else {
        println!("{}", output.as_str());
    }
    Ok(())
}

fn insert(stores: &mut Stores, config: &Config, args: InsertArgs) -> Result<()> {
    let name = &args.name;
    validate_name(name)?;
    let target = match (args.pass, args.native) {
        (true, _) => Backend::Pass,
        (_, true) => Backend::Native,
        _ => config.backend().unwrap_or(Backend::Native),
    };
    // Check for conflicts before asking for the secret.
    check_available(stores, target, name, args.force)?;

    let mut otp = read_otp(config, &args)?;
    if args.issuer.is_some() {
        otp.issuer = args.issuer.clone();
    }
    if args.account.is_some() {
        otp.account = args.account.clone();
    }
    // The --issuer/--account overrides go through the same checks as URI labels.
    otp.validate()?;
    let store = stores.get_or_create(target)?;
    let entry = Entry::new(otp);
    // Without --force, fail if another process added the name while we were prompting.
    if args.force {
        store.put(name, &entry)?;
    } else {
        store.insert(name, &entry)?;
    }
    eprintln!("Inserted {name} into the {target} store.");
    Ok(())
}

/// Checks that `name` can be written to `backend`: names are unique across stores, and
/// an existing entry in `backend` is only replaced with `force`.
fn check_available(stores: &mut Stores, backend: Backend, name: &str, force: bool) -> Result<()> {
    let other = match backend {
        Backend::Pass => Backend::Native,
        Backend::Native => Backend::Pass,
    };
    if stores.contains(other, name)? {
        bail!("{name} already exists in the {other} store; remove it first");
    }
    if stores.contains(backend, name)? && !force {
        bail!("{name} already exists; use --force to overwrite it");
    }
    Ok(())
}

fn read_otp(config: &Config, args: &InsertArgs) -> Result<OtpSecret> {
    if let Some(image) = &args.qrcode {
        let contents = match image {
            Some(path) => qr::decode_file(path)?,
            None => {
                eprintln!("Select the QR code on screen...");
                qr::capture(&config.capture_command)?
            }
        };
        let uri = qr::find_otpauth_uri(contents)?;
        return Ok(OtpSecret::from_uri(&uri)?);
    }
    if !args.secret {
        let uri = prompt::secret("otpauth URI: ")?;
        return Ok(OtpSecret::from_uri(&uri)?);
    }

    let secret = prompt::secret("Secret (base32): ")?;
    let kind = match args.counter {
        Some(counter) => Kind::Hotp { counter },
        None => Kind::Totp {
            period: args.period,
        },
    };
    let mut otp = OtpSecret::from_base32(&secret, kind)?;
    otp.algorithm = args.algorithm.into();
    otp.digits = args.digits;
    label_from_name(&mut otp, &args.name);
    otp.validate()?;
    Ok(otp)
}

/// Labels a secret entered without an otpauth URI after its entry name: the folder is
/// the issuer, the last component the account (`google.com/alice` → issuer google.com, account alice).
fn label_from_name(otp: &mut OtpSecret, name: &str) {
    match name.rsplit_once('/') {
        Some((issuer, account)) => {
            otp.issuer = Some(issuer.to_string());
            otp.account = Some(account.to_string());
        }
        None => otp.account = Some(name.to_string()),
    }
}

/// Prints the entries starting with `prefix` and returns how many rows were printed.
fn list(stores: &mut Stores, prefix: &str, long: bool, only: Option<Backend>) -> Result<usize> {
    let rows = stores.list(only)?;
    let mut out = std::io::stdout().lock();
    let mut previous = None;
    let mut printed = 0;
    for (name, backend) in rows.iter().filter(|(name, _)| name.starts_with(prefix)) {
        if long {
            writeln!(out, "{backend:<6}  {name}")?;
            printed += 1;
        } else if previous != Some(name) {
            writeln!(out, "{name}")?;
            printed += 1;
        }
        previous = Some(name);
    }
    Ok(printed)
}

fn show(stores: &mut Stores, name: &str, uri: bool, only: Option<Backend>) -> Result<()> {
    validate_name(name)?;
    let backend = stores.locate(name, only)?;
    let store = stores.get(backend)?.expect("located store exists");
    let entry = store.get(name)?.context("entry disappeared")?;
    let otp = &entry.otp;
    if uri {
        println!("{}", otp.to_uri());
        return Ok(());
    }
    println!("name:      {name}");
    println!("store:     {backend}");
    println!("type:      {}", describe_kind(otp.kind));
    // Labels are validated when entries are created, but entries saved by older versions
    // may still contain control characters: never print them raw.
    println!(
        "issuer:    {}",
        printable(otp.issuer.as_deref().unwrap_or("-"))
    );
    println!(
        "account:   {}",
        printable(otp.account.as_deref().unwrap_or("-"))
    );
    println!("algorithm: {}", otp.algorithm);
    println!("digits:    {}", otp.digits);
    println!("created:   {}", timestamp(entry.meta.created_at));
    println!("updated:   {}", timestamp(entry.meta.updated_at));
    Ok(())
}

/// `text` with the characters that could act on the terminal escaped as `\u{..}`.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if otp_core::is_unsafe_char(c) {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn describe_kind(kind: Kind) -> String {
    match kind {
        Kind::Totp { period } => format!("TOTP, {period}s period"),
        Kind::Hotp { counter } => format!("HOTP, next counter {counter}"),
    }
}

fn timestamp(t: Option<time::OffsetDateTime>) -> String {
    t.and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| "-".into())
}

fn remove(stores: &mut Stores, name: &str, force: bool, only: Option<Backend>) -> Result<()> {
    validate_name(name)?;
    let backend = stores.locate(name, only)?;
    if !force && !prompt::confirm(&format!("Remove {name} from the {backend} store?"))? {
        bail!("aborted");
    }
    let store = stores.get(backend)?.expect("located store exists");
    store.remove(name)?;
    eprintln!("Removed {name} from the {backend} store.");
    Ok(())
}

/// `otp mv FROM TO`: renames an entry within its store.
fn move_entry(
    stores: &mut Stores,
    from: &str,
    to: &str,
    force: bool,
    only: Option<Backend>,
) -> Result<()> {
    if from.ends_with('/') {
        bail!("{from} is a folder; move its entries one at a time");
    }
    validate_name(from)?;
    // Like mv(1): a trailing slash moves the entry into that folder.
    let to = match to.strip_suffix('/') {
        Some(folder) => format!("{folder}/{}", from.rsplit('/').next().unwrap_or(from)),
        None => to.to_string(),
    };
    validate_name(&to)?;
    if from == to {
        bail!("{from} is already named {to}");
    }
    let backend = stores.locate(from, only)?;
    check_available(stores, backend, &to, force)?;
    let store = stores.get(backend)?.expect("located store exists");
    store.rename(from, &to, force)?;
    eprintln!("Moved {from} to {to} in the {backend} store.");
    Ok(())
}

fn passwd(stores: &mut Stores) -> Result<()> {
    let store = stores.native_for_passwd()?;
    let password = PasswordSource::Prompt.new_password("New master password")?;
    store.change_password(password.as_bytes())?;
    eprintln!("Master password changed.");
    Ok(())
}

/// Writes the QR code of `uri` to `file`, or shows it: with `qrcode_viewer_command` when
/// configured, otherwise drawn in the terminal.
fn show_qrcode(config: &Config, uri: &str, file: Option<&Path>) -> Result<()> {
    if let Some(path) = file {
        qr::write_png(uri, path).with_context(|| format!("writing {}", path.display()))?;
        eprintln!(
            "Wrote the QR code to {}; it contains the secret.",
            path.display()
        );
        return Ok(());
    }
    if let Some(viewer) = &config.qrcode_viewer_command {
        return Ok(qr::view(viewer, uri)?);
    }
    let lines = qr::QrMatrix::encode_compact(uri)?.half_block_lines(2);
    // Force dark modules on a light background whatever the terminal's colors: palette
    // entries 16 (black) and 231 (white) are not affected by themes.
    let (start, end) = if std::io::stdout().is_terminal() {
        ("\x1b[38;5;16;48;5;231m", "\x1b[0m")
    } else {
        ("", "")
    };
    let mut out = std::io::stdout().lock();
    for line in lines {
        writeln!(out, "{start}{line}{end}")?;
    }
    Ok(())
}

/// Copies `text` with `clipboard_command`, then schedules clearing it after
/// `clipboard_timeout` seconds.
fn copy_to_clipboard(config: &Config, text: &str) -> Result<()> {
    let (program, args) = config
        .clipboard_command
        .split_first()
        .context("clipboard_command is empty")?;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("running clipboard command {program:?}"))?;
    let written = child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(text.as_bytes());
    // A tool that exits before reading is better explained by its exit status.
    match written {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => return Err(e.into()),
        _ => {}
    }
    let status = child.wait()?;
    if !status.success() {
        bail!("clipboard command {program:?} failed ({status})");
    }
    if config.clipboard_timeout > 0 {
        schedule_clipboard_clear(config.clipboard_timeout, text)
            .context("scheduling the clipboard clearing")?;
    }
    Ok(())
}

/// Starts `otp __clear-clipboard SECONDS` in the background. It outlives this process,
/// and receives only a hash of the copied value, on stdin.
fn schedule_clipboard_clear(seconds: u64, text: &str) -> Result<()> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["__clear-clipboard", &seconds.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Its own process group, so closing the terminal does not stop it.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(digest(text.as_bytes()).as_bytes())?;
    Ok(())
}

/// `otp __clear-clipboard SECONDS`: waits, then clears the clipboard if it still holds
/// the value whose hash is read from stdin, so that a newer copy is left alone.
fn clear_clipboard_later(config: &Config, seconds: u64) -> Result<()> {
    let mut expected = String::new();
    std::io::stdin().read_to_string(&mut expected)?;
    std::thread::sleep(std::time::Duration::from_secs(seconds));
    if let Some((program, args)) = config.clipboard_paste_command.split_first() {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        let current = Zeroizing::new(output.stdout);
        if !output.status.success() || digest(&current) != expected.trim() {
            return Ok(());
        }
    }
    let (program, args) = config
        .clipboard_clear_command
        .split_first()
        .context("clipboard_clear_command is empty")?;
    std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .status()?;
    Ok(())
}

/// Hex SHA-256 of `data`.
fn digest(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::printable;

    #[test]
    fn printable_escapes_terminal_sequences() {
        assert_eq!(printable("Société 日🔑"), "Société 日🔑");
        assert_eq!(printable("\u{1b}[2J"), "\\u{1b}[2J");
        assert_eq!(printable("\u{1b}]0;PWNED\u{7}"), "\\u{1b}]0;PWNED\\u{7}");
        assert_eq!(printable("\u{202e}moc"), "\\u{202e}moc");
    }
}
