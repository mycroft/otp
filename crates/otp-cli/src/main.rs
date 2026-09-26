mod complete;
mod config;
mod prompt;
mod stores;
#[cfg(feature = "tui")]
mod tui;

use std::io::{IsTerminal, Write};
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
    /// Change the master password of the native database
    Passwd,
    /// Browse entries interactively; Enter copies the selected code
    #[cfg(feature = "tui")]
    Tui {
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
        Some(Command::Passwd) => passwd(&mut stores),
        #[cfg(feature = "tui")]
        Some(Command::Tui { only }) => {
            match tui::run(&mut stores, only.only(default), &config.tui)? {
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
    let mut entry = store.get(&name)?.context("entry disappeared")?;
    // Exporting the secret, URI or QR code leaves an HOTP counter untouched.
    if let Some(file) = &args.qrcode {
        let uri = Zeroizing::new(entry.otp.to_uri());
        return show_qrcode(config, &uri, file.as_deref());
    }
    let (output, what) = if args.secret {
        (Zeroizing::new(entry.otp.secret_base32()), "secret")
    } else if args.otpauth {
        (Zeroizing::new(entry.otp.to_uri()), "otpauth URI")
    } else {
        let code = entry.otp.generate(SystemTime::now());
        if let Kind::Hotp { .. } = entry.otp.kind {
            // The counter moved forward; persist it before showing the code.
            entry.touch();
            store.put(&name, &entry)?;
        }
        (Zeroizing::new(code.value), "code")
    };
    if args.clip {
        copy_to_clipboard(&config.clipboard_command, &output)?;
        eprintln!("Copied the {what} for {name} to the clipboard.");
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
    let other = match target {
        Backend::Pass => Backend::Native,
        Backend::Native => Backend::Pass,
    };
    // Check for conflicts before asking for the secret.
    if stores.contains(other, name)? {
        bail!("{name} already exists in the {other} store; remove it first");
    }
    if stores.contains(target, name)? && !args.force {
        bail!("{name} already exists; use --force to overwrite it");
    }

    let mut otp = read_otp(config, &args)?;
    if args.issuer.is_some() {
        otp.issuer = args.issuer.clone();
    }
    if args.account.is_some() {
        otp.account = args.account.clone();
    }
    stores.get_or_create(target)?.put(name, &Entry::new(otp))?;
    eprintln!("Inserted {name} into the {target} store.");
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
    match args.name.rsplit_once('/') {
        Some((issuer, account)) => {
            otp.issuer = Some(issuer.to_string());
            otp.account = Some(account.to_string());
        }
        None => otp.account = Some(args.name.clone()),
    }
    otp.validate()?;
    Ok(otp)
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
    println!("issuer:    {}", otp.issuer.as_deref().unwrap_or("-"));
    println!("account:   {}", otp.account.as_deref().unwrap_or("-"));
    println!("algorithm: {}", otp.algorithm);
    println!("digits:    {}", otp.digits);
    println!("created:   {}", timestamp(entry.meta.created_at));
    println!("updated:   {}", timestamp(entry.meta.updated_at));
    Ok(())
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

fn copy_to_clipboard(command: &[String], text: &str) -> Result<()> {
    let (program, args) = command
        .split_first()
        .context("clipboard_command is empty")?;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("running clipboard command {program:?}"))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(text.as_bytes())?;
    let status = child.wait()?;
    if !status.success() {
        bail!("clipboard command {program:?} failed ({status})");
    }
    Ok(())
}
