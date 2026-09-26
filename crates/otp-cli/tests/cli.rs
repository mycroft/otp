//! End-to-end tests of the `otp` binary, isolated from the user's real stores.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

// RFC 4226 test secret "12345678901234567890".
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const HOTP_URI: &str =
    "otpauth://hotp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0";

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Env {
            dir: tempfile::tempdir().unwrap(),
        };
        fs::create_dir_all(env.pass_dir()).unwrap();
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn pass_dir(&self) -> PathBuf {
        self.path("password-store")
    }

    fn write_config(&self, toml: &str) {
        fs::write(self.path("config.toml"), toml).unwrap();
    }

    /// Installs a plaintext stand-in for pass(1) that stores entries as
    /// `$PASSWORD_STORE_DIR/NAME.gpg`, so the pass backend works without gpg.
    fn with_fake_pass(self) -> Self {
        let bin = self.path("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = bin.join("pass");
        fs::write(
            &script,
            r#"#!/bin/sh
for name; do :; done
file="$PASSWORD_STORE_DIR/$name.gpg"
case "$1" in
    insert) mkdir -p "$(dirname "$file")" && cat > "$file" ;;
    show) cat "$file" ;;
    rm) rm "$file" ;;
    mv)
        # mv --force -- FROM TO
        from="$PASSWORD_STORE_DIR/$4.gpg"
        mkdir -p "$(dirname "$file")" && mv "$from" "$file" ;;
    *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        self
    }

    fn otp(&self) -> Command {
        Command::from_std(self.std_otp())
    }

    /// `otp` as a plain process, for tests that interleave several of them.
    fn std_otp(&self) -> std::process::Command {
        let mut path = std::ffi::OsString::from(self.path("bin"));
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap());
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("otp"));
        cmd.env_clear()
            .env("PATH", path)
            .env("HOME", self.dir.path())
            .env("OTP_CONFIG", self.path("config.toml"))
            .env("OTP_DB", self.path("data/otp.db"))
            .env("OTP_PASSWORD", "correct horse")
            .env("PASSWORD_STORE_DIR", self.pass_dir());
        cmd
    }

    fn insert_uri(&self, name: &str, uri: &str) {
        self.otp()
            .args(["insert", name])
            .write_stdin(format!("{uri}\n"))
            .assert()
            .success()
            .stderr(predicate::str::contains(format!(
                "Inserted {name} into the native store"
            )));
    }
}

fn write_qr_png(path: &Path, text: &str) {
    let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
    let width = code.width();
    let colors = code.to_colors();
    let (scale, border) = (6, 4);
    let size = ((width + 2 * border) * scale) as u32;
    let image = image::GrayImage::from_fn(size, size, |x, y| {
        let (mx, my) = (x as usize / scale, y as usize / scale);
        let dark = (border..border + width).contains(&mx)
            && (border..border + width).contains(&my)
            && colors[(my - border) * width + (mx - border)] == qrcode::Color::Dark;
        image::Luma([if dark { 0 } else { 255 }])
    });
    image.save(path).unwrap();
}

#[test]
fn hotp_codes_advance_and_persist() {
    let env = Env::new();
    env.insert_uri("example.com/alice", HOTP_URI);
    assert!(env.path("data/otp.db").is_file());

    env.otp()
        .arg("example.com/alice")
        .assert()
        .success()
        .stdout("755224\n");
    env.otp()
        .args(["code", "example.com/alice"])
        .assert()
        .success()
        .stdout("287082\n");
    env.otp()
        .args(["show", "--uri", "example.com/alice"])
        .assert()
        .success()
        .stdout(predicate::str::contains("counter=2"));
}

#[test]
fn insert_base32_secret_with_parameters() {
    let env = Env::new();
    env.otp()
        .args([
            "insert",
            "--secret",
            "--digits",
            "8",
            "--algorithm",
            "sha256",
        ])
        .arg("google.com/codingmyc@gmail.com")
        .write_stdin(format!("{}\n", SECRET.to_lowercase()))
        .assert()
        .success();

    env.otp()
        .arg("google.com/codingmyc@gmail.com")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{8}\n$").unwrap());
    env.otp()
        .args(["show", "google.com/codingmyc@gmail.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("store:     native"))
        .stdout(predicate::str::contains("type:      TOTP, 30s period"))
        .stdout(predicate::str::contains("issuer:    google.com"))
        .stdout(predicate::str::contains("account:   codingmyc@gmail.com"))
        .stdout(predicate::str::contains("algorithm: SHA256"))
        .stdout(predicate::str::contains("digits:    8"));
}

#[test]
fn insert_from_qr_image_and_screenshot() {
    let env = Env::new();
    let png = env.path("qr.png");
    write_qr_png(&png, HOTP_URI);

    env.otp()
        .args([
            "insert",
            "from-image",
            &format!("--qrcode={}", png.display()),
        ])
        .assert()
        .success();
    env.otp()
        .arg("from-image")
        .assert()
        .success()
        .stdout("755224\n");

    // Screenshot capture goes through capture_command; `cp` stands in for grimshot.
    env.write_config(&format!(
        "capture_command = [\"cp\", \"{}\", \"{{file}}\"]\n",
        png.display()
    ));
    env.otp()
        .args(["insert", "--qrcode", "from-screen"])
        .assert()
        .success();
    env.otp()
        .arg("from-screen")
        .assert()
        .success()
        .stdout("755224\n");
}

#[test]
fn qr_errors_are_reported() {
    let env = Env::new();
    let png = env.path("not-otp.png");
    write_qr_png(&png, "https://example.com");
    env.otp()
        .args(["insert", "x", &format!("--qrcode={}", png.display())])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not contain an otpauth:// URI",
        ));

    env.write_config("capture_command = [\"false\"]\n");
    env.otp()
        .args(["insert", "x", "--qrcode"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("screenshot capture failed"));
    assert!(
        !env.path("data/otp.db").exists(),
        "nothing should have been written"
    );
}

#[test]
fn duplicates_need_force() {
    let env = Env::new();
    env.insert_uri("dup", HOTP_URI);
    env.otp()
        .args(["insert", "dup"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists; use --force"));
    env.otp()
        .args(["insert", "--force", "dup"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .success();
}

#[test]
fn names_must_be_unique_across_stores() {
    let env = Env::new();
    env.insert_uri("shared", HOTP_URI);
    env.otp()
        .args(["insert", "--pass", "shared"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "already exists in the native store",
        ));

    // An entry already in pass blocks a native insert (checked without decrypting).
    fs::write(env.pass_dir().join("in-pass-otp.gpg"), b"").unwrap();
    env.otp()
        .args(["insert", "in-pass"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists in the pass store"));
}

#[test]
fn list_merges_both_stores() {
    let env = Env::new();
    env.otp().arg("list").assert().success().stdout("");
    env.insert_uri("b/native", HOTP_URI);
    env.insert_uri("a", HOTP_URI);
    fs::create_dir_all(env.pass_dir().join("c")).unwrap();
    fs::write(env.pass_dir().join("c/in-pass-otp.gpg"), b"").unwrap();
    fs::write(env.pass_dir().join("c/password.gpg"), b"").unwrap();

    env.otp()
        .arg("ls")
        .assert()
        .success()
        .stdout("a\nb/native\nc/in-pass\n");
    env.otp()
        .args(["list", "--long"])
        .assert()
        .success()
        .stdout("native  a\nnative  b/native\npass    c/in-pass\n");
}

#[test]
fn remove_entry() {
    let env = Env::new();
    env.insert_uri("gone", HOTP_URI);
    env.otp()
        .args(["rm", "gone"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    env.otp().args(["rm", "-f", "gone"]).assert().success();
    env.otp()
        .arg("gone")
        .assert()
        .failure()
        .stderr(predicate::str::contains("gone is not in the store"));
}

#[test]
fn wrong_password_fails() {
    let env = Env::new();
    env.insert_uri("x", HOTP_URI);
    env.otp()
        .env("OTP_PASSWORD", "wrong")
        .arg("x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong master password"));
}

#[test]
fn password_command_is_used() {
    let env = Env::new();
    env.write_config("password_command = [\"echo\", \"from command\"]\n");
    let insert = |password: Option<&str>| {
        let mut cmd = env.otp();
        cmd.env_remove("OTP_PASSWORD");
        if let Some(password) = password {
            cmd.env("OTP_PASSWORD", password);
        }
        cmd
    };
    insert(None)
        .args(["insert", "x"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .success();
    insert(None).arg("x").assert().success().stdout("755224\n");
    insert(Some("from command"))
        .arg("x")
        .assert()
        .success()
        .stdout("287082\n");
}

#[test]
fn clipboard_command_receives_code() {
    let env = Env::new();
    let clip = env.path("clipboard");
    env.write_config(&format!(
        "clipboard_command = [\"sh\", \"-c\", \"cat > '{}'\"]\nclipboard_timeout = 0\n",
        clip.display()
    ));
    env.insert_uri("x", HOTP_URI);
    env.otp()
        .args(["--clip", "x"])
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains("Copied the code for x"));
    assert_eq!(fs::read_to_string(clip).unwrap(), "755224");
}

#[test]
fn rejects_bad_input() {
    let env = Env::new();
    env.otp()
        .args(["insert", "../escape"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid entry name"));
    env.otp()
        .args(["insert", "x"])
        .write_stdin("https://example.com\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid otpauth URI"));
    env.otp()
        .args(["insert", "x", "--digits", "8"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--secret"));
    env.write_config("unknown_key = 1\n");
    env.otp()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("config.toml"));
}

#[test]
fn backend_pass_config_acts_as_pass_flag() {
    let env = Env::new().with_fake_pass();
    env.write_config("backend = \"pass\"\n");

    env.otp()
        .args(["insert", "google.com/alice"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("into the pass store"));
    let stored = fs::read_to_string(env.pass_dir().join("google.com/alice-otp.gpg")).unwrap();
    assert!(stored.starts_with("otpauth://hotp/"), "got {stored:?}");
    env.otp()
        .arg("google.com/alice")
        .assert()
        .success()
        .stdout("755224\n");
    env.otp()
        .arg("google.com/alice")
        .assert()
        .success()
        .stdout("287082\n");
    env.otp()
        .args(["show", "google.com/alice"])
        .assert()
        .success()
        .stdout(predicate::str::contains("store:     pass"));
    assert!(
        !env.path("data/otp.db").exists(),
        "pass-only usage must not create the database"
    );

    // --native overrides the configured backend, for every command.
    env.otp()
        .args(["insert", "--native", "local"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("into the native store"));
    env.otp()
        .arg("list")
        .assert()
        .success()
        .stdout("google.com/alice\n");
    env.otp()
        .args(["list", "--native"])
        .assert()
        .success()
        .stdout("local\n");
    env.otp()
        .arg("local")
        .assert()
        .failure()
        .stderr(predicate::str::contains("local is not in the pass store"));
    env.otp()
        .args(["--native", "local"])
        .assert()
        .success()
        .stdout("755224\n");
    env.otp().args(["rm", "-f", "local"]).assert().failure();
    env.otp()
        .args(["rm", "-f", "--native", "local"])
        .assert()
        .success();

    env.otp()
        .args(["rm", "-f", "google.com/alice"])
        .assert()
        .success();
    env.otp().arg("list").assert().success().stdout("");
}

#[test]
fn backend_database_config_acts_as_native_flag() {
    let env = Env::new().with_fake_pass();
    env.write_config("backend = \"database\"\n");
    fs::write(
        env.pass_dir().join("in-pass-otp.gpg"),
        format!("{HOTP_URI}\n"),
    )
    .unwrap();
    env.insert_uri("local", HOTP_URI);

    env.otp().arg("list").assert().success().stdout("local\n");
    env.otp()
        .arg("in-pass")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "in-pass is not in the native store",
        ));
    env.otp()
        .args(["--pass", "in-pass"])
        .assert()
        .success()
        .stdout("755224\n");
    env.otp()
        .args(["insert", "--pass", "--native", "x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn backend_config_is_validated() {
    let env = Env::new();
    env.write_config("backend = \"native\"\n");
    env.otp()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("config.toml"))
        .stderr(predicate::str::contains("pass"))
        .stderr(predicate::str::contains("database"));
}

#[test]
fn export_secret_and_otpauth_uri() {
    let env = Env::new();
    env.insert_uri("google/login@domain.tld", HOTP_URI);

    env.otp()
        .args(["--secret", "google/login@domain.tld"])
        .assert()
        .success()
        .stdout(format!("{SECRET}\n"));
    env.otp()
        .args(["--otpauth", "google/login@domain.tld"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "otpauth://hotp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        ))
        .stdout(predicate::str::contains("&counter=0\n"));
    env.otp()
        .args(["code", "--secret", "google/login@domain.tld"])
        .assert()
        .success()
        .stdout(format!("{SECRET}\n"));

    // Exports do not consume the HOTP counter.
    env.otp()
        .arg("google/login@domain.tld")
        .assert()
        .success()
        .stdout("755224\n");

    env.otp()
        .args(["--secret", "--otpauth", "google/login@domain.tld"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn clip_copies_exported_secret() {
    let env = Env::new();
    let clip = env.path("clipboard");
    env.write_config(&format!(
        "clipboard_command = [\"sh\", \"-c\", \"cat > '{}'\"]\nclipboard_timeout = 0\n",
        clip.display()
    ));
    env.insert_uri("x", HOTP_URI);
    env.otp()
        .args(["-c", "--secret", "x"])
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains("Copied the secret for x"));
    assert_eq!(fs::read_to_string(clip).unwrap(), SECRET);
}

#[test]
fn list_filters_by_prefix() {
    let env = Env::new();
    for name in [
        "google/work",
        "google.com/alice",
        "github",
        "blah/x",
        "other",
    ] {
        env.insert_uri(name, HOTP_URI);
    }
    fs::write(env.pass_dir().join("goo-in-pass-otp.gpg"), b"").unwrap();

    env.otp()
        .args(["list", "goo"])
        .assert()
        .success()
        .stdout("goo-in-pass\ngoogle.com/alice\ngoogle/work\n");
    env.otp()
        .args(["ls", "--long", "google/"])
        .assert()
        .success()
        .stdout("native  google/work\n");
    env.otp()
        .args(["list", "--pass", "goo"])
        .assert()
        .success()
        .stdout("goo-in-pass\n");
    env.otp()
        .args(["list", "nothing"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn bare_otp_lists_or_prints_code() {
    let env = Env::new();
    for name in ["google.com", "google.com/alice", "google.com/bob", "github"] {
        env.insert_uri(name, HOTP_URI);
    }

    env.otp()
        .assert()
        .success()
        .stdout("github\ngoogle.com\ngoogle.com/alice\ngoogle.com/bob\n");
    // An exact entry prints its code, even when other entries share the prefix.
    env.otp()
        .arg("google.com")
        .assert()
        .success()
        .stdout("755224\n");
    env.otp()
        .arg("google.com/")
        .assert()
        .success()
        .stdout("google.com/alice\ngoogle.com/bob\n");
    env.otp()
        .arg("g")
        .assert()
        .success()
        .stdout("github\ngoogle.com\ngoogle.com/alice\ngoogle.com/bob\n");
    env.otp()
        .arg("nothing")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing is not in the store"));

    // Exporting never falls back to listing.
    env.otp()
        .args(["--secret", "google.com/a"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("google.com/a is not in the store"));
    env.otp()
        .arg("--clip")
        .assert()
        .failure()
        .stderr(predicate::str::contains("<NAME>"));
}

#[test]
fn bare_otp_respects_backend_selection() {
    let env = Env::new();
    env.insert_uri("native-entry", HOTP_URI);
    fs::write(env.pass_dir().join("pass-entry-otp.gpg"), b"").unwrap();
    env.otp()
        .assert()
        .success()
        .stdout("native-entry\npass-entry\n");
    env.otp()
        .arg("--pass")
        .assert()
        .success()
        .stdout("pass-entry\n");
    env.write_config("backend = \"database\"\n");
    env.otp().assert().success().stdout("native-entry\n");
}

#[test]
fn help_is_concise() {
    let env = Env::new();
    let short = env
        .otp()
        .arg("-h")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    env.otp().arg("--help").assert().success().stdout(short);
}

fn complete(env: &Env, words: &[&str]) -> String {
    let output = env
        .otp()
        .env("COMPLETE", "fish")
        .arg("--")
        .arg("otp")
        .args(words)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).unwrap()
}

#[test]
fn completes_entry_names_from_both_stores() {
    let env = Env::new();
    env.insert_uri("google.com/bob", HOTP_URI);
    env.insert_uri("other", HOTP_URI);
    fs::create_dir_all(env.pass_dir().join("google.com")).unwrap();
    fs::write(env.pass_dir().join("google.com/alice-otp.gpg"), b"").unwrap();

    let expected = "google.com/\ngoogle.com/alice\tpass\ngoogle.com/bob\tnative\n";
    assert_eq!(complete(&env, &["goo"]), expected);
    assert_eq!(complete(&env, &["show", "goo"]), expected);
    assert_eq!(complete(&env, &["rm", "-f", "goo"]), expected);
    assert_eq!(complete(&env, &["list", "goo"]), expected);
    assert_eq!(complete(&env, &["--secret", "goo"]), expected);
    assert!(complete(&env, &["ins"]).starts_with("insert\t"));
    assert!(complete(&env, &["--ot"]).starts_with("--otpauth\t"));
}

#[test]
fn completion_never_prompts_for_the_master_password() {
    let env = Env::new();
    env.insert_uri("google.com/bob", HOTP_URI);
    fs::write(env.pass_dir().join("google.com-otp.gpg"), b"").unwrap();

    // No non-interactive password source: native names are skipped.
    let output = env
        .otp()
        .env_remove("OTP_PASSWORD")
        .env("COMPLETE", "fish")
        .args(["--", "otp", "goo"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(output).unwrap(), "google.com\tpass\n");

    // backend = "pass" never opens the database.
    env.write_config("backend = \"pass\"\n");
    assert_eq!(complete(&env, &["goo"]), "google.com\tpass\n");
}

#[test]
fn qrcode_export_round_trips() {
    let env = Env::new();
    env.insert_uri("google/login@domain.tld", HOTP_URI);
    let uri = || {
        let output = env
            .otp()
            .args(["--otpauth", "google/login@domain.tld"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(output).unwrap()
    };
    let original = uri();

    let png = env.path("qr.png");
    env.otp()
        .arg(format!("--qrcode={}", png.display()))
        .arg("google/login@domain.tld")
        .assert()
        .success()
        .stderr(predicate::str::contains("it contains the secret"));
    // Re-importing the PNG gives back the same entry.
    env.otp()
        .args(["insert", "copy", &format!("--qrcode={}", png.display())])
        .assert()
        .success();
    env.otp()
        .args(["--otpauth", "copy"])
        .assert()
        .success()
        .stdout(original.clone());
    // Existing files are not overwritten.
    env.otp()
        .arg(format!("--qrcode={}", png.display()))
        .arg("google/login@domain.tld")
        .assert()
        .failure()
        .stderr(predicate::str::contains("exists"));

    // Exporting does not consume the HOTP counter.
    assert_eq!(uri(), original);
    env.otp()
        .arg("google/login@domain.tld")
        .assert()
        .success()
        .stdout("755224\n");
}

#[test]
fn qrcode_is_drawn_or_shown_with_the_viewer() {
    let env = Env::new();
    env.insert_uri("x", HOTP_URI);
    let output = env
        .otp()
        .args(["--qrcode", "x"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let drawn = String::from_utf8(output).unwrap();
    let lines: Vec<&str> = drawn.lines().collect();
    assert!(lines.len() > 10, "{drawn}");
    assert!(drawn.contains('█') && drawn.contains('▀'), "{drawn}");
    assert!(!drawn.contains('\x1b'), "no colors when piped");
    let width = lines[0].chars().count();
    assert!(lines.iter().all(|l| l.chars().count() == width), "{drawn}");

    // With a viewer, it gets a PNG instead; `cp` stands in for chafa.
    let seen = env.path("seen.png");
    env.write_config(&format!(
        "qrcode_viewer_command = [\"cp\", \"{{file}}\", \"{}\"]\n",
        seen.display()
    ));
    env.otp()
        .args(["--qrcode", "x"])
        .assert()
        .success()
        .stdout("");
    env.otp()
        .args(["insert", "seen", &format!("--qrcode={}", seen.display())])
        .assert()
        .success();

    env.write_config("qrcode_viewer_command = [\"false\"]\n");
    env.otp()
        .args(["--qrcode", "x"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("QR code viewer: false failed"));
}

#[test]
fn qrcode_needs_an_exact_entry() {
    let env = Env::new();
    env.insert_uri("google/a", HOTP_URI);
    env.otp()
        .args(["--qrcode", "goo"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("goo is not in the store"));
    env.otp()
        .args(["--qrcode", "--clip", "google/a"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn tui_section_is_accepted_and_validated() {
    // Valid in every build, with or without the `tui` feature.
    let env = Env::new();
    env.write_config("[tui]\ngroup_digits = true\nhidden = true\n");
    env.otp().arg("list").assert().success();
    env.write_config("[tui]\ngroup_digit = true\n");
    env.otp()
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("group_digit"));
}

#[test]
fn completes_folders_along_entry_paths() {
    let env = Env::new();
    fs::create_dir_all(env.pass_dir().join("Web/amazon.fr")).unwrap();
    fs::write(env.pass_dir().join("Web/amazon.fr/pm@mkz.me-otp.gpg"), b"").unwrap();
    env.insert_uri("Web/github", HOTP_URI);
    env.insert_uri("Web/amazon.fr/other", HOTP_URI);
    env.insert_uri("google.com", HOTP_URI);

    // Every folder along the paths is offered, each right before its contents.
    assert_eq!(
        complete(&env, &["W"]),
        "Web/\nWeb/amazon.fr/\nWeb/amazon.fr/other\tnative\n\
         Web/amazon.fr/pm@mkz.me\tpass\nWeb/github\tnative\n"
    );
    assert_eq!(
        complete(&env, &["show", "Web/amazon.fr/p"]),
        "Web/amazon.fr/pm@mkz.me\tpass\n"
    );
    // A name without a folder adds none.
    assert_eq!(complete(&env, &["goo"]), "google.com\tnative\n");

    // `insert` creates new names, so only folders are offered.
    assert_eq!(complete(&env, &["insert", "W"]), "Web/\nWeb/amazon.fr/\n");
    assert_eq!(
        complete(&env, &["insert", "--pass", "Web/a"]),
        "Web/amazon.fr/\n"
    );
    assert_eq!(complete(&env, &["insert", "g"]), "");
}

#[cfg(feature = "tui")]
#[test]
fn tui_accepts_hidden_flag() {
    // Without a terminal the TUI refuses to start, after the flag was parsed.
    let env = Env::new();
    env.otp()
        .args(["tui", "--hidden"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("otp tui needs a terminal"));
}

#[test]
fn mv_renames_within_the_store() {
    let env = Env::new();
    env.insert_uri("a/b/c", HOTP_URI);
    let uri = |name: &str| {
        let output = env.otp().args(["--otpauth", name]).assert().success();
        String::from_utf8(output.get_output().stdout.clone()).unwrap()
    };
    let original = uri("a/b/c");

    env.otp()
        .args(["mv", "a/b/c", "a/b/d"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Moved a/b/c to a/b/d in the native store",
        ));
    assert_eq!(uri("a/b/d"), original);
    env.otp()
        .arg("a/b/c")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in the store"));

    // A trailing slash moves the entry into that folder, keeping its name.
    env.otp()
        .args(["mv", "a/b/d", "archive/"])
        .assert()
        .success();
    env.otp()
        .arg("list")
        .assert()
        .success()
        .stdout("archive/d\n");

    // The destination must be free unless --force is given.
    env.insert_uri("other", HOTP_URI);
    env.otp()
        .args(["mv", "other", "archive/d"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists; use --force"));
    env.otp()
        .args(["mv", "-f", "other", "archive/d"])
        .assert()
        .success();
    env.otp()
        .arg("list")
        .assert()
        .success()
        .stdout("archive/d\n");

    for (args, error) in [
        (["mv", "missing", "x"], "missing is not in the store"),
        (["mv", "archive/d", "archive/d"], "already named"),
        (["mv", "archive/", "x"], "is a folder"),
        (["mv", "archive/d", "../escape"], "invalid entry name"),
    ] {
        env.otp()
            .args(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(error));
    }
}

#[test]
fn mv_in_pass_and_across_stores() {
    let env = Env::new().with_fake_pass();
    fs::write(env.pass_dir().join("web-otp.gpg"), format!("{HOTP_URI}\n")).unwrap();
    env.insert_uri("native-entry", HOTP_URI);

    env.otp()
        .args(["mv", "web", "Web/amazon.fr/pm@mkz.me"])
        .assert()
        .success()
        .stderr(predicate::str::contains("in the pass store"));
    assert!(
        env.pass_dir()
            .join("Web/amazon.fr/pm@mkz.me-otp.gpg")
            .is_file()
    );
    env.otp()
        .arg("Web/amazon.fr/pm@mkz.me")
        .assert()
        .success()
        .stdout("755224\n");

    // Names stay unique across stores, even with --force.
    env.otp()
        .args(["mv", "-f", "Web/amazon.fr/pm@mkz.me", "native-entry"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "already exists in the native store",
        ));
}

#[test]
fn concurrent_inserts_keep_both_entries() {
    use std::io::Write;
    use std::process::Stdio;

    let env = Env::new();
    env.insert_uri("existing", HOTP_URI);
    // The first insert opens the database, then waits at its URI prompt...
    let mut first = env
        .std_otp()
        .args(["insert", "first"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    // ...while a second one completes.
    env.insert_uri("second", HOTP_URI);
    writeln!(first.stdin.take().unwrap(), "{HOTP_URI}").unwrap();
    let output = first.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    env.otp()
        .arg("list")
        .assert()
        .success()
        .stdout("existing\nfirst\nsecond\n");
}

#[test]
fn concurrent_inserts_of_one_name_keep_the_first() {
    use std::io::Write;
    use std::process::Stdio;

    let env = Env::new();
    env.insert_uri("existing", HOTP_URI);
    let mut late = env
        .std_otp()
        .args(["insert", "same"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    env.insert_uri("same", HOTP_URI);
    let other = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
    writeln!(late.stdin.take().unwrap(), "{other}").unwrap();
    let output = late.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("same already exists"));
    // The entry enrolled first is intact.
    env.otp()
        .args(["--otpauth", "same"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret=GEZDGNBVGY3TQOJQ"));
}

#[test]
fn crafted_labels_are_rejected_without_being_echoed() {
    let env = Env::new();
    for uri in [
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=%1b%5b2J",
        "otpauth://totp/Issuer:%1b%5d0;PWNED%07?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/Bank:%e2%80%aemoc.knab?secret=JBSWY3DPEHPK3PXP",
    ] {
        let output = env
            .otp()
            .args(["insert", "x"])
            .write_stdin(format!("{uri}\n"))
            .assert()
            .failure()
            .stderr(predicate::str::contains("control or bidirectional"))
            .get_output()
            .clone();
        assert!(!output.stderr.contains(&0x1b), "{uri}: escape echoed");
    }
    // The same check covers --issuer and --account, with a URI or a secret.
    env.otp()
        .args(["insert", "y", "--issuer", "\u{1b}]52;c;cHduZWQ=\u{7}"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("issuer contains"));
    env.otp()
        .args(["insert", "y", "--secret", "--account", "\u{202e}evil"])
        .write_stdin("JBSWY3DPEHPK3PXP\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("account contains"));
    // And a QR code carrying such a URI.
    let png = env.path("evil.png");
    write_qr_png(&png, "otpauth://totp/%1b%5b2J:a?secret=JBSWY3DPEHPK3PXP");
    env.otp()
        .args(["insert", "z", &format!("--qrcode={}", png.display())])
        .assert()
        .failure()
        .stderr(predicate::str::contains("control or bidirectional"));
    env.otp().arg("list").assert().success().stdout("");

    // Names with bidi overrides are refused too.
    env.otp()
        .args(["insert", "\u{202e}moc.elgoog"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid entry name"));
}

#[test]
fn show_escapes_labels_saved_by_older_versions() {
    use otp_core::store::{NativeStore, Store};
    use otp_core::{Entry, Kind, OtpSecret};

    // Before labels were validated, such an entry could be saved.
    let env = Env::new();
    let mut store = NativeStore::create(env.path("data/otp.db"), b"correct horse").unwrap();
    let mut otp = OtpSecret::from_base32("JBSWY3DPEHPK3PXP", Kind::Totp { period: 30 }).unwrap();
    otp.issuer = Some("\u{1b}]0;PWNED\u{7}".into());
    otp.account = Some("\u{1b}[2J".into());
    store.put("old", &Entry::new(otp)).unwrap();

    let output = env.otp().args(["show", "old"]).assert().success();
    let stdout = &output.get_output().stdout;
    assert!(!stdout.contains(&0x1b), "escape printed raw");
    let stdout = String::from_utf8_lossy(stdout);
    assert!(
        stdout.contains("issuer:    \\u{1b}]0;PWNED\\u{7}"),
        "{stdout}"
    );
    assert!(stdout.contains("account:   \\u{1b}[2J"), "{stdout}");
}

#[test]
fn master_password_is_not_passed_to_child_processes() {
    // Every tool otp runs records its environment.
    let env = Env::new().with_fake_pass();
    let dumps = env.path("env");
    fs::create_dir_all(&dumps).unwrap();
    let dump = |tool: &str| format!("env > {}/{tool}", dumps.display());
    let png = env.path("qr.png");
    write_qr_png(&png, HOTP_URI);
    env.write_config(&format!(
        "password_command = [\"sh\", \"-c\", \"{password}; echo 'correct horse'\"]\n\
         clipboard_command = [\"sh\", \"-c\", \"{clipboard}; cat > /dev/null\"]\n\
         clipboard_timeout = 0\n\
         capture_command = [\"sh\", \"-c\", \"{capture}; cp {png} \\\"$0\\\"\"]\n\
         qrcode_viewer_command = [\"sh\", \"-c\", \"{viewer}\"]\n",
        password = dump("password"),
        clipboard = dump("clipboard"),
        capture = dump("capture"),
        viewer = dump("viewer"),
        png = png.display(),
    ));
    let pass_script = env.path("bin/pass");
    let script = fs::read_to_string(&pass_script).unwrap();
    fs::write(
        &pass_script,
        script.replacen("\n", &format!("\n{}\n", dump("pass")), 1),
    )
    .unwrap();

    env.otp()
        .args(["insert", "--qrcode", "x"])
        .assert()
        .success();
    env.otp().args(["-c", "x"]).assert().success();
    env.otp().args(["--qrcode", "x"]).assert().success();
    env.otp()
        .args(["insert", "--pass", "p"])
        .write_stdin(format!("{HOTP_URI}\n"))
        .assert()
        .success();
    // Without OTP_PASSWORD, the password command runs; it must not see it either.
    env.otp()
        .env_remove("OTP_PASSWORD")
        .arg("x")
        .assert()
        .success();

    for tool in ["clipboard", "capture", "viewer", "pass", "password"] {
        let seen =
            fs::read_to_string(dumps.join(tool)).unwrap_or_else(|_| panic!("{tool} did not run"));
        assert!(!seen.contains("OTP_PASSWORD"), "{tool} got OTP_PASSWORD");
        assert!(
            !seen.contains("correct horse"),
            "{tool} got the master password"
        );
        assert!(
            seen.contains("OTP_DB="),
            "{tool}: the rest of the environment is kept"
        );
    }
}

/// A clipboard backed by a file: copy writes it, paste prints it, clear empties it.
fn file_clipboard(env: &Env, timeout: u64) -> std::path::PathBuf {
    let clip = env.path("clipboard");
    env.write_config(&format!(
        "clipboard_command = [\"sh\", \"-c\", \"cat > '{clip}'\"]\n\
         clipboard_paste_command = [\"cat\", \"{clip}\"]\n\
         clipboard_clear_command = [\"sh\", \"-c\", \": > '{clip}'\"]\n\
         clipboard_timeout = {timeout}\n",
        clip = clip.display(),
    ));
    clip
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
fn clipboard_is_cleared_after_the_timeout() {
    let env = Env::new();
    let clip = file_clipboard(&env, 1);
    env.insert_uri("x", HOTP_URI);
    env.otp()
        .args(["-c", "--secret", "x"])
        .assert()
        .success()
        .stderr(predicate::str::contains("it will be cleared in 1 seconds"));
    assert_eq!(fs::read_to_string(&clip).unwrap(), SECRET);
    wait_until("the clipboard to be cleared", || {
        fs::read_to_string(&clip).unwrap().is_empty()
    });
}

#[test]
fn clipboard_clearing_spares_a_newer_copy() {
    let env = Env::new();
    let clip = file_clipboard(&env, 1);
    env.insert_uri("x", HOTP_URI);
    env.otp().args(["-c", "x"]).assert().success();
    // Something else is copied before the timeout.
    fs::write(&clip, "copied later").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(fs::read_to_string(&clip).unwrap(), "copied later");
}

#[test]
fn clipboard_timeout_zero_keeps_the_value() {
    let env = Env::new();
    let clip = file_clipboard(&env, 0);
    env.insert_uri("x", HOTP_URI);
    env.otp()
        .args(["-c", "x"])
        .assert()
        .success()
        .stderr(predicate::str::contains("will be cleared").not());
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(fs::read_to_string(&clip).unwrap(), "755224");
}

#[test]
fn default_clipboard_command_is_sensitive() {
    // The default copy command asks clipboard managers not to keep the copy.
    let env = Env::new();
    env.write_config("clipboard_timeout = 0\n");
    let bin = env.path("bin");
    fs::create_dir_all(&bin).unwrap();
    let args = env.path("wl-copy-args");
    let script = bin.join("wl-copy");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\ncat > /dev/null\n",
            args.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    env.insert_uri("x", HOTP_URI);
    env.otp().args(["-c", "x"]).assert().success();
    assert_eq!(fs::read_to_string(&args).unwrap(), "--sensitive\n");
}
