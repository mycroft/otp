//! Exercises `PassStore` against real pass(1) and gpg with a throwaway GPG home.
//! Skipped when pass or gpg is not installed.

use std::path::Path;
use std::process::{Command, Stdio};

use otp_core::store::{PassStore, Store};
use otp_core::{Entry, Kind, OtpSecret};

fn installed(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

struct GpgHome(tempfile::TempDir);

impl GpgHome {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let status = Command::new("gpg")
            .args([
                "--batch",
                "--passphrase",
                "",
                "--quick-gen-key",
                "otp-test@example.com",
            ])
            .args(["default", "default", "never"])
            .env("GNUPGHOME", dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "gpg key generation failed");
        GpgHome(dir)
    }

    fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for GpgHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .args(["--kill", "gpg-agent"])
            .env("GNUPGHOME", self.path())
            .status();
    }
}

fn pass(gpg: &GpgHome, store: &Path, args: &[&str], stdin: Option<&str>) -> String {
    use std::io::Write;
    let mut child = Command::new("pass")
        .args(args)
        .env("GNUPGHOME", gpg.path())
        .env("PASSWORD_STORE_DIR", store)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.unwrap_or("").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "pass {args:?} failed");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn pass_store_end_to_end() {
    if !installed("pass") || !installed("gpg") {
        eprintln!("skipping: pass or gpg not installed");
        return;
    }
    let gpg = GpgHome::new();
    let store_dir = tempfile::tempdir().unwrap();
    pass(
        &gpg,
        store_dir.path(),
        &["init", "otp-test@example.com"],
        None,
    );

    let mut store =
        PassStore::new(Some(store_dir.path().to_path_buf())).env("GNUPGHOME", gpg.path());

    let mut otp = OtpSecret::from_base32(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        Kind::Hotp { counter: 0 },
    )
    .unwrap();
    otp.issuer = Some("google.com".into());
    otp.account = Some("alice@gmail.com".into());
    let entry = Entry::new(otp);

    let name = "google.com/alice@gmail.com";
    assert!(!store.contains(name).unwrap());
    store.put(name, &entry).unwrap();
    assert!(
        store_dir
            .path()
            .join("google.com/alice@gmail.com-otp.gpg")
            .is_file()
    );
    assert_eq!(store.list().unwrap(), [name]);
    assert_eq!(store.get(name).unwrap().unwrap(), entry);

    // The pass entry is an otpauth URI followed by JSON metadata.
    let raw = pass(
        &gpg,
        store_dir.path(),
        &["show", "google.com/alice@gmail.com-otp"],
        None,
    );
    let (first, rest) = raw.split_once('\n').unwrap();
    assert!(first.starts_with("otpauth://hotp/google.com:alice@gmail.com?secret="));
    let meta: serde_json::Value = serde_json::from_str(rest).unwrap();
    assert!(meta["created_at"].is_string());

    // Consuming an HOTP code persists the new counter.
    let mut got = store.get(name).unwrap().unwrap();
    assert_eq!(
        got.otp.generate(std::time::SystemTime::now()).value,
        "755224"
    );
    store.put(name, &got).unwrap();
    assert_eq!(
        store.get(name).unwrap().unwrap().otp.kind,
        Kind::Hotp { counter: 1 }
    );

    // Foreign entries keep their trailing notes when rewritten.
    let foreign = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\nrecovery: 1111 2222\n";
    pass(
        &gpg,
        store_dir.path(),
        &["insert", "-m", "notes-otp"],
        Some(foreign),
    );
    let notes = store.get("notes").unwrap().unwrap();
    store.put("notes", &notes).unwrap();
    let raw = pass(&gpg, store_dir.path(), &["show", "notes-otp"], None);
    assert!(raw.ends_with("\nrecovery: 1111 2222\n"), "got {raw:?}");

    // Renaming moves the file into new folders and keeps the contents.
    let before = store.get(name).unwrap().unwrap();
    assert!(store.rename(name, "archive/google/alice", false).unwrap());
    assert!(!store.contains(name).unwrap());
    assert_eq!(store.get("archive/google/alice").unwrap().unwrap(), before);
    assert!(
        !store.rename(name, "elsewhere", false).unwrap(),
        "source is gone"
    );
    // An existing destination is only replaced when asked; insert never replaces.
    assert!(
        store
            .rename("archive/google/alice", "notes", false)
            .is_err()
    );
    assert!(store.insert("notes", &before).is_err());
    assert!(store.rename("archive/google/alice", "notes", true).unwrap());
    assert_eq!(store.get("notes").unwrap().unwrap(), before);

    assert!(store.remove("notes").unwrap());
    assert!(!store.remove("notes").unwrap());
    assert!(store.list().unwrap().is_empty());
}
