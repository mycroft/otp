//! Native store: a single file encrypted with XChaCha20-Poly1305, keyed by a master
//! password through Argon2id.
//!
//! The file is a JSON envelope. Everything except the nonce and ciphertext is
//! authenticated as associated data, so KDF parameters cannot be tampered with.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{Backend, Store};
use crate::{Entry, Error, Result, validate_name};

const FORMAT: &str = "otp-db";
const VERSION: u32 = 1;
const CIPHER: &str = "xchacha20poly1305";
const KDF: &str = "argon2id";
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, 3 passes: a few hundred milliseconds on a typical machine.
        KdfParams {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    format: String,
    version: u32,
    cipher: String,
    kdf: KdfHeader,
}

#[derive(Serialize, Deserialize)]
struct KdfHeader {
    algorithm: String,
    #[serde(flatten)]
    params: KdfParams,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(flatten)]
    header: Header,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Contents {
    entries: BTreeMap<String, Entry>,
}

/// A database file, parsed but not decrypted.
struct Sealed {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    /// The authenticated header.
    aad: Vec<u8>,
}

impl Sealed {
    fn read(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        let envelope: Envelope = serde_json::from_slice(&data)
            .map_err(|e| Error::DatabaseFormat(format!("{}: {e}", path.display())))?;
        let header = &envelope.header;
        if header.format != FORMAT || header.version != VERSION {
            return Err(Error::DatabaseFormat(format!(
                "{}: expected {FORMAT} version {VERSION}, found {} version {}",
                path.display(),
                header.format,
                header.version
            )));
        }
        if header.cipher != CIPHER || header.kdf.algorithm != KDF {
            return Err(Error::DatabaseFormat(format!(
                "{}: unsupported cipher {:?} or KDF {:?}",
                path.display(),
                header.cipher,
                header.kdf.algorithm
            )));
        }
        Ok(Sealed {
            params: header.kdf.params,
            salt: decode_fixed(&header.kdf.salt, "salt")?,
            nonce: decode_fixed(&envelope.nonce, "nonce")?,
            ciphertext: BASE64
                .decode(envelope.ciphertext.as_bytes())
                .map_err(|e| Error::DatabaseFormat(format!("ciphertext: {e}")))?,
            aad: serde_json::to_vec(header)?,
        })
    }

    fn decrypt(&self, key: &[u8; KEY_LEN]) -> Result<Contents> {
        let plaintext = Zeroizing::new(
            cipher(key)
                .decrypt(
                    &XNonce::from(self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &self.aad,
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

/// The database, decrypted.
///
/// Reads use the copy loaded when the database was opened. Every change is made under
/// an exclusive lock on `<path>.lock`, to the file as it is at that moment, so that
/// changes made meanwhile by other processes are kept.
pub struct NativeStore {
    path: PathBuf,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    key: Zeroizing<[u8; KEY_LEN]>,
    contents: Contents,
}

impl NativeStore {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Creates a new, empty database with default KDF parameters and writes it to `path`.
    pub fn create(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        Self::create_with_params(path, password, KdfParams::default())
    }

    pub fn create_with_params(
        path: impl Into<PathBuf>,
        password: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
        let path = path.into();
        // Under the lock, so two processes cannot both create the database.
        let _lock = lock(&path)?;
        if path.exists() {
            return Err(Error::DatabaseExists(path.display().to_string()));
        }
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| Error::Rng)?;
        let key = derive_key(password, &salt, params)?;
        let store = NativeStore {
            path,
            params,
            salt,
            key,
            contents: Contents::default(),
        };
        store.write(&store.contents)?;
        Ok(store)
    }

    /// Opens and decrypts an existing database.
    pub fn open(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        let sealed = Sealed::read(&path)?;
        let key = derive_key(password, &sealed.salt, sealed.params)?;
        let contents = sealed.decrypt(&key)?;
        Ok(NativeStore {
            path,
            params: sealed.params,
            salt: sealed.salt,
            key,
            contents,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-encrypts the database under a new password (and a fresh salt).
    pub fn change_password(&mut self, password: &[u8]) -> Result<()> {
        let _lock = lock(&self.path)?;
        let contents = self.reload()?;
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| Error::Rng)?;
        let key = derive_key(password, &salt, self.params)?;
        let previous = (
            std::mem::replace(&mut self.salt, salt),
            std::mem::replace(&mut self.key, key),
        );
        if let Err(e) = self.write(&contents) {
            (self.salt, self.key) = previous;
            return Err(e);
        }
        self.contents = contents;
        Ok(())
    }

    /// Applies `change` to the database as it currently is on disk, under the lock, and
    /// saves the result.
    fn modify<T>(&mut self, change: impl FnOnce(&mut Contents) -> Result<T>) -> Result<T> {
        let _lock = lock(&self.path)?;
        let mut contents = self.reload()?;
        let result = change(&mut contents)?;
        self.write(&contents)?;
        self.contents = contents;
        Ok(result)
    }

    /// Reads the database file again. Must be called with the lock held.
    fn reload(&self) -> Result<Contents> {
        let sealed = Sealed::read(&self.path)?;
        if sealed.salt != self.salt || sealed.params != self.params {
            // Another process changed the master password: our key no longer applies.
            return Err(Error::DatabaseChanged(self.path.display().to_string()));
        }
        sealed.decrypt(&self.key)
    }

    fn header(&self) -> Header {
        Header {
            format: FORMAT.into(),
            version: VERSION,
            cipher: CIPHER.into(),
            kdf: KdfHeader {
                algorithm: KDF.into(),
                params: self.params,
                salt: BASE64.encode(&self.salt),
            },
        }
    }

    /// Encrypts `contents` with a fresh nonce and atomically replaces the database file.
    fn write(&self, contents: &Contents) -> Result<()> {
        let header = self.header();
        let aad = serde_json::to_vec(&header)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(contents)?);
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::Rng)?;
        let ciphertext = cipher(&self.key)
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::DatabaseFormat("encryption failed".into()))?;
        let envelope = Envelope {
            header,
            nonce: BASE64.encode(&nonce),
            ciphertext: BASE64.encode(&ciphertext),
        };

        let dir = parent_dir(&self.path);
        create_private_dir(dir)?;
        // NamedTempFile is created with mode 0600.
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer_pretty(&mut tmp, &envelope)?;
        tmp.write_all(b"\n")?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path).map_err(|e| e.error)?;
        Ok(())
    }
}

impl Store for NativeStore {
    fn backend(&self) -> Backend {
        Backend::Native
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.contents.entries.keys().cloned().collect())
    }

    fn contains(&self, name: &str) -> Result<bool> {
        Ok(self.contents.entries.contains_key(name))
    }

    fn get(&self, name: &str) -> Result<Option<Entry>> {
        Ok(self.contents.entries.get(name).cloned())
    }

    fn put(&mut self, name: &str, entry: &Entry) -> Result<()> {
        validate_name(name)?;
        self.modify(|contents| {
            contents.entries.insert(name.to_string(), entry.clone());
            Ok(())
        })
    }

    fn insert(&mut self, name: &str, entry: &Entry) -> Result<()> {
        validate_name(name)?;
        self.modify(|contents| {
            if contents.entries.contains_key(name) {
                return Err(Error::EntryExists(name.to_string()));
            }
            contents.entries.insert(name.to_string(), entry.clone());
            Ok(())
        })
    }

    fn remove(&mut self, name: &str) -> Result<bool> {
        self.modify(|contents| Ok(contents.entries.remove(name).is_some()))
    }

    fn rename(&mut self, from: &str, to: &str, replace: bool) -> Result<bool> {
        validate_name(to)?;
        // A single save, so the entry is never missing or duplicated on disk.
        self.modify(|contents| {
            let entries = &mut contents.entries;
            if !entries.contains_key(from) {
                return Ok(false);
            }
            if !replace && entries.contains_key(to) {
                return Err(Error::EntryExists(to.to_string()));
            }
            let entry = entries.remove(from).expect("checked above");
            entries.insert(to.to_string(), entry);
            Ok(true)
        })
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Takes the exclusive lock that guards changes to the database at `path`: a flock on
/// `<path>.lock`, released when the returned file is dropped. The lock file is left in
/// place, since removing it would let two processes lock different files.
fn lock(path: &Path) -> Result<fs::File> {
    create_private_dir(parent_dir(path))?;
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&lock_path)?;
    file.lock()?;
    Ok(file)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("key has the correct length")
}

fn derive_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon_params =
        argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(key)
}

fn decode_fixed<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    BASE64
        .decode(value.as_bytes())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::DatabaseFormat(format!("invalid {what}")))
}

fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kind, OtpSecret};

    // Cheap parameters so tests stay fast.
    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
    };

    fn entry(secret: &str) -> Entry {
        Entry::new(OtpSecret::from_base32(secret, Kind::Totp { period: 30 }).unwrap())
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/otp.db");
        let mut store = NativeStore::create_with_params(&path, b"hunter2", TEST_PARAMS).unwrap();
        store
            .put("google.com/alice", &entry("JBSWY3DPEHPK3PXP"))
            .unwrap();
        store.put("github", &entry("GEZDGNBVGY3TQOJQ")).unwrap();

        let store = NativeStore::open(&path, b"hunter2").unwrap();
        assert_eq!(store.list().unwrap(), ["github", "google.com/alice"]);
        let got = store.get("google.com/alice").unwrap().unwrap();
        assert_eq!(got, entry_with_meta("JBSWY3DPEHPK3PXP", &got));
        assert!(store.get("missing").unwrap().is_none());

        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("JBSWY3DPEHPK3PXP"),
            "secret must not be stored in clear"
        );
        assert!(
            !raw.contains("google.com"),
            "names must not be stored in clear"
        );
    }

    fn entry_with_meta(secret: &str, like: &Entry) -> Entry {
        Entry {
            otp: OtpSecret::from_base32(secret, Kind::Totp { period: 30 }).unwrap(),
            meta: like.meta.clone(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "database mode is {mode:o}");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        NativeStore::create_with_params(&path, b"right", TEST_PARAMS).unwrap();
        assert!(matches!(
            NativeStore::open(&path, b"wrong"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        let mut store = NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        store.put("a", &entry("JBSWY3DPEHPK3PXP")).unwrap();

        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        let mut envelope = original.clone();
        envelope["kdf"]["t_cost"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            NativeStore::open(&path, b"pw"),
            Err(Error::Decrypt)
        ));

        let mut envelope = original.clone();
        let mut ciphertext = BASE64
            .decode(envelope["ciphertext"].as_str().unwrap().as_bytes())
            .unwrap();
        ciphertext[0] ^= 1;
        envelope["ciphertext"] = serde_json::json!(BASE64.encode(&ciphertext));
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(matches!(
            NativeStore::open(&path, b"pw"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        assert!(matches!(
            NativeStore::create_with_params(&path, b"pw", TEST_PARAMS),
            Err(Error::DatabaseExists(_))
        ));
    }

    #[test]
    fn rename_moves_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        let mut store = NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        let a = entry("JBSWY3DPEHPK3PXP");
        let b = entry("GEZDGNBVGY3TQOJQ");
        store.put("a/b/c", &a).unwrap();
        store.put("x", &b).unwrap();

        assert!(store.rename("a/b/c", "a/b/d", false).unwrap());
        assert!(
            !store.rename("a/b/c", "a/b/e", false).unwrap(),
            "source is gone"
        );
        // An existing destination is only replaced when asked.
        assert!(matches!(
            store.rename("x", "a/b/d", false),
            Err(Error::EntryExists(name)) if name == "a/b/d"
        ));
        assert!(store.rename("x", "a/b/d", true).unwrap());
        assert!(
            store
                .rename("../escape", "y", false)
                .is_ok_and(|moved| !moved)
        );
        assert!(store.rename("a/b/d", "../escape", false).is_err());

        let store = NativeStore::open(&path, b"pw").unwrap();
        assert_eq!(store.list().unwrap(), ["a/b/d"]);
        assert_eq!(store.get("a/b/d").unwrap().unwrap(), b, "metadata is kept");
    }

    #[test]
    fn concurrent_writers_keep_each_others_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        // Two processes open the same database, then both write.
        let mut first = NativeStore::open(&path, b"pw").unwrap();
        let mut second = NativeStore::open(&path, b"pw").unwrap();
        first.put("first", &entry("JBSWY3DPEHPK3PXP")).unwrap();
        second.put("second", &entry("GEZDGNBVGY3TQOJQ")).unwrap();
        assert_eq!(
            NativeStore::open(&path, b"pw").unwrap().list().unwrap(),
            ["first", "second"]
        );
        // A stale handle's other changes also keep what it has not seen.
        second.remove("second").unwrap();
        first.put("third", &entry("JBSWY3DPEHPK3PXP")).unwrap();
        second.rename("first", "renamed", false).unwrap();
        assert_eq!(
            NativeStore::open(&path, b"pw").unwrap().list().unwrap(),
            ["renamed", "third"]
        );
        // After a change, the handle sees the others' entries.
        assert_eq!(second.list().unwrap(), ["renamed", "third"]);
    }

    #[test]
    fn insert_refuses_a_name_added_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        let mut first = NativeStore::open(&path, b"pw").unwrap();
        let mut second = NativeStore::open(&path, b"pw").unwrap();
        let theirs = entry("JBSWY3DPEHPK3PXP");
        first.insert("x", &theirs).unwrap();
        assert!(matches!(
            second.insert("x", &entry("GEZDGNBVGY3TQOJQ")),
            Err(Error::EntryExists(name)) if name == "x"
        ));
        let store = NativeStore::open(&path, b"pw").unwrap();
        assert_eq!(store.get("x").unwrap().unwrap(), theirs, "not overwritten");
    }

    #[test]
    fn password_changed_elsewhere_refuses_to_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        let mut first = NativeStore::create_with_params(&path, b"old", TEST_PARAMS).unwrap();
        first.put("a", &entry("JBSWY3DPEHPK3PXP")).unwrap();
        let mut second = NativeStore::open(&path, b"old").unwrap();
        first.change_password(b"new").unwrap();
        assert!(matches!(
            second.put("b", &entry("JBSWY3DPEHPK3PXP")),
            Err(Error::DatabaseChanged(_))
        ));
        let store = NativeStore::open(&path, b"new").unwrap();
        assert_eq!(store.list().unwrap(), ["a"], "nothing was written");
    }

    #[test]
    fn changes_wait_for_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        NativeStore::create_with_params(&path, b"pw", TEST_PARAMS).unwrap();
        let held = lock(&path).unwrap();
        let writer = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut store = NativeStore::open(&path, b"pw").unwrap();
                store.put("a", &entry("JBSWY3DPEHPK3PXP")).unwrap();
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!writer.is_finished(), "the write must wait for the lock");
        drop(held);
        writer.join().unwrap();
        assert_eq!(
            NativeStore::open(&path, b"pw").unwrap().list().unwrap(),
            ["a"]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock_file = dir.path().join("otp.db.lock");
            let mode = fs::metadata(lock_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "lock file mode is {mode:o}");
        }
    }

    #[test]
    fn remove_and_change_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("otp.db");
        let mut store = NativeStore::create_with_params(&path, b"old", TEST_PARAMS).unwrap();
        store.put("a", &entry("JBSWY3DPEHPK3PXP")).unwrap();
        store.put("b", &entry("JBSWY3DPEHPK3PXP")).unwrap();
        assert!(store.remove("a").unwrap());
        assert!(!store.remove("a").unwrap());
        store.change_password(b"new").unwrap();

        assert!(matches!(
            NativeStore::open(&path, b"old"),
            Err(Error::Decrypt)
        ));
        let store = NativeStore::open(&path, b"new").unwrap();
        assert_eq!(store.list().unwrap(), ["b"]);
    }

    #[test]
    fn rejects_invalid_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            NativeStore::create_with_params(dir.path().join("otp.db"), b"pw", TEST_PARAMS).unwrap();
        assert!(store.put("../escape", &entry("JBSWY3DPEHPK3PXP")).is_err());
        assert!(store.list().unwrap().is_empty());
    }
}
