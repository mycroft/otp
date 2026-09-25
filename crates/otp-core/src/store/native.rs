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

#[derive(Default, Serialize, Deserialize)]
struct Contents {
    entries: BTreeMap<String, Entry>,
}

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
        store.save()?;
        Ok(store)
    }

    /// Opens and decrypts an existing database.
    pub fn open(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        let data = fs::read(&path)?;
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
        let salt: [u8; SALT_LEN] = decode_fixed(&header.kdf.salt, "salt")?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&envelope.nonce, "nonce")?;
        let ciphertext = BASE64
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|e| Error::DatabaseFormat(format!("ciphertext: {e}")))?;

        let params = header.kdf.params;
        let key = derive_key(password, &salt, params)?;
        let aad = serde_json::to_vec(header)?;
        let plaintext = Zeroizing::new(
            cipher(&key)
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Decrypt)?,
        );
        let contents: Contents = serde_json::from_slice(&plaintext)?;
        Ok(NativeStore {
            path,
            params,
            salt,
            key,
            contents,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-encrypts the database under a new password (and a fresh salt).
    pub fn change_password(&mut self, password: &[u8]) -> Result<()> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| Error::Rng)?;
        self.key = derive_key(password, &salt, self.params)?;
        self.salt = salt;
        self.save()
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

    /// Encrypts with a fresh nonce and atomically replaces the database file.
    fn save(&self) -> Result<()> {
        let header = self.header();
        let aad = serde_json::to_vec(&header)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.contents)?);
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

        let dir = match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
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
        let previous = self
            .contents
            .entries
            .insert(name.to_string(), entry.clone());
        if let Err(e) = self.save() {
            match previous {
                Some(previous) => self.contents.entries.insert(name.to_string(), previous),
                None => self.contents.entries.remove(name),
            };
            return Err(e);
        }
        Ok(())
    }

    fn remove(&mut self, name: &str) -> Result<bool> {
        let Some(previous) = self.contents.entries.remove(name) else {
            return Ok(false);
        };
        if let Err(e) = self.save() {
            self.contents.entries.insert(name.to_string(), previous);
            return Err(e);
        }
        Ok(true)
    }
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
