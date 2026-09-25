use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use otp_core::store::{Backend, NativeStore, PassStore, Store};

use crate::prompt::PasswordSource;

/// Both backends, with the native database opened lazily so that pass-only usage
/// never asks for the master password.
pub struct Stores<'a> {
    db_path: PathBuf,
    password: PasswordSource<'a>,
    native: Option<NativeStore>,
    pass: PassStore,
}

impl<'a> Stores<'a> {
    pub fn new(db_path: PathBuf, password: PasswordSource<'a>, pass: PassStore) -> Self {
        Stores {
            db_path,
            password,
            native: None,
            pass,
        }
    }

    fn native_if_exists(&mut self) -> Result<Option<&mut NativeStore>> {
        if self.native.is_none() && NativeStore::exists(&self.db_path) {
            let password = self.password.existing()?;
            let store = NativeStore::open(&self.db_path, password.as_bytes())
                .with_context(|| format!("opening {}", self.db_path.display()))?;
            self.native = Some(store);
        }
        Ok(self.native.as_mut())
    }

    /// Returns the store for `backend`, or `None` if the native database does not exist.
    pub fn get(&mut self, backend: Backend) -> Result<Option<&mut dyn Store>> {
        Ok(match backend {
            Backend::Pass => Some(&mut self.pass),
            Backend::Native => self.native_if_exists()?.map(|s| s as &mut dyn Store),
        })
    }

    /// Returns the store for `backend`, creating the native database if needed.
    pub fn get_or_create(&mut self, backend: Backend) -> Result<&mut dyn Store> {
        if backend == Backend::Native && self.native_if_exists()?.is_none() {
            eprintln!("Creating a new database at {}", self.db_path.display());
            let password = self.password.new_password("New master password")?;
            let store = NativeStore::create(&self.db_path, password.as_bytes())
                .with_context(|| format!("creating {}", self.db_path.display()))?;
            self.native = Some(store);
        }
        Ok(self.get(backend)?.expect("store exists"))
    }

    pub fn contains(&mut self, backend: Backend, name: &str) -> Result<bool> {
        match self.get(backend)? {
            Some(store) => Ok(store.contains(name)?),
            None => Ok(false),
        }
    }

    /// Finds which backend holds `name`. pass is checked first because it needs no
    /// decryption to answer.
    pub fn find(&mut self, name: &str, only: Option<Backend>) -> Result<Option<Backend>> {
        let candidates = match only {
            Some(backend) => vec![backend],
            None => vec![Backend::Pass, Backend::Native],
        };
        for backend in candidates {
            if self.contains(backend, name)? {
                return Ok(Some(backend));
            }
        }
        Ok(None)
    }

    /// Like [`Stores::find`], but a missing entry is an error.
    pub fn locate(&mut self, name: &str, only: Option<Backend>) -> Result<Backend> {
        if let Some(backend) = self.find(name, only)? {
            return Ok(backend);
        }
        match only {
            Some(backend) => bail!("{name} is not in the {backend} store"),
            None => bail!("{name} is not in the store"),
        }
    }

    /// Lists `(name, backend)` for every entry (in `only`, if given), sorted by name.
    pub fn list(&mut self, only: Option<Backend>) -> Result<Vec<(String, Backend)>> {
        let mut rows = Vec::new();
        let backends = match only {
            Some(backend) => vec![backend],
            None => vec![Backend::Pass, Backend::Native],
        };
        for backend in backends {
            if let Some(store) = self.get(backend)? {
                rows.extend(store.list()?.into_iter().map(|name| (name, backend)));
            }
        }
        rows.sort();
        Ok(rows)
    }

    pub fn native_for_passwd(&mut self) -> Result<&mut NativeStore> {
        if !NativeStore::exists(&self.db_path) {
            bail!("no database at {}", self.db_path.display());
        }
        Ok(self.native_if_exists()?.expect("database exists"))
    }
}
