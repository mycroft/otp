//! Storage backends for OTP entries.

mod native;
mod pass;

use std::fmt;

pub use native::{KdfParams, NativeStore};
pub use pass::PassStore;

use crate::{Entry, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Backend {
    /// The encrypted, master-password protected database.
    Native,
    /// pass(1), the standard Unix password manager.
    Pass,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Backend::Native => "native",
            Backend::Pass => "pass",
        })
    }
}

/// A place where entries are stored, keyed by name (see [`crate::validate_name`]).
pub trait Store {
    fn backend(&self) -> Backend;

    /// Returns all entry names, sorted.
    fn list(&self) -> Result<Vec<String>>;

    fn contains(&self, name: &str) -> Result<bool>;

    fn get(&self, name: &str) -> Result<Option<Entry>>;

    /// Inserts or replaces an entry, persisting it immediately.
    fn put(&mut self, name: &str, entry: &Entry) -> Result<()>;

    /// Inserts a new entry, persisting it immediately. Fails with
    /// [`crate::Error::EntryExists`] if the name is taken, including by a process that
    /// added it since this store was opened.
    fn insert(&mut self, name: &str, entry: &Entry) -> Result<()>;

    /// Changes an entry as it is currently stored, not as it was read earlier, and
    /// returns the result: for the native store, under the lock, on the freshly read
    /// file. Fails with [`crate::Error::EntryGone`] if the entry was removed meanwhile.
    ///
    /// Used to advance HOTP counters, so a code is never generated twice.
    fn update(&mut self, name: &str, change: &mut dyn FnMut(&mut Entry)) -> Result<Entry>;

    /// Removes an entry. Returns whether it existed.
    fn remove(&mut self, name: &str) -> Result<bool>;

    /// Renames an entry. An entry already named `to` is replaced with `replace`,
    /// otherwise the rename fails with [`crate::Error::EntryExists`]. Returns whether
    /// `from` existed.
    fn rename(&mut self, from: &str, to: &str, replace: bool) -> Result<bool>;
}
