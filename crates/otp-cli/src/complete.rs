//! Dynamic shell completion of entry names (`COMPLETE=$SHELL otp`).

use std::collections::BTreeSet;
use std::ffi::OsStr;

use clap_complete::CompletionCandidate;
use otp_core::store::{Backend, NativeStore, PassStore, Store};

use crate::config::Config;
use crate::prompt::PasswordSource;

/// Completes entry names and the folders along their paths: `Web/amazon.fr/pm@mkz.me`
/// also offers `Web/` and `Web/amazon.fr/`.
///
/// Never prompts: pass names are read from the filesystem, native names only when the
/// master password is available non-interactively (`OTP_PASSWORD` or
/// `password_command`).
pub fn entry_names(current: &OsStr) -> Vec<CompletionCandidate> {
    candidates(current, true)
}

/// Completes folders only, for `otp insert`: new entries go into existing folders.
pub fn entry_folders(current: &OsStr) -> Vec<CompletionCandidate> {
    candidates(current, false)
}

fn candidates(current: &OsStr, with_entries: bool) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    let names = stored_names();
    let folders: BTreeSet<&str> = names
        .iter()
        .flat_map(|(name, _)| name.match_indices('/').map(|(i, _)| &name[..=i]))
        .collect();
    // Folders have no description; entries are labelled with their store.
    let mut candidates: Vec<(&str, Option<String>)> =
        folders.into_iter().map(|folder| (folder, None)).collect();
    if with_entries {
        candidates.extend(
            names
                .iter()
                .map(|(name, backend)| (name.as_str(), Some(backend.to_string()))),
        );
    }
    candidates.retain(|(value, _)| value.starts_with(current));
    // Sorted, each folder comes right before what it contains.
    candidates.sort();
    candidates.dedup_by(|a, b| a.0 == b.0);
    candidates
        .into_iter()
        .map(|(value, help)| CompletionCandidate::new(value).help(help.map(Into::into)))
        .collect()
}

/// `(name, store)` of every entry that can be listed without prompting.
fn stored_names() -> Vec<(String, Backend)> {
    let Ok(config) = Config::load() else {
        return Vec::new();
    };
    let only = config.backend();
    let mut names = Vec::new();
    if only != Some(Backend::Native) {
        let pass = PassStore::new(config.password_store_dir.clone());
        names.extend(names_in(&pass));
    }
    if only != Some(Backend::Pass) {
        names.extend(native_names(&config));
    }
    names.sort();
    names.dedup_by(|a, b| a.0 == b.0);
    names
}

fn names_in(store: &dyn Store) -> Vec<(String, Backend)> {
    let backend = store.backend();
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|name| (name, backend))
        .collect()
}

fn native_names(config: &Config) -> Vec<(String, Backend)> {
    let Ok(path) = config.database_path() else {
        return Vec::new();
    };
    if !NativeStore::exists(&path) {
        return Vec::new();
    }
    let source = PasswordSource::new(config.password_command.as_deref());
    let Some(Ok(password)) = source.non_interactive() else {
        return Vec::new();
    };
    match NativeStore::open(&path, password.as_bytes()) {
        Ok(store) => names_in(&store),
        Err(_) => Vec::new(),
    }
}
