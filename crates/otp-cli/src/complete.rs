//! Dynamic shell completion of entry names (`COMPLETE=$SHELL otp`).

use std::ffi::OsStr;

use clap_complete::CompletionCandidate;
use otp_core::store::{Backend, NativeStore, PassStore, Store};

use crate::config::Config;
use crate::prompt::PasswordSource;

/// Completes entry names without ever prompting: pass names are read from the
/// filesystem, native names only when the master password is available
/// non-interactively (`OTP_PASSWORD` or `password_command`).
pub fn entry_names(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
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
    names.retain(|(name, _)| name.starts_with(current));
    names.sort();
    names.dedup_by(|a, b| a.0 == b.0);
    names
        .into_iter()
        .map(|(name, backend)| {
            CompletionCandidate::new(name).help(Some(backend.to_string().into()))
        })
        .collect()
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
