use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),

    #[error("invalid OTP parameters: {0}")]
    InvalidOtp(String),

    #[error("invalid entry name {name:?}: {reason}")]
    InvalidName { name: String, reason: &'static str },

    #[error("wrong master password or corrupted database")]
    Decrypt,

    #[error("unsupported database: {0}")]
    DatabaseFormat(String),

    #[error("database already exists at {0}")]
    DatabaseExists(String),

    #[error(
        "the master password of {0} was changed by another otp since it was opened; \
         nothing was saved, run the command again"
    )]
    DatabaseChanged(String),

    #[error("{0} already exists")]
    EntryExists(String),

    #[error("{0} is not in the store anymore (removed or renamed meanwhile?)")]
    EntryGone(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("system random number generator failed")]
    Rng,

    #[error("pass: {0}")]
    Pass(String),

    #[error("screenshot capture failed: {0}")]
    Capture(String),

    #[error("QR code viewer: {0}")]
    Viewer(String),

    #[error("QR code: {0}")]
    Qr(String),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
