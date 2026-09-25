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

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("system random number generator failed")]
    Rng,

    #[error("pass: {0}")]
    Pass(String),

    #[error("screenshot capture failed: {0}")]
    Capture(String),

    #[error("QR code: {0}")]
    Qr(String),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
