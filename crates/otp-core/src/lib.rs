//! Core library for storing MFA secrets and generating one-time passwords.
//!
//! - [`OtpSecret`] holds a TOTP/HOTP secret and generates codes (RFC 4226 / RFC 6238).
//! - [`OtpSecret::from_uri`] / [`OtpSecret::to_uri`] handle `otpauth://` URIs.
//! - [`store`] provides the storage backends: an encrypted native database and pass(1).
//! - [`qr`] decodes `otpauth://` URIs from QR code images or screenshots.

mod entry;
mod error;
mod otp;
pub mod qr;
pub mod store;
mod uri;

pub use entry::{Entry, Metadata, is_unsafe_char, validate_name};
pub use error::{Error, Result};
pub use otp::{Algorithm, Code, Kind, OtpSecret};
