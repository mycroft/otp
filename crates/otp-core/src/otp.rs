use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Error, Result};

pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_PERIOD: u32 = 30;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(Error::InvalidOtp(format!("unsupported algorithm {s:?}"))),
        }
    }
}

/// Time-based (RFC 6238) or counter-based (RFC 4226) one-time password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Kind {
    Totp {
        period: u32,
    },
    /// `counter` is the value that will be used for the next generated code.
    Hotp {
        counter: u64,
    },
}

/// A generated one-time code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Code {
    pub value: String,
    /// For TOTP, how long the code remains valid.
    pub valid_for: Option<Duration>,
}

/// An OTP secret and its generation parameters.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpSecret {
    #[serde(with = "base32_serde")]
    secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    #[serde(flatten)]
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

impl OtpSecret {
    /// Creates a secret with default parameters (SHA1, 6 digits) of the given kind.
    pub fn new(secret: Vec<u8>, kind: Kind) -> Result<Self> {
        let otp = OtpSecret {
            secret,
            algorithm: Algorithm::default(),
            digits: DEFAULT_DIGITS,
            kind,
            issuer: None,
            account: None,
        };
        otp.validate()?;
        Ok(otp)
    }

    /// Creates a TOTP secret from a base32 string with default parameters.
    ///
    /// Parsing is lenient: whitespace, dashes, padding and lowercase letters are accepted.
    pub fn from_base32(secret: &str, kind: Kind) -> Result<Self> {
        Self::new(decode_base32(secret)?, kind)
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn secret_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.secret)
    }

    pub fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(Error::InvalidOtp("secret is empty".into()));
        }
        if !(1..=10).contains(&self.digits) {
            return Err(Error::InvalidOtp(format!(
                "digits must be between 1 and 10, got {}",
                self.digits
            )));
        }
        if let Kind::Totp { period: 0 } = self.kind {
            return Err(Error::InvalidOtp("period must be greater than 0".into()));
        }
        // Labels come from URIs and QR codes, so they may be crafted to be printed.
        for (what, label) in [("issuer", &self.issuer), ("account", &self.account)] {
            let unsafe_char = label
                .as_deref()
                .and_then(|label| label.chars().find(|&c| crate::is_unsafe_char(c)));
            if let Some(c) = unsafe_char {
                // Name the character, never echo the label: printing it is the danger.
                return Err(Error::InvalidOtp(format!(
                    "{what} contains a control or bidirectional formatting character \
                     (U+{:04X})",
                    c as u32
                )));
            }
        }
        Ok(())
    }

    /// Computes the HOTP value (RFC 4226) for a counter.
    pub fn hotp(&self, counter: u64) -> String {
        let msg = counter.to_be_bytes();
        let mut hash = match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(&self.secret, &msg),
            Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(&self.secret, &msg),
            Algorithm::Sha512 => mac::<Hmac<sha2::Sha512>>(&self.secret, &msg),
        };
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        hash.zeroize();
        let code = u64::from(binary) % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// Computes the TOTP value (RFC 6238) at a Unix timestamp, whatever this secret's kind.
    pub fn totp_at(&self, unix_time: u64, period: u32) -> String {
        self.hotp(unix_time / u64::from(period))
    }

    /// Generates the current code.
    ///
    /// For HOTP this consumes the counter: it is incremented, and the caller must persist
    /// the updated secret.
    pub fn generate(&mut self, now: SystemTime) -> Code {
        match &mut self.kind {
            Kind::Totp { period } => {
                let period = *period;
                let unix = now
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let remaining = u64::from(period) - unix % u64::from(period);
                Code {
                    value: self.totp_at(unix, period),
                    valid_for: Some(Duration::from_secs(remaining)),
                }
            }
            Kind::Hotp { counter } => {
                let current = *counter;
                *counter = current.wrapping_add(1);
                Code {
                    value: self.hotp(current),
                    valid_for: None,
                }
            }
        }
    }
}

impl Drop for OtpSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for OtpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpSecret")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish()
    }
}

fn mac<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let normalized: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(Error::InvalidOtp("secret is empty".into()));
    }
    BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|e| Error::InvalidOtp(format!("secret is not valid base32: {e}")))
}

mod base32_serde {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(secret: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&data_encoding::BASE32_NOPAD.encode(secret))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::decode_base32(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC4226_SECRET: &[u8] = b"12345678901234567890";

    fn secret(key: &[u8], algorithm: Algorithm, digits: u32) -> OtpSecret {
        let mut otp = OtpSecret::new(key.to_vec(), Kind::Totp { period: 30 }).unwrap();
        otp.algorithm = algorithm;
        otp.digits = digits;
        otp
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        let otp = secret(RFC4226_SECRET, Algorithm::Sha1, 6);
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(otp.hotp(counter as u64), *code, "counter {counter}");
        }
    }

    #[test]
    fn rfc6238_totp_vectors() {
        let sha1 = secret(b"12345678901234567890", Algorithm::Sha1, 8);
        let sha256 = secret(b"12345678901234567890123456789012", Algorithm::Sha256, 8);
        let sha512 = secret(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            Algorithm::Sha512,
            8,
        );
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, c1, c256, c512) in vectors {
            assert_eq!(sha1.totp_at(t, 30), c1, "SHA1 at {t}");
            assert_eq!(sha256.totp_at(t, 30), c256, "SHA256 at {t}");
            assert_eq!(sha512.totp_at(t, 30), c512, "SHA512 at {t}");
        }
    }

    #[test]
    fn generate_totp_reports_remaining_validity() {
        let mut otp = secret(RFC4226_SECRET, Algorithm::Sha1, 8);
        let code = otp.generate(UNIX_EPOCH + Duration::from_secs(59));
        assert_eq!(code.value, "94287082");
        assert_eq!(code.valid_for, Some(Duration::from_secs(1)));
    }

    #[test]
    fn generate_hotp_increments_counter() {
        let mut otp = OtpSecret::new(RFC4226_SECRET.to_vec(), Kind::Hotp { counter: 0 }).unwrap();
        assert_eq!(otp.generate(SystemTime::now()).value, "755224");
        assert_eq!(otp.generate(SystemTime::now()).value, "287082");
        assert_eq!(otp.kind, Kind::Hotp { counter: 2 });
    }

    #[test]
    fn base32_parsing_is_lenient() {
        let otp = OtpSecret::from_base32(
            "gezd gnbv-gy3t qojq gezd gnbv gy3t qojq====",
            Kind::Totp { period: 30 },
        )
        .unwrap();
        assert_eq!(otp.secret(), RFC4226_SECRET);
        assert_eq!(otp.secret_base32(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert!(OtpSecret::from_base32("", Kind::Totp { period: 30 }).is_err());
        assert!(OtpSecret::from_base32("not base32!", Kind::Totp { period: 30 }).is_err());
        assert!(OtpSecret::new(b"k".to_vec(), Kind::Totp { period: 0 }).is_err());
        let mut otp = secret(RFC4226_SECRET, Algorithm::Sha1, 6);
        otp.digits = 11;
        assert!(otp.validate().is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let otp = secret(RFC4226_SECRET, Algorithm::Sha1, 6);
        let debug = format!("{otp:?}");
        assert!(!debug.contains("GEZDGNBV"));
        assert!(!debug.contains("1234567890"));
    }

    #[test]
    fn serde_round_trip() {
        let mut otp = OtpSecret::new(RFC4226_SECRET.to_vec(), Kind::Hotp { counter: 7 }).unwrap();
        otp.issuer = Some("Example".into());
        let json = serde_json::to_value(&otp).unwrap();
        assert_eq!(json["type"], "hotp");
        assert_eq!(json["counter"], 7);
        assert_eq!(json["secret"], "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(json["algorithm"], "SHA1");
        let back: OtpSecret = serde_json::from_value(json).unwrap();
        assert_eq!(back, otp);
    }
}
