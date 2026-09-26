//! `otpauth://` URI parsing and formatting, following the Google Authenticator key URI format.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use url::Url;

use crate::otp::{DEFAULT_DIGITS, DEFAULT_PERIOD, decode_base32};
use crate::{Algorithm, Error, Kind, OtpSecret, Result};

const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'@');

impl OtpSecret {
    /// Parses an `otpauth://totp/...` or `otpauth://hotp/...` URI.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let uri = uri.trim();
        if uri.starts_with("otpauth-migration:") {
            return Err(Error::InvalidUri(
                "Google Authenticator export (otpauth-migration://) is not supported".into(),
            ));
        }
        let url = Url::parse(uri).map_err(|e| Error::InvalidUri(e.to_string()))?;
        if url.scheme() != "otpauth" {
            return Err(Error::InvalidUri(format!(
                "expected scheme otpauth, got {:?}",
                url.scheme()
            )));
        }
        let otp_type = url.host_str().unwrap_or_default().to_ascii_lowercase();

        let mut secret = None;
        let mut issuer = None;
        let mut algorithm = Algorithm::default();
        let mut digits = DEFAULT_DIGITS;
        let mut period = DEFAULT_PERIOD;
        let mut counter = None;
        for (key, value) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(&value)?),
                "issuer" if !value.is_empty() => issuer = Some(value.into_owned()),
                "algorithm" => algorithm = value.parse()?,
                "digits" => digits = parse_number(&key, &value)?,
                "period" => period = parse_number(&key, &value)?,
                "counter" => counter = Some(parse_number(&key, &value)?),
                _ => {}
            }
        }

        let kind = match otp_type.as_str() {
            "totp" => Kind::Totp { period },
            "hotp" => Kind::Hotp {
                counter: counter.unwrap_or(0),
            },
            other => {
                return Err(Error::InvalidUri(format!(
                    "unsupported OTP type {other:?} (expected totp or hotp)"
                )));
            }
        };

        let label = percent_decode_str(url.path().trim_start_matches('/'))
            .decode_utf8()
            .map_err(|e| Error::InvalidUri(format!("label is not valid UTF-8: {e}")))?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (non_empty(issuer), non_empty(account)),
            None => (None, non_empty(&label)),
        };

        let secret = secret.ok_or_else(|| Error::InvalidUri("missing secret parameter".into()))?;
        let mut otp = OtpSecret::new(secret, kind)?;
        otp.algorithm = algorithm;
        otp.digits = digits;
        otp.issuer = issuer.or(label_issuer);
        otp.account = account;
        otp.validate()?;
        Ok(otp)
    }

    /// Formats this secret as an `otpauth://` URI. The URI contains the secret.
    pub fn to_uri(&self) -> String {
        let encode = |s: &str| utf8_percent_encode(s, COMPONENT).to_string();
        let (otp_type, extra) = match self.kind {
            Kind::Totp { period } => ("totp", format!("&period={period}")),
            Kind::Hotp { counter } => ("hotp", format!("&counter={counter}")),
        };
        let label = match (&self.issuer, &self.account) {
            (Some(issuer), Some(account)) => format!("{}:{}", encode(issuer), encode(account)),
            (Some(issuer), None) => format!("{}:", encode(issuer)),
            (None, Some(account)) => encode(account),
            (None, None) => String::new(),
        };
        let mut uri = format!(
            "otpauth://{otp_type}/{label}?secret={}",
            self.secret_base32()
        );
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&encode(issuer));
        }
        uri.push_str(&format!(
            "&algorithm={}&digits={}{extra}",
            self.algorithm, self.digits
        ));
        uri
    }
}

fn parse_number<T: std::str::FromStr>(key: &str, value: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| Error::InvalidUri(format!("invalid {key} value {value:?}")))
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_google_example() {
        let otp = OtpSecret::from_uri(
            "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(otp.secret(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(otp.issuer.as_deref(), Some("Example"));
        assert_eq!(otp.account.as_deref(), Some("alice@google.com"));
        assert_eq!(otp.kind, Kind::Totp { period: 30 });
        assert_eq!(otp.algorithm, Algorithm::Sha1);
        assert_eq!(otp.digits, 6);
    }

    #[test]
    fn parses_all_parameters() {
        let otp = OtpSecret::from_uri(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\
             &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(otp.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(otp.account.as_deref(), Some("john.doe@email.com"));
        assert_eq!(otp.algorithm, Algorithm::Sha256);
        assert_eq!(otp.digits, 8);
        assert_eq!(otp.kind, Kind::Totp { period: 60 });
    }

    #[test]
    fn parses_hotp_and_account_only_label() {
        let otp = OtpSecret::from_uri(
            "otpauth://HOTP/bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=5",
        )
        .unwrap();
        assert_eq!(otp.kind, Kind::Hotp { counter: 5 });
        assert_eq!(otp.issuer, None);
        assert_eq!(otp.account.as_deref(), Some("bob"));
    }

    #[test]
    fn issuer_parameter_wins_over_label() {
        let otp = OtpSecret::from_uri("otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=New")
            .unwrap();
        assert_eq!(otp.issuer.as_deref(), Some("New"));
    }

    #[test]
    fn round_trips() {
        let original = OtpSecret::from_uri(
            "otpauth://hotp/ACME%20Co:j%2Bdoe@x.com?secret=JBSWY3DPEHPK3PXP\
             &issuer=ACME%20Co&algorithm=SHA512&digits=7&counter=42",
        )
        .unwrap();
        let uri = original.to_uri();
        assert!(uri.starts_with("otpauth://hotp/ACME%20Co:j%2Bdoe@x.com?secret=JBSWY3DPEHPK3PXP"));
        assert_eq!(OtpSecret::from_uri(&uri).unwrap(), original);
    }

    #[test]
    fn rejects_terminal_escapes_and_bidi_in_labels() {
        for uri in [
            // Clear screen, in the issuer parameter.
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=%1b%5b2J",
            // Set window title, in the label's account.
            "otpauth://totp/Issuer:%1b%5d0;PWNED%07?secret=JBSWY3DPEHPK3PXP",
            // OSC 52 clipboard write, in the label's issuer.
            "otpauth://totp/%1b%5d52;c;cHduZWQ=%07:alice?secret=JBSWY3DPEHPK3PXP",
            // C1 CSI.
            "otpauth://totp/a%c2%9b2Jb?secret=JBSWY3DPEHPK3PXP",
            // Right-to-left override.
            "otpauth://totp/Bank:%e2%80%aemoc.knab?secret=JBSWY3DPEHPK3PXP",
        ] {
            let error = OtpSecret::from_uri(uri).unwrap_err().to_string();
            assert!(error.contains("control or bidirectional"), "{uri}: {error}");
            assert!(
                !error.chars().any(crate::is_unsafe_char),
                "{error:?} echoes it"
            );
        }
        // Other Unicode is fine.
        let otp = OtpSecret::from_uri(
            "otpauth://totp/Soci%C3%A9t%C3%A9:%E6%97%A5%F0%9F%94%91?secret=JBSWY3DPEHPK3PXP",
        )
        .unwrap();
        assert_eq!(otp.issuer.as_deref(), Some("Société"));
        assert_eq!(otp.account.as_deref(), Some("日🔑"));
    }

    #[test]
    fn rejects_invalid_uris() {
        for uri in [
            "https://example.com/?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x",
            "otpauth://motp/x?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth-migration://offline?data=abc",
            "not a uri",
        ] {
            assert!(
                OtpSecret::from_uri(uri).is_err(),
                "{uri} should be rejected"
            );
        }
    }
}
