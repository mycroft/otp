use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{Error, OtpSecret, Result};

/// Bookkeeping stored alongside a secret.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
}

/// A stored secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub otp: OtpSecret,
    #[serde(flatten)]
    pub meta: Metadata,
}

impl Entry {
    /// Creates an entry stamped with the current time.
    pub fn new(otp: OtpSecret) -> Self {
        let now = now();
        Entry {
            otp,
            meta: Metadata {
                created_at: Some(now),
                updated_at: Some(now),
            },
        }
    }

    pub fn touch(&mut self) {
        self.meta.updated_at = Some(now());
    }
}

fn now() -> OffsetDateTime {
    // Drop sub-second precision to keep stored timestamps readable.
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0).unwrap_or(now)
}

/// Whether `c` could act on a terminal or disguise text when printed: C0 and C1 control
/// characters (escape sequences start with ESC or CSI), DEL, and the Unicode bidirectional
/// overrides, isolates and marks, which can make text display in a misleading order.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// Checks that an entry name is a safe, pass-compatible relative path such as
/// `google.com/alice@gmail.com`.
pub fn validate_name(name: &str) -> Result<()> {
    let invalid = |reason| {
        Err(Error::InvalidName {
            name: name.to_string(),
            reason,
        })
    };
    if name.is_empty() {
        return invalid("name is empty");
    }
    if name.starts_with('-') {
        return invalid("name must not start with '-'");
    }
    if name.chars().any(|c| is_unsafe_char(c) || c == '\\') {
        return invalid(
            "name must not contain control characters, bidirectional formatting \
             characters or backslashes",
        );
    }
    for component in name.split('/') {
        match component {
            "" => return invalid("name must not contain empty path components"),
            "." | ".." => return invalid("name must not contain '.' or '..' components"),
            c if c.starts_with('.') => {
                return invalid("path components must not start with '.'");
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_names() {
        for name in [
            "google.com/codingmyc@gmail.com",
            "github",
            "work/aws/root",
            "a b/c-d",
        ] {
            validate_name(name).unwrap();
        }
    }

    #[test]
    fn rejects_unsafe_names() {
        for name in [
            "",
            "/abs",
            "trailing/",
            "a//b",
            "../x",
            "a/../b",
            "./a",
            "-rf",
            ".hidden",
            "a/.git",
            "a\\b",
            "a\nb",
            "a\u{1b}[2Jb",
            "\u{202E}gro.elgoog",
            "a\u{2066}b",
            "a\u{9b}b",
        ] {
            assert!(validate_name(name).is_err(), "{name:?} should be rejected");
        }
    }

    #[test]
    fn unsafe_chars() {
        for c in [
            '\u{1b}', '\u{7}', '\u{7f}', '\u{9b}', '\u{202E}', '\u{2067}', '\u{200F}',
        ] {
            assert!(is_unsafe_char(c), "{c:?}");
        }
        for c in ['a', 'é', '@', ' ', '日', '🔑', '\u{200D}'] {
            assert!(!is_unsafe_char(c), "{c:?}");
        }
    }

    #[test]
    fn metadata_serializes_as_rfc3339() {
        let meta = Metadata {
            created_at: Some(time::macros::datetime!(2026-09-25 10:00:00 UTC)),
            updated_at: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert_eq!(
            json,
            r#"{"created_at":"2026-09-25T10:00:00Z","updated_at":null}"#
        );
        assert_eq!(serde_json::from_str::<Metadata>(&json).unwrap(), meta);
        assert_eq!(
            serde_json::from_str::<Metadata>("{}").unwrap(),
            Metadata::default()
        );
    }
}
