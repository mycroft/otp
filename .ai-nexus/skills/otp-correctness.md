---
name: otp-correctness
description: Code generation, otpauth URIs and stored entries
applies_to: ["crates/**/*.rs"]
---
otp generates TOTP and HOTP codes from stored secrets. A wrong code locks
the user out, so review the change for divergence from the RFCs and for
entries that change meaning:

- HOTP (RFC 4226): the counter as an 8-byte big-endian integer, dynamic
  truncation (offset from the low 4 bits of the last byte, 31-bit mask),
  the code modulo 10^digits, left-padded with zeros.
- TOTP (RFC 6238): `floor((now - t0) / period)`, the configured digits,
  period and algorithm (SHA-1, SHA-256, SHA-512) used rather than defaults;
  arithmetic that can overflow or go negative on odd clocks or periods.
- Secrets: base32 decoding that accepts what authenticators issue (lower
  case, spaces, missing padding) and rejects what is not base32, instead of
  silently producing another key.
- `otpauth://` URIs: label (`issuer:account`) and parameters percent-decoded
  and encoded symmetrically, so export then import gives the same entry.
- Stored entries: serialized fields renamed, removed or defaulted so that an
  existing store reads differently, or a HOTP counter not persisted after a
  code is shown.
- Panics outside tests: `unwrap`, `expect`, indexing, casts that truncate.

Do not report formatting or Clippy lints: CI runs both. Only report what is
visible in the diff and the files given.
