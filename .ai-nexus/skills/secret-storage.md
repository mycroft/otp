---
name: secret-storage
description: Master password, encryption and the pass backend
applies_to: ["crates/**/*.rs"]
---
otp stores MFA secrets in a native file encrypted with a master password
(Argon2 key derivation, XChaCha20-Poly1305 in a JSON envelope) or in
pass(1). Review the change for:

- A nonce reused or not drawn from the OS RNG for each encryption, a key
  derived with weaker Argon2 parameters than stored without the user's say,
  or envelope fields not covered by the authentication tag.
- Secrets, master passwords or derived keys that reach logs, error messages,
  shell completion output, the terminal (except a code asked for), or
  temporary files; buffers holding them that are not zeroized.
- Store writes that can lose the store: not written to a temporary file and
  renamed, or created with permissions others can read.
- The pass backend: entry names passed so that `pass` reads them as options
  (a leading `-`) or as paths outside the store (`..`), or commands built
  through a shell.
- Completion that prompts or decrypts the store when no password is
  available without a prompt.

Report only concrete, reachable problems in the changed code.
