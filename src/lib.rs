//! `ikigai-encrypt` — public-key encryption as an ikigai module, the **dual of
//! `ikigai-sign`**. Signing proves *who*; encryption hides *what*.
//!
//! Two faces, over one implementation of age:
//!
//! - **The library**, [`age`]: [`age::seal`], [`age::open`], [`age::parse_identities`] and
//!   [`age::parse_recipients`], with no kernel. It builds with `default-features = false`,
//!   for a host that seals its own files.
//! - **The endpoints**, behind the default `endpoints` feature, are thin calls into it.
//!
//! ## Features
//!
//! - `endpoints` (default): the kernel endpoints and `space()`. Brings in `ikigai-core` and
//!   implies `armor`.
//! - `armor` (default, through `endpoints`): `age::seal_armored`, and armored input to
//!   [`age::open`].
//!
//! A library consumer takes `ikigai-encrypt = { version = "…", default-features = false }`
//! and gets binary age and the key parsing, without the kernel or the armor code.
//!
//! ## The endpoints
//!
//! Two endpoints, over the [`age`](https://age-encryption.org) format (X25519
//! recipients, ChaCha20-Poly1305, ASCII armor):
//!
//! - `urn:encrypt:encrypt` — **open** (anyone may seal to a public key,
//!   which is exactly how an untrusted dropper encrypts a request to an inbox owner).
//!   Reads the plaintext (any bytes) as `in` (or piped `content`) and one or more recipient public
//!   keys from the `to` resource; emits ASCII-armored age ciphertext. **Multi-recipient**:
//!   the `to` resource may list several `age1…` keys (one per line), so an inbox can be
//!   sealed to *all* of an owner's devices at once and any of them opens it.
//! - `urn:encrypt:decrypt` — requires **`urn:cap:decrypt`**, since it needs
//!   the private key. Reads the age ciphertext (armored or binary) as `in` and the
//!   owner's identity file from the `key` resource; emits the plaintext.
//!
//! Keys are resolved **through the kernel** (`inv.source` on the URI, cap-scoped) — an
//! `age` recipient (`age1…`) or identity (`AGE-SECRET-KEY-1…`) from a `urn:file:` or a
//! `urn:secret:*`. **No keygen here** — minting keys is the secret module's job,
//! exactly as `ikigai-sign` leaves keygen to the secret module.
//!
//! **Caching.** Encryption is never cacheable (a fresh ephemeral key per call makes
//! every ciphertext different bytes); decryption is a pure function of ciphertext and
//! identity, marked cacheable, and inherits its EFFECTIVE cacheability from the
//! identity resource — cached under the keystore's thread, or live over a live
//! keystore. Neither endpoint holds key material, watches anything, or names a
//! thread of its own. `tests/conformance.rs` pins all of it.
#![forbid(unsafe_code)]

pub mod age;

#[cfg(feature = "endpoints")]
mod endpoints;
#[cfg(feature = "endpoints")]
pub use endpoints::{space, Decrypt, Encrypt, SPACE_ID};

/// The capability gating decryption (it wields the private key). Encryption is open.
pub const CAP_DECRYPT: &str = "urn:cap:decrypt";
