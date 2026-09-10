//! `ikigai-encrypt` — public-key encryption as an ikigai module, the **dual of
//! `ikigai-sign`**. Signing proves *who*; encryption hides *what*.
//!
//! Two endpoints, over the [`age`](https://age-encryption.org) format (X25519
//! recipients, ChaCha20-Poly1305, ASCII armor):
//!
//! - `urn:encrypt:encrypt` — **open** (anyone may seal to a public key,
//!   which is exactly how an untrusted dropper encrypts a request to an inbox owner).
//!   Reads the plaintext as `in` (or piped `content`) and one or more recipient public
//!   keys from the `to` resource; emits ASCII-armored age ciphertext. **Multi-recipient**:
//!   the `to` resource may list several `age1…` keys (one per line), so an inbox can be
//!   sealed to *all* of an owner's devices at once and any of them opens it.
//! - `urn:encrypt:decrypt` — requires **`urn:cap:decrypt`**, since it needs
//!   the private key. Reads the armored ciphertext as `in` and the owner's identity from
//!   the `key` resource; emits the plaintext.
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

use age::armor::{ArmoredWriter, Format};
use age::x25519::{Identity, Recipient};
use async_trait::async_trait;
use ikigai_core::{
    ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, Iri, ReprType,
    Representation, Request, Result, Verb,
};
use std::io::{Read, Write};
use std::str::FromStr;

/// The capability gating decryption (it wields the private key). Encryption is open.
pub const CAP_DECRYPT: &str = "urn:cap:decrypt";

/// The `class` of a key-resource argument: an RDF resource (resolved through the kernel).
const RDFS_RESOURCE: &str = "http://www.w3.org/2000/01/rdf-schema#Resource";
/// The `class` of the plaintext/ciphertext byte arguments.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// Mount the module: `urn:encrypt:encrypt` + `urn:encrypt:decrypt`.
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:encrypt:encrypt"), Encrypt)
        .bind(Exact::new("urn:encrypt:decrypt"), Decrypt)
}

/// A `text/plain; charset=utf-8` representation of armored ciphertext.
fn armored(body: String) -> Representation {
    Representation::new(
        ReprType::new("text/plain").with_param("charset", "utf-8"),
        body.into_bytes(),
    )
}

/// Read the plaintext/ciphertext input: the `in` argument, falling back to piped `content`.
/// Neither present is the typed `MissingArgument` naming `in` — the declared required
/// input — so a validator and a caller see the contract, not a prose complaint.
fn read_input<'a>(inv: &'a Invocation<'_>) -> Result<&'a str> {
    inv.inline_str("in")
        .or_else(|_| inv.inline_str("content"))
        .map_err(|_| Error::MissingArgument("in".to_string()))
}

/// Resolve the `key`/`to` argument to its bytes THROUGH the kernel (cap-scoped), as a string.
///
/// The argument is an IRI, never key material — and the error for a non-IRI does NOT
/// echo the value: a caller who passes the identity itself as `key=` would otherwise
/// read their private key back in the error text, which travels through logs, traces
/// and MCP replies.
async fn resolve_key(inv: &Invocation<'_>, arg: &str, who: &str) -> Result<String> {
    let uri = inv
        .inline_str(arg)
        .map_err(|_| Error::MissingArgument(arg.to_string()))?;
    let iri = Iri::parse(uri).map_err(|_| Error::InvalidArgument {
        name: arg.to_string(),
        detail: format!(
            "{who}: `{arg}` must be an IRI naming a key resource (a `urn:file:`, a \
             `urn:secret:*`); the key itself is never passed by value"
        ),
    })?;
    let repr = inv.issue(Request::new(Verb::Source, iri)).await?;
    String::from_utf8(repr.bytes)
        .map_err(|_| Error::Endpoint(format!("{who}: key resource is not UTF-8 text")))
}

/// `urn:encrypt:encrypt` — seal `in` to the recipient public key(s) in `to`. Open.
pub struct Encrypt;

#[async_trait]
impl Endpoint for Encrypt {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        let plaintext = read_input(inv)?.as_bytes().to_vec();
        let key_text = resolve_key(inv, "to", "urn:encrypt:encrypt").await?;

        // One or more `age1…` recipients (one per non-empty line) → multi-recipient encrypt.
        let recipients: Vec<Recipient> = key_text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(Recipient::from_str)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: bad age recipient: {e}")))?;
        if recipients.is_empty() {
            return Err(Error::Endpoint(
                "urn:encrypt:encrypt: `to` has no age recipients (expected age1…)".to_string(),
            ));
        }

        let encryptor =
            age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
                .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: {e}")))?;

        let mut armored_out = Vec::new();
        let armor = ArmoredWriter::wrap_output(&mut armored_out, Format::AsciiArmor)
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: armor: {e}")))?;
        let mut writer = encryptor
            .wrap_output(armor)
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: {e}")))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: write: {e}")))?;
        let armor = writer
            .finish()
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: finish: {e}")))?;
        armor
            .finish()
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: armor finish: {e}")))?;

        let text = String::from_utf8(armored_out)
            .map_err(|_| Error::Endpoint("urn:encrypt:encrypt: armor not UTF-8".to_string()))?;
        // NOT cacheable, by construction: age mints a fresh ephemeral X25519 key and
        // file key per call, so two encryptions of the same plaintext to the same
        // recipients are different bytes. A cached ciphertext would be a function of
        // nothing — served forever, byte-identical, under whatever thread the
        // recipient resource carried — and `Expiry::Always` is the only honest
        // expiry for a non-deterministic result. (Correctness would survive a cache;
        // the contract "every call is a fresh sealing" would not.)
        Ok(armored(text))
    }

    fn name(&self) -> &str {
        "encrypt"
    }

    fn describe(&self) -> Description {
        Description::new("encrypt")
            .title("Encrypt (age / X25519)")
            .summary(
                "Seal bytes to one or more recipient public keys (age X25519), emitting ASCII-\
                 armored age ciphertext. Pass the bytes as `in` (or pipe them as `content`) and \
                 the recipient key resource as `to=` (a `urn:…`/`file:` resolving to one or more \
                 `age1…` recipients, one per line — multi-recipient, so an inbox seals to every \
                 device). Open: anyone may encrypt to a public key. No keygen here.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .input(
                ArgSpec::new("in")
                    .summary("the bytes to encrypt (positional or piped as `content`)")
                    .class(XSD_STRING),
            )
            // ONE resource IRI, whose bytes list one or more `age1…` recipients (one per
            // line). The list lives inside the resource, so the argument itself is a single
            // reference and `rdfs:Resource` is its true class; a by-value recipient LIST
            // would have no ArgSpec spelling (conformance PENDING #15) and is not offered.
            .input(
                ArgSpec::new("to")
                    .summary(
                        "recipient public-key resource: ONE IRI whose bytes list one or more \
                         age1… recipients, one per line",
                    )
                    .class(RDFS_RESOURCE),
            )
            .output("text/plain;charset=utf-8")
    }
}

/// `urn:encrypt:decrypt` — open `in` with the identity in `key`. Requires `urn:cap:decrypt`.
pub struct Decrypt;

#[async_trait]
impl Endpoint for Decrypt {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        if !inv.capability.allows(CAP_DECRYPT) {
            return Err(Error::Denied(format!(
                "urn:encrypt:decrypt requires the {CAP_DECRYPT} capability"
            )));
        }
        let ciphertext = read_input(inv)?.to_string();
        let key_text = resolve_key(inv, "key", "urn:encrypt:decrypt").await?;
        let identity = Identity::from_str(key_text.trim())
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:decrypt: bad age identity: {e}")))?;

        let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:decrypt: {e}")))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| Error::Denied(format!("urn:encrypt:decrypt: {e}")))?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| Error::Endpoint(format!("urn:encrypt:decrypt: read: {e}")))?;

        // A pure function of the ciphertext and the identity: the same two inputs
        // open to the same bytes every time. Marked cacheable and declaring no
        // thread of its own — the kernel folds the `key` sub-resolution's expiry and
        // golden threads into this result, so the plaintext is EXACTLY as cacheable
        // as the identity resource it was opened with: cached under the keystore's
        // thread when the key is served under one (a `urn:file:` mount), and
        // recomputed on every call when the key is served live (a secret backend).
        // The cache keys on the capability fingerprint, so a caller without
        // `urn:cap:decrypt` never sees a cached plaintext. What this cannot do is
        // notice a rotation: a plaintext cached under a key thread is served until
        // the keystore CUTS that thread (README, "Caching").
        Ok(Representation::new(ReprType::new("application/octet-stream"), plaintext).cacheable())
    }

    fn name(&self) -> &str {
        "decrypt"
    }

    fn describe(&self) -> Description {
        Description::new("decrypt")
            .title("Decrypt (age / X25519)")
            .summary(
                "Open ASCII-armored age ciphertext with a kernel-resolved identity. Pass the \
                 ciphertext as `in` (or piped `content`) and the identity resource as `key=` (an \
                 `AGE-SECRET-KEY-1…`). Requires the urn:cap:decrypt capability (it wields the \
                 private key); a wrong key or tampered ciphertext is a typed Denied/error.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .requires(CAP_DECRYPT)
            .input(
                ArgSpec::new("in")
                    .summary("the armored age ciphertext (positional or piped as `content`)")
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("key")
                    .summary("the owner's identity resource (AGE-SECRET-KEY-1…)")
                    .class(RDFS_RESOURCE),
            )
            .output("application/octet-stream")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use futures::executor::block_on;
    use ikigai_core::{ArgRef, Capability, FnEndpoint, Kernel, Result as CoreResult};
    use std::sync::Arc;

    /// A kernel that serves a generated age keypair as two resources (pub at `urn:key:pub`,
    /// identity at `urn:key:id`) plus the encrypt/decrypt endpoints — so the round-trip runs
    /// through the real kernel, keys resolved as resources exactly as in production.
    fn kernel_with_key() -> (Kernel, String, String) {
        let id = Identity::generate();
        let recipient = id.to_public().to_string(); // age1…
        let secret = id.to_string().expose_secret().to_string(); // AGE-SECRET-KEY-1…
        let (rc, sc) = (recipient.clone(), secret.clone());
        let pub_ep = FnEndpoint::new("k-pub", move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                rc.clone().into_bytes(),
            ))
        });
        let id_ep = FnEndpoint::new("k-id", move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                sc.clone().into_bytes(),
            ))
        });
        let space = space()
            .bind(Exact::new("urn:key:pub"), pub_ep)
            .bind(Exact::new("urn:key:id"), id_ep);
        (Kernel::new(Arc::new(space)), recipient, secret)
    }

    fn decrypt_cap() -> Capability {
        Capability::scoped(["urn:cap:decrypt"])
    }

    fn encrypt(k: &Kernel, plaintext: &str, cap: &Capability) -> CoreResult<Vec<u8>> {
        let req = Request::new(Verb::Source, Iri::parse("urn:encrypt:encrypt").unwrap())
            .with_arg("in", ArgRef::Inline(plaintext.as_bytes().to_vec()))
            .with_arg("to", ArgRef::Inline(b"urn:key:pub".to_vec()));
        block_on(k.issue(req, cap)).map(|r| r.bytes)
    }

    fn decrypt(k: &Kernel, ciphertext: &[u8], key: &str, cap: &Capability) -> CoreResult<Vec<u8>> {
        let req = Request::new(Verb::Source, Iri::parse("urn:encrypt:decrypt").unwrap())
            .with_arg("in", ArgRef::Inline(ciphertext.to_vec()))
            .with_arg("key", ArgRef::Inline(key.as_bytes().to_vec()));
        block_on(k.issue(req, cap)).map(|r| r.bytes)
    }

    #[test]
    fn round_trips_through_the_kernel() {
        let (k, _r, _s) = kernel_with_key();
        let ct = encrypt(
            &k,
            "attack at dawn",
            &Capability::scoped(Vec::<String>::new()),
        )
        .unwrap();
        // Ciphertext is armored age, not the plaintext.
        let ct_str = String::from_utf8(ct.clone()).unwrap();
        assert!(
            ct_str.contains("BEGIN AGE ENCRYPTED FILE"),
            "expected armored age, got: {ct_str}"
        );
        assert!(!ct_str.contains("attack at dawn"));
        // Decrypt with the identity recovers the plaintext.
        let pt = decrypt(&k, &ct, "urn:key:id", &decrypt_cap()).unwrap();
        assert_eq!(String::from_utf8(pt).unwrap(), "attack at dawn");
    }

    #[test]
    fn encrypt_is_open_no_cap_needed() {
        // Encryption to a public key needs no capability (the dropper case).
        let (k, _r, _s) = kernel_with_key();
        assert!(encrypt(&k, "hi", &Capability::scoped(Vec::<String>::new())).is_ok());
    }

    #[test]
    fn decrypt_without_cap_is_denied() {
        let (k, _r, _s) = kernel_with_key();
        let ct = encrypt(&k, "secret", &Capability::scoped(Vec::<String>::new())).unwrap();
        let err = decrypt(
            &k,
            &ct,
            "urn:key:id",
            &Capability::scoped(Vec::<String>::new()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Denied(_)));
        assert!(!err.is_transient());
    }

    #[test]
    fn a_wrong_identity_cannot_decrypt() {
        let (k, _r, _s) = kernel_with_key();
        let ct = encrypt(&k, "secret", &Capability::scoped(Vec::<String>::new())).unwrap();
        // A different identity string.
        let other = Identity::generate().to_string().expose_secret().to_string();
        assert!(
            decrypt(&k, &ct, &other, &decrypt_cap()).is_err(),
            "wrong key must not decrypt"
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (k, _r, _s) = kernel_with_key();
        let mut ct = encrypt(&k, "secret", &Capability::scoped(Vec::<String>::new())).unwrap();
        // Flip a byte in the armored body (skip the header).
        if let Some(b) = ct.get_mut(120) {
            *b ^= 0x01;
        }
        assert!(decrypt(&k, &ct, "urn:key:id", &decrypt_cap()).is_err());
    }

    #[test]
    fn describe_declares_the_cap_and_argspec() {
        let d = Decrypt.describe();
        assert_eq!(d.requires, vec![CAP_DECRYPT.to_string()]);
        assert!(d.inputs.iter().any(|a| a.name == "key"));
        let e = Encrypt.describe();
        assert!(e.requires.is_empty(), "encrypt is open");
        assert!(e.inputs.iter().any(|a| a.name == "to"));
    }
}
