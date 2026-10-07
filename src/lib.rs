//! `ikigai-encrypt` — public-key encryption as an ikigai module, the **dual of
//! `ikigai-sign`**. Signing proves *who*; encryption hides *what*.
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

use age::armor::{ArmoredWriter, Format};
use age::x25519::{Identity, Recipient};
use async_trait::async_trait;
use ikigai_core::{
    ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation, Iri, ReprType,
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

/// Refuse every verb but Source. Both endpoints declare Source (and Meta, which the
/// KERNEL answers from the description without entering the endpoint), and the kernel
/// dispatches an undeclared verb all the same; before this check an `Exists`, `Sink`
/// or `Delete` on `urn:encrypt:encrypt` sealed, and a `Sink` would then have cut the
/// endpoint's own thread. Core has no typed "verb not supported" error, so this is
/// the ecosystem's spelling of one (`ikigai-ledger`, `ikigai-log`).
fn source_only(who: &str, verb: Verb) -> Result<()> {
    if verb == Verb::Source {
        Ok(())
    } else {
        Err(Error::Endpoint(format!(
            "`{who}` answers only Source; it does not answer {verb:?}"
        )))
    }
}

/// Where the input bytes come from: `in`, or, only when `in` is ABSENT, the pipe's
/// spelling of it, `content`. A present `in` is never passed over for `content`,
/// whatever it holds (before this, a non-UTF-8 `in` fell through to `content` and the
/// module sealed or opened the wrong bytes, silently). Neither present is the typed
/// `MissingArgument` naming `in`, the declared required input. Looks at nothing but
/// the request, so a call refused here has read nothing.
fn input_arg<'a>(inv: &'a Invocation<'_>) -> Result<(&'static str, &'a ArgRef)> {
    ["in", "content"]
        .into_iter()
        .find_map(|name| inv.request.args.get(name).map(|arg| (name, arg)))
        .ok_or_else(|| Error::MissingArgument("in".to_string()))
}

/// The input's BYTES, whatever they are: plaintext is any bytes, and ciphertext is
/// armored or binary age. An inline value is the bytes; a reference is dereferenced
/// through the kernel (cap-scoped, and recorded as a dependency, so a plaintext opened
/// from a ciphertext resource is no more cacheable than that resource).
async fn input_bytes(inv: &Invocation<'_>, who: &str) -> Result<Vec<u8>> {
    let (name, arg) = input_arg(inv)?;
    match arg {
        ArgRef::Inline(bytes) => Ok(bytes.clone()),
        ArgRef::Reference(iri) => inv
            .source(iri)
            .await
            .map(|repr| repr.bytes)
            .map_err(|e| sub_failure(who, name, iri, e)),
        ArgRef::Content(_) => Err(not_content_addressed(who, name)),
    }
}

/// The refusal for an `ArgRef::Content` argument. An invocation carries no content
/// store, so an endpoint has no way to read a content-addressed value; saying so beats
/// the `MissingArgument` it used to be reported as.
fn not_content_addressed(who: &str, name: &str) -> Error {
    Error::InvalidArgument {
        name: name.to_string(),
        detail: format!(
            "{who}: a content-addressed value cannot be read here (an invocation carries no \
             content store); pass `{name}` inline or by reference"
        ),
    }
}

/// The IRI of the `key`/`to` resource. Looks at nothing but the request.
///
/// Inline, the argument is the IRI's text; by reference (`ArgRef::Reference`, core's
/// own spelling of "another resolvable resource", and the argument's declared class
/// is `rdfs:Resource`) it IS the IRI, and resolves exactly as the by-name spelling
/// does. Anything present that is not an IRI is an `InvalidArgument` naming the
/// argument, never `MissingArgument`. The error does NOT echo the value: a caller who
/// passes the identity itself as `key=` would otherwise read their private key back
/// in the error text, which travels through logs, traces and MCP replies.
fn key_iri(inv: &Invocation<'_>, arg: &str, who: &str) -> Result<Iri> {
    let not_an_iri = || Error::InvalidArgument {
        name: arg.to_string(),
        detail: format!(
            "{who}: `{arg}` must be an IRI naming a key resource (a `urn:file:`, a \
             `urn:secret:*`); the key itself is never passed by value"
        ),
    };
    match inv.request.args.get(arg) {
        None => Err(Error::MissingArgument(arg.to_string())),
        Some(ArgRef::Reference(iri)) => Ok(iri.clone()),
        Some(ArgRef::Inline(bytes)) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| Iri::parse(text).ok())
            .ok_or_else(not_an_iri),
        Some(ArgRef::Content(_)) => Err(not_content_addressed(who, arg)),
    }
}

/// Resolve the key resource THROUGH the kernel (cap-scoped), as text.
async fn resolve_key(inv: &Invocation<'_>, iri: &Iri, arg: &str, who: &str) -> Result<String> {
    let repr = inv
        .issue(Request::new(Verb::Source, iri.clone()))
        .await
        .map_err(|e| sub_failure(who, arg, iri, e))?;
    String::from_utf8(repr.bytes).map_err(|_| Error::InvalidArgument {
        name: arg.to_string(),
        detail: format!("{who}: the `{arg}` resource {iri} is not UTF-8 text"),
    })
}

/// A sub-request for an ARGUMENT failed: report it against that argument, naming the
/// resource, never as the outer call's own failure. Passed up unchanged, a key
/// resource that lacked its own `in` answered "missing `in`" to a caller who had passed
/// `in`, and an unbound key IRI answered `Unresolved`, which says the endpoint the
/// caller named does not exist. Three kinds keep their kind, because they mean the same
/// thing one level down as at the top: `Denied` (the caller lacks the grant to read the
/// key) and the transient `Timeout`/`Unavailable` (a retry may succeed). Every other
/// failure, `NotFound` included, is the argument naming nothing usable.
fn sub_failure(who: &str, arg: &str, iri: &Iri, error: Error) -> Error {
    let context = format!("{who}: reading the `{arg}` resource {iri}");
    match error {
        Error::Denied(m) => Error::Denied(format!("{context}: {m}")),
        Error::Timeout(m) => Error::Timeout(format!("{context}: {m}")),
        Error::Unavailable(m) => Error::Unavailable(format!("{context}: {m}")),
        other => Error::InvalidArgument {
            name: arg.to_string(),
            detail: format!("{context} failed: {other}"),
        },
    }
}

/// Parse an identity file in age's format, as `age-keygen -o key.txt` writes it and
/// `age -d -i` reads it: one `AGE-SECRET-KEY-1…` per line, blank lines and `#` comments
/// skipped, any number of identities (any one that matches opens the file). Lines are
/// trimmed, a superset of age's own parser. Plugin identities are not supported (this
/// module runs no plugins). A bad line is named by NUMBER, never echoed.
fn parse_identities(key_text: &str) -> Result<Vec<Identity>> {
    let invalid = |detail: String| Error::InvalidArgument {
        name: "key".to_string(),
        detail,
    };
    let mut identities = Vec::new();
    for (number, line) in key_text.lines().enumerate().map(|(n, l)| (n + 1, l.trim())) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        identities.push(Identity::from_str(line).map_err(|e| {
            invalid(format!(
                "urn:encrypt:decrypt: bad age identity on line {number}: {e}"
            ))
        })?);
    }
    if identities.is_empty() {
        return Err(invalid(
            "urn:encrypt:decrypt: the `key` resource holds no age identity (expected \
             AGE-SECRET-KEY-1…)"
                .to_string(),
        ));
    }
    Ok(identities)
}

/// The fixed scalar the low-order check multiplies by. Any scalar works once
/// X25519 clamps it (a multiple of 8, so it annihilates every point of order 1, 2, 4
/// or 8, on the curve or its twist) provided it is not a multiple of the prime
/// subgroup order, which would annihilate honest keys too; a unit test pins that it
/// is not (`the_probe_scalar_is_not_degenerate`).
const LOW_ORDER_PROBE: [u8; 32] = [0x42; 32];

/// The 32-byte u-coordinate of an `age1…` recipient, decoded exactly as `age` 0.11
/// decodes it (bech32 0.9, the Bech32 variant, HRP `age`). `age::x25519::Recipient`
/// does not expose its bytes, so the string is decoded a second time here; `None`
/// is a spelling age accepted and this decoder did not, and is refused rather than
/// sealed to unchecked.
fn recipient_point(recipient: &str) -> Option<[u8; 32]> {
    use bech32::FromBase32;
    let (hrp, data, variant) = bech32::decode(recipient).ok()?;
    if hrp != "age" || variant != bech32::Variant::Bech32 {
        return None;
    }
    Vec::<u8>::from_base32(&data).ok()?.try_into().ok()
}

/// Whether X25519 with a clamped scalar sends this point to the all-zero output.
///
/// That is the condition `age` 0.11 PANICS on when it seals (`x25519.rs`, "Generated
/// the all-zero esk"), and a sealing that did not panic would be worse: the wrapped
/// file key would be derivable by anyone. The check is the scalar multiplication
/// itself rather than a list of known small-order u-coordinates because it is the
/// SAME function age runs (x25519-dalek, the same masking of bit 255 and reduction
/// mod p): a list has to enumerate the non-canonical spellings (u ≥ p, bit 255 set)
/// and is right only as far as it is complete; this cannot disagree with age.
fn is_low_order(point: [u8; 32]) -> bool {
    let probe = x25519_dalek::StaticSecret::from(LOW_ORDER_PROBE);
    !probe
        .diffie_hellman(&x25519_dalek::PublicKey::from(point))
        .was_contributory()
}

/// Parse the recipient list: one `age1…` per line, blank lines and `#` comments
/// skipped. A low-order point is a typed `InvalidArgument` on `to` naming the LINE
/// (never the key: the module does not echo what it read), and it refuses the whole
/// list; sealing to the rest would silently drop a device the caller named.
fn parse_recipients(key_text: &str) -> Result<Vec<Recipient>> {
    let mut recipients = Vec::new();
    for (number, line) in key_text.lines().enumerate().map(|(n, l)| (n + 1, l.trim())) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let recipient = Recipient::from_str(line).map_err(|e| Error::InvalidArgument {
            name: "to".to_string(),
            detail: format!("urn:encrypt:encrypt: bad age recipient on line {number}: {e}"),
        })?;
        match recipient_point(line) {
            Some(point) if !is_low_order(point) => recipients.push(recipient),
            Some(_) => {
                return Err(Error::InvalidArgument {
                    name: "to".to_string(),
                    detail: format!(
                        "urn:encrypt:encrypt: the recipient on line {number} is a low-order \
                         X25519 point; anyone could open a file sealed to it, so it is refused"
                    ),
                })
            }
            None => {
                return Err(Error::InvalidArgument {
                    name: "to".to_string(),
                    detail: format!(
                        "urn:encrypt:encrypt: the recipient on line {number} could not be \
                         decoded for the low-order check"
                    ),
                })
            }
        }
    }
    Ok(recipients)
}

/// Run `f`, turning a panic inside it into a typed error.
///
/// The low-order check stops the one panic the audit found, but `age` is a library
/// that still answers some states with `panic!`, and this module is reachable by a
/// caller holding nothing. A host that does not catch unwinds (the MCP projection
/// is one) would go down with it, so a panic in the sealing or opening is contained
/// HERE and answered as an error. The panic's message is not echoed: it comes from
/// code that held the plaintext or the identity, and error text travels through
/// logs, traces and MCP replies (the panic hook still prints it to stderr).
///
/// `AssertUnwindSafe` is sound here because `f` owns everything it touches: its
/// buffers are dropped by the unwind and nothing it could have left half-written is
/// observed afterwards.
fn contained<T>(who: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        Err(Error::Endpoint(format!(
            "{who}: the age library panicked; the panic was contained and nothing was produced"
        )))
    })
}

/// Seal `plaintext` to `recipients` as ASCII-armored age.
fn seal(plaintext: &[u8], recipients: &[Recipient]) -> Result<String> {
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
        .write_all(plaintext)
        .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: write: {e}")))?;
    let armor = writer
        .finish()
        .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: finish: {e}")))?;
    armor
        .finish()
        .map_err(|e| Error::Endpoint(format!("urn:encrypt:encrypt: armor finish: {e}")))?;

    String::from_utf8(armored_out)
        .map_err(|_| Error::Endpoint("urn:encrypt:encrypt: armor not UTF-8".to_string()))
}

/// Open age `ciphertext`, armored or binary (`ArmoredReader` passes binary through),
/// with whichever of `identities` matches.
fn open(ciphertext: &[u8], identities: &[Identity]) -> Result<Vec<u8>> {
    let decryptor =
        age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext)).map_err(|e| {
            Error::InvalidArgument {
                name: "in".to_string(),
                detail: format!(
                    "urn:encrypt:decrypt: `in` is not age ciphertext (armored or binary): {e}"
                ),
            }
        })?;
    let mut reader = decryptor
        .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
        .map_err(|e| Error::Denied(format!("urn:encrypt:decrypt: {e}")))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| Error::Endpoint(format!("urn:encrypt:decrypt: read: {e}")))?;
    Ok(plaintext)
}

/// `urn:encrypt:encrypt` — seal `in` to the recipient public key(s) in `to`. Open.
pub struct Encrypt;

#[async_trait]
impl Endpoint for Encrypt {
    async fn invoke(&self, inv: &Invocation<'_>) -> Result<Representation> {
        const WHO: &str = "urn:encrypt:encrypt";
        source_only(WHO, inv.request.verb)?;
        // Every argument's SHAPE first, then the reads: a call refused for a missing or
        // malformed argument has resolved nothing.
        input_arg(inv)?;
        let to = key_iri(inv, "to", WHO)?;
        let plaintext = input_bytes(inv, WHO).await?;
        let key_text = resolve_key(inv, &to, "to", WHO).await?;

        // One or more `age1…` recipients (one per non-empty line) → multi-recipient
        // encrypt, every one of them checked for low order before age sees it.
        let recipients = parse_recipients(&key_text)?;
        if recipients.is_empty() {
            return Err(Error::InvalidArgument {
                name: "to".to_string(),
                detail: "urn:encrypt:encrypt: the `to` resource holds no age recipient                          (expected age1…)"
                    .to_string(),
            });
        }

        let text = contained("urn:encrypt:encrypt", || seal(&plaintext, &recipients))?;
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
                    .summary("the bytes to encrypt, any bytes (positional or piped as `content`)")
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
        const WHO: &str = "urn:encrypt:decrypt";
        source_only(WHO, inv.request.verb)?;
        if !inv.capability.allows(CAP_DECRYPT) {
            return Err(Error::Denied(format!(
                "urn:encrypt:decrypt requires the {CAP_DECRYPT} capability"
            )));
        }
        input_arg(inv)?;
        let key = key_iri(inv, "key", WHO)?;
        let ciphertext = input_bytes(inv, WHO).await?;
        let key_text = resolve_key(inv, &key, "key", WHO).await?;
        let identities = parse_identities(&key_text)?;

        let plaintext = contained(WHO, || open(&ciphertext, &identities))?;

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
                "Open age ciphertext (ASCII-armored or binary) with a kernel-resolved identity. \
                 Pass the ciphertext as `in` (or piped `content`) and the identity resource as \
                 `key=` (an age identity file: one or more `AGE-SECRET-KEY-1…` lines, `#` \
                 comments allowed). Requires the urn:cap:decrypt capability (it wields the \
                 private key); a wrong key or tampered ciphertext is a typed Denied/error.",
            )
            .verb(Verb::Source)
            .verb(Verb::Meta)
            .requires(CAP_DECRYPT)
            .input(
                ArgSpec::new("in")
                    .summary(
                        "the age ciphertext, armored or binary (positional or piped as `content`)",
                    )
                    .class(XSD_STRING),
            )
            .input(
                ArgSpec::new("key")
                    .summary(
                        "the owner's identity resource: an age identity file \
                         (AGE-SECRET-KEY-1… lines)",
                    )
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

    /// The probe scalar is not a multiple of the prime-subgroup order: multiplied by
    /// the base point (order ℓ) it gives a non-zero point, so it cannot annihilate a
    /// full-order key, only a small-order one.
    #[test]
    fn the_probe_scalar_is_not_degenerate() {
        let mut base = [0u8; 32];
        base[0] = 9;
        assert!(!is_low_order(base), "the base point is full order");
        assert!(is_low_order([0u8; 32]), "u = 0 is low order");
    }

    /// The README promises a typed error, never a panic. Whatever `age` does in a
    /// future release, a panic inside the sealing or opening is answered as an error
    /// and the caller's thread unwinds no further than this module.
    #[test]
    fn a_panic_inside_age_is_contained_as_a_typed_error() {
        // (The default hook prints this panic to stderr; that is the point of it.)
        let err =
            contained::<()>("urn:encrypt:encrypt", || panic!("AGE-SECRET-KEY-1LEAK")).unwrap_err();
        assert!(matches!(err, Error::Endpoint(_)), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("panicked"), "{text}");
        assert!(
            !text.contains("LEAK"),
            "the panic message is not echoed: {text}"
        );
        // And an ordinary result passes through untouched.
        assert_eq!(contained("x", || Ok(7)).unwrap(), 7);
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
