//! The two kernel endpoints, `urn:encrypt:encrypt` and `urn:encrypt:decrypt`: argument
//! handling, key resolution THROUGH the kernel, and the mapping of library errors onto
//! kernel errors. Every byte of cryptography is a call into [`crate::age`].

use crate::age as lib;
use crate::CAP_DECRYPT;
use async_trait::async_trait;
use ikigai_core::{
    space_iri, ArgRef, ArgSpec, Description, Endpoint, EndpointSpace, Error, Exact, Invocation,
    Iri, ReprType, Representation, Request, Result, Verb,
};

/// The `class` of a key-resource argument: an RDF resource (resolved through the kernel).
const RDFS_RESOURCE: &str = "http://www.w3.org/2000/01/rdf-schema#Resource";
/// The `class` of the plaintext/ciphertext byte arguments.
const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// The name [`space`] claims: `urn:iki:space:encrypt`.
pub const SPACE_ID: &str = "urn:iki:space:encrypt";

/// Mount the module: `urn:encrypt:encrypt` + `urn:encrypt:decrypt`, named
/// [`SPACE_ID`]. Configuration-free (two stateless endpoints, nothing read while
/// building it), so every call holds the same doors and the name is a true claim.
/// A host that binds more doors onto it gets an anonymous space (core 0.1.89).
pub fn space() -> EndpointSpace {
    EndpointSpace::new()
        .bind(Exact::new("urn:encrypt:encrypt"), Encrypt)
        .bind(Exact::new("urn:encrypt:decrypt"), Decrypt)
        .named(space_iri("encrypt"))
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

/// The ONE place a library [`lib::Error`] becomes a kernel [`Error`], for the endpoint
/// `who`. The key-list failures land on that endpoint's key argument (`to` for encrypt,
/// `key` for decrypt) and name the line, never its text. For an open: not age at all is
/// `InvalidArgument` on `in`; a key that does not match, or a header that was altered, is
/// `Denied`; a payload that does not authenticate is an `Endpoint` failure.
fn kernel_error(who: &str, error: lib::Error) -> Error {
    let (arg, kind, expected) = if who == "urn:encrypt:decrypt" {
        ("key", "identity", "AGE-SECRET-KEY-1…")
    } else {
        ("to", "recipient", "age1…")
    };
    let invalid = |name: &str, detail: String| Error::InvalidArgument {
        name: name.to_string(),
        detail,
    };
    match error {
        lib::Error::BadKey { line, detail } => invalid(
            arg,
            format!("{who}: bad age {kind} on line {line}: {detail}"),
        ),
        lib::Error::NoKeys | lib::Error::NoRecipients => invalid(
            arg,
            format!("{who}: the `{arg}` resource holds no age {kind} (expected {expected})"),
        ),
        e @ (lib::Error::LowOrder { .. } | lib::Error::Unchecked { .. }) => {
            invalid(arg, format!("{who}: {e}"))
        }
        lib::Error::NotAge(why) => invalid(
            "in",
            format!("{who}: `in` is not age ciphertext (armored or binary): {why}"),
        ),
        e @ (lib::Error::NoMatchingKey | lib::Error::Rejected(_)) => {
            Error::Denied(format!("{who}: {e}"))
        }
        e => Error::Endpoint(format!("{who}: {e}")),
    }
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
        // An empty list is refused by the parse, with the same typed error.
        let recipients = lib::parse_recipients(&key_text).map_err(|e| kernel_error(WHO, e))?;

        let text = lib::seal_armored(&plaintext, &recipients).map_err(|e| kernel_error(WHO, e))?;
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
        let identities = lib::parse_identities(&key_text).map_err(|e| kernel_error(WHO, e))?;

        let plaintext = lib::open(&ciphertext, &identities).map_err(|e| kernel_error(WHO, e))?;

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
    use crate::age::{ExposeSecret, Identity};
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
