//! The module recipe as one test: `ikigai-conformance` walks the two endpoints
//! [`ikigai_encrypt::space`] binds and reports every violation at once.
//!
//! ## The keystore is a fixture — and it decides what is cacheable
//!
//! Neither endpoint holds key material. `encrypt` reads the recipient(s) THROUGH
//! the kernel (`to=<uri>`, resolved with `inv.issue`) and `decrypt` reads the
//! identity the same way (`key=<uri>`), and the kernel folds each sub-resolution's
//! expiry and golden threads into the result. The two endpoints then part ways:
//!
//! - **`encrypt` is never cacheable.** age mints a fresh ephemeral X25519 key per
//!   call, so two encryptions of one plaintext to one recipient are different
//!   bytes; the result is `Expiry::Always` whatever the recipient resource's
//!   expiry. The suite has no spelling for "live by design" (conformance PENDING
//!   #22), so [`every_encrypt_is_live`] pins it by hand — and [`conforms`] walks
//!   once more with `cacheable("encrypt")` declared, asserting the one finding
//!   that draws: the day someone marks it `.cacheable()`, the declaration goes
//!   red, not nothing.
//! - **`decrypt` is exactly as cacheable as its key.** A pure function of the
//!   ciphertext and the identity, marked `.cacheable()`, declaring no thread of its
//!   own: a key served UNDER A THREAD (an `ikigai-fs` cacheable mount) makes the
//!   plaintext cacheable under that thread, and a key served UNCACHEABLE (a secret
//!   backend read on every call) makes it recompute on every call
//!   ([`over_a_live_keystore_nothing_is_cached`]). The half the suite cannot see —
//!   a cached plaintext outlives a rotation until the keystore CUTS its thread —
//!   is [`a_rotated_key_is_cut_and_the_plaintext_recomputes`].
//!
//! The walk covers the fixture too (PENDING #17): [`Key`] describes itself the way
//! a module endpoint must (a kebab-case id, a Source action, an output), and counts
//! its reads so a test can say what a refused call did NOT do.
//!
//! ## Fixtures
//!
//! The suite's minimal inputs (`x`, `urn:example:conformance`) are not a key IRI or
//! an age ciphertext, so each action takes a [`Fixture`]: `encrypt` the recipient
//! IRI, `decrypt` a ciphertext this file seals first plus the identity IRI.
//! Fixtures key on the DESCRIPTION id (`encrypt`, `decrypt` — PENDING #57), which
//! here equals `name()`.
//!
//! ## What the suite cannot see, pinned by hand
//!
//! - **Declared outputs against what is served** (PENDING #11/#31,
//!   [`declared_outputs_are_the_media_types_served`]).
//! - **Required means required** (PENDING #49, [`required_inputs_are_required`]):
//!   drop `in`, `to` or `key` — a typed `MissingArgument` naming it, before any
//!   key is read; and the piped `content` fallback for `in` works.
//! - **Denied before the key is read**
//!   ([`ungranted_callers_are_refused_before_the_key_is_read`]): ENFORCED proves
//!   the KERNEL's floor on the declared `urn:cap:decrypt` (PENDING #46); the same
//!   refusal under a grant on some OTHER scope, and that the identity resource was
//!   never consulted, are this test's. `encrypt` is open and resolves under no
//!   grants.
//! - **No face carries the private key**
//!   ([`the_manifold_carries_no_private_key`]): `describe()`, the catalog, the
//!   action manifold, a `Meta` on each IRI, and every error text a caller can
//!   provoke — a wrong key, a tampered ciphertext, the identity passed BY VALUE as
//!   `key=`, a `to=` pointing at the private key by mistake, a key resource
//!   holding garbage — are searched for the identity's secret tail.
//!
//! No RDF face, so no namespace; no opt-outs; NAMES runs (both ids are kebab-case).

use age::secrecy::ExposeSecret;
use age::x25519::Identity;
use async_trait::async_trait;
use ikigai_conformance::{Check, Fixture, Report, Suite};
use ikigai_core::{
    ArgRef, Capability, Description, Endpoint, Error, Exact, Expiry, Invocation, Iri, Kernel,
    MetaRenderer, ReprType, Representation, Request, Result as CoreResult, Verb,
};
use ikigai_encrypt::CAP_DECRYPT;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// The two endpoints `space()` binds, by description id, and where.
const ENCRYPT: &str = "encrypt";
const DECRYPT: &str = "decrypt";
const ENCRYPT_IRI: &str = "urn:encrypt:encrypt";
const DECRYPT_IRI: &str = "urn:encrypt:decrypt";

/// Where the fixture binds the keypair. Each doubles as the golden thread the
/// threaded keystore names for it — the `ikigai-fs` convention (`depends_on` the
/// resource's own IRI), so a cut is keyed on the name the caller resolved.
const RECIPIENT_IRI: &str = "urn:conformance:key:recipient";
const IDENTITY_IRI: &str = "urn:conformance:key:identity";

/// The bytes every fired action seals or opens.
const MESSAGE: &str = "conformance";

/// The bech32 prefix every age identity shares; what follows it is the secret.
const IDENTITY_PREFIX: &str = "AGE-SECRET-KEY-1";

/// An age keypair in the encodings the module consumes: the `age1…` recipient and
/// the `AGE-SECRET-KEY-1…` identity. Generated per fixture — the walk's
/// determinism does not depend on the key, only on the plaintext.
struct Keypair {
    recipient: String,
    identity: String,
}

fn keypair() -> Keypair {
    let id = Identity::generate();
    Keypair {
        recipient: id.to_public().to_string(),
        identity: id.to_string().expose_secret().to_string(),
    }
}

/// The secret tail of an identity — the part that must never appear anywhere.
fn secret_tail(identity: &str) -> &str {
    identity
        .strip_prefix(IDENTITY_PREFIX)
        .expect("an age identity")
}

/// A key resource — what `urn:file:<key>` or `urn:secret:<name>` is to the module:
/// key text behind an IRI, resolved through the kernel. `thread` is the golden
/// thread a keystore that can be rotated names (and cuts on rotation); `None` is a
/// live store that must be read every time, and serves the key uncacheable. The
/// text sits behind a lock so a test can rotate the key in place, and every read
/// is counted.
struct Key {
    id: &'static str,
    text: Arc<RwLock<String>>,
    thread: Option<&'static str>,
    reads: Arc<AtomicUsize>,
}

#[async_trait]
impl Endpoint for Key {
    async fn invoke(&self, _inv: &Invocation<'_>) -> CoreResult<Representation> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let text = self.text.read().expect("key lock").clone();
        let repr = Representation::new(ReprType::new("text/plain"), text.into_bytes());
        Ok(match self.thread {
            Some(thread) => repr.cacheable().depends_on(thread),
            None => repr,
        })
    }

    fn name(&self) -> &str {
        self.id
    }

    /// The suite walks this endpoint beside the module's, so it carries the same
    /// contract a module endpoint must: an id, a Source action, an output.
    fn describe(&self) -> Description {
        Description::new(self.id)
            .title("Conformance key resource")
            .summary("An age recipient or identity, served as a kernel resource for the walk.")
            .verb(Verb::Source)
            .output("text/plain")
    }
}

/// The smallest `Meta` renderer: every field of the description, as text. The
/// catalog and a `Meta` request both render through it, and a leak check wants
/// every field visible, so `Debug` is the right face here (PENDING #62: core
/// exports no renderer).
struct EveryField;

impl MetaRenderer for EveryField {
    fn render(&self, description: &Description, _target: &ReprType) -> CoreResult<Representation> {
        Ok(Representation::new(
            ReprType::new("text/plain"),
            format!("{description:#?}").into_bytes(),
        ))
    }
}

/// The module's space with one keypair bound as kernel resources, handles to both
/// key texts so a test can rotate or corrupt them, and the read counters.
/// `threaded` selects the keystore's kind (see the file docs): every key under a
/// golden thread named after its IRI, or every key live.
struct Keystore {
    kernel: Kernel,
    keys: Keypair,
    recipient: Arc<RwLock<String>>,
    identity: Arc<RwLock<String>>,
    recipient_reads: Arc<AtomicUsize>,
    identity_reads: Arc<AtomicUsize>,
}

fn keystore(threaded: bool) -> Keystore {
    let keys = keypair();
    let recipient = Arc::new(RwLock::new(keys.recipient.clone()));
    let identity = Arc::new(RwLock::new(keys.identity.clone()));
    let recipient_reads = Arc::new(AtomicUsize::new(0));
    let identity_reads = Arc::new(AtomicUsize::new(0));
    let thread = |iri: &'static str| threaded.then_some(iri);
    let space = ikigai_encrypt::space()
        .bind(
            Exact::new(RECIPIENT_IRI),
            Key {
                id: "key-recipient",
                text: Arc::clone(&recipient),
                thread: thread(RECIPIENT_IRI),
                reads: Arc::clone(&recipient_reads),
            },
        )
        .bind(
            Exact::new(IDENTITY_IRI),
            Key {
                id: "key-identity",
                text: Arc::clone(&identity),
                thread: thread(IDENTITY_IRI),
                reads: Arc::clone(&identity_reads),
            },
        );
    Keystore {
        kernel: Kernel::with_meta_renderer(Arc::new(space), Arc::new(EveryField)),
        keys,
        recipient,
        identity,
        recipient_reads,
        identity_reads,
    }
}

impl Keystore {
    fn identity_reads(&self) -> usize {
        self.identity_reads.load(Ordering::SeqCst)
    }

    fn recipient_reads(&self) -> usize {
        self.recipient_reads.load(Ordering::SeqCst)
    }
}

fn request(verb: Verb, iri: &str, args: &[(&str, &str)]) -> Request {
    let mut request = Request::new(verb, Iri::parse(iri).unwrap());
    for (name, value) in args {
        request = request.with_arg(*name, ArgRef::Inline(value.as_bytes().to_vec()));
    }
    request
}

fn encrypt_request(plaintext: &str) -> Request {
    request(
        Verb::Source,
        ENCRYPT_IRI,
        &[("in", plaintext), ("to", RECIPIENT_IRI)],
    )
}

fn decrypt_request(ciphertext: &str) -> Request {
    request(
        Verb::Source,
        DECRYPT_IRI,
        &[("in", ciphertext), ("key", IDENTITY_IRI)],
    )
}

/// A caller holding nothing at all — the dropper.
fn nobody() -> Capability {
    Capability::scoped(Vec::<String>::new())
}

/// The capability a decrypter holds: `urn:cap:decrypt` and nothing else.
fn decrypter() -> Capability {
    Capability::scoped([CAP_DECRYPT])
}

fn issue(kernel: &Kernel, request: Request, capability: &Capability) -> CoreResult<Representation> {
    futures::executor::block_on(kernel.issue(request, capability))
}

/// Seal `plaintext` to the fixture's recipient through the kernel, under no grants
/// (encryption is open), returning the armored ciphertext.
fn encrypt(kernel: &Kernel, plaintext: &str) -> String {
    let repr = issue(kernel, encrypt_request(plaintext), &nobody())
        .unwrap_or_else(|e| panic!("encrypt failed: {e}"));
    String::from_utf8(repr.bytes).expect("armored age is ASCII")
}

/// Open `ciphertext` with the fixture's identity through the kernel, as a decrypter.
fn decrypt(kernel: &Kernel, ciphertext: &str) -> CoreResult<Representation> {
    issue(kernel, decrypt_request(ciphertext), &decrypter())
}

/// The suite, configured for this module (see the file docs for why each line):
/// one fixture per action.
fn suite(ciphertext: &str) -> Suite {
    Suite::new()
        .fixture(
            Fixture::new(ENCRYPT, Verb::Source)
                .arg("in", MESSAGE)
                .arg("to", RECIPIENT_IRI),
        )
        .fixture(
            Fixture::new(DECRYPT, Verb::Source)
                .arg("in", ciphertext)
                .arg("key", IDENTITY_IRI),
        )
}

/// The walk saw the two module endpoints and the two fixture keys, one Source
/// action each, skipped nothing and opted nothing out. A third module endpoint
/// bound without a line here would be held to a weaker standard; a declared id
/// that binds nothing is a stale list.
fn assert_shape(report: &Report) {
    assert_eq!(
        report.endpoints, 4,
        "encrypt, decrypt, key-recipient, key-identity: {report}"
    );
    assert_eq!(report.actions, 4, "one Source action each: {report}");
    assert_eq!(
        report.checks.skipped().count(),
        0,
        "every check runs: {report}"
    );
    assert!(report.declared.opted_out.is_empty(), "{report}");
    assert!(report.declared.pure.is_empty(), "{report}");
    assert!(report.declared.namespaces.is_empty(), "{report}");
}

/// The threaded keystore: `decrypt` declared cacheable and held to a cache hit,
/// byte-identical results and a non-empty thread set (the key's); `encrypt` left
/// undeclared, so its `Always` passes the probe. Then the same walk with
/// `encrypt` DECLARED cacheable: exactly one finding, naming the declaration —
/// the red line a future `.cacheable()` on the ciphertext would cross.
#[test]
fn conforms() {
    let store = keystore(true);
    let ciphertext = encrypt(&store.kernel, MESSAGE);

    let report = suite(&ciphertext)
        .cacheable(DECRYPT)
        .run_blocking(&store.kernel);
    // Printed even when clean (`--nocapture`): the report is the record.
    eprintln!("[threaded keystore]\n{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);
    assert_eq!(report.declared.cacheable, [DECRYPT], "{report}");

    let report = suite(&ciphertext)
        .cacheable(DECRYPT)
        .cacheable(ENCRYPT)
        .run_blocking(&store.kernel);
    eprintln!("[threaded keystore, encrypt declared cacheable]\n{report}");
    assert_eq!(report.findings.len(), 1, "{report}");
    let finding = &report.findings[0];
    assert_eq!(finding.check, Check::Cacheable, "{report}");
    assert_eq!(finding.endpoint, ENCRYPT, "{report}");
    assert_eq!(finding.verb, Some(Verb::Source), "{report}");
    assert!(
        finding.detail.contains("declared cacheable"),
        "the finding names the declaration: {finding}"
    );
    assert_shape(&report);
}

/// Encryption is not a function of its inputs: two sealings of one plaintext to
/// one recipient are different bytes (a fresh ephemeral key each), both open to
/// the plaintext, and neither is cached — `Expiry::Always` even over a THREADED
/// recipient, whose own representation is cacheable. The recipient is read on
/// every call only because the module never caches; the kernel serves the
/// recipient itself from ITS cache after the first read.
#[test]
fn every_encrypt_is_live() {
    let store = keystore(true);
    let first = issue(&store.kernel, encrypt_request(MESSAGE), &nobody()).unwrap();
    let second = issue(&store.kernel, encrypt_request(MESSAGE), &nobody()).unwrap();
    assert_ne!(first.bytes, second.bytes, "a fresh sealing every call");
    for repr in [&first, &second] {
        assert_eq!(
            repr.expiry,
            Expiry::Always,
            "a ciphertext is never cacheable"
        );
        let text = std::str::from_utf8(&repr.bytes).unwrap();
        assert!(text.contains("BEGIN AGE ENCRYPTED FILE"), "{text}");
        assert!(!text.contains(MESSAGE), "the plaintext is sealed");
        let opened = decrypt(&store.kernel, text).unwrap();
        assert_eq!(opened.bytes, MESSAGE.as_bytes());
    }
    assert!(
        !store.kernel.is_cached(&encrypt_request(MESSAGE), &nobody()),
        "nothing was stored in the cache"
    );
    assert_eq!(
        store.recipient_reads(),
        1,
        "the threaded recipient was read once and served from the kernel's cache after"
    );
}

/// The other keystore: keys served uncacheable, as a secret backend that must hit
/// its store on every read would serve them. `decrypt` still says `.cacheable()`,
/// and the kernel hands the plaintext back uncacheable — the effective expiry is
/// the key's, so every decryption reads the identity again and nothing is ever
/// served from the cache. Undeclared, that is correct and the walk is clean;
/// DECLARED, the suite reports the downgrade on `decrypt` and nothing else —
/// which is the only way the ~2000× incident becomes visible, the types being
/// identical either way.
#[test]
fn over_a_live_keystore_nothing_is_cached() {
    let store = keystore(false);
    let ciphertext = encrypt(&store.kernel, MESSAGE);

    let before = store.identity_reads();
    for _ in 0..2 {
        let opened = decrypt(&store.kernel, &ciphertext).unwrap();
        assert_eq!(opened.bytes, MESSAGE.as_bytes());
        assert_eq!(opened.expiry, Expiry::Always, "as live as its key");
    }
    assert_eq!(
        store.identity_reads() - before,
        2,
        "every decryption reads the identity"
    );
    assert!(
        !store
            .kernel
            .is_cached(&decrypt_request(&ciphertext), &decrypter()),
        "a plaintext over an uncacheable key is not cached"
    );

    let report = suite(&ciphertext).run_blocking(&store.kernel);
    eprintln!("[live keystore, undeclared]\n{report}");
    assert!(report.is_clean(), "{report}");
    assert_shape(&report);

    let report = suite(&ciphertext)
        .cacheable(DECRYPT)
        .run_blocking(&store.kernel);
    eprintln!("[live keystore, declared cacheable]\n{report}");
    assert_eq!(report.findings.len(), 1, "{report}");
    let finding = &report.findings[0];
    assert_eq!(finding.check, Check::Cacheable, "{report}");
    assert_eq!(finding.endpoint, DECRYPT, "{report}");
    assert!(
        finding.detail.contains("declared cacheable"),
        "the finding names the declaration: {finding}"
    );
}

/// The half the suite cannot see: the thread a plaintext inherits is a name the
/// KEYSTORE cuts. This module has no watcher and no key material, so after a
/// rotation with no cut the cached plaintext — opened with the OLD key — is still
/// served, and the identity resource is not even read; the keystore cutting the
/// thread it declared (the key's own IRI) is what recomputes it. The
/// recomputation is visible because the rotated key cannot open the ciphertext at
/// all: the fresh resolution is a typed `Denied`, not the stale plaintext.
#[test]
fn a_rotated_key_is_cut_and_the_plaintext_recomputes() {
    let store = keystore(true);
    let ciphertext = encrypt(&store.kernel, MESSAGE);

    let first = decrypt(&store.kernel, &ciphertext).unwrap();
    assert_eq!(first.bytes, MESSAGE.as_bytes());
    assert_ne!(
        first.expiry,
        Expiry::Always,
        "over a threaded key the plaintext is cacheable"
    );
    assert!(
        first
            .threads()
            .iter()
            .any(|t| t.to_string() == IDENTITY_IRI),
        "under the key's thread: {:?}",
        first.threads()
    );
    assert!(
        store
            .kernel
            .is_cached(&decrypt_request(&ciphertext), &decrypter()),
        "and cached"
    );
    let reads = store.identity_reads();

    // The operator rotates the key in the store. Nothing in this module notices.
    *store.identity.write().expect("key lock") = keypair().identity;
    let stale = decrypt(&store.kernel, &ciphertext).unwrap();
    assert_eq!(
        stale.bytes, first.bytes,
        "no watcher here: a rotation with no cut is served from the cache"
    );
    assert_eq!(
        store.identity_reads(),
        reads,
        "served from the cache: the rotated identity was not read"
    );

    // The keystore cuts the thread it named — the key's IRI — and the plaintext
    // that depended on it goes with it: the next call reads the rotated key, which
    // cannot open a ciphertext sealed to the old one.
    store.kernel.cut(IDENTITY_IRI);
    let err = decrypt(&store.kernel, &ciphertext).unwrap_err();
    assert!(
        matches!(err, Error::Denied(_)),
        "recomputed with the rotated key: {err:?}"
    );
    assert_eq!(store.identity_reads(), reads + 1, "the cut forced a read");
    assert!(
        !store
            .kernel
            .is_cached(&decrypt_request(&ciphertext), &decrypter()),
        "the stale plaintext is gone"
    );
}

/// What `ikigai-conformance` 0.1.0 does not check (PENDING #11/#31): a declared
/// output that is not an RDF face is never compared with what the action serves.
/// Read by hand, then pinned: `encrypt` declares and serves `text/plain` (with a
/// `charset` parameter the comparison ignores), `decrypt` declares and serves
/// `application/octet-stream`.
#[test]
fn declared_outputs_are_the_media_types_served() {
    let store = keystore(true);
    let ciphertext = encrypt(&store.kernel, MESSAGE);
    let served = [
        (
            ENCRYPT_IRI,
            issue(&store.kernel, encrypt_request(MESSAGE), &nobody()).unwrap(),
        ),
        (DECRYPT_IRI, decrypt(&store.kernel, &ciphertext).unwrap()),
    ];
    for (iri, repr) in served {
        let description = store
            .kernel
            .describe_pattern(iri)
            .unwrap_or_else(|| panic!("{iri} describes itself"));
        let got = ikigai_conformance::rdf::bare_media_type(&repr.repr_type.media_type);
        let declared: Vec<String> = description
            .outputs
            .iter()
            .map(|o| ikigai_conformance::rdf::bare_media_type(o))
            .collect();
        assert!(
            declared.contains(&got),
            "{iri} served `{got}`, declared only {declared:?}"
        );
        assert_eq!(declared.len(), 1, "{iri} declares exactly one face");
    }
}

/// PENDING #49: a required input dropped from an otherwise valid call is a typed
/// `MissingArgument` naming it — `in` and `to` on `encrypt`, `in` and `key` on
/// `decrypt` — and no key resource is read on the way. The one substitute the
/// contract admits is the pipe: `content` in place of `in` seals and opens alike.
#[test]
fn required_inputs_are_required() {
    let store = keystore(true);
    let ciphertext = encrypt(&store.kernel, MESSAGE);
    let reads = (store.recipient_reads(), store.identity_reads());

    let missing = |iri: &str, args: &[(&str, &str)], expected: &str| {
        let err = issue(
            &store.kernel,
            request(Verb::Source, iri, args),
            &decrypter(),
        )
        .err()
        .unwrap_or_else(|| panic!("{iri} resolved without `{expected}`"));
        assert!(
            matches!(&err, Error::MissingArgument(name) if name == expected),
            "{iri} without `{expected}`: {err:?}"
        );
        assert!(!err.is_transient(), "{err:?}");
    };
    missing(ENCRYPT_IRI, &[("to", RECIPIENT_IRI)], "in");
    missing(ENCRYPT_IRI, &[("in", MESSAGE)], "to");
    missing(DECRYPT_IRI, &[("key", IDENTITY_IRI)], "in");
    missing(DECRYPT_IRI, &[("in", &ciphertext)], "key");
    assert_eq!(
        (store.recipient_reads(), store.identity_reads()),
        reads,
        "a call refused for a missing input reads no key"
    );

    // The pipe's spelling: `content` where `in` would be.
    let piped = issue(
        &store.kernel,
        request(
            Verb::Source,
            ENCRYPT_IRI,
            &[("content", MESSAGE), ("to", RECIPIENT_IRI)],
        ),
        &nobody(),
    )
    .unwrap();
    let piped = String::from_utf8(piped.bytes).unwrap();
    let opened = issue(
        &store.kernel,
        request(
            Verb::Source,
            DECRYPT_IRI,
            &[("content", &piped), ("key", IDENTITY_IRI)],
        ),
        &decrypter(),
    )
    .unwrap();
    assert_eq!(opened.bytes, MESSAGE.as_bytes());
}

/// Denied before the key is read. ENFORCED sees a typed `Denied` under no grants
/// — the KERNEL's floor on the declared `urn:cap:decrypt`, before the endpoint
/// runs (PENDING #46). Pinned here beyond that: the same refusal under a grant on
/// some OTHER scope, that the denial names the scope, that it is permanent, and
/// that the identity resource is never consulted — an ungranted caller learns
/// nothing about the key, not even that it resolves. `encrypt` declares nothing
/// and resolves under nothing: sealing to a public key is open.
#[test]
fn ungranted_callers_are_refused_before_the_key_is_read() {
    let store = keystore(true);
    let ciphertext = encrypt(&store.kernel, MESSAGE);
    let reads = store.identity_reads();

    for capability in [nobody(), Capability::scoped(["urn:cap:sign"])] {
        let err = issue(&store.kernel, decrypt_request(&ciphertext), &capability)
            .err()
            .unwrap_or_else(|| panic!("decrypt resolved under {capability:?}"));
        assert!(matches!(err, Error::Denied(_)), "{err:?}");
        assert!(!err.is_transient(), "{err:?}");
        assert!(
            err.to_string().contains(CAP_DECRYPT),
            "the denial names the scope: {err}"
        );
    }
    assert_eq!(
        store.identity_reads(),
        reads,
        "no refused call reached the identity"
    );

    // Open: a dropper holding nothing seals to the recipient.
    assert!(issue(&store.kernel, encrypt_request(MESSAGE), &nobody()).is_ok());
    // And the decrypter opens it.
    assert_eq!(
        decrypt(&store.kernel, &ciphertext).unwrap().bytes,
        MESSAGE.as_bytes()
    );
}

/// The private key must not leak. `describe()`, the catalog, the action manifold
/// and a `Meta` on each IRI are resolved under root — the most any caller can
/// hold — and searched for the identity's secret tail; then every error text a
/// caller can provoke: a wrong identity, a tampered ciphertext, the identity
/// passed BY VALUE as `key=` (a non-IRI the module must not echo), a `to=`
/// pointing at the identity by mistake (age refuses the HRP; the module must not
/// echo the resource), and a key resource holding garbage.
#[test]
fn the_manifold_carries_no_private_key() {
    let store = keystore(true);
    let root = Capability::root();
    let secret = secret_tail(&store.keys.identity).to_string();
    let ciphertext = encrypt(&store.kernel, MESSAGE);
    // Warm the kernel: a decrypt has happened, so a leak through a cached
    // representation or a trace would be reachable if there were one.
    decrypt(&store.kernel, &ciphertext).unwrap();

    for iri in [ENCRYPT_IRI, DECRYPT_IRI] {
        let described = format!("{:?}", store.kernel.describe_pattern(iri).unwrap());
        assert!(
            !described.contains(&secret),
            "describe() of {iri}: {described}"
        );
    }
    for (verb, iri) in [
        (Verb::Source, "urn:kernel:catalog"),
        (Verb::Source, "urn:kernel:actions"),
        (Verb::Meta, ENCRYPT_IRI),
        (Verb::Meta, DECRYPT_IRI),
    ] {
        let repr = issue(&store.kernel, request(verb, iri, &[]), &root)
            .unwrap_or_else(|e| panic!("{iri}: {e}"));
        let text = String::from_utf8_lossy(&repr.bytes);
        assert!(!text.is_empty(), "{verb:?} {iri} answered");
        assert!(
            !text.contains(&secret),
            "{verb:?} {iri} carries the private key: {text}"
        );
    }

    let denied_text = |args: &[(&str, &str)]| -> String {
        let err = issue(
            &store.kernel,
            request(Verb::Source, DECRYPT_IRI, args),
            &decrypter(),
        )
        .err()
        .unwrap_or_else(|| panic!("decrypt resolved with {args:?}"));
        err.to_string()
    };

    // The identity itself as `key=`: refused as a non-IRI, and NOT echoed.
    let by_value = denied_text(&[("in", &ciphertext), ("key", &store.keys.identity)]);
    assert!(
        !by_value.contains(&secret),
        "an identity passed by value is echoed: {by_value}"
    );
    assert!(by_value.contains("must be an IRI"), "{by_value}");

    // A tampered ciphertext: the error names no key.
    let mut tampered = ciphertext.clone().into_bytes();
    if let Some(b) = tampered.get_mut(120) {
        *b ^= 0x01;
    }
    let tampered = String::from_utf8(tampered).unwrap();
    let text = denied_text(&[("in", &tampered), ("key", IDENTITY_IRI)]);
    assert!(!text.contains(&secret), "{text}");

    // The identity resource rotated to a key that cannot open it, then to garbage:
    // neither the wrong key nor the garbage appears in the error.
    let other = keypair().identity;
    *store.identity.write().unwrap() = other.clone();
    store.kernel.cut(IDENTITY_IRI);
    let text = denied_text(&[("in", &ciphertext), ("key", IDENTITY_IRI)]);
    assert!(
        !text.contains(&secret) && !text.contains(secret_tail(&other)),
        "{text}"
    );

    let garbage = "not-an-age-identity-7f3a9c";
    *store.identity.write().unwrap() = garbage.to_string();
    store.kernel.cut(IDENTITY_IRI);
    let text = denied_text(&[("in", &ciphertext), ("key", IDENTITY_IRI)]);
    assert!(text.contains("bad age identity"), "{text}");
    assert!(
        !text.contains(garbage),
        "the key resource is echoed: {text}"
    );

    // A `to=` pointing at the private key by mistake: age refuses the prefix, and
    // the module does not echo what it read.
    *store.recipient.write().unwrap() = store.keys.identity.clone();
    store.kernel.cut(RECIPIENT_IRI);
    let err = issue(&store.kernel, encrypt_request(MESSAGE), &nobody()).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("bad age recipient"), "{text}");
    assert!(
        !text.contains(&secret),
        "the recipient resource is echoed: {text}"
    );
}

/// The contract as the manifold states it: `encrypt` one open Source taking `in`
/// and `to`, `decrypt` one Source under `urn:cap:decrypt` taking `in` and `key`;
/// every input required, every input classed with an IRI — the scalars
/// `xsd:string`, the key references `rdfs:Resource`.
#[test]
fn the_manifold_states_the_contract() {
    let store = keystore(true);
    let xsd_string = "http://www.w3.org/2001/XMLSchema#string";
    let rdfs_resource = "http://www.w3.org/2000/01/rdf-schema#Resource";
    let contract = [
        (
            ENCRYPT_IRI,
            ENCRYPT,
            Vec::<&str>::new(),
            vec![("in", xsd_string), ("to", rdfs_resource)],
            "text/plain",
        ),
        (
            DECRYPT_IRI,
            DECRYPT,
            vec![CAP_DECRYPT],
            vec![("in", xsd_string), ("key", rdfs_resource)],
            "application/octet-stream",
        ),
    ];
    for (iri, id, requires, inputs, output) in contract {
        let description = store.kernel.describe_pattern(iri).unwrap();
        assert_eq!(description.id, id);
        let specs = description.action_specs();
        assert_eq!(specs.len(), 1, "{id}: one action");
        let spec = &specs[0];
        assert_eq!(spec.verb, Verb::Source, "{id}");
        assert_eq!(spec.requires, requires, "{id}: declared = enforced");
        let declared: Vec<(&str, &str)> = spec
            .inputs
            .iter()
            .map(|i| (i.name.as_str(), i.class.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(declared, inputs, "{id}: inputs and their classes");
        assert!(
            spec.inputs.iter().all(|i| i.required),
            "{id}: every input is required"
        );
        let outputs: Vec<String> = spec
            .outputs
            .iter()
            .map(|o| ikigai_conformance::rdf::bare_media_type(o))
            .collect();
        assert_eq!(outputs, [output], "{id}: one face");
    }
}
