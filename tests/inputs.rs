//! What the module reads, and what it says when what it was given is wrong.
//!
//! Audit round 3 (ledger #853) reproduced five defects in how the two endpoints read
//! their arguments, all on e07de32; each test below names the bug it pins.
//!
//! - **Bug 2 (serious, wrong output).** A present `in` that was not UTF-8 fell
//!   through to `content`, so the module sealed or opened the WRONG bytes, silently.
//! - **Bug 3.** `encrypt` could not seal binary data and `decrypt` could not open a
//!   binary `.age` file (what `age` writes by default, and the README's own example),
//!   both refused as `MissingArgument("in")` although `in` was passed.
//! - **Bug 4.** An identity file in the format `age-keygen -o key.txt` writes
//!   (comment lines, then the key) was refused as invalid Bech32.
//! - **Bug 5.** Any failure to read `key`/`to` (a by-reference IRI, non-UTF-8 bytes)
//!   was reported as `MissingArgument`.
//! - **Bug 6.** The key sub-request's own error came back as if it were the OUTER
//!   call's: a `to=` naming a resource that itself lacked `in` answered "missing
//!   `in`" to a caller that had passed `in`.
//!
//! Plus the suspected one, confirmed here before the fix: both endpoints answered
//! every verb as if it were Source, so an `Exists`, `Sink` or `Delete` on
//! `urn:encrypt:encrypt` sealed.

use age::secrecy::ExposeSecret;
use age::x25519::Identity;
use ikigai_core::{
    ArgRef, Capability, ContentId, Error, Exact, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Result as CoreResult, Verb,
};
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;

struct Fixture {
    kernel: Kernel,
    recipient: String,
}

/// The module plus key and data resources:
///
/// - `urn:key:pub` — a bare `age1…`; `urn:key:id` — a bare `AGE-SECRET-KEY-1…`;
/// - `urn:key:keygen` — the identity exactly as `age-keygen -o key.txt` writes it;
/// - `urn:key:several` — an identity file holding two identities, the right one second;
/// - `urn:key:comments` — an identity file holding only comments;
/// - `urn:key:missing` — a bound resource answering NotFound;
/// - `urn:data:binary` — non-UTF-8 bytes, for a by-reference `in`.
fn fixture() -> Fixture {
    let id = Identity::generate();
    let recipient = id.to_public().to_string();
    let identity = id.to_string().expose_secret().to_string();
    let other = Identity::generate().to_string().expose_secret().to_string();
    let keygen =
        format!("# created: 2026-10-07T00:00:00Z\n# public key: {recipient}\n{identity}\n");
    let several = format!("# laptop\n{other}\n\n# desktop\n{identity}\n");
    let serve = |name: &'static str, bytes: Vec<u8>| {
        FnEndpoint::new(name, move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("application/octet-stream"),
                bytes.clone(),
            ))
        })
    };
    let space = ikigai_encrypt::space()
        .bind(
            Exact::new("urn:key:pub"),
            serve("k-pub", recipient.clone().into()),
        )
        .bind(Exact::new("urn:key:id"), serve("k-id", identity.into()))
        .bind(
            Exact::new("urn:key:keygen"),
            serve("k-keygen", keygen.into()),
        )
        .bind(
            Exact::new("urn:key:several"),
            serve("k-several", several.into()),
        )
        .bind(
            Exact::new("urn:key:comments"),
            serve("k-comments", b"# nothing here\n\n".to_vec()),
        )
        .bind(
            Exact::new("urn:key:missing"),
            FnEndpoint::new("k-missing", |_inv: &Invocation<'_>| {
                Err(Error::NotFound("no such key".to_string()))
            }),
        )
        .bind(
            Exact::new("urn:data:binary"),
            serve("d-binary", BINARY.to_vec()),
        );
    Fixture {
        kernel: Kernel::new(Arc::new(space)),
        recipient,
    }
}

/// Bytes no UTF-8 decoder accepts: a PNG signature with a stray 0xff and a NUL.
const BINARY: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00];

fn nobody() -> Capability {
    Capability::scoped(Vec::<String>::new())
}

fn decrypter() -> Capability {
    Capability::scoped(["urn:cap:decrypt"])
}

fn issue(k: &Kernel, req: Request, cap: &Capability) -> CoreResult<Representation> {
    futures::executor::block_on(k.issue(req, cap))
}

fn req(verb: Verb, iri: &str, args: Vec<(&str, ArgRef)>) -> Request {
    let mut r = Request::new(verb, Iri::parse(iri).unwrap());
    for (n, a) in args {
        r = r.with_arg(n, a);
    }
    r
}

fn inline(b: &[u8]) -> ArgRef {
    ArgRef::Inline(b.to_vec())
}

fn reference(iri: &str) -> ArgRef {
    ArgRef::Reference(Iri::parse(iri).unwrap())
}

fn seal(f: &Fixture, args: Vec<(&str, ArgRef)>) -> CoreResult<Vec<u8>> {
    issue(
        &f.kernel,
        req(Verb::Source, "urn:encrypt:encrypt", args),
        &nobody(),
    )
    .map(|r| r.bytes)
}

fn open(f: &Fixture, args: Vec<(&str, ArgRef)>) -> CoreResult<Vec<u8>> {
    issue(
        &f.kernel,
        req(Verb::Source, "urn:encrypt:decrypt", args),
        &decrypter(),
    )
    .map(|r| r.bytes)
}

/// Seal `plain` to the fixture's recipient and open it again with `urn:key:id`.
fn round_trip(f: &Fixture, plain: &[u8]) -> Vec<u8> {
    let sealed = seal(
        f,
        vec![("in", inline(plain)), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap_or_else(|e| panic!("seal: {e:?}"));
    open(
        f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:id")),
        ],
    )
    .unwrap_or_else(|e| panic!("open: {e:?}"))
}

/// age-encrypt `plain` WITHOUT armor: the binary `.age` the `age` CLI writes by default.
fn binary_age(recipient: &str, plain: &[u8]) -> Vec<u8> {
    let r = age::x25519::Recipient::from_str(recipient).unwrap();
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient)).unwrap();
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out).unwrap();
    w.write_all(plain).unwrap();
    w.finish().unwrap();
    out
}

fn invalid(err: &Error, arg: &str) -> String {
    match err {
        Error::InvalidArgument { name, detail } if name == arg => detail.clone(),
        other => panic!("expected InvalidArgument on `{arg}`, got {other:?}"),
    }
}

// ------------------------------------------------------------------- bug 3: bytes

/// Bug 3: `encrypt` seals bytes, as its summary says, not only UTF-8 text.
#[test]
fn encrypt_seals_binary_bytes_and_they_round_trip() {
    let f = fixture();
    assert_eq!(round_trip(&f, BINARY), BINARY);
}

/// Bug 3: `decrypt` opens the binary `.age` format, not only the armored one.
#[test]
fn decrypt_opens_a_binary_age_file() {
    let f = fixture();
    let ct = binary_age(&f.recipient, b"attack at dawn");
    assert!(
        std::str::from_utf8(&ct).is_err(),
        "the fixture is truly binary"
    );
    let pt = open(
        &f,
        vec![("in", ArgRef::Inline(ct)), ("key", inline(b"urn:key:id"))],
    )
    .unwrap_or_else(|e| panic!("binary age refused: {e:?}"));
    assert_eq!(pt, b"attack at dawn");
}

/// The armored form still opens through every whitespace mangling a text channel
/// commonly applies: a trailing newline added, the final one stripped, CRLF line ends.
#[test]
fn armored_ciphertext_survives_newline_mangling() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("in", inline(b"hello")), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    let text = String::from_utf8(sealed).unwrap();
    for variant in [
        format!("{text}\n"),
        text.trim_end().to_string(),
        text.replace('\n', "\r\n"),
    ] {
        let pt = open(
            &f,
            vec![
                ("in", inline(variant.as_bytes())),
                ("key", inline(b"urn:key:id")),
            ],
        );
        assert_eq!(pt.ok(), Some(b"hello".to_vec()), "{variant:?}");
    }
}

/// Bug 3's second half: a present `in` is never reported missing, whatever it holds.
/// Ciphertext that is not age at all is an `InvalidArgument` on `in`.
#[test]
fn a_present_in_is_never_reported_missing() {
    let f = fixture();
    let err = open(
        &f,
        vec![
            ("in", inline(&[0xff, 0xfe])),
            ("key", inline(b"urn:key:id")),
        ],
    )
    .unwrap_err();
    let detail = invalid(&err, "in");
    assert!(detail.contains("not age ciphertext"), "{detail}");
}

// ---------------------------------------------------------------- bug 2: precedence

/// Bug 2: a present, non-UTF-8 `in` beside a `content` seals `in`; `content` is only
/// the pipe's spelling of `in` when `in` is absent.
#[test]
fn encrypt_seals_in_never_content_when_both_are_present() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![
            ("in", inline(&[0xff, 0xfe, 0x00])),
            ("content", inline(b"something else entirely")),
            ("to", inline(b"urn:key:pub")),
        ],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:id")),
        ],
    )
    .unwrap();
    assert_eq!(
        pt,
        vec![0xff, 0xfe, 0x00],
        "sealed {:?} in place of `in`",
        String::from_utf8_lossy(&pt)
    );
}

/// Bug 2, decrypt's half: a binary ciphertext as `in` beside a decoy armored
/// ciphertext as `content` opens `in`.
#[test]
fn decrypt_opens_in_never_content_when_both_are_present() {
    let f = fixture();
    let real = binary_age(&f.recipient, b"the real one");
    let decoy = seal(
        &f,
        vec![("in", inline(b"the decoy")), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("in", ArgRef::Inline(real)),
            ("content", ArgRef::Inline(decoy)),
            ("key", inline(b"urn:key:id")),
        ],
    )
    .unwrap();
    assert_eq!(pt, b"the real one");
}

/// The pipe still works: `content` alone, binary, seals and opens.
#[test]
fn piped_content_alone_is_read_as_bytes() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("content", inline(BINARY)), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("content", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:id")),
        ],
    )
    .unwrap();
    assert_eq!(pt, BINARY);
}

// ------------------------------------------------- bug 5: by reference, bad bytes

/// Bug 5: `key` and `to` are classed `rdfs:Resource`, and core's own spelling of "a
/// reference to another resolvable resource" is `ArgRef::Reference`. It is resolved
/// exactly like a by-name IRI.
#[test]
fn keys_passed_by_reference_resolve_like_keys_passed_by_name() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("in", inline(b"hello")), ("to", reference("urn:key:pub"))],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", reference("urn:key:id")),
        ],
    )
    .unwrap();
    assert_eq!(pt, b"hello");
}

/// `in` by reference is dereferenced the same way: the bytes of the named resource.
#[test]
fn input_passed_by_reference_is_dereferenced() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![
            ("in", reference("urn:data:binary")),
            ("to", inline(b"urn:key:pub")),
        ],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:id")),
        ],
    )
    .unwrap();
    assert_eq!(pt, BINARY);
}

/// Bug 5: a present `key` or `to` whose bytes are not an IRI is an `InvalidArgument`
/// naming it, never `MissingArgument`, and the bytes are not echoed.
#[test]
fn a_key_argument_that_is_not_an_iri_is_invalid_not_missing() {
    let f = fixture();
    let err = open(
        &f,
        vec![("in", inline(b"x")), ("key", inline(&[0xff, 0xfe]))],
    )
    .unwrap_err();
    assert!(invalid(&err, "key").contains("must be an IRI"), "{err:?}");
    let err = seal(
        &f,
        vec![("in", inline(b"x")), ("to", inline(&[0xff, 0xfe]))],
    )
    .unwrap_err();
    assert!(invalid(&err, "to").contains("must be an IRI"), "{err:?}");
}

/// A content-addressed argument (`ArgRef::Content`) cannot be read by an endpoint (an
/// invocation carries no content store): a typed refusal that says so, not
/// `MissingArgument`.
#[test]
fn a_content_addressed_argument_is_refused_by_name() {
    let f = fixture();
    let cid = || ArgRef::Content(ContentId::of(b"big"));
    let err = seal(&f, vec![("in", cid()), ("to", inline(b"urn:key:pub"))]).unwrap_err();
    assert!(invalid(&err, "in").contains("content-addressed"), "{err:?}");
    let err = seal(&f, vec![("in", inline(b"x")), ("to", cid())]).unwrap_err();
    assert!(invalid(&err, "to").contains("content-addressed"), "{err:?}");
}

// ------------------------------------------------------- bug 4: identity files

/// Bug 4: an identity file exactly as `age-keygen -o key.txt` writes it opens.
#[test]
fn an_age_keygen_identity_file_opens() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("in", inline(b"hello")), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:keygen")),
        ],
    )
    .unwrap_or_else(|e| panic!("age-keygen identity file refused: {e:?}"));
    assert_eq!(pt, b"hello");
}

/// Bug 4: an identity file may hold several identities; any one that matches opens
/// the file, as with `age -d -i`.
#[test]
fn an_identity_file_with_several_identities_opens_with_any() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("in", inline(b"hello")), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    let pt = open(
        &f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:several")),
        ],
    )
    .unwrap_or_else(|e| panic!("multi-identity file refused: {e:?}"));
    assert_eq!(pt, b"hello");
}

/// An identity file holding no identity is an `InvalidArgument` on `key`.
#[test]
fn an_identity_file_with_no_identity_is_invalid() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("in", inline(b"hello")), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    let err = open(
        &f,
        vec![
            ("in", ArgRef::Inline(sealed)),
            ("key", inline(b"urn:key:comments")),
        ],
    )
    .unwrap_err();
    assert!(invalid(&err, "key").contains("no age identity"), "{err:?}");
}

// ------------------------------------------------- bug 6: the key's own failure

/// Bug 6: a `to=` naming a resource that fails for its own reasons (here,
/// `urn:encrypt:decrypt`, which lacks its own `in`) is reported against `to`, naming
/// that resource, not as the outer call's "missing `in`".
#[test]
fn a_failing_key_resource_is_reported_against_the_key_argument() {
    let f = fixture();
    let err = issue(
        &f.kernel,
        req(
            Verb::Source,
            "urn:encrypt:encrypt",
            vec![
                ("in", inline(b"hello")),
                ("to", inline(b"urn:encrypt:decrypt")),
            ],
        ),
        &decrypter(),
    )
    .unwrap_err();
    let detail = invalid(&err, "to");
    assert!(
        detail.contains("urn:encrypt:decrypt"),
        "names the resource: {detail}"
    );
}

/// Bug 6, the other shapes: an unbound key IRI and a key resource answering
/// NotFound are both reported against `key`, naming the resource. Neither is the
/// OUTER call's `Unresolved`/`NotFound`, which would say the decrypt endpoint itself
/// was missing.
#[test]
fn an_absent_key_resource_is_reported_against_the_key_argument() {
    let f = fixture();
    for iri in ["urn:key:nowhere", "urn:key:missing"] {
        let err = open(
            &f,
            vec![("in", inline(b"x")), ("key", inline(iri.as_bytes()))],
        )
        .unwrap_err();
        let detail = invalid(&err, "key");
        assert!(detail.contains(iri), "{iri}: names the resource: {detail}");
    }
}

// --------------------------------------------------------- undeclared verbs

/// Both endpoints declare Source (and Meta, which the kernel answers from the
/// description). Every other verb is refused before anything is read or sealed:
/// an `Exists` that seals, or a `Sink` that cuts the endpoint's own thread, is an
/// action the manifold never offered.
#[test]
fn only_the_declared_verb_is_answered() {
    let f = fixture();
    let sealed = seal(
        &f,
        vec![("in", inline(b"hello")), ("to", inline(b"urn:key:pub"))],
    )
    .unwrap();
    for verb in [Verb::Exists, Verb::Sink, Verb::Delete] {
        let err = issue(
            &f.kernel,
            req(
                verb,
                "urn:encrypt:encrypt",
                vec![("in", inline(b"hello")), ("to", inline(b"urn:key:pub"))],
            ),
            &nobody(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not answer"),
            "encrypt {verb:?}: {err:?}"
        );
        let err = issue(
            &f.kernel,
            req(
                verb,
                "urn:encrypt:decrypt",
                vec![
                    ("in", ArgRef::Inline(sealed.clone())),
                    ("key", inline(b"urn:key:id")),
                ],
            ),
            &decrypter(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not answer"),
            "decrypt {verb:?}: {err:?}"
        );
    }
}
