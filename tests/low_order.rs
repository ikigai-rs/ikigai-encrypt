//! A low-order X25519 recipient is a typed refusal, never a panic.
//!
//! The README promises that a bad input to this module is a typed error, "never a
//! panic". Audit round 3 (ledger #853, bug 1) broke that promise from the OPEN side:
//! a syntactically valid `age1…` recipient whose point has small order (u = 0, u = 1,
//! the order-8 points, and their non-canonical spellings) makes the DH output
//! all-zero, and `age` 0.11 answers an all-zero shared secret with
//! `panic!("Generated the all-zero esk; OS RNG is likely failing!")`. `encrypt` needs
//! no capability, so a caller holding nothing could take down any host that does not
//! catch unwinds — the MCP projection among them.
//!
//! The spellings below are literal fixtures. Each was derived OUTSIDE this crate (an
//! RFC 7748 ladder in Python, bech32-encoded with the audit's `lowo.py`), and each
//! takes a fixed clamped scalar to the all-zero output there; the base point, the
//! control, does not. The first two are the audit's own reproductions; the rest are
//! the libsodium small-order blocklist plus the non-canonical encodings X25519 reduces
//! to the same points (u ≥ p, and bit 255 set, which X25519 ignores).

use age::x25519::Identity;
use ikigai_core::{
    ArgRef, Capability, Error, Exact, FnEndpoint, Invocation, Iri, Kernel, ReprType,
    Representation, Request, Result as CoreResult, Verb,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

const LOW_ORDER: [(&str, &str); 10] = [
    (
        "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z",
        "u = 0",
    ),
    (
        "age1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj7vrya",
        "u = 1",
    ),
    (
        "age1ur4h5lpmgxu2u9jku0a0r87ydtdqnr0tnsetrlvxvgz3vh6fhqqqzyt4v9",
        "an order-8 point",
    ),
    (
        "age1t7wft09r2zxzfvwsk92eeql0tvzyghxytqwgapkcyf8dm5ylz9ts6wm9s8",
        "the other order-8 point",
    ),
    (
        "age1anlllllllllllllllllllllllllllllllllllllllllllllllals4n2t7m",
        "u = p - 1",
    ),
    (
        "age1ahlllllllllllllllllllllllllllllllllllllllllllllllalsn46ayy",
        "u = p (a non-canonical 0)",
    ),
    (
        "age1amlllllllllllllllllllllllllllllllllllllllllllllllalselrwrv",
        "u = p + 1 (a non-canonical 1)",
    ),
    (
        "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqqsuwj9m",
        "u = 0 with bit 255 set",
    ),
    (
        "age1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqqk67yly",
        "u = 1 with bit 255 set",
    ),
    (
        "age1anllllllllllllllllllllllllllllllllllllllllllllllllls3hcv9z",
        "u = p - 1 with bit 255 set",
    ),
];

/// The base point (u = 9): a valid, full-order point. Not anyone's key, but it must
/// NOT be refused — the check is for small order, not for unfamiliar keys.
const BASE_POINT: &str = "age1pyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8r66x";

/// The module plus one key resource, `urn:key:list`, serving `list` verbatim.
fn kernel_with_recipients(list: String) -> Kernel {
    let space = ikigai_encrypt::space().bind(
        Exact::new("urn:key:list"),
        FnEndpoint::new("k-list", move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                list.clone().into_bytes(),
            ))
        }),
    );
    Kernel::new(Arc::new(space))
}

fn nobody() -> Capability {
    Capability::scoped(Vec::<String>::new())
}

/// Seal `hi` to `urn:key:list` as a caller holding nothing, turning a panic into a
/// test failure that says so instead of an unwinding test.
fn seal(kernel: &Kernel, what: &str) -> CoreResult<Representation> {
    let request = Request::new(Verb::Source, Iri::parse("urn:encrypt:encrypt").unwrap())
        .with_arg("in", ArgRef::Inline(b"hi".to_vec()))
        .with_arg("to", ArgRef::Inline(b"urn:key:list".to_vec()));
    catch_unwind(AssertUnwindSafe(|| {
        futures::executor::block_on(kernel.issue(request, &nobody()))
    }))
    .unwrap_or_else(|panic| {
        let message = panic
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        panic!(
            "{what}: urn:encrypt:encrypt PANICKED (the README promises never a panic): {message}"
        )
    })
}

fn assert_refused(err: &Error, what: &str, line: usize) {
    match err {
        Error::InvalidArgument { name, detail } => {
            assert_eq!(name, "to", "{what}: the refusal names the `to` argument");
            assert!(
                detail.contains("low-order"),
                "{what}: the refusal says why: {detail}"
            );
            assert!(
                detail.contains(&format!("line {line}")),
                "{what}: the refusal names the offending line: {detail}"
            );
        }
        other => panic!("{what}: expected a typed InvalidArgument on `to`, got {other:?}"),
    }
    assert!(!err.is_transient(), "{what}: a bad key is permanent");
}

/// Every low-order spelling, alone in the recipient resource, is a typed
/// `InvalidArgument` on `to` — refused before `age` sees it, never a panic.
#[test]
fn a_low_order_recipient_is_a_typed_refusal_not_a_panic() {
    for (recipient, what) in LOW_ORDER {
        let kernel = kernel_with_recipients(format!("{recipient}\n"));
        let err = seal(&kernel, what).expect_err(what);
        assert_refused(&err, what, 1);
    }
}

/// One poisoned line in an otherwise good multi-recipient list refuses the WHOLE
/// call. Dropping the bad line and sealing to the rest would hand the caller a
/// ciphertext for fewer devices than they named, silently; sealing to all of them
/// would put a file key anyone can recover into the header.
#[test]
fn one_low_order_line_refuses_the_whole_list() {
    for (recipient, what) in LOW_ORDER {
        let good = Identity::generate().to_public().to_string();
        let kernel = kernel_with_recipients(format!("# devices\n{good}\n\n{recipient}\n"));
        let err = seal(&kernel, what).expect_err(what);
        assert_refused(&err, what, 4);
    }
}

/// The check refuses small order, nothing else: honest keys and the base point seal.
#[test]
fn full_order_recipients_still_seal() {
    let mut list = String::from(BASE_POINT);
    for _ in 0..32 {
        list.push('\n');
        list.push_str(&Identity::generate().to_public().to_string());
    }
    let kernel = kernel_with_recipients(list);
    let sealed = seal(&kernel, "full-order recipients").expect("full-order recipients seal");
    let text = String::from_utf8(sealed.bytes).unwrap();
    assert!(text.contains("BEGIN AGE ENCRYPTED FILE"), "{text}");
}

/// The kernel that refused a low-order recipient keeps serving: an honest call on
/// the SAME kernel seals, and the poisoned one is refused again, the same way.
#[test]
fn the_kernel_serves_on_after_a_refusal() {
    let good = Identity::generate().to_public().to_string();
    let serve = |name: &'static str, text: String| {
        FnEndpoint::new(name, move |_inv: &Invocation<'_>| {
            Ok(Representation::new(
                ReprType::new("text/plain"),
                text.clone().into_bytes(),
            ))
        })
    };
    let space = ikigai_encrypt::space()
        .bind(
            Exact::new("urn:key:list"),
            serve("k-list", LOW_ORDER[0].0.to_string()),
        )
        .bind(Exact::new("urn:key:good"), serve("k-good", good));
    let kernel = Kernel::new(Arc::new(space));
    let honest = Request::new(Verb::Source, Iri::parse("urn:encrypt:encrypt").unwrap())
        .with_arg("in", ArgRef::Inline(b"hi".to_vec()))
        .with_arg("to", ArgRef::Inline(b"urn:key:good".to_vec()));

    assert_refused(&seal(&kernel, "low-order").unwrap_err(), "low-order", 1);
    assert!(futures::executor::block_on(kernel.issue(honest, &nobody())).is_ok());
    assert_refused(
        &seal(&kernel, "low-order again").unwrap_err(),
        "low-order again",
        1,
    );
}
