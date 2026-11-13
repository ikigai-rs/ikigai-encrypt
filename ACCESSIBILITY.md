# Accessibility

What `ikigai-encrypt` emits that people read, the rules that output follows, how it is tested,
and how to report a barrier. It is not a conformance claim. Adapted from the
[ACCESSIBILITY.md template](https://github.com/mgifford/ACCESSIBILITY.md) (MIT).

| Field | Value |
|---|---|
| Target | WCAG 2.2 Level AA, for any page that presents this output; this repository writes text only (no HTML, SVG or color) |
| Status | Evaluation in progress. No conformance claim. |
| Owner | the maintainers of this repository |
| Report a barrier | [a GitHub issue](https://github.com/ikigai-rs/ikigai-encrypt/issues/new?labels=accessibility) with the `accessibility` label; anything security-sensitive through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-encrypt/security/advisories/new) |
| Last reviewed | 2026-11-12 |

## What it emits that people read

This is a library: two endpoints a host binds, and the `age` functions under them. What a
person reads is its refusals and errors.

- **Refusals from the endpoints** (`src/endpoints.rs`): a missing input is core's
  `MissingArgument` naming it (`in`, `to`, `key`); an unusable one is `InvalidArgument` naming
  the argument, with a sentence that starts with the endpoint's IRI (`kernel_error`, `key_iri`,
  `sub_failure`), for example ``urn:encrypt:decrypt: the `key` resource holds no age identity
  (expected AGE-SECRET-KEY-1…)`` or `urn:encrypt:encrypt: bad age recipient on line 2: …`; a
  wrong key or an altered
  header is `Denied`; a verb other than Source is refused in a sentence.
- **The library's errors** (`src/age.rs`, the `Display` of `age::Error`): text descriptions,
  such as `the recipient on line 3 is a low-order X25519 point; anyone could open a file sealed
  to it, so it is refused`.
- **Its outputs** are not meant to be read: `urn:encrypt:encrypt` answers ASCII-armored age
  ciphertext (`text/plain`), and `urn:encrypt:decrypt` answers the plaintext as
  `application/octet-stream`, whatever the sender sealed.

Not this repository's: how a host shows any of this, and the wording of core's error kinds.

## The rules that output follows

The intended rules, with the scope of verification recorded below:

- A refusal names the argument it is about (`in`, `to` or `key`), and a failure while reading a
  key resource is reported against that argument, naming the resource.
- A bad key line is named by its line NUMBER and never echoed, and a key passed by value is
  refused without repeating it, so a private key never reaches an error message.
- Invalid key arguments explain that an IRI naming a key resource is expected; empty key
  resources name the expected `age1…` recipient or `AGE-SECRET-KEY-1…` identity. Other parse
  failures carry the dependency's detail, which may not explain how to recover.
- This repository's message templates express meaning in words, without color, terminal
  control sequences or markup. Dependency errors and resource identifiers are interpolated;
  this is not a guarantee about all text supplied by a dependency or host.

## How it is tested

Every named check has a result: Pass, Fail or Blocked. A Pass covers only the stated
check, not overall accessibility. Checks below ran on 2026-11-12 against main commit
[`faf3aff37f3f0774213d59762c4b6625467d3cab`](https://github.com/ikigai-rs/ikigai-encrypt/commit/faf3aff37f3f0774213d59762c4b6625467d3cab),
before this documentation update. Automated checks used Cargo 1.99.1 and rustc 1.99.1
with `age` 0.11.5. `cargo test --all-features` ran 61 unit/integration tests and 7 doctests;
CI repeats the Rust checks, not the manual source review or assistive-technology checks.
These are correctness and secrecy tests, not an accessibility evaluation of a host.

| Check | Result | Evidence |
|---|---|---|
| Bad key line number and no echoed bad line | Pass | `cargo test --all-features`: `tests/library.rs::a_bad_key_line_is_named_by_number_and_never_echoed` and the `parse_identities` doctest in `src/age.rs` check the line number and absence of the bad identity text. This samples malformed identities, not every possible dependency error. |
| Low-order recipient refusal names the argument and line | Pass | `cargo test --all-features`: `tests/library.rs::a_low_order_recipient_is_refused_by_line`, `tests/low_order.rs` (its `assert_refused` helper checks `to`, `low-order` and the line), and the `parse_recipients` doctest in `src/age.rs`. The recipient doctest checks the typed line number, not absence of echoed bad text. |
| Present input and invalid key arguments are identified correctly | Pass | `cargo test --all-features`: `tests/inputs.rs::a_present_in_is_never_reported_missing` checks `in` and `not age ciphertext`; `a_key_argument_that_is_not_an_iri_is_invalid_not_missing` checks `key`/`to` and `must be an IRI`; `an_identity_file_with_no_identity_is_invalid` checks `key` and `no age identity`. These assert selected wording, not comprehension. |
| Failed key-resource reads retain argument and resource context | Pass | `cargo test --all-features`: `tests/inputs.rs::a_failing_key_resource_is_reported_against_the_key_argument` and `an_absent_key_resource_is_reported_against_the_key_argument`. Selected failures only; not every host error. |
| Message templates keep meaning in words and explain expected key forms | Pass | Manual source review of `src/endpoints.rs` (`source_only`, `key_iri`, `resolve_key`, `sub_failure`, `kernel_error`) and `src/age.rs` (`Display`), 2026-11-12. Own templates use words without color, terminal controls or markup; malformed IRI and empty-key messages state expected forms. Does not evaluate host rendering, interpolated text, or whether users understand the wording. |
| Actionable recovery guidance for every error | Fail | Manual review of `src/age.rs` `Display`, 2026-11-12: `Panicked` says the panic was contained but gives no next step; dependency details in `BadKey`, `Seal`, `NotAge`, `Rejected` and `Corrupt` may provide no recovery guidance. No WCAG conformance determination follows from this wording review. |
| Automated accessibility checker | Blocked | No accessibility checker was run. This library supplies text rather than a rendered host page; no host/checker integration was available for this review. Rust tests do not replace this check. |
| Browser rendering, contrast, reflow and zoom | Blocked | No host page or browser evaluation was available for this review. Text-only library output does not establish the accessibility of a host's presentation. |
| Manual keyboard | Blocked | No person performed a keyboard pass in a host presenting these errors; no interactive host session was available. |
| Screen reader | Blocked | No screen reader was used on this output; no screen reader session with a host was available. |
| Screen magnifier | Blocked | No screen magnifier was used on this output; no magnifier session with a host was available. |
| Speech input | Blocked | No speech-input software was used on this output; no speech-input session with a host was available. |
| Switch access | Blocked | No switch-access software was used on this output; no switch-access session with a host was available. |
| Braille display | Blocked | No braille display was used on this output; no braille display was available. |

The earlier source review was dated 2026-10-31 and recorded no browser, automated
accessibility-checker or assistive-technology run. It supplies no historical Pass for those
checks. Any future historical run that CI does not repeat must be marked Blocked with its
date until rerun for the review. The result-table format follows
[gonk-starter PR 91](https://github.com/ikigai-rs/ikigai-gonk-starter/pull/91).

## Known limitations

Confirmed by reading the source on 2026-11-12:

- **Some sentences end in the `age` library's own wording.** `sealing failed: …`, `not age
  ciphertext: …`, `the header was rejected: …`, `the payload did not open: …` and a bad key
  line's detail carry the dependency's error text, which this repository does not control and
  which may not say what to do.
- **A contained panic says nothing actionable**: `the age library panicked; the panic was
  contained and nothing was produced` does not say whether to retry or what input caused it.
- Every message is English only.

## Contributing

Read this file before changing any output listed above, above all a refusal or an
`age::Error` sentence. Name the argument, keep meaning in words, and never echo a key. Say in
the pull request's `## Accessibility` section what was tested in a
`Check | Result | Evidence` table. Give every check a Pass, Fail or Blocked result with the
test or command and tool version, or why it could not run. Keep unrun checks as Blocked,
including each assistive technology; a historical run CI does not repeat is Blocked with its
date. State what each Pass covers and does not cover.

## Reporting a barrier

[Open an issue](https://github.com/ikigai-rs/ikigai-encrypt/issues/new?labels=accessibility)
with the `accessibility` label (the link sets it when GitHub lets you add labels; otherwise a
maintainer adds it): what you were doing, what happened, and the host and any assistive
technology you used, if you are comfortable sharing them. Anything security-sensitive goes
through [private vulnerability reporting](https://github.com/ikigai-rs/ikigai-encrypt/security/advisories/new).
**We acknowledge a report within 7 days**, and promise nothing further.

## Change history

| Date | Change |
|---|---|
| 2026-10-31 | First version. |
| 2026-11-12 | Added Pass / Fail / Blocked results, current main test evidence, review scope and explicit unrun host and assistive-technology checks. |
