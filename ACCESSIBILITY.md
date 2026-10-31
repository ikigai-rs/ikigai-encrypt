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
| Last reviewed | 2026-10-31 |

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
- **The library's errors** (`src/age.rs`, the `Display` of `age::Error`): one sentence each,
  such as `the recipient on line 3 is a low-order X25519 point; anyone could open a file sealed
  to it, so it is refused`.
- **Its outputs** are not meant to be read: `urn:encrypt:encrypt` answers ASCII-armored age
  ciphertext (`text/plain`), and `urn:encrypt:decrypt` answers the plaintext as
  `application/octet-stream`, whatever the sender sealed.

Not this repository's: how a host shows any of this, and the wording of core's error kinds.

## The rules that output follows

Verified by reading the source:

- A refusal names the argument it is about (`in`, `to` or `key`), and a failure while reading a
  key resource is reported against that argument, naming the resource.
- A bad key line is named by its line NUMBER and never echoed, and a key passed by value is
  refused without repeating it, so a private key never reaches an error message.
- A refusal about a key says what is expected instead (an IRI naming a key resource; an
  `age1…` recipient; an `AGE-SECRET-KEY-1…` identity).
- No color, no terminal control sequences and no markup are written.

## How it is tested

- `tests/library.rs`: `a_bad_key_line_is_named_by_number_and_never_echoed`,
  `a_low_order_recipient_is_refused_by_line`.
- `tests/low_order.rs`: `assert_refused` checks that every low-order refusal names `to`, says
  `low-order` and names the line.
- `tests/inputs.rs`: `a_present_in_is_never_reported_missing`,
  `a_key_argument_that_is_not_an_iri_is_invalid_not_missing`,
  `an_identity_file_with_no_identity_is_invalid` (the sentence says `no age identity`),
  `a_failing_key_resource_is_reported_against_the_key_argument` and
  `an_absent_key_resource_is_reported_against_the_key_argument` (the sentence names the
  endpoint and the resource).
- The doctests on `parse_identities` and `parse_recipients` pin the line number and that a bad
  line is not echoed.

These test wording for correctness and secrecy; none was written as an accessibility test.
**No automated accessibility checker, browser or assistive technology has been used on this
output.**

## Known limitations

Found by reading the source on 2026-10-31:

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
the pull request what was tested, with what, and what was not.

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
