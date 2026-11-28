//! The library face: seal, open and key parsing over the [age](https://age-encryption.org)
//! format, with no kernel.
//!
//! This is the ONE implementation of age in the ecosystem. The two endpoints
//! (`urn:encrypt:encrypt`, `urn:encrypt:decrypt`) are thin calls into it, so they cannot
//! drift from it, and a host that seals its own files (ikigai-layers' state at rest) calls
//! it directly instead of taking `age` itself.
//!
//! It builds with `default-features = false`: no `ikigai-core`, no kernel, no armor.
//! [`seal`] always writes BINARY age; `seal_armored` and armored input to [`open`] need
//! the `armor` feature (on by default, and implied by `endpoints`).
//!
//! The module is named for the FORMAT, so another format has an obvious sibling: HPKE
//! (RFC 9180) wraps, when they come, belong in `ikigai_encrypt::hpke` beside this one, with
//! their own key types and the same shape of functions.
//!
//! ```
//! use ikigai_encrypt::age::{open, parse_identities, parse_recipients, seal, ExposeSecret, Identity};
//!
//! let identity = Identity::generate();
//! let key_file = format!("# my key\n{}\n", identity.to_string().expose_secret());
//! let identities = parse_identities(&key_file).unwrap();
//! let recipients = parse_recipients(&identity.to_public().to_string()).unwrap();
//!
//! let sealed = seal(b"attack at dawn", &recipients).unwrap();
//! assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
//! assert_eq!(open(&sealed, &identities).unwrap(), b"attack at dawn");
//! ```
//!
//! # Plugin keys
//!
//! [`seal_dyn`], [`seal_armored_dyn`] and [`open_dyn`] take age's own key traits,
//! [`DynRecipient`] and [`DynIdentity`], so one call can seal to any mix of X25519 and
//! plugin recipients (`age1se1…`, `age1yubikey1…`, `age1tpm1…`, `age1tag1…`) and open with
//! an X25519 identity or a plugin one: a Secure Enclave, YubiKey or TPM key.
//!
//! This crate is a MODULE, so it never runs a plugin binary. The line falls at
//! construction: a host-role crate turns on `age`'s `plugin` feature itself and builds
//! `age::plugin::RecipientPluginV1` or `IdentityPluginV1`, which spawn
//! `age-plugin-<name>` when they wrap or unwrap. It passes them here as `&dyn DynRecipient`
//! or `&dyn DynIdentity`, and this crate only calls the trait methods on the value it was
//! handed. This crate does not turn on `age/plugin`, names no plugin type, and never
//! spawns a process; with `age` built without `plugin`, nothing in it can.
//!
//! Every failure is a typed [`Error`], never a panic: a panic inside `age` is contained
//! and answered as [`Error::Panicked`]. No error echoes a key, a plaintext or a line of
//! key text; a bad line is named by its NUMBER.

use std::io::{Read, Write};
use std::str::FromStr;

use ::age_core::format::{FileKey, Stanza};

/// `Identity::to_string` answers a `SecretString`; this trait reads it. Re-exported from
/// the `secrecy` crate `age` 0.11 uses, so the two always agree.
pub use ::age::secrecy::ExposeSecret;
/// An X25519 age identity (`AGE-SECRET-KEY-1…`), re-exported from `age` 0.11 so a caller
/// can name it without depending on `age`. [`Identity::generate`] mints one, and
/// [`Identity::to_public`] gives its [`Recipient`].
pub use ::age::x25519::Identity;
/// An X25519 age recipient (`age1…`), re-exported from `age` 0.11. Parse one with
/// [`parse_recipients`], which refuses a low-order point; `Recipient::from_str` does not.
pub use ::age::x25519::Recipient;
/// Any age identity: `age`'s own `Identity` trait, re-exported from `age` 0.11 and named
/// apart from the X25519 [`Identity`]. An X25519 [`Identity`] is one; so is a plugin
/// identity a host built (`age::plugin::IdentityPluginV1`). [`open_dyn`] takes them.
pub use ::age::Identity as DynIdentity;
/// Any age recipient: `age`'s own `Recipient` trait, re-exported from `age` 0.11 and named
/// apart from the X25519 [`Recipient`]. An X25519 [`Recipient`] is one; so is a plugin
/// recipient a host built (`age::plugin::RecipientPluginV1`). [`seal_dyn`] takes them.
pub use ::age::Recipient as DynRecipient;

/// Why a seal, an open or a parse failed.
///
/// For an open, the distinction a caller acts on is [`Error::NoMatchingKey`] (the file is
/// whole, but sealed to someone else) against [`Error::is_corrupt`] (the bytes are not a
/// whole age file). Neither variant carries key material or plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Line `line` (1-based) of an identity or recipient list is not one. `detail` is
    /// age's reason, which names no key.
    BadKey {
        /// The 1-based line number.
        line: usize,
        /// age's parse error.
        detail: String,
    },
    /// The text holds no key at all (only blank lines and `#` comments).
    NoKeys,
    /// The recipient on line `line` is a low-order X25519 point: anyone could open a file
    /// sealed to it, and `age` 0.11 panics sealing to it. The whole list is refused, since
    /// sealing to the rest would silently drop a device the caller named.
    LowOrder {
        /// The 1-based line number.
        line: usize,
    },
    /// The recipient on line `line` parsed for age but could not be decoded for the
    /// low-order check, so it is refused rather than sealed to unchecked.
    Unchecked {
        /// The 1-based line number.
        line: usize,
    },
    /// [`seal`] was given no recipients.
    NoRecipients,
    /// Sealing failed in `age` or in writing the output.
    Seal(String),
    /// The input is not an age file (armored or binary, as the build accepts), or its
    /// header does not parse. A torn write that stopped inside the header lands here.
    NotAge(String),
    /// The file is a whole age file, and none of the identities opens it.
    NoMatchingKey,
    /// The header parsed, and a matching stanza failed to unwrap or the header MAC did
    /// not verify: the header was altered.
    Rejected(String),
    /// The header opened, and the payload did not authenticate: altered or truncated.
    Corrupt(String),
    /// An identity given to [`open_dyn`] failed while unwrapping the file key: a plugin
    /// that is not installed, a device that is not present, a touch or PIN that was
    /// refused. It says nothing about the file, so it is not [`Error::is_corrupt`].
    /// `detail` is the identity's reason.
    Identity(String),
    /// `age` panicked. The panic was contained and nothing was produced; its message is
    /// not carried, because it came from code that held the plaintext or the identity.
    Panicked,
}

impl Error {
    /// Whether the bytes are not a whole, unaltered age file: [`Error::NotAge`],
    /// [`Error::Rejected`] or [`Error::Corrupt`]. [`Error::NoMatchingKey`] is not corrupt.
    ///
    /// ```
    /// use ikigai_encrypt::age::Error;
    /// assert!(Error::Corrupt("truncated".into()).is_corrupt());
    /// assert!(Error::NotAge("no header".into()).is_corrupt());
    /// assert!(!Error::NoMatchingKey.is_corrupt());
    /// ```
    pub fn is_corrupt(&self) -> bool {
        matches!(
            self,
            Error::NotAge(_) | Error::Rejected(_) | Error::Corrupt(_)
        )
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadKey { line, detail } => write!(f, "line {line}: {detail}"),
            Error::NoKeys => f.write_str("no key found"),
            Error::LowOrder { line } => write!(
                f,
                "the recipient on line {line} is a low-order X25519 point; anyone could open \
                 a file sealed to it, so it is refused"
            ),
            Error::Unchecked { line } => write!(
                f,
                "the recipient on line {line} could not be decoded for the low-order check"
            ),
            Error::NoRecipients => f.write_str("no recipients to seal to"),
            Error::Seal(why) => write!(f, "sealing failed: {why}"),
            Error::NotAge(why) => write!(f, "not age ciphertext: {why}"),
            Error::NoMatchingKey => f.write_str("no identity matched any of the recipients"),
            Error::Rejected(why) => write!(f, "the header was rejected: {why}"),
            Error::Corrupt(why) => write!(f, "the payload did not open: {why}"),
            Error::Identity(why) => write!(
                f,
                "an identity could not unwrap the file key: {why}; the file was not judged. \
                 Check that the identity's plugin is installed and its device is present"
            ),
            Error::Panicked => f.write_str(
                "the age library panicked; the panic was contained and nothing was produced",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// The non-comment lines of a key list, each with its 1-based number, trimmed: blank lines
/// and `#` comments skipped, as age's own parser does (trimming is a superset of it).
fn key_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(n, l)| (n + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Parse an identity file in age's format, as `age-keygen -o key.txt` writes it and
/// `age -d -i` reads it: one `AGE-SECRET-KEY-1…` per line, blank lines and `#` comments
/// skipped, any number of identities (any one that matches opens a file), in order.
/// Plugin identities are not parsed here (nothing here runs plugins): a host builds one
/// and passes it to [`open_dyn`].
///
/// A bad line is [`Error::BadKey`] naming its number, never its text; a file with no
/// identity is [`Error::NoKeys`].
///
/// ```
/// use ikigai_encrypt::age::{parse_identities, Error, ExposeSecret, Identity};
/// let one = Identity::generate();
/// let text = format!("# created: today\n\n{}\n", one.to_string().expose_secret());
/// assert_eq!(parse_identities(&text).unwrap().len(), 1);
/// assert_eq!(parse_identities("# nothing\n").err().unwrap(), Error::NoKeys);
/// let err = parse_identities("# a comment\nnot a key\n").err().unwrap();
/// assert!(matches!(err, Error::BadKey { line: 2, .. }), "{err:?}");
/// assert!(!err.to_string().contains("not a key"), "a bad line is never echoed");
/// ```
pub fn parse_identities(text: &str) -> Result<Vec<Identity>, Error> {
    let identities = key_lines(text)
        .map(|(line, key)| {
            Identity::from_str(key).map_err(|e| Error::BadKey {
                line,
                detail: e.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if identities.is_empty() {
        return Err(Error::NoKeys);
    }
    Ok(identities)
}

/// Parse a recipient list: one `age1…` per line, blank lines and `#` comments skipped.
///
/// Every recipient is checked for LOW ORDER before age sees it (ledger #853): a low-order
/// point is [`Error::LowOrder`] naming its line, and it refuses the whole list. A bad line
/// is [`Error::BadKey`]; a list with no recipient is [`Error::NoKeys`].
///
/// ```
/// use ikigai_encrypt::age::{parse_recipients, Error, Identity};
/// let mine = Identity::generate().to_public().to_string();
/// let theirs = Identity::generate().to_public().to_string();
/// assert_eq!(parse_recipients(&format!("{mine}\n# laptop\n{theirs}\n")).unwrap().len(), 2);
///
/// // u = 0, a valid bech32 recipient whose point has small order.
/// let low = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z";
/// assert_eq!(
///     parse_recipients(&format!("{mine}\n{low}\n")).unwrap_err(),
///     Error::LowOrder { line: 2 }
/// );
/// ```
pub fn parse_recipients(text: &str) -> Result<Vec<Recipient>, Error> {
    let mut recipients = Vec::new();
    for (line, key) in key_lines(text) {
        let recipient = Recipient::from_str(key).map_err(|e| Error::BadKey {
            line,
            detail: e.to_string(),
        })?;
        match recipient_point(key) {
            Some(point) if !is_low_order(point) => recipients.push(recipient),
            Some(_) => return Err(Error::LowOrder { line }),
            None => return Err(Error::Unchecked { line }),
        }
    }
    if recipients.is_empty() {
        return Err(Error::NoKeys);
    }
    Ok(recipients)
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

/// Run `f`, turning a panic inside it into [`Error::Panicked`].
///
/// The low-order check stops the one panic the audit found, but `age` is a library
/// that still answers some states with `panic!`, and the endpoints are reachable by a
/// caller holding nothing. A host that does not catch unwinds (the MCP projection
/// is one) would go down with it, so a panic in the sealing or opening is contained
/// HERE. The panic's message is not kept: it comes from code that held the plaintext
/// or the identity (the panic hook still prints it to stderr).
///
/// `AssertUnwindSafe` is sound here because `f` owns everything it touches: its
/// buffers are dropped by the unwind and nothing it could have left half-written is
/// observed afterwards.
fn contained<T>(f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(Err(Error::Panicked))
}

/// The X25519 recipients as age's trait objects, for the shared sealing path.
fn as_dyn_recipients(recipients: &[Recipient]) -> Vec<&dyn DynRecipient> {
    recipients.iter().map(|r| r as &dyn DynRecipient).collect()
}

/// Encrypt `plaintext` into `out`, which `age` wraps and hands back on finish.
fn seal_into<W: Write>(
    plaintext: &[u8],
    recipients: &[&dyn DynRecipient],
    out: W,
) -> Result<W, Error> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    let seal_error = |e: &dyn std::fmt::Display| Error::Seal(e.to_string());
    let encryptor = ::age::Encryptor::with_recipients(recipients.iter().copied())
        .map_err(|e| seal_error(&e))?;
    let mut writer = encryptor.wrap_output(out).map_err(|e| seal_error(&e))?;
    writer.write_all(plaintext).map_err(|e| seal_error(&e))?;
    writer.finish().map_err(|e| seal_error(&e))
}

/// Seal `plaintext` to every one of `recipients` as BINARY age: any one of their
/// identities opens it. Two seals of the same bytes differ (a fresh file key each time).
///
/// The output starts with age's header line, `age-encryption.org/v1`. No recipients is
/// [`Error::NoRecipients`]. Parse recipients with [`parse_recipients`], which refuses a
/// low-order point.
///
/// ```
/// use ikigai_encrypt::age::{seal, Error, Identity};
/// let to = [Identity::generate().to_public()];
/// let sealed = seal(b"hello", &to).unwrap();
/// assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
/// assert_ne!(sealed, seal(b"hello", &to).unwrap(), "a fresh file key per seal");
/// assert_eq!(seal(b"hello", &[]).unwrap_err(), Error::NoRecipients);
/// ```
pub fn seal(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, Error> {
    seal_dyn(plaintext, &as_dyn_recipients(recipients))
}

/// Seal `plaintext` as BINARY age to any mix of X25519 and plugin recipients: any one of
/// their identities opens it. Otherwise exactly [`seal`].
///
/// Each recipient is anything that implements age's [`DynRecipient`]: an X25519
/// [`Recipient`], or a plugin recipient a host built and passed in (see the module's
/// "Plugin keys"; this crate never runs the plugin binary itself). age's label rule
/// holds: recipients whose labels differ (a plugin that must be sealed to alone, say)
/// are refused as [`Error::Seal`], as is a recipient that fails to wrap the file key.
/// No recipients is [`Error::NoRecipients`].
///
/// An X25519 [`Recipient`] here has the same contract as in [`seal`]: parse it with
/// [`parse_recipients`], which refuses a low-order point (a trait object cannot be
/// checked here; a panic in age on one is still contained as [`Error::Panicked`]).
///
/// ```
/// use ikigai_encrypt::age::{open_dyn, seal_dyn, DynIdentity, DynRecipient, Identity};
/// let laptop = Identity::generate();
/// let desktop = Identity::generate();
/// let (a, b) = (laptop.to_public(), desktop.to_public());
/// // A plugin recipient a host built goes in the same slice.
/// let to: [&dyn DynRecipient; 2] = [&a, &b];
/// let sealed = seal_dyn(b"hello", &to).unwrap();
/// assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
/// let with: [&dyn DynIdentity; 1] = [&desktop];
/// assert_eq!(open_dyn(&sealed, &with).unwrap(), b"hello");
/// ```
pub fn seal_dyn(plaintext: &[u8], recipients: &[&dyn DynRecipient]) -> Result<Vec<u8>, Error> {
    contained(|| {
        seal_into(
            plaintext,
            recipients,
            Vec::with_capacity(plaintext.len() + 256),
        )
    })
}

/// Seal `plaintext` to `recipients` as ASCII-ARMORED age, the form that travels as a text
/// literal. Otherwise exactly [`seal`]. Needs the `armor` feature.
///
/// The output starts with `-----BEGIN AGE ENCRYPTED FILE-----`.
///
/// ```
/// use ikigai_encrypt::age::{open, seal_armored, Identity};
/// let me = Identity::generate();
/// let text = seal_armored(b"hello", &[me.to_public()]).unwrap();
/// assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
/// assert_eq!(open(text.as_bytes(), &[me]).unwrap(), b"hello");
/// ```
#[cfg(feature = "armor")]
pub fn seal_armored(plaintext: &[u8], recipients: &[Recipient]) -> Result<String, Error> {
    seal_armored_dyn(plaintext, &as_dyn_recipients(recipients))
}

/// Seal `plaintext` as ASCII-ARMORED age to any mix of X25519 and plugin recipients.
/// Otherwise exactly [`seal_dyn`]. Needs the `armor` feature.
///
/// ```
/// use ikigai_encrypt::age::{open, seal_armored_dyn, DynRecipient, Identity};
/// let me = Identity::generate();
/// let to = me.to_public();
/// let text = seal_armored_dyn(b"hello", &[&to as &dyn DynRecipient]).unwrap();
/// assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
/// assert_eq!(open(text.as_bytes(), &[me]).unwrap(), b"hello");
/// ```
#[cfg(feature = "armor")]
pub fn seal_armored_dyn(
    plaintext: &[u8],
    recipients: &[&dyn DynRecipient],
) -> Result<String, Error> {
    use ::age::armor::{ArmoredWriter, Format};
    contained(|| {
        let armor = ArmoredWriter::wrap_output(Vec::new(), Format::AsciiArmor)
            .map_err(|e| Error::Seal(format!("armor: {e}")))?;
        let armored = seal_into(plaintext, recipients, armor)?
            .finish()
            .map_err(|e| Error::Seal(format!("armor: {e}")))?;
        String::from_utf8(armored).map_err(|_| Error::Seal("armor is not UTF-8".to_string()))
    })
}

/// Open age `ciphertext` with whichever of `identities` matches.
///
/// Binary age always; ASCII-armored age too when the `armor` feature is on (the armor
/// reader passes binary through). The failures a caller tells apart:
/// [`Error::NoMatchingKey`] (whole, but sealed to someone else) and the corrupt ones,
/// [`Error::is_corrupt`]: [`Error::NotAge`] (no age header, or a write torn inside it),
/// [`Error::Rejected`] (the header was altered) and [`Error::Corrupt`] (the payload was
/// altered or truncated).
///
/// ```
/// use ikigai_encrypt::age::{open, seal, Error, Identity};
/// let me = Identity::generate();
/// let sealed = seal(b"hello", &[me.to_public()]).unwrap();
/// assert_eq!(open(&sealed, &[me.clone()]).unwrap(), b"hello");
/// assert_eq!(open(&sealed, &[Identity::generate()]).unwrap_err(), Error::NoMatchingKey);
/// assert!(open(&sealed[..sealed.len() - 1], &[me.clone()]).unwrap_err().is_corrupt());
/// assert!(matches!(open(b"plain text", &[me]).unwrap_err(), Error::NotAge(_)));
/// ```
pub fn open(ciphertext: &[u8], identities: &[Identity]) -> Result<Vec<u8>, Error> {
    let identities: Vec<&dyn DynIdentity> =
        identities.iter().map(|i| i as &dyn DynIdentity).collect();
    open_dyn(ciphertext, &identities)
}

/// Open age `ciphertext` with whichever of `identities` matches, each one anything that
/// implements age's [`DynIdentity`]: an X25519 [`Identity`], or a plugin identity a host
/// built and passed in (see the module's "Plugin keys"; this crate never runs the plugin
/// binary itself). Otherwise exactly [`open`], with one more failure:
///
/// [`Error::Identity`]: an identity failed while unwrapping (its plugin is missing, its
/// device is absent, a touch was refused). It is not [`Error::is_corrupt`], so a caller
/// does not mistake an unplugged YubiKey for a damaged file. As in age, identities are
/// tried in order and the first one that answers for a stanza (a key, or a failure) ends
/// the search, so list the identity that needs no device first.
///
/// ```
/// use ikigai_encrypt::age::{open_dyn, seal, DynIdentity, Error, Identity};
/// let me = Identity::generate();
/// let sealed = seal(b"hello", &[me.to_public()]).unwrap();
/// let other = Identity::generate();
/// let with: [&dyn DynIdentity; 2] = [&other, &me];
/// assert_eq!(open_dyn(&sealed, &with).unwrap(), b"hello");
/// assert_eq!(open_dyn(&sealed, &[&other as &dyn DynIdentity]).unwrap_err(), Error::NoMatchingKey);
/// assert_eq!(open_dyn(&sealed, &[]).unwrap_err(), Error::NoMatchingKey);
/// ```
pub fn open_dyn(ciphertext: &[u8], identities: &[&dyn DynIdentity]) -> Result<Vec<u8>, Error> {
    contained(|| {
        #[cfg(feature = "armor")]
        let input = ::age::armor::ArmoredReader::new(ciphertext);
        #[cfg(not(feature = "armor"))]
        let input = ciphertext;
        let decryptor = ::age::Decryptor::new(input).map_err(|e| Error::NotAge(e.to_string()))?;
        let failed = std::cell::Cell::new(false);
        let watched: Vec<Watched<'_>> = identities
            .iter()
            .map(|&inner| Watched {
                inner,
                failed: &failed,
            })
            .collect();
        let mut reader = decryptor
            .decrypt(watched.iter().map(|w| w as &dyn DynIdentity))
            .map_err(|e| match e {
                ::age::DecryptError::NoMatchingKeys => Error::NoMatchingKey,
                other if failed.get() => Error::Identity(other.to_string()),
                other => Error::Rejected(other.to_string()),
            })?;
        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| Error::Corrupt(e.to_string()))?;
        Ok(plaintext)
    })
}

/// An identity handed to age through [`open_dyn`], watched so a failure the IDENTITY
/// reported can be told from one about the FILE.
///
/// age stops at the first identity that answers, so if it answers with an error, that
/// error is the decrypt's. `failed` records that it came from an identity and was not
/// `InvalidHeader`. `InvalidHeader` is what an identity answers for a stanza of its type
/// that is malformed (the only error age's X25519 identity ever gives), so it stays
/// [`Error::Rejected`], a property of the file. Anything else an identity answers (a
/// plugin's failure, a missing plugin, I/O) is [`Error::Identity`].
struct Watched<'a> {
    inner: &'a dyn DynIdentity,
    failed: &'a std::cell::Cell<bool>,
}

impl Watched<'_> {
    fn watch(
        &self,
        answer: Option<Result<FileKey, ::age::DecryptError>>,
    ) -> Option<Result<FileKey, ::age::DecryptError>> {
        if let Some(Err(e)) = &answer {
            if !matches!(e, ::age::DecryptError::InvalidHeader) {
                self.failed.set(true);
            }
        }
        answer
    }
}

impl DynIdentity for Watched<'_> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, ::age::DecryptError>> {
        self.watch(self.inner.unwrap_stanza(stanza))
    }

    // Forwarded, not left to the default: an identity may override `unwrap_stanzas` to
    // check the whole header (age's own docs invite it), and that must still run.
    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, ::age::DecryptError>> {
        self.watch(self.inner.unwrap_stanzas(stanzas))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A typed error, never a panic: whatever `age` does in a future release, a panic
    /// inside the sealing or opening is answered as [`Error::Panicked`], and its message
    /// is not carried.
    #[test]
    fn a_panic_inside_age_is_contained_as_a_typed_error() {
        // (The default hook prints this panic to stderr; that is the point of it.)
        let err = contained::<()>(|| panic!("AGE-SECRET-KEY-1LEAK")).unwrap_err();
        assert_eq!(err, Error::Panicked);
        assert!(!err.to_string().contains("LEAK"), "{err}");
        assert_eq!(contained(|| Ok(7)).unwrap(), 7);
    }
}

#[cfg(feature = "endpoints")]
pub(crate) mod body;
