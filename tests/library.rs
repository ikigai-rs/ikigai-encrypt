//! The library face, [`ikigai_encrypt::age`], with no kernel: the round trips, the two
//! failures a caller tells apart (no matching key, corrupt), and the one file shape that
//! already exists in the field, ikigai-layers' state at rest.
//!
//! Runs in every build: the binary half under `--no-default-features`, the armored half
//! only when `armor` is on.

use ikigai_encrypt::age::{
    open, parse_identities, parse_recipients, seal, Error, ExposeSecret, Identity,
};
use std::io::Write;

/// A fresh identity, as the text of an identity file and as the parsed recipient.
fn keypair() -> (Vec<Identity>, Vec<ikigai_encrypt::age::Recipient>) {
    let identity = Identity::generate();
    let file = format!(
        "# created by the test\n{}\n",
        identity.to_string().expose_secret()
    );
    let recipient = identity.to_public().to_string();
    (
        parse_identities(&file).unwrap(),
        parse_recipients(&recipient).unwrap(),
    )
}

#[test]
fn a_binary_seal_round_trips() {
    let (identities, recipients) = keypair();
    let sealed = seal(b"attack at dawn", &recipients).unwrap();
    assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
    assert!(!sealed
        .windows(b"attack at dawn".len())
        .any(|w| w == b"attack at dawn"));
    assert_eq!(open(&sealed, &identities).unwrap(), b"attack at dawn");
}

#[test]
fn any_one_of_several_recipients_opens_it() {
    let (first, to_first) = keypair();
    let (second, to_second) = keypair();
    let both: Vec<_> = to_first.into_iter().chain(to_second).collect();
    let sealed = seal(b"to every device", &both).unwrap();
    assert_eq!(open(&sealed, &first).unwrap(), b"to every device");
    assert_eq!(open(&sealed, &second).unwrap(), b"to every device");
}

#[cfg(feature = "armor")]
#[test]
fn an_armored_seal_round_trips_and_open_takes_both_forms() {
    let (identities, recipients) = keypair();
    let text = ikigai_encrypt::age::seal_armored(b"attack at dawn", &recipients).unwrap();
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert_eq!(
        open(text.as_bytes(), &identities).unwrap(),
        b"attack at dawn"
    );
    let binary = seal(b"binary too", &recipients).unwrap();
    assert_eq!(open(&binary, &identities).unwrap(), b"binary too");
}

/// Without `armor`, armored text is not an age file to this build.
#[cfg(not(feature = "armor"))]
#[test]
fn without_armor_armored_text_is_not_age() {
    let (identities, _) = keypair();
    let armored = b"-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n";
    assert!(matches!(
        open(armored, &identities).unwrap_err(),
        Error::NotAge(_)
    ));
}

#[test]
fn a_wrong_identity_is_no_matching_key() {
    let (_, recipients) = keypair();
    let (other, _) = keypair();
    let sealed = seal(b"secret", &recipients).unwrap();
    let err = open(&sealed, &other).unwrap_err();
    assert_eq!(err, Error::NoMatchingKey);
    assert!(!err.is_corrupt());
}

#[test]
fn truncated_ciphertext_is_corrupt() {
    let (identities, recipients) = keypair();
    let sealed = seal(&[7u8; 1000], &recipients).unwrap();
    // Cut inside the payload: the header opens, the last chunk does not authenticate.
    let err = open(&sealed[..sealed.len() - 10], &identities).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    assert!(err.is_corrupt());
    // Cut inside the header: not an age file at all (a torn write).
    let err = open(&sealed[..20], &identities).unwrap_err();
    assert!(matches!(err, Error::NotAge(_)), "{err:?}");
    assert!(err.is_corrupt());
    // And nothing is not an age file either.
    assert!(open(b"", &identities).unwrap_err().is_corrupt());
}

#[test]
fn a_flipped_payload_byte_is_corrupt() {
    let (identities, recipients) = keypair();
    let mut sealed = seal(b"secret payload", &recipients).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    let err = open(&sealed, &identities).unwrap_err();
    assert!(err.is_corrupt(), "{err:?}");
    assert_ne!(err, Error::NoMatchingKey);
}

#[test]
fn a_low_order_recipient_is_refused_by_line() {
    let honest = Identity::generate().to_public().to_string();
    let list = format!("{honest}\n\n# the bad one\nage1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj7vrya\n");
    assert_eq!(
        parse_recipients(&list).unwrap_err(),
        Error::LowOrder { line: 4 }
    );
}

#[test]
fn an_empty_list_is_no_keys() {
    assert_eq!(parse_recipients("\n# none\n").unwrap_err(), Error::NoKeys);
    assert_eq!(parse_identities("").err().unwrap(), Error::NoKeys);
}

#[test]
fn a_bad_key_line_is_named_by_number_and_never_echoed() {
    let err = parse_recipients("# list\nage1-not-really-a-key\n").unwrap_err();
    assert!(matches!(err, Error::BadKey { line: 2, .. }), "{err:?}");
    assert!(!err.to_string().contains("not-really"), "{err}");
}

/// The file ikigai-layers writes today (`src/at_rest.rs`, layers PR 34): age 0.11 called
/// directly, one x25519 recipient, binary, no armor. Built here exactly as at_rest.rs
/// builds it, and opened with the new `open`, so arc 2 can switch layers over with every
/// existing state directory still readable.
#[test]
fn a_file_sealed_the_way_layers_at_rest_seals_opens() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    // at_rest.rs `Sealer::seal`, verbatim but for the error type.
    let as_dyn = &recipient as &dyn age::Recipient;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(as_dyn)).unwrap();
    let plaintext = b"<urn:a> <urn:b> <urn:c> .\n";
    let mut sealed = Vec::with_capacity(plaintext.len() + 256);
    let mut writer = encryptor.wrap_output(&mut sealed).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // The key file as `StateKey::load` reads it.
    let key_file = format!(
        "# the layer host's state identity\n{}\n",
        identity.to_string().expose_secret()
    );
    let identities = parse_identities(&key_file).unwrap();
    assert_eq!(open(&sealed, &identities).unwrap(), plaintext);

    // And the other direction: what the new `seal` writes, at_rest.rs `open_with` opens.
    let ours = seal(plaintext, &[recipient]).unwrap();
    let decryptor = age::Decryptor::new(&ours[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut opened = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut opened).unwrap();
    assert_eq!(opened, plaintext);
}
