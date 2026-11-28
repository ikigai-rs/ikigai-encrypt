//! Plugin keys through `seal_dyn` / `open_dyn` (ledger #4515).
//!
//! No plugin binary runs here, and none could: this crate never spawns one. A plugin
//! identity or recipient reaches this crate as an implementation of age's own `Identity`
//! and `Recipient` traits (a host builds `age::plugin::IdentityPluginV1` and
//! `RecipientPluginV1`), so the stand-in below implements those same traits, with a
//! stanza of its own type, as a Secure Enclave or YubiKey plugin would. Its wrapping is
//! a toy XOR: it stands in for a device, not for its cryptography.

use std::cell::Cell;
use std::collections::HashSet;

use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use ikigai_encrypt::age::{
    open, open_dyn, seal, seal_dyn, DynIdentity, DynRecipient, Error, Identity,
};

const TAG: &str = "standin";

fn pad(device: &str) -> [u8; 16] {
    let mut pad = [0x5a; 16];
    for (i, b) in device.bytes().enumerate() {
        pad[i % 16] ^= b;
    }
    pad
}

/// A plugin recipient: one stanza `-> standin <device>`.
struct StandInRecipient {
    device: &'static str,
    labels: &'static [&'static str],
    fails: bool,
}

impl StandInRecipient {
    fn new(device: &'static str) -> Self {
        StandInRecipient {
            device,
            labels: &[],
            fails: false,
        }
    }
}

impl DynRecipient for StandInRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        if self.fails {
            return Err(age::EncryptError::Io(std::io::Error::other(
                "the stand-in device refused to wrap",
            )));
        }
        let pad = pad(self.device);
        let body = file_key
            .expose_secret()
            .iter()
            .zip(pad)
            .map(|(k, p)| k ^ p)
            .collect();
        let stanza = Stanza {
            tag: TAG.to_string(),
            args: vec![self.device.to_string()],
            body,
        };
        let labels = self.labels.iter().map(|l| l.to_string()).collect();
        Ok((vec![stanza], labels))
    }
}

/// How the stand-in identity behaves when it meets its own stanza.
#[derive(Clone, Copy)]
enum Device {
    /// Present: unwraps.
    Present,
    /// Absent (the YubiKey is unplugged, the plugin is not installed): an error.
    Absent,
    /// Panics, as a buggy plugin adapter might.
    Panics,
}

/// A plugin identity for one device. `asked` counts the stanzas it was shown.
struct StandInIdentity {
    device: &'static str,
    state: Device,
    asked: Cell<usize>,
}

impl StandInIdentity {
    fn new(device: &'static str, state: Device) -> Self {
        StandInIdentity {
            device,
            state,
            asked: Cell::new(0),
        }
    }
}

impl DynIdentity for StandInIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        self.asked.set(self.asked.get() + 1);
        if stanza.tag != TAG {
            return None;
        }
        if stanza.args.len() != 1 || stanza.body.len() != 16 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        if stanza.args[0] != self.device {
            return None;
        }
        match self.state {
            Device::Present => {}
            Device::Absent => {
                return Some(Err(age::DecryptError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "the stand-in device is not present",
                ))))
            }
            Device::Panics => panic!("stand-in plugin panicked"),
        }
        let pad = pad(self.device);
        Some(Ok(FileKey::init_with_mut(|key| {
            for (k, (b, p)) in key.iter_mut().zip(stanza.body.iter().zip(pad)) {
                *k = b ^ p;
            }
        })))
    }
}

#[test]
fn a_mix_of_x25519_and_plugin_recipients_opens_with_either_identity() {
    let laptop = Identity::generate();
    let laptop_pub = laptop.to_public();
    let enclave = StandInRecipient::new("enclave");
    let sealed = seal_dyn(b"db password", &[&laptop_pub, &enclave]).unwrap();
    assert!(sealed.starts_with(b"age-encryption.org/v1\n"));

    let service = StandInIdentity::new("enclave", Device::Present);
    assert_eq!(open_dyn(&sealed, &[&service]).unwrap(), b"db password");
    assert_eq!(open_dyn(&sealed, &[&laptop]).unwrap(), b"db password");
    // The X25519-only face still opens a mixed file.
    assert_eq!(open(&sealed, &[laptop]).unwrap(), b"db password");
}

#[test]
fn a_plugin_only_file_opens_with_its_plugin_identity_and_no_other() {
    let sealed = seal_dyn(b"secret", &[&StandInRecipient::new("yubikey-1")]).unwrap();
    let right = StandInIdentity::new("yubikey-1", Device::Present);
    let wrong = StandInIdentity::new("yubikey-2", Device::Present);
    let x25519 = Identity::generate();
    assert_eq!(
        open_dyn(&sealed, &[&wrong, &x25519, &right]).unwrap(),
        b"secret"
    );
    assert_eq!(
        open_dyn(&sealed, &[&wrong, &x25519]).unwrap_err(),
        Error::NoMatchingKey
    );
    assert_eq!(open(&sealed, &[x25519]).unwrap_err(), Error::NoMatchingKey);
}

#[cfg(feature = "armor")]
#[test]
fn an_armored_seal_to_a_plugin_recipient_opens() {
    let text = ikigai_encrypt::age::seal_armored_dyn(b"armored", &[&StandInRecipient::new("tpm")])
        .unwrap();
    assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    let tpm = StandInIdentity::new("tpm", Device::Present);
    assert_eq!(open_dyn(text.as_bytes(), &[&tpm]).unwrap(), b"armored");
}

/// An unplugged device is the identity's failure, not the file's: a caller that treats
/// `is_corrupt` as "quarantine the file" must not do so because a YubiKey is out.
#[test]
fn an_absent_device_is_an_identity_failure_never_corrupt() {
    let sealed = seal_dyn(b"secret", &[&StandInRecipient::new("yubikey")]).unwrap();
    let absent = StandInIdentity::new("yubikey", Device::Absent);
    let err = open_dyn(&sealed, &[&absent]).unwrap_err();
    assert!(matches!(err, Error::Identity(_)), "{err:?}");
    assert!(!err.is_corrupt());
    let text = err.to_string();
    assert!(text.contains("not present"), "{text}");
    assert!(text.contains("plugin is installed"), "{text}");
}

/// As in age, the first identity that answers ends the search: an X25519 identity listed
/// first opens the file before an absent device is asked.
#[test]
fn identities_are_tried_in_order() {
    let laptop = Identity::generate();
    let laptop_pub = laptop.to_public();
    let sealed = seal_dyn(b"secret", &[&laptop_pub, &StandInRecipient::new("yubikey")]).unwrap();
    let absent = StandInIdentity::new("yubikey", Device::Absent);
    assert_eq!(open_dyn(&sealed, &[&laptop, &absent]).unwrap(), b"secret");
    assert_eq!(absent.asked.get(), 0, "the device was never asked");
    assert!(matches!(
        open_dyn(&sealed, &[&absent, &laptop]).unwrap_err(),
        Error::Identity(_)
    ));
}

/// A malformed stanza of the identity's own type is a property of the FILE: `Rejected`
/// and corrupt, exactly as a malformed X25519 stanza is.
#[test]
fn a_malformed_plugin_stanza_is_rejected_as_corrupt() {
    struct Malformed;
    impl DynRecipient for Malformed {
        fn wrap_file_key(
            &self,
            _: &FileKey,
        ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
            let stanza = Stanza {
                tag: TAG.to_string(),
                args: vec![],
                body: vec![0; 3],
            };
            Ok((vec![stanza], HashSet::new()))
        }
    }
    let sealed = seal_dyn(b"secret", &[&Malformed]).unwrap();
    let present = StandInIdentity::new("yubikey", Device::Present);
    let err = open_dyn(&sealed, &[&present]).unwrap_err();
    assert!(matches!(err, Error::Rejected(_)), "{err:?}");
    assert!(err.is_corrupt());
}

#[test]
fn a_panicking_plugin_identity_is_contained() {
    let sealed = seal_dyn(b"AGE-SECRET-KEY-1LEAK", &[&StandInRecipient::new("se")]).unwrap();
    let panics = StandInIdentity::new("se", Device::Panics);
    let err = open_dyn(&sealed, &[&panics]).unwrap_err();
    assert_eq!(err, Error::Panicked);
    assert!(!err.to_string().contains("LEAK"));
}

#[test]
fn a_damaged_payload_is_still_corrupt_through_a_plugin_identity() {
    let sealed = seal_dyn(b"secret", &[&StandInRecipient::new("se")]).unwrap();
    let present = StandInIdentity::new("se", Device::Present);
    let err = open_dyn(&sealed[..sealed.len() - 1], &[&present]).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
}

#[test]
fn recipients_with_different_labels_are_refused_together() {
    let alone = StandInRecipient {
        device: "tag",
        labels: &["standin-alone"],
        fails: false,
    };
    let x25519 = Identity::generate().to_public();
    let err = seal_dyn(b"secret", &[&x25519, &alone]).unwrap_err();
    assert!(matches!(err, Error::Seal(_)), "{err:?}");
    // Alone, it seals.
    assert!(seal_dyn(b"secret", &[&alone]).is_ok());
}

#[test]
fn a_recipient_that_fails_to_wrap_is_a_seal_error() {
    let refusing = StandInRecipient {
        device: "se",
        labels: &[],
        fails: true,
    };
    let err = seal_dyn(b"secret", &[&refusing]).unwrap_err();
    assert!(
        matches!(&err, Error::Seal(why) if why.contains("refused to wrap")),
        "{err:?}"
    );
}

#[test]
fn no_recipients_and_no_identities_are_typed() {
    assert_eq!(seal_dyn(b"x", &[]).unwrap_err(), Error::NoRecipients);
    let me = Identity::generate();
    let sealed = seal(b"x", &[me.to_public()]).unwrap();
    assert_eq!(open_dyn(&sealed, &[]).unwrap_err(), Error::NoMatchingKey);
}
