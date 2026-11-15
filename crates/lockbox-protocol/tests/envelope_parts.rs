use lockbox_protocol::crypto::envelope::{Envelope, MIN_CIPHERTEXT_LEN};
use lockbox_protocol::crypto::keys::generate_keypair;
use lockbox_protocol::crypto::{CryptoError, SigningKey, VerifyingKey};

const TAG_LEN: usize = 16;

fn recipients(count: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let secrets: Vec<SigningKey> = (0..count).map(|_| generate_keypair()).collect();
    let publics = secrets.iter().map(SigningKey::verifying_key).collect();
    (secrets, publics)
}

#[test]
fn an_envelope_round_trips_through_its_parts() {
    let (secrets, publics) = recipients(3);
    let envelope = Envelope::encrypt_to_recipients(b"in pieces", &publics).unwrap();
    let (header, ciphertext) = envelope.clone().into_parts();
    let rebuilt = Envelope::from_parts(header, ciphertext).unwrap();
    assert_eq!(rebuilt, envelope);
    for secret in &secrets {
        assert_eq!(rebuilt.decrypt(secret).unwrap(), b"in pieces");
    }
}

#[test]
fn the_ciphertext_is_the_message_plus_a_tag() {
    let (_, publics) = recipients(1);
    let (_, ciphertext) = Envelope::encrypt_to_recipients(b"twelve bytes", &publics)
        .unwrap()
        .into_parts();
    assert_eq!(ciphertext.len(), 12 + TAG_LEN);
}

#[test]
fn the_header_lists_recipients_in_the_order_given() {
    let (_, publics) = recipients(4);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    let listed: Vec<VerifyingKey> = header.recipients().copied().collect();
    assert_eq!(listed, publics);
}

#[test]
fn a_duplicate_recipient_is_listed_once() {
    let (_, publics) = recipients(2);
    let repeated = [publics[0], publics[1], publics[0]];
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &repeated)
        .unwrap()
        .into_parts();
    assert_eq!(header.recipients().count(), 2);
}

#[test]
fn a_freshly_made_header_is_valid() {
    let (_, publics) = recipients(2);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    assert!(header.validate().is_ok());
}

#[test]
fn a_ciphertext_shorter_than_a_tag_is_rejected() {
    let (_, publics) = recipients(1);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    for length in [0, 1, TAG_LEN - 1] {
        assert!(matches!(
            Envelope::from_parts(header.clone(), vec![0u8; length]),
            Err(CryptoError::MalformedEnvelope)
        ));
    }
}

#[test]
fn a_ciphertext_of_exactly_a_tag_is_accepted() {
    let (_, publics) = recipients(1);
    let (header, ciphertext) = Envelope::encrypt_to_recipients(b"", &publics)
        .unwrap()
        .into_parts();
    assert_eq!(ciphertext.len(), TAG_LEN);
    assert!(Envelope::from_parts(header, ciphertext).is_ok());
}

#[test]
fn a_header_joined_to_another_files_ciphertext_does_not_decrypt() {
    let (secrets, publics) = recipients(1);
    let (header, _) = Envelope::encrypt_to_recipients(b"first", &publics)
        .unwrap()
        .into_parts();
    let (_, other_ciphertext) = Envelope::encrypt_to_recipients(b"second", &publics)
        .unwrap()
        .into_parts();
    let mixed = Envelope::from_parts(header, other_ciphertext).unwrap();
    assert!(mixed.decrypt(&secrets[0]).is_err());
}

#[test]
fn a_changed_ciphertext_byte_is_caught_on_decrypt() {
    let (secrets, publics) = recipients(1);
    let (header, mut ciphertext) = Envelope::encrypt_to_recipients(b"intact", &publics)
        .unwrap()
        .into_parts();
    ciphertext[0] ^= 0x01;
    let tampered = Envelope::from_parts(header, ciphertext).unwrap();
    assert!(tampered.decrypt(&secrets[0]).is_err());
}

#[test]
fn the_smallest_valid_ciphertext_is_an_encrypted_empty_message() {
    let (_, publics) = recipients(1);
    let (_, ciphertext) = Envelope::encrypt_to_recipients(b"", &publics)
        .unwrap()
        .into_parts();
    assert_eq!(ciphertext.len(), MIN_CIPHERTEXT_LEN);
}
