use lockbox_protocol::crypto::envelope::{Envelope, MIN_CIPHERTEXT_LEN, RecipientHeader};
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

const ENTRY_AT: usize = 1 + 24;
const SEALED_LEN_AT: usize = ENTRY_AT + 33 + 32 + 24;

fn recipient_header_bytes() -> Vec<u8> {
    let (_, publics) = recipients(3);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    let bytes = postcard::to_stdvec(&header.for_recipient(&publics[1]).unwrap()).unwrap();
    assert_eq!(bytes.len(), ENTRY_AT + 33 + 32 + 24 + 1 + 48);
    assert_eq!(bytes[SEALED_LEN_AT], 48);
    bytes
}

fn decoded(bytes: &[u8]) -> RecipientHeader {
    postcard::from_bytes(bytes).unwrap()
}

#[test]
fn a_recipient_header_is_made_for_exactly_that_key() {
    let (_, publics) = recipients(4);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    for key in &publics {
        let narrowed = header.for_recipient(key).unwrap();
        assert_eq!(narrowed.recipient(), key);
        assert!(narrowed.validate().is_ok());
    }
}

#[test]
fn every_recipient_can_decrypt_from_their_own_header() {
    let (secrets, publics) = recipients(5);
    let (header, ciphertext) = Envelope::encrypt_to_recipients(b"just for you", &publics)
        .unwrap()
        .into_parts();
    for secret in &secrets {
        let own = header.for_recipient(&secret.verifying_key()).unwrap();
        assert_eq!(own.decrypt(secret, &ciphertext).unwrap(), b"just for you");
    }
}

#[test]
fn a_recipient_header_does_not_open_for_anyone_else() {
    let (secrets, publics) = recipients(3);
    let (header, ciphertext) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    let own = header.for_recipient(&publics[0]).unwrap();
    for other in &secrets[1..] {
        assert!(matches!(
            own.decrypt(other, &ciphertext),
            Err(CryptoError::NotARecipient)
        ));
    }
}

#[test]
fn a_key_that_is_not_a_recipient_gets_no_header() {
    let (_, publics) = recipients(2);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    assert!(
        header
            .for_recipient(&generate_keypair().verifying_key())
            .is_none()
    );
}

#[test]
fn making_a_recipient_header_leaves_the_original_unchanged() {
    let (_, publics) = recipients(3);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    let before = header.clone();
    let _ = header.for_recipient(&publics[1]);
    assert_eq!(header, before);
}

#[test]
fn the_encoded_recipient_header_leaves_out_the_other_keys_and_is_small() {
    let (_, publics) = recipients(10);
    let (header, _) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    let own = header.for_recipient(&publics[3]).unwrap();
    let bytes = postcard::to_stdvec(&own).unwrap();
    let full = postcard::to_stdvec(&header).unwrap();
    assert!(bytes.len() < 200, "{} bytes", bytes.len());
    assert!(full.len() > 5 * bytes.len());
    for (index, key) in publics.iter().enumerate() {
        let present = bytes
            .windows(32)
            .any(|window| window == key.as_bytes().as_slice());
        assert_eq!(present, index == 3, "key {index}");
    }
    assert_eq!(decoded(&bytes), own);
}

#[test]
fn an_unknown_version_in_a_recipient_header_is_rejected() {
    let mut bytes = recipient_header_bytes();
    bytes[0] = 9;
    assert!(matches!(
        decoded(&bytes).validate(),
        Err(CryptoError::UnsupportedVersion(9))
    ));
}

#[test]
fn a_sealed_key_of_the_wrong_length_in_a_recipient_header_is_rejected() {
    let shorter = {
        let mut bytes = recipient_header_bytes();
        bytes[SEALED_LEN_AT] = 47;
        bytes.pop();
        bytes
    };
    let longer = {
        let mut bytes = recipient_header_bytes();
        bytes[SEALED_LEN_AT] = 49;
        bytes.push(0);
        bytes
    };
    for bytes in [shorter, longer] {
        assert!(matches!(
            decoded(&bytes).validate(),
            Err(CryptoError::MalformedEnvelope)
        ));
    }
}

#[test]
fn decrypting_from_a_recipient_header_gives_the_same_result_as_the_envelope() {
    let (secrets, publics) = recipients(3);
    let envelope = Envelope::encrypt_to_recipients(b"same either way", &publics).unwrap();
    let (header, ciphertext) = envelope.clone().into_parts();
    for secret in &secrets {
        let own = header.for_recipient(&secret.verifying_key()).unwrap();
        assert_eq!(
            own.decrypt(secret, &ciphertext).unwrap(),
            envelope.decrypt(secret).unwrap()
        );
    }
}

#[test]
fn a_changed_ciphertext_does_not_decrypt_from_a_recipient_header() {
    let (secrets, publics) = recipients(2);
    let (header, mut ciphertext) = Envelope::encrypt_to_recipients(b"intact", &publics)
        .unwrap()
        .into_parts();
    let own = header.for_recipient(&publics[0]).unwrap();
    ciphertext[0] ^= 0x01;
    assert!(matches!(
        own.decrypt(&secrets[0], &ciphertext),
        Err(CryptoError::Decryption)
    ));
}

#[test]
fn a_recipient_header_refuses_to_decrypt_when_it_is_invalid() {
    let (secrets, publics) = recipients(2);
    let (header, ciphertext) = Envelope::encrypt_to_recipients(b"x", &publics)
        .unwrap()
        .into_parts();
    let mut bytes = postcard::to_stdvec(&header.for_recipient(&publics[0]).unwrap()).unwrap();
    bytes[0] = 9;
    let invalid = decoded(&bytes);
    assert!(matches!(
        invalid.decrypt(&secrets[0], &ciphertext),
        Err(CryptoError::UnsupportedVersion(9))
    ));
}
